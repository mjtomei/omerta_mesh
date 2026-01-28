// Package netstack provides a userspace TCP/IP stack for tunnel traffic routing.
// It receives raw IP packets from the mesh and forwards them to real internet
// connections, then returns response packets back through the mesh.
package netstack

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// Default MTU for the virtual interface
	DefaultMTU = 1500

	// Channel size for packet queues
	PacketQueueSize = 256

	// Timeouts
	TCPConnectTimeout = 30 * time.Second
	UDPIdleTimeout    = 60 * time.Second
)

// Stats holds connection statistics
type Stats struct {
	TCPConns int
	UDPConns int
}

// Stack represents a userspace TCP/IP stack instance
type Stack struct {
	stack    *stack.Stack
	endpoint *channel.Endpoint
	nicID    tcpip.NICID

	// Callback for returning packets to the mesh
	returnPacket func([]byte)

	// Track active connections for cleanup
	mu          sync.RWMutex
	tcpConns    map[string]*tcpForwarder
	udpConns    map[string]*udpForwarder

	// Shutdown
	ctx    context.Context
	cancel context.CancelFunc
}

// Config for creating a new Stack
type Config struct {
	// MTU for the virtual interface (default: 1500)
	MTU uint32

	// Subnet for the virtual network (e.g., "10.200.0.0/16")
	// Packets from this subnet are forwarded
	Subnet string

	// Gateway IP (the stack's address, e.g., "10.200.0.1")
	GatewayIP string
}

// NewStack creates a new userspace TCP/IP stack
func NewStack(cfg Config) (*Stack, error) {
	if cfg.MTU == 0 {
		cfg.MTU = DefaultMTU
	}

	// Create the stack with IPv4, IPv6, TCP, UDP, ICMP
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})

	// Create channel endpoint for packet injection/extraction
	ep := channel.New(PacketQueueSize, cfg.MTU, "")

	// Create NIC
	nicID := tcpip.NICID(1)
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("failed to create NIC: %v", err)
	}

	// Parse and add gateway address
	gatewayAddr, err := parseIPAddress(cfg.GatewayIP)
	if err != nil {
		return nil, fmt.Errorf("invalid gateway IP: %v", err)
	}

	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: gatewayAddr.WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("failed to add address: %v", err)
	}

	// Enable promiscuous mode so the NIC accepts packets to any address
	// This is required for transparent proxying
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("failed to set promiscuous mode: %v", err)
	}

	// Enable spoofing so we can send packets from any source address
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("failed to enable spoofing: %v", err)
	}

	// Add default route (all traffic goes through this NIC)
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})

	// Enable forwarding
	s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)
	s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true)

	ctx, cancel := context.WithCancel(context.Background())

	ns := &Stack{
		stack:    s,
		endpoint: ep,
		nicID:    nicID,
		tcpConns: make(map[string]*tcpForwarder),
		udpConns: make(map[string]*udpForwarder),
		ctx:      ctx,
		cancel:   cancel,
	}

	return ns, nil
}

// SetReturnCallback sets the callback for returning packets to the mesh
func (s *Stack) SetReturnCallback(cb func([]byte)) {
	s.returnPacket = cb
}

// InjectPacket injects a raw IP packet into the stack for processing
func (s *Stack) InjectPacket(packet []byte) error {
	if len(packet) < 1 {
		return fmt.Errorf("empty packet")
	}

	// Determine IP version from first nibble
	version := packet[0] >> 4

	var proto tcpip.NetworkProtocolNumber
	switch version {
	case 4:
		proto = ipv4.ProtocolNumber
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		return fmt.Errorf("unknown IP version: %d", version)
	}

	// Create packet buffer and inject
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	defer pkb.DecRef()

	s.endpoint.InjectInbound(proto, pkb)
	return nil
}

// Start begins processing packets and forwarding connections
func (s *Stack) Start() {
	// Start goroutine to read outbound packets and return them
	go s.readOutboundPackets()

	// Set up TCP forwarder
	tcpFwd := tcp.NewForwarder(s.stack, 0, 1024, s.handleTCPConnection)
	s.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// Set up UDP forwarder
	udpFwd := udp.NewForwarder(s.stack, s.handleUDPPacket)
	s.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
}

// Stop shuts down the stack and all connections
func (s *Stack) Stop() {
	s.cancel()

	s.mu.Lock()
	for _, fwd := range s.tcpConns {
		fwd.Close()
	}
	for _, fwd := range s.udpConns {
		fwd.Close()
	}
	s.tcpConns = make(map[string]*tcpForwarder)
	s.udpConns = make(map[string]*udpForwarder)
	s.mu.Unlock()

	s.stack.Close()
}

// GetStats returns current connection statistics
func (s *Stack) GetStats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Stats{
		TCPConns: len(s.tcpConns),
		UDPConns: len(s.udpConns),
	}
}

// readOutboundPackets reads packets from the stack and sends them back
func (s *Stack) readOutboundPackets() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		pkt := s.endpoint.ReadContext(s.ctx)
		if pkt == nil {
			continue
		}

		// Extract the packet data
		view := pkt.ToView()
		data := view.AsSlice()

		if s.returnPacket != nil && len(data) > 0 {
			// Make a copy since the buffer will be reused
			packet := make([]byte, len(data))
			copy(packet, data)
			s.returnPacket(packet)
		}

		pkt.DecRef()
	}
}

// handleTCPConnection handles a new TCP connection from the virtual network
func (s *Stack) handleTCPConnection(r *tcp.ForwarderRequest) {
	id := r.ID()
	key := fmt.Sprintf("%s:%d->%s:%d",
		id.LocalAddress, id.LocalPort,
		id.RemoteAddress, id.RemotePort)

	// Create endpoint
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true) // RST
		return
	}
	r.Complete(false)

	// Connect to real destination
	dstAddr := fmt.Sprintf("%s:%d", id.LocalAddress.String(), id.LocalPort)

	realConn, dialErr := net.DialTimeout("tcp", dstAddr, TCPConnectTimeout)
	if dialErr != nil {
		ep.Close()
		return
	}

	// Create gonet adapter
	conn := gonet.NewTCPConn(&wq, ep)

	// Create forwarder
	fwd := &tcpForwarder{
		virtual: conn,
		real:    realConn,
		ctx:     s.ctx,
	}

	s.mu.Lock()
	s.tcpConns[key] = fwd
	s.mu.Unlock()

	// Start forwarding in both directions
	go fwd.Forward()

	// Cleanup when done
	go func() {
		<-fwd.Done()
		s.mu.Lock()
		delete(s.tcpConns, key)
		s.mu.Unlock()
	}()
}

// handleUDPPacket handles a UDP packet from the virtual network
// Returns true if the packet was handled, false otherwise
func (s *Stack) handleUDPPacket(r *udp.ForwarderRequest) bool {
	id := r.ID()
	key := fmt.Sprintf("%s:%d->%s:%d",
		id.LocalAddress, id.LocalPort,
		id.RemoteAddress, id.RemotePort)

	s.mu.RLock()
	_, exists := s.udpConns[key]
	s.mu.RUnlock()

	if exists {
		// Already have a forwarder for this connection
		return true
	}

	// Create new UDP forwarder
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return false
	}

	// Create real UDP socket
	dstAddr := fmt.Sprintf("%s:%d", id.LocalAddress.String(), id.LocalPort)
	realConn, dialErr := net.Dial("udp", dstAddr)
	if dialErr != nil {
		ep.Close()
		return false
	}

	conn := gonet.NewUDPConn(&wq, ep)

	fwd := &udpForwarder{
		virtual: conn,
		real:    realConn.(*net.UDPConn),
		ctx:     s.ctx,
		timeout: UDPIdleTimeout,
	}

	s.mu.Lock()
	s.udpConns[key] = fwd
	s.mu.Unlock()

	go fwd.Forward()

	go func() {
		<-fwd.Done()
		s.mu.Lock()
		delete(s.udpConns, key)
		s.mu.Unlock()
	}()

	return true
}

// parseIPAddress parses an IP address string into a tcpip.Address
func parseIPAddress(s string) (tcpip.Address, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return tcpip.Address{}, fmt.Errorf("invalid IP address: %s", s)
	}

	if ip4 := ip.To4(); ip4 != nil {
		return tcpip.AddrFromSlice(ip4), nil
	}
	return tcpip.AddrFromSlice(ip.To16()), nil
}

// tcpForwarder forwards TCP traffic between virtual and real connections
type tcpForwarder struct {
	virtual *gonet.TCPConn
	real    net.Conn
	ctx     context.Context
	done    chan struct{}
	once    sync.Once
}

func (f *tcpForwarder) Forward() {
	f.done = make(chan struct{})

	// Forward in both directions
	go func() {
		io.Copy(f.real, f.virtual)
		f.Close()
	}()

	go func() {
		io.Copy(f.virtual, f.real)
		f.Close()
	}()
}

func (f *tcpForwarder) Close() {
	f.once.Do(func() {
		f.virtual.Close()
		f.real.Close()
		close(f.done)
	})
}

func (f *tcpForwarder) Done() <-chan struct{} {
	return f.done
}

// udpForwarder forwards UDP traffic between virtual and real connections
type udpForwarder struct {
	virtual *gonet.UDPConn
	real    *net.UDPConn
	ctx     context.Context
	timeout time.Duration
	done    chan struct{}
	once    sync.Once
}

func (f *udpForwarder) Forward() {
	f.done = make(chan struct{})

	// Forward virtual -> real
	go func() {
		buf := make([]byte, DefaultMTU)
		for {
			f.virtual.SetReadDeadline(time.Now().Add(f.timeout))
			n, err := f.virtual.Read(buf)
			if err != nil {
				f.Close()
				return
			}
			f.real.Write(buf[:n])
		}
	}()

	// Forward real -> virtual
	go func() {
		buf := make([]byte, DefaultMTU)
		for {
			f.real.SetReadDeadline(time.Now().Add(f.timeout))
			n, err := f.real.Read(buf)
			if err != nil {
				f.Close()
				return
			}
			f.virtual.Write(buf[:n])
		}
	}()
}

func (f *udpForwarder) Close() {
	f.once.Do(func() {
		f.virtual.Close()
		f.real.Close()
		close(f.done)
	})
}

func (f *udpForwarder) Done() <-chan struct{} {
	return f.done
}

// TCPConnection represents an outbound TCP connection through the stack
type TCPConnection struct {
	conn *gonet.TCPConn
	wq   waiter.Queue
	mu   sync.Mutex
}

// DialTCP creates a new TCP connection to the specified address through the stack.
// This is used for outbound connections (e.g., SSH to a VM) where the consumer
// initiates the connection rather than receiving it from the virtual network.
func (s *Stack) DialTCP(host string, port uint16) (*TCPConnection, error) {
	// Parse host address
	dstAddr, err := parseIPAddress(host)
	if err != nil {
		return nil, fmt.Errorf("invalid host address: %v", err)
	}

	// Create full address with port
	fullAddr := tcpip.FullAddress{
		Addr: dstAddr,
		Port: port,
	}

	// Use gonet to dial - this uses the netstack's routing and generates
	// proper SYN packets that will be sent out via the NIC callback
	var wq waiter.Queue
	conn, err := gonet.DialTCPWithBind(s.ctx, s.stack, tcpip.FullAddress{}, fullAddr, ipv4.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %v", err)
	}

	return &TCPConnection{
		conn: conn,
		wq:   wq,
	}, nil
}

// DialTCPByName resolves a hostname through the stack's network (DNS over UDP
// routed through the virtual NIC) and then dials TCP to the resolved address.
// This ensures DNS queries travel through the same tunnel path as data traffic.
func (s *Stack) DialTCPByName(host string, port uint16) (*TCPConnection, error) {
	// If the host is already an IP address, just use DialTCP directly
	if ip := net.ParseIP(host); ip != nil {
		return s.DialTCP(host, port)
	}

	// Create a custom resolver that sends DNS queries through our gVisor stack.
	// We always use 8.8.8.8:53 because the system resolver (e.g. 127.0.0.53)
	// is unreachable from inside the userspace network stack.
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dnsAddr, err := parseIPAddress("8.8.8.8")
			if err != nil {
				return nil, err
			}

			fullAddr := tcpip.FullAddress{
				Addr: dnsAddr,
				Port: 53,
			}

			// Dial UDP through the gVisor stack — this generates UDP packets
			// that exit via the channel endpoint, get routed through the mesh
			// to the gateway, and reach a real DNS server
			conn, err := gonet.DialUDP(s.stack, nil, &fullAddr, ipv4.ProtocolNumber)
			if err != nil {
				return nil, fmt.Errorf("gonet UDP dial to DNS failed: %v", err)
			}
			return conn, nil
		},
	}

	ctx, cancel := context.WithTimeout(s.ctx, TCPConnectTimeout)
	defer cancel()

	addrs, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %q: %v", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses found for %q", host)
	}

	// Filter to IPv4 addresses only (our stack uses ipv4.ProtocolNumber)
	var ipv4Addrs []string
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
			ipv4Addrs = append(ipv4Addrs, addr)
		}
	}
	if len(ipv4Addrs) == 0 {
		return nil, fmt.Errorf("no IPv4 addresses found for %q", host)
	}

	// Try each resolved address until one succeeds
	var lastErr error
	for _, addr := range ipv4Addrs {
		conn, err := s.DialTCP(addr, port)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all addresses failed for %q: %v", host, lastErr)
}

// Read reads data from the TCP connection
func (tc *TCPConnection) Read(buf []byte) (int, error) {
	return tc.conn.Read(buf)
}

// Write writes data to the TCP connection
func (tc *TCPConnection) Write(buf []byte) (int, error) {
	return tc.conn.Write(buf)
}

// Close closes the TCP connection
func (tc *TCPConnection) Close() error {
	return tc.conn.Close()
}

// SetReadDeadline sets the read deadline
func (tc *TCPConnection) SetReadDeadline(t time.Time) error {
	return tc.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (tc *TCPConnection) SetWriteDeadline(t time.Time) error {
	return tc.conn.SetWriteDeadline(t)
}
