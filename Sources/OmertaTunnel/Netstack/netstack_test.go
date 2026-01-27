package netstack

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestNetstackInit(t *testing.T) {
	cfg := Config{
		GatewayIP: "10.200.0.1",
		MTU:       1500,
	}

	stack, err := NewStack(cfg)
	if err != nil {
		t.Fatalf("Failed to create stack: %v", err)
	}
	defer stack.Stop()

	if stack.stack == nil {
		t.Error("Stack is nil")
	}
	if stack.endpoint == nil {
		t.Error("Endpoint is nil")
	}
}

func TestInjectInvalidPacket(t *testing.T) {
	cfg := Config{
		GatewayIP: "10.200.0.1",
		MTU:       1500,
	}

	stack, err := NewStack(cfg)
	if err != nil {
		t.Fatalf("Failed to create stack: %v", err)
	}
	defer stack.Stop()

	// Empty packet should fail
	if err := stack.InjectPacket(nil); err == nil {
		t.Error("Expected error for empty packet")
	}

	// Invalid IP version should fail
	badPacket := []byte{0x00, 0x01, 0x02, 0x03}
	if err := stack.InjectPacket(badPacket); err == nil {
		t.Error("Expected error for invalid IP version")
	}
}

func TestTCPForwarding(t *testing.T) {
	// Start a simple HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello from server"))
	}))
	defer server.Close()

	// Parse server address
	serverAddr := server.Listener.Addr().(*net.TCPAddr)

	cfg := Config{
		GatewayIP: "10.200.0.1",
		MTU:       1500,
	}

	stack, err := NewStack(cfg)
	if err != nil {
		t.Fatalf("Failed to create stack: %v", err)
	}
	defer stack.Stop()

	// Collect returned packets
	var returnedPackets [][]byte
	var mu sync.Mutex

	stack.SetReturnCallback(func(packet []byte) {
		mu.Lock()
		returnedPackets = append(returnedPackets, packet)
		mu.Unlock()
	})

	stack.Start()

	// Create a TCP SYN packet to the server
	// This is a simplified test - in real usage, the VM would generate these
	synPacket := createTCPSYN("10.200.0.2", 12345, serverAddr.IP.String(), uint16(serverAddr.Port))

	if err := stack.InjectPacket(synPacket); err != nil {
		t.Logf("Inject SYN (expected to process): %v", err)
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Check that we got some response packets
	mu.Lock()
	numPackets := len(returnedPackets)
	mu.Unlock()

	t.Logf("Received %d return packets", numPackets)
}

func TestUDPForwarding(t *testing.T) {
	// Start a UDP echo server
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to start UDP server: %v", err)
	}
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	// Echo server goroutine
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			serverConn.WriteToUDP(buf[:n], addr)
		}
	}()

	cfg := Config{
		GatewayIP: "10.200.0.1",
		MTU:       1500,
	}

	stack, err := NewStack(cfg)
	if err != nil {
		t.Fatalf("Failed to create stack: %v", err)
	}
	defer stack.Stop()

	var returnedPackets [][]byte
	var mu sync.Mutex

	stack.SetReturnCallback(func(packet []byte) {
		mu.Lock()
		returnedPackets = append(returnedPackets, packet)
		mu.Unlock()
	})

	stack.Start()

	// Create a UDP packet
	udpPacket := createUDPPacket("10.200.0.2", 54321, serverAddr.IP.String(), uint16(serverAddr.Port), []byte("ping"))

	if err := stack.InjectPacket(udpPacket); err != nil {
		t.Logf("Inject UDP: %v", err)
	}

	// Wait for echo
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	numPackets := len(returnedPackets)
	mu.Unlock()

	t.Logf("Received %d return packets", numPackets)
}

// TestEndToEndUDP tests real UDP echo through netstack
func TestEndToEndUDP(t *testing.T) {
	// Start a UDP echo server on all interfaces
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("Failed to start UDP server: %v", err)
	}
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)
	t.Logf("Echo server listening on %s", serverAddr)

	// Get a local non-loopback IP to use as destination
	localIP := getLocalIP(t)
	if localIP == "" {
		t.Skip("No non-loopback network interface found")
	}
	t.Logf("Using local IP: %s", localIP)

	// Echo server goroutine
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 1500)
		serverConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			t.Logf("Server read error: %v", err)
			return
		}
		t.Logf("Server received %d bytes from %s: %s", n, addr, string(buf[:n]))
		serverConn.WriteToUDP(buf[:n], addr)
	}()

	cfg := Config{
		GatewayIP: "10.200.0.1",
		MTU:       1500,
	}

	stack, err := NewStack(cfg)
	if err != nil {
		t.Fatalf("Failed to create stack: %v", err)
	}
	defer stack.Stop()

	// Collect returned packets
	var returnedPackets [][]byte
	var mu sync.Mutex
	packetReceived := make(chan struct{}, 1)

	stack.SetReturnCallback(func(packet []byte) {
		mu.Lock()
		returnedPackets = append(returnedPackets, append([]byte{}, packet...))
		mu.Unlock()
		select {
		case packetReceived <- struct{}{}:
		default:
		}
	})

	stack.Start()

	// Create and inject UDP packet
	testPayload := []byte("ECHO_TEST_12345")
	udpPacket := createUDPPacket("10.200.0.2", 54321, localIP, uint16(serverAddr.Port), testPayload)

	t.Logf("Injecting UDP packet to %s:%d", localIP, serverAddr.Port)
	if err := stack.InjectPacket(udpPacket); err != nil {
		t.Fatalf("Failed to inject packet: %v", err)
	}

	// Wait for response with timeout
	select {
	case <-packetReceived:
		t.Log("Received response packet")
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for UDP response")
	}

	// Verify we got a response with our payload
	mu.Lock()
	defer mu.Unlock()

	if len(returnedPackets) == 0 {
		t.Fatal("No packets returned")
	}

	// Parse the returned packet to verify payload
	for i, pkt := range returnedPackets {
		if len(pkt) < header.IPv4MinimumSize+header.UDPMinimumSize {
			t.Logf("Packet %d: too short (%d bytes)", i, len(pkt))
			continue
		}

		ipHdr := header.IPv4(pkt)
		if ipHdr.Protocol() != uint8(header.UDPProtocolNumber) {
			t.Logf("Packet %d: not UDP (proto=%d)", i, ipHdr.Protocol())
			continue
		}

		udpHdr := header.UDP(pkt[ipHdr.HeaderLength():])
		payload := pkt[int(ipHdr.HeaderLength())+header.UDPMinimumSize:]

		t.Logf("Packet %d: UDP from %s:%d to %s:%d, payload=%q",
			i, ipHdr.SourceAddress(), udpHdr.SourcePort(),
			ipHdr.DestinationAddress(), udpHdr.DestinationPort(),
			string(payload))

		if string(payload) == string(testPayload) {
			t.Log("SUCCESS: Echo response received with correct payload")
			return
		}
	}

	t.Error("Did not receive echo response with expected payload")
}

// TestEndToEndTCP tests real TCP connection through netstack to local HTTP server
func TestEndToEndTCP(t *testing.T) {
	// Start a local HTTP server on all interfaces
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Failed to start TCP listener: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)
	t.Logf("HTTP server listening on %s", serverAddr)

	// Get local non-loopback IP
	localIP := getLocalIP(t)
	if localIP == "" {
		t.Skip("No non-loopback network interface found")
	}
	t.Logf("Using local IP: %s", localIP)

	// Simple HTTP server
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			t.Logf("Accept error: %v", err)
			return
		}
		defer conn.Close()

		// Read request
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Logf("Server read error: %v", err)
			return
		}
		t.Logf("Server received request: %s", string(buf[:n]))

		// Send response
		response := "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nHello from netstack test server!"
		conn.Write([]byte(response))
	}()

	cfg := Config{
		GatewayIP: "10.200.0.1",
		MTU:       1500,
	}

	stack, err := NewStack(cfg)
	if err != nil {
		t.Fatalf("Failed to create stack: %v", err)
	}
	defer stack.Stop()

	// Collect returned packets
	var returnedPackets [][]byte
	var mu sync.Mutex
	packetReceived := make(chan struct{}, 10)

	stack.SetReturnCallback(func(packet []byte) {
		mu.Lock()
		returnedPackets = append(returnedPackets, append([]byte{}, packet...))
		mu.Unlock()
		select {
		case packetReceived <- struct{}{}:
		default:
		}
	})

	stack.Start()

	// TCP state machine variables
	srcIP := "10.200.0.2"
	srcPort := uint16(44444)
	seqNum := uint32(1000)
	var ackNum uint32

	targetIP := localIP
	targetPort := uint16(serverAddr.Port)

	// Step 1: Send SYN
	t.Log("Sending SYN...")
	synPacket := createTCPPacket(srcIP, srcPort, targetIP, targetPort, seqNum, 0, header.TCPFlagSyn, nil)
	if err := stack.InjectPacket(synPacket); err != nil {
		t.Fatalf("Failed to inject SYN: %v", err)
	}

	// Wait for SYN-ACK
	if !waitForTCPFlag(t, &mu, &returnedPackets, packetReceived, header.TCPFlagSyn|header.TCPFlagAck, 5*time.Second, &ackNum) {
		t.Fatal("Did not receive SYN-ACK")
	}
	t.Logf("Received SYN-ACK, server seq=%d", ackNum)

	// Step 2: Send ACK to complete handshake
	seqNum++
	ackNum++
	t.Log("Sending ACK to complete handshake...")
	ackPacket := createTCPPacket(srcIP, srcPort, targetIP, targetPort, seqNum, ackNum, header.TCPFlagAck, nil)
	if err := stack.InjectPacket(ackPacket); err != nil {
		t.Fatalf("Failed to inject ACK: %v", err)
	}

	// Step 3: Send HTTP GET request
	httpRequest := []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
	t.Log("Sending HTTP GET request...")
	dataPacket := createTCPPacket(srcIP, srcPort, targetIP, targetPort, seqNum, ackNum, header.TCPFlagAck|header.TCPFlagPsh, httpRequest)
	if err := stack.InjectPacket(dataPacket); err != nil {
		t.Fatalf("Failed to inject HTTP request: %v", err)
	}
	seqNum += uint32(len(httpRequest))

	// Wait for HTTP response data
	time.Sleep(2 * time.Second)

	// Check for HTTP response
	mu.Lock()
	defer mu.Unlock()

	var httpResponse []byte
	for _, pkt := range returnedPackets {
		if len(pkt) < header.IPv4MinimumSize {
			continue
		}
		ipHdr := header.IPv4(pkt)
		if ipHdr.Protocol() != uint8(header.TCPProtocolNumber) {
			continue
		}
		tcpHdr := header.TCP(pkt[ipHdr.HeaderLength():])
		dataOffset := int(ipHdr.HeaderLength()) + int(tcpHdr.DataOffset())
		if dataOffset < len(pkt) {
			payload := pkt[dataOffset:]
			if len(payload) > 0 {
				httpResponse = append(httpResponse, payload...)
			}
		}
	}

	t.Logf("Received %d bytes of HTTP response", len(httpResponse))
	if len(httpResponse) > 0 {
		t.Logf("Response:\n%s", string(httpResponse))
	}

	// Verify we got an HTTP response
	if len(httpResponse) == 0 {
		t.Error("No HTTP response data received")
	} else if !containsHTTPResponse(httpResponse) {
		t.Error("Response does not look like HTTP")
	} else {
		t.Log("SUCCESS: Received valid HTTP response through netstack")
	}
}

// Helper: get local non-loopback IP
func getLocalIP(t *testing.T) string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Logf("Failed to get interface addrs: %v", err)
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
				return ip4.String()
			}
		}
	}
	return ""
}

// Helper: create TCP packet with options
func createTCPPacket(srcIP string, srcPort uint16, dstIP string, dstPort uint16, seqNum, ackNum uint32, flags header.TCPFlags, payload []byte) []byte {
	tcpLen := header.TCPMinimumSize + len(payload)
	ipLen := header.IPv4MinimumSize + tcpLen
	packet := make([]byte, ipLen)

	// IPv4 header
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(ipLen),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     tcpipAddrFromString(srcIP),
		DstAddr:     tcpipAddrFromString(dstIP),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	// TCP header
	tcp := header.TCP(packet[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seqNum,
		AckNum:     ackNum,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: 65535,
	})

	// Copy payload
	if len(payload) > 0 {
		copy(packet[header.IPv4MinimumSize+header.TCPMinimumSize:], payload)
	}

	// TCP checksum
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber,
		tcpipAddrFromString(srcIP), tcpipAddrFromString(dstIP), uint16(tcpLen))
	xsum = checksum.Checksum(packet[header.IPv4MinimumSize:], xsum)
	tcp.SetChecksum(^xsum)

	return packet
}

// Helper: wait for TCP packet with specific flags
func waitForTCPFlag(t *testing.T, mu *sync.Mutex, packets *[][]byte, notify <-chan struct{}, expectedFlags header.TCPFlags, timeout time.Duration, outAckNum *uint32) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-notify:
		case <-time.After(100 * time.Millisecond):
		}

		mu.Lock()
		for _, pkt := range *packets {
			if len(pkt) < header.IPv4MinimumSize {
				continue
			}
			ipHdr := header.IPv4(pkt)
			if ipHdr.Protocol() != uint8(header.TCPProtocolNumber) {
				continue
			}
			tcpHdr := header.TCP(pkt[ipHdr.HeaderLength():])
			if tcpHdr.Flags()&expectedFlags == expectedFlags {
				if outAckNum != nil {
					*outAckNum = tcpHdr.SequenceNumber()
				}
				mu.Unlock()
				return true
			}
		}
		mu.Unlock()
	}
	return false
}

// Helper: check if data looks like HTTP response
func containsHTTPResponse(data []byte) bool {
	s := string(data)
	return len(s) > 10 && (s[:4] == "HTTP" || contains(s, "HTTP/1"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && (s[:len(substr)] == substr || contains(s[1:], substr)))
}

func BenchmarkPacketInjection(b *testing.B) {
	cfg := Config{
		GatewayIP: "10.200.0.1",
		MTU:       1500,
	}

	stack, err := NewStack(cfg)
	if err != nil {
		b.Fatalf("Failed to create stack: %v", err)
	}
	defer stack.Stop()

	stack.SetReturnCallback(func(packet []byte) {
		// Discard
	})

	stack.Start()

	// Create a test packet
	packet := createUDPPacket("10.200.0.2", 12345, "1.1.1.1", 53, []byte("test"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stack.InjectPacket(packet)
	}
}

// Helper functions to create test packets

func createTCPSYN(srcIP string, srcPort uint16, dstIP string, dstPort uint16) []byte {
	// Create a minimal IPv4 + TCP SYN packet
	ipLen := header.IPv4MinimumSize + header.TCPMinimumSize
	packet := make([]byte, ipLen)

	// IPv4 header
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(ipLen),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     tcpipAddrFromString(srcIP),
		DstAddr:     tcpipAddrFromString(dstIP),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	// TCP header
	tcp := header.TCP(packet[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     1,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})

	return packet
}

func createUDPPacket(srcIP string, srcPort uint16, dstIP string, dstPort uint16, payload []byte) []byte {
	ipLen := header.IPv4MinimumSize + header.UDPMinimumSize + len(payload)
	packet := make([]byte, ipLen)

	// IPv4 header
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(ipLen),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpipAddrFromString(srcIP),
		DstAddr:     tcpipAddrFromString(dstIP),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	// UDP header
	udp := header.UDP(packet[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})

	// Payload
	copy(packet[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)

	return packet
}

func tcpipAddrFromString(s string) tcpip.Address {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return tcpip.Address{}
	}
	return tcpip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]})
}
