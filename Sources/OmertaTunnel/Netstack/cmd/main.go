package main

/*
#include <stdlib.h>
#include <stdint.h>

// Callback type for returning packets to Swift
typedef void (*ReturnPacketCallback)(void* context, const uint8_t* data, size_t len);

// Helper function to invoke the callback (can't call function pointers directly from Go)
static inline void invokeCallback(ReturnPacketCallback cb, void* ctx, const uint8_t* data, size_t len) {
    if (cb != NULL) {
        cb(ctx, data, len);
    }
}
*/
import "C"
import (
	"sync"
	"time"
	"unsafe"

	netstack "github.com/omerta/tunnel-netstack"
)

// Global registry for stack instances
var (
	stacksMu  sync.RWMutex
	stacks    = make(map[uint64]*netstack.Stack)
	nextID    uint64 = 1
	callbacks = make(map[uint64]C.ReturnPacketCallback)
	contexts  = make(map[uint64]unsafe.Pointer)
)

// Global registry for TCP connections
var (
	connsMu    sync.RWMutex
	conns      = make(map[uint64]*netstack.TCPConnection)
	nextConnID uint64 = 1
)

//export NetstackCreate
// NetstackCreate creates a new netstack instance.
// Returns a handle (>0) on success, 0 on failure.
// gatewayIP should be like "10.200.0.1"
func NetstackCreate(gatewayIP *C.char, mtu C.uint32_t) C.uint64_t {
	cfg := netstack.Config{
		GatewayIP: C.GoString(gatewayIP),
		MTU:       uint32(mtu),
	}

	stack, err := netstack.NewStack(cfg)
	if err != nil {
		return 0
	}

	stacksMu.Lock()
	id := nextID
	nextID++
	stacks[id] = stack
	stacksMu.Unlock()

	return C.uint64_t(id)
}

//export NetstackSetCallback
// NetstackSetCallback sets the callback for returning packets.
// context is passed back to the callback (typically a Swift object pointer).
func NetstackSetCallback(handle C.uint64_t, callback C.ReturnPacketCallback, context unsafe.Pointer) {
	stacksMu.Lock()
	stack, ok := stacks[uint64(handle)]
	if ok {
		callbacks[uint64(handle)] = callback
		contexts[uint64(handle)] = context

		// Set up the Go callback that calls the C callback
		stack.SetReturnCallback(func(packet []byte) {
			stacksMu.RLock()
			cb := callbacks[uint64(handle)]
			ctx := contexts[uint64(handle)]
			stacksMu.RUnlock()

			if cb != nil && len(packet) > 0 {
				C.invokeCallback(cb, ctx, (*C.uint8_t)(unsafe.Pointer(&packet[0])), C.size_t(len(packet)))
			}
		})
	}
	stacksMu.Unlock()
}

//export NetstackStart
// NetstackStart starts the netstack processing.
func NetstackStart(handle C.uint64_t) C.int {
	stacksMu.RLock()
	stack, ok := stacks[uint64(handle)]
	stacksMu.RUnlock()

	if !ok {
		return -1
	}

	stack.Start()
	return 0
}

//export NetstackStop
// NetstackStop stops and destroys the netstack instance.
func NetstackStop(handle C.uint64_t) {
	stacksMu.Lock()
	stack, ok := stacks[uint64(handle)]
	if ok {
		delete(stacks, uint64(handle))
		delete(callbacks, uint64(handle))
		delete(contexts, uint64(handle))
	}
	stacksMu.Unlock()

	if ok {
		stack.Stop()
	}
}

//export NetstackInjectPacket
// NetstackInjectPacket injects a raw IP packet into the stack.
// Returns 0 on success, -1 on error.
func NetstackInjectPacket(handle C.uint64_t, data *C.uint8_t, len C.size_t) C.int {
	stacksMu.RLock()
	stack, ok := stacks[uint64(handle)]
	stacksMu.RUnlock()

	if !ok {
		return -1
	}

	// Copy packet data from C memory
	packet := C.GoBytes(unsafe.Pointer(data), C.int(len))

	if err := stack.InjectPacket(packet); err != nil {
		return -1
	}

	return 0
}

//export NetstackGetStats
// NetstackGetStats returns statistics about the stack.
// Writes to the provided pointers.
func NetstackGetStats(handle C.uint64_t, tcpConns *C.uint32_t, udpConns *C.uint32_t) C.int {
	stacksMu.RLock()
	stack, ok := stacks[uint64(handle)]
	stacksMu.RUnlock()

	if !ok {
		return -1
	}

	stats := stack.GetStats()
	*tcpConns = C.uint32_t(stats.TCPConns)
	*udpConns = C.uint32_t(stats.UDPConns)

	return 0
}

//export NetstackDialTCP
// NetstackDialTCP creates a TCP connection to the specified host:port through the stack.
// Returns a connection handle (>0) on success, 0 on failure.
func NetstackDialTCP(stackHandle C.uint64_t, host *C.char, port C.uint16_t) C.uint64_t {
	stacksMu.RLock()
	stack, ok := stacks[uint64(stackHandle)]
	stacksMu.RUnlock()

	if !ok {
		return 0
	}

	conn, err := stack.DialTCP(C.GoString(host), uint16(port))
	if err != nil {
		return 0
	}

	connsMu.Lock()
	id := nextConnID
	nextConnID++
	conns[id] = conn
	connsMu.Unlock()

	return C.uint64_t(id)
}

//export NetstackDialTCPByName
// NetstackDialTCPByName resolves a hostname via DNS through the stack's network,
// then creates a TCP connection to the resolved address.
// Returns a connection handle (>0) on success, 0 on failure.
func NetstackDialTCPByName(stackHandle C.uint64_t, host *C.char, port C.uint16_t) C.uint64_t {
	stacksMu.RLock()
	stack, ok := stacks[uint64(stackHandle)]
	stacksMu.RUnlock()

	if !ok {
		return 0
	}

	conn, err := stack.DialTCPByName(C.GoString(host), uint16(port))
	if err != nil {
		return 0
	}

	connsMu.Lock()
	id := nextConnID
	nextConnID++
	conns[id] = conn
	connsMu.Unlock()

	return C.uint64_t(id)
}

//export NetstackConnRead
// NetstackConnRead reads data from a TCP connection.
// Returns number of bytes read, 0 on EOF, -1 on error.
func NetstackConnRead(connHandle C.uint64_t, buf *C.uint8_t, maxLen C.size_t) C.int {
	connsMu.RLock()
	conn, ok := conns[uint64(connHandle)]
	connsMu.RUnlock()

	if !ok {
		return -1
	}

	// Create Go slice backed by C buffer
	goBuf := make([]byte, int(maxLen))

	n, err := conn.Read(goBuf)
	if err != nil {
		if n > 0 {
			// Copy partial read
			for i := 0; i < n; i++ {
				*(*C.uint8_t)(unsafe.Pointer(uintptr(unsafe.Pointer(buf)) + uintptr(i))) = C.uint8_t(goBuf[i])
			}
			return C.int(n)
		}
		return -1
	}

	// Copy to C buffer
	for i := 0; i < n; i++ {
		*(*C.uint8_t)(unsafe.Pointer(uintptr(unsafe.Pointer(buf)) + uintptr(i))) = C.uint8_t(goBuf[i])
	}

	return C.int(n)
}

//export NetstackConnWrite
// NetstackConnWrite writes data to a TCP connection.
// Returns number of bytes written, -1 on error.
func NetstackConnWrite(connHandle C.uint64_t, buf *C.uint8_t, len C.size_t) C.int {
	connsMu.RLock()
	conn, ok := conns[uint64(connHandle)]
	connsMu.RUnlock()

	if !ok {
		return -1
	}

	// Copy from C buffer
	data := C.GoBytes(unsafe.Pointer(buf), C.int(len))

	n, err := conn.Write(data)
	if err != nil {
		if n > 0 {
			return C.int(n)
		}
		return -1
	}

	return C.int(n)
}

//export NetstackConnClose
// NetstackConnClose closes a TCP connection.
func NetstackConnClose(connHandle C.uint64_t) {
	connsMu.Lock()
	conn, ok := conns[uint64(connHandle)]
	if ok {
		delete(conns, uint64(connHandle))
	}
	connsMu.Unlock()

	if ok {
		conn.Close()
	}
}

//export NetstackConnSetReadDeadline
// NetstackConnSetReadDeadline sets the read deadline in milliseconds from now.
// Use 0 to clear the deadline.
func NetstackConnSetReadDeadline(connHandle C.uint64_t, milliseconds C.int64_t) C.int {
	connsMu.RLock()
	conn, ok := conns[uint64(connHandle)]
	connsMu.RUnlock()

	if !ok {
		return -1
	}

	var deadline time.Time
	if milliseconds > 0 {
		deadline = time.Now().Add(time.Duration(milliseconds) * time.Millisecond)
	}

	if err := conn.SetReadDeadline(deadline); err != nil {
		return -1
	}

	return 0
}

//export NetstackConnSetWriteDeadline
// NetstackConnSetWriteDeadline sets the write deadline in milliseconds from now.
// Use 0 to clear the deadline.
func NetstackConnSetWriteDeadline(connHandle C.uint64_t, milliseconds C.int64_t) C.int {
	connsMu.RLock()
	conn, ok := conns[uint64(connHandle)]
	connsMu.RUnlock()

	if !ok {
		return -1
	}

	var deadline time.Time
	if milliseconds > 0 {
		deadline = time.Now().Add(time.Duration(milliseconds) * time.Millisecond)
	}

	if err := conn.SetWriteDeadline(deadline); err != nil {
		return -1
	}

	return 0
}

func main() {}
