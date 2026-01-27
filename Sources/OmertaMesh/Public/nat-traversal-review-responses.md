# Review Responses: VM Networking Plan

## Comment 1: Leaving/Destroying Networks

> Various places in the doc talk about leaving or destroying a network. What does that mean? I don't think it is possible to do either. But you can delete your peer info and ignore packets targeting a given network. Please update the doc accordingly.

**Response:** You're right. Networks aren't "destroyed" — they're just peer state. When a VM session ends:
- Delete local peer info for that network
- Stop processing packets with that network ID
- The network "ceases to exist" when no peers have state for it

Will update terminology from "leave/destroy network" to "delete peer state and stop processing network ID."

---

## Comment 2: Port Forwarding Support

> Let's have built in support for port forwarding. Can you add that to the plan and spec out the consumer changes required? Are there any protocols for port forwarding we can support?

**Response:** Yes, this is a good addition. Port forwarding allows exposing VM services through the consumer's network.

**Relevant protocols:**
- **UPnP IGD (Internet Gateway Device)** — Consumer could use UPnP to request port mappings from their router automatically
- **NAT-PMP / PCP (Port Control Protocol)** — Apple's protocol, supported by many routers
- **Manual configuration** — User specifies external port → VM port mapping

**Consumer changes needed:**
1. Port mapping configuration (which ports to forward)
2. Listen on external ports
3. Forward incoming connections through mesh to VM
4. Optionally use UPnP/NAT-PMP to open ports on consumer's router

Will add a new section specifying port forwarding protocol and consumer implementation.

---

## Comment 3: EndpointMethod Usage

> What is the EndpointMethod struct used for?

**Response:** `EndpointMethod` indicates HOW an endpoint was established, which affects:
- **Reliability expectations** — direct/publicIP are stable; holePunched may break if NAT mapping expires
- **Failover decisions** — if holePunched fails, try relay; if direct fails, something is very wrong
- **Debugging/logging** — helps understand connection path

However, looking at the current plan, it may be over-engineered for initial implementation. We could simplify to just track whether we're using relay or not.

Will clarify usage or simplify if not needed for initial implementation.

---

## Comment 4: Swift Protocol Conformance Terminology

> What do the Codable, Sendable, and Equatable literals in the TunnelEndpoint struct definition mean? Is literal the right word to describe those in a programming language?

**Response:** These are Swift **protocol conformances** (not literals):
- `Codable` — Can be serialized to/from JSON, binary, etc.
- `Sendable` — Safe to pass between concurrent contexts (Swift concurrency requirement)
- `Equatable` — Can compare two instances with `==`

The correct terminology is "protocol conformance" or just "protocols." Will add a brief note explaining these for readers unfamiliar with Swift.

---

## Comment 5: Public Struct Members

> Why is every member of the structs public? Are we not separating concerns properly?

**Response:** These are data transfer objects (DTOs) that cross module boundaries — they're defined in OmertaMesh but used by OmertaProvider and OmertaConsumer. In Swift, `public` is required for access from other modules.

For internal implementation types, we would use `internal` (the default) or `private`. The structs in the plan are intentionally public because they're part of the public API.

Could add a note clarifying which types are public API vs internal implementation.

---

## Comment 6: Never Give Up on Connections

> There is a method for endpoint failure. It's ok for an endpoint to fail, but let's make sure we never give up on a connection without user approval. We should periodically keep trying different interfaces with a backoff mechanism.

**Response:** Agreed. The `tunnelEndpointDidFail` delegate method should be renamed or reframed. Instead of "failed," we should:
1. Always keep retrying with exponential backoff
2. Try different approaches (direct → hole punch → relay → different relay)
3. Only surface to user as "degraded" or "reconnecting" state
4. Never fully give up — keep trying indefinitely until user explicitly disconnects

Will update the delegate protocol and failure handling to reflect "always reconnecting" behavior.

---

## Comment 7: Bridge/L2/L3/Sockets Confusion

> The text on bridge mode, L2, and L3 is very confused. We talk later in the document about using sockets which also doesn't seem to fit. Is a better description of what we are doing something like a proxy but without any setup on the user side? As in, we forward all traffic from the VM so it doesn't know about the proxy, but the consumer side looks like a proxy server. Does the proposed ConsumerPacketHandler look similar to existing open source proxy server code? Do we really need to handle NAT in software?

**Response:** You're right, the terminology is muddled. Let me clarify what we're actually doing:

**What we're building:**
- **Provider side:** Transparent proxy — captures all VM traffic at IP level, VM is unaware
- **Consumer side:** Proxy server — opens real connections on VM's behalf

This is similar to:
- **Transparent proxy** (like mitmproxy in transparent mode)
- **SOCKS proxy** but transparent (VM doesn't configure it)
- **slirp** (user-mode networking for QEMU) — very similar concept

**Do we need NAT?** No, not really. Since we're using userspace sockets:
- We don't rewrite packet headers
- Consumer just opens connections and relays data
- No NAT table needed

The "NAT" terminology crept in from the TUN-based approach we abandoned. With userspace sockets, it's just connection tracking (which socket belongs to which VM flow).

Will rewrite to use "transparent proxy" terminology and remove NAT references.

---

## Comment 8: VM Isolation Code Reuse

> Is 3.4 different from the existing code we have for isolation of VMs?

**Response:** Need to check existing VM isolation code. If we already have namespace/veth setup or Virtualization.framework file handle code, we should reference that instead of duplicating.

Will review existing code and either reference it or note what's new.

---

## Comment 9: Traffic Buffering and Acknowledgment

> We should buffer all traffic that isn't acknowledged by the consumer to resend later. We can acknowledge in batches.

**Response:** Good point. The mesh provides delivery but we need application-level reliability for the VM traffic flow.

**Proposed approach:**
- Provider buffers ForwardPackets until acknowledged
- Consumer sends batch acknowledgments (e.g., "received up to sequence 1234")
- Provider can resend unacknowledged packets after timeout
- Flow control: consumer can signal backpressure

This is similar to TCP's reliability layer but at the ForwardPacket level.

Will add a section on reliable delivery with buffering and batch acknowledgments.

---

## Comment 10: Similar Software

> It seems like what we are doing is a mix between a proxy and a bridge. Is there any similar software you can find online? How did they describe what they are doing? Is there anything we can learn from their implementation?

**Response:** Yes, there are similar projects:

1. **slirp / libslirp** — User-mode networking for QEMU/VMs. Exactly what we're doing: captures VM packets, handles TCP/UDP/ICMP in userspace. Used by Docker, Podman, QEMU.

2. **gvisor's netstack** — Userspace TCP/IP stack used by gVisor for container networking.

3. **Tailscale's userspace networking** — Similar transparent proxying for their VPN.

4. **sshuttle** — Transparent proxy over SSH, captures traffic and forwards.

**Terminology they use:**
- "User-mode networking" (slirp, QEMU)
- "Userspace network stack" (gvisor)
- "Transparent proxy"

**What we can learn:**
- slirp's architecture is very close to ours — worth studying
- Connection tracking patterns
- How they handle edge cases (fragmentation, ICMP errors, etc.)

Will add references to similar software and adopt "user-mode networking" terminology.

---

## Research: Similar Software Architectures

### 1. libslirp (QEMU's User-Mode Networking)

**Sources:** [libslirp GitHub](https://github.com/qemu/libslirp), [QEMU Networking Docs](https://wiki.qemu.org/Documentation/Networking), [slirp4netns GitHub](https://github.com/rootless-containers/slirp4netns)

**What it is:** A user-mode TCP/IP emulator library used by QEMU, VirtualBox, and containers. Provides virtual networking without requiring root privileges or host configuration.

**Architecture:**
- Guest sends packets to a virtual network interface
- libslirp receives packets and processes them in userspace
- Implements full TCP/IP stack: parses packets, manages TCP state, handles ICMP
- Opens real sockets on host to make actual connections
- Synthesizes response packets back to guest

**Callback-based API:**
```c
static const SlirpCb slirp_cb = {
    .send_packet = net_slirp_send_packet,    // Send packet back to guest
    .guest_error = net_slirp_guest_error,    // Handle errors
    .clock_get_ns = net_slirp_clock_get_ns,  // Time for TCP timers
    .timer_new = net_slirp_timer_new,        // TCP retransmit timers
    .timer_free = net_slirp_timer_free,
    .timer_mod = net_slirp_timer_mod,
    .register_poll_fd = net_slirp_register_poll_fd,  // Socket polling
    .unregister_poll_fd = net_slirp_unregister_poll_fd,
    .notify = net_slirp_notify,              // ACK notification for flow control
};
```

**Key insight - the `notify` callback:** When the guest ACKs data, libslirp invokes this callback. This is used for flow control — the host knows when it's safe to send more data. *This is similar to what we need for our batch acknowledgment system.*

**Default network:** Uses 10.0.2.0/24, gateway at 10.0.2.2, DHCP assigns from 10.0.2.15+

**Limitations:**
- Performance overhead from userspace processing
- ICMP generally doesn't work (can't create raw sockets without root)
- Guest not directly accessible from external network (no port forwarding by default)

**slirp4netns** (used by Podman/Docker rootless):
- Wraps libslirp for container networking
- Achieves 9.21 Gbps at MTU 65520 with optimizations
- Avoids packet copying between namespaces

---

### 2. gVisor netstack (Google's Userspace TCP/IP Stack)

**Sources:** [gVisor Networking Guide](https://gvisor.dev/docs/architecture_guide/networking/), [netstack GitHub](https://github.com/google/netstack), [gVisor Security Blog](https://gvisor.dev/blog/2020/04/02/gvisor-networking-security/)

**What it is:** A complete TCP/IP stack written in Go, used by gVisor for container sandboxing. Also used by Tailscale and wireguard-go.

**Architecture:**
- Written entirely in Go (memory-safe, no FFI)
- Link endpoints receive packets and pass up the stack
- TCP packets queued and processed by dedicated goroutines
- Outgoing packets processed through queueing discipline
- Supports AF_PACKET, AF_XDP, shared memory, Go channels as link layers

**Key design decisions:**
- Full TCP state machine implementation
- Reference-counted, pooled buffers to reduce GC pressure
- Goroutine-per-connection model (being optimized)

**Performance:** ~17 Gbps download, ~8 Gbps upload (vs ~42 Gbps native Linux)

**Why Tailscale uses it:** Enables userspace WireGuard tunneling without kernel modules. Packets processed entirely in userspace, then injected into the tunnel.

**Relevance to us:** Shows that a full userspace TCP/IP stack is viable and performant. However, it's more complex than we need — we don't need to implement TCP, just forward connections.

---

### 3. sshuttle (Transparent Proxy over SSH)

**Sources:** [sshuttle GitHub](https://github.com/sshuttle/sshuttle), [sshuttle Docs](https://sshuttle.readthedocs.io/en/stable/manpage.html)

**What it is:** A "poor man's VPN" that forwards TCP sessions over SSH. Transparent to applications.

**Key insight - Session forwarding, not packet forwarding:**
> "Unlike most VPNs, sshuttle forwards sessions, not packets."

**How it works:**
1. Uses iptables REDIRECT to capture outgoing TCP connections
2. Assembles TCP stream locally
3. Multiplexes streams over SSH (data-over-TCP, not TCP-over-TCP)
4. Disassembles back into connections at remote end

**Why this matters:**
> "You can't safely just forward TCP packets over a TCP session, because TCP's performance depends fundamentally on packet loss."

This is the **TCP-over-TCP problem**. If you tunnel TCP packets inside a TCP connection (like SSH), you get double retransmission — both the inner and outer TCP stacks try to recover from loss, causing massive performance degradation.

**sshuttle's solution:** Don't forward packets — forward *connection data*. Let the kernel handle TCP on both ends. This is exactly what our ConsumerPacketHandler does.

**Relevance to us:** Validates our approach of using userspace sockets rather than tunneling raw packets. We're doing the same thing — forwarding connection data over the mesh, not TCP packets over TCP.

---

### Comparison to Our Design

| Aspect                         | libslirp | gVisor netstack | sshuttle       | Our Design |
|--------------------------------|----------|-----------------|----------------|------------|
| Processes packets in userspace | Yes      | Yes             | No (sessions)  | Hybrid     |
| Implements TCP stack           | Yes      | Yes             | No             | No         |
| Uses real sockets for outbound | Yes      | No              | Yes            | Yes        |
| Requires root                  | No       | No              | Yes (iptables) | No         |
| Written in                     | C        | Go              | Python         | Swift      |

**Our approach is closest to sshuttle's philosophy** — forward connection data, not packets — **but with libslirp's deployment model** — no root required, transparent to VM.

---

### Lessons for Our Implementation

1. **Session-based forwarding is correct:** sshuttle proves that forwarding connection data (not packets) avoids TCP-over-TCP problems and is more efficient.

2. **Callback-based API:** libslirp's callback structure is clean — we should adopt a similar pattern for our RemoteBridge and ConsumerPacketHandler.

3. **ACK-based flow control:** libslirp's `notify` callback for ACK handling is exactly what we need for our batch acknowledgment system.

4. **TCP timers are complex:** Both libslirp and netstack implement extensive timer systems for TCP. By using real sockets, we avoid this complexity — the kernel handles it.

5. **ICMP is special:** Both libslirp and slirp4netns note ICMP limitations. We can use Network.framework on macOS for ping without root.

6. **Performance is achievable:** slirp4netns achieves 9+ Gbps, netstack achieves 17 Gbps. Userspace networking is not inherently slow.

7. **Terminology:** "User-mode networking" (libslirp) or "transparent proxy" (sshuttle) are better descriptions than "bridge" or "NAT".

---

## Comment 11: Reuse Endpoint Negotiation Code

> Re-negotiation of endpoints after disconnection should use the same flow as the initial endpoint negotiation. I just want to make sure the code here is reused and not new.

**Response:** Agreed. The plan should explicitly state that reconnection calls the same `negotiateEndpoint()` method. There should be one code path for negotiation, whether initial or recovery.

Will clarify that re-negotiation reuses the same code path.

---

## Comment 12: Time Intervals in Milliseconds

> Let's denominate the time intervals for health monitoring in ms and not seconds.

**Response:** Will update all time intervals to milliseconds:
- `minProbeInterval: 500` (was 0.5 seconds)
- `maxProbeInterval: 15000` (was 15 seconds)
- `tunnelProbeTimeout: 2500` (was implied)

---

## Comment 13: Summary First

> The summary should be the first thing in the doc. Please make sure everything coming after the summary conforms or update the summary.

**Response:** Will move summary to the top and ensure it accurately reflects the detailed sections that follow.

---

# Plan of Changes

## COMPLETED: Netstack Integration

The plan has been updated to use **gVisor netstack** on the consumer side instead of custom packet handling. Key changes made:

- Part 3b rewritten to describe netstack integration
- Go files added for netstack wrapper
- Swift/Go interop via C archive explained
- Summary updated to reflect "user-mode networking with netstack"

## Remaining Terminology Changes
1. Replace "leave/destroy network" with "delete peer state, stop processing network ID"
2. Replace remaining "bridge mode" / "L2/L3" references with "user-mode networking"
3. Change delegate method from "failed" to "reconnecting" to reflect never-give-up behavior

## Remaining Structural Changes
1. Move Summary to the top of the document
2. Add new section: Port Forwarding (UPnP/NAT-PMP, consumer changes)
3. Add new section: Reliable Delivery (buffering, batch acknowledgments)

## Remaining Content Updates
1. Clarify or simplify EndpointMethod — explain usage or remove if not needed initially
2. Add brief note explaining Swift protocol conformances for non-Swift readers
3. Note which types are public API vs internal
4. Update failure handling to "always reconnecting" with backoff
5. Check existing VM isolation code and reference instead of duplicating
6. Clarify that re-negotiation reuses the same negotiateEndpoint() code path
7. Change all time intervals to milliseconds

## Review After Changes
- Ensure summary accurately reflects all sections
- Ensure consistent terminology throughout
- Verify the architecture aligns with netstack approach
