// OmertaSSH - SSH client over mesh tunnel
//
// Provides SSH connectivity to VMs through the mesh tunnel network.
//
// ## Phase 1 (Current)
// Uses SSHProxy to bridge stdin/stdout to netstack TCP, allowing
// the system `ssh` command to work through the tunnel.
//
// ## Phase 2 (Planned)
// Terminal layer with RawTerminal for proper termios handling.
//
// ## Phase 3 (Planned)
// Local echo engine for mosh-like responsive typing.
//
// ## Phase 4 (Planned)
// Resilience with auto-reconnect on mesh disconnection.

@_exported import class OmertaNetwork.NetstackBridge
@_exported import class OmertaNetwork.NetstackTCPConnection
