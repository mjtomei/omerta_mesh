# In-VM Mesh Daemon

> **Context:** VMs run omertad inside the guest and join the mesh as first-class
> peers. The provider host does not proxy VM packets — the VM handles its own
> mesh participation. This plan covers getting omertad built, installed, and
> running inside VMs so they can join the virtual network.
>
> **Leads into:** VIRTUAL_NETWORK_REWORK.md Phase 15 (VM Network Integration),
> which assumes the daemon is already running in the VM and tests SSH, ping,
> and multi-VM communication.
>
> **Replaces:** TUNNEL_INFRASTRUCTURE.md Phase 1 (VMPacketCapture). The
> external packet capture approach is superseded by this in-VM daemon model.
>
> **Related plans:**
> - VIRTUAL_NETWORK_REWORK.md — virtual network architecture, phases 1-16
> - TUNNEL_INFRASTRUCTURE.md — health monitoring, failure handling, cleanup
> - GOSSIP_RELAY_PLAN.md — relay discovery gossip

## Overview

Each VM is a full mesh participant:

```
┌─────────────────────────────────────────────────────┐
│  VM Guest                                           │
│                                                     │
│  ┌──────────┐    ┌──────────────────────────────┐   │
│  │ sshd,    │    │ omertad                      │   │
│  │ apps     │    │ ├── MeshNetwork (joins mesh) │   │
│  │          │    │ ├── TUN or netstack interface │   │
│  │          │    │ ├── DHCPClient (gets IP)      │   │
│  └────┬─────┘    │ ├── PacketRouter             │   │
│       │          │ └── VirtualNetwork            │   │
│       │          └──────────┬───────────────────┘   │
│       └─────────────────────┘                       │
│              (omerta0 interface or netstack)         │
└─────────────────────────────────────────────────────┘
          │ (mesh UDP traffic)
          ▼
    Provider's physical network → mesh peers
```

The provider host's only job is to run the VM hypervisor. It does not
intercept, route, or proxy any VM traffic. Network isolation comes from
the VM itself: the only network path the guest uses is the mesh.

**Advantages over external packet capture:**
- VM is a real mesh peer with its own MachineId and PeerId
- No provider-side packet routing code needed
- VM can talk directly to any mesh peer (not just through the provider)
- Standard omertad — same binary inside and outside VMs
- Simpler provider: just hypervisor management

---

## Phase 1: VM Image with omertad

**Goal:** Build a VM base image that includes omertad and is configured to
run it on boot. The image is reusable across providers.

### Image Requirements

| Requirement | Details |
|-------------|---------|
| Base OS | Ubuntu 24.04 minimal cloud image |
| omertad binary | Statically linked Linux/amd64 (or arm64) |
| Auto-start | systemd unit starts omertad on boot |
| Configuration | Cloud-init injects mesh network key + bootstrap peers |
| SSH | openssh-server installed, key-based auth only |
| Minimal | No GUI, no unnecessary packages |

### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaVM/ImageBuilder.swift` | Builds/customizes VM images with omertad |
| `Sources/OmertaVM/OmertadSystemdUnit.swift` | Generates systemd unit file for omertad |
| `vm-images/cloud-init/omertad.service` | systemd service template |
| `vm-images/cloud-init/omertad-setup.sh` | First-boot setup script |
| `Tests/OmertaVMTests/ImageBuilderTests.swift` | Image builder tests |

### systemd Unit

```ini
# omertad.service — installed at /etc/systemd/system/omertad.service
[Unit]
Description=Omerta Mesh Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/omertad start \
    --config /etc/omerta/mesh.json \
    --vpn
Restart=always
RestartSec=5
Environment=OMERTA_LOG_LEVEL=info

[Install]
WantedBy=multi-user.target
```

### Cloud-Init Configuration

Cloud-init injects per-VM configuration at boot. The provider generates this
for each VM instance.

```yaml
#cloud-config
write_files:
  - path: /etc/omerta/mesh.json
    content: |
      {
        "networkKey": "<base64-encoded-network-key>",
        "bootstrapPeers": ["<provider-peer>@<provider-endpoint>"],
        "enableVPN": true
      }
    permissions: '0600'

  - path: /etc/omerta/identity.json
    content: |
      {
        "machineId": "<generated-uuid>",
        "keypair": "<generated-keypair>"
      }
    permissions: '0600'

runcmd:
  - systemctl enable --now omertad.service
```

### API

```swift
/// Generates cloud-init configuration for a VM joining the mesh.
public struct CloudInitGenerator {
    /// Generate cloud-init user-data for a VM.
    ///
    /// - Parameters:
    ///   - networkKey: The mesh network encryption key
    ///   - bootstrapPeers: Peers the VM should connect to (typically the provider)
    ///   - machineId: Pre-generated MachineId for the VM
    ///   - keypair: Pre-generated identity keypair for the VM
    ///   - sshAuthorizedKeys: SSH public keys to install
    /// - Returns: Cloud-init user-data as a string
    public static func generate(
        networkKey: Data,
        bootstrapPeers: [String],
        machineId: MachineId,
        keypair: IdentityKeypair,
        sshAuthorizedKeys: [String]
    ) throws -> String
}

/// Builds or customizes a VM image with omertad installed.
public struct ImageBuilder {
    /// Path to the base cloud image
    public let baseImagePath: String

    /// Verify the base image has the expected omertad binary.
    /// Images are pre-built with omertad baked in.
    public func verify() async throws -> ImageInfo

    /// Generate a cloud-init ISO for a specific VM instance.
    /// This ISO is attached to the VM at boot.
    public func generateCloudInitISO(
        config: CloudInitGenerator,
        outputPath: String
    ) async throws
}

public struct ImageInfo {
    public let omertadVersion: String
    public let arch: String  // "amd64" or "arm64"
    public let baseOS: String
}
```

### Image Build Process

The omertad binary is baked into the base image (not downloaded at boot):

```
1. Start with Ubuntu 24.04 cloud image
2. Mount image, chroot in
3. Copy statically-linked omertad to /usr/local/bin/
4. Install omertad.service systemd unit
5. Install openssh-server
6. Shrink and seal image
7. Store as base image (reused across all VMs)

Per-VM customization (at boot):
- Cloud-init ISO provides: network key, bootstrap peers, machine identity, SSH keys
- omertad reads /etc/omerta/mesh.json and joins the mesh
```

### Unit Tests

| Test | Description |
|------|-------------|
| `testCloudInitGeneration` | Generate cloud-init, verify YAML is valid |
| `testCloudInitContainsNetworkKey` | Verify network key is included |
| `testCloudInitContainsBootstrap` | Verify bootstrap peers are included |
| `testCloudInitContainsMachineId` | Verify machine identity is included |
| `testCloudInitContainsSSHKeys` | Verify SSH authorized keys are included |
| `testSystemdUnitGeneration` | Verify unit file is valid |

---

## Phase 2: VM Lifecycle Manager

**Goal:** Create VMManager to launch, monitor, and tear down VMs.
VMManager is platform-specific (Linux KVM/QEMU, macOS Virtualization.framework).

### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaVM/VMManager.swift` | VM lifecycle: create, start, stop, destroy |
| `Sources/OmertaVM/VMConfig.swift` | VM configuration (CPU, memory, disk, network) |
| `Sources/OmertaVM/VMInstance.swift` | Running VM state and monitoring |
| `Sources/OmertaVM/Platform/LinuxVMPlatform.swift` | KVM/QEMU backend |
| `Sources/OmertaVM/Platform/MacOSVMPlatform.swift` | Virtualization.framework backend |
| `Sources/OmertaVM/Platform/VMPlatform.swift` | Platform protocol |
| `Tests/OmertaVMTests/VMManagerTests.swift` | Lifecycle tests |

### Architecture

```
┌────────────────────────────────────────────────────┐
│  VMManager                                         │
│  ├── instances: [UUID: VMInstance]                  │
│  ├── platform: VMPlatform                          │
│  │                                                 │
│  │  create(config) → VMInstance                    │
│  │  start(vmId) — boots VM, attaches cloud-init   │
│  │  stop(vmId) — graceful shutdown                 │
│  │  destroy(vmId) — remove VM and disk             │
│  │  waitForMeshJoin(vmId) — polls until VM peer    │
│  │                          appears in mesh        │
│  └─────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────┐  ┌──────────────────────────┐
│ LinuxVMPlatform     │  │ MacOSVMPlatform          │
│ - QEMU/KVM          │  │ - Virtualization.fwk     │
│ - virsh / libvirt   │  │ - VZVirtualMachine       │
│ - cloud-init ISO    │  │ - cloud-init via aux     │
└─────────────────────┘  └──────────────────────────┘
```

### API

```swift
/// Platform-specific VM hypervisor backend.
public protocol VMPlatform: Sendable {
    func createVM(config: VMConfig, cloudInitISO: String) async throws -> VMHandle
    func startVM(_ handle: VMHandle) async throws
    func stopVM(_ handle: VMHandle) async throws
    func destroyVM(_ handle: VMHandle) async throws
    func vmState(_ handle: VMHandle) async -> VMState

    static var isAvailable: Bool { get }
}

public struct VMHandle: Sendable {
    public let id: UUID
    public let platformData: Data  // opaque platform-specific state
}

public enum VMState: Sendable {
    case creating
    case booting
    case running
    case stopping
    case stopped
    case failed(String)
}

/// VM resource configuration.
public struct VMConfig: Sendable {
    public var cpuCount: Int = 2
    public var memoryMB: Int = 2048
    public var diskGB: Int = 20
    public var baseImagePath: String
    public var name: String
}

/// Manages VM lifecycle. Does NOT manage networking — the VM handles
/// that itself by running omertad.
public actor VMManager {
    private let platform: any VMPlatform
    private var instances: [UUID: VMInstance] = [:]
    private let imageBuilder: ImageBuilder

    public init(platform: any VMPlatform, imageBuilder: ImageBuilder)

    /// Create and boot a VM that joins the mesh.
    ///
    /// 1. Generates MachineId and identity keypair for the VM
    /// 2. Creates cloud-init ISO with mesh config
    /// 3. Launches VM via platform backend
    /// 4. Returns immediately — VM boots in background
    public func createVM(
        config: VMConfig,
        networkKey: Data,
        bootstrapPeers: [String],
        sshAuthorizedKeys: [String]
    ) async throws -> UUID

    /// Wait for a VM's omertad to join the mesh and obtain an IP.
    /// Polls the mesh peer list until the VM's MachineId appears.
    ///
    /// - Parameters:
    ///   - vmId: The VM's UUID
    ///   - mesh: The mesh network to check for the VM's peer
    ///   - timeout: Max time to wait
    /// - Returns: The VM's mesh IP address
    public func waitForMeshJoin(
        vmId: UUID,
        mesh: MeshNetwork,
        timeout: Duration = .seconds(120)
    ) async throws -> String

    /// Stop a VM gracefully.
    public func stopVM(_ vmId: UUID) async throws

    /// Destroy a VM and its disk.
    public func destroyVM(_ vmId: UUID) async throws

    /// Get the MachineId assigned to a VM (generated at create time).
    public func machineId(for vmId: UUID) -> MachineId?

    /// List all managed VMs.
    public var allVMs: [VMInstance] { get }
}

/// State of a managed VM.
public struct VMInstance: Sendable {
    public let vmId: UUID
    public let machineId: MachineId
    public let config: VMConfig
    public var state: VMState
    public var meshIP: String?      // set after mesh join
    public var createdAt: Date
}
```

### Network Isolation

The VM gets network connectivity solely through omertad's TUN interface:

**Linux (KVM/QEMU):**
```
VM has a single virtio-net interface connected to a TAP device.
The TAP device is in an isolated network namespace on the host.
omertad inside the VM creates the omerta0 TUN interface.
The virtio-net interface is used ONLY for mesh UDP traffic to the
bootstrap peer (the provider host). All application traffic goes
through omerta0 → mesh.
```

**macOS (Virtualization.framework):**
```
VM has a VZNATNetworkDeviceAttachment for initial mesh connectivity.
omertad inside the VM creates omerta0.
Application traffic goes through omerta0 → mesh.
NAT attachment is only used for mesh UDP to bootstrap.
```

The VM needs one path to reach its bootstrap peer (the provider). After
that, all application traffic routes through the mesh virtual network.

### Unit Tests

| Test | Description |
|------|-------------|
| `testCreateVMGeneratesMachineId` | Create VM, verify unique MachineId generated |
| `testCreateVMGeneratesCloudInit` | Create VM, verify cloud-init ISO created |
| `testStopVM` | Start then stop, verify state transitions |
| `testDestroyVMCleansUp` | Destroy VM, verify disk removed |
| `testWaitForMeshJoinTimeout` | VM never joins, verify timeout error |
| `testMultipleVMs` | Create 3 VMs, verify independent MachineIds |

---

## Phase 3: Provider Daemon Integration

**Goal:** Wire VMManager into the provider daemon so consumers can request
VMs over the mesh.

### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaProvider/MeshProviderDaemon.swift` | Provider daemon: handles VM requests over mesh |
| `Sources/OmertaProvider/ProviderConfig.swift` | Provider configuration |
| `Tests/OmertaProviderTests/ProviderDaemonTests.swift` | Provider tests |

### Files to Modify

| File | Changes |
|------|---------|
| `Package.swift` | Add OmertaVM and OmertaProvider targets |

### API

```swift
/// Provider daemon — runs on machines that host VMs.
/// Listens for VM requests over the mesh and manages VM lifecycle.
public actor MeshProviderDaemon {
    private let mesh: MeshNetwork
    private let vmManager: VMManager
    private let config: ProviderConfig

    public init(
        mesh: MeshNetwork,
        vmManager: VMManager,
        config: ProviderConfig
    )

    /// Start listening for VM requests on the "vm-request" channel.
    public func start() async throws

    /// Stop the provider and all managed VMs.
    public func stop() async

    /// Current VM count.
    public var activeVMCount: Int { get }
}

public struct ProviderConfig: Sendable {
    /// Maximum number of concurrent VMs
    public var maxVMs: Int = 5

    /// Default VM resources
    public var defaultVMConfig: VMConfig

    /// Path to base VM image with omertad
    public var baseImagePath: String
}
```

### VM Request Flow

```
Consumer                          Provider
   │                                 │
   │  "vm-request" channel           │
   │  { sshKeys, resources }    ──→  │
   │                                 │  1. Generate MachineId + keypair
   │                                 │  2. Create cloud-init ISO
   │                                 │  3. Launch VM via VMPlatform
   │                                 │  4. Wait for mesh join
   │  "vm-response" channel          │
   │  { machineId, meshIP }     ←──  │
   │                                 │
   │  Consumer can now:              │
   │  - ssh user@<meshIP>            │
   │  - omerta ssh user@<meshIP>     │
   │  - ping <meshIP>                │
```

The provider passes its own endpoint as the bootstrap peer for the VM.
The VM connects to the provider via its NAT/TAP interface, joins the
mesh, obtains an IP via DHCP from the gateway, and becomes reachable
by all mesh peers.

### Unit Tests

| Test | Description |
|------|-------------|
| `testProviderHandlesVMRequest` | Send request, verify VM created |
| `testProviderRejectsAtCapacity` | At maxVMs, verify rejection |
| `testProviderReturnsVMInfo` | Verify response contains machineId and meshIP |
| `testProviderStopCleansUpVMs` | Stop provider, verify all VMs stopped |

---

## Phase 4: Bootstrap Connectivity

**Goal:** Ensure the VM can reach its bootstrap peer (the provider host)
to join the mesh. After joining, all traffic flows through the mesh
virtual network.

### Problem

The VM needs UDP connectivity to the provider to bootstrap into the mesh.
But the VM shouldn't have general internet or LAN access — only mesh access.

### Solution

The VM gets minimal host connectivity solely for mesh bootstrap:

**Linux:**
```bash
# Provider creates a TAP device for the VM in a restricted namespace
ip tuntap add mode tap vm-tap-${VM_ID}
ip addr add 192.168.100.1/30 dev vm-tap-${VM_ID}
ip link set vm-tap-${VM_ID} up

# VM cloud-init configures its eth0:
# - IP: 192.168.100.2/30
# - Default route: 192.168.100.1
# - DNS: none (DNS goes through mesh after join)

# Provider runs omertad on the host, listening on 192.168.100.1
# VM's omertad bootstraps to 192.168.100.1:<port>

# After mesh join:
# - omertad creates omerta0 TUN interface
# - All application traffic routes through omerta0
# - eth0 carries only mesh UDP to provider
```

**macOS:**
```swift
// VZNATNetworkDeviceAttachment gives VM a private NAT interface
// VM can reach the host's mesh port through the NAT
// After mesh join, omerta0 handles application traffic
```

### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaVM/Platform/LinuxBootstrapNetwork.swift` | TAP device setup for VM bootstrap |
| `vm-images/cloud-init/configure-bootstrap.sh` | Guest-side bootstrap network config |

### Cloud-Init Addition

```yaml
# Added to cloud-init user-data
write_files:
  - path: /etc/omerta/bootstrap-network.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      # Configure eth0 for mesh bootstrap only
      ip addr add 192.168.100.2/30 dev eth0
      ip link set eth0 up
      ip route add default via 192.168.100.1

bootcmd:
  - /etc/omerta/bootstrap-network.sh
```

### Post-Join Routing

Once omertad joins the mesh and creates the TUN interface:

```
omerta0 (10.0.x.x/16) — all application traffic
  - Default route for 10.0.0.0/16 → omerta0
  - Default route for 0.0.0.0/0 → omerta0 (internet via gateway)

eth0 (192.168.100.2/30) — mesh UDP only
  - Route to 192.168.100.1/30 → eth0 (bootstrap peer)
  - No other routes on eth0
```

Applications (sshd, curl, ping) use omerta0. The only traffic on eth0
is encrypted mesh UDP between the VM's omertad and the provider's omertad.

### Unit Tests

| Test | Description |
|------|-------------|
| `testTAPDeviceCreated` | Verify TAP device exists after VM create |
| `testTAPDeviceCleanedUp` | Verify TAP device removed after VM destroy |
| `testBootstrapNetworkConfig` | Verify cloud-init contains bootstrap network |
| `testVMCanReachProvider` | VM can ping provider's TAP IP |
| `testVMCannotReachLAN` | VM cannot ping provider's LAN IP |

---

## Handoff to VIRTUAL_NETWORK_REWORK Phase 15

After completing phases 1-4, the system is ready for Phase 15 of
VIRTUAL_NETWORK_REWORK.md, which tests:

- VM boots and joins mesh (`waitForMeshJoin`)
- VM obtains IP via DHCP
- SSH to VM over mesh (OmertaSSH and standard SSH via TUN)
- VM-to-VM communication
- Consumer with TUN can `ssh omerta@10.0.x.x`

The in-VM daemon model means Phase 15 tests work without any special
provider-side packet routing — the VM is just another mesh peer.
