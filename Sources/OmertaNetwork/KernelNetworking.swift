// KernelNetworking.swift - Kernel IP forwarding and NAT masquerade helpers
//
// Configures Linux kernel networking for gateway bridge mode:
// - ip_forward: allows the kernel to route packets between interfaces
// - iptables MASQUERADE: source-NATs packets exiting to the real internet

#if os(Linux)
import Foundation
import Glibc
import Logging

public enum KernelNetworking {
    private static let logger = Logger(label: "io.omerta.network.kernel")

    /// Check that kernel networking tools are available.
    /// Call before enableForwarding/enableMasquerade to get clear errors.
    public static func preflight() throws {
        guard Glibc.access("/proc/sys/net/ipv4/ip_forward", F_OK) == 0 else {
            throw InterfaceError.preflightFailed(
                "/proc/sys/net/ipv4/ip_forward not found. "
                + "procfs may not be mounted (required for kernel networking).")
        }
        let hasNft = Glibc.access("/usr/sbin/nft", X_OK) == 0
        let hasIptablesLegacy = Glibc.access("/sbin/iptables-legacy", X_OK) == 0
        let hasIptables = Glibc.access("/sbin/iptables", X_OK) == 0
        guard hasNft || hasIptablesLegacy || hasIptables else {
            throw InterfaceError.preflightFailed(
                "No firewall tool found. Need one of: /usr/sbin/nft, "
                + "/sbin/iptables-legacy, /sbin/iptables. "
                + "Install nftables (apt install nftables) or iptables (apt install iptables).")
        }
        guard Glibc.access("/sbin/ip", X_OK) == 0 else {
            throw InterfaceError.preflightFailed(
                "/sbin/ip not found. Install iproute2 (e.g. apt install iproute2).")
        }
    }

    /// Enable kernel IP forwarding
    public static func enableForwarding() throws {
        let path = "/proc/sys/net/ipv4/ip_forward"
        let fd = Glibc.open(path, O_WRONLY)
        guard fd >= 0 else {
            let e = errno
            let hint = e == EACCES ? " (permission denied — run as root)"
                : e == ENOENT ? " (procfs not mounted?)" : ""
            throw InterfaceError.writeFailed(
                "Cannot open \(path): \(String(cString: strerror(e)))\(hint)")
        }
        let written = "1".withCString { Glibc.write(fd, $0, 1) }
        Glibc.close(fd)
        guard written == 1 else {
            throw InterfaceError.writeFailed("Failed to write to \(path): errno \(errno)")
        }
        logger.info("Enabled ip_forward")
    }

    /// Set reverse path filtering to loose mode (2) for a TUN interface.
    /// Loose mode still validates source IPs exist in the routing table but
    /// allows asymmetric routing — required so the kernel doesn't drop packets
    /// with source IPs arriving on the "wrong" interface (e.g. mesh peer IPs
    /// arriving on the gateway TUN).
    public static func looseRPFilter(tunName: String) {
        // Only set the per-interface value. The kernel uses max(all, interface),
        // so setting the TUN to 2 (loose) is sufficient regardless of the global setting.
        writeProcSys("/proc/sys/net/ipv4/conf/\(tunName)/rp_filter", value: "2")
        logger.info("Set rp_filter to loose mode (2)", metadata: ["tun": "\(tunName)"])
    }

    /// Set up MASQUERADE for a TUN interface so packets exiting through the
    /// kernel get source-NATted to the host's real IP.
    ///
    /// Tries backends in order: iptables-legacy, nft, iptables (nft backend).
    /// The iptables-nft backend can silently fail on systems with complex
    /// nftables rulesets (e.g. Docker), so we prefer iptables-legacy or raw nft.
    ///
    /// Note: call looseRPFilter(tunName:) separately after the TUN device is created,
    /// since the per-interface procfs entry only exists after creation.
    public static func enableMasquerade(tunName: String, outInterface: String, sourceSubnet: String) throws {
        let backend = detectFirewallBackend()
        logger.info("Using firewall backend: \(backend)")

        switch backend {
        case .iptablesLegacy:
            try enableMasqueradeIptables(tunName: tunName, outInterface: outInterface, sourceSubnet: sourceSubnet, binary: "/sbin/iptables-legacy")
        case .nft:
            try enableMasqueradeNft(tunName: tunName, outInterface: outInterface, sourceSubnet: sourceSubnet)
        case .iptablesNft:
            try enableMasqueradeIptables(tunName: tunName, outInterface: outInterface, sourceSubnet: sourceSubnet, binary: "/sbin/iptables")
        }

        // Verify rules were actually applied (use the same backend for checking)
        let verified = verifyMasquerade(tunName: tunName, outInterface: outInterface, backend: backend)
        if !verified {
            // If preferred backend silently failed, try fallbacks
            logger.warning("Firewall rules not applied with \(backend), trying fallbacks...")
            for fallback in FirewallBackend.allCases where fallback != backend {
                do {
                    switch fallback {
                    case .iptablesLegacy:
                        try enableMasqueradeIptables(tunName: tunName, outInterface: outInterface, sourceSubnet: sourceSubnet, binary: "/sbin/iptables-legacy")
                    case .nft:
                        try enableMasqueradeNft(tunName: tunName, outInterface: outInterface, sourceSubnet: sourceSubnet)
                    case .iptablesNft:
                        try enableMasqueradeIptables(tunName: tunName, outInterface: outInterface, sourceSubnet: sourceSubnet, binary: "/sbin/iptables")
                    }
                    if verifyMasquerade(tunName: tunName, outInterface: outInterface, backend: fallback) {
                        logger.info("Masquerade applied via fallback: \(fallback)")
                        return
                    }
                } catch {
                    logger.debug("Fallback \(fallback) failed: \(error)")
                }
            }
            logger.error("All firewall backends failed to apply masquerade rules. Ensure nftables or iptables is installed and you are running as root.")
        } else {
            logger.info("Masquerade verified with \(backend)")
        }
    }

    /// Clean up firewall rules
    public static func disableMasquerade(tunName: String, outInterface: String, sourceSubnet: String) {
        let backend = detectFirewallBackend()
        switch backend {
        case .iptablesLegacy:
            disableMasqueradeIptables(tunName: tunName, outInterface: outInterface, sourceSubnet: sourceSubnet, binary: "/sbin/iptables-legacy")
        case .nft:
            disableMasqueradeNft(tunName: tunName, outInterface: outInterface)
        case .iptablesNft:
            disableMasqueradeIptables(tunName: tunName, outInterface: outInterface, sourceSubnet: sourceSubnet, binary: "/sbin/iptables")
        }
        // Also try nft cleanup in case we used nft as fallback
        if backend != .nft {
            disableMasqueradeNft(tunName: tunName, outInterface: outInterface)
        }
        logger.info("Disabled masquerade", metadata: [
            "tun": "\(tunName)", "out": "\(outInterface)"
        ])
    }

    // MARK: - Firewall backend detection

    private enum FirewallBackend: String, CaseIterable {
        case iptablesLegacy = "iptables-legacy"
        case nft = "nft"
        case iptablesNft = "iptables-nft"
    }

    private static func detectFirewallBackend() -> FirewallBackend {
        // Prefer nft directly — iptables-nft can silently fail verification
        // and iptables-legacy uses a separate kernel subsystem that may not
        // be loaded when nftables is managing the firewall (e.g. Docker).
        if access("/usr/sbin/nft", X_OK) == 0 {
            return .nft
        }
        // Then iptables-legacy
        if access("/sbin/iptables-legacy", X_OK) == 0 {
            return .iptablesLegacy
        }
        // Fall back to whatever iptables is
        return .iptablesNft
    }

    // MARK: - iptables backend (works for both legacy and nft)

    private static func enableMasqueradeIptables(tunName: String, outInterface: String, sourceSubnet: String, binary: String) throws {
        try runFirewall(binary, [
            "-t", "nat", "-A", "POSTROUTING",
            "-s", sourceSubnet, "-o", outInterface,
            "-j", "MASQUERADE"
        ])
        try runFirewall(binary, [
            "-I", "FORWARD", "1", "-i", tunName, "-o", outInterface,
            "-j", "ACCEPT"
        ])
        try runFirewall(binary, [
            "-I", "FORWARD", "2", "-i", outInterface, "-o", tunName,
            "-m", "state", "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT"
        ])
    }

    private static func disableMasqueradeIptables(tunName: String, outInterface: String, sourceSubnet: String, binary: String) {
        try? runFirewall(binary, [
            "-t", "nat", "-D", "POSTROUTING",
            "-s", sourceSubnet, "-o", outInterface,
            "-j", "MASQUERADE"
        ])
        try? runFirewall(binary, [
            "-D", "FORWARD", "-i", tunName, "-o", outInterface,
            "-j", "ACCEPT"
        ])
        try? runFirewall(binary, [
            "-D", "FORWARD", "-i", outInterface, "-o", tunName,
            "-m", "state", "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT"
        ])
    }

    // MARK: - nft backend

    private static func enableMasqueradeNft(tunName: String, outInterface: String, sourceSubnet: String) throws {
        // Create our own nft table with chains that run before Docker's.
        // Docker's filter FORWARD chain is at priority 0; we use -1 to go first.
        // For NAT, Docker uses priority srcnat (100); we use 99.
        let commands = """
        add table ip omerta
        add chain ip omerta postrouting { type nat hook postrouting priority 99 ; }
        add chain ip omerta forward { type filter hook forward priority -1 ; policy accept ; }
        flush chain ip omerta postrouting
        flush chain ip omerta forward
        add rule ip omerta postrouting ip saddr \(sourceSubnet) oifname "\(outInterface)" masquerade
        add rule ip omerta forward iifname "\(tunName)" oifname "\(outInterface)" accept
        add rule ip omerta forward iifname "\(outInterface)" oifname "\(tunName)" ct state related,established accept
        """
        try runFirewall("/usr/sbin/nft", ["-f", "-"], stdin: commands)
    }

    private static func disableMasqueradeNft(tunName: String, outInterface: String) {
        // Delete the whole table — clean
        try? runFirewall("/usr/sbin/nft", ["delete", "table", "ip", "omerta"])
    }

    // MARK: - Verification

    private static func verifyMasquerade(tunName: String, outInterface: String, backend: FirewallBackend) -> Bool {
        switch backend {
        case .iptablesLegacy:
            let natCheck = shellOutput("/sbin/iptables-legacy", ["-t", "nat", "-L", "POSTROUTING", "-n"])
            let fwdCheck = shellOutput("/sbin/iptables-legacy", ["-L", "FORWARD", "-n"])
            return natCheck.contains("MASQUERADE") && natCheck.contains(outInterface) && fwdCheck.contains(tunName)
        case .nft:
            let ruleset = shellOutput("/usr/sbin/nft", ["list", "table", "ip", "omerta"])
            return ruleset.contains("masquerade") && ruleset.contains(outInterface) && ruleset.contains(tunName)
        case .iptablesNft:
            let natCheck = iptablesOutput(["-t", "nat", "-L", "POSTROUTING", "-n"])
            let fwdCheck = iptablesOutput(["-L", "FORWARD", "-n"])
            return natCheck.contains("MASQUERADE") && natCheck.contains(outInterface) && fwdCheck.contains(tunName)
        }
    }

    /// Write a value to a procfs sysctl path. Public for use by restore-sysctl.
    public static func writeProcSysPublic(_ path: String, value: String) {
        writeProcSys(path, value: value)
    }

    private static func writeProcSys(_ path: String, value: String) {
        let fd = Glibc.open(path, O_WRONLY)
        guard fd >= 0 else { return }
        _ = value.withCString { Glibc.write(fd, $0, value.utf8.count) }
        Glibc.close(fd)
    }

    /// Run diagnostics and print results. Call after TUN devices are created and
    /// kernel networking is configured.
    public static func printDiagnostics(tunName: String, outInterface: String, sourceSubnet: String) {
        var issues: [String] = []

        // Check ip_forward
        let ipForward = readProcSys("/proc/sys/net/ipv4/ip_forward")
        if ipForward != "1" {
            issues.append("ip_forward is '\(ipForward)' (should be '1'). Fix: sysctl net.ipv4.ip_forward=1")
        }

        // Check rp_filter — only the per-interface value matters since kernel uses max(all, iface)
        let rpTun = readProcSys("/proc/sys/net/ipv4/conf/\(tunName)/rp_filter")
        if rpTun != "0" && rpTun != "2" {
            issues.append("rp_filter too strict: \(tunName)=\(rpTun). Need loose mode (2). Fix: sysctl net.ipv4.conf.\(tunName).rp_filter=2")
        }

        // Check if Docker is interfering (DOCKER-USER/DOCKER-FORWARD chains)
        let forwardRules = iptablesOutput(["-L", "FORWARD", "--line-numbers", "-n"])
        if forwardRules.contains("DOCKER") {
            let ourRulePos = forwardRules.components(separatedBy: "\n")
                .first { $0.contains(tunName) && $0.contains(outInterface) }
            let dockerPos = forwardRules.components(separatedBy: "\n")
                .first { $0.contains("DOCKER") }
            if let ours = ourRulePos, let docker = dockerPos {
                let ourNum = ours.prefix(while: { $0.isNumber || $0 == " " }).trimmingCharacters(in: .whitespaces)
                let dockerNum = docker.prefix(while: { $0.isNumber || $0 == " " }).trimmingCharacters(in: .whitespaces)
                if let o = Int(ourNum), let d = Int(dockerNum), o > d {
                    issues.append("Docker FORWARD rules (line \(d)) precede our rules (line \(o)). Our TUN traffic may be dropped by Docker. Fix: use iptables -I FORWARD 1 to insert at top")
                }
            }
        }

        // Check MASQUERADE rule (check both nft and iptables)
        let nftRules = shellOutput("/usr/sbin/nft", ["list", "table", "ip", "omerta"])
        let natRules = iptablesOutput(["-t", "nat", "-L", "POSTROUTING", "-n"])
        let hasMasq = (nftRules.contains("masquerade") && nftRules.contains(outInterface))
            || (natRules.contains("MASQUERADE") && natRules.contains(outInterface))
        if !hasMasq {
            issues.append("No MASQUERADE rule for \(outInterface). Fix: nft add rule ip omerta postrouting ip saddr \(sourceSubnet) oifname \(outInterface) masquerade")
        }

        // Check route to internet exists
        let routeOutput = shellOutput("/sbin/ip", ["route", "show", "default"])
        if !routeOutput.contains(outInterface) {
            issues.append("No default route via \(outInterface). Internet access unlikely.")
        }

        // Check for overlapping subnets (our TUN source IP might be local to another iface)
        let addrOutput = shellOutput("/sbin/ip", ["-o", "addr", "show"])
        let tunLines = addrOutput.components(separatedBy: "\n")
        var localSubnets: [(iface: String, network: String)] = []
        for line in tunLines {
            let parts = line.split(separator: " ")
            if let inetIdx = parts.firstIndex(of: "inet"), inetIdx + 1 < parts.endIndex,
               parts.count > 1 {
                let ifaceName = String(parts[1])
                let cidr = String(parts[inetIdx + 1])
                localSubnets.append((ifaceName, cidr))
            }
        }
        // Check if 10.0.0.0/16 (omerta0 subnet) overlaps with omerta-gw0
        let peerSubnets = localSubnets.filter { $0.network.hasPrefix("10.0.") || $0.network.hasPrefix("10.") }
        let conflicting = peerSubnets.filter { $0.iface != tunName && $0.network.hasPrefix("10.") }
        if conflicting.count > 1 {
            let ifaceList = conflicting.map { "\($0.iface)=\($0.network)" }.joined(separator: ", ")
            issues.append("Multiple interfaces with 10.x.x.x subnets: \(ifaceList). The kernel may treat forwarded packets as local/martian.")
        }

        // Print results
        if issues.isEmpty {
            logger.info("Kernel networking diagnostics: all checks passed")
        } else {
            logger.warning("Kernel networking issues detected:")
            for (i, issue) in issues.enumerated() {
                logger.warning("  [\(i + 1)] \(issue)")
            }
        }
    }

    private static func readProcSys(_ path: String) -> String {
        let fd = Glibc.open(path, O_RDONLY)
        guard fd >= 0 else { return "N/A" }
        var buf = [UInt8](repeating: 0, count: 64)
        let n = Glibc.read(fd, &buf, buf.count)
        Glibc.close(fd)
        guard n > 0 else { return "N/A" }
        return String(bytes: buf[..<n], encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "N/A"
    }

    private static func iptablesOutput(_ args: [String]) -> String {
        shellOutput("/sbin/iptables", args)
    }

    private static func shellOutput(_ executable: String, _ args: [String]) -> String {
        guard Glibc.access(executable, X_OK) == 0 else { return "" }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: executable)
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice
        do {
            try proc.run()
            proc.waitUntilExit()
        } catch { return "" }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }

    private static func runFirewall(_ executable: String, _ args: [String], stdin stdinData: String? = nil) throws {
        guard Glibc.access(executable, X_OK) == 0 else {
            throw InterfaceError.preflightFailed(
                "\(executable) not found or not executable. "
                + "Install the appropriate package (nftables or iptables).")
        }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: executable)
        proc.arguments = args
        let outPipe = Pipe()
        let errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe
        if let stdinData {
            let inPipe = Pipe()
            proc.standardInput = inPipe
            try proc.run()
            inPipe.fileHandleForWriting.write(Data(stdinData.utf8))
            inPipe.fileHandleForWriting.closeFile()
        } else {
            try proc.run()
        }
        proc.waitUntilExit()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        let errStr = String(data: errData, encoding: .utf8) ?? ""
        guard proc.terminationStatus == 0 else {
            let cmd = ([executable] + args).joined(separator: " ")
            logger.error("\(cmd) failed (exit \(proc.terminationStatus)): \(errStr)")
            throw InterfaceError.readFailed("'\(cmd)' failed (exit \(proc.terminationStatus)): \(errStr.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        if !errStr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            logger.debug("\(executable) stderr: \(errStr.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
    }
}
#endif
