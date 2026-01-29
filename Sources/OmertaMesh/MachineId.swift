// MachineId.swift - Persistent machine identifier for mesh networking

import Foundation

/// Machine ID uniquely identifies a physical machine, separate from peerId (identity).
/// Multiple machines can share the same peerId if they have the same identity keypair.
public typealias MachineId = String

/// Get the storage path for machine ID (handles sudo correctly)
private func getMachineIdPath() -> URL {
    URL(fileURLWithPath: getRealUserHome())
        .appendingPathComponent(".omerta/mesh/machine_id")
}

/// Load or generate a persistent machine ID.
/// The machine ID is generated once and persists forever on this machine.
public func getOrCreateMachineId() throws -> MachineId {
    let fileManager = FileManager.default
    let machineIdPath = getMachineIdPath()

    // Try to load existing machine ID
    if fileManager.fileExists(atPath: machineIdPath.path) {
        let contents = try String(contentsOf: machineIdPath, encoding: .utf8)
        let machineId = contents.trimmingCharacters(in: .whitespacesAndNewlines)
        if !machineId.isEmpty {
            return machineId
        }
    }

    // Generate new machine ID
    let newId = UUID().uuidString

    // Ensure directory exists
    let configDir = machineIdPath.deletingLastPathComponent()
    try fileManager.createDirectory(at: configDir, withIntermediateDirectories: true)

    // Write machine ID
    try newId.write(to: machineIdPath, atomically: true, encoding: .utf8)
    try fileManager.setAttributes(
        [.posixPermissions: 0o600],
        ofItemAtPath: machineIdPath.path
    )

    return newId
}

/// Get the machine ID if it exists, without creating one.
public func getMachineId() -> MachineId? {
    let machineIdPath = getMachineIdPath()
    guard FileManager.default.fileExists(atPath: machineIdPath.path) else {
        return nil
    }

    do {
        let contents = try String(contentsOf: machineIdPath, encoding: .utf8)
        let machineId = contents.trimmingCharacters(in: .whitespacesAndNewlines)
        return machineId.isEmpty ? nil : machineId
    } catch {
        return nil
    }
}
