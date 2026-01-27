// ConfigUtils.swift - Utilities extracted from OmertaCore

import Foundation

/// Get the real user's home directory, even when running under sudo
/// Handles the case where `sudo -i` followed by `su [user]` leaves SUDO_USER set incorrectly
public func getRealUserHome() -> String {
    // First check if SUDO_USER is set and still applies to the current process
    if let sudoUser = ProcessInfo.processInfo.environment["SUDO_USER"] {
        // Verify the current effective UID is root (0) - meaning sudo is actually in effect
        // If we're not running as root, SUDO_USER is stale (e.g., after `su [user]`)
        if geteuid() == 0 {
            #if os(macOS)
            return "/Users/\(sudoUser)"
            #else
            return "/home/\(sudoUser)"
            #endif
        }
        // SUDO_USER is set but we're not root - ignore it (we switched users)
    }

    if let home = ProcessInfo.processInfo.environment["HOME"] {
        return home
    }

    return NSHomeDirectory()
}
