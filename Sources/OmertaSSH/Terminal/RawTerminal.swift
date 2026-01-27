// RawTerminal.swift - Low-level terminal control using termios
//
// Provides raw terminal mode for SSH interactive sessions,
// handling terminal settings, input/output, and window resize signals.

import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Errors from terminal operations
public enum TerminalError: Error, LocalizedError {
    case notATTY
    case failedToGetAttributes
    case failedToSetAttributes
    case failedToGetWindowSize

    public var errorDescription: String? {
        switch self {
        case .notATTY:
            return "Standard input is not a terminal"
        case .failedToGetAttributes:
            return "Failed to get terminal attributes"
        case .failedToSetAttributes:
            return "Failed to set terminal attributes"
        case .failedToGetWindowSize:
            return "Failed to get terminal window size"
        }
    }
}

/// Terminal window size
public struct TerminalSize: Sendable, Equatable {
    public let rows: UInt16
    public let cols: UInt16
    public let pixelWidth: UInt16
    public let pixelHeight: UInt16

    public init(rows: UInt16, cols: UInt16, pixelWidth: UInt16 = 0, pixelHeight: UInt16 = 0) {
        self.rows = rows
        self.cols = cols
        self.pixelWidth = pixelWidth
        self.pixelHeight = pixelHeight
    }
}

/// Low-level terminal control for SSH sessions
public final class RawTerminal: @unchecked Sendable {
    /// File descriptor for terminal input (stdin)
    private let inputFd: Int32

    /// File descriptor for terminal output (stdout)
    private let outputFd: Int32

    /// Original terminal attributes (for restoration)
    private var originalTermios: termios?

    /// Whether raw mode is currently active
    private var isRawMode = false

    /// Lock for thread safety
    private let lock = NSLock()

    /// Callback for window resize events
    private var resizeHandler: ((TerminalSize) -> Void)?

    /// Global reference for signal handler (needed because signal handlers can't capture context)
    private static var currentInstance: RawTerminal?

    /// Initialize with stdin/stdout
    public init() throws {
        self.inputFd = STDIN_FILENO
        self.outputFd = STDOUT_FILENO

        // Verify stdin is a terminal
        guard isatty(inputFd) != 0 else {
            throw TerminalError.notATTY
        }
    }

    deinit {
        exitRawMode()
    }

    // MARK: - Raw Mode

    /// Enter raw terminal mode (disable line buffering, echo, etc.)
    public func enterRawMode() throws {
        lock.lock()
        defer { lock.unlock() }

        guard !isRawMode else { return }

        // Get current terminal attributes
        var raw = termios()
        guard tcgetattr(inputFd, &raw) == 0 else {
            throw TerminalError.failedToGetAttributes
        }

        // Save original for restoration
        originalTermios = raw

        // Configure raw mode:
        // - Disable ICANON (canonical mode) - read byte-by-byte instead of line-by-line
        // - Disable ECHO - don't echo input (we'll handle this)
        // - Disable ISIG - don't generate signals for Ctrl+C, etc. (pass to remote)
        // - Disable IEXTEN - disable extended input processing
        raw.c_lflag &= ~tcflag_t(ICANON | ECHO | ISIG | IEXTEN)

        // Input flags:
        // - Disable IXON - don't handle Ctrl+S/Ctrl+Q for flow control
        // - Disable ICRNL - don't translate CR to NL
        // - Disable BRKINT - don't generate SIGINT on break
        // - Disable INPCK - disable parity checking
        // - Disable ISTRIP - don't strip 8th bit
        raw.c_iflag &= ~tcflag_t(IXON | ICRNL | BRKINT | INPCK | ISTRIP)

        // Output flags:
        // - Disable OPOST - disable output processing
        raw.c_oflag &= ~tcflag_t(OPOST)

        // Control flags:
        // - Set 8 bits per character
        raw.c_cflag |= tcflag_t(CS8)

        // Control characters:
        // - VMIN = 1: read() returns after at least 1 byte
        // - VTIME = 0: no timeout
        withUnsafeMutablePointer(to: &raw.c_cc) { ptr in
            let ccPtr = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: cc_t.self)
            ccPtr[Int(VMIN)] = 1
            ccPtr[Int(VTIME)] = 0
        }

        // Apply settings
        guard tcsetattr(inputFd, TCSAFLUSH, &raw) == 0 else {
            throw TerminalError.failedToSetAttributes
        }

        isRawMode = true

        // Set up signal handler for window resize
        RawTerminal.currentInstance = self
        setupResizeHandler()
    }

    /// Exit raw mode and restore original terminal settings
    public func exitRawMode() {
        lock.lock()
        defer { lock.unlock() }

        guard isRawMode, var original = originalTermios else { return }

        // Restore original settings
        tcsetattr(inputFd, TCSAFLUSH, &original)
        isRawMode = false

        // Clear signal handler
        signal(SIGWINCH, SIG_DFL)
        if RawTerminal.currentInstance === self {
            RawTerminal.currentInstance = nil
        }
    }

    // MARK: - I/O

    /// Read a single byte from the terminal (blocks until available)
    public func readByte() -> UInt8? {
        var byte: UInt8 = 0
        let result = read(inputFd, &byte, 1)
        return result == 1 ? byte : nil
    }

    /// Read available bytes from the terminal (non-blocking with timeout)
    public func readBytes(maxCount: Int = 1024, timeoutMs: Int = 0) -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: maxCount)

        if timeoutMs > 0 {
            // Use poll for timeout (more portable than select)
            var pfd = pollfd(fd: Int32(inputFd), events: Int16(POLLIN), revents: 0)
            let pollResult = poll(&pfd, 1, Int32(timeoutMs))
            if pollResult <= 0 {
                return []
            }
        }

        let count = read(inputFd, &buffer, maxCount)
        if count > 0 {
            return Array(buffer.prefix(count))
        }
        return []
    }

    /// Write bytes to the terminal
    public func write(_ bytes: [UInt8]) {
        _ = bytes.withUnsafeBytes { buffer in
            Foundation.write(outputFd, buffer.baseAddress, buffer.count)
        }
    }

    /// Write data to the terminal
    public func write(_ data: Data) {
        _ = data.withUnsafeBytes { buffer in
            Foundation.write(outputFd, buffer.baseAddress!, buffer.count)
        }
    }

    /// Write a string to the terminal
    public func write(_ string: String) {
        write(Array(string.utf8))
    }

    /// Flush terminal output
    public func flush() {
        // fsync doesn't work on terminals, but we can use fflush on stdout
        fflush(stdout)
    }

    // MARK: - Window Size

    /// Get current terminal size
    public func getSize() throws -> TerminalSize {
        var ws = winsize()
        guard ioctl(outputFd, UInt(TIOCGWINSZ), &ws) == 0 else {
            throw TerminalError.failedToGetWindowSize
        }
        return TerminalSize(
            rows: ws.ws_row,
            cols: ws.ws_col,
            pixelWidth: ws.ws_xpixel,
            pixelHeight: ws.ws_ypixel
        )
    }

    /// Set callback for window resize events
    public func onResize(_ handler: @escaping (TerminalSize) -> Void) {
        lock.lock()
        resizeHandler = handler
        lock.unlock()
    }

    // MARK: - Private

    private func setupResizeHandler() {
        // Set up SIGWINCH handler for terminal resize
        signal(SIGWINCH) { _ in
            guard let instance = RawTerminal.currentInstance else { return }
            instance.handleResize()
        }
    }

    private func handleResize() {
        lock.lock()
        let handler = resizeHandler
        lock.unlock()

        guard let handler = handler else { return }

        do {
            let size = try getSize()
            handler(size)
        } catch {
            // Ignore errors in signal handler
        }
    }
}

// MARK: - fd_set helpers for Linux

#if !canImport(Darwin)
private func FD_ZERO(_ set: inout fd_set) {
    set.__fds_bits = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
}

private func FD_SET(_ fd: Int32, _ set: inout fd_set) {
    let intOffset = Int(fd) / 64
    let bitOffset = Int(fd) % 64
    withUnsafeMutablePointer(to: &set.__fds_bits) { ptr in
        let bits = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: Int.self)
        bits[intOffset] |= 1 << bitOffset
    }
}
#endif
