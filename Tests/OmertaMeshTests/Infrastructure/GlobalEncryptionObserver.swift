// GlobalEncryptionObserver.swift - Verify all test traffic is encrypted via capture hook

import XCTest
@testable import OmertaMesh

#if DEBUG
/// Tracks packets sent during tests and flags any that lack the BinaryEnvelope prefix
/// or fail decryption against registered network keys.
/// Install once via `GlobalEncryptionObserver.install()`.
final class GlobalEncryptionObserver: NSObject, XCTestObservation {

    /// Unencrypted packets captured during the entire test run.
    static let shared = GlobalEncryptionObserver()

    private let lock = NSLock()
    private var _violations: [(testName: String, data: Data, destination: String, reason: String)] = []
    private var _networkKeys: Set<Data> = []
    private var currentTestName: String = ""

    /// Whether the hook is currently suppressed (for tests that intentionally use sendRaw).
    static var suppressHook: Bool = false

    var violations: [(testName: String, data: Data, destination: String, reason: String) ] {
        lock.lock()
        defer { lock.unlock() }
        return _violations
    }

    /// Register a network key for full decryption verification.
    /// Tests should call this with any key they use for encryption.
    static func registerNetworkKey(_ key: Data) {
        let observer = shared
        observer.lock.lock()
        observer._networkKeys.insert(key)
        observer.lock.unlock()
    }

    /// Call once to register the observer and install the capture hook.
    static func install() {
        let observer = shared
        XCTestObservationCenter.shared.addTestObserver(observer)
        UDPSocket.captureHook = { data, dest in
            guard !suppressHook else { return }

            // Layer 1: prefix check
            guard BinaryEnvelope.isValidPrefix(data) else {
                observer.recordViolation(data: data, dest: dest, reason: "missing encrypted envelope prefix")
                return
            }

            // Layer 2: attempt decryption against all registered keys
            observer.lock.lock()
            let keys = observer._networkKeys
            observer.lock.unlock()

            guard !keys.isEmpty else { return }

            var decryptedWithAny = false
            for key in keys {
                do {
                    _ = try BinaryEnvelope.decode(data, networkKey: key)
                    decryptedWithAny = true
                    break
                } catch {
                    continue
                }
            }

            if !decryptedWithAny {
                observer.recordViolation(data: data, dest: dest, reason: "valid prefix but decryption failed against all \(keys.count) registered key(s)")
            }
        }
    }

    private func recordViolation(data: Data, dest: String, reason: String) {
        lock.lock()
        _violations.append((currentTestName, data, dest, reason))
        lock.unlock()
    }

    func testCaseWillStart(_ testCase: XCTestCase) {
        lock.lock()
        currentTestName = "\(type(of: testCase)).\(testCase.name)"
        lock.unlock()
    }
}
#endif
