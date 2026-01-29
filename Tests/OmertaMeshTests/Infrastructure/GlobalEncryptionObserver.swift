// GlobalEncryptionObserver.swift - Verify all test traffic is encrypted via capture hook

import XCTest
@testable import OmertaMesh

#if DEBUG
/// Tracks packets sent during tests and flags any that lack the BinaryEnvelopeV2 prefix.
/// Install once via `NSPrincipalClass` or call `GlobalEncryptionObserver.install()`.
final class GlobalEncryptionObserver: NSObject, XCTestObservation {

    /// Unencrypted packets captured during the entire test run.
    static let shared = GlobalEncryptionObserver()

    private let lock = NSLock()
    private var _violations: [(testName: String, data: Data, destination: String)] = []
    private var currentTestName: String = ""

    /// Whether the hook is currently suppressed (for tests that intentionally use sendRaw).
    static var suppressHook: Bool = false

    var violations: [(testName: String, data: Data, destination: String)] {
        lock.lock()
        defer { lock.unlock() }
        return _violations
    }

    /// Call once to register the observer and install the capture hook.
    static func install() {
        let observer = shared
        XCTestObservationCenter.shared.addTestObserver(observer)
        UDPSocket.captureHook = { data, dest in
            guard !suppressHook else { return }
            if !BinaryEnvelopeV2.isValidPrefix(data) {
                observer.lock.lock()
                observer._violations.append((observer.currentTestName, data, dest))
                observer.lock.unlock()
            }
        }
    }

    func testCaseWillStart(_ testCase: XCTestCase) {
        lock.lock()
        currentTestName = "\(type(of: testCase)).\(testCase.name)"
        lock.unlock()
    }
}
#endif
