// EndpointChangeDetectorTests.swift - Tests for EndpointChangeDetector

import XCTest
@testable import OmertaTunnel

final class EndpointChangeDetectorTests: XCTestCase {

    func testEmitsChangeOnNetworkSwitch() async throws {
        let detector = EndpointChangeDetector()
        await detector.start()

        let stream = await detector.changes

        // Emit a simulated change
        await detector.emit(EndpointChange(
            oldEndpoint: "en0",
            newEndpoint: "en1",
            reason: .networkSwitch
        ))

        var received: EndpointChange?
        for await change in stream {
            received = change
            break
        }

        XCTAssertNotNil(received)
        XCTAssertEqual(received?.oldEndpoint, "en0")
        XCTAssertEqual(received?.newEndpoint, "en1")
        XCTAssertEqual(received?.reason, .networkSwitch)

        await detector.stop()
    }

    func testEmitsChangeOnInterfaceDown() async throws {
        let detector = EndpointChangeDetector()
        await detector.start()

        let stream = await detector.changes

        await detector.emit(EndpointChange(
            oldEndpoint: "en0",
            newEndpoint: nil,
            reason: .interfaceDown
        ))

        var received: EndpointChange?
        for await change in stream {
            received = change
            break
        }

        XCTAssertNotNil(received)
        XCTAssertNil(received?.newEndpoint)
        XCTAssertEqual(received?.reason, .interfaceDown)

        await detector.stop()
    }

    func testNoChangeWhenStable() async throws {
        let detector = EndpointChangeDetector()
        await detector.start()

        let stream = await detector.changes

        // Don't emit anything — verify no events arrive within a timeout
        let task = Task<EndpointChange?, Never> {
            for await change in stream {
                return change
            }
            return nil
        }

        try await Task.sleep(for: .milliseconds(200))
        task.cancel()

        let result = await task.value
        XCTAssertNil(result, "No events should be emitted when network is stable")

        await detector.stop()
    }

    func testStartStop() async throws {
        let detector = EndpointChangeDetector()

        // Start and stop should not crash
        await detector.start()
        await detector.stop()

        // Double start/stop should be safe
        await detector.start()
        await detector.start()
        await detector.stop()
        await detector.stop()
    }
}
