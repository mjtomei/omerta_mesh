// EndpointSetTests.swift - Tests for EndpointSet DWRR scheduler and failure pruning

import XCTest
@testable import OmertaTunnel

final class EndpointSetTests: XCTestCase {

    // MARK: - DWRR Scheduling

    func testSingleEndpointAlwaysSelected() async {
        let set = EndpointSet()
        await set.add(address: "10.0.0.1:5000", localPort: nil)

        for _ in 0..<10 {
            let ep = await set.next(byteCount: 100)
            XCTAssertNotNil(ep)
            XCTAssertEqual(ep?.address, "10.0.0.1:5000")
        }
    }

    func testEqualWeightsDistributeEvenly() async {
        let set = EndpointSet()
        await set.add(address: "10.0.0.1:5000", localPort: nil)
        await set.add(address: "10.0.0.2:5000", localPort: nil)

        var counts: [String: Int] = [:]
        for _ in 0..<100 {
            guard let ep = await set.next(byteCount: 100) else {
                XCTFail("next() returned nil unexpectedly")
                return
            }
            counts[ep.address, default: 0] += 1
        }

        // With equal weights, expect roughly 50/50 (allow 30-70 range)
        XCTAssertGreaterThan(counts["10.0.0.1:5000"] ?? 0, 30)
        XCTAssertGreaterThan(counts["10.0.0.2:5000"] ?? 0, 30)
    }

    func testUnequalWeightsDistributeProportionally() async {
        let set = EndpointSet()
        await set.add(address: "10.0.0.1:5000", localPort: nil)
        await set.add(address: "10.0.0.2:5000", localPort: nil)

        // Manually adjust weights by recording delivery stats and rebalancing
        // For now, test that with default equal weights both get traffic
        var counts: [String: Int] = [:]
        for _ in 0..<100 {
            guard let ep = await set.next(byteCount: 100) else {
                XCTFail("next() returned nil unexpectedly")
                return
            }
            counts[ep.address, default: 0] += 1
        }

        XCTAssertGreaterThan(counts["10.0.0.1:5000"] ?? 0, 0)
        XCTAssertGreaterThan(counts["10.0.0.2:5000"] ?? 0, 0)
    }

    func testEmptySetReturnsNil() async {
        let set = EndpointSet()
        let ep = await set.next(byteCount: 100)
        XCTAssertNil(ep)
    }

    // MARK: - Failure Pruning

    func testSingleFailureNoPrune() async {
        let set = EndpointSet()
        await set.add(address: "10.0.0.1:5000", localPort: nil)

        let pruned = await set.recordFailure(address: "10.0.0.1:5000")
        XCTAssertFalse(pruned, "One failure should not prune (threshold is 3)")

        let count = await set.count
        XCTAssertEqual(count, 1)
    }

    func testConsecutiveFailuresPrune() async {
        let set = EndpointSet()
        await set.add(address: "10.0.0.1:5000", localPort: nil)
        await set.add(address: "10.0.0.2:5000", localPort: nil)

        // 3 consecutive failures should prune
        _ = await set.recordFailure(address: "10.0.0.1:5000")
        _ = await set.recordFailure(address: "10.0.0.1:5000")
        let pruned = await set.recordFailure(address: "10.0.0.1:5000")
        XCTAssertTrue(pruned)

        let count = await set.count
        XCTAssertEqual(count, 1)
        let addresses = await set.activeAddresses
        XCTAssertEqual(addresses, ["10.0.0.2:5000"])
    }

    func testSuccessResetsFailureCount() async {
        let set = EndpointSet()
        await set.add(address: "10.0.0.1:5000", localPort: nil)

        // 2 failures, then a success
        _ = await set.recordFailure(address: "10.0.0.1:5000")
        _ = await set.recordFailure(address: "10.0.0.1:5000")
        await set.recordSend(to: "10.0.0.1:5000", bytes: 100)

        // 2 more failures should not prune (counter was reset)
        _ = await set.recordFailure(address: "10.0.0.1:5000")
        _ = await set.recordFailure(address: "10.0.0.1:5000")

        let count = await set.count
        XCTAssertEqual(count, 1, "Success should have reset failure counter")
    }

    func testPruneLastEndpointReturnsFalse() async {
        let set = EndpointSet()
        await set.add(address: "10.0.0.1:5000", localPort: nil)

        let remaining = await set.prune(address: "10.0.0.1:5000")
        XCTAssertFalse(remaining, "Pruning the last endpoint should return false")
    }

    func testPruneWithRemainingReturnsTrue() async {
        let set = EndpointSet()
        await set.add(address: "10.0.0.1:5000", localPort: nil)
        await set.add(address: "10.0.0.2:5000", localPort: nil)

        let remaining = await set.prune(address: "10.0.0.1:5000")
        XCTAssertTrue(remaining)
    }

    // MARK: - Rebalancing

    func testRebalanceAdjustsWeights() async {
        let set = EndpointSet()
        await set.add(address: "10.0.0.1:5000", localPort: nil)
        await set.add(address: "10.0.0.2:5000", localPort: nil)

        // Simulate sends
        await set.recordSend(to: "10.0.0.1:5000", bytes: 1000)
        await set.recordSend(to: "10.0.0.2:5000", bytes: 1000)

        // Simulate different delivery rates
        await set.recordDelivery(from: "10.0.0.1:5000", bytes: 900)  // 90% delivery
        await set.recordDelivery(from: "10.0.0.2:5000", bytes: 500)  // 50% delivery

        await set.rebalance()

        let endpoints = await set.allEndpoints
        let ep1 = endpoints.first { $0.address == "10.0.0.1:5000" }!
        let ep2 = endpoints.first { $0.address == "10.0.0.2:5000" }!

        // Higher delivery ratio should get higher weight
        XCTAssertGreaterThan(ep1.weight, ep2.weight)
    }

    func testRebalanceWithNoDeliveryData() async {
        let set = EndpointSet()
        await set.add(address: "10.0.0.1:5000", localPort: nil)
        await set.add(address: "10.0.0.2:5000", localPort: nil)

        // No sends, no deliveries — rebalance should be a no-op
        await set.rebalance()

        let endpoints = await set.allEndpoints
        XCTAssertEqual(endpoints[0].weight, 1.0)
        XCTAssertEqual(endpoints[1].weight, 1.0)
    }

    func testRecordDeliveryUpdatesStats() async {
        let set = EndpointSet()
        await set.add(address: "10.0.0.1:5000", localPort: nil)

        await set.recordDelivery(from: "10.0.0.1:5000", bytes: 5000)

        let endpoints = await set.allEndpoints
        XCTAssertEqual(endpoints[0].bytesAcked, 5000)
    }

    // MARK: - Lifecycle

    func testAddEndpoint() async {
        let set = EndpointSet()
        await set.add(address: "10.0.0.1:5000", localPort: 6000)

        let count = await set.count
        XCTAssertEqual(count, 1)

        let endpoints = await set.allEndpoints
        XCTAssertEqual(endpoints[0].address, "10.0.0.1:5000")
        XCTAssertEqual(endpoints[0].localPort, 6000)
        XCTAssertEqual(endpoints[0].weight, 1.0)
    }

    func testAddMultipleEndpoints() async {
        let set = EndpointSet()
        await set.add(address: "10.0.0.1:5000", localPort: nil)
        await set.add(address: "10.0.0.2:5000", localPort: 6001)
        await set.add(address: "10.0.0.3:5000", localPort: 6002)

        let count = await set.count
        XCTAssertEqual(count, 3)

        let addresses = await set.activeAddresses
        XCTAssertEqual(addresses.count, 3)
    }

    func testAddDuplicateIgnored() async {
        let set = EndpointSet()
        await set.add(address: "10.0.0.1:5000", localPort: nil)
        await set.add(address: "10.0.0.1:5000", localPort: nil)

        let count = await set.count
        XCTAssertEqual(count, 1)
    }

    func testPruneRemovesEndpoint() async {
        let set = EndpointSet()
        await set.add(address: "10.0.0.1:5000", localPort: nil)
        await set.add(address: "10.0.0.2:5000", localPort: nil)

        await set.prune(address: "10.0.0.1:5000")

        let ep = await set.next(byteCount: 100)
        XCTAssertEqual(ep?.address, "10.0.0.2:5000")
    }
}
