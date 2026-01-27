// Phase5Tests.swift - Tests for Freshness Queries (Phase 5)

import XCTest
import Foundation
@testable import OmertaMesh

final class Phase5Tests: XCTestCase {

    // MARK: - RecentContactTracker Tests

    /// Test recording and retrieving a contact
    func testRecentContactTrackerRecordAndRetrieve() async throws {
        let tracker = RecentContactTracker()

        await tracker.recordContact(
            peerId: "peer-1",
            reachability: .direct(endpoint: "1.2.3.4:5000"),
            latencyMs: 50,
            connectionType: .direct
        )

        let contact = await tracker.getContact("peer-1")
        XCTAssertNotNil(contact)
        XCTAssertEqual(contact?.peerId, "peer-1")
        XCTAssertEqual(contact?.latencyMs, 50)
        XCTAssertEqual(contact?.connectionType, .direct)
    }

    /// Test contact age calculation
    func testRecentContactAge() async throws {
        let tracker = RecentContactTracker()

        await tracker.recordContact(
            peerId: "peer-age",
            reachability: .direct(endpoint: "1.2.3.4:5000"),
            latencyMs: 10,
            connectionType: .direct
        )

        let contact = await tracker.getContact("peer-age")
        XCTAssertNotNil(contact)
        XCTAssertLessThan(contact!.age, 1.0, "Contact age should be less than 1 second")
        XCTAssertLessThan(contact!.ageSeconds, 1, "Contact ageSeconds should be 0")
    }

    /// Test hasRecentContact check
    func testHasRecentContact() async throws {
        let tracker = RecentContactTracker()

        // Should not have contact initially
        let beforeResult = await tracker.hasRecentContact("peer-check", maxAgeSeconds: 60)
        XCTAssertFalse(beforeResult)

        // Record contact
        await tracker.recordContact(
            peerId: "peer-check",
            reachability: .direct(endpoint: "1.2.3.4:5000"),
            latencyMs: 10,
            connectionType: .direct
        )

        // Should have contact now
        let afterResult = await tracker.hasRecentContact("peer-check", maxAgeSeconds: 60)
        XCTAssertTrue(afterResult)
    }

    /// Test contact removal
    func testRecentContactRemoval() async throws {
        let tracker = RecentContactTracker()

        await tracker.recordContact(
            peerId: "peer-remove",
            reachability: .direct(endpoint: "1.2.3.4:5000"),
            latencyMs: 10,
            connectionType: .direct
        )

        var contact = await tracker.getContact("peer-remove")
        XCTAssertNotNil(contact)

        await tracker.removeContact("peer-remove")

        contact = await tracker.getContact("peer-remove")
        XCTAssertNil(contact)
    }

    /// Test touch updates lastSeen
    func testRecentContactTouch() async throws {
        let tracker = RecentContactTracker()

        await tracker.recordContact(
            peerId: "peer-touch",
            reachability: .direct(endpoint: "1.2.3.4:5000"),
            latencyMs: 10,
            connectionType: .direct
        )

        let firstContact = await tracker.getContact("peer-touch")
        let firstSeen = firstContact!.lastSeen

        // Wait a tiny bit
        try await Task.sleep(nanoseconds: 10_000_000)  // 10ms

        await tracker.touch("peer-touch")

        let secondContact = await tracker.getContact("peer-touch")
        let secondSeen = secondContact!.lastSeen

        XCTAssertGreaterThan(secondSeen, firstSeen)
    }

    /// Test LRU eviction when over capacity
    func testRecentContactLRUEviction() async throws {
        let config = RecentContactTracker.Config(maxAge: 300, maxContacts: 3, cleanupInterval: 60)
        let tracker = RecentContactTracker(config: config)

        // Add 4 contacts (capacity is 3)
        for i in 1...4 {
            await tracker.recordContact(
                peerId: "peer-\(i)",
                reachability: .direct(endpoint: "1.2.3.4:\(5000 + i)"),
                latencyMs: 10,
                connectionType: .direct
            )
            // Small delay to ensure order
            try await Task.sleep(nanoseconds: 1_000_000)
        }

        let count = await tracker.count
        XCTAssertEqual(count, 3, "Should have evicted oldest contact")

        // First contact should be evicted
        let firstContact = await tracker.getContact("peer-1")
        XCTAssertNil(firstContact, "Oldest contact should be evicted")

        // Last contact should exist
        let lastContact = await tracker.getContact("peer-4")
        XCTAssertNotNil(lastContact, "Newest contact should still exist")
    }

    /// Test allContacts returns all tracked contacts
    func testAllContacts() async throws {
        let tracker = RecentContactTracker()

        for i in 1...3 {
            await tracker.recordContact(
                peerId: "peer-\(i)",
                reachability: .direct(endpoint: "1.2.3.4:\(5000 + i)"),
                latencyMs: 10,
                connectionType: .direct
            )
        }

        let all = await tracker.allContacts
        XCTAssertEqual(all.count, 3)
    }

    /// Test contactsWithin filters by age
    func testContactsWithin() async throws {
        let tracker = RecentContactTracker()

        await tracker.recordContact(
            peerId: "peer-recent",
            reachability: .direct(endpoint: "1.2.3.4:5000"),
            latencyMs: 10,
            connectionType: .direct
        )

        let contacts = await tracker.contactsWithin(maxAgeSeconds: 60)
        XCTAssertEqual(contacts.count, 1)
        XCTAssertEqual(contacts.first?.peerId, "peer-recent")
    }

    /// Test removeContactsUsingPath
    func testRemoveContactsUsingPath() async throws {
        let tracker = RecentContactTracker()

        let path = ReachabilityPath.direct(endpoint: "1.2.3.4:5000")

        await tracker.recordContact(
            peerId: "peer-path-1",
            reachability: path,
            latencyMs: 10,
            connectionType: .direct
        )

        await tracker.recordContact(
            peerId: "peer-path-2",
            reachability: .direct(endpoint: "5.6.7.8:5000"),
            latencyMs: 10,
            connectionType: .direct
        )

        await tracker.removeContactsUsingPath(path)

        let contact1 = await tracker.getContact("peer-path-1")
        XCTAssertNil(contact1, "Contact using removed path should be gone")

        let contact2 = await tracker.getContact("peer-path-2")
        XCTAssertNotNil(contact2, "Contact using different path should remain")
    }

    // MARK: - PathFailureReporter Tests

    /// Test reporting a failure
    func testPathFailureReporting() async throws {
        let reporter = PathFailureReporter()

        let message = await reporter.reportFailure(
            peerId: "peer-fail",
            path: .direct(endpoint: "1.2.3.4:5000")
        )

        XCTAssertNotNil(message)
        if case .pathFailed(let peerId, _, _) = message! {
            XCTAssertEqual(peerId, "peer-fail")
        } else {
            XCTFail("Expected pathFailed message")
        }
    }

    /// Test failure rate limiting
    func testPathFailureRateLimiting() async throws {
        let config = PathFailureReporter.Config(reportInterval: 60.0)
        let reporter = PathFailureReporter(config: config)

        // First report should succeed
        let first = await reporter.reportFailure(
            peerId: "peer-ratelimit",
            path: .direct(endpoint: "1.2.3.4:5000")
        )
        XCTAssertNotNil(first)

        // Second immediate report should be rate limited
        let second = await reporter.reportFailure(
            peerId: "peer-ratelimit",
            path: .direct(endpoint: "1.2.3.4:5000")
        )
        XCTAssertNil(second, "Should be rate limited")
    }

    /// Test shouldReport check
    func testShouldReport() async throws {
        let config = PathFailureReporter.Config(reportInterval: 60.0)
        let reporter = PathFailureReporter(config: config)

        let path = ReachabilityPath.direct(endpoint: "1.2.3.4:5000")

        // Initially should be able to report
        let canReport = await reporter.shouldReport(peerId: "peer-check", path: path)
        XCTAssertTrue(canReport)

        // After reporting, should not be able to report again immediately
        _ = await reporter.reportFailure(peerId: "peer-check", path: path)
        let cannotReport = await reporter.shouldReport(peerId: "peer-check", path: path)
        XCTAssertFalse(cannotReport)
    }

    /// Test isPathFailed check
    func testIsPathFailed() async throws {
        let reporter = PathFailureReporter()
        let path = ReachabilityPath.direct(endpoint: "1.2.3.4:5000")

        // Initially path is not failed
        var isFailed = await reporter.isPathFailed(peerId: "peer-status", path: path)
        XCTAssertFalse(isFailed)

        // After reporting failure, path should be marked as failed
        _ = await reporter.reportFailure(peerId: "peer-status", path: path)
        isFailed = await reporter.isPathFailed(peerId: "peer-status", path: path)
        XCTAssertTrue(isFailed)
    }

    /// Test handling incoming failure
    func testHandleIncomingFailure() async throws {
        let reporter = PathFailureReporter()
        let path = ReachabilityPath.direct(endpoint: "1.2.3.4:5000")

        await reporter.handleFailure(
            peerId: "peer-incoming",
            path: path,
            failedAt: Date(),
            reportedBy: "other-peer"
        )

        let isFailed = await reporter.isPathFailed(peerId: "peer-incoming", path: path)
        XCTAssertTrue(isFailed)
    }

    /// Test failures query
    func testFailuresForPeer() async throws {
        let reporter = PathFailureReporter()

        _ = await reporter.reportFailure(
            peerId: "peer-multi-fail",
            path: .direct(endpoint: "1.2.3.4:5000")
        )

        _ = await reporter.reportFailure(
            peerId: "peer-multi-fail",
            path: .direct(endpoint: "5.6.7.8:5000")
        )

        let failures = await reporter.failures(for: "peer-multi-fail")
        XCTAssertEqual(failures.count, 2)
    }

    /// Test failure propagation decision
    func testShouldPropagate() async throws {
        let config = PathFailureReporter.Config(maxPropagationHops: 2)
        let reporter = PathFailureReporter(config: config)

        XCTAssertTrue(reporter.shouldPropagate(hopCount: 0))
        XCTAssertTrue(reporter.shouldPropagate(hopCount: 1))
        XCTAssertFalse(reporter.shouldPropagate(hopCount: 2))
        XCTAssertFalse(reporter.shouldPropagate(hopCount: 3))
    }

    /// Test failure handler callback
    func testFailureHandlerCallback() async throws {
        let reporter = PathFailureReporter()
        let path = ReachabilityPath.direct(endpoint: "1.2.3.4:5000")

        var receivedFailure: PathFailure?
        await reporter.onFailure { failure in
            receivedFailure = failure
        }

        await reporter.handleFailure(
            peerId: "peer-callback",
            path: path,
            failedAt: Date(),
            reportedBy: "reporter-peer"
        )

        XCTAssertNotNil(receivedFailure)
        XCTAssertEqual(receivedFailure?.peerId, "peer-callback")
        XCTAssertEqual(receivedFailure?.reportedBy, "reporter-peer")
    }

    // MARK: - FreshnessQuery Tests

    /// Test local contact check before query
    func testFreshnessQueryLocalContactCheck() async throws {
        let tracker = RecentContactTracker()
        let query = FreshnessQuery(recentContacts: tracker)

        // Record a fresh contact
        await tracker.recordContact(
            peerId: "peer-local",
            reachability: .direct(endpoint: "1.2.3.4:5000"),
            latencyMs: 10,
            connectionType: .direct
        )

        // Query should return local contact without sending network query
        var sendCalled = false
        let result = await query.query(peerId: "peer-local") { _, _ in
            sendCalled = true
        }

        XCTAssertTrue(result.success)
        XCTAssertFalse(sendCalled, "Should not send network query when local contact exists")
    }

    /// Test query rate limiting
    func testFreshnessQueryRateLimiting() async throws {
        let config = FreshnessQuery.Config(queryTimeout: 0.1, queryInterval: 60.0)
        let tracker = RecentContactTracker()
        let query = FreshnessQuery(recentContacts: tracker, config: config)

        var queryCount = 0

        // First query
        _ = await query.query(peerId: "peer-rate-limit") { _, _ in
            queryCount += 1
        }

        // Second immediate query should be rate limited
        _ = await query.query(peerId: "peer-rate-limit") { _, _ in
            queryCount += 1
        }

        XCTAssertEqual(queryCount, 1, "Second query should be rate limited")
    }

    /// Test canQuery check
    func testCanQuery() async throws {
        let config = FreshnessQuery.Config(queryTimeout: 0.1, queryInterval: 60.0)
        let tracker = RecentContactTracker()
        let query = FreshnessQuery(recentContacts: tracker, config: config)

        // Initially can query
        var canQuery = await query.canQuery("peer-can-query")
        XCTAssertTrue(canQuery)

        // After querying, cannot query again immediately
        _ = await query.query(peerId: "peer-can-query") { _, _ in }
        canQuery = await query.canQuery("peer-can-query")
        XCTAssertFalse(canQuery)
    }

    /// Test handling response improves result
    func testFreshnessQueryHandleResponse() async throws {
        let config = FreshnessQuery.Config(queryTimeout: 0.5)
        let tracker = RecentContactTracker()
        let query = FreshnessQuery(recentContacts: tracker, config: config)

        // Start a query in background
        let resultTask = Task {
            await query.query(peerId: "peer-response") { _, _ in }
        }

        // Small delay to let query start
        try await Task.sleep(nanoseconds: 50_000_000)  // 50ms

        // Handle a response
        await query.handleResponse(
            peerId: "peer-response",
            lastSeenSecondsAgo: 30,
            reachability: .direct(endpoint: "1.2.3.4:5000"),
            fromPeerId: "responder"
        )

        let result = await resultTask.value
        XCTAssertTrue(result.success)
        XCTAssertEqual(result.lastSeenSecondsAgo, 30)
        XCTAssertEqual(result.responderId, "responder")
    }

    /// Test handleQuery returns response when we have contact
    func testHandleQueryWithContact() async throws {
        let tracker = RecentContactTracker()
        let query = FreshnessQuery(recentContacts: tracker)

        await tracker.recordContact(
            peerId: "peer-handle-query",
            reachability: .direct(endpoint: "1.2.3.4:5000"),
            latencyMs: 10,
            connectionType: .direct
        )

        let response = await query.handleQuery(peerId: "peer-handle-query", maxAgeSeconds: 300)
        XCTAssertNotNil(response)

        if case .iHaveRecent(let peerId, let age, let path) = response! {
            XCTAssertEqual(peerId, "peer-handle-query")
            XCTAssertLessThan(age, 5)
            if case .direct(let endpoint) = path {
                XCTAssertEqual(endpoint, "1.2.3.4:5000")
            } else {
                XCTFail("Expected direct path")
            }
        } else {
            XCTFail("Expected iHaveRecent response")
        }
    }

    /// Test handleQuery returns nil when no contact
    func testHandleQueryWithoutContact() async throws {
        let tracker = RecentContactTracker()
        let query = FreshnessQuery(recentContacts: tracker)

        let response = await query.handleQuery(peerId: "unknown-peer", maxAgeSeconds: 300)
        XCTAssertNil(response)
    }

    /// Test shouldForward hop count check
    func testShouldForward() async throws {
        let config = FreshnessQuery.Config(maxHops: 3)
        let tracker = RecentContactTracker()
        let query = FreshnessQuery(recentContacts: tracker, config: config)

        XCTAssertTrue(query.shouldForward(hopCount: 0))
        XCTAssertTrue(query.shouldForward(hopCount: 1))
        XCTAssertTrue(query.shouldForward(hopCount: 2))
        XCTAssertFalse(query.shouldForward(hopCount: 3))
        XCTAssertFalse(query.shouldForward(hopCount: 4))
    }

    // MARK: - FreshnessManager Tests

    /// Test recording contact through manager
    func testFreshnessManagerRecordContact() async throws {
        let manager = FreshnessManager()

        await manager.recordContact(
            peerId: "peer-manager",
            reachability: .direct(endpoint: "1.2.3.4:5000"),
            latencyMs: 25,
            connectionType: .direct
        )

        let hasContact = await manager.hasRecentContact("peer-manager")
        XCTAssertTrue(hasContact)

        let contact = await manager.getRecentContact("peer-manager")
        XCTAssertNotNil(contact)
        XCTAssertEqual(contact?.latencyMs, 25)
    }

    /// Test manager handles whoHasRecent message
    func testFreshnessManagerHandleWhoHasRecent() async throws {
        let manager = FreshnessManager()

        // Record a contact first
        await manager.recordContact(
            peerId: "target-peer",
            reachability: .direct(endpoint: "1.2.3.4:5000"),
            latencyMs: 10,
            connectionType: .direct
        )

        // Handle whoHasRecent query
        let message = MeshMessage.whoHasRecent(peerId: "target-peer", maxAgeSeconds: 300)
        let (response, shouldForward) = await manager.handleMessage(message, from: "querier", hopCount: 0)

        XCTAssertNotNil(response)
        XCTAssertTrue(shouldForward, "Should forward to other peers")

        if case .iHaveRecent(let peerId, _, _) = response! {
            XCTAssertEqual(peerId, "target-peer")
        } else {
            XCTFail("Expected iHaveRecent response")
        }
    }

    /// Test manager handles iHaveRecent message
    func testFreshnessManagerHandleIHaveRecent() async throws {
        let manager = FreshnessManager()

        let message = MeshMessage.iHaveRecent(
            peerId: "target",
            lastSeenSecondsAgo: 30,
            reachability: .direct(endpoint: "1.2.3.4:5000")
        )
        let (response, shouldForward) = await manager.handleMessage(message, from: "responder", hopCount: 0)

        XCTAssertNil(response, "iHaveRecent should not produce response")
        XCTAssertFalse(shouldForward, "iHaveRecent should not be forwarded")
    }

    /// Test manager handles pathFailed message
    func testFreshnessManagerHandlePathFailed() async throws {
        let manager = FreshnessManager()
        let path = ReachabilityPath.direct(endpoint: "1.2.3.4:5000")

        let message = MeshMessage.pathFailed(peerId: "failed-peer", path: path, failedAt: Date())
        let (response, shouldForward) = await manager.handleMessage(message, from: "reporter", hopCount: 0)

        XCTAssertNil(response, "pathFailed should not produce response")
        XCTAssertTrue(shouldForward, "pathFailed should be forwarded")

        // Verify path is now marked as failed
        let isFailed = await manager.isPathFailed(peerId: "failed-peer", path: path)
        XCTAssertTrue(isFailed)
    }

    /// Test manager reportConnectionFailure
    /// Note: pathFailed broadcast was intentionally removed for security (prevents information leakage)
    /// Failure tracking is now local only
    func testFreshnessManagerReportConnectionFailure() async throws {
        let manager = FreshnessManager()
        let path = ReachabilityPath.direct(endpoint: "1.2.3.4:5000")

        // Record a contact first
        await manager.recordContact(
            peerId: "peer-to-fail",
            reachability: path,
            latencyMs: 10,
            connectionType: .direct
        )

        // Track if broadcast was called
        var broadcastCalled = false
        await manager.setCallbacks(
            sendMessage: { _, _ in },
            broadcastMessage: { _, _ in broadcastCalled = true },
            invalidateCache: { _, _ in }
        )

        // Report failure
        await manager.reportConnectionFailure(peerId: "peer-to-fail", path: path)

        // Failures are no longer broadcast (security: prevents information leakage)
        XCTAssertFalse(broadcastCalled, "Should NOT broadcast failure (security fix)")

        // But failures should still be tracked locally
        let isFailed = await manager.isPathFailed(peerId: "peer-to-fail", path: path)
        XCTAssertTrue(isFailed)
    }

    /// Test manager lifecycle
    func testFreshnessManagerLifecycle() async throws {
        let manager = FreshnessManager()

        await manager.start()
        // Should be running now

        await manager.stop()
        // Should be stopped now
    }

    /// Test recentContactCount
    func testRecentContactCount() async throws {
        let manager = FreshnessManager()

        var count = await manager.recentContactCount
        XCTAssertEqual(count, 0)

        await manager.recordContact(
            peerId: "peer-1",
            reachability: .direct(endpoint: "1.2.3.4:5000"),
            latencyMs: 10,
            connectionType: .direct
        )

        count = await manager.recentContactCount
        XCTAssertEqual(count, 1)
    }

    /// Test recentPeerIds
    func testRecentPeerIds() async throws {
        let manager = FreshnessManager()

        await manager.recordContact(
            peerId: "peer-a",
            reachability: .direct(endpoint: "1.2.3.4:5000"),
            latencyMs: 10,
            connectionType: .direct
        )

        await manager.recordContact(
            peerId: "peer-b",
            reachability: .direct(endpoint: "5.6.7.8:5000"),
            latencyMs: 10,
            connectionType: .direct
        )

        let peerIds = await manager.recentPeerIds
        XCTAssertEqual(peerIds.count, 2)
        XCTAssertTrue(peerIds.contains("peer-a"))
        XCTAssertTrue(peerIds.contains("peer-b"))
    }

    // MARK: - ConnectionType Tests

    /// Test ConnectionType raw values
    func testConnectionTypeRawValues() {
        XCTAssertEqual(ConnectionType.direct.rawValue, "direct")
        XCTAssertEqual(ConnectionType.inboundDirect.rawValue, "inboundDirect")
        XCTAssertEqual(ConnectionType.viaRelay.rawValue, "viaRelay")
        XCTAssertEqual(ConnectionType.holePunched.rawValue, "holePunched")
    }

    // MARK: - RecentContact Tests

    /// Test RecentContact initialization
    func testRecentContactInitialization() {
        let contact = RecentContact(
            peerId: "test-peer",
            lastSeen: Date(),
            reachability: .direct(endpoint: "1.2.3.4:5000"),
            latencyMs: 42,
            connectionType: .holePunched
        )

        XCTAssertEqual(contact.peerId, "test-peer")
        XCTAssertEqual(contact.latencyMs, 42)
        XCTAssertEqual(contact.connectionType, .holePunched)
    }

    // MARK: - PathFailure Tests

    /// Test PathFailure initialization
    func testPathFailureInitialization() {
        let failure = PathFailure(
            peerId: "failed-peer",
            path: .relay(relayPeerId: "relay", relayEndpoint: "1.2.3.4:5000"),
            failedAt: Date(),
            reportedBy: "reporter"
        )

        XCTAssertEqual(failure.peerId, "failed-peer")
        XCTAssertEqual(failure.reportedBy, "reporter")
    }

    /// Test PathFailure equality
    func testPathFailureEquality() {
        let date = Date()
        let failure1 = PathFailure(
            peerId: "peer",
            path: .direct(endpoint: "1.2.3.4:5000"),
            failedAt: date,
            reportedBy: nil
        )
        let failure2 = PathFailure(
            peerId: "peer",
            path: .direct(endpoint: "1.2.3.4:5000"),
            failedAt: date,
            reportedBy: nil
        )

        XCTAssertEqual(failure1, failure2)
    }

    // MARK: - FreshnessQueryResult Tests

    /// Test successful result
    func testFreshnessQueryResultSuccess() {
        let result = FreshnessQueryResult(
            peerId: "peer",
            reachability: .direct(endpoint: "1.2.3.4:5000"),
            lastSeenSecondsAgo: 30,
            responderId: "responder"
        )

        XCTAssertTrue(result.success)
        XCTAssertEqual(result.peerId, "peer")
        XCTAssertEqual(result.lastSeenSecondsAgo, 30)
        XCTAssertEqual(result.responderId, "responder")
    }

    /// Test notFound result
    func testFreshnessQueryResultNotFound() {
        let result = FreshnessQueryResult.notFound("unknown-peer")

        XCTAssertFalse(result.success)
        XCTAssertEqual(result.peerId, "unknown-peer")
        XCTAssertNil(result.reachability)
        XCTAssertNil(result.lastSeenSecondsAgo)
        XCTAssertNil(result.responderId)
    }

    // MARK: - Config Tests

    /// Test RecentContactTracker.Config defaults
    func testRecentContactTrackerConfigDefaults() {
        let config = RecentContactTracker.Config()

        XCTAssertEqual(config.maxAge, 300)
        XCTAssertEqual(config.maxContacts, 500)
        XCTAssertEqual(config.cleanupInterval, 60)
    }

    /// Test FreshnessQuery.Config defaults
    func testFreshnessQueryConfigDefaults() {
        let config = FreshnessQuery.Config()

        XCTAssertEqual(config.maxHops, 3)
        XCTAssertEqual(config.queryTimeout, 5.0)
        XCTAssertEqual(config.queryInterval, 30.0)
        XCTAssertEqual(config.maxAcceptableAge, 300)
        XCTAssertEqual(config.maxConcurrentQueries, 10)
    }

    /// Test PathFailureReporter.Config defaults
    func testPathFailureReporterConfigDefaults() {
        let config = PathFailureReporter.Config()

        XCTAssertEqual(config.reportInterval, 60.0)
        XCTAssertEqual(config.failureMemory, 300.0)
        XCTAssertEqual(config.maxFailures, 200)
        XCTAssertEqual(config.maxPropagationHops, 2)
    }

    /// Test FreshnessManager.Config defaults
    func testFreshnessManagerConfigDefaults() {
        let config = FreshnessManager.Config.default

        XCTAssertEqual(config.recentContactConfig.maxAge, 300)
        XCTAssertEqual(config.freshnessQueryConfig.maxHops, 3)
        XCTAssertEqual(config.pathFailureConfig.maxPropagationHops, 2)
    }
}
