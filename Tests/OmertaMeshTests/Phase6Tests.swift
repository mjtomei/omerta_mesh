// Phase6Tests.swift - Tests for Hole Punching (Phase 6)

import XCTest
import Foundation
@testable import OmertaMesh

final class Phase6Tests: XCTestCase {

    // MARK: - ProbePacket Tests

    /// Test probe packet serialization and parsing
    func testProbePacketSerializationRoundtrip() {
        let original = ProbePacket(
            sequence: 42,
            timestamp: 1234567890123,
            senderId: "test-peer-id",
            isResponse: false
        )

        let data = original.serialize()
        let parsed = ProbePacket.parse(data)

        XCTAssertNotNil(parsed)
        XCTAssertEqual(parsed?.sequence, 42)
        XCTAssertEqual(parsed?.timestamp, 1234567890123)
        XCTAssertFalse(parsed?.isResponse ?? true)
    }

    /// Test probe packet response flag
    func testProbePacketResponseFlag() {
        let probe = ProbePacket(
            sequence: 1,
            senderId: "peer",
            isResponse: true
        )

        let data = probe.serialize()
        let parsed = ProbePacket.parse(data)

        XCTAssertNotNil(parsed)
        XCTAssertTrue(parsed?.isResponse ?? false)
    }

    /// Test probe packet magic validation
    func testProbePacketMagicValidation() {
        // Valid probe
        let validProbe = ProbePacket(sequence: 1, senderId: "peer")
        let validData = validProbe.serialize()
        XCTAssertTrue(isHolePunchProbe(validData))

        // Invalid data
        let invalidData = Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
        XCTAssertFalse(isHolePunchProbe(invalidData))
    }

    /// Test probe packet size
    func testProbePacketSize() {
        let probe = ProbePacket(sequence: 0, senderId: "test")
        let data = probe.serialize()

        XCTAssertEqual(data.count, ProbePacket.packetSize)
    }

    /// Test sender ID truncation
    func testProbePacketSenderIdTruncation() {
        let longId = "this-is-a-very-long-peer-id-that-exceeds-sixteen-bytes"
        let probe = ProbePacket(sequence: 1, senderId: longId)
        let data = probe.serialize()
        let parsed = ProbePacket.parse(data)

        XCTAssertNotNil(parsed)
        // Sender ID should be truncated to 16 bytes
    }

    // MARK: - HolePunchStrategy Tests

    /// Test strategy selection for cone to cone
    func testStrategySelectionConeToCone() {
        let strategy = HolePunchStrategy.select(
            initiator: .restrictedCone,
            responder: .portRestrictedCone
        )
        XCTAssertEqual(strategy, .simultaneous)
    }

    /// Test strategy selection for symmetric to symmetric
    func testStrategySelectionSymmetricToSymmetric() {
        let strategy = HolePunchStrategy.select(
            initiator: .symmetric,
            responder: .symmetric
        )
        XCTAssertEqual(strategy, .impossible)
    }

    /// Test strategy selection for symmetric to cone
    func testStrategySelectionSymmetricToCone() {
        let strategy = HolePunchStrategy.select(
            initiator: .symmetric,
            responder: .restrictedCone
        )
        XCTAssertEqual(strategy, .initiatorFirst)
    }

    /// Test strategy selection for cone to symmetric
    func testStrategySelectionConeToSymmetric() {
        let strategy = HolePunchStrategy.select(
            initiator: .restrictedCone,
            responder: .symmetric
        )
        XCTAssertEqual(strategy, .responderFirst)
    }

    /// Test strategy selection for public to public
    func testStrategySelectionPublicToPublic() {
        let strategy = HolePunchStrategy.select(
            initiator: .public,
            responder: .fullCone
        )
        XCTAssertEqual(strategy, .simultaneous)
    }

    /// Test strategy canSucceed property
    func testStrategyCanSucceed() {
        XCTAssertTrue(HolePunchStrategy.simultaneous.canSucceed)
        XCTAssertTrue(HolePunchStrategy.initiatorFirst.canSucceed)
        XCTAssertTrue(HolePunchStrategy.responderFirst.canSucceed)
        XCTAssertFalse(HolePunchStrategy.impossible.canSucceed)
    }

    /// Test strategy explanation
    func testStrategyExplanation() {
        XCTAssertFalse(HolePunchStrategy.simultaneous.explanation.isEmpty)
        XCTAssertFalse(HolePunchStrategy.initiatorFirst.explanation.isEmpty)
        XCTAssertFalse(HolePunchStrategy.responderFirst.explanation.isEmpty)
        XCTAssertFalse(HolePunchStrategy.impossible.explanation.isEmpty)
    }

    // MARK: - NATType Extension Tests

    /// Test isDirectlyReachable
    func testNATTypeIsDirectlyReachable() {
        XCTAssertTrue(NATType.public.isDirectlyReachable)
        XCTAssertTrue(NATType.fullCone.isDirectlyReachable)
        XCTAssertFalse(NATType.restrictedCone.isDirectlyReachable)
        XCTAssertFalse(NATType.portRestrictedCone.isDirectlyReachable)
        XCTAssertFalse(NATType.symmetric.isDirectlyReachable)
        XCTAssertFalse(NATType.unknown.isDirectlyReachable)
    }

    /// Test isConeType
    func testNATTypeIsConeType() {
        XCTAssertTrue(NATType.fullCone.isConeType)
        XCTAssertTrue(NATType.restrictedCone.isConeType)
        XCTAssertTrue(NATType.portRestrictedCone.isConeType)
        XCTAssertFalse(NATType.public.isConeType)
        XCTAssertFalse(NATType.symmetric.isConeType)
        XCTAssertFalse(NATType.unknown.isConeType)
    }

    /// Test canHolePunch
    func testNATTypeCanHolePunch() {
        XCTAssertTrue(NATType.public.canHolePunch)
        XCTAssertTrue(NATType.fullCone.canHolePunch)
        XCTAssertTrue(NATType.restrictedCone.canHolePunch)
        XCTAssertTrue(NATType.portRestrictedCone.canHolePunch)
        XCTAssertFalse(NATType.symmetric.canHolePunch)
        XCTAssertFalse(NATType.unknown.canHolePunch)
    }

    /// Test holePunchDifficulty ordering
    func testNATTypeHolePunchDifficulty() {
        XCTAssertLessThan(NATType.public.holePunchDifficulty, NATType.fullCone.holePunchDifficulty)
        XCTAssertLessThan(NATType.fullCone.holePunchDifficulty, NATType.restrictedCone.holePunchDifficulty)
        XCTAssertLessThan(NATType.restrictedCone.holePunchDifficulty, NATType.portRestrictedCone.holePunchDifficulty)
        XCTAssertLessThan(NATType.portRestrictedCone.holePunchDifficulty, NATType.symmetric.holePunchDifficulty)
    }

    // MARK: - HolePunchCompatibility Tests

    /// Test compatibility check for easy case
    func testCompatibilityCheckEasy() {
        let compat = HolePunchCompatibility.check(
            initiator: .fullCone,
            responder: .fullCone
        )

        XCTAssertEqual(compat.strategy, .simultaneous)
        XCTAssertTrue(compat.likely)
        XCTAssertLessThanOrEqual(compat.difficulty, 2)
    }

    /// Test compatibility check for impossible case
    func testCompatibilityCheckImpossible() {
        let compat = HolePunchCompatibility.check(
            initiator: .symmetric,
            responder: .symmetric
        )

        XCTAssertEqual(compat.strategy, .impossible)
        XCTAssertFalse(compat.likely)
        XCTAssertTrue(compat.recommendation.contains("relay"))
    }

    /// Test compatibility check for mixed case
    func testCompatibilityCheckMixed() {
        let compat = HolePunchCompatibility.check(
            initiator: .symmetric,
            responder: .restrictedCone
        )

        XCTAssertEqual(compat.strategy, .initiatorFirst)
        XCTAssertFalse(compat.recommendation.isEmpty)
    }

    // MARK: - HolePunchFailure Tests

    /// Test failure descriptions
    func testHolePunchFailureDescriptions() {
        XCTAssertEqual(HolePunchFailure.timeout.description, "Hole punch timed out")
        XCTAssertEqual(HolePunchFailure.bothSymmetric.description, "Both peers have symmetric NAT - hole punching impossible")
        XCTAssertEqual(HolePunchFailure.bindFailed.description, "Failed to bind UDP socket")
        XCTAssertTrue(HolePunchFailure.invalidEndpoint("bad").description.contains("bad"))
        XCTAssertEqual(HolePunchFailure.cancelled.description, "Hole punch was cancelled")
        XCTAssertTrue(HolePunchFailure.socketError("test").description.contains("test"))
    }

    /// Test failure equality
    func testHolePunchFailureEquality() {
        XCTAssertEqual(HolePunchFailure.timeout, HolePunchFailure.timeout)
        XCTAssertEqual(HolePunchFailure.invalidEndpoint("a"), HolePunchFailure.invalidEndpoint("a"))
        XCTAssertNotEqual(HolePunchFailure.invalidEndpoint("a"), HolePunchFailure.invalidEndpoint("b"))
        XCTAssertNotEqual(HolePunchFailure.timeout, HolePunchFailure.cancelled)
    }

    // MARK: - HolePunchResult Tests

    /// Test success result
    func testHolePunchResultSuccess() {
        let result = HolePunchResult.success(endpoint: "1.2.3.4:5000", rtt: 0.05)

        XCTAssertTrue(result.succeeded)
        XCTAssertEqual(result.endpoint, "1.2.3.4:5000")
    }

    /// Test failed result
    func testHolePunchResultFailed() {
        let result = HolePunchResult.failed(reason: .timeout)

        XCTAssertFalse(result.succeeded)
        XCTAssertNil(result.endpoint)
    }

    /// Test result equality
    func testHolePunchResultEquality() {
        let success1 = HolePunchResult.success(endpoint: "1.2.3.4:5000", rtt: 0.05)
        let success2 = HolePunchResult.success(endpoint: "1.2.3.4:5000", rtt: 0.05)
        let failed1 = HolePunchResult.failed(reason: .timeout)
        let failed2 = HolePunchResult.failed(reason: .timeout)

        XCTAssertEqual(success1, success2)
        XCTAssertEqual(failed1, failed2)
        XCTAssertNotEqual(success1, failed1)
    }

    // MARK: - HolePunchConfig Tests

    /// Test default config
    func testHolePunchConfigDefaults() {
        let config = HolePunchConfig.default

        XCTAssertEqual(config.probeCount, 5)
        XCTAssertEqual(config.probeInterval, 0.2)
        XCTAssertEqual(config.timeout, 10.0)
        XCTAssertTrue(config.sendResponseProbes)
        XCTAssertEqual(config.responseProbeCount, 3)
    }

    /// Test custom config
    func testHolePunchConfigCustom() {
        let config = HolePunchConfig(
            probeCount: 10,
            probeInterval: 0.5,
            timeout: 20.0,
            sendResponseProbes: false,
            responseProbeCount: 5
        )

        XCTAssertEqual(config.probeCount, 10)
        XCTAssertEqual(config.probeInterval, 0.5)
        XCTAssertEqual(config.timeout, 20.0)
        XCTAssertFalse(config.sendResponseProbes)
        XCTAssertEqual(config.responseProbeCount, 5)
    }

    // MARK: - HolePuncher Tests

    /// Test hole puncher initialization
    func testHolePuncherInitialization() async {
        let puncher = HolePuncher(peerId: "test-peer")

        let count = await puncher.activeSessionCount
        XCTAssertEqual(count, 0)
    }

    /// Test impossible strategy returns failure
    func testHolePuncherImpossibleStrategy() async {
        let puncher = HolePuncher(peerId: "test-peer")

        let result = await puncher.execute(
            targetPeerId: "target",
            targetEndpoint: "1.2.3.4:5000",
            strategy: .impossible,
            localPort: 0
        )

        XCTAssertFalse(result.succeeded)
        if case .failed(let reason) = result {
            XCTAssertEqual(reason, .bothSymmetric)
        } else {
            XCTFail("Expected failed result")
        }
    }

    // MARK: - HolePunchRequest Tests

    /// Test request initialization
    func testHolePunchRequestInitialization() {
        let request = HolePunchRequest(
            initiatorPeerId: "initiator",
            initiatorEndpoint: "1.2.3.4:5000",
            initiatorNATType: .restrictedCone,
            targetPeerId: "target"
        )

        XCTAssertEqual(request.initiatorPeerId, "initiator")
        XCTAssertEqual(request.initiatorEndpoint, "1.2.3.4:5000")
        XCTAssertEqual(request.initiatorNATType, .restrictedCone)
        XCTAssertEqual(request.targetPeerId, "target")
        XCTAssertEqual(request.state, .pending)
    }

    /// Test request state
    func testHolePunchRequestState() {
        var request = HolePunchRequest(
            initiatorPeerId: "initiator",
            initiatorEndpoint: "1.2.3.4:5000",
            initiatorNATType: .restrictedCone,
            targetPeerId: "target"
        )

        XCTAssertEqual(request.state, .pending)

        request.state = .inviteSent
        XCTAssertEqual(request.state, .inviteSent)

        request.state = .executing
        XCTAssertEqual(request.state, .executing)

        request.state = .completed(success: true)
        if case .completed(let success) = request.state {
            XCTAssertTrue(success)
        } else {
            XCTFail("Expected completed state")
        }
    }

    // MARK: - HolePunchCoordinator Tests

    /// Test coordinator initialization
    func testCoordinatorInitialization() async {
        let coordinator = HolePunchCoordinator()

        let count = await coordinator.activeRequestCount
        XCTAssertEqual(count, 0)
    }

    /// Test coordinator config defaults
    func testCoordinatorConfigDefaults() {
        let config = HolePunchCoordinator.Config.default

        XCTAssertEqual(config.inviteTimeout, 10.0)
        XCTAssertEqual(config.requestTimeout, 30.0)
        XCTAssertEqual(config.maxConcurrent, 50)
        XCTAssertEqual(config.cleanupInterval, 60.0)
    }

    /// Test coordinator lifecycle
    func testCoordinatorLifecycle() async {
        let coordinator = HolePunchCoordinator()

        await coordinator.start()
        await coordinator.stop()

        let count = await coordinator.activeRequestCount
        XCTAssertEqual(count, 0)
    }

    // MARK: - HolePunchManager Tests

    /// Test manager initialization
    func testManagerInitialization() async {
        let manager = HolePunchManager(peerId: "test-peer")

        let count = await manager.activeHolePunchCount
        XCTAssertEqual(count, 0)
    }

    /// Test manager config
    func testManagerConfig() {
        let config = HolePunchManager.Config(
            canCoordinate: true
        )

        XCTAssertTrue(config.canCoordinate)
    }

    /// Test manager lifecycle
    func testManagerLifecycle() async {
        let manager = HolePunchManager(peerId: "test-peer")

        await manager.start(natType: .restrictedCone, localPort: 5000)
        await manager.stop()

        let count = await manager.activeHolePunchCount
        XCTAssertEqual(count, 0)
    }

    /// Test manager with coordinator
    func testManagerWithCoordinator() async {
        let config = HolePunchManager.Config(canCoordinate: true)
        let manager = HolePunchManager(peerId: "test-peer", config: config)

        await manager.start(natType: .public, localPort: 5000)

        let coordCount = await manager.coordinatorRequestCount
        XCTAssertEqual(coordCount, 0)

        await manager.stop()
    }

    /// Test manager NAT type update
    func testManagerNATTypeUpdate() async {
        let manager = HolePunchManager(peerId: "test-peer")

        await manager.start(natType: .unknown, localPort: 5000)
        await manager.updateNATType(.restrictedCone)
        await manager.stop()
    }

    // MARK: - HolePunchRequestState Tests

    /// Test state equality
    func testRequestStateEquality() {
        XCTAssertEqual(HolePunchRequestState.pending, HolePunchRequestState.pending)
        XCTAssertEqual(HolePunchRequestState.inviteSent, HolePunchRequestState.inviteSent)
        XCTAssertEqual(HolePunchRequestState.executing, HolePunchRequestState.executing)
        XCTAssertEqual(HolePunchRequestState.expired, HolePunchRequestState.expired)
        XCTAssertEqual(HolePunchRequestState.completed(success: true), HolePunchRequestState.completed(success: true))
        XCTAssertNotEqual(HolePunchRequestState.completed(success: true), HolePunchRequestState.completed(success: false))
        XCTAssertNotEqual(HolePunchRequestState.pending, HolePunchRequestState.executing)
    }
}
