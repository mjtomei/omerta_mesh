// KnownContactsTests.swift - Tests for Phase 2: Contact Tracking for All NAT Types

import XCTest
import Foundation
@testable import OmertaMesh

final class KnownContactsTests: XCTestCase {

    // MARK: - KnownContact Struct Tests

    func testKnownContactStruct() {
        let contact = MeshNode.KnownContact(
            contactMachineId: "contact-machine",
            contactPeerId: "contact-peer",
            lastSeen: Date(),
            isFirstHand: true
        )

        XCTAssertEqual(contact.contactMachineId, "contact-machine")
        XCTAssertEqual(contact.contactPeerId, "contact-peer")
        XCTAssertTrue(contact.isFirstHand)
    }

    // MARK: - Contact Recording Tests

    func testRecordKnownContact() async throws {
        let node = try await createTestMeshNode(peerId: "test-node")

        // Record a contact
        await node.recordKnownContact(
            for: "target-machine",
            targetPeerId: "target-peer",
            via: "contact-machine",
            contactPeerId: "contact-peer",
            isFirstHand: true
        )

        let contacts = await node.getContactsForMachine("target-machine")
        XCTAssertEqual(contacts.count, 1)
        XCTAssertEqual(contacts.first?.contactMachineId, "contact-machine")
        XCTAssertEqual(contacts.first?.contactPeerId, "contact-peer")
        XCTAssertTrue(contacts.first?.isFirstHand ?? false)
    }

    func testRecordMultipleContacts() async throws {
        let node = try await createTestMeshNode(peerId: "test-node")

        // Record multiple contacts for the same target
        await node.recordKnownContact(
            for: "target", targetPeerId: "t",
            via: "contact1", contactPeerId: "peer1",
            isFirstHand: true
        )
        await node.recordKnownContact(
            for: "target", targetPeerId: "t",
            via: "contact2", contactPeerId: "peer2",
            isFirstHand: false
        )
        await node.recordKnownContact(
            for: "target", targetPeerId: "t",
            via: "contact3", contactPeerId: "peer3",
            isFirstHand: true
        )

        let contacts = await node.getContactsForMachine("target")
        XCTAssertEqual(contacts.count, 3)
    }

    func testDuplicateContactUpdatesPosition() async throws {
        let node = try await createTestMeshNode(peerId: "test-node")

        // Add first contact
        await node.recordKnownContact(
            for: "target", targetPeerId: "t",
            via: "contact1", contactPeerId: "peer1",
            isFirstHand: true
        )

        // Add second contact
        await node.recordKnownContact(
            for: "target", targetPeerId: "t",
            via: "contact2", contactPeerId: "peer2",
            isFirstHand: true
        )

        // Re-add first contact (should move to front)
        await node.recordKnownContact(
            for: "target", targetPeerId: "t",
            via: "contact1", contactPeerId: "peer1",
            isFirstHand: true
        )

        let contacts = await node.getContactsForMachine("target")
        XCTAssertEqual(contacts.count, 2)
        // Most recent (contact1) should be first when both are first-hand
        XCTAssertEqual(contacts.first?.contactMachineId, "contact1")
    }

    func testMaxContactsLimit() async throws {
        let node = try await createTestMeshNode(peerId: "test-node")

        // Add more than maxContactsPerMachine (10)
        for i in 0..<15 {
            await node.recordKnownContact(
                for: "target", targetPeerId: "t",
                via: "contact\(i)", contactPeerId: "peer\(i)",
                isFirstHand: true
            )
        }

        let contacts = await node.getContactsForMachine("target")
        XCTAssertEqual(contacts.count, 10, "Should be limited to maxContactsPerMachine")
        // Most recent should be first
        XCTAssertEqual(contacts.first?.contactMachineId, "contact14")
    }

    func testDoesNotRecordSelfAsContact() async throws {
        let node = try await createTestMeshNode(peerId: "test-node")
        let nodePeerId = await node.peerId

        // Try to record self as contact
        await node.recordKnownContact(
            for: "target", targetPeerId: "t",
            via: "self-machine", contactPeerId: nodePeerId,
            isFirstHand: true
        )

        let contacts = await node.getContactsForMachine("target")
        XCTAssertTrue(contacts.isEmpty, "Should not record self as contact")
    }

    func testDoesNotRecordTargetAsOwnContact() async throws {
        let node = try await createTestMeshNode(peerId: "test-node")

        // Try to record target as its own contact
        await node.recordKnownContact(
            for: "target", targetPeerId: "t",
            via: "target", contactPeerId: "peer",
            isFirstHand: true
        )

        let contacts = await node.getContactsForMachine("target")
        XCTAssertTrue(contacts.isEmpty, "Should not record target as its own contact")
    }

    // MARK: - Contact Selection Priority Tests

    func testFirstHandContactsPrioritized() async throws {
        let node = try await createTestMeshNode(peerId: "test-node")

        // Add second-hand first
        await node.recordKnownContact(
            for: "target", targetPeerId: "t",
            via: "secondHand", contactPeerId: "secondHandPeer",
            isFirstHand: false
        )

        // Small delay to ensure different timestamps
        try await Task.sleep(nanoseconds: 10_000_000)

        // Add first-hand second
        await node.recordKnownContact(
            for: "target", targetPeerId: "t",
            via: "firstHand", contactPeerId: "firstHandPeer",
            isFirstHand: true
        )

        let contacts = await node.getContactsForMachine("target")
        XCTAssertEqual(contacts.first?.contactMachineId, "firstHand", "First-hand contacts should be prioritized")
    }

    // MARK: - Helper

    private func createTestMeshNode(peerId: String) async throws -> MeshNode {
        let identity = IdentityKeypair()
        let testKey = Data(repeating: 0x42, count: 32)
        let config = MeshNode.Config(encryptionKey: testKey, port: 0)
        return try MeshNode(identity: identity, config: config)
    }
}
