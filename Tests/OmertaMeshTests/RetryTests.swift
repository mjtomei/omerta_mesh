// RetryTests.swift - Tests for retry functionality

import XCTest
@testable import OmertaMesh

final class RetryTests: XCTestCase {

    // MARK: - RetryConfig Tests

    func testRetryConfigDelayCalculation() {
        let config = RetryConfig(
            maxAttempts: 5,
            initialDelay: 1.0,
            maxDelay: 10.0,
            backoffMultiplier: 2.0,
            jitter: false  // Disable jitter for predictable testing
        )

        // Delays should follow exponential backoff: 1, 2, 4, 8, 10 (capped)
        XCTAssertEqual(config.delay(forAttempt: 0), 1.0)
        XCTAssertEqual(config.delay(forAttempt: 1), 2.0)
        XCTAssertEqual(config.delay(forAttempt: 2), 4.0)
        XCTAssertEqual(config.delay(forAttempt: 3), 8.0)
        XCTAssertEqual(config.delay(forAttempt: 4), 10.0)  // Capped at maxDelay
        XCTAssertEqual(config.delay(forAttempt: 10), 10.0)  // Still capped
    }

    func testRetryConfigWithJitter() {
        let config = RetryConfig(
            maxAttempts: 3,
            initialDelay: 1.0,
            maxDelay: 10.0,
            backoffMultiplier: 2.0,
            jitter: true
        )

        // With jitter, delays should be within range
        for _ in 0..<10 {
            let delay = config.delay(forAttempt: 0)
            XCTAssertGreaterThanOrEqual(delay, 1.0)
            XCTAssertLessThanOrEqual(delay, 1.25)  // Max 25% jitter
        }
    }

    func testRetryConfigPresets() {
        // Network preset
        XCTAssertEqual(RetryConfig.network.maxAttempts, 3)
        XCTAssertEqual(RetryConfig.network.initialDelay, 0.5)

        // Quick preset
        XCTAssertEqual(RetryConfig.quick.maxAttempts, 2)
        XCTAssertEqual(RetryConfig.quick.initialDelay, 0.1)

        // Persistent preset
        XCTAssertEqual(RetryConfig.persistent.maxAttempts, 5)
        XCTAssertEqual(RetryConfig.persistent.initialDelay, 1.0)
    }

    // MARK: - withRetry Tests

    func testWithRetrySucceedsFirstAttempt() async throws {
        var attempts = 0

        let result = try await withRetry(
            config: RetryConfig(maxAttempts: 3, initialDelay: 0.01, jitter: false),
            operation: "test"
        ) {
            attempts += 1
            return "success"
        }

        XCTAssertEqual(result, "success")
        XCTAssertEqual(attempts, 1)
    }

    func testWithRetrySucceedsAfterFailures() async throws {
        var attempts = 0

        let result = try await withRetry(
            config: RetryConfig(maxAttempts: 3, initialDelay: 0.01, jitter: false),
            operation: "test",
            shouldRetry: { _ in true }
        ) {
            attempts += 1
            if attempts < 3 {
                throw MeshError.timeout(operation: "test")
            }
            return "success"
        }

        XCTAssertEqual(result, "success")
        XCTAssertEqual(attempts, 3)
    }

    func testWithRetryExhaustsAttempts() async {
        var attempts = 0

        do {
            _ = try await withRetry(
                config: RetryConfig(maxAttempts: 3, initialDelay: 0.01, jitter: false),
                operation: "test",
                shouldRetry: { _ in true }
            ) { () -> String in
                attempts += 1
                throw MeshError.timeout(operation: "test")
            }
            XCTFail("Should have thrown")
        } catch {
            XCTAssertEqual(attempts, 3)
            if case MeshError.timeout = error {
                // Expected
            } else {
                XCTFail("Expected MeshError.timeout, got \(error)")
            }
        }
    }

    func testWithRetryDoesNotRetryNonRetryableError() async {
        var attempts = 0

        do {
            _ = try await withRetry(
                config: RetryConfig(maxAttempts: 3, initialDelay: 0.01, jitter: false),
                operation: "test"
            ) { () -> String in
                attempts += 1
                throw MeshError.invalidConfiguration(reason: "test")
            }
            XCTFail("Should have thrown")
        } catch {
            XCTAssertEqual(attempts, 1)  // Should not retry
        }
    }

    // MARK: - withRetryResult Tests

    func testWithRetryResultSuccess() async {
        let result = await withRetryResult(
            config: RetryConfig(maxAttempts: 3, initialDelay: 0.01, jitter: false),
            operation: "test"
        ) {
            return 42
        }

        if case .success(let value, let attempts) = result {
            XCTAssertEqual(value, 42)
            XCTAssertEqual(attempts, 1)
        } else {
            XCTFail("Expected success")
        }
    }

    func testWithRetryResultFailure() async {
        let result = await withRetryResult(
            config: RetryConfig(maxAttempts: 2, initialDelay: 0.01, jitter: false),
            operation: "test",
            shouldRetry: { _ in true }
        ) { () -> Int in
            throw MeshError.timeout(operation: "test")
        }

        if case .failure(let error, let attempts) = result {
            XCTAssertEqual(attempts, 2)
            XCTAssertTrue(error is MeshError)
        } else {
            XCTFail("Expected failure")
        }
    }

    // MARK: - MeshError.shouldRetry Tests

    func testMeshErrorShouldRetryValues() {
        // Should retry
        XCTAssertTrue(MeshError.timeout(operation: "test").shouldRetry)
        XCTAssertTrue(MeshError.connectionFailed(peerId: "test", reason: "test").shouldRetry)
        XCTAssertTrue(MeshError.sendFailed(reason: "test").shouldRetry)

        // Should not retry
        XCTAssertFalse(MeshError.peerNotFound(peerId: "test").shouldRetry)
        XCTAssertFalse(MeshError.invalidConfiguration(reason: "test").shouldRetry)
        XCTAssertFalse(MeshError.holePunchImpossible(peerId: "test").shouldRetry)
        XCTAssertFalse(MeshError.alreadyStarted.shouldRetry)
        XCTAssertFalse(MeshError.notStarted.shouldRetry)
    }
}
