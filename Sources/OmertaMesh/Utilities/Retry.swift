// Retry.swift - Retry logic for recoverable operations

import Foundation
import Logging

/// Configuration for retry behavior
public struct RetryConfig: Sendable {
    /// Maximum number of retry attempts
    public let maxAttempts: Int

    /// Initial delay between retries (seconds)
    public let initialDelay: TimeInterval

    /// Maximum delay between retries (seconds)
    public let maxDelay: TimeInterval

    /// Multiplier for exponential backoff
    public let backoffMultiplier: Double

    /// Whether to add jitter to delays
    public let jitter: Bool

    public init(
        maxAttempts: Int = 3,
        initialDelay: TimeInterval = 0.1,
        maxDelay: TimeInterval = 5.0,
        backoffMultiplier: Double = 2.0,
        jitter: Bool = true
    ) {
        self.maxAttempts = maxAttempts
        self.initialDelay = initialDelay
        self.maxDelay = maxDelay
        self.backoffMultiplier = backoffMultiplier
        self.jitter = jitter
    }

    /// Default configuration for network operations
    public static let network = RetryConfig(
        maxAttempts: 3,
        initialDelay: 0.5,
        maxDelay: 10.0,
        backoffMultiplier: 2.0,
        jitter: true
    )

    /// Quick retry for latency-sensitive operations
    public static let quick = RetryConfig(
        maxAttempts: 2,
        initialDelay: 0.1,
        maxDelay: 1.0,
        backoffMultiplier: 2.0,
        jitter: true
    )

    /// Persistent retry for important operations
    public static let persistent = RetryConfig(
        maxAttempts: 5,
        initialDelay: 1.0,
        maxDelay: 30.0,
        backoffMultiplier: 2.0,
        jitter: true
    )

    /// Calculate delay for a given attempt number (0-indexed)
    public func delay(forAttempt attempt: Int) -> TimeInterval {
        var delay = initialDelay * pow(backoffMultiplier, Double(attempt))
        delay = min(delay, maxDelay)

        if jitter {
            // Add up to 25% jitter
            let jitterAmount = delay * 0.25 * Double.random(in: 0...1)
            delay += jitterAmount
        }

        return delay
    }
}

/// Result of a retry operation
public enum RetryResult<T: Sendable>: Sendable {
    case success(T, attempts: Int)
    case failure(Error, attempts: Int)
}

/// Execute an operation with retry logic
/// - Parameters:
///   - config: Retry configuration
///   - operation: The name of the operation (for logging)
///   - shouldRetry: Closure to determine if an error should trigger retry
///   - action: The async operation to execute
/// - Returns: The result of the operation
public func withRetry<T: Sendable>(
    config: RetryConfig = .network,
    operation: String,
    shouldRetry: @escaping (Error) -> Bool = { ($0 as? MeshError)?.shouldRetry ?? false },
    action: @escaping () async throws -> T
) async throws -> T {
    var lastError: Error?
    let logger = Logger(label: "io.omerta.mesh.retry")

    for attempt in 0..<config.maxAttempts {
        do {
            let result = try await action()
            if attempt > 0 {
                logger.info("Operation '\(operation)' succeeded after \(attempt + 1) attempts")
            }
            return result
        } catch {
            lastError = error

            // Check if we should retry
            guard shouldRetry(error) else {
                logger.debug("Operation '\(operation)' failed with non-retryable error: \(error)")
                throw error
            }

            // Check if we have more attempts
            guard attempt < config.maxAttempts - 1 else {
                logger.warning("Operation '\(operation)' failed after \(config.maxAttempts) attempts: \(error)")
                throw error
            }

            // Calculate and wait for delay
            let delay = config.delay(forAttempt: attempt)
            logger.debug("Operation '\(operation)' failed (attempt \(attempt + 1)/\(config.maxAttempts)), retrying in \(String(format: "%.2f", delay))s: \(error)")

            try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
        }
    }

    throw lastError ?? MeshError.internalError(reason: "Retry failed with no error")
}

/// Execute an operation with retry, returning a result instead of throwing
public func withRetryResult<T: Sendable>(
    config: RetryConfig = .network,
    operation: String,
    shouldRetry: @escaping (Error) -> Bool = { ($0 as? MeshError)?.shouldRetry ?? false },
    action: @escaping () async throws -> T
) async -> RetryResult<T> {
    var attempts = 0
    let logger = Logger(label: "io.omerta.mesh.retry")

    for attempt in 0..<config.maxAttempts {
        attempts = attempt + 1
        do {
            let result = try await action()
            return .success(result, attempts: attempts)
        } catch {
            // Check if we should retry
            guard shouldRetry(error) else {
                return .failure(error, attempts: attempts)
            }

            // Check if we have more attempts
            guard attempt < config.maxAttempts - 1 else {
                return .failure(error, attempts: attempts)
            }

            // Calculate and wait for delay
            let delay = config.delay(forAttempt: attempt)
            logger.debug("Operation '\(operation)' failed (attempt \(attempt + 1)), retrying in \(String(format: "%.2f", delay))s")

            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
        }
    }

    return .failure(MeshError.internalError(reason: "Retry exhausted"), attempts: attempts)
}
