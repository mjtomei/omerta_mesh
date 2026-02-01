// CryptoProcessPool.swift - ChaCha20-Poly1305 encrypt/decrypt worker process pool
//
// Offloads chunked payload encryption/decryption to forked worker processes
// communicating via shared memory rings and eventfd signaling.
// This breaks the actor serialization bottleneck in MeshNode for high-throughput scenarios.
//
// Only available on Linux (uses fork()).

#if os(Linux)

import Glibc
import Foundation
import Crypto

/// Process pool for ChaCha20-Poly1305 chunk encryption/decryption.
///
/// Workers are forked from the parent process and inherit the mmap'd shared memory
/// region. Jobs are dispatched via per-worker ring buffers with eventfd signaling.
public final class CryptoProcessPool: @unchecked Sendable {
    /// Shared memory region
    private let region: SharedMemoryRegion

    /// Worker PIDs
    private var workerPids: [pid_t]

    /// Number of workers
    public let workerCount: Int

    /// Number of slots
    public let slotCount: Int

    /// Round-robin counter for worker assignment
    private var nextWorker: Int = 0

    /// Lock for slot allocation and worker assignment
    private let lock = NSLock()

    /// Pending completions: slot index → continuation
    private var pendingCompletions: [Int: CheckedContinuation<Void, Never>] = [:]
    private let completionLock = NSLock()

    /// Whether the pool is running
    private var isRunning = true

    /// Completion monitor thread
    private var monitorThread: Thread?

    /// Create and start a crypto process pool.
    ///
    /// - Parameters:
    ///   - workerCount: Number of worker processes (default: processor count)
    ///   - slotCount: Number of shared memory slots (default: 32)
    public init(workerCount: Int = ProcessInfo.processInfo.processorCount, slotCount: Int = 32) throws {
        self.workerCount = max(workerCount, 1)
        self.slotCount = max(slotCount, 4)
        self.workerPids = []

        self.region = try SharedMemoryRegion(slotCount: self.slotCount, workerCount: self.workerCount)

        // Fork workers
        for i in 0..<self.workerCount {
            let pid = fork()
            if pid == 0 {
                // Child process — enter worker loop (never returns)
                cryptoWorkerLoop(workerId: i, region: region)
            } else if pid > 0 {
                workerPids.append(pid)
            } else {
                // Fork failed — kill already-forked workers and throw
                for existingPid in workerPids {
                    kill(existingPid, SIGKILL)
                    var status: Int32 = 0
                    waitpid(existingPid, &status, 0)
                }
                throw ProcessPoolError.forkFailed(errno)
            }
        }

        // Start completion monitor thread
        startCompletionMonitor()
    }

    deinit {
        shutdown()
    }

    /// Shutdown all workers gracefully.
    public func shutdown() {
        lock.lock()
        guard isRunning else {
            lock.unlock()
            return
        }
        isRunning = false
        lock.unlock()

        // Kill all workers
        for pid in workerPids {
            kill(pid, SIGTERM)
        }

        // Wait for workers to exit (with timeout)
        for pid in workerPids {
            var status: Int32 = 0
            // Non-blocking wait, then SIGKILL if needed
            let result = waitpid(pid, &status, WNOHANG)
            if result == 0 {
                // Still running, give it 100ms then force kill
                usleep(100_000)
                kill(pid, SIGKILL)
                waitpid(pid, &status, 0)
            }
        }
        workerPids.removeAll()

        // Resume any pending completions
        completionLock.lock()
        let pending = pendingCompletions
        pendingCompletions.removeAll()
        completionLock.unlock()

        for (_, continuation) in pending {
            continuation.resume()
        }
    }

    // MARK: - Decrypt

    /// Submit a decryption job and wait for completion.
    ///
    /// - Parameters:
    ///   - encryptedPayload: The encrypted chunk region (ciphertext+tag pairs contiguous)
    ///   - chunkCount: Number of chunks
    ///   - totalPlaintextLen: Total plaintext length
    ///   - key: The symmetric key (32 bytes)
    ///   - baseNonce: The base nonce (12 bytes)
    /// - Returns: Decrypted plaintext data
    public func decrypt(
        encryptedPayload: Data,
        chunkCount: Int,
        totalPlaintextLen: Int,
        key: SymmetricKey,
        baseNonce: [UInt8]
    ) async throws -> Data {
        guard isRunning else { throw ProcessPoolError.shutdownInProgress }
        guard encryptedPayload.count <= kInputRegionSize else { throw ProcessPoolError.payloadTooLarge }

        // Acquire a slot
        let slotIndex = try acquireSlotWithBackpressure()

        // Fill slot header
        region.setOperation(slotIndex, CryptoOperation.decrypt.rawValue)
        region.setChunkCount(slotIndex, UInt16(chunkCount))
        region.setTotalPlaintextLen(slotIndex, UInt32(totalPlaintextLen))

        // Copy key
        key.withUnsafeBytes { keyBuf in
            region.setKey(slotIndex, UnsafeRawBufferPointer(keyBuf))
        }

        // Copy nonce
        baseNonce.withUnsafeBytes { nonceBuf in
            region.setBaseNonce(slotIndex, UnsafeRawBufferPointer(nonceBuf))
        }

        // Copy encrypted data to input region
        let inputPtr = region.slotInput(slotIndex)
        encryptedPayload.withUnsafeBytes { src in
            memcpy(inputPtr, src.baseAddress!, src.count)
        }

        // Assign to worker and signal
        let worker = assignWorker()
        region.setWorkerAssignment(slotIndex, UInt8(worker))

        // Submit and wait
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            completionLock.lock()
            pendingCompletions[slotIndex] = continuation
            completionLock.unlock()

            // Push to worker ring and signal
            _ = region.pushToWorkerRing(worker, slotIndex: slotIndex)
            signalEventfd(region.workerSignalWrite[worker])
        }

        // Read output
        let outputPtr = region.slotOutput(slotIndex)
        let result = Data(bytes: outputPtr, count: totalPlaintextLen)

        // Release slot
        region.releaseSlot(slotIndex)

        return result
    }

    // MARK: - Encrypt

    /// Submit an encryption job and wait for completion.
    ///
    /// - Parameters:
    ///   - plaintext: The plaintext data
    ///   - chunkCount: Number of chunks
    ///   - key: The symmetric key (32 bytes)
    ///   - baseNonce: The base nonce (12 bytes)
    /// - Returns: Encrypted data (ciphertext+tag pairs contiguous)
    public func encrypt(
        plaintext: Data,
        chunkCount: Int,
        key: SymmetricKey,
        baseNonce: [UInt8]
    ) async throws -> Data {
        guard isRunning else { throw ProcessPoolError.shutdownInProgress }
        guard plaintext.count <= kInputRegionSize else { throw ProcessPoolError.payloadTooLarge }

        let slotIndex = try acquireSlotWithBackpressure()

        region.setOperation(slotIndex, CryptoOperation.encrypt.rawValue)
        region.setChunkCount(slotIndex, UInt16(chunkCount))
        region.setTotalPlaintextLen(slotIndex, UInt32(plaintext.count))

        key.withUnsafeBytes { keyBuf in
            region.setKey(slotIndex, UnsafeRawBufferPointer(keyBuf))
        }

        baseNonce.withUnsafeBytes { nonceBuf in
            region.setBaseNonce(slotIndex, UnsafeRawBufferPointer(nonceBuf))
        }

        // Copy plaintext to input region
        let inputPtr = region.slotInput(slotIndex)
        plaintext.withUnsafeBytes { src in
            memcpy(inputPtr, src.baseAddress!, src.count)
        }

        let worker = assignWorker()
        region.setWorkerAssignment(slotIndex, UInt8(worker))

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            completionLock.lock()
            pendingCompletions[slotIndex] = continuation
            completionLock.unlock()

            _ = region.pushToWorkerRing(worker, slotIndex: slotIndex)
            signalEventfd(region.workerSignalWrite[worker])
        }

        // Read output: each chunk produces chunkLen + 16 bytes
        let outputPtr = region.slotOutput(slotIndex)
        var totalOutputSize = 0
        let plaintextLen = plaintext.count
        for i in 0..<chunkCount {
            let chunkLen: Int
            if plaintextLen == 0 {
                chunkLen = 0
            } else if i < chunkCount - 1 {
                chunkLen = kCryptoChunkSize
            } else {
                let remainder = plaintextLen % kCryptoChunkSize
                chunkLen = remainder == 0 ? kCryptoChunkSize : remainder
            }
            totalOutputSize += chunkLen + 16
        }

        let result = Data(bytes: outputPtr, count: totalOutputSize)
        region.releaseSlot(slotIndex)
        return result
    }

    // MARK: - Worker Management

    /// Check worker health and restart crashed workers.
    public func checkWorkers() {
        lock.lock()
        defer { lock.unlock() }
        guard isRunning else { return }

        for i in 0..<workerPids.count {
            var status: Int32 = 0
            let result = waitpid(workerPids[i], &status, WNOHANG)
            if result > 0 {
                // Worker exited — restart
                let pid = fork()
                if pid == 0 {
                    cryptoWorkerLoop(workerId: i, region: region)
                } else if pid > 0 {
                    workerPids[i] = pid
                }
            }
        }
    }

    // MARK: - Private

    private func assignWorker() -> Int {
        lock.lock()
        let worker = nextWorker
        nextWorker = (nextWorker + 1) % workerCount
        lock.unlock()
        return worker
    }

    private func acquireSlotWithBackpressure() throws -> Int {
        // Try to acquire a slot, spin briefly if all are busy
        for _ in 0..<1000 {
            if let slot = region.acquireSlot() {
                return slot
            }
            usleep(10)  // 10µs
        }
        throw ProcessPoolError.slotExhausted
    }

    private func startCompletionMonitor() {
        let thread = Thread {
            while self.isRunning {
                // Wait for completion signal from any worker
                let gotSignal = waitEventfd(self.region.completionSignalRead, timeoutUs: 50_000)
                if gotSignal {
                    drainEventfd(self.region.completionSignalRead)
                }

                // Check all slots for completion
                self.completionLock.lock()
                let pendingSlots = Array(self.pendingCompletions.keys)
                self.completionLock.unlock()

                for slotIndex in pendingSlots {
                    if self.region.getStatus(slotIndex) == SlotStatus.done.rawValue {
                        self.completionLock.lock()
                        let continuation = self.pendingCompletions.removeValue(forKey: slotIndex)
                        self.completionLock.unlock()
                        continuation?.resume()
                    }
                }
            }
        }
        thread.name = "CryptoPool-Monitor"
        thread.start()
        self.monitorThread = thread
    }
}

#else

import Foundation
import Crypto

/// Stub for non-Linux platforms. Process pools require fork() which is only available on Linux.
public final class CryptoProcessPool: @unchecked Sendable {
    public let workerCount: Int
    public let slotCount: Int

    public init(workerCount: Int = 1, slotCount: Int = 4) throws {
        fatalError("CryptoProcessPool is only available on Linux")
    }

    public func decrypt(encryptedPayload: Data, chunkCount: Int, totalPlaintextLen: Int, key: SymmetricKey, baseNonce: [UInt8]) async throws -> Data {
        fatalError("CryptoProcessPool is only available on Linux")
    }

    public func encrypt(plaintext: Data, chunkCount: Int, key: SymmetricKey, baseNonce: [UInt8]) async throws -> Data {
        fatalError("CryptoProcessPool is only available on Linux")
    }

    public func shutdown() {}
    public func checkWorkers() {}
}

#endif // os(Linux)
