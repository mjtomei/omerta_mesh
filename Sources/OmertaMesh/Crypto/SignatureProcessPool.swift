// SignatureProcessPool.swift - Ed25519 signature verification/signing worker process pool
//
// Separate pool from crypto because:
// - Signature verification is per-packet (not chunked)
// - Different performance characteristics than symmetric crypto
// - Can run fully in parallel with chunk decryption
// - Fewer workers needed (signatures are less frequent)

#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
import Foundation
import Crypto

/// Process pool for Ed25519 signature verification and signing.
public final class SignatureProcessPool: @unchecked Sendable {
    private let region: SharedMemoryRegion
    private var workerPids: [pid_t]
    public let workerCount: Int
    public let slotCount: Int

    private var nextWorker: Int = 0
    private let lock = NSLock()

    private var pendingCompletions: [Int: CheckedContinuation<Void, Never>] = [:]
    private let completionLock = NSLock()

    private var isRunning = true
    private var monitorThread: Thread?

    /// Create and start a signature process pool.
    ///
    /// - Parameters:
    ///   - workerCount: Number of worker processes (default: 2)
    ///   - slotCount: Number of shared memory slots (default: 16)
    public init(workerCount: Int = 2, slotCount: Int = 16) throws {
        self.workerCount = max(workerCount, 1)
        self.slotCount = max(slotCount, 4)
        self.workerPids = []

        self.region = try SharedMemoryRegion(slotCount: self.slotCount, workerCount: self.workerCount)

        for i in 0..<self.workerCount {
            let pid = fork()
            if pid == 0 {
                signatureWorkerLoop(workerId: i, region: region)
            } else if pid > 0 {
                workerPids.append(pid)
            } else {
                for existingPid in workerPids {
                    kill(existingPid, SIGKILL)
                    var status: Int32 = 0
                    waitpid(existingPid, &status, 0)
                }
                throw ProcessPoolError.forkFailed(errno)
            }
        }

        startCompletionMonitor()
    }

    deinit {
        shutdown()
    }

    /// Shutdown all workers.
    public func shutdown() {
        lock.lock()
        guard isRunning else {
            lock.unlock()
            return
        }
        isRunning = false
        lock.unlock()

        for pid in workerPids {
            kill(pid, SIGTERM)
        }
        for pid in workerPids {
            var status: Int32 = 0
            let result = waitpid(pid, &status, WNOHANG)
            if result == 0 {
                usleep(100_000)
                kill(pid, SIGKILL)
                waitpid(pid, &status, 0)
            }
        }
        workerPids.removeAll()

        completionLock.lock()
        let pending = pendingCompletions
        pendingCompletions.removeAll()
        completionLock.unlock()
        for (_, continuation) in pending {
            continuation.resume()
        }
    }

    // MARK: - Verify

    /// Verify an Ed25519 signature off-process.
    ///
    /// - Parameters:
    ///   - data: The data that was signed
    ///   - signature: The 64-byte Ed25519 signature
    ///   - publicKey: The 32-byte Ed25519 public key
    /// - Returns: true if signature is valid
    public func verify(data: Data, signature: Data, publicKey: Data) async throws -> Bool {
        guard isRunning else { throw ProcessPoolError.shutdownInProgress }
        guard data.count <= kMaxSignatureDataLen else { throw ProcessPoolError.payloadTooLarge }
        guard signature.count == kSignatureSize else { return false }
        guard publicKey.count == 32 else { return false }

        let slotIndex = try acquireSlotWithBackpressure()

        // Fill slot
        region.setOperation(slotIndex, SignatureOperation.verify.rawValue)
        region.setResult(slotIndex, 0)

        // Copy public key
        publicKey.withUnsafeBytes { buf in
            region.setSignatureKey(slotIndex, UnsafeRawBufferPointer(buf))
        }

        // Copy signature
        let sigPtr = region.signatureBytes(slotIndex)
        signature.withUnsafeBytes { buf in
            memcpy(sigPtr, buf.baseAddress!, kSignatureSize)
        }

        // Copy data
        region.setSignatureDataLen(slotIndex, UInt32(data.count))
        let dataPtr = region.signatureData(slotIndex)
        data.withUnsafeBytes { buf in
            memcpy(dataPtr, buf.baseAddress!, buf.count)
        }

        // Assign and signal
        let worker = assignWorker()
        region.setWorkerAssignment(slotIndex, UInt8(worker))

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            completionLock.lock()
            pendingCompletions[slotIndex] = continuation
            completionLock.unlock()

            _ = region.pushToWorkerRing(worker, slotIndex: slotIndex)
            signalEventfd(region.workerSignalWrite[worker])
        }

        let result = region.getResult(slotIndex) == 1
        region.releaseSlot(slotIndex)
        return result
    }

    // MARK: - Sign

    /// Sign data off-process using Ed25519.
    ///
    /// - Parameters:
    ///   - data: The data to sign
    ///   - privateKey: The 32-byte Ed25519 private key
    /// - Returns: The 64-byte signature
    public func sign(data: Data, privateKey: Data) async throws -> Data {
        guard isRunning else { throw ProcessPoolError.shutdownInProgress }
        guard data.count <= kMaxSignatureDataLen else { throw ProcessPoolError.payloadTooLarge }
        guard privateKey.count == 32 else { throw ProcessPoolError.payloadTooLarge }

        let slotIndex = try acquireSlotWithBackpressure()

        region.setOperation(slotIndex, SignatureOperation.sign.rawValue)
        region.setResult(slotIndex, 0)

        privateKey.withUnsafeBytes { buf in
            region.setSignatureKey(slotIndex, UnsafeRawBufferPointer(buf))
        }

        region.setSignatureDataLen(slotIndex, UInt32(data.count))
        let dataPtr = region.signatureData(slotIndex)
        data.withUnsafeBytes { buf in
            memcpy(dataPtr, buf.baseAddress!, buf.count)
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

        let sigPtr = region.signatureBytes(slotIndex)
        let result = Data(bytes: sigPtr, count: kSignatureSize)
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
                let pid = fork()
                if pid == 0 {
                    signatureWorkerLoop(workerId: i, region: region)
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
        for _ in 0..<1000 {
            if let slot = region.acquireSlot() {
                return slot
            }
            usleep(10)
        }
        throw ProcessPoolError.slotExhausted
    }

    private func startCompletionMonitor() {
        let thread = Thread {
            while self.isRunning {
                let gotSignal = waitEventfd(self.region.completionSignalRead, timeoutUs: 50_000)
                if gotSignal {
                    drainEventfd(self.region.completionSignalRead)
                }

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
        thread.name = "SigPool-Monitor"
        thread.start()
        self.monitorThread = thread
    }
}
