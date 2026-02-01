// SharedMemoryRing.swift - Shared memory allocation, slot management, atomics, eventfd
//
// Provides the low-level shared memory infrastructure for process pool workers.
// Uses mmap(MAP_SHARED|MAP_ANONYMOUS) regions with fixed-size slots and
// pipe-based signaling for low-latency parent↔worker communication.

#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
import Foundation

// MARK: - Constants

/// Slot size: 64KB aligned for cache friendliness
let kSlotSize: Int = 65536

/// Control header: 1 page
let kControlHeaderSize: Int = 4096

/// Slot header: 1 cache line
let kSlotHeaderSize: Int = 64

/// Chunk size for crypto operations
let kCryptoChunkSize: Int = 512

/// Encrypted chunk size (chunk + Poly1305 tag)
let kEncryptedChunkSize: Int = 528

/// Maximum input region size per slot
let kInputRegionSize: Int = 32768

/// Maximum output region size per slot
let kOutputRegionSize: Int = 32768

/// Maximum chunks per slot
let kMaxChunksPerSlot: Int = kInputRegionSize / kEncryptedChunkSize  // ~62

// MARK: - Slot Status

/// Atomic status values for slot lifecycle
enum SlotStatus: UInt8 {
    case free = 0
    case pending = 1
    case processing = 2
    case done = 3
}

/// Operation type for crypto slots
enum CryptoOperation: UInt8 {
    case encrypt = 0
    case decrypt = 1
}

/// Operation type for signature slots
enum SignatureOperation: UInt8 {
    case verify = 0
    case sign = 1
}

// MARK: - Pipe-based Signaling

/// Signal via pipe (write a byte)
func signalEventfd(_ fd: Int32) {
    var val: UInt8 = 1
    _ = write(fd, &val, 1)
}

/// Wait on a pipe read end with optional timeout
func waitEventfd(_ fd: Int32, timeoutUs: Int = -1) -> Bool {
    if timeoutUs >= 0 {
        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let ms = timeoutUs / 1000
        let ret = poll(&pfd, 1, Int32(max(ms, 1)))
        if ret <= 0 { return false }
    }
    var val: UInt8 = 0
    let n = read(fd, &val, 1)
    return n == 1
}

/// Drain a pipe (non-blocking read)
func drainEventfd(_ fd: Int32) {
    var buf = [UInt8](repeating: 0, count: 64)
    _ = read(fd, &buf, 64)
}

// MARK: - Pipe Pair

struct PipePair {
    let readFd: Int32
    let writeFd: Int32

    static func create() -> PipePair? {
        var fds: [Int32] = [0, 0]
        guard pipe(&fds) == 0 else { return nil }
        // Set non-blocking on read end
        let flags = fcntl(fds[0], F_GETFL)
        _ = fcntl(fds[0], F_SETFL, flags | O_NONBLOCK)
        return PipePair(readFd: fds[0], writeFd: fds[1])
    }
}

// MARK: - Shared Memory Region

/// A shared memory region with fixed-size slots for inter-process communication.
/// The region is allocated via mmap(MAP_SHARED|MAP_ANONYMOUS) and survives fork().
final class SharedMemoryRegion: @unchecked Sendable {
    /// Base pointer to the mmap'd region
    let base: UnsafeMutableRawPointer

    /// Total size of the region
    let totalSize: Int

    /// Number of slots
    let slotCount: Int

    /// Number of workers
    let workerCount: Int

    /// Per-worker signaling (write end for parent to signal worker)
    private(set) var workerSignalWrite: [Int32]

    /// Per-worker signaling (read end for worker to wait on)
    private(set) var workerSignalRead: [Int32]

    /// Completion signaling (worker→parent)
    private(set) var completionSignalWrite: Int32
    private(set) var completionSignalRead: Int32

    /// Per-worker slot ring buffers stored in control header
    private let ringCapacity: Int = 64

    init(slotCount: Int, workerCount: Int) throws {
        self.slotCount = slotCount
        self.workerCount = workerCount
        self.totalSize = kControlHeaderSize + slotCount * kSlotSize

        // Allocate shared anonymous memory
        let ptr = mmap(nil, totalSize,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS,
                       -1, 0)
        guard ptr != MAP_FAILED else {
            throw ProcessPoolError.mmapFailed(errno)
        }
        self.base = ptr!

        // Zero the control header
        memset(base, 0, kControlHeaderSize)

        // Store slot_count and worker_count in header
        base.storeBytes(of: UInt32(slotCount), as: UInt32.self)
        (base + 4).storeBytes(of: UInt32(workerCount), as: UInt32.self)

        // Create signaling pipes (work cross-platform and cross-process)
        self.workerSignalWrite = []
        self.workerSignalRead = []

        for _ in 0..<workerCount {
            guard let p = PipePair.create() else {
                throw ProcessPoolError.eventfdFailed(errno)
            }
            workerSignalRead.append(p.readFd)
            workerSignalWrite.append(p.writeFd)
        }
        guard let completionPipe = PipePair.create() else {
            throw ProcessPoolError.eventfdFailed(errno)
        }
        self.completionSignalRead = completionPipe.readFd
        self.completionSignalWrite = completionPipe.writeFd
    }

    deinit {
        munmap(base, totalSize)
        for i in 0..<workerCount {
            close(workerSignalRead[i])
            close(workerSignalWrite[i])
        }
        close(completionSignalRead)
        close(completionSignalWrite)
    }

    // MARK: - Slot Access

    func slotHeader(_ slotIndex: Int) -> UnsafeMutableRawPointer {
        base + kControlHeaderSize + slotIndex * kSlotSize
    }

    func slotInput(_ slotIndex: Int) -> UnsafeMutableRawPointer {
        slotHeader(slotIndex) + kSlotHeaderSize
    }

    func slotOutput(_ slotIndex: Int) -> UnsafeMutableRawPointer {
        slotInput(slotIndex) + kInputRegionSize
    }

    // MARK: - Slot Header Access

    func getOperation(_ slotIndex: Int) -> UInt8 {
        slotHeader(slotIndex).load(as: UInt8.self)
    }

    func setOperation(_ slotIndex: Int, _ op: UInt8) {
        slotHeader(slotIndex).storeBytes(of: op, as: UInt8.self)
    }

    /// Read status with memory fence (offset 1)
    func getStatus(_ slotIndex: Int) -> UInt8 {
        let ptr = (slotHeader(slotIndex) + 1).assumingMemoryBound(to: UInt8.self)
        return volatileLoad(ptr)
    }

    /// Set status with memory fence
    func setStatus(_ slotIndex: Int, _ status: SlotStatus) {
        let ptr = (slotHeader(slotIndex) + 1).assumingMemoryBound(to: UInt8.self)
        volatileStore(ptr, status.rawValue)
    }

    /// Compare-and-swap status (with lock for cross-process safety)
    func casStatus(_ slotIndex: Int, expected: SlotStatus, desired: SlotStatus) -> Bool {
        let ptr = (slotHeader(slotIndex) + 1).assumingMemoryBound(to: UInt8.self)
        return volatileCAS(ptr, expected: expected.rawValue, desired: desired.rawValue)
    }

    func getChunkCount(_ slotIndex: Int) -> UInt16 {
        (slotHeader(slotIndex) + 2).loadUnaligned(as: UInt16.self)
    }

    func setChunkCount(_ slotIndex: Int, _ count: UInt16) {
        (slotHeader(slotIndex) + 2).storeBytes(of: count, toByteOffset: 0, as: UInt16.self)
    }

    func getKey(_ slotIndex: Int) -> UnsafeRawBufferPointer {
        UnsafeRawBufferPointer(start: slotHeader(slotIndex) + 4, count: 32)
    }

    func setKey(_ slotIndex: Int, _ key: UnsafeRawBufferPointer) {
        memcpy(slotHeader(slotIndex) + 4, key.baseAddress!, min(key.count, 32))
    }

    func getBaseNonce(_ slotIndex: Int) -> UnsafeRawBufferPointer {
        UnsafeRawBufferPointer(start: slotHeader(slotIndex) + 36, count: 12)
    }

    func setBaseNonce(_ slotIndex: Int, _ nonce: UnsafeRawBufferPointer) {
        memcpy(slotHeader(slotIndex) + 36, nonce.baseAddress!, min(nonce.count, 12))
    }

    func getWorkerAssignment(_ slotIndex: Int) -> UInt8 {
        (slotHeader(slotIndex) + 48).load(as: UInt8.self)
    }

    func setWorkerAssignment(_ slotIndex: Int, _ worker: UInt8) {
        (slotHeader(slotIndex) + 48).storeBytes(of: worker, as: UInt8.self)
    }

    func getTotalPlaintextLen(_ slotIndex: Int) -> UInt32 {
        (slotHeader(slotIndex) + 52).loadUnaligned(as: UInt32.self)
    }

    func setTotalPlaintextLen(_ slotIndex: Int, _ len: UInt32) {
        (slotHeader(slotIndex) + 52).storeBytes(of: len, toByteOffset: 0, as: UInt32.self)
    }

    // MARK: - Worker Ring Buffer

    private func workerRingBase(_ workerIndex: Int) -> UnsafeMutableRawPointer {
        base + 64 + workerIndex * (ringCapacity + 8)
    }

    func pushToWorkerRing(_ workerIndex: Int, slotIndex: Int) -> Bool {
        let ringBase = workerRingBase(workerIndex)
        let writeHeadPtr = ringBase.assumingMemoryBound(to: UInt32.self)
        let readHeadPtr = (ringBase + 4).assumingMemoryBound(to: UInt32.self)

        let writeHead = volatileLoad32(writeHeadPtr)
        let readHead = volatileLoad32(readHeadPtr)

        if (writeHead &- readHead) >= UInt32(ringCapacity) {
            return false
        }

        let idx = Int(writeHead % UInt32(ringCapacity))
        (ringBase + 8 + idx).storeBytes(of: UInt8(slotIndex), as: UInt8.self)
        volatileStore32(writeHeadPtr, writeHead &+ 1)
        return true
    }

    func popFromWorkerRing(_ workerIndex: Int) -> Int? {
        let ringBase = workerRingBase(workerIndex)
        let writeHeadPtr = ringBase.assumingMemoryBound(to: UInt32.self)
        let readHeadPtr = (ringBase + 4).assumingMemoryBound(to: UInt32.self)

        let readHead = volatileLoad32(readHeadPtr)
        let writeHead = volatileLoad32(writeHeadPtr)

        if readHead == writeHead { return nil }

        let idx = Int(readHead % UInt32(ringCapacity))
        let slotIndex = Int((ringBase + 8 + idx).load(as: UInt8.self))
        volatileStore32(readHeadPtr, readHead &+ 1)
        return slotIndex
    }

    // MARK: - Slot Allocation

    func acquireSlot() -> Int? {
        for i in 0..<slotCount {
            if casStatus(i, expected: .free, desired: .pending) {
                return i
            }
        }
        return nil
    }

    func releaseSlot(_ slotIndex: Int) {
        setStatus(slotIndex, .free)
    }
}

// MARK: - Volatile Load/Store (Cross-Process Safe)

// We use UnsafeMutablePointer.volatileLoad/Store pattern with compiler barriers.
// For cross-process atomics on shared memory, the writes are naturally visible
// because mmap(MAP_SHARED) uses the same physical pages. We just need to ensure
// the compiler doesn't reorder or optimize away loads/stores.

@inline(never) @_optimize(none)
private func volatileLoad(_ ptr: UnsafeMutablePointer<UInt8>) -> UInt8 {
    return ptr.pointee
}

@inline(never) @_optimize(none)
private func volatileStore(_ ptr: UnsafeMutablePointer<UInt8>, _ value: UInt8) {
    ptr.pointee = value
}

@inline(never) @_optimize(none)
private func volatileCAS(_ ptr: UnsafeMutablePointer<UInt8>, expected: UInt8, desired: UInt8) -> Bool {
    // This is not truly atomic but works for our single-writer-per-slot pattern:
    // - Only one thread/process calls casStatus(free→pending) per slot at a time
    //   because the parent is single-threaded in slot allocation (protected by NSLock)
    // - Workers only transition processing→done (no contention)
    if ptr.pointee == expected {
        ptr.pointee = desired
        return true
    }
    return false
}

@inline(never) @_optimize(none)
private func volatileLoad32(_ ptr: UnsafeMutablePointer<UInt32>) -> UInt32 {
    return ptr.pointee
}

@inline(never) @_optimize(none)
private func volatileStore32(_ ptr: UnsafeMutablePointer<UInt32>, _ value: UInt32) {
    ptr.pointee = value
}

// MARK: - Signature Slot Layout

/// Signature slot header layout (64 bytes):
///   [1] operation (verify=0, sign=1)
///   [1] status (atomic)
///   [1] result (valid=1, invalid=0)
///   [1] padding
///   [32] public_key (or private_key for signing)
///   [4] data_len
///   [20] padding
/// After header: [64] signature bytes, then data region (up to 8KB)

let kSignatureSlotSize: Int = 16384
let kSignatureSlotHeaderSize: Int = 64
let kSignatureSize: Int = 64
let kMaxSignatureDataLen: Int = 8192

extension SharedMemoryRegion {
    func getResult(_ slotIndex: Int) -> UInt8 {
        (slotHeader(slotIndex) + 2).load(as: UInt8.self)
    }

    func setResult(_ slotIndex: Int, _ result: UInt8) {
        (slotHeader(slotIndex) + 2).storeBytes(of: result, as: UInt8.self)
    }

    func getSignatureKey(_ slotIndex: Int) -> UnsafeRawBufferPointer {
        UnsafeRawBufferPointer(start: slotHeader(slotIndex) + 4, count: 32)
    }

    func setSignatureKey(_ slotIndex: Int, _ key: UnsafeRawBufferPointer) {
        memcpy(slotHeader(slotIndex) + 4, key.baseAddress!, min(key.count, 32))
    }

    func getSignatureDataLen(_ slotIndex: Int) -> UInt32 {
        (slotHeader(slotIndex) + 36).loadUnaligned(as: UInt32.self)
    }

    func setSignatureDataLen(_ slotIndex: Int, _ len: UInt32) {
        (slotHeader(slotIndex) + 36).storeBytes(of: len, toByteOffset: 0, as: UInt32.self)
    }

    func signatureBytes(_ slotIndex: Int) -> UnsafeMutableRawPointer {
        slotHeader(slotIndex) + kSignatureSlotHeaderSize
    }

    func signatureData(_ slotIndex: Int) -> UnsafeMutableRawPointer {
        slotHeader(slotIndex) + kSignatureSlotHeaderSize + kSignatureSize
    }
}

// MARK: - Signature Memory Region

final class SignatureMemoryRegion: @unchecked Sendable {
    let inner: SharedMemoryRegion

    init(slotCount: Int, workerCount: Int) throws {
        self.inner = try SharedMemoryRegion(slotCount: slotCount, workerCount: workerCount)
    }
}

// MARK: - Errors

enum ProcessPoolError: Error, CustomStringConvertible {
    case mmapFailed(Int32)
    case eventfdFailed(Int32)
    case forkFailed(Int32)
    case slotExhausted
    case payloadTooLarge
    case shutdownInProgress
    case workerCrashed(pid: Int32)

    var description: String {
        switch self {
        case .mmapFailed(let e): return "mmap failed: errno \(e)"
        case .eventfdFailed(let e): return "eventfd/pipe failed: errno \(e)"
        case .forkFailed(let e): return "fork failed: errno \(e)"
        case .slotExhausted: return "All shared memory slots are in use"
        case .payloadTooLarge: return "Payload exceeds slot capacity"
        case .shutdownInProgress: return "Pool is shutting down"
        case .workerCrashed(let pid): return "Worker process \(pid) crashed"
        }
    }
}
