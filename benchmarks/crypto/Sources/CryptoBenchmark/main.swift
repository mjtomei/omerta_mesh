import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
import Atomics

// MARK: - Helpers

func pad(_ s: String, _ w: Int) -> String { s.count >= w ? s : s + String(repeating: " ", count: w - s.count) }
func rpad(_ s: String, _ w: Int) -> String { s.count >= w ? s : String(repeating: " ", count: w - s.count) + s }
func fmtNs(_ v: Double) -> String { rpad(String(Int(v)), 10) }
func fmtX(_ v: Double) -> String { rpad("\(Double(Int(v * 100)) / 100.0)x", 8) }

func makeKey() -> SymmetricKey { SymmetricKey(size: .bits256) }
func chunkNonce(base: [UInt8], index: Int) -> ChaChaPoly.Nonce {
    var n = base; n[11] ^= 0x02; n[10] ^= UInt8(index & 0xFF)
    return try! ChaChaPoly.Nonce(data: n)
}

struct ChunkedCiphertext { let boxes: [ChaChaPoly.SealedBox] }

func encryptChunkedSerial(payload: Data, key: SymmetricKey, chunkSize: Int) -> ChunkedCiphertext {
    let base: [UInt8] = (0..<12).map { _ in UInt8.random(in: 0...255) }
    var boxes: [ChaChaPoly.SealedBox] = []; var off = 0; var i = 0
    while off < payload.count {
        let end = min(off + chunkSize, payload.count)
        boxes.append(try! ChaChaPoly.seal(payload[off..<end], using: key, nonce: chunkNonce(base: base, index: i)))
        off = end; i += 1
    }
    return ChunkedCiphertext(boxes: boxes)
}

func measure(iterations: Int, block: () -> Void) -> Double {
    for _ in 0..<10 { block() }
    let start = DispatchTime.now()
    for _ in 0..<iterations { block() }
    let end = DispatchTime.now()
    return Double(end.uptimeNanoseconds - start.uptimeNanoseconds) / Double(iterations)
}

let payloadSize = 131072
let chunkSizes = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
let workerCounts = [1, 2, 4, 8]
let iterations = 5000
let cpuCount = ProcessInfo.processInfo.activeProcessorCount

let payload = Data((0..<payloadSize).map { _ in UInt8.random(in: 0...255) })
let key = makeKey()

// ==========================================
// TEST A: Per-chunk overhead analysis
// ==========================================
print("═══ TEST A: Per-chunk cost breakdown (single-threaded) ═══")
print("Measuring cost of ChaChaPoly.open per chunk at different sizes")
print()

do {
    print("\(pad("Chunk", 7))  \(rpad("Chunks", 6))  \(rpad("Total (ns)", 12))  \(rpad("Per-chunk", 12))  \(rpad("Per-byte", 10))  \(rpad("Overhead", 10))")
    print(String(repeating: "-", count: 80))

    // Measure whole first
    let wholeBox = try! ChaChaPoly.seal(payload, using: key)
    let wholeNs = measure(iterations: iterations) { _ = try! ChaChaPoly.open(wholeBox, using: key) }
    let wholePerByte = wholeNs / Double(payloadSize)
    print("\(pad("whole", 7))  \(rpad("1", 6))  \(rpad(String(Int(wholeNs)), 12))  \(rpad(String(Int(wholeNs)), 12))  \(rpad(String(format: "%.2f", wholePerByte), 10))  \(rpad("-", 10))")

    for cs in chunkSizes {
        let ct = encryptChunkedSerial(payload: payload, key: key, chunkSize: cs)
        let n = ct.boxes.count

        // Measure total serial decrypt time
        let totalNs = measure(iterations: iterations) {
            for box in ct.boxes { _ = try! ChaChaPoly.open(box, using: key) }
        }
        let perChunk = totalNs / Double(n)
        let perByte = totalNs / Double(payloadSize)

        // Overhead = extra cost vs whole, per chunk (fixed cost of each open() call)
        let overhead = perChunk - (Double(cs) * wholePerByte)

        print("\(pad(String(cs), 7))  \(rpad(String(n), 6))  \(rpad(String(Int(totalNs)), 12))  \(rpad(String(Int(perChunk)), 12))  \(rpad(String(format: "%.2f", perByte), 10))  \(rpad(String(Int(overhead)) + " ns", 10))")
    }
}

// ==========================================
// TEST B: SpinPool with varying chunk sizes
// ==========================================
print()
print("═══ TEST B: SpinPool decrypt ═══")
print()

final class SpinPool {
    let workerCount: Int
    private var threads: [pthread_t?]
    private let generation = ManagedAtomic<Int>(0)
    private let workIndex = ManagedAtomic<Int>(0)
    private let doneCount = ManagedAtomic<Int>(0)
    private let shutdownFlag = ManagedAtomic<Bool>(false)

    private struct Job {
        var boxes: UnsafeBufferPointer<ChaChaPoly.SealedBox> = .init(start: nil, count: 0)
        var key: SymmetricKey = SymmetricKey(size: .bits256)
        var totalChunks: Int = 0
        var chunkPlaintextSize: Int = 0
        var outputBuffer: UnsafeMutableRawPointer? = nil
    }
    private let job: UnsafeMutablePointer<Job>
    private let outputBuf: UnsafeMutablePointer<UInt8>

    init(workerCount: Int, maxPayloadSize: Int) {
        self.workerCount = workerCount
        self.outputBuf = .allocate(capacity: maxPayloadSize)
        self.threads = Array(repeating: nil, count: workerCount)
        self.job = .allocate(capacity: 1)
        self.job.initialize(to: Job())
        for i in 0..<workerCount {
            let ctx = Unmanaged.passUnretained(self).toOpaque()
            #if canImport(Darwin)
            var tid: pthread_t?
            pthread_create(&tid, nil, { arg in
                Unmanaged<SpinPool>.fromOpaque(arg).takeUnretainedValue().workerLoop()
                return nil
            }, ctx)
            threads[i] = tid
            #else
            var tid = pthread_t()
            pthread_create(&tid, nil, { arg in
                Unmanaged<SpinPool>.fromOpaque(arg!).takeUnretainedValue().workerLoop()
                return nil
            }, ctx)
            threads[i] = tid
            #endif
        }
        usleep(10000)
    }

    private func workerLoop() {
        var lastGen = 0
        while true {
            while true {
                if shutdownFlag.load(ordering: .acquiring) { return }
                let g = generation.load(ordering: .acquiring)
                if g != lastGen { lastGen = g; break }
                sched_yield()
            }
            let j = job.pointee
            let total = j.totalChunks
            let chunkSize = j.chunkPlaintextSize
            let outBase = j.outputBuffer!
            while true {
                let idx = workIndex.wrappingIncrementThenLoad(ordering: .acquiringAndReleasing) - 1
                if idx >= total { break }
                let plain = try! ChaChaPoly.open(j.boxes[idx], using: j.key)
                let destOffset = idx * chunkSize
                plain.withUnsafeBytes { src in
                    outBase.advanced(by: destOffset).copyMemory(from: src.baseAddress!, byteCount: src.count)
                }
            }
            _ = doneCount.wrappingIncrementThenLoad(ordering: .releasing)
        }
    }

    func decryptInPlace(boxes: UnsafeBufferPointer<ChaChaPoly.SealedBox>, key: SymmetricKey, chunkPlaintextSize: Int, totalPayloadSize: Int) {
        job.pointee.boxes = boxes
        job.pointee.key = key
        job.pointee.totalChunks = boxes.count
        job.pointee.chunkPlaintextSize = chunkPlaintextSize
        job.pointee.outputBuffer = UnsafeMutableRawPointer(outputBuf)
        workIndex.store(0, ordering: .releasing)
        doneCount.store(0, ordering: .releasing)
        _ = generation.wrappingIncrementThenLoad(ordering: .sequentiallyConsistent)
        while doneCount.load(ordering: .acquiring) < workerCount { sched_yield() }
    }

    func stop() {
        shutdownFlag.store(true, ordering: .sequentiallyConsistent)
        for tid in threads { if let tid = tid { pthread_join(tid, nil) } }
    }
    deinit { outputBuf.deallocate(); job.deinitialize(count: 1); job.deallocate() }
}

let wholeBox2 = try! ChaChaPoly.seal(payload, using: key)
let wholeDecNs = measure(iterations: iterations) { _ = try! ChaChaPoly.open(wholeBox2, using: key) }
print("Whole decrypt: \(Int(wholeDecNs)) ns, CPUs: \(cpuCount)")
print()

var hdr = "\(pad("Chunk", 7))  \(rpad("Chunks", 6))  \(rpad("Serial", 10))  \(rpad("Ideal8w", 10))"
for w in workerCounts { hdr += "  \(rpad("Spin\(w)w", 10))" }
hdr += "  |  \(rpad("Effic2", 8))  \(rpad("Effic4", 8))  \(rpad("Effic8", 8))"
print(hdr)
print(String(repeating: "-", count: hdr.count))

var spinPools: [Int: SpinPool] = [:]
for w in workerCounts { spinPools[w] = SpinPool(workerCount: w, maxPayloadSize: payloadSize) }

for cs in chunkSizes {
    let ct = encryptChunkedSerial(payload: payload, key: key, chunkSize: cs)
    let n = ct.boxes.count
    let serialNs = measure(iterations: iterations) {
        for box in ct.boxes { _ = try! ChaChaPoly.open(box, using: key) }
    }

    // Ideal = serial / workerCount (perfect scaling)
    let ideal8 = serialNs / 8.0

    var spinResults: [Double] = []
    for w in workerCounts {
        let ns: Double = ct.boxes.withUnsafeBufferPointer { buf in
            measure(iterations: iterations) {
                spinPools[w]!.decryptInPlace(boxes: buf, key: key, chunkPlaintextSize: cs, totalPayloadSize: payloadSize)
            }
        }
        spinResults.append(ns)
    }

    // Efficiency = ideal / actual (1.0 = perfect scaling)
    var line = "\(pad(String(cs), 7))  \(rpad(String(n), 6))  \(fmtNs(serialNs))  \(fmtNs(ideal8))"
    for ns in spinResults { line += "  \(fmtNs(ns))" }
    line += "  |"
    for (i, w) in workerCounts.enumerated() {
        let ideal = serialNs / Double(w)
        let efficiency = ideal / spinResults[i]
        line += "  \(rpad(String(format: "%.0f%%", efficiency * 100), 8))"
    }
    print(line)
}

for (_, sp) in spinPools { sp.stop() }

print()
print("Ideal8w  = serial / 8 (theoretical perfect scaling)")
print("Effic    = (serial / workers) / actual (100% = perfect scaling)")
print("          Low efficiency at small chunks = per-call overhead dominates")
