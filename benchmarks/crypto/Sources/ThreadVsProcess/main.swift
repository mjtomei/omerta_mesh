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

// MARK: - Helpers

func pad(_ s: String, _ w: Int) -> String { s.count >= w ? s : s + String(repeating: " ", count: w - s.count) }
func rpad(_ s: String, _ w: Int) -> String { s.count >= w ? s : String(repeating: " ", count: w - s.count) + s }

// MARK: - Worker logic

struct WorkerResult {
    var encryptNs: Double
    var decryptNs: Double
}

func workerRun(blockSize: Int, chunkSize: Int, iterations: Int) -> WorkerResult {
    let key = SymmetricKey(size: .bits256)
    let numChunks = (blockSize + chunkSize - 1) / chunkSize

    let plainBuf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: blockSize)
    _ = plainBuf.initialize(from: (0..<blockSize).lazy.map { UInt8(truncatingIfNeeded: $0) })

    let baseNonce: [UInt8] = (0..<12).map { _ in UInt8.random(in: 0...255) }

    // Pre-allocate SealedBox array
    var boxes: [ChaChaPoly.SealedBox] = []
    boxes.reserveCapacity(numChunks)
    for i in 0..<numChunks {
        let off = i * chunkSize
        let end = min(off + chunkSize, blockSize)
        var n = baseNonce; n[11] ^= 0x02; n[10] ^= UInt8(i & 0xFF)
        let nonce = try! ChaChaPoly.Nonce(data: n)
        let chunk = Data(bytesNoCopy: plainBuf.baseAddress! + off, count: end - off, deallocator: .none)
        boxes.append(try! ChaChaPoly.seal(chunk, using: key, nonce: nonce))
    }

    let outBuf = UnsafeMutablePointer<UInt8>.allocate(capacity: blockSize)

    // Warmup
    for _ in 0..<10 {
        for i in 0..<numChunks {
            let off = i * chunkSize
            let end = min(off + chunkSize, blockSize)
            var n = baseNonce; n[11] ^= 0x02; n[10] ^= UInt8(i & 0xFF)
            let chunk = Data(bytesNoCopy: plainBuf.baseAddress! + off, count: end - off, deallocator: .none)
            boxes[i] = try! ChaChaPoly.seal(chunk, using: key, nonce: try! ChaChaPoly.Nonce(data: n))
        }
        for i in 0..<numChunks {
            let plain = try! ChaChaPoly.open(boxes[i], using: key)
            plain.withUnsafeBytes { src in
                outBuf.advanced(by: i * chunkSize).initialize(from: src.bindMemory(to: UInt8.self).baseAddress!, count: src.count)
            }
        }
    }

    // Timed encrypt
    let encStart = DispatchTime.now()
    for _ in 0..<iterations {
        for i in 0..<numChunks {
            let off = i * chunkSize
            let end = min(off + chunkSize, blockSize)
            var n = baseNonce; n[11] ^= 0x02; n[10] ^= UInt8(i & 0xFF)
            let nonce = try! ChaChaPoly.Nonce(data: n)
            let chunk = Data(bytesNoCopy: plainBuf.baseAddress! + off, count: end - off, deallocator: .none)
            boxes[i] = try! ChaChaPoly.seal(chunk, using: key, nonce: nonce)
        }
    }
    let encEnd = DispatchTime.now()

    // Timed decrypt
    let decStart = DispatchTime.now()
    for _ in 0..<iterations {
        for i in 0..<numChunks {
            let plain = try! ChaChaPoly.open(boxes[i], using: key)
            let off = i * chunkSize
            plain.withUnsafeBytes { src in
                outBuf.advanced(by: off).initialize(from: src.bindMemory(to: UInt8.self).baseAddress!, count: src.count)
            }
        }
    }
    let decEnd = DispatchTime.now()

    plainBuf.deallocate()
    outBuf.deallocate()

    return WorkerResult(
        encryptNs: Double(encEnd.uptimeNanoseconds - encStart.uptimeNanoseconds),
        decryptNs: Double(decEnd.uptimeNanoseconds - decStart.uptimeNanoseconds)
    )
}

// MARK: - Child worker mode

if CommandLine.arguments.contains("--child-worker") {
    func argVal(_ name: String) -> Int {
        guard let idx = CommandLine.arguments.firstIndex(of: name), idx + 1 < CommandLine.arguments.count,
              let v = Int(CommandLine.arguments[idx + 1]) else { fatalError("Missing \(name)") }
        return v
    }
    let bs = argVal("--block-size")
    let cs = argVal("--chunk-size")
    let iters = argVal("--iterations")
    let r = workerRun(blockSize: bs, chunkSize: cs, iterations: iters)
    // Print both times for parent to read
    print("\(Int(r.encryptNs)) \(Int(r.decryptNs))")
    exit(0)
}

// MARK: - Process runner

func runProcesses(workers: Int, blockSize: Int, chunkSize: Int, iterations: Int) -> (wallNs: Double, childEncNs: [Double], childDecNs: [Double]) {
    let exe = CommandLine.arguments[0]

    // Create pipes to read child output
    struct ChildInfo { var pid: pid_t; var readFd: Int32 }
    var children: [ChildInfo] = []

    let wallStart = DispatchTime.now()
    for _ in 0..<workers {
        var pipeFds: [Int32] = [0, 0]
        pipe(&pipeFds)

        #if canImport(Darwin)
        var fileActions: posix_spawn_file_actions_t?
        #else
        var fileActions = posix_spawn_file_actions_t()
        #endif
        posix_spawn_file_actions_init(&fileActions)
        posix_spawn_file_actions_adddup2(&fileActions, pipeFds[1], STDOUT_FILENO)
        posix_spawn_file_actions_addclose(&fileActions, pipeFds[0])

        var pid: pid_t = 0
        let args = [exe, "--child-worker", "--block-size", String(blockSize), "--chunk-size", String(chunkSize), "--iterations", String(iterations)]
        var cArgs = args.map { strdup($0) }; cArgs.append(nil)
        #if canImport(Darwin)
        posix_spawn(&pid, exe, &fileActions, nil, &cArgs, environ)
        #else
        posix_spawn(&pid, exe, &fileActions, nil, &cArgs, __environ)
        #endif
        for p in cArgs { free(p) }
        posix_spawn_file_actions_destroy(&fileActions)
        close(pipeFds[1])
        children.append(ChildInfo(pid: pid, readFd: pipeFds[0]))
    }

    var childEncNs: [Double] = []
    var childDecNs: [Double] = []
    for child in children {
        var s: Int32 = 0
        waitpid(child.pid, &s, 0)
        // Read output
        var buf = [UInt8](repeating: 0, count: 256)
        let n = read(child.readFd, &buf, 255)
        close(child.readFd)
        if n > 0 {
            let str = String(bytes: buf[0..<n], encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let parts = str.split(separator: " ")
            if parts.count == 2, let e = Double(parts[0]), let d = Double(parts[1]) {
                childEncNs.append(e)
                childDecNs.append(d)
            }
        }
    }
    let wallEnd = DispatchTime.now()
    return (Double(wallEnd.uptimeNanoseconds - wallStart.uptimeNanoseconds), childEncNs, childDecNs)
}

// MARK: - Main

let blockSize = 131072  // 128KB per worker
let chunkSizes = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
let workerCounts = [1, 2, 4, 8]
let iterations = 2000
let cpuCount = ProcessInfo.processInfo.activeProcessorCount

print("═══ Encrypt & Decrypt Throughput (Multiprocessing) ═══")
print("Block: \(blockSize) bytes/worker, \(iterations) iters, CPUs: \(cpuCount)")
print()

// Peak baseline: encrypt/decrypt whole block as single chunk (no chunking overhead)
print("--- Peak baseline (whole block, no chunking) ---")
let peakResult = workerRun(blockSize: blockSize, chunkSize: blockSize, iterations: iterations)
let peakEncNs = peakResult.encryptNs / Double(iterations)
let peakDecNs = peakResult.decryptNs / Double(iterations)
let peakEncMBs = Double(blockSize) / peakEncNs * 1000.0
let peakDecMBs = Double(blockSize) / peakDecNs * 1000.0
print("  Encrypt: \(String(format: "%.0f", peakEncMBs)) MB/s (\(Int(peakEncNs)) ns/iter)")
print("  Decrypt: \(String(format: "%.0f", peakDecMBs)) MB/s (\(Int(peakDecNs)) ns/iter)")
print()

// Baseline: single-threaded at each chunk size
print("--- Baseline (single worker, by chunk size) ---")
var baseEnc: [Int: Double] = [:]
var baseDec: [Int: Double] = [:]
do {
    var hdr = "\(pad("Chunk", 7))  \(rpad("Enc MB/s", 10))  \(rpad("Enc %peak", 10))  \(rpad("Dec MB/s", 10))  \(rpad("Dec %peak", 10))"
    print(hdr)
    print(String(repeating: "-", count: hdr.count))
    for cs in chunkSizes {
        let r = workerRun(blockSize: blockSize, chunkSize: cs, iterations: iterations)
        let encPerIter = r.encryptNs / Double(iterations)
        let decPerIter = r.decryptNs / Double(iterations)
        baseEnc[cs] = encPerIter
        baseDec[cs] = decPerIter
        let encMBs = Double(blockSize) / encPerIter * 1000.0
        let decMBs = Double(blockSize) / decPerIter * 1000.0
        let encPct = encMBs / peakEncMBs * 100
        let decPct = decMBs / peakDecMBs * 100
        var line = "\(pad(String(cs), 7))  \(rpad(String(format: "%.0f", encMBs), 10))  \(rpad(String(format: "%.0f%%", encPct), 10))  \(rpad(String(format: "%.0f", decMBs), 10))  \(rpad(String(format: "%.0f%%", decPct), 10))"
        print(line)
    }
}
print()

// Collect all results: run processes once per (chunk, workers) combo
struct ThroughputResult {
    var encMBs: Double
    var decMBs: Double
}

var results: [String: ThroughputResult] = [:]

for cs in chunkSizes {
    for w in workerCounts {
        let (_, childEncNs, childDecNs) = runProcesses(workers: w, blockSize: blockSize, chunkSize: cs, iterations: iterations)
        let bytesPerWorker = Double(blockSize * iterations)
        var aggEnc = 0.0, aggDec = 0.0
        for i in 0..<childEncNs.count {
            aggEnc += bytesPerWorker / childEncNs[i] * 1000.0
            aggDec += bytesPerWorker / childDecNs[i] * 1000.0
        }
        results["\(cs)-\(w)"] = ThroughputResult(encMBs: aggEnc, decMBs: aggDec)
    }
}

// Encrypt throughput table — normalized to peak
print("--- Encrypt: Aggregate throughput (MB/s, % of peak) ---")
print("Peak single-worker = \(String(format: "%.0f", peakEncMBs)) MB/s")
do {
    var hdr = "\(pad("Chunk", 7))"
    for w in workerCounts { hdr += "  \(rpad("\(w)w MB/s", 10))  \(rpad("%peak", 6))" }
    print(hdr)
    print(String(repeating: "-", count: hdr.count))
    for cs in chunkSizes {
        var line = "\(pad(String(cs), 7))"
        for w in workerCounts {
            let r = results["\(cs)-\(w)"]!
            let pct = r.encMBs / (peakEncMBs * Double(w)) * 100
            line += "  \(rpad(String(format: "%.0f", r.encMBs), 10))  \(rpad(String(format: "%.0f%%", pct), 6))"
        }
        print(line)
    }
}
print()

// Decrypt throughput table — normalized to peak
print("--- Decrypt: Aggregate throughput (MB/s, % of peak) ---")
print("Peak single-worker = \(String(format: "%.0f", peakDecMBs)) MB/s")
do {
    var hdr = "\(pad("Chunk", 7))"
    for w in workerCounts { hdr += "  \(rpad("\(w)w MB/s", 10))  \(rpad("%peak", 6))" }
    print(hdr)
    print(String(repeating: "-", count: hdr.count))
    for cs in chunkSizes {
        var line = "\(pad(String(cs), 7))"
        for w in workerCounts {
            let r = results["\(cs)-\(w)"]!
            let pct = r.decMBs / (peakDecMBs * Double(w)) * 100
            line += "  \(rpad(String(format: "%.0f", r.decMBs), 10))  \(rpad(String(format: "%.0f%%", pct), 6))"
        }
        print(line)
    }
}

print()
print("%peak = aggregate / (peak_single_worker * workers)")
print("       100% = every worker running at unchunked single-core speed")
