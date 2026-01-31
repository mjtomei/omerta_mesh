import Foundation
import CBoringSSL
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

let TAG_LEN = 16  // Poly1305 tag
let NONCE_LEN = 12
let KEY_LEN = 32
let CTX_SIZE = 584  // sizeof(EVP_AEAD_CTX) — padded to 8-byte alignment

// MARK: - Helpers

func pad(_ s: String, _ w: Int) -> String { s.count >= w ? s : s + String(repeating: " ", count: w - s.count) }
func rpad(_ s: String, _ w: Int) -> String { s.count >= w ? s : String(repeating: " ", count: w - s.count) + s }

// MARK: - Worker result

struct WorkerResult {
    var encryptNs: Double
    var decryptNs: Double
}

// MARK: - Worker: Direct BoringSSL API

func workerDirectAPI(blockSize: Int, chunkSize: Int, iterations: Int) -> WorkerResult {
    let numChunks = (blockSize + chunkSize - 1) / chunkSize
    let ciphertextChunkSize = chunkSize + TAG_LEN

    // Allocate key
    var keyBytes = [UInt8](repeating: 0, count: KEY_LEN)
    for i in 0..<KEY_LEN { keyBytes[i] = UInt8.random(in: 0...255) }

    // Init AEAD context
    let ctx = UnsafeMutableRawPointer.allocate(byteCount: CTX_SIZE, alignment: 8)
    CCryptoBoringSSL_EVP_AEAD_CTX_zero(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self))
    let aead = CCryptoBoringSSL_EVP_aead_chacha20_poly1305()!
    guard CCryptoBoringSSL_EVP_AEAD_CTX_init(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self), aead, &keyBytes, KEY_LEN, 0, nil) == 1 else {
        fatalError("EVP_AEAD_CTX_init failed")
    }

    // Pre-allocate all buffers
    let plainBuf = UnsafeMutablePointer<UInt8>.allocate(capacity: blockSize)
    for i in 0..<blockSize { plainBuf[i] = UInt8(truncatingIfNeeded: i) }

    let cipherBuf = UnsafeMutablePointer<UInt8>.allocate(capacity: numChunks * ciphertextChunkSize)
    let decBuf = UnsafeMutablePointer<UInt8>.allocate(capacity: blockSize)

    // Nonces
    var nonces = [[UInt8]](repeating: [UInt8](repeating: 0, count: NONCE_LEN), count: numChunks)
    let baseNonce: [UInt8] = (0..<12).map { _ in UInt8.random(in: 0...255) }
    for i in 0..<numChunks {
        nonces[i] = baseNonce
        nonces[i][11] ^= 0x02
        nonces[i][10] ^= UInt8(i & 0xFF)
    }

    var outLen = 0

    // Warmup
    for _ in 0..<10 {
        for i in 0..<numChunks {
            let off = i * chunkSize
            let thisChunkSize = min(chunkSize, blockSize - off)
            let cOff = i * ciphertextChunkSize
            CCryptoBoringSSL_EVP_AEAD_CTX_seal(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self),
                cipherBuf + cOff, &outLen, thisChunkSize + TAG_LEN,
                &nonces[i], NONCE_LEN,
                plainBuf + off, thisChunkSize,
                nil, 0)
        }
        for i in 0..<numChunks {
            let off = i * chunkSize
            let thisChunkSize = min(chunkSize, blockSize - off)
            let cOff = i * ciphertextChunkSize
            CCryptoBoringSSL_EVP_AEAD_CTX_open(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self),
                decBuf + off, &outLen, thisChunkSize,
                &nonces[i], NONCE_LEN,
                cipherBuf + cOff, thisChunkSize + TAG_LEN,
                nil, 0)
        }
    }

    // Timed encrypt
    let encStart = DispatchTime.now()
    for _ in 0..<iterations {
        for i in 0..<numChunks {
            let off = i * chunkSize
            let thisChunkSize = min(chunkSize, blockSize - off)
            let cOff = i * ciphertextChunkSize
            CCryptoBoringSSL_EVP_AEAD_CTX_seal(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self),
                cipherBuf + cOff, &outLen, thisChunkSize + TAG_LEN,
                &nonces[i], NONCE_LEN,
                plainBuf + off, thisChunkSize,
                nil, 0)
        }
    }
    let encEnd = DispatchTime.now()

    // Timed decrypt
    let decStart = DispatchTime.now()
    for _ in 0..<iterations {
        for i in 0..<numChunks {
            let off = i * chunkSize
            let thisChunkSize = min(chunkSize, blockSize - off)
            let cOff = i * ciphertextChunkSize
            CCryptoBoringSSL_EVP_AEAD_CTX_open(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self),
                decBuf + off, &outLen, thisChunkSize,
                &nonces[i], NONCE_LEN,
                cipherBuf + cOff, thisChunkSize + TAG_LEN,
                nil, 0)
        }
    }
    let decEnd = DispatchTime.now()

    CCryptoBoringSSL_EVP_AEAD_CTX_cleanup(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self))
    ctx.deallocate()
    plainBuf.deallocate(); cipherBuf.deallocate(); decBuf.deallocate()

    return WorkerResult(
        encryptNs: Double(encEnd.uptimeNanoseconds - encStart.uptimeNanoseconds),
        decryptNs: Double(decEnd.uptimeNanoseconds - decStart.uptimeNanoseconds))
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

    let r = workerDirectAPI(blockSize: bs, chunkSize: cs, iterations: iters)
    print("\(Int(r.encryptNs)) \(Int(r.decryptNs))")
    exit(0)
}

// MARK: - Process runner

func runProcesses(workers: Int, blockSize: Int, chunkSize: Int, iterations: Int) -> (encTimes: [Double], decTimes: [Double]) {
    let exe = CommandLine.arguments[0]
    struct ChildInfo { var pid: pid_t; var readFd: Int32 }
    var children: [ChildInfo] = []

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

    var encTimes: [Double] = []
    var decTimes: [Double] = []
    for child in children {
        var s: Int32 = 0
        waitpid(child.pid, &s, 0)
        var buf = [UInt8](repeating: 0, count: 256)
        let n = read(child.readFd, &buf, 255)
        close(child.readFd)
        if n > 0 {
            let str = String(bytes: buf[0..<n], encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let parts = str.split(separator: " ")
            if parts.count == 2, let e = Double(parts[0]), let d = Double(parts[1]) {
                encTimes.append(e)
                decTimes.append(d)
            }
        }
    }
    return (encTimes, decTimes)
}

// MARK: - Main

let blockSize = 131072
let chunkSizes = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
let workerCounts = [1, 2, 4, 8]
let iterations = 2000
let cpuCount = ProcessInfo.processInfo.activeProcessorCount

print("═══ Direct BoringSSL API Benchmark (Multiprocessing) ═══")
print("Block: \(blockSize) bytes/worker, \(iterations) iters, CPUs: \(cpuCount)")
print()

// Peak baseline (single worker, whole block = 1 chunk)
print("--- Peak baseline (whole block, no chunking) ---")
let peakDirect = workerDirectAPI(blockSize: blockSize, chunkSize: blockSize, iterations: iterations)
let peakEncMBs = Double(blockSize) / (peakDirect.encryptNs / Double(iterations)) * 1000
let peakDecMBs = Double(blockSize) / (peakDirect.decryptNs / Double(iterations)) * 1000
print("  Direct API: Enc \(String(format: "%.0f", peakEncMBs)) MB/s  Dec \(String(format: "%.0f", peakDecMBs)) MB/s")
print()

// Single-worker by chunk size
print("--- Single-worker: Direct API by chunk size ---")
do {
    var hdr = "\(pad("Chunk", 7))"
    hdr += "  \(rpad("Enc MB/s", 10))  \(rpad("Dec MB/s", 10))  \(rpad("Enc %pk", 8))  \(rpad("Dec %pk", 8))"
    print(hdr)
    print(String(repeating: "-", count: hdr.count))

    for cs in chunkSizes {
        let dr = workerDirectAPI(blockSize: blockSize, chunkSize: cs, iterations: iterations)
        let drEncMBs = Double(blockSize) / (dr.encryptNs / Double(iterations)) * 1000
        let drDecMBs = Double(blockSize) / (dr.decryptNs / Double(iterations)) * 1000
        let encPct = drEncMBs / peakEncMBs * 100
        let decPct = drDecMBs / peakDecMBs * 100

        var line = "\(pad(String(cs), 7))"
        line += "  \(rpad(String(format: "%.0f", drEncMBs), 10))  \(rpad(String(format: "%.0f", drDecMBs), 10))"
        line += "  \(rpad(String(format: "%.0f%%", encPct), 8))  \(rpad(String(format: "%.0f%%", decPct), 8))"
        print(line)
    }
}
print()

// Multiprocessing: Encrypt
print("--- Multiprocessing: Encrypt %peak ---")
do {
    var hdr = "\(pad("Chunk", 7))"
    for w in workerCounts { hdr += "  \(rpad("\(w)w", 7))" }
    print(hdr)
    print(String(repeating: "-", count: hdr.count))

    for cs in chunkSizes {
        var line = "\(pad(String(cs), 7))"
        for w in workerCounts {
            let dr = runProcesses(workers: w, blockSize: blockSize, chunkSize: cs, iterations: iterations)
            let bytesPerWorker = Double(blockSize * iterations)
            var drAgg = 0.0
            for i in 0..<dr.encTimes.count { drAgg += bytesPerWorker / dr.encTimes[i] * 1000 }
            let drPct = drAgg / (peakEncMBs * Double(w)) * 100
            line += "  \(rpad(String(format: "%.0f%%", drPct), 7))"
        }
        print(line)
    }
}
print()

// Multiprocessing: Decrypt
print("--- Multiprocessing: Decrypt %peak ---")
do {
    var hdr = "\(pad("Chunk", 7))"
    for w in workerCounts { hdr += "  \(rpad("\(w)w", 7))" }
    print(hdr)
    print(String(repeating: "-", count: hdr.count))

    for cs in chunkSizes {
        var line = "\(pad(String(cs), 7))"
        for w in workerCounts {
            let dr = runProcesses(workers: w, blockSize: blockSize, chunkSize: cs, iterations: iterations)
            let bytesPerWorker = Double(blockSize * iterations)
            var drAgg = 0.0
            for i in 0..<dr.decTimes.count { drAgg += bytesPerWorker / dr.decTimes[i] * 1000 }
            let drPct = drAgg / (peakDecMBs * Double(w)) * 100
            line += "  \(rpad(String(format: "%.0f%%", drPct), 7))"
        }
        print(line)
    }
}

print()
print("%peak = aggregate / (peak * workers), 100% = every worker at unchunked speed")
