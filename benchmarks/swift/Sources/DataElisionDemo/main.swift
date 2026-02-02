// data_elision_demo.swift
//
// Demonstrates that Data's internal _DataStorage class prevents the
// compiler from eliding heap allocation, even when the value never
// escapes scope. Uses a real C library call (BoringSSL AEAD seal)
// to simulate our actual crypto workload.
//
// Build: swift run -c release DataElisionDemo

import Foundation
import CBoringSSL

let N = 500_000
let SIZE = 512
let TAG = 16
let NONCE = 12
let KEY = 32
let CTX_SIZE = 584

// Setup: shared AEAD context (reused, like our AEADContext class)
var keyBytes = [UInt8]((0..<KEY).map { _ in UInt8.random(in: 0...255) })
var nonce = [UInt8]((0..<NONCE).map { _ in UInt8.random(in: 0...255) })

let ctx = UnsafeMutableRawPointer.allocate(byteCount: CTX_SIZE, alignment: 8)
CCryptoBoringSSL_EVP_AEAD_CTX_zero(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self))
let aead = CCryptoBoringSSL_EVP_aead_chacha20_poly1305()!
CCryptoBoringSSL_EVP_AEAD_CTX_init(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self),
    aead, &keyBytes, KEY, 0, nil)

// Source plaintext
let plainSrc = [UInt8]((0..<SIZE).map { UInt8(truncatingIfNeeded: $0) })
let plainData = Data(plainSrc)

// Accumulator to prevent elision
var checksum: UInt8 = 0

// --- Test 1: Seal with [UInt8] output (never escapes) ---
// Allocate output buffer, seal into it, read a byte, discard buffer.
func testArrayOutput() -> Double {
    for _ in 0..<1000 {
        var out = [UInt8](repeating: 0, count: SIZE + TAG)
        var outLen = 0
        var n = nonce
        var p = plainSrc
        CCryptoBoringSSL_EVP_AEAD_CTX_seal(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self),
            &out, &outLen, SIZE + TAG, &n, NONCE, &p, SIZE, nil, 0)
        checksum &+= out[0]
    }
    let start = DispatchTime.now()
    for _ in 0..<N {
        var out = [UInt8](repeating: 0, count: SIZE + TAG)
        var outLen = 0
        var n = nonce
        var p = plainSrc
        CCryptoBoringSSL_EVP_AEAD_CTX_seal(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self),
            &out, &outLen, SIZE + TAG, &n, NONCE, &p, SIZE, nil, 0)
        checksum &+= out[0]  // read result, then buffer dies
    }
    let end = DispatchTime.now()
    return Double(end.uptimeNanoseconds - start.uptimeNanoseconds) / Double(N)
}

// --- Test 2: Seal with [UInt8], then wrap in Data (never escapes) ---
// Same as test 1 but constructs Data from the result before reading.
func testDataOutput() -> Double {
    for _ in 0..<1000 {
        var out = [UInt8](repeating: 0, count: SIZE + TAG)
        var outLen = 0
        var n = nonce
        var p = plainSrc
        CCryptoBoringSSL_EVP_AEAD_CTX_seal(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self),
            &out, &outLen, SIZE + TAG, &n, NONCE, &p, SIZE, nil, 0)
        let ct = Data(out[0..<(outLen - TAG)])
        let tag = Data(out[(outLen - TAG)..<outLen])
        checksum &+= ct[0]
        checksum &+= tag[0]
    }
    let start = DispatchTime.now()
    for _ in 0..<N {
        var out = [UInt8](repeating: 0, count: SIZE + TAG)
        var outLen = 0
        var n = nonce
        var p = plainSrc
        CCryptoBoringSSL_EVP_AEAD_CTX_seal(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self),
            &out, &outLen, SIZE + TAG, &n, NONCE, &p, SIZE, nil, 0)
        let ct = Data(out[0..<(outLen - TAG)])
        let tag = Data(out[(outLen - TAG)..<outLen])
        checksum &+= ct[0]   // read from Data, then it dies
        checksum &+= tag[0]
    }
    let end = DispatchTime.now()
    return Double(end.uptimeNanoseconds - start.uptimeNanoseconds) / Double(N)
}

// --- Test 3: Seal with pre-allocated [UInt8] (reused across iterations) ---
// This is what our caller-provided buffer approach does.
func testPreallocOutput() -> Double {
    var out = [UInt8](repeating: 0, count: SIZE + TAG)
    var outLen = 0
    for _ in 0..<1000 {
        var n = nonce
        var p = plainSrc
        CCryptoBoringSSL_EVP_AEAD_CTX_seal(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self),
            &out, &outLen, SIZE + TAG, &n, NONCE, &p, SIZE, nil, 0)
        checksum &+= out[0]
    }
    let start = DispatchTime.now()
    for _ in 0..<N {
        var n = nonce
        var p = plainSrc
        CCryptoBoringSSL_EVP_AEAD_CTX_seal(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self),
            &out, &outLen, SIZE + TAG, &n, NONCE, &p, SIZE, nil, 0)
        checksum &+= out[0]
    }
    let end = DispatchTime.now()
    return Double(end.uptimeNanoseconds - start.uptimeNanoseconds) / Double(N)
}

// --- Test 4: Seal with Data input (simulates our actual wrapper) ---
// plaintext comes in as Data (via withUnsafeBytes), output to prealloc.
func testDataInputPreallocOutput() -> Double {
    var out = [UInt8](repeating: 0, count: SIZE + TAG)
    var outLen = 0
    for _ in 0..<1000 {
        var n = nonce
        plainData.withUnsafeBytes { ptr in
            CCryptoBoringSSL_EVP_AEAD_CTX_seal(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self),
                &out, &outLen, SIZE + TAG, &n, NONCE,
                ptr.baseAddress!.assumingMemoryBound(to: UInt8.self), SIZE, nil, 0)
        }
        checksum &+= out[0]
    }
    let start = DispatchTime.now()
    for _ in 0..<N {
        var n = nonce
        plainData.withUnsafeBytes { ptr in
            CCryptoBoringSSL_EVP_AEAD_CTX_seal(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self),
                &out, &outLen, SIZE + TAG, &n, NONCE,
                ptr.baseAddress!.assumingMemoryBound(to: UInt8.self), SIZE, nil, 0)
        }
        checksum &+= out[0]
    }
    let end = DispatchTime.now()
    return Double(end.uptimeNanoseconds - start.uptimeNanoseconds) / Double(N)
}

// ============================================================
// PART B: Pure Swift consumer (compiler can see everything)
// ============================================================

// Expensive pure-Swift consumer: multiple passes over 512 bytes
// to approximate the ~400-500 ns cost of a real ChaCha20 seal.
// Compiler has full visibility — can inline and analyze everything.
@inline(__always)
func expensiveReduce(_ buf: [UInt8]) -> UInt8 {
    var acc: UInt8 = 0
    // ~8 passes over 512 bytes ≈ 4096 byte-ops, similar cost to ChaCha20
    for _ in 0..<8 {
        for b in buf { acc = acc &+ b ^ (acc &>> 3) }
    }
    return acc
}

@inline(__always)
func expensiveReduceData(_ buf: Data) -> UInt8 {
    buf.withUnsafeBytes { ptr in
        let bytes = ptr.bindMemory(to: UInt8.self)
        var acc: UInt8 = 0
        for _ in 0..<8 {
            for i in 0..<bytes.count { acc = acc &+ bytes[i] ^ (acc &>> 3) }
        }
        return acc
    }
}

// --- Test 5: Pure Swift, [UInt8] created and consumed locally ---
func testSwiftArrayLocal() -> Double {
    for _ in 0..<1000 {
        let a = [UInt8](plainSrc[0..<SIZE])
        checksum &+= expensiveReduce(a)
    }
    let start = DispatchTime.now()
    for _ in 0..<N {
        let a = [UInt8](plainSrc[0..<SIZE])
        checksum &+= expensiveReduce(a)  // compiler sees full lifecycle
    }
    let end = DispatchTime.now()
    return Double(end.uptimeNanoseconds - start.uptimeNanoseconds) / Double(N)
}

// --- Test 6: Pure Swift, Data created and consumed locally ---
func testSwiftDataLocal() -> Double {
    for _ in 0..<1000 {
        let d = Data(plainSrc[0..<SIZE])
        checksum &+= expensiveReduceData(d)
    }
    let start = DispatchTime.now()
    for _ in 0..<N {
        let d = Data(plainSrc[0..<SIZE])
        checksum &+= expensiveReduceData(d)  // compiler sees full lifecycle
    }
    let end = DispatchTime.now()
    return Double(end.uptimeNanoseconds - start.uptimeNanoseconds) / Double(N)
}

// --- Test 7: Pure Swift, prealloc [UInt8] baseline ---
func testSwiftPrealloc() -> Double {
    var buf = [UInt8](plainSrc)
    for _ in 0..<1000 { checksum &+= expensiveReduce(buf) }
    let start = DispatchTime.now()
    for _ in 0..<N {
        // Simulate "fill" by writing first byte (memcpy would be more realistic
        // but we want to isolate the alloc cost, not the fill cost)
        buf[0] = plainSrc[0]
        checksum &+= expensiveReduce(buf)
    }
    let end = DispatchTime.now()
    return Double(end.uptimeNanoseconds - start.uptimeNanoseconds) / Double(N)
}

// --- Run ---
print("512-byte ChaCha20-Poly1305 seal: Data elision test (\(N) iterations)")
print("====================================================================")

let preallocNs = testPreallocOutput()
print("1. Prealloc [UInt8] (reused):          \(String(format: "%5.0f", preallocNs)) ns  <- best case")

let dataInNs = testDataInputPreallocOutput()
print("2. Data in, prealloc [UInt8] out:       \(String(format: "%5.0f", dataInNs)) ns  (+\(String(format: "%.0f", dataInNs - preallocNs)))")

let arrayNs = testArrayOutput()
print("3. New [UInt8] per call (not reused):   \(String(format: "%5.0f", arrayNs)) ns  (+\(String(format: "%.0f", arrayNs - preallocNs)))")

let dataNs = testDataOutput()
print("4. New [UInt8] + wrap in Data:          \(String(format: "%5.0f", dataNs)) ns  (+\(String(format: "%.0f", dataNs - preallocNs)))")

print()
print("[UInt8] alloc overhead (3 vs 1):         \(String(format: "%.0f", arrayNs - preallocNs)) ns")
print("Data wrapping overhead (4 vs 3):         \(String(format: "%.0f", dataNs - arrayNs)) ns")
print("Total Data overhead (4 vs 1):            \(String(format: "%.0f", dataNs - preallocNs)) ns")
print()

if dataNs > arrayNs + 20 {
    print("CONFIRMED: Data construction adds overhead the compiler")
    print("cannot elide, even though the Data never escapes scope.")
} else {
    print("UNEXPECTED: Data matched [UInt8] performance.")
}

print()
print("--- Part B: Pure Swift consumer (compiler sees everything) ---")

let swiftPreNs = testSwiftPrealloc()
print("5. Prealloc [UInt8] + expensiveReduce:       \(String(format: "%5.0f", swiftPreNs)) ns  <- best case")

let swiftArrayNs = testSwiftArrayLocal()
print("6. New [UInt8] + expensiveReduce:            \(String(format: "%5.0f", swiftArrayNs)) ns  (+\(String(format: "%.0f", swiftArrayNs - swiftPreNs)))")

let swiftDataNs = testSwiftDataLocal()
print("7. New Data + expensiveReduceData:           \(String(format: "%5.0f", swiftDataNs)) ns  (+\(String(format: "%.0f", swiftDataNs - swiftPreNs)))")

print()
print("[UInt8] alloc overhead (6 vs 5):         \(String(format: "%.0f", swiftArrayNs - swiftPreNs)) ns")
print("Data overhead (7 vs 6):                  \(String(format: "%.0f", swiftDataNs - swiftArrayNs)) ns")

print()
print("(checksum: \(checksum))")

CCryptoBoringSSL_EVP_AEAD_CTX_cleanup(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self))
ctx.deallocate()
