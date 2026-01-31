# Benchmarks

Standalone SPM packages for measuring cryptographic and Swift runtime performance. Each package lives in its own directory with its own `Package.swift` and can be built independently.

Both packages depend on a vendored copy of BoringSSL (symlinked from `Sources/CBoringSSL`).

## Crypto Benchmarks (`crypto/`)

ChaCha20-Poly1305 encryption/decryption benchmarks. See [crypto/REPORT.md](crypto/REPORT.md) for full results.

### CryptoBenchmark

Compares serial vs parallel chunked decryption using swift-crypto's `ChaChaPoly` API. Tests thread pool sizes from 1–8 across payload sizes from 4 KB to 1 MB to determine whether parallelism helps at the message layer.

```bash
cd benchmarks/crypto
swift run -c release CryptoBenchmark
```

### DirectAPI

Same chunked encrypt/decrypt workload but using the BoringSSL C API directly (`EVP_AEAD_CTX`), bypassing swift-crypto's `Data` wrappers. Measures the raw performance ceiling.

```bash
cd benchmarks/crypto
swift run -c release DirectAPI
```

### ThreadVsProcess

Compares multi-threaded vs multi-process parallelism for chunked decryption using swift-crypto. Spawns child processes via `posix_spawn` to test whether per-process isolation changes throughput.

```bash
cd benchmarks/crypto
swift run -c release ThreadVsProcess
```

## Swift Benchmarks (`swift/`)

Swift runtime and compiler behavior benchmarks. See [swift/DATA_ELISION_REPORT.md](swift/DATA_ELISION_REPORT.md) for full results.

### DataElisionDemo

Demonstrates that the Swift compiler cannot stack-promote `Data` values due to the class-backed `_DataStorage` implementation, while `[UInt8]` is stack-promoted with near-zero overhead. Runs 500k iterations of BoringSSL AEAD seal with both types and compares allocation counts and wall time.

```bash
cd benchmarks/swift
swift run -c release DataElisionDemo
```
