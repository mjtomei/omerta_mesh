# Swift `Data` Allocation Elision: Compiler Limitation Report

## Summary

The Swift compiler does not stack-promote `Data` values even when it can prove the value never escapes the local scope. In the same scenario, `[UInt8]` is stack-promoted with near-zero overhead. This is a fundamental limitation of `Data`'s class-backed `_DataStorage` design, not an optimizer gap — the compiler correctly refuses to elide a heap allocation it cannot prove is safe to move to the stack because `_DataStorage` is a reference-counted class.

This affects any Swift code that creates short-lived `Data` values on a hot path.

## Test Setup

All tests use 512-byte buffers with 500,000 iterations, run in `-O` (release) mode. Two consumer types are tested:

- **Part A**: Opaque C library consumer (BoringSSL ChaCha20-Poly1305 AEAD seal). The compiler cannot see into the C function, so it must assume the buffer could escape.
- **Part B**: Pure Swift consumer (`@inline(__always)` function doing 8 passes of byte-level arithmetic over the buffer). The compiler has full visibility into the consumer and can prove the buffer never escapes.

Source: `Sources/DataElisionDemo/main.swift`

## Results

### Part A: C library consumer (BoringSSL seal, ~400-500 ns compute)

| Test                                                     | Linux (ns) | Mac (ns) |
|----------------------------------------------------------|------------|----------|
| 1. Prealloc `[UInt8]` (reused across iterations)         |        404 |      512 |
| 2. `Data` input via `withUnsafeBytes`, prealloc output   |        395 |      442 |
| 3. New `[UInt8]` per call (never escapes)                |        447 |      517 |
| 4. New `[UInt8]` + wrap result in `Data` (never escapes) |        624 |      738 |

| Metric                              | Linux  |   Mac  |
|--------------------------------------|--------|--------|
| `[UInt8]` alloc overhead (3 vs 1)   | 43 ns  |  5 ns  |
| `Data` wrapping overhead (4 vs 3)   | 177 ns | 221 ns |
| Total `Data` overhead (4 vs 1)      | 220 ns | 227 ns |

### Part B: Pure Swift consumer (~2-3.5 µs compute, compiler sees everything)

With `withUnsafeBytes` for Data iteration (isolating allocation cost only):

| Test                                                     | Linux (ns) | Mac (ns) |
|----------------------------------------------------------|------------|----------|
| 5. Prealloc `[UInt8]` + expensiveReduce                  |      2,102 |    3,584 |
| 6. New `[UInt8]` + expensiveReduce (never escapes)       |      2,150 |    3,629 |
| 7. New `Data` + expensiveReduceData (never escapes)      |      2,178 |    3,757 |

| Metric                                |  Linux |   Mac  |
|---------------------------------------|--------|--------|
| `[UInt8]` alloc overhead (6 vs 5)     |  48 ns |  46 ns |
| `Data` overhead vs `[UInt8]` (7 vs 6) |  28 ns | 128 ns |

### Data iteration overhead (without `withUnsafeBytes`)

When iterating over `Data` byte-by-byte using its `Sequence` conformance instead of `withUnsafeBytes`:

| Test                                             | Linux (ns) | Mac (ns) |
|--------------------------------------------------|------------|----------|
| 6. New `[UInt8]` + expensiveReduce               |      2,150 |    3,629 |
| 7. New `Data` + expensiveReduce (byte-by-byte)   |     10,915 |   13,423 |
| **Slowdown factor**                              |   **5.1x** | **3.7x** |

This is a separate issue from allocation: `Data`'s `Sequence`/subscript implementation is 4-5x slower than direct `[UInt8]` indexing.

## Two Distinct Problems

### 1. Allocation overhead: 28-232 ns per `Data` construction

`Data` internally allocates a `_DataStorage` class instance on every construction. Because `_DataStorage` is a class (reference type), the Swift compiler cannot stack-promote it — stack promotion only works for value types. The compiler would need to prove that the reference count never needs atomic operations, which requires deeper analysis than current escape analysis provides.

`[UInt8]` is a value type (struct wrapping a `_ContiguousArrayStorage` buffer). The compiler can and does stack-promote these when it proves the value doesn't escape. Tests 3 and 6 show this: new `[UInt8]` costs only 5-48 ns more than reusing a pre-allocated buffer.

### 2. Iteration overhead: 4-5x slower byte access

`Data`'s `Sequence` conformance and subscript go through multiple layers of indirection (`_DataStorage` → `_SliceBuffer` → pointer). `[UInt8]` subscript compiles to a direct pointer offset. Using `withUnsafeBytes` eliminates this overhead for `Data`, but requires the caller to know about the problem and use the uglier API.

## Why the compiler can't fix this

**For allocation**: `Data` uses `_DataStorage`, an internal class. ARC requires the compiler to emit retain/release calls for class instances, which in turn require heap allocation (the reference count lives in the object header). Even if escape analysis proves the value is local, the compiler would need to:

1. Prove no concurrent access (to skip atomic refcounting)
2. Inline the `_DataStorage` allocation onto the stack
3. Rewrite all retain/release to no-ops

Step 1 is theoretically possible but not implemented for class instances in the Swift optimizer. Steps 2-3 would require the compiler to special-case `Data`'s internals or implement general class stack-promotion, which is a significant optimizer change.

**For iteration**: This is a stdlib design issue. `Data` could use `@inlinable` more aggressively on its subscript and iterator, or use `withContiguousStorageIfAvailable` in its `Sequence` conformance. Some of this has improved in recent Swift versions but remains slower than `[UInt8]`.

## Potential fixes

### In Swift stdlib/Foundation (upstream or fork)

1. **Small-buffer optimization for `Data`**: Like `SmallString`, `Data` could store bytes inline in the struct for sizes below a threshold (e.g., 22 bytes or 64 bytes). This avoids `_DataStorage` allocation entirely for small values. Limited benefit for 512-byte buffers.

2. **Class stack-promotion in the optimizer**: Teach the Swift compiler to stack-promote class instances when escape analysis proves they're local. This is the general fix that would benefit all class-backed value types, not just `Data`. This is a significant compiler change but has been discussed in the Swift community.

3. **Replace `_DataStorage` with a value-type backing**: Redesign `Data` to use `ManagedBuffer` or a similar value-type wrapper instead of a plain class. This would allow the existing value-type stack-promotion to work. Breaking internal ABI change.

### In application code (workarounds)

4. **Use `[UInt8]` on hot paths**: Convert to/from `Data` only at API boundaries. This is the manual workaround for the missing optimization.

5. **Use `withUnsafeBytes` consistently**: Avoids the iteration overhead but not the allocation overhead.

6. **Wait for Swift 6.2**: `InlineArray<Count, UInt8>` provides fixed-size stack-allocated arrays. `Span` provides non-owning views. Neither fixes `Data` itself but provides alternatives for hot paths.

## Reproduction

```bash
cd benchmarks/swift
swift run -c release DataElisionDemo
```

Requires the `CBoringSSL` vendored target for Part A tests. Part B tests are pure Swift.

## Environment

- Swift 5.9+ (tested with 5.10 on Linux, 5.9.2 on macOS)
- Linux: Ubuntu on x86_64
- macOS: Apple Silicon (arm64)
