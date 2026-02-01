// DirectCrypto.swift - Direct BoringSSL AEAD API for ChaCha20-Poly1305
//
// On macOS: imports vendored CBoringSSL C target directly.
// On Linux: uses @_silgen_name to call CCryptoBoringSSL symbols already
// linked by swift-crypto (which uses BoringSSL on Linux, CryptoKit on Mac).
//
// All public API uses [UInt8] — no Data allocations on the hot path.

import Foundation
#if canImport(CBoringSSL)
import CBoringSSL
#endif

// MARK: - Errors

public enum DirectCryptoError: Error {
    case sealFailed
    case openFailed
    case invalidKeySize
    case invalidNonceSize
    case initFailed
}

// MARK: - Constants

public enum DirectCrypto {
    public static let tagLen = 16
    public static let nonceLen = 12
    public static let keyLen = 32
    /// sizeof(EVP_AEAD_CTX), padded to 8-byte alignment
    static let ctxSize = 584
}

// MARK: - @_silgen_name declarations (Linux only)

#if !canImport(CBoringSSL)
@_silgen_name("CCryptoBoringSSL_EVP_aead_chacha20_poly1305")
private func _evp_aead_chacha20_poly1305() -> OpaquePointer

@_silgen_name("CCryptoBoringSSL_EVP_AEAD_CTX_zero")
private func _evp_aead_ctx_zero(_ ctx: UnsafeMutableRawPointer)

@_silgen_name("CCryptoBoringSSL_EVP_AEAD_CTX_init")
private func _evp_aead_ctx_init(
    _ ctx: UnsafeMutableRawPointer,
    _ aead: OpaquePointer,
    _ key: UnsafePointer<UInt8>,
    _ keyLen: Int,
    _ tagLen: Int,
    _ engine: OpaquePointer?
) -> Int32

@_silgen_name("CCryptoBoringSSL_EVP_AEAD_CTX_cleanup")
private func _evp_aead_ctx_cleanup(_ ctx: UnsafeMutableRawPointer)

@_silgen_name("CCryptoBoringSSL_EVP_AEAD_CTX_seal")
private func _evp_aead_ctx_seal(
    _ ctx: UnsafeRawPointer,
    _ out: UnsafeMutablePointer<UInt8>,
    _ outLen: UnsafeMutablePointer<Int>,
    _ maxOut: Int,
    _ nonce: UnsafePointer<UInt8>,
    _ nonceLen: Int,
    _ input: UnsafePointer<UInt8>,
    _ inputLen: Int,
    _ ad: UnsafePointer<UInt8>?,
    _ adLen: Int
) -> Int32

@_silgen_name("CCryptoBoringSSL_EVP_AEAD_CTX_open")
private func _evp_aead_ctx_open(
    _ ctx: UnsafeRawPointer,
    _ out: UnsafeMutablePointer<UInt8>,
    _ outLen: UnsafeMutablePointer<Int>,
    _ maxOut: Int,
    _ nonce: UnsafePointer<UInt8>,
    _ nonceLen: Int,
    _ input: UnsafePointer<UInt8>,
    _ inputLen: Int,
    _ ad: UnsafePointer<UInt8>?,
    _ adLen: Int
) -> Int32
#endif

// MARK: - Platform-abstracted C calls

private enum BoringSSL {
    static func aeadChaCha20Poly1305() -> OpaquePointer {
        #if canImport(CBoringSSL)
        return CCryptoBoringSSL_EVP_aead_chacha20_poly1305()!
        #else
        return _evp_aead_chacha20_poly1305()
        #endif
    }

    static func ctxZero(_ ctx: UnsafeMutableRawPointer) {
        #if canImport(CBoringSSL)
        CCryptoBoringSSL_EVP_AEAD_CTX_zero(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self))
        #else
        _evp_aead_ctx_zero(ctx)
        #endif
    }

    static func ctxInit(_ ctx: UnsafeMutableRawPointer, _ aead: OpaquePointer,
                         _ key: UnsafePointer<UInt8>, _ keyLen: Int,
                         _ tagLen: Int, _ engine: OpaquePointer?) -> Int32 {
        #if canImport(CBoringSSL)
        return CCryptoBoringSSL_EVP_AEAD_CTX_init(
            ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self),
            aead, key, keyLen, tagLen, engine)
        #else
        return _evp_aead_ctx_init(ctx, aead, key, keyLen, tagLen, engine)
        #endif
    }

    static func ctxCleanup(_ ctx: UnsafeMutableRawPointer) {
        #if canImport(CBoringSSL)
        CCryptoBoringSSL_EVP_AEAD_CTX_cleanup(ctx.assumingMemoryBound(to: EVP_AEAD_CTX.self))
        #else
        _evp_aead_ctx_cleanup(ctx)
        #endif
    }

    static func ctxSeal(_ ctx: UnsafeRawPointer,
                          _ out: UnsafeMutablePointer<UInt8>, _ outLen: UnsafeMutablePointer<Int>,
                          _ maxOut: Int, _ nonce: UnsafePointer<UInt8>, _ nonceLen: Int,
                          _ input: UnsafePointer<UInt8>, _ inputLen: Int,
                          _ ad: UnsafePointer<UInt8>?, _ adLen: Int) -> Int32 {
        #if canImport(CBoringSSL)
        return CCryptoBoringSSL_EVP_AEAD_CTX_seal(
            UnsafeMutableRawPointer(mutating: ctx).assumingMemoryBound(to: EVP_AEAD_CTX.self),
            out, outLen, maxOut, nonce, nonceLen, input, inputLen, ad, adLen)
        #else
        return _evp_aead_ctx_seal(ctx, out, outLen, maxOut, nonce, nonceLen, input, inputLen, ad, adLen)
        #endif
    }

    static func ctxOpen(_ ctx: UnsafeRawPointer,
                          _ out: UnsafeMutablePointer<UInt8>, _ outLen: UnsafeMutablePointer<Int>,
                          _ maxOut: Int, _ nonce: UnsafePointer<UInt8>, _ nonceLen: Int,
                          _ input: UnsafePointer<UInt8>, _ inputLen: Int,
                          _ ad: UnsafePointer<UInt8>?, _ adLen: Int) -> Int32 {
        #if canImport(CBoringSSL)
        return CCryptoBoringSSL_EVP_AEAD_CTX_open(
            UnsafeMutableRawPointer(mutating: ctx).assumingMemoryBound(to: EVP_AEAD_CTX.self),
            out, outLen, maxOut, nonce, nonceLen, input, inputLen, ad, adLen)
        #else
        return _evp_aead_ctx_open(ctx, out, outLen, maxOut, nonce, nonceLen, input, inputLen, ad, adLen)
        #endif
    }
}

// MARK: - AEADContext (reusable, key-bound context)

/// Holds an initialized EVP_AEAD_CTX for a single key. Reuse across multiple
/// seal/open calls to avoid repeated key schedule computation (~455 ns per init).
///
/// Thread safety: BoringSSL's EVP_AEAD_CTX_seal/open are safe to call concurrently
/// on a const (initialized, read-only) context. The context is immutable after init.
public final class AEADContext: @unchecked Sendable {
    private let ctx: UnsafeMutableRawPointer

    /// Initialize with a 32-byte ChaCha20-Poly1305 key.
    public init(key: [UInt8]) throws {
        guard key.count == DirectCrypto.keyLen else {
            throw DirectCryptoError.invalidKeySize
        }

        ctx = UnsafeMutableRawPointer.allocate(byteCount: DirectCrypto.ctxSize, alignment: 8)
        BoringSSL.ctxZero(ctx)

        let aead = BoringSSL.aeadChaCha20Poly1305()
        let rc = key.withUnsafeBufferPointer { keyPtr -> Int32 in
            BoringSSL.ctxInit(ctx, aead, keyPtr.baseAddress!, DirectCrypto.keyLen, 0, nil)
        }
        guard rc == 1 else {
            ctx.deallocate()
            throw DirectCryptoError.initFailed
        }
    }

    deinit {
        BoringSSL.ctxCleanup(ctx)
        ctx.deallocate()
    }

    /// Seal plaintext with an explicit 12-byte nonce. Returns (ciphertext, 16-byte tag).
    public func seal(plaintext: [UInt8], nonce: [UInt8]) throws -> (ciphertext: [UInt8], tag: [UInt8]) {
        guard nonce.count == DirectCrypto.nonceLen else {
            throw DirectCryptoError.invalidNonceSize
        }

        let outCapacity = plaintext.count + DirectCrypto.tagLen
        var outBuf = [UInt8](repeating: 0, count: outCapacity)
        var outLen = 0

        let rc: Int32 = plaintext.withUnsafeBufferPointer { plainPtr in
            let pBase = plainPtr.baseAddress ?? UnsafePointer<UInt8>(bitPattern: 1)!
            return BoringSSL.ctxSeal(ctx, &outBuf, &outLen, outCapacity,
                                     nonce, DirectCrypto.nonceLen,
                                     pBase, plaintext.count,
                                     nil, 0)
        }

        guard rc == 1 else { throw DirectCryptoError.sealFailed }

        let ciphertextLen = outLen - DirectCrypto.tagLen
        let ciphertext = Array(outBuf[0..<ciphertextLen])
        let tag = Array(outBuf[ciphertextLen..<outLen])
        return (ciphertext, tag)
    }

    /// Open ciphertext with an explicit 12-byte nonce and 16-byte tag. Returns plaintext.
    public func open(ciphertext: [UInt8], tag: [UInt8], nonce: [UInt8]) throws -> [UInt8] {
        guard nonce.count == DirectCrypto.nonceLen else {
            throw DirectCryptoError.invalidNonceSize
        }

        // BoringSSL expects ciphertext+tag concatenated as input
        var input = ciphertext + tag

        var outBuf = [UInt8](repeating: 0, count: ciphertext.count)
        var outLen = 0

        let rc = BoringSSL.ctxOpen(ctx, &outBuf, &outLen, ciphertext.count,
                                    nonce, DirectCrypto.nonceLen,
                                    &input, input.count,
                                    nil, 0)

        guard rc == 1 else { throw DirectCryptoError.openFailed }

        return Array(outBuf[0..<outLen])
    }

    /// Seal in combined format: [12-byte nonce][ciphertext][16-byte tag].
    /// Generates a random nonce.
    public func sealCombined(_ data: [UInt8]) throws -> [UInt8] {
        let nonce = DirectCrypto.randomNonce()
        let (ciphertext, tag) = try seal(plaintext: data, nonce: nonce)
        var combined = [UInt8]()
        combined.reserveCapacity(DirectCrypto.nonceLen + ciphertext.count + DirectCrypto.tagLen)
        combined.append(contentsOf: nonce)
        combined.append(contentsOf: ciphertext)
        combined.append(contentsOf: tag)
        return combined
    }

    /// Open combined format: [12-byte nonce][ciphertext][16-byte tag].
    public func openCombined(_ combined: [UInt8]) throws -> [UInt8] {
        let minSize = DirectCrypto.nonceLen + DirectCrypto.tagLen
        guard combined.count >= minSize else {
            throw DirectCryptoError.openFailed
        }

        let nonce = Array(combined[0..<DirectCrypto.nonceLen])
        let ciphertext = Array(combined[DirectCrypto.nonceLen..<(combined.count - DirectCrypto.tagLen)])
        let tag = Array(combined[(combined.count - DirectCrypto.tagLen)..<combined.count])

        return try open(ciphertext: ciphertext, tag: tag, nonce: nonce)
    }
}

// MARK: - Static convenience (one-shot, creates ephemeral context)

extension DirectCrypto {
    /// One-shot seal with explicit nonce. Creates ephemeral context.
    public static func seal(plaintext: [UInt8], key: [UInt8], nonce: [UInt8]) throws -> (ciphertext: [UInt8], tag: [UInt8]) {
        let ctx = try AEADContext(key: key)
        return try ctx.seal(plaintext: plaintext, nonce: nonce)
    }

    /// One-shot open with explicit nonce and tag. Creates ephemeral context.
    public static func open(ciphertext: [UInt8], tag: [UInt8], key: [UInt8], nonce: [UInt8]) throws -> [UInt8] {
        let ctx = try AEADContext(key: key)
        return try ctx.open(ciphertext: ciphertext, tag: tag, nonce: nonce)
    }

    /// One-shot seal in combined format [nonce][ciphertext][tag] with random nonce.
    public static func sealCombined(_ data: [UInt8], key: [UInt8]) throws -> [UInt8] {
        let ctx = try AEADContext(key: key)
        return try ctx.sealCombined(data)
    }

    /// One-shot open combined format [nonce][ciphertext][tag].
    public static func openCombined(_ combined: [UInt8], key: [UInt8]) throws -> [UInt8] {
        let ctx = try AEADContext(key: key)
        return try ctx.openCombined(combined)
    }

    /// Generate 12 random bytes suitable for use as a nonce.
    public static func randomNonce() -> [UInt8] {
        (0..<nonceLen).map { _ in UInt8.random(in: 0...255) }
    }
}
