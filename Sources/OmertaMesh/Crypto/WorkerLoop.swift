// WorkerLoop.swift - Worker main loops for crypto and signature process pools
//
// Workers are forked from the parent process and inherit mmap'd shared memory.
// They run a simple C-style event loop: wait for eventfd → process slots → signal completion.
// No Swift concurrency runtime is used in workers (no actors, no Tasks).

#if os(Linux)

import Glibc
import Foundation
import Crypto

// MARK: - Crypto Worker Loop

/// Main loop for a crypto worker process.
/// This function never returns — the worker processes slots until killed.
///
/// - Parameters:
///   - workerId: This worker's index (0..<workerCount)
///   - region: The shared memory region (inherited via fork)
///   - spinIterations: Number of spin iterations before blocking on eventfd
func cryptoWorkerLoop(workerId: Int, region: SharedMemoryRegion, spinIterations: Int = 100) -> Never {
    let readFd = region.workerSignalRead[workerId]
    let completionFd = region.completionSignalWrite

    while true {
        // Try spinning first for low latency
        var found = false
        for _ in 0..<spinIterations {
            if let slotIndex = region.popFromWorkerRing(workerId) {
                processCryptoSlot(slotIndex, region: region)
                signalEventfd(completionFd)
                found = true
                break
            }
        }
        if found { continue }

        // Block on eventfd
        _ = waitEventfd(readFd, timeoutUs: 100_000)  // 100ms timeout to check for new work
        drainEventfd(readFd)

        // Process all available slots
        while let slotIndex = region.popFromWorkerRing(workerId) {
            processCryptoSlot(slotIndex, region: region)
            signalEventfd(completionFd)
        }
    }
}

/// Process a single crypto slot
private func processCryptoSlot(_ slotIndex: Int, region: SharedMemoryRegion) {
    // Mark as processing
    region.setStatus(slotIndex, .processing)

    let operation = region.getOperation(slotIndex)
    let chunkCount = Int(region.getChunkCount(slotIndex))
    let totalPlaintextLen = Int(region.getTotalPlaintextLen(slotIndex))

    // Read key
    let keyBuf = region.getKey(slotIndex)
    let keyData = Data(bytes: keyBuf.baseAddress!, count: 32)
    let symmetricKey = SymmetricKey(data: keyData)

    // Read base nonce
    let nonceBuf = region.getBaseNonce(slotIndex)
    var baseNonce = [UInt8](repeating: 0, count: 12)
    memcpy(&baseNonce, nonceBuf.baseAddress!, 12)

    let inputPtr = region.slotInput(slotIndex)
    let outputPtr = region.slotOutput(slotIndex)

    if operation == CryptoOperation.decrypt.rawValue {
        decryptChunks(
            inputPtr: inputPtr,
            outputPtr: outputPtr,
            baseNonce: baseNonce,
            key: symmetricKey,
            chunkCount: chunkCount,
            totalPlaintextLen: totalPlaintextLen
        )
    } else {
        encryptChunks(
            inputPtr: inputPtr,
            outputPtr: outputPtr,
            baseNonce: baseNonce,
            key: symmetricKey,
            chunkCount: chunkCount,
            totalPlaintextLen: totalPlaintextLen
        )
    }

    // Mark done
    region.setStatus(slotIndex, .done)
}

/// Decrypt chunks from input region to output region
private func decryptChunks(
    inputPtr: UnsafeMutableRawPointer,
    outputPtr: UnsafeMutableRawPointer,
    baseNonce: [UInt8],
    key: SymmetricKey,
    chunkCount: Int,
    totalPlaintextLen: Int
) {
    var inputOffset = 0
    var outputOffset = 0

    for i in 0..<chunkCount {
        // Derive chunk plaintext size
        let chunkLen: Int
        if totalPlaintextLen == 0 {
            chunkLen = 0
        } else if i < chunkCount - 1 {
            chunkLen = kCryptoChunkSize
        } else {
            let remainder = totalPlaintextLen % kCryptoChunkSize
            chunkLen = remainder == 0 ? kCryptoChunkSize : remainder
        }

        // Derive nonce
        var nonce = baseNonce
        nonce[11] ^= 0x02
        nonce[9] ^= UInt8(truncatingIfNeeded: i >> 8)
        nonce[10] ^= UInt8(truncatingIfNeeded: i)

        // Read ciphertext + tag from input
        let ciphertext = Data(bytes: inputPtr + inputOffset, count: chunkLen)
        let tag = Data(bytes: inputPtr + inputOffset + chunkLen, count: 16)
        inputOffset += chunkLen + 16

        do {
            let chunkNonce = try ChaChaPoly.Nonce(data: nonce)
            let sealedBox = try ChaChaPoly.SealedBox(nonce: chunkNonce, ciphertext: ciphertext, tag: tag)
            let plaintext = try ChaChaPoly.open(sealedBox, using: key)

            // Write plaintext to output
            plaintext.withUnsafeBytes { src in
                memcpy(outputPtr + outputOffset, src.baseAddress!, src.count)
            }
        } catch {
            // On decryption failure, zero the output chunk
            memset(outputPtr + outputOffset, 0, chunkLen)
        }

        outputOffset += chunkLen
    }
}

/// Encrypt chunks from input region to output region
private func encryptChunks(
    inputPtr: UnsafeMutableRawPointer,
    outputPtr: UnsafeMutableRawPointer,
    baseNonce: [UInt8],
    key: SymmetricKey,
    chunkCount: Int,
    totalPlaintextLen: Int
) {
    var inputOffset = 0
    var outputOffset = 0

    for i in 0..<chunkCount {
        let chunkLen: Int
        if totalPlaintextLen == 0 {
            chunkLen = 0
        } else if i < chunkCount - 1 {
            chunkLen = kCryptoChunkSize
        } else {
            let remainder = totalPlaintextLen % kCryptoChunkSize
            chunkLen = remainder == 0 ? kCryptoChunkSize : remainder
        }

        // Derive nonce
        var nonce = baseNonce
        nonce[11] ^= 0x02
        nonce[9] ^= UInt8(truncatingIfNeeded: i >> 8)
        nonce[10] ^= UInt8(truncatingIfNeeded: i)

        // Read plaintext from input
        let plaintext = Data(bytes: inputPtr + inputOffset, count: chunkLen)
        inputOffset += chunkLen

        do {
            let chunkNonce = try ChaChaPoly.Nonce(data: nonce)
            let sealedBox = try ChaChaPoly.seal(plaintext, using: key, nonce: chunkNonce)

            // Write ciphertext + tag to output
            sealedBox.ciphertext.withUnsafeBytes { src in
                memcpy(outputPtr + outputOffset, src.baseAddress!, src.count)
            }
            sealedBox.tag.withUnsafeBytes { src in
                memcpy(outputPtr + outputOffset + chunkLen, src.baseAddress!, src.count)
            }
        } catch {
            memset(outputPtr + outputOffset, 0, chunkLen + 16)
        }

        outputOffset += chunkLen + 16
    }
}

// MARK: - Signature Worker Loop

/// Main loop for a signature verification worker process.
func signatureWorkerLoop(workerId: Int, region: SharedMemoryRegion, spinIterations: Int = 100) -> Never {
    let readFd = region.workerSignalRead[workerId]
    let completionFd = region.completionSignalWrite

    while true {
        var found = false
        for _ in 0..<spinIterations {
            if let slotIndex = region.popFromWorkerRing(workerId) {
                processSignatureSlot(slotIndex, region: region)
                signalEventfd(completionFd)
                found = true
                break
            }
        }
        if found { continue }

        _ = waitEventfd(readFd, timeoutUs: 100_000)
        drainEventfd(readFd)

        while let slotIndex = region.popFromWorkerRing(workerId) {
            processSignatureSlot(slotIndex, region: region)
            signalEventfd(completionFd)
        }
    }
}

/// Process a single signature slot
private func processSignatureSlot(_ slotIndex: Int, region: SharedMemoryRegion) {
    region.setStatus(slotIndex, .processing)

    let operation = region.getOperation(slotIndex)
    let keyBuf = region.getSignatureKey(slotIndex)
    let keyData = Data(bytes: keyBuf.baseAddress!, count: 32)
    let dataLen = Int(region.getSignatureDataLen(slotIndex))
    let dataPtr = region.signatureData(slotIndex)
    let sigPtr = region.signatureBytes(slotIndex)

    if operation == SignatureOperation.verify.rawValue {
        // Verify Ed25519 signature
        let signatureData = Data(bytes: sigPtr, count: kSignatureSize)
        let messageData = Data(bytes: dataPtr, count: dataLen)

        do {
            let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: keyData)
            let isValid = publicKey.isValidSignature(signatureData, for: messageData)
            region.setResult(slotIndex, isValid ? 1 : 0)
        } catch {
            region.setResult(slotIndex, 0)
        }
    } else {
        // Sign with Ed25519
        let messageData = Data(bytes: dataPtr, count: dataLen)

        do {
            let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: keyData)
            let signature = try privateKey.signature(for: messageData)

            // Write signature to slot
            signature.withUnsafeBytes { src in
                memcpy(sigPtr, src.baseAddress!, min(src.count, kSignatureSize))
            }
            region.setResult(slotIndex, 1)
        } catch {
            region.setResult(slotIndex, 0)
        }
    }

    region.setStatus(slotIndex, .done)
}

#endif // os(Linux)
