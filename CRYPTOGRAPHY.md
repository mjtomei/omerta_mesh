# OmertaMesh Cryptography

This document describes the cryptographic protocols used in OmertaMesh for packet encryption and key negotiation.

## Overview

OmertaMesh uses three main cryptographic protocols:

1. **Packet Encryption (Wire Format v3)** - Split-header ChaCha20-Poly1305 encryption with chunked payloads
2. **Network Key Negotiation** - X25519 key exchange for creating new private networks
3. **Network Invite Sharing** - X25519 key exchange for sharing existing network keys

All cryptographic operations use:
- **ChaCha20-Poly1305** for authenticated encryption ([RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html))
- **X25519** for ephemeral key agreement ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748))
- **HKDF-SHA256** for key derivation ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html))
- **Ed25519** for message signatures ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html))
- **SHA256** for hashing

All cryptographic operations use Apple's [CryptoKit](https://developer.apple.com/documentation/cryptokit) framework.

### Code References

| Component | File |
|-----------|------|
| Wire Format v2 encoding/decoding | `Envelope/BinaryEnvelope.swift` |
| Envelope header structure | `Envelope/EnvelopeHeader.swift` |
| Key exchange state machine | `Services/Cloister/KeyExchange.swift` |
| Network negotiation client | `Services/Cloister/CloisterClient.swift` |
| Network negotiation handler | `Services/Cloister/CloisterHandler.swift` |
| Service message types | `Services/ServiceMessages.swift` |
| Channel definitions | `Services/ServiceChannels.swift` |
| Message signing | `MeshNode.swift` (sign/verify methods) |

---

## 1. Wire Format v3 - Packet Encryption

**Implementation:** `Envelope/BinaryEnvelope.swift`, `Envelope/EnvelopeHeader.swift`

### Structure

The v3 wire format splits the header into two independently encrypted sections: a **RoutingHeader** (encrypted with the header key) and an **AuthHeader** (encrypted with the payload key). This allows relay nodes to decrypt only the routing information needed for forwarding without accessing authentication data or payload contents.

```
UNENCRYPTED PREFIX (4 bytes):
  [3 bytes] magic "OMR"
  [1 byte]  version 0x03

BASE NONCE (12 bytes):
  [12 bytes] base_nonce (random, used to derive all section nonces)

ROUTING HEADER (44 bytes plaintext + 16 bytes tag, encrypted with headerKey):
  [8 bytes]  networkHash        SHA256(networkKey)[0:8]
  [16 bytes] fromPeerId         truncated peer ID
  [16 bytes] toPeerId           truncated peer ID
  [1 byte]   flags
  [1 byte]   hopCount
  [2 bytes]  channel            UInt16 hash of channel name
  [16 bytes] poly1305 tag

AUTH HEADER (136 bytes plaintext + 16 bytes tag, encrypted with payloadKey):
  [8 bytes]  timestamp          Unix timestamp
  [16 bytes] messageId          UUID
  [16 bytes] machineId          raw 16-byte UUID
  [32 bytes] publicKey          Ed25519 public key
  [64 bytes] signature          Ed25519 signature
  [16 bytes] poly1305 tag

CHUNKED PAYLOAD (encrypted with payloadKey):
  [4 bytes]  total_payload_length   (unencrypted total plaintext size)
  For each chunk (count = ceil(total_payload_length / 512), chunk size 512):
    [N bytes]  encrypted chunk data (512 bytes for all but last)
    [16 bytes] chunk_tag (Poly1305)
```

### Key Derivation

```
networkKey (32 bytes) - shared by all network participants

headerKey = HKDF-SHA256(
    inputKeyMaterial: networkKey,
    info: "omerta-header-v3",
    outputByteCount: 32
)

payloadKey = networkKey (used directly)
```

### Nonce Derivation

A single random 12-byte base nonce is generated per packet. Each section derives its nonce by XORing the base nonce with a section-specific constant:

```
base_nonce          = random(12 bytes)

routing_nonce       = base_nonce XOR 0x00           (effectively unchanged)
auth_nonce          = base_nonce XOR 0x01           (last byte flipped)
payload_chunk_nonce = base_nonce XOR (0x02 | (chunk_index << 8))
```

For payload chunks, `chunk_index` is a zero-based index encoded into the second-to-last byte, allowing up to 256 chunks per packet. This ensures every encryption operation across all three sections uses a unique nonce.

### Chunked Payload

The payload is split into 512-byte blocks, each independently encrypted with its own nonce and authentication tag. This design enables:

- **Parallel decryption using standard APIs**: While ChaCha20 is theoretically parallelizable by block counter, CryptoKit's `ChaChaPoly.open()` is an opaque single-call API with no way to decrypt a sub-range of the ciphertext on a separate thread. Chunking allows each chunk to be handed to a standard `ChaChaPoly.open()` call independently, enabling parallel decryption without custom crypto code or dropping to a lower-level library.
- **Parallel authentication**: Poly1305 authentication of a single large message is inherently serial (sequential polynomial evaluation). Parallelizing it over a single message requires precomputed powers of `r` and more complex evaluation schemes. Independent chunks give trivially parallel, independent Poly1305 verifications with no additional implementation complexity.
- **Granular integrity**: Corruption in one chunk does not prevent decryption of other chunks.
- **Bounded memory**: Chunks can be processed in a streaming fashion without buffering the entire payload.

### Security Properties

- **Authenticated encryption (AEAD)**: ChaCha20-Poly1305 provides confidentiality and integrity per [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html)
- **Fast rejection**: Invalid magic/version rejected in O(1) without crypto operations
- **Network isolation**: Network hash check ensures packets are for correct network
- **Domain separation**: HKDF info string "omerta-header-v3" separates header key derivation
- **Relay privacy**: Split headers allow relay nodes to route packets using only the headerKey, without accessing authentication data or payload contents
- **Nonce uniqueness**: XOR-differentiated nonces from a single base nonce guarantee no nonce reuse across sections within a packet

---

## 2. Network Key Negotiation (Cloister Service)

**Implementation:**
- Key exchange: `Services/Cloister/KeyExchange.swift`
- Client: `Services/Cloister/CloisterClient.swift:negotiate()`
- Handler: `Services/Cloister/CloisterHandler.swift:handleNegotiationRequest()`
- Messages: `Services/ServiceMessages.swift` (`CloisterRequest`, `CloisterResponse`)

Used when two peers want to create a new private network together.

### Protocol Flow

```
Initiator (A)                                Responder (B)
─────────────────────────────────────────────────────────────────

1. Generate ephemeral X25519 keypair
   (privA, pubA)

2. Send CloisterRequest:            →
   { requestId, networkName, pubA }

                                          3. Generate ephemeral X25519 keypair
                                             (privB, pubB)

                                          4. Compute shared secret:
                                             sharedSecret = X25519(privB, pubA)

                                          5. Derive network key:
                                             networkKey = HKDF-SHA256(
                                                 inputKeyMaterial: sharedSecret,
                                                 info: "omerta-network-key",
                                                 outputByteCount: 32
                                             )

                                    ←     6. Send CloisterResponse:
                                             { requestId, accepted, pubB }

7. Compute shared secret:
   sharedSecret = X25519(privA, pubB)

8. Derive network key:
   networkKey = HKDF-SHA256(...)

9. Both peers now have identical networkKey
```

### Security Properties

- **Diffie-Hellman key agreement**: X25519 enables two parties to derive a shared secret from public key exchange. Eavesdroppers cannot compute the shared secret without a private key. See [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748).
- **Forward secrecy**: Fresh ephemeral keys for each negotiation
- **Domain separation**: HKDF info string "omerta-network-key" prevents cross-protocol attacks per [RFC 5869 §3.2](https://www.rfc-editor.org/rfc/rfc5869.html#section-3.2)

---

## 3. Network Invite Sharing (Cloister Service)

**Implementation:**
- Key exchange: `Services/Cloister/KeyExchange.swift`
- Client: `Services/Cloister/CloisterClient.swift:shareInvite()`
- Handler: `Services/Cloister/CloisterHandler.swift:handleInviteShare()`
- Messages: `Services/ServiceMessages.swift` (`NetworkInviteShare`, `NetworkInviteAck`)

Used when a peer wants to share an existing network key with another peer.

### Protocol Flow (Two-Round)

```
Inviter (A)                                  Recipient (B)
─────────────────────────────────────────────────────────────────

ROUND 1: KEY EXCHANGE

1. Generate ephemeral X25519 keypair
   (privA, pubA)

2. Send InviteKeyExchange:          →
   { requestId, pubA, networkNameHint }

                                          3. Generate ephemeral X25519 keypair
                                             (privB, pubB)

                                          4. Compute shared secret and derive
                                             inviteKey via HKDF

                                    ←     5. Send InviteKeyExchangeResponse:
                                             { requestId, pubB, accepted }

6. Complete key exchange, derive
   same inviteKey

ROUND 2: ENCRYPTED INVITE

7. Encrypt network key:
   encryptedInvite = ChaCha20-Poly1305(
       plaintext: networkKey,
       key: inviteKey,
       nonce: random(12)
   )

8. Send InvitePayload:             →
   { requestId, encryptedInvite }

                                          9. Decrypt network key using inviteKey

                                    ←     10. Send InviteAck:
                                              { requestId, accepted, joinedNetworkId }
```

### Why Two Rounds?

Unlike negotiation where both peers derive a new key, invite sharing transmits an existing key. The key exchange must complete before the invite can be encrypted, requiring two rounds.

### Security Properties

- **Diffie-Hellman key agreement**: Same security as negotiation per [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)
- **Forward secrecy**: Fresh ephemeral keys for each invite
- **Authenticated encryption**: Network key encrypted with ChaCha20-Poly1305 per [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html)
- **Domain separation**: "omerta-invite-key" separates from "omerta-network-key"

---

## 4. Message Signatures

**Implementation:** `MeshNode.swift` (see `signEnvelope()` and signature verification in `handleIncomingPacket()`)

All mesh messages are signed by the sender using Ed25519 ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html)).

### Signing Data

```
signatureData = concat(
    networkId, messageId, fromPeerId, toPeerId,
    channel, hopCount, timestamp, payloadBytes
)

signature = Ed25519.sign(signatureData, privateKey)
```

### Verification

Recipients verify signatures before processing using the public key included in the header.

---

## 5. Network Hashes and IDs

### Network Hash (8 bytes)

Included in every packet header for fast network filtering:

```
networkHash = SHA256(networkKey)[0:8]
```

### Network ID (16 hex chars)

Human-readable identifier for networks:

```
networkId = hex(SHA256(networkKey)[0:8])
```

---

## 6. Security Considerations

### Threat Model

- **Network eavesdroppers**: Cannot read packet contents (AEAD encryption)
- **Network attackers**: Cannot forge packets (authenticated encryption + signatures)
- **Wrong-network peers**: Packets rejected via networkHash verification
- **Replay attacks**: Message IDs and timestamps prevent replay
- **Key compromise**: Ephemeral keys provide forward secrecy for negotiations

### Implementation Notes

- Nonces are generated using `ChaChaPoly.Nonce()` (cryptographically secure random)
- Keys are stored using CryptoKit's `SymmetricKey`
- Network keys are persisted encrypted at rest (see STRUCTURE.md)
- HKDF uses empty salt, acceptable per [RFC 5869 §3.1](https://www.rfc-editor.org/rfc/rfc5869.html#section-3.1) when IKM has sufficient entropy

### Known Limitations

1. **No post-quantum security**: X25519 and Ed25519 are not quantum-resistant
2. **Trust on first use**: Peer identities are not externally verified
3. **No key rotation**: Network keys are static once created

---

## References

- [RFC 7748: Elliptic Curves for Security (X25519)](https://www.rfc-editor.org/rfc/rfc7748)
- [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439.html)
- [RFC 5869: HKDF (HMAC-based Key Derivation Function)](https://www.rfc-editor.org/rfc/rfc5869.html)
- [RFC 8032: Edwards-Curve Digital Signature Algorithm (Ed25519)](https://www.rfc-editor.org/rfc/rfc8032.html)
- [Apple CryptoKit Documentation](https://developer.apple.com/documentation/cryptokit)
- [Curve25519 Wikipedia](https://en.wikipedia.org/wiki/Curve25519)
- [Understanding HKDF (Soatok)](https://soatok.blog/2021/11/17/understanding-hkdf/)
