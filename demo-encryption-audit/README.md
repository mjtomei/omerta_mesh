# Encryption Audit Demo

Demonstrates that the encryption audit system catches various malicious or
accidental code changes that would send unencrypted or improperly encrypted
data over the network.

## Attack Scenarios

Each `.patch` file simulates a different bad change to `MeshNode.swift`:

| # | Patch | Attack | Detection |
|---|-------|--------|-----------|
| 1 | `01-plaintext-json-send.patch` | Developer reverts broadcast to unencrypted JSON | Prefix check (no OMRT magic) |
| 2 | `02-debug-probe-send.patch` | Developer adds an unencrypted diagnostic probe | Prefix check (raw ASCII) |
| 3 | `03-spoofed-magic-prefix.patch` | Code adds OMRT prefix to plaintext keepalive | Compile-time (`sendRaw` is internal) or decryption check |
| 4 | `04-wrong-key-encryption.patch` | Bug uses random session key instead of network key | Decryption check (wrong key) |
| 5 | `05-legacy-encryption-path.patch` | Code uses old `MessageEncryption.encrypt()` path | Prefix check (no OMRT magic) |
| 6 | `06-payload-corruption.patch` | Bug truncates payload destroying AEAD tag | Decryption check (auth failure) |

## Running

```bash
cd demo-encryption-audit
./run-demo.sh
```

Or specify a repo path:

```bash
./run-demo.sh /path/to/omerta_mesh
```

The script clones the repo to a temp directory, applies each patch, builds,
runs the audit tests, and reports whether the violation was caught. The
original repo is never modified.

## How Detection Works

Two layers of defense:

1. **Compile-time**: `UDPSocket.send()` only accepts `SealedEnvelope`, which
   can only be constructed by `BinaryEnvelopeV2.encodeV2()`. Code that tries
   to send raw `Data` won't compile (unless it uses `sendRaw`, which is
   `internal`-only).

2. **Runtime**: The `--audit-encryption` flag (DEBUG builds) installs a
   capture hook on every UDP send that verifies:
   - The packet starts with the `OMRT` magic + version prefix
   - The packet successfully decrypts with the network key

   In tests, `GlobalEncryptionObserver` provides the same checking across
   the entire test suite.
