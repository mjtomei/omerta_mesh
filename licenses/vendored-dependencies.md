# Vendored Dependencies

Some third-party code is vendored directly into the repository rather than
fetched at build time.

## Dependencies

| Package | License | Source | Vendored Path |
|---------|---------|--------|---------------|
| [gVisor netstack](https://gvisor.dev/) | [Apache-2.0](https://github.com/google/gvisor/blob/master/LICENSE) | https://github.com/google/gvisor | `Sources/OmertaTunnel/Netstack/` |
| [BoringSSL](https://boringssl.googlesource.com/boringssl/) | [Apache-2.0](https://boringssl.googlesource.com/boringssl/+/refs/heads/master/LICENSE) | Vendored via [swift-crypto](https://github.com/apple/swift-crypto) | `benchmarks/crypto/Sources/CBoringSSL/` |

gVisor's netstack provides a userspace TCP/IP stack for the OmertaTunnel
module. The Go source is vendored and compiled into `libnetstack.a`.
See [go-dependencies.md](go-dependencies.md) for the full list of transitive
Go dependencies included in the static library.

BoringSSL is Google's fork of OpenSSL. The vendored copy was taken from
Apple's [swift-crypto](https://github.com/apple/swift-crypto) package
(which wraps BoringSSL as `CCryptoBoringSSL`) and re-exported as a standalone
`CBoringSSL` module for direct C API access in the crypto benchmarks.

The `third_party/fiat/` subdirectory contains auto-generated code from the
[fiat-crypto](https://github.com/mit-plv/fiat-crypto) project (MIT license).
