# Third-Party Licenses

This directory contains license information for third-party dependencies used in OmertaMesh.

## Go Dependencies (OmertaTunnel/Netstack)

The `OmertaTunnel` module uses a userspace TCP/IP stack built on gVisor's netstack.
These dependencies are compiled into `libnetstack.a`.

See [go-dependencies.md](go-dependencies.md) for the full list.

## Swift Dependencies

Swift dependencies are managed via Swift Package Manager and are not bundled
in this repository. See [swift-dependencies.md](swift-dependencies.md) for the list.

## Vendored Dependencies

Some third-party code is vendored directly into the repository.
See [vendored-dependencies.md](vendored-dependencies.md) for the list.
