// swift-tools-version: 5.9
import PackageDescription
import Foundation

// Compute the package directory for linker paths
let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path

let package = Package(
    name: "OmertaMesh",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "OmertaMesh", targets: ["OmertaMesh"]),
        .library(name: "OmertaTunnel", targets: ["OmertaTunnel"]),
        .library(name: "OmertaSSH", targets: ["OmertaSSH"]),
        .executable(name: "omerta-mesh", targets: ["OmertaMeshCLI"]),
        .executable(name: "omerta-meshd", targets: ["OmertaMeshDaemon"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.60.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
    ],
    targets: [
        .target(
            name: "OmertaMesh",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .systemLibrary(name: "CNetstack", path: "Sources/CNetstack"),
        .target(
            name: "OmertaTunnel",
            dependencies: ["OmertaMesh", .product(name: "Logging", package: "swift-log")],
            exclude: ["Netstack"]
        ),
        .target(
            name: "OmertaSSH",
            dependencies: ["OmertaTunnel", "OmertaNetwork", .product(name: "Logging", package: "swift-log")]
        ),
        .executableTarget(
            name: "OmertaMeshCLI",
            dependencies: [
                "OmertaMesh",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
            ]
        ),
        .executableTarget(
            name: "OmertaMeshDaemon",
            dependencies: [
                "OmertaMesh",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
            ]
        ),
        .testTarget(name: "OmertaMeshTests", dependencies: [
            "OmertaMesh",
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
        ]),
        .target(
            name: "OmertaNetwork",
            dependencies: ["OmertaMesh", "OmertaTunnel", "CNetstack", .product(name: "Logging", package: "swift-log")],
            linkerSettings: [
                .linkedLibrary("netstack", .when(platforms: [.macOS, .linux])),
                .unsafeFlags(["-L\(packageDir)/Sources/CNetstack"], .when(platforms: [.macOS, .linux])),
            ]
        ),
        .testTarget(name: "OmertaTunnelTests", dependencies: ["OmertaTunnel", "OmertaNetwork", "OmertaMesh"]),
        .testTarget(name: "OmertaNetworkTests", dependencies: ["OmertaNetwork", "OmertaMesh"]),
    ]
)
