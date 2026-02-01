// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "CryptoBenchmark",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/apple/swift-atomics.git", from: "1.2.0"),
    ],
    targets: [
        .target(
            name: "CBoringSSL",
            path: "Sources/CBoringSSL",
            exclude: [
                "crypto/bio/connect.cc",
                "crypto/bio/socket_helper.cc",
                "crypto/bio/socket.cc",
            ],
            cSettings: [
                .define("_HAS_EXCEPTIONS", to: "0", .when(platforms: [.windows])),
                .define("WIN32_LEAN_AND_MEAN", .when(platforms: [.windows])),
                .define("NOMINMAX", .when(platforms: [.windows])),
                .define("_CRT_SECURE_NO_WARNINGS", .when(platforms: [.windows])),
            ]
        ),
        .executableTarget(
            name: "CryptoBenchmark",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Atomics", package: "swift-atomics"),
            ],
            path: "Sources/CryptoBenchmark"
        ),
        .executableTarget(
            name: "ThreadVsProcess",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources/ThreadVsProcess"
        ),
        .executableTarget(
            name: "DirectAPI",
            dependencies: [
                "CBoringSSL",
            ],
            path: "Sources/DirectAPI"
        ),
    ],
    cxxLanguageStandard: .cxx17
)
