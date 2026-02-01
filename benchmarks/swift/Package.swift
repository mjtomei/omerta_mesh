// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SwiftBenchmarks",
    platforms: [.macOS(.v13)],
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
            name: "DataElisionDemo",
            dependencies: [
                "CBoringSSL",
            ],
            path: "Sources/DataElisionDemo"
        ),
    ],
    cxxLanguageStandard: .cxx17
)
