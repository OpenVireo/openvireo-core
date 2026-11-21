// swift-tools-version:5.9
// The OpenVireoRustCore Swift package: the UniFFI-generated Swift over OpenVireoCore.xcframework.
// Run `cargo xtask xcframework` first; it writes build/OpenVireoCore.xcframework and
// Sources/OpenVireoRustCore/OpenVireoRustCore.swift (both gitignored).
import PackageDescription

let package = Package(
    name: "OpenVireoRustCore",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "OpenVireoRustCore", targets: ["OpenVireoRustCore"]),
    ],
    targets: [
        // The static libraries plus the C module `OpenVireoRustCoreFFI`. The target is not named
        // after the xcframework, so it can't clash with the iOS app's `OpenVireoCore` target.
        .binaryTarget(name: "OpenVireoRustCoreFFI", path: "build/OpenVireoCore.xcframework"),
        .target(
            name: "OpenVireoRustCore",
            dependencies: ["OpenVireoRustCoreFFI"],
            path: "Sources/OpenVireoRustCore"
        ),
    ]
)
