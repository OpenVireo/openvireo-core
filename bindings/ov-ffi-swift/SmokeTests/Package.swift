// swift-tools-version:5.9
// macOS smoke test of the Swift binding: `cargo xtask xcframework`, then `swift test` here.
import PackageDescription

let package = Package(
    name: "SmokeTests",
    platforms: [.macOS(.v12)],
    dependencies: [.package(name: "OpenVireoRustCore", path: "..")],
    targets: [
        .testTarget(
            name: "SmokeTests",
            dependencies: [.product(name: "OpenVireoRustCore", package: "OpenVireoRustCore")]
        ),
    ]
)
