// swift-tools-version: 6.0
import PackageDescription
import Foundation

let rustTargetDir: String = {
    let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    return repoRoot.appendingPathComponent("target/debug").path
}()

let package = Package(
    name: "C2PASwiftCompat",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "C2PASwiftCompat",
            targets: ["C2PASwiftCompat"]
        ),
    ],
    targets: [
        .target(
            name: "CContentauthC2pa",
            path: "Sources/CContentauthC2pa",
            publicHeadersPath: "include"
        ),
        .target(
            name: "C2PASwiftCompat",
            dependencies: ["CContentauthC2pa"],
            path: "Sources/C2PASwiftCompat",
            linkerSettings: [
                .unsafeFlags([
                    "-L" + rustTargetDir,
                    "-lcontentauth_c2pa_c_api"
                ])
            ]
        ),
        .testTarget(
            name: "C2PASwiftCompatTests",
            dependencies: ["C2PASwiftCompat"],
            path: "Tests/C2PASwiftCompatTests"
        ),
    ]
)
