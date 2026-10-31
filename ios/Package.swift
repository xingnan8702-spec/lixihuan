// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "IPadProxyCore",
    platforms: [
        .iOS(.v15),
        .macOS(.v13),
    ],
    products: [
        .library(name: "IPadProxyCore", targets: ["IPadProxyCore"]),
    ],
    targets: [
        .target(name: "IPadProxyCore"),
        .testTarget(name: "IPadProxyCoreTests", dependencies: ["IPadProxyCore"]),
    ]
)
