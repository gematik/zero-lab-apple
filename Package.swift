// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "TrustClient",
    platforms: [.macOS(.v11), .iOS(.v14)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "TrustClient",
            targets: ["TrustClient"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", .upToNextMajor(from: "1.0.0")),
        .package(url: "https://github.com/airsidemobile/JOSESwift.git", from: "2.3.0")

    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "TrustClient",
            dependencies: [
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "JOSESwift", package: "JOSESwift")
            ]),
            
        .testTarget(
            name: "TrustClientTests",
            dependencies: ["TrustClient"]),
    ]
)
