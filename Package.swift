// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Menkyo",
    products: [
        .library(
            name: "Menkyo",
            targets: ["Menkyo"]),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/ctls.git", from: "1.1.3")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "Menkyo",
            dependencies: ["CTLS"]),
        .testTarget(
            name: "MenkyoTests",
            dependencies: ["Menkyo"]),
    ]
)
