// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Watchword",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
    ],
    products: [
        .library(name: "WatchwordModel", targets: ["WatchwordModel"]),
        .library(name: "WatchwordMatching", targets: ["WatchwordMatching"]),
        .library(name: "WatchwordGenerator", targets: ["WatchwordGenerator"]),
        .library(name: "WatchwordEnvelope", targets: ["WatchwordEnvelope"]),
    ],
    targets: [
        // Pure data types shared by every other module.
        .target(name: "WatchwordModel"),

        // Service-scope matching and ranking for AutoFill (see docs/02-architecture.md §9).
        .target(name: "WatchwordMatching", dependencies: ["WatchwordModel"]),

        // Password, passphrase and PIN generation with entropy estimates (§12).
        .target(name: "WatchwordGenerator"),

        // Envelope header and KDF parameter validation with anti-downgrade floors (§5, ADR 0003).
        .target(name: "WatchwordEnvelope"),

        // XCTest suite.
        .testTarget(name: "WatchwordMatchingTests", dependencies: ["WatchwordMatching", "WatchwordModel"]),

        // Swift Testing suites.
        .testTarget(name: "WatchwordGeneratorTests", dependencies: ["WatchwordGenerator"]),
        .testTarget(name: "WatchwordEnvelopeTests", dependencies: ["WatchwordEnvelope"]),

        // Adversarial security suite (Swift Testing, tag .adversarial, run as its own CI job).
        .testTarget(
            name: "WatchwordAdversarialTests",
            dependencies: ["WatchwordMatching", "WatchwordGenerator", "WatchwordEnvelope", "WatchwordModel"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
