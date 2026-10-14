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
        .library(name: "SecureMemory", targets: ["SecureMemory"]),
        .library(name: "WatchwordCrypto", targets: ["WatchwordCrypto"]),
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

        // Zeroising, page-locked buffers for key material, and the one CommonCrypto call that needs raw pointers.
        // The only module allowed unsafe constructs; each one is marked `unsafe` (§11, ADR 0001).
        .target(name: "SecureMemory"),

        // Secret Key, 2SKD, keyset, vault keys, HPKE grants, signatures, record sealing (§4, §5; milestone 1).
        .target(name: "WatchwordCrypto", dependencies: ["SecureMemory", "WatchwordEnvelope"]),

        // Seeded and deliberately broken generators and vector helpers, for test targets only (§15). Not a product,
        // and no production target may depend on it.
        .target(name: "WatchwordTestSupport"),

        // XCTest suite.
        .testTarget(name: "WatchwordMatchingTests", dependencies: ["WatchwordMatching", "WatchwordModel"]),

        // Swift Testing suites.
        .testTarget(name: "WatchwordGeneratorTests", dependencies: ["WatchwordGenerator", "WatchwordTestSupport"]),
        .testTarget(name: "WatchwordEnvelopeTests", dependencies: ["WatchwordEnvelope", "WatchwordTestSupport"]),
        .testTarget(name: "SecureMemoryTests", dependencies: ["SecureMemory", "WatchwordTestSupport"]),
        .testTarget(
            name: "WatchwordCryptoTests",
            dependencies: ["WatchwordCrypto", "SecureMemory", "WatchwordEnvelope", "WatchwordTestSupport"]
        ),

        // Adversarial security suite (Swift Testing, tag .adversarial, run as its own CI job).
        .testTarget(
            name: "WatchwordAdversarialTests",
            dependencies: [
                "WatchwordMatching", "WatchwordGenerator", "WatchwordEnvelope", "WatchwordModel", "WatchwordCrypto",
                "SecureMemory", "WatchwordTestSupport",
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
