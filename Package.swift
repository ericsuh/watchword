// swift-tools-version: 6.0
import PackageDescription

// CryptoKit's API over BoringSSL, on Linux only (ADR 0006), so the cryptographic core, VaultSession and their tests
// build and run where CryptoKit does not exist. Apple builds never link it: they use CryptoKit and CommonCrypto.
let linuxCrypto = Target.Dependency.product(
    name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux]))
// PBKDF2 (`KDF.Insecure.PBKDF2`), standing in for CommonCrypto's on Linux.
let linuxCryptoExtras = Target.Dependency.product(
    name: "CryptoExtras", package: "swift-crypto", condition: .when(platforms: [.linux]))

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
        .library(name: "WatchwordStore", targets: ["WatchwordStore"]),
        .library(name: "WatchwordSync", targets: ["WatchwordSync"]),
        .library(name: "WatchwordKit", targets: ["WatchwordKit"]),
        .library(name: "WatchwordPlatform", targets: ["WatchwordPlatform"]),
    ],
    dependencies: [
        // Exact version, and Package.resolved pins the commit (ADR 0006).
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.5.2")
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

        // Zeroising, page-locked buffers for key material, and PBKDF2 (CommonCrypto; swift-crypto on Linux).
        // The only module allowed unsafe constructs; each one is marked `unsafe` (§11, ADR 0001).
        .target(name: "SecureMemory", dependencies: [linuxCrypto, linuxCryptoExtras]),

        // Secret Key, 2SKD, keyset, vault keys, HPKE grants, signatures, record sealing (§4, §5; milestone 1).
        .target(name: "WatchwordCrypto", dependencies: ["SecureMemory", "WatchwordEnvelope", linuxCrypto]),

        // Local ciphertext store: the port, an in-memory implementation and the SQLite database (§6; milestone 2).
        .target(name: "WatchwordStore", dependencies: ["SecureMemory", "WatchwordEnvelope"]),

        // Change-log segments, snapshots, field-level merge and the SyncTransport port (§7; milestone 3). Pure: segment
        // sealing, signing and item decryption reach it through ports, so nothing here imports CryptoKit and the whole
        // engine runs under `swift test` on Linux (docs/03-implementation-plan.md, "Where each milestone is built").
        .target(name: "WatchwordSync", dependencies: ["WatchwordModel", "WatchwordEnvelope", "WatchwordStore"]),

        // VaultSession façade, unlock and auto-lock policies, and the ports the UI and adapters plug into (§10, §15).
        .target(
            name: "WatchwordKit",
            dependencies: [
                "WatchwordModel", "WatchwordMatching", "WatchwordEnvelope", "WatchwordCrypto", "WatchwordStore",
                "SecureMemory",
            ]
        ),

        // Apple-framework adapters for the WatchwordKit ports: Keychain, LocalAuthentication, the App Group container
        // and the Emergency Kit PDF. In the package rather than Apps/ so the strict-memory-safety job, the unsafe
        // tripwire, lint and `swift test` all cover them.
        .target(name: "WatchwordPlatform", dependencies: ["WatchwordKit", "WatchwordStore", "SecureMemory"]),

        // Seeded and deliberately broken generators and vector helpers, for test targets only (§15). Not a product,
        // and no production target may depend on it.
        .target(
            name: "WatchwordTestSupport",
            dependencies: [
                "WatchwordKit", "WatchwordModel", "WatchwordStore", "WatchwordSync", "WatchwordEnvelope",
                "SecureMemory",
            ]
        ),

        // XCTest suite.
        .testTarget(name: "WatchwordMatchingTests", dependencies: ["WatchwordMatching", "WatchwordModel"]),

        // Swift Testing suites.
        .testTarget(name: "WatchwordGeneratorTests", dependencies: ["WatchwordGenerator", "WatchwordTestSupport"]),
        .testTarget(name: "WatchwordEnvelopeTests", dependencies: ["WatchwordEnvelope", "WatchwordTestSupport"]),
        .testTarget(name: "SecureMemoryTests", dependencies: ["SecureMemory", "WatchwordTestSupport", linuxCrypto]),
        .testTarget(
            name: "WatchwordCryptoTests",
            dependencies: [
                "WatchwordCrypto", "SecureMemory", "WatchwordEnvelope", "WatchwordTestSupport", linuxCrypto,
            ]
        ),

        .testTarget(
            name: "WatchwordStoreTests",
            dependencies: ["WatchwordStore", "WatchwordEnvelope", "SecureMemory", "WatchwordTestSupport"]
        ),
        .testTarget(
            name: "WatchwordSyncTests",
            dependencies: [
                "WatchwordSync", "WatchwordModel", "WatchwordStore", "WatchwordEnvelope", "WatchwordKit",
                "WatchwordTestSupport",
            ]
        ),
        .testTarget(
            name: "WatchwordKitTests",
            dependencies: [
                "WatchwordKit", "WatchwordModel", "WatchwordMatching", "WatchwordStore", "WatchwordCrypto",
                "WatchwordEnvelope", "SecureMemory", "WatchwordTestSupport",
            ]
        ),
        .testTarget(
            name: "WatchwordPlatformTests",
            dependencies: ["WatchwordPlatform", "WatchwordKit", "SecureMemory", "WatchwordTestSupport"]
        ),

        // Adversarial security suite (Swift Testing, tag .adversarial, run as its own CI job).
        .testTarget(
            name: "WatchwordAdversarialTests",
            dependencies: [
                "WatchwordMatching", "WatchwordGenerator", "WatchwordEnvelope", "WatchwordModel", "WatchwordCrypto",
                "SecureMemory", "WatchwordStore", "WatchwordSync", "WatchwordKit", "WatchwordPlatform",
                "WatchwordTestSupport", linuxCrypto,
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
