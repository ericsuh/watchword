// swift-tools-version: 6.0
import PackageDescription

// The libFuzzer harness for the parsers that face hostile bytes (docs/04-test-plan.md §6.8).
//
// A package of its own, beside the shipped one, on purpose: nothing here can reach an app. The root `Package.swift`
// does not know this directory exists, so the harness, its entry point (the one place outside `SecureMemory` that
// must name a pointer type, because libFuzzer's callback is a C function) and its corpus are outside everything the
// apps link. `.github/scripts/assert-no-dependencies.sh` holds this manifest to the same rules as the root one and
// to one dependency, the repository itself; `assert-unsafe-confined.sh` confines the pointer to `LibFuzzerEntry.swift`.
//
// Build and run through `mise run fuzz`. The target has two forms, chosen by a `-D` on the command line because a
// manifest may not carry compiler flags here:
//
//   swift build --package-path Fuzz -c release --product WatchwordFuzz
//       a replay and blind-mutation tool with its own `main` (any toolchain)
//   swift build --package-path Fuzz -c release --product WatchwordFuzz \
//       -Xswiftc -sanitize=fuzzer -Xswiftc -parse-as-library -Xswiftc -DWATCHWORD_LIBFUZZER
//       the libFuzzer binary, whose `main` is libFuzzer's
let package = Package(
    name: "WatchwordFuzz",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "WatchwordFuzz", targets: ["WatchwordFuzz"])
    ],
    dependencies: [
        // Named, so the products below resolve whatever the checkout directory is called.
        .package(name: "Watchword", path: "..")
    ],
    targets: [
        .executableTarget(
            name: "WatchwordFuzz",
            dependencies: [
                .product(name: "WatchwordInterchange", package: "Watchword"),
                .product(name: "WatchwordModel", package: "Watchword"),
                .product(name: "WatchwordMatching", package: "Watchword"),
                .product(name: "WatchwordEnvelope", package: "Watchword"),
                .product(name: "WatchwordStore", package: "Watchword"),
                .product(name: "WatchwordSync", package: "Watchword"),
                .product(name: "WatchwordCrypto", package: "Watchword"),
            ]
        )
    ],
    swiftLanguageModes: [.v6]
)
