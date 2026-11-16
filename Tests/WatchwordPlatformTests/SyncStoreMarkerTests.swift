import Foundation
import Testing
import WatchwordPlatform

/// The memory of which remote stores this device has seen exist (docs/02-architecture.md §7.2), which keeps a store the
/// person deleted from being recreated. Portable.
@Suite("Sync store marker")
struct SyncStoreMarkerTests {
    static func directory() -> URL {
        URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("watchword-marker-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("SyncStores", isDirectory: true)
    }

    static func markers() -> [any SyncStoreMarker] {
        [InMemorySyncStoreMarker(), FileSyncStoreMarker(directory: directory())]
    }

    @Test("a store is unseen until marked, seen after, and unseen again only when forgotten")
    func contract() async throws {
        for marker in Self.markers() {
            #expect(try await marker.hasSeen("cloudkit-Watchword") == false)
            try await marker.markSeen("cloudkit-Watchword")
            try await marker.markSeen("cloudkit-Watchword")
            #expect(try await marker.hasSeen("cloudkit-Watchword"))
            #expect(try await marker.hasSeen("cloudkit-Other") == false)
            try await marker.forget("cloudkit-Watchword")
            #expect(try await marker.hasSeen("cloudkit-Watchword") == false)
        }
    }

    @Test(
        "the file marker survives a new instance, refuses names outside its alphabet, and is never unsure towards unseen"
    )
    func file() async throws {
        let directory = Self.directory()
        try await FileSyncStoreMarker(directory: directory).markSeen("cloudkit-Watchword")
        let again = FileSyncStoreMarker(directory: directory)
        #expect(try await again.hasSeen("cloudkit-Watchword"))
        for bad in ["", "a/b", "../x", "a b", String(repeating: "a", count: 65)] {
            await #expect(throws: FileSyncStoreMarker.MarkerNameError.invalid(bad)) { try await again.hasSeen(bad) }
        }
        // Something other than an empty marker under the name (A8, or damage): seen, so nothing is recreated.
        try await again.forget("cloudkit-Other")
        let name = try #require(
            try FileManager.default.contentsOfDirectory(atPath: directory.path).first.map {
                directory.appendingPathComponent($0)
            })
        try FileManager.default.removeItem(at: name)
        try FileManager.default.createDirectory(at: name, withIntermediateDirectories: false)
        #expect(try await again.hasSeen("cloudkit-Watchword"))
    }
}
