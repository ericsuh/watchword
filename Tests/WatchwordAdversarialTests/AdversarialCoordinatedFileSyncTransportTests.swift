#if canImport(Darwin)
    import Foundation
    import Testing
    import WatchwordPlatform
    import WatchwordSync

    /// The coordinated iCloud Drive transport against whoever else can write the folder (docs/02-architecture.md §7.3).
    ///
    /// Threat model: **A1, anyone with the iCloud account or the provider's side** (and on a shared folder, milestone 4,
    /// other members), able to put any file, link, directory or placeholder in the sync folder. Every rule of the portable
    /// `FileSyncTransport` must still hold with coordination in between, and the iCloud-specific paths (placeholders,
    /// conflict versions) must not open a way around them: a planted link is never followed, a planted placeholder is at
    /// most a withheld object (which A1 could always do), and nothing is ever written over an existing object. Runs on a
    /// Mac only; not in `adversarial-suites.txt`, which Linux also checks.
    @Suite("Adversarial: Apple adapters: iCloud Drive transport", .tags(.adversarial))
    struct AdversarialCoordinatedFileSyncTransportTests {
        static func root() -> URL {
            URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
                .appendingPathComponent("watchword-adversarial-coordinated-\(UUID().uuidString)", isDirectory: true)
        }

        /// A1 replaces a stream's directory with a link to somewhere else on the device: nothing is listed through it,
        /// fetching through it is refused, and nothing is written through it.
        @Test("a directory replaced by a link is neither listed, read nor written through")
        func linkedDirectory() async throws {
            let root = Self.root()
            let transport = CoordinatedFileSyncTransport(root: root)
            let name = SyncObjectLocation.segment(vaultID: UUID(), author: UUID(), sequence: 1).name
            let url = try transport.base.fileURL(for: name)
            let elsewhere = Self.root()
            try FileManager.default.createDirectory(at: elsewhere, withIntermediateDirectories: true)
            try Data([9]).write(to: elsewhere.appendingPathComponent(url.lastPathComponent))
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent().deletingLastPathComponent(), withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(
                at: url.deletingLastPathComponent(), withDestinationURL: elsewhere)

            let prefix = String(name.split(separator: "/").dropLast().joined(separator: "/")) + "/"
            #expect(try await transport.list(prefix: prefix).isEmpty)
            await #expect(throws: SyncTransportError.invalidName(name)) {
                try await transport.fetch(name, maximumLength: 100)
            }
            await #expect(throws: SyncTransportError.invalidName(name)) {
                try await transport.create(name, contents: [1])
            }
            #expect(try Data(contentsOf: elsewhere.appendingPathComponent(url.lastPathComponent)) == Data([9]))
        }

        /// A1 plants a placeholder whose name is outside the layout, or one beside an object that is here: the first
        /// is not an object at all, and the second changes nothing about reading the object.
        @Test("planted placeholders are at most a withheld object")
        func plantedPlaceholders() async throws {
            let root = Self.root()
            let transport = CoordinatedFileSyncTransport(root: root)
            let name = SyncObjectLocation.segment(vaultID: UUID(), author: UUID(), sequence: 1).name
            try await transport.create(name, contents: [1, 2])
            let url = try transport.base.fileURL(for: name)
            try Data([0]).write(to: FileSyncTransport.placeholderURL(for: url))
            try Data([0]).write(to: url.deletingLastPathComponent().appendingPathComponent("..wwe.icloud"))
            try Data([0]).write(to: url.deletingLastPathComponent().appendingPathComponent(".a b.wwe.icloud"))
            let prefix = String(name.split(separator: "/").dropLast().joined(separator: "/")) + "/"
            #expect(try await transport.list(prefix: prefix) == [name])
            #expect(try await transport.fetch(name, maximumLength: 100) == [1, 2])
        }

        /// A1 makes an object's file larger than any object can be, behind the size check's back: still refused.
        @Test("an oversized object is refused under coordination too")
        func oversized() async throws {
            let transport = CoordinatedFileSyncTransport(root: Self.root())
            let name = SyncObjectLocation.segment(vaultID: UUID(), author: UUID(), sequence: 1).name
            try await transport.create(name, contents: [1])
            let handle = try FileHandle(forWritingTo: try transport.base.fileURL(for: name))
            try handle.truncate(atOffset: UInt64(4) << 30)
            try handle.close()
            await #expect(throws: SyncTransportError.objectTooLarge(name)) {
                try await transport.fetch(name, maximumLength: 64 << 20)
            }
        }
    }
#endif
