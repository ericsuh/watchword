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
    /// conflict versions and renamed copies) must not open a way around them: a planted link is never followed, a planted placeholder is at
    /// most a withheld object (which A1 could always do), and nothing is ever written over an existing object. Runs on a
    /// Mac only; required there through its `darwin:` line in `adversarial-suites.txt`.
    @Suite("Adversarial: Apple adapters: iCloud Drive transport", .serialized, .tags(.adversarial))
    struct AdversarialCoordinatedFileSyncTransportTests {
        /// A transport whose coordination deadline is never reached in a test: a loaded runner may take its time to
        /// schedule these tasks, and that must decide nothing here (the deadline has a test of its own).
        static func transport(_ root: URL) -> CoordinatedFileSyncTransport {
            CoordinatedFileSyncTransport(root: root) { try? await Task.sleep(for: .seconds(86_400)) }
        }

        static func root() -> URL {
            URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
                .appendingPathComponent("watchword-adversarial-coordinated-\(UUID().uuidString)", isDirectory: true)
        }

        /// A1 replaces a stream's directory with a link to somewhere else on the device: nothing is listed through it,
        /// fetching through it is refused, and nothing is written through it.
        @Test("a directory replaced by a link is neither listed, read nor written through")
        func linkedDirectory() async throws {
            let root = Self.root()
            let transport = Self.transport(root)
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
            let transport = Self.transport(root)
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
            let transport = Self.transport(Self.root())
            let name = SyncObjectLocation.segment(vaultID: UUID(), author: UUID(), sequence: 1).name
            try await transport.create(name, contents: [1])
            let handle = try FileHandle(forWritingTo: try transport.base.fileURL(for: name))
            // Twice the reader's limit is enough, and stays cheap where a file system does not keep it sparse.
            try handle.truncate(atOffset: UInt64(128) << 20)
            try handle.close()
            await #expect(throws: SyncTransportError.objectTooLarge(name)) {
                try await transport.fetch(name, maximumLength: 64 << 20)
            }
        }

        /// A1 plants renamed copies beside an object (docs/02-architecture.md §7.5) and makes some of them traps: a
        /// link to a file elsewhere on the device, a directory, a file over any object's size, and names that only
        /// look like a copy's. The copies that are regular files within the limit are handed over as bytes for the
        /// engine to check; the link is never followed or deleted through, the oversized file is never read, and none
        /// of it stops the object being read. (iCloud's own conflict versions need a ubiquity container and are not
        /// exercised here.)
        @Test("planted renamed copies are handed over as bytes; links and oversized ones are counted, never read")
        func plantedRenamedCopies() async throws {
            let transport = Self.transport(Self.root())
            let name = SyncObjectLocation.segment(vaultID: UUID(), author: UUID(), sequence: 1).name
            try await transport.create(name, contents: [1, 2])
            let url = try transport.base.fileURL(for: name)
            let stem = url.deletingPathExtension().lastPathComponent
            func copy(_ suffix: String) -> URL {
                url.deletingLastPathComponent().appendingPathComponent(stem + suffix + ".wwe")
            }
            let elsewhere = Self.root()
            try FileManager.default.createDirectory(at: elsewhere, withIntermediateDirectories: true)
            let secret = elsewhere.appendingPathComponent("secret")
            try Data([7, 7, 7]).write(to: secret)
            try FileManager.default.createSymbolicLink(at: copy(" 2"), withDestinationURL: secret)
            try FileManager.default.createDirectory(at: copy(" 3"), withIntermediateDirectories: true)
            try Data([4]).write(to: copy(" 4"))
            FileManager.default.createFile(atPath: copy(" 5").path, contents: nil)
            let handle = try FileHandle(forWritingTo: copy(" 5"))
            try handle.truncate(atOffset: 200)
            try handle.close()
            for inexact in [" 1", " 02", " 65", "  2", " 2 3"] { try Data([9]).write(to: copy(inexact)) }

            let prefix = String(name.split(separator: "/").dropLast().joined(separator: "/")) + "/"
            let listing = try await transport.listWithCopies(prefix: prefix)
            #expect(listing == SyncListing(names: [name], copied: [name: 3]))
            #expect(
                try await transport.fetchCopies(name, maximumLength: 100, maximumCopies: 8)
                    == SyncObjectCopies(copies: [[1, 2], [4]], omitted: 3))
            #expect(try await transport.fetch(name, maximumLength: 100) == [1, 2])
            try await transport.delete(name)
            #expect(try Data(contentsOf: secret) == Data([7, 7, 7]))
            #expect(FileManager.default.fileExists(atPath: copy(" 1").path), "not a copy: not this object's")
        }
    }
#endif
