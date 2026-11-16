import Foundation
import Testing
import WatchwordKit
import WatchwordPlatform

/// The device-local file store against someone who can write its directory (docs/02-architecture.md §13.8).
///
/// Threat model: **A8, local malware running as the user while the app is locked** (or a tampered backup restored
/// onto the device), with read and write access to the App Group container but not to the Keychain or the password.
/// They can plant files, links and directories under any record's name, replace the store's directory with a link, and
/// make files of any size. They must not make the adapter read or write outside its directory, read an unbounded
/// file, or read a planted object as a record; and erasing the account must remove everything without touching what a
/// planted link points to. What the adapter does return is only bytes, which the session opens under the device-local
/// key or ignores ("hygiene in the vault session").
@Suite("Adversarial: device-local store files", .tags(.adversarial))
struct AdversarialDeviceLocalStoreTests {
    static func fixture() throws -> (store: FileDeviceLocalStore, directory: URL, outside: URL) {
        let base = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("watchword-adversarial-local-\(UUID().uuidString)", isDirectory: true)
        let directory = base.appendingPathComponent("DeviceLocal", isDirectory: true)
        let outside = base.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        return (FileDeviceLocalStore(directory: directory), directory, outside)
    }

    /// A8 links a record's name to a file elsewhere (say, another app's data or the Keychain's database path): the
    /// read must not follow it, and a write must replace the link rather than the target.
    @Test("a link planted under a record's name is never followed, for reading or writing")
    func plantedLink() async throws {
        let (store, _, outside) = try Self.fixture()
        try await store.write([0], as: UUID())  // creates the directory
        let target = outside.appendingPathComponent("secret")
        try Data([7, 7, 7]).write(to: target)
        let name = UUID()
        try FileManager.default.createSymbolicLink(at: store.fileURL(for: name), withDestinationURL: target)

        await #expect(throws: DeviceLocalFileError.notARegularFile(name)) { try await store.read(name) }
        try await store.write([1], as: name)
        #expect(try Data(contentsOf: target) == Data([7, 7, 7]))
        #expect(try await store.read(name) == [1])
    }

    /// A8 replaces the whole store directory with a link to a folder of their choosing: every read and write is
    /// refused, and erasing the account removes the link and leaves the folder it pointed to alone.
    @Test("a store directory replaced by a link is refused, and deleteAll removes only the link")
    func directoryReplaced() async throws {
        let (store, directory, outside) = try Self.fixture()
        let planted = outside.appendingPathComponent(store.fileURL(for: UUID()).lastPathComponent)
        try Data([9]).write(to: planted)
        try FileManager.default.createDirectory(
            at: directory.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: directory, withDestinationURL: outside)

        let name = UUID()
        await #expect(throws: DeviceLocalFileError.directoryReplaced) { try await store.read(name) }
        await #expect(throws: DeviceLocalFileError.directoryReplaced) { try await store.write([1], as: name) }
        try await store.delete([name])
        try await store.deleteAll()
        #expect(FileManager.default.fileExists(atPath: planted.path))
        #expect((try? FileManager.default.attributesOfItem(atPath: directory.path)) == nil)
    }

    /// A8 plants a huge file under a record's name to exhaust memory when the session reads its ledger: refused from
    /// its size, before any byte is read. The file is sparse, so the test costs nothing.
    @Test("an oversized planted record is refused before it is read")
    func oversized() async throws {
        let (store, _, _) = try Self.fixture()
        let name = UUID()
        try await store.write([1], as: name)
        let handle = try FileHandle(forWritingTo: store.fileURL(for: name))
        try handle.truncate(atOffset: UInt64(8) << 30)
        try handle.close()
        await #expect(throws: DeviceLocalFileError.recordTooLarge(name)) { try await store.read(name) }
    }

    /// A8 plants a directory (or anything but a regular file) under a record's name: not a record, and a write there
    /// fails rather than writing somewhere else.
    @Test("a directory planted under a record's name is not a record")
    func plantedDirectory() async throws {
        let (store, _, _) = try Self.fixture()
        let name = UUID()
        try await store.write([1], as: UUID())
        try FileManager.default.createDirectory(at: store.fileURL(for: name), withIntermediateDirectories: false)
        await #expect(throws: DeviceLocalFileError.notARegularFile(name)) { try await store.read(name) }
        await #expect(throws: DeviceLocalFileError.notARegularFile(name)) { try await store.write([1], as: name) }
        try await store.delete([name])
        #expect(try await store.read(name) == nil)
    }

    /// A8 fills the directory with files of other names (temporaries, look-alike names, hidden files): none is ever
    /// read as a record, and erasing the account removes them all.
    @Test("files of other names are never records, and erasing the account removes them")
    func strayFiles() async throws {
        let (store, directory, _) = try Self.fixture()
        let name = UUID()
        try await store.write([1], as: name)
        for stray in [
            name.uuidString.lowercased() + ".wwl", name.uuidString, "." + name.uuidString + ".wwl",
            name.uuidString + ".wwl.tmp",
        ] {
            try Data([6]).write(to: directory.appendingPathComponent(stray))
        }
        #expect(try await store.read(name) == [1])
        try await store.deleteAll()
        #expect(!FileManager.default.fileExists(atPath: directory.path))
    }

    /// The session's own reading of whatever the adapter returns: a planted record under the ledger's name, or one
    /// truncated by A8, opens as nothing because it does not open under this device's key (the contract the session
    /// relies on, `VaultSession.openLocal`). Here, the adapter hands back exactly what is on disk and nothing more.
    @Test("a damaged record reads back as exactly the bytes on disk, for the session to refuse")
    func damaged() async throws {
        let (store, _, _) = try Self.fixture()
        let name = UUID()
        try await store.write(Array(repeating: 0xAB, count: 64), as: name)
        let handle = try FileHandle(forWritingTo: store.fileURL(for: name))
        try handle.truncate(atOffset: 10)
        try handle.close()
        #expect(try await store.read(name) == Array(repeating: 0xAB, count: 10))
    }
}
