import Foundation
import Testing
import WatchwordKit
import WatchwordPlatform

/// The file adapter of the `DeviceLocalStore` port (docs/02-architecture.md §13.8), against the same expectations the
/// session has of `InMemoryDeviceLocalStore`. Portable: runs on Linux and on a Mac, where the backup flag is checked too.
@Suite("Device-local file store")
struct FileDeviceLocalStoreTests {
    static func temporaryDirectory() -> URL {
        URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("watchword-local-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("DeviceLocal", isDirectory: true)
    }

    @Test("records round-trip, are replaced whole, and absence reads as nothing")
    func roundTrip() async throws {
        let store = FileDeviceLocalStore(directory: Self.temporaryDirectory())
        let name = UUID()
        #expect(try await store.read(name) == nil)
        try await store.write([1, 2, 3], as: name)
        #expect(try await store.read(name) == [1, 2, 3])
        try await store.write([4], as: name)
        #expect(try await store.read(name) == [4])
        try await store.write([], as: name)
        #expect(try await store.read(name) == [])
    }

    @Test("delete removes the named records only, and tolerates absence")
    func deletion() async throws {
        let store = FileDeviceLocalStore(directory: Self.temporaryDirectory())
        let (a, b) = (UUID(), UUID())
        try await store.write([1], as: a)
        try await store.write([2], as: b)
        try await store.delete([a, UUID()])
        #expect(try await store.read(a) == nil)
        #expect(try await store.read(b) == [2])
    }

    @Test("deleteAll removes the directory and everything in it; the store works again afterwards")
    func deleteAll() async throws {
        let directory = Self.temporaryDirectory()
        let store = FileDeviceLocalStore(directory: directory)
        try await store.write([1], as: UUID())
        try Data([9]).write(to: directory.appendingPathComponent("stray.txt"))
        try await store.deleteAll()
        #expect(!FileManager.default.fileExists(atPath: directory.path))
        try await store.deleteAll()
        let name = UUID()
        try await store.write([5], as: name)
        #expect(try await store.read(name) == [5])
    }

    @Test("writes are atomic: nothing but the records is left in the directory")
    func atomic() async throws {
        let directory = Self.temporaryDirectory()
        let store = FileDeviceLocalStore(directory: directory)
        let names = (0..<8).map { _ in UUID() }
        for (index, name) in names.enumerated() {
            try await store.write(Array(repeating: UInt8(index), count: 4096), as: name)
        }
        let entries = Set(try FileManager.default.contentsOfDirectory(atPath: directory.path))
        #expect(entries == Set(names.map { $0.uuidString + ".wwl" }))
    }

    @Test("a record larger than the limit is neither written nor read")
    func limits() async throws {
        let store = FileDeviceLocalStore(directory: Self.temporaryDirectory(), maximumRecordLength: 16)
        let name = UUID()
        await #expect(throws: DeviceLocalFileError.recordTooLarge(name)) {
            try await store.write(Array(repeating: 1, count: 17), as: name)
        }
        try await store.write(Array(repeating: 1, count: 16), as: name)
        #expect(try await store.read(name)?.count == 16)
    }

    @Test("the directory is owner-only")
    func permissions() async throws {
        let directory = Self.temporaryDirectory()
        try await FileDeviceLocalStore(directory: directory).write([1], as: UUID())
        let mode = try FileManager.default.attributesOfItem(atPath: directory.path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o700)
    }

    @Test("an existing directory is made owner-only again before a write")
    func permissionsReasserted() async throws {
        let directory = Self.temporaryDirectory()
        let store = FileDeviceLocalStore(directory: directory)
        try await store.write([1], as: UUID())
        try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o755)], ofItemAtPath: directory.path)
        try await store.write([2], as: UUID())
        let mode = try FileManager.default.attributesOfItem(atPath: directory.path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o700)
    }

    @Test("a store below a container creates the whole path, and reads and writes there")
    func belowContainer() async throws {
        let container = Self.temporaryDirectory().deletingLastPathComponent()
        let store = FileDeviceLocalStore(ancestor: container, components: ["Library", "Watchword", "DeviceLocal"])
        let name = UUID()
        try await store.write([3], as: name)
        #expect(try await store.read(name) == [3])
        #expect(store.directory.lastPathComponent == "DeviceLocal")
        #expect(FileManager.default.fileExists(atPath: store.fileURL(for: name).path))
    }

    #if canImport(Darwin)
        @Test("the directory and every record are excluded from backup")
        func excludedFromBackup() async throws {
            let directory = Self.temporaryDirectory()
            let store = FileDeviceLocalStore(directory: directory)
            let name = UUID()
            try await store.write([1], as: name)
            try await store.write([2], as: name)
            for url in [directory, store.fileURL(for: name)] {
                let values = try url.resourceValues(forKeys: [.isExcludedFromBackupKey])
                #expect(values.isExcludedFromBackup == true, "\(url.lastPathComponent)")
            }
        }
    #endif

    #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        @Test("records are written with completeUntilFirstUserAuthentication protection")
        func protection() async throws {
            let store = FileDeviceLocalStore(directory: Self.temporaryDirectory())
            let name = UUID()
            try await store.write([1], as: name)
            let attributes = try FileManager.default.attributesOfItem(atPath: store.fileURL(for: name).path)
            #expect(attributes[.protectionKey] as? FileProtectionType == .completeUntilFirstUserAuthentication)
        }
    #endif

    #if canImport(Darwin)
        /// iOS gives no container without the entitlement; macOS names one regardless. Either way the store, when
        /// there is one, is beside the database and never in it.
        @Test("the App Group path puts the store beside the database")
        func containerPath() throws {
            let group = "group.invalid.watchword.tests"
            let database = AppContainer.databaseURL(appGroup: group)
            let local = AppContainer.deviceLocalStoreURL(appGroup: group)
            #expect((database == nil) == (local == nil))
            if let database, let local {
                #expect(local.deletingLastPathComponent() == database.deletingLastPathComponent())
                #expect(local.lastPathComponent == "DeviceLocal")
            }
        }
    #endif
}
