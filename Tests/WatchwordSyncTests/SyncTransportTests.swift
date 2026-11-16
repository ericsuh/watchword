import Foundation
import Testing

@testable import WatchwordSync

enum TransportKind: String, CaseIterable, CustomTestStringConvertible, Sendable {
    case inMemory
    case directory

    var testDescription: String { rawValue }

    func make() -> any SyncTransport {
        switch self {
        case .inMemory: return InMemorySyncTransport()
        case .directory: return FileSyncTransport(root: TransportFixtures.temporaryRoot())
        }
    }
}

enum TransportFixtures {
    static func temporaryRoot() -> URL {
        URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("watchword-sync-\(UUID().uuidString)", isDirectory: true)
    }

    static let name = SyncObjectLocation.segment(vaultID: SyncFixtures.vault, author: SyncFixtures.deviceA, sequence: 1)
        .name
    static let prefix = SyncObjectLocation.vaultPrefix(SyncFixtures.vault)
}

/// One contract, every transport (docs/02-architecture.md §7): immutable objects in a flat namespace.
@Suite("Sync transport contract")
struct SyncTransportContractTests {
    @Test("objects round-trip and are listed by prefix", arguments: TransportKind.allCases)
    func roundTrip(_ kind: TransportKind) async throws {
        let transport = kind.make()
        #expect(try await transport.list(prefix: TransportFixtures.prefix).isEmpty)
        #expect(try await transport.fetch(TransportFixtures.name, maximumLength: 100) == nil)
        try await transport.create(TransportFixtures.name, contents: [1, 2, 3])
        let other = SyncObjectLocation.snapshot(
            vaultID: SyncFixtures.otherVault, author: SyncFixtures.deviceB, lamport: 9)
        try await transport.create(other.name, contents: [4])
        #expect(try await transport.list(prefix: TransportFixtures.prefix) == [TransportFixtures.name])
        #expect(try await transport.list(prefix: "vault/").count == 2)
        #expect(try await transport.fetch(TransportFixtures.name, maximumLength: 100) == [1, 2, 3])
    }

    @Test("an object is written once and never overwritten", arguments: TransportKind.allCases)
    func immutable(_ kind: TransportKind) async throws {
        let transport = kind.make()
        try await transport.create(TransportFixtures.name, contents: [1])
        await #expect(throws: SyncTransportError.objectExists(TransportFixtures.name)) {
            try await transport.create(TransportFixtures.name, contents: [2])
        }
        #expect(try await transport.fetch(TransportFixtures.name, maximumLength: 100) == [1])
    }

    @Test("an object larger than the reader's limit is refused", arguments: TransportKind.allCases)
    func sizeLimit(_ kind: TransportKind) async throws {
        let transport = kind.make()
        try await transport.create(TransportFixtures.name, contents: Array(repeating: 7, count: 101))
        await #expect(throws: SyncTransportError.objectTooLarge(TransportFixtures.name)) {
            try await transport.fetch(TransportFixtures.name, maximumLength: 100)
        }
    }

    @Test("deletion removes one object and tolerates absence", arguments: TransportKind.allCases)
    func deletion(_ kind: TransportKind) async throws {
        let transport = kind.make()
        try await transport.create(TransportFixtures.name, contents: [1])
        try await transport.delete(TransportFixtures.name)
        try await transport.delete(TransportFixtures.name)
        #expect(try await transport.list(prefix: TransportFixtures.prefix).isEmpty)
    }
}

@Suite("File sync transport")
struct FileSyncTransportTests {
    @Test("objects are files with the .wwe extension under the layout of §7.3; temporaries are not listed")
    func layout() async throws {
        let root = TransportFixtures.temporaryRoot()
        let transport = FileSyncTransport(root: root)
        try await transport.create(TransportFixtures.name, contents: [1])
        let path = root.appendingPathComponent(TransportFixtures.name + ".wwe").path
        #expect(FileManager.default.fileExists(atPath: path))
        let directory = root.appendingPathComponent(TransportFixtures.name).deletingLastPathComponent()
        try Data([9]).write(to: directory.appendingPathComponent(".tmp-leftover"))
        try Data([9]).write(to: directory.appendingPathComponent("notes.txt"))
        #expect(try await transport.list(prefix: TransportFixtures.prefix) == [TransportFixtures.name])
    }

    @Test(
        "names outside the layout's alphabet are refused",
        arguments: ["", "../x", "vault/../../etc/passwd", "vault/.hidden", "vault/a b", "vault//x", "vault/x/"])
    func invalidNames(_ name: String) async {
        let transport = FileSyncTransport(root: TransportFixtures.temporaryRoot())
        await #expect(throws: SyncTransportError.invalidName(name)) {
            try await transport.create(name, contents: [1])
        }
    }
}

@Suite("File sync transport: iCloud placeholders")
struct FileSyncTransportPlaceholderTests {
    static func placeholder(for name: String, in root: URL) throws -> URL {
        let url = try FileSyncTransport(root: root).fileURL(for: name)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        return FileSyncTransport.placeholderURL(for: url)
    }

    @Test("a placeholder is listed as its object only when asked, and fetching it finds no file yet")
    func placeholderListed() async throws {
        let root = TransportFixtures.temporaryRoot()
        try Data([1]).write(to: try Self.placeholder(for: TransportFixtures.name, in: root))
        #expect(try await FileSyncTransport(root: root).list(prefix: TransportFixtures.prefix).isEmpty)
        let ubiquitous = FileSyncTransport(root: root, listsUbiquityPlaceholders: true)
        #expect(try await ubiquitous.list(prefix: TransportFixtures.prefix) == [TransportFixtures.name])
        #expect(try await ubiquitous.fetch(TransportFixtures.name, maximumLength: 100) == nil)
    }

    @Test("a placeholder beside its downloaded file is one object")
    func placeholderAndFile() async throws {
        let root = TransportFixtures.temporaryRoot()
        let ubiquitous = FileSyncTransport(root: root, listsUbiquityPlaceholders: true)
        try await ubiquitous.create(TransportFixtures.name, contents: [1])
        try Data([1]).write(to: try Self.placeholder(for: TransportFixtures.name, in: root))
        #expect(try await ubiquitous.list(prefix: TransportFixtures.prefix) == [TransportFixtures.name])
    }

    @Test(
        "placeholder names outside the layout are not objects",
        arguments: [".x y.wwe.icloud", "..wwe.icloud", ".a.wwe.icloud.icloud", "x.wwe.icloud", ".a.wwe", ".a.icloud"])
    func strangePlaceholders(_ entry: String) {
        #expect(FileSyncTransport.placeholderStem(entry) == nil)
    }

    @Test("the placeholder of an object is the dot-file iCloud Drive keeps beside it")
    func placeholderName() {
        #expect(FileSyncTransport.placeholderStem(".7.wwe.icloud") == "7")
        let url = URL(fileURLWithPath: "/r/vault/v/log/d/7.wwe")
        #expect(FileSyncTransport.placeholderURL(for: url).lastPathComponent == ".7.wwe.icloud")
    }
}
