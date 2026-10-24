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
