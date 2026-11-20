import Foundation
import Testing
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// Several copies under one object name (docs/02-architecture.md §7.5, "Conflict copies"): what the transports hand
/// over, and what the engine makes of them.
@Suite("Conflict copies: transports")
struct ConflictCopyTransportTests {
    static func duplicate(_ name: String, _ number: Int, in transport: FileSyncTransport) throws -> URL {
        let url = try transport.fileURL(for: name)
        let stem = String(url.lastPathComponent.dropLast(4))
        return url.deletingLastPathComponent().appendingPathComponent("\(stem) \(number).wwe")
    }

    @Test("a transport that holds one copy per name says so", arguments: TransportKind.allCases)
    func singleCopies(_ kind: TransportKind) async throws {
        #expect(try await SyncTransportContract.singleCopies(kind.make()) == [])
    }

    @Test("the in-memory transport hands over every copy, bounded, and deletes them with the object")
    func inMemory() async throws {
        let transport = InMemorySyncTransport()
        let found = try await SyncTransportContract.heldCopies(transport) { name, bytes in
            await transport.plantCopy(name, contents: bytes)
        }
        #expect(found == [])
    }

    @Test("the directory transport attributes a provider's renamed duplicates to their object")
    func directory() async throws {
        let transport = FileSyncTransport(root: TransportFixtures.temporaryRoot())
        var next = 2
        let found = try await SyncTransportContract.heldCopies(transport) { name, bytes in
            try Data(bytes).write(to: try Self.duplicate(name, next, in: transport))
            next += 1
        }
        #expect(found == [])
    }

    @Test("the simulated server hands over planted copies")
    func simulated() async throws {
        let server = SimulatedServer(seed: 1, maximumVisibilityDelay: 0, duplicateListings: false)
        let transport = await server.transport(for: SyncFixtures.deviceA)
        let found = try await SyncTransportContract.heldCopies(transport) { name, bytes in
            await server.plantCopy(name, contents: bytes)
        }
        #expect(found == [])
    }

    @Test(
        "only an exact `<name> <n>` from 2 to 64 is a duplicate; anything else is not an object at all",
        arguments: ["N 1", "N 02", "N 65", "N  2", "N 2 3", "N -2", "N 2x", " 2", "N\u{301} 2", "N 2\u{301}"])
    func inexactDuplicates(_ pattern: String) async throws {
        let transport = FileSyncTransport(root: TransportFixtures.temporaryRoot())
        let name = TransportFixtures.name
        try await transport.create(name, contents: [1])
        let url = try transport.fileURL(for: name)
        let stem = String(url.lastPathComponent.dropLast(4))
        let planted = url.deletingLastPathComponent().appendingPathComponent(
            pattern.replacingOccurrences(of: "N", with: stem) + ".wwe")
        try Data([9]).write(to: planted)
        let listing = try await transport.listWithCopies(prefix: TransportFixtures.prefix)
        #expect(listing == SyncListing(names: [name]))
        #expect(
            try await transport.fetchCopies(name, maximumLength: 100, maximumCopies: 8)
                == SyncObjectCopies(copies: [[1]]))
        try await transport.delete(name)
        #expect(FileManager.default.fileExists(atPath: planted.path), "not this object's to delete")
    }

    @Test("a renamed duplicate whose object is gone is still listed under the object's name")
    func duplicateAlone() async throws {
        let transport = FileSyncTransport(root: TransportFixtures.temporaryRoot())
        let name = TransportFixtures.name
        try await transport.create(name, contents: [1])
        try Data([2]).write(to: try Self.duplicate(name, 2, in: transport))
        try FileManager.default.removeItem(at: try transport.fileURL(for: name))
        #expect(
            try await transport.listWithCopies(prefix: TransportFixtures.prefix)
                == SyncListing(names: [name], copied: [name: 1]))
        #expect(try await transport.fetch(name, maximumLength: 100) == nil)
        #expect(
            try await transport.fetchCopies(name, maximumLength: 100, maximumCopies: 8)
                == SyncObjectCopies(copies: [[2]]))
        try await transport.delete(name)
        #expect(try await transport.list(prefix: TransportFixtures.prefix).isEmpty)
    }

    /// Review finding R18: iCloud's legacy placeholder of a renamed duplicate (`.<stem> 2.wwe.icloud`) has a space in
    /// its stem, so it was neither an object nor a duplicate: nothing listed or counted it, the download was never
    /// asked for, and the author collected the name with a copy nobody had read.
    @Test("a renamed duplicate known only by its iCloud placeholder is counted, and read as unread, never as absent")
    func duplicatePlaceholder() async throws {
        let root = TransportFixtures.temporaryRoot()
        let plain = FileSyncTransport(root: root)
        let ubiquitous = FileSyncTransport(root: root, listsUbiquityPlaceholders: true)
        let name = TransportFixtures.name
        try await ubiquitous.create(name, contents: [1])
        let duplicate = try Self.duplicate(name, 2, in: ubiquitous)
        try Data([2]).write(to: FileSyncTransport.placeholderURL(for: duplicate))
        #expect(
            try await ubiquitous.listWithCopies(prefix: TransportFixtures.prefix)
                == SyncListing(names: [name], copied: [name: 2]))
        #expect(
            try await ubiquitous.fetchCopies(name, maximumLength: 100, maximumCopies: 8)
                == SyncObjectCopies(copies: [[1]], unread: 1))
        // Without placeholders listed (not iCloud Drive), a dot-file is nothing.
        #expect(try await plain.listWithCopies(prefix: TransportFixtures.prefix) == SyncListing(names: [name]))

        // Downloaded, with its placeholder still there for a moment: one copy, read.
        try Data([2]).write(to: duplicate)
        #expect(
            try await ubiquitous.listWithCopies(prefix: TransportFixtures.prefix)
                == SyncListing(names: [name], copied: [name: 2]))
        #expect(
            try await ubiquitous.fetchCopies(name, maximumLength: 100, maximumCopies: 8)
                == SyncObjectCopies(copies: [[1], [2]]))
    }

    @Test("a name left with only a duplicate's placeholder is still listed, and its copy is unread")
    func duplicatePlaceholderAlone() async throws {
        let root = TransportFixtures.temporaryRoot()
        let ubiquitous = FileSyncTransport(root: root, listsUbiquityPlaceholders: true)
        let name = TransportFixtures.name
        try await ubiquitous.create(name, contents: [1])
        try Data([2]).write(to: FileSyncTransport.placeholderURL(for: try Self.duplicate(name, 3, in: ubiquitous)))
        try FileManager.default.removeItem(at: try ubiquitous.fileURL(for: name))
        #expect(
            try await ubiquitous.listWithCopies(prefix: TransportFixtures.prefix)
                == SyncListing(names: [name], copied: [name: 1]))
        #expect(
            try await ubiquitous.fetchCopies(name, maximumLength: 100, maximumCopies: 8)
                == SyncObjectCopies(unread: 1))
    }

    @Test(
        "only an exact duplicate's placeholder counts",
        arguments: ["N 1", "N 02", "N 65", "N  2", "N 2x", " 2", "N 2\u{301}"])
    func inexactDuplicatePlaceholders(_ pattern: String) async throws {
        let root = TransportFixtures.temporaryRoot()
        let ubiquitous = FileSyncTransport(root: root, listsUbiquityPlaceholders: true)
        let name = TransportFixtures.name
        try await ubiquitous.create(name, contents: [1])
        let url = try ubiquitous.fileURL(for: name)
        let stem = String(url.lastPathComponent.dropLast(4))
        let entry = "." + pattern.replacingOccurrences(of: "N", with: stem) + ".wwe.icloud"
        try Data([9]).write(to: url.deletingLastPathComponent().appendingPathComponent(entry))
        #expect(try await ubiquitous.listWithCopies(prefix: TransportFixtures.prefix) == SyncListing(names: [name]))
    }

    @Test("a link or a directory under a duplicate's name is counted, never followed, and hides nothing after it")
    func plantedLinkAsDuplicate() async throws {
        let transport = FileSyncTransport(root: TransportFixtures.temporaryRoot())
        let name = TransportFixtures.name
        try await transport.create(name, contents: [1])
        let elsewhere = TransportFixtures.temporaryRoot()
        try FileManager.default.createDirectory(at: elsewhere, withIntermediateDirectories: true)
        let secret = elsewhere.appendingPathComponent("secret")
        try Data([7, 7, 7]).write(to: secret)
        try FileManager.default.createSymbolicLink(
            at: try Self.duplicate(name, 2, in: transport), withDestinationURL: secret)
        try FileManager.default.createDirectory(
            at: try Self.duplicate(name, 3, in: transport), withIntermediateDirectories: true)
        try Data([4]).write(to: try Self.duplicate(name, 4, in: transport))
        let listing = try await transport.listWithCopies(prefix: TransportFixtures.prefix)
        #expect(listing == SyncListing(names: [name], copied: [name: 2]), "only the regular file counts")
        #expect(
            try await transport.fetchCopies(name, maximumLength: 100, maximumCopies: 8)
                == SyncObjectCopies(copies: [[1], [4]], omitted: 2))
        try await transport.delete(name)
        #expect(try Data(contentsOf: secret) == Data([7, 7, 7]), "nothing was deleted through the link")
    }
}

@Suite("Conflict copies: what is staged and remembered")
struct ConflictCopyStateTests {
    static let location = SyncObjectLocation.segment(
        vaultID: SyncFixtures.vault, author: SyncFixtures.deviceA, sequence: 3)

    static func object(_ n: UInt8) -> SignedObject {
        SignedObject(signature: Array(repeating: n, count: 64), envelope: Array(repeating: n, count: 40 + Int(n)))
    }

    @Test("a staged object with one copy is stored as it always was; several copies round-trip")
    func storage() throws {
        let single = StagedObject(location: Self.location, object: Self.object(1))
        #expect(single.storageBytes == Self.object(1).serialized())
        #expect(StagedObject(location: Self.location, storageBytes: single.storageBytes) == single)
        let several = StagedObject(
            location: Self.location, object: Self.object(1), alternates: [Self.object(2), Self.object(3)], copies: 5)
        #expect(StagedObject(location: Self.location, storageBytes: several.storageBytes) == several)
        let counted = StagedObject(location: Self.location, object: Self.object(1), copies: 2)
        #expect(StagedObject(location: Self.location, storageBytes: counted.storageBytes) == counted)
    }

    @Test("a staged row that is not exactly one this version writes is not an object")
    func hostileStorage() throws {
        let good = StagedObject(
            location: Self.location, object: Self.object(1), alternates: [Self.object(2)], copies: 2
        ).storageBytes
        #expect(StagedObject(location: Self.location, storageBytes: good + [0]) == nil, "trailing bytes")
        #expect(StagedObject(location: Self.location, storageBytes: Array(good.dropLast())) == nil, "truncated")
        var version = good
        version[4] = 2
        #expect(StagedObject(location: Self.location, storageBytes: version) == nil)
        var none = good
        none[9] = 0
        #expect(StagedObject(location: Self.location, storageBytes: none) == nil, "no copies")
        var many = good
        many[9] = 200
        #expect(StagedObject(location: Self.location, storageBytes: many) == nil, "more copies than bytes")
        var long = good
        long[10...13] = [0xFF, 0xFF, 0xFF, 0xFF]
        #expect(StagedObject(location: Self.location, storageBytes: long) == nil, "a length past the end")
        #expect(StagedObject(location: Self.location, storageBytes: Array("WWSC".utf8)) == nil)
        #expect(StagedObject(location: Self.location, storageBytes: []) == nil)
    }

    @Test(
        "the state remembers examined and unread copies, their turns and an owed hand-on across encoding; an older row has none"
    )
    func encoding() throws {
        var state = SyncState(vaultID: SyncFixtures.vault)
        state.examinedCopies[Self.location] = 3
        state.unreadCopies[Self.location] = 4
        state.unreadCopiesExamined[Self.location] = 9
        state.handOnOwed = true
        let data = try JSONEncoder().encode(EncodedState(state))
        #expect(try JSONDecoder().decode(EncodedState.self, from: data).state == state)
        var older = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        older["examinedCopies"] = nil
        older["unreadCopies"] = nil
        older["unreadCopiesExamined"] = nil
        older["handOnOwed"] = nil
        let decoded = try JSONDecoder().decode(
            EncodedState.self, from: try JSONSerialization.data(withJSONObject: older))
        #expect(decoded.state?.examinedCopies == [:] && decoded.state?.unreadCopies == [:])
        #expect(decoded.state?.unreadCopiesExamined == [:])
        #expect(decoded.state?.handOnOwed == false)
        for field in ["examinedCopies", "unreadCopies", "unreadCopiesExamined"] {
            var bad = older
            bad[field] = ["not a name": 2]
            #expect(
                try JSONDecoder().decode(EncodedState.self, from: try JSONSerialization.data(withJSONObject: bad))
                    .state == nil)
        }
    }
}

@Suite("Conflict copies: the engine")
struct ConflictCopyEngineTests {
    struct Fork {
        let home: Household
        let transport: InMemorySyncTransport
        /// The device whose stream forks, and a second installation of it (same ID and keys, its own store and
        /// state, writing to a transport nobody else reads): a backup restored before its sync caught up.
        let author: SyncTestClient
        let restored: SyncTestClient
        let restoredTransport: InMemorySyncTransport
        let reader: SyncTestClient

        static func make(configuration: SyncConfiguration = SyncTestClient.configuration) async -> Fork {
            let transport = InMemorySyncTransport()
            let home = await Household.make(2, transport: transport, configuration: configuration)
            let restoredTransport = InMemorySyncTransport()
            let restored = SyncTestClient(
                deviceID: SyncFixtures.deviceA, vaultID: Household.vault, keys: home.keys,
                transport: restoredTransport, configuration: configuration)
            return Fork(
                home: home, transport: transport, author: home.devices[0], restored: restored,
                restoredTransport: restoredTransport, reader: home.devices[1])
        }

        var name: String {
            SyncObjectLocation.segment(vaultID: Household.vault, author: SyncFixtures.deviceA, sequence: 1).name
        }

        /// The restored installation's first segment, put beside the author's under the same name.
        func plantRestoredCopy() async throws {
            let bytes = try #require(await restoredTransport.allObjects[name])
            await transport.plantCopy(name, contents: bytes)
        }
    }

    static func values(_ item: Item) -> Set<String> {
        var present = Set(item.fields.map(\.value))
        for conflict in Array(item.conflicts.values.joined()) + item.retainedValues {
            if case .field(let field?) = conflict.value { present.insert(field.value) }
        }
        return present
    }

    @Test("junk beside an object costs one check, changes nothing, and is not read again")
    func junkBeside() async throws {
        let fork = await Fork.make()
        let saved = try await fork.author.save(Household.login())
        try await fork.author.sync()
        await fork.transport.plantCopy(fork.name, contents: [1, 2, 3])
        await fork.transport.plantCopy(fork.name, contents: Array(repeating: 0xAB, count: 300))
        let report = try await fork.reader.sync()
        #expect(report.applied == 1 && report.rejected.isEmpty && report.waiting.isEmpty)
        #expect(report.copiesExamined == 3 && report.copiesRefused == 2 && report.forkedObjects.isEmpty)
        #expect(try await fork.reader.item(saved.id) == saved)
        let again = try await fork.reader.sync()
        #expect(again.copiesExamined == 0 && again.fetched == 0, "remembered: \(again)")
        // A further copy changes the count, and the name is looked at once more.
        await fork.transport.plantCopy(fork.name, contents: [4])
        let third = try await fork.reader.sync()
        #expect(third.copiesExamined == 4 && third.copiesRefused == 3 && third.applied == 0)
        #expect(try await fork.reader.sync().copiesExamined == 0)
    }

    @Test("the genuine object is found behind a junk current file")
    func hiddenBehindJunk() async throws {
        let fork = await Fork.make()
        let saved = try await fork.author.save(Household.login())
        try await fork.author.sync()
        let genuine = try #require(await fork.transport.allObjects[fork.name])
        await fork.transport.tamper(fork.name, contents: [0xDE, 0xAD])
        await fork.transport.plantCopy(fork.name, contents: genuine)
        let report = try await fork.reader.sync()
        #expect(report.applied == 1 && report.rejected.isEmpty && report.copiesRefused == 1)
        #expect(try await fork.reader.item(saved.id) == saved)
    }

    @Test("a name none of whose copies verifies is refused alone: other streams merge and this device publishes")
    func noneVerifies() async throws {
        let transport = InMemorySyncTransport()
        let home = await Household.make(3, transport: transport)
        let (a, b, c) = (home.devices[0], home.devices[1], home.devices[2])
        try await a.save(Household.login(title: "From A"))
        try await a.sync()
        let other = try await c.save(Household.login(title: "From C"))
        try await c.sync()
        let name = SyncObjectLocation.segment(vaultID: Household.vault, author: SyncFixtures.deviceA, sequence: 1).name
        await transport.tamper(name, contents: [9, 9])
        await transport.plantCopy(name, contents: [8, 8, 8])
        let mine = try await b.save(Household.login(title: "From B"))
        let report = try await b.sync()
        #expect(report.rejected.map(\.name) == [name])
        #expect(report.waiting == [SyncFixtures.deviceA: 1])
        #expect(!report.transportUnavailable && report.transportFailure == nil)
        #expect(report.segmentsWritten == 1, "still publishes")
        #expect(try await b.items().keys.sorted { $0.precedes($1) } == [other.id, mine.id].sorted { $0.precedes($1) })
    }

    @Test("two copies that both verify are both merged: every item of each, and both values of one edited in both")
    func twoForks() async throws {
        let fork = await Fork.make()
        let shared = UUID()
        try await fork.author.save(Household.login(shared, password: "written-before-the-backup"))
        let first = try await fork.author.save(Household.login(title: "Only in the first"))
        try await fork.author.sync()
        try await fork.restored.save(Household.login(shared, password: "written-after-the-restore"))
        let second = try await fork.restored.save(Household.login(title: "Only in the second"))
        try await fork.restored.sync()
        try await fork.plantRestoredCopy()

        let report = try await fork.reader.sync()
        #expect(report.rejected.isEmpty && report.waiting.isEmpty)
        #expect(report.forkedObjects == [fork.name])
        #expect(report.copiesExamined == 2 && report.copiesRefused == 0)
        let items = try await fork.reader.items()
        #expect(items[first.id] != nil && items[second.id] != nil)
        let item = try #require(items[shared])
        #expect(
            Self.values(item).isSuperset(of: ["written-before-the-backup", "written-after-the-restore"]),
            "one revision, two writes: both kept (docs/10-sync-correctness.md §8)")
        #expect(await fork.reader.state()?.merged[SyncFixtures.deviceA] == 1)
        #expect(try await fork.reader.sync().copiesExamined == 0)
    }

    @Test("the copies of a fork merge to the same items in either order")
    func orderOfCopies() async throws {
        var seen: [[UUID: Item]] = []
        for swapped in [false, true] {
            let fork = await Fork.make()
            let shared = UUID(uuidString: "5A5A5A5A-0000-4000-8000-000000000001")!
            try await fork.author.save(Household.login(shared, password: "one"))
            try await fork.author.sync()
            try await fork.restored.save(Household.login(shared, password: "two"))
            try await fork.restored.sync()
            if swapped {
                let original = try #require(await fork.transport.allObjects[fork.name])
                let other = try #require(await fork.restoredTransport.allObjects[fork.name])
                await fork.transport.tamper(fork.name, contents: other)
                await fork.transport.plantCopy(fork.name, contents: original)
            } else {
                try await fork.plantRestoredCopy()
            }
            try await fork.reader.sync()
            seen.append(try await fork.reader.items().mapValues(MergeFixtures.current))
        }
        #expect(seen[0] == seen[1])
    }

    @Test("a copy that appears after the position was merged is applied late, and the stream stays where it was")
    func lateCopy() async throws {
        let fork = await Fork.make()
        try await fork.author.save(Household.login(title: "First"))
        try await fork.author.sync()
        try await fork.reader.sync()
        let later = try await fork.author.save(Household.login(title: "Later"))
        try await fork.author.sync()
        try await fork.reader.sync()
        let second = try await fork.restored.save(Household.login(title: "Only in the second copy"))
        try await fork.restored.sync()
        try await fork.plantRestoredCopy()

        let report = try await fork.reader.sync()
        #expect(report.applied == 1 && report.rejected.isEmpty && report.forkedObjects == [fork.name])
        #expect(try await fork.reader.items()[second.id] != nil)
        #expect(try await fork.reader.items()[later.id] != nil)
        #expect(await fork.reader.state()?.merged[SyncFixtures.deviceA] == 2)
        let again = try await fork.reader.sync()
        #expect(again.copiesExamined == 0 && again.applied == 0)
    }

    @Test("a device whose own stream forked hands both copies on in a snapshot, and collects nothing before")
    func authorHandsOn() async throws {
        let fork = await Fork.make()
        try await fork.author.save(Household.login(title: "First"))
        try await fork.author.sync()
        let second = try await fork.restored.save(Household.login(title: "Only in the second copy"))
        try await fork.restored.sync()
        try await fork.plantRestoredCopy()

        let report = try await fork.author.sync()
        #expect(report.forkedObjects == [fork.name] && report.snapshotsWritten == 1)
        #expect(report.collected == 0 && !report.handOnOwed)
        #expect(await fork.author.state()?.handOnOwed == false)
        #expect(try await fork.author.items()[second.id] != nil)
        // A device that joins from the snapshot alone holds what both copies carried.
        let joiner = SyncTestClient(
            deviceID: SyncFixtures.deviceC, vaultID: Household.vault, keys: fork.home.keys,
            transport: fork.transport)
        await fork.home.keys.trust(device: SyncFixtures.deviceC)
        await fork.transport.tamper(fork.name, contents: nil)
        try await joiner.sync()
        #expect(try await joiner.items().count == 2)
        #expect(try await fork.author.sync().snapshotsWritten == 0, "owed once")
    }

    @Test("several copies' acknowledgements count only where every copy agrees")
    func acknowledgements() async throws {
        let fork = await Fork.make()
        let item = try await fork.reader.save(Household.login(title: "Reader's"))
        try await fork.reader.sync()
        #expect(try await fork.reader.item(item.id) == item)
        let reader = SyncFixtures.deviceB
        let high = try await fork.author.signedSegment(
            1, carrying: [], acknowledging: [reader: 9, SyncFixtures.deviceA: 4])
        let low = try await fork.author.signedSegment(1, carrying: [], acknowledging: [reader: 1])
        await fork.transport.tamper(fork.name, contents: high)
        await fork.transport.plantCopy(fork.name, contents: low)
        let report = try await fork.reader.sync()
        #expect(report.forkedObjects == [fork.name])
        #expect(await fork.reader.state()?.acknowledgements[SyncFixtures.deviceA] == [reader: 1])
    }

    @Test("past the bound per name copies are counted, not read; a genuine object among the first is still used")
    func boundPerName() async throws {
        let fork = await Fork.make()
        let saved = try await fork.author.save(Household.login())
        try await fork.author.sync()
        for index in 0..<100 { await fork.transport.plantCopy(fork.name, contents: [UInt8(index), 1, 2]) }
        let report = try await fork.reader.sync()
        #expect(report.copiesExamined == 16 && report.copiesRefused == 15 && report.copiesNotExamined == 85)
        #expect(report.applied == 1 && report.rejected.isEmpty)
        #expect(try await fork.reader.item(saved.id) == saved)
        #expect(try await fork.reader.sync().copiesExamined == 0)
    }

    @Test("past the bound per sync a needed name is read as its current file, and its copies are looked at later")
    func boundPerSync() async throws {
        var configuration = SyncTestClient.configuration
        configuration.maximumCopiesPerSync = 6
        configuration.maximumCopiesPerObject = 4
        let fork = await Fork.make(configuration: configuration)
        for index in 0..<5 {
            try await fork.author.save(Household.login(title: "Item \(index)"))
            try await fork.author.sync()
        }
        for sequence in 1...5 {
            let name = SyncObjectLocation.segment(
                vaultID: Household.vault, author: SyncFixtures.deviceA, sequence: UInt64(sequence)
            ).name
            for index in 0..<3 { await fork.transport.plantCopy(name, contents: [UInt8(sequence), UInt8(index)]) }
        }
        let report = try await fork.reader.sync()
        #expect(report.applied == 5 && report.rejected.isEmpty && report.waiting.isEmpty, "\(report)")
        // Half the bound (3) is for names this sync waits on (R13): the first name's four copies, finished.
        #expect(report.copiesExamined == 4, "the bound, and the name it was reached on finished")
        var examined = report.copiesExamined
        for _ in 0..<6 { examined += try await fork.reader.sync().copiesExamined }
        #expect(examined == 20, "every copy is looked at in the end, a bounded number per sync")
        #expect(try await fork.reader.sync().copiesExamined == 0)
    }

    @Test("several verifying copies of a snapshot are each merged and cover the most either covers")
    func snapshotCopies() async throws {
        let fork = await Fork.make()
        let first = try await fork.author.save(Household.login(title: "In one"))
        let row = try #require(await fork.author.store.record(RecordKey(recordID: first.id, kind: .item)))
        let second = try await fork.restored.save(Household.login(title: "In the other"))
        let otherRow = try #require(await fork.restored.store.record(RecordKey(recordID: second.id, kind: .item)))
        let location = SyncObjectLocation.snapshot(vaultID: Household.vault, author: SyncFixtures.deviceA, lamport: 5)
        func snapshot(_ rows: [StoredRecord], _ vector: [UUID: UInt64]) async throws -> [UInt8] {
            let payload = SyncPayload(
                kind: .snapshot, vaultID: Household.vault, author: SyncFixtures.deviceA, number: 5, vector: vector,
                entries: rows.map(SyncEntry.init))
            let envelope = try await fork.author.keyring.seal(payload.encoded(), at: location)
            let signature = try await fork.author.keyring.sign(envelope, at: location)
            return SignedObject(signature: signature, envelope: envelope).serialized()
        }
        let author = SyncFixtures.deviceA
        await fork.transport.tamper(location.name, contents: try await snapshot([row], [author: 3]))
        await fork.transport.plantCopy(
            location.name, contents: try await snapshot([otherRow], [author: 2, SyncFixtures.deviceC: 7]))
        let report = try await fork.reader.sync()
        #expect(report.applied == 2 && report.forkedObjects == [location.name])
        #expect(await fork.reader.state()?.snapshots[location] == [author: 3, SyncFixtures.deviceC: 7])
    }

    @Test("a vault with a judge refuses several verifying copies and waits; one among junk is used")
    func judged() async throws {
        let fork = await Fork.make()
        let saved = try await fork.author.save(Household.login(title: "First"))
        try await fork.author.sync()
        try await fork.restored.save(Household.login(title: "Second"))
        try await fork.restored.sync()
        var configuration = SyncTestClient.configuration
        configuration.maintainsLog = false
        let store = InMemoryRecordStore()
        let state = InMemorySyncStateStore()
        let keyring = FakeSyncKeyring(deviceID: SyncFixtures.deviceB, keys: fork.home.keys)
        let engine = SyncEngine(
            vaultID: Household.vault, deviceID: SyncFixtures.deviceB, store: store, syncState: state,
            transport: fork.transport, keyring: keyring, merger: FakeItemMerger(keyring: keyring),
            configuration: configuration, judge: ScriptedJudge())

        await fork.transport.plantCopy(fork.name, contents: [1, 2, 3])
        let withJunk = try await engine.sync()
        #expect(withJunk.applied == 1 && withJunk.rejected.isEmpty && withJunk.copiesRefused == 1)
        #expect(await store.record(RecordKey(recordID: saved.id, kind: .item)) != nil)

        // A second verifying copy, found late: reported, not applied.
        try await fork.plantRestoredCopy()
        let late = try await engine.sync()
        #expect(late.applied == 0)
        #expect(late.rejected == [SyncRejection(name: fork.name, reason: .transport(.conflictingVersions(fork.name)))])
        #expect(await store.records(in: Household.vault, kind: .item).count == 1)
        #expect(try await engine.sync().rejected.isEmpty, "reported once per count")

        // A device that has not merged the position waits at it.
        let fresh = InMemoryRecordStore()
        let other = SyncEngine(
            vaultID: Household.vault, deviceID: SyncFixtures.deviceB, store: fresh,
            syncState: InMemorySyncStateStore(), transport: fork.transport, keyring: keyring,
            merger: FakeItemMerger(keyring: keyring), configuration: configuration, judge: ScriptedJudge())
        let waiting = try await other.sync()
        #expect(waiting.applied == 0 && waiting.waiting == [SyncFixtures.deviceA: 1])
        #expect(waiting.rejected.map(\.reason) == [.transport(.conflictingVersions(fork.name))])
        #expect(await fresh.records(in: Household.vault, kind: .item).isEmpty)
    }

    @Test("a staged row edited to hold several copies is refused in a vault with a judge")
    func judgedStagingEdited() async throws {
        let fork = await Fork.make()
        try await fork.author.save(Household.login(title: "First"))
        try await fork.author.sync()
        try await fork.restored.save(Household.login(title: "Second"))
        try await fork.restored.sync()
        let location = SyncObjectLocation.segment(vaultID: Household.vault, author: SyncFixtures.deviceA, sequence: 1)
        let one = try SignedObject.parse(try #require(await fork.transport.allObjects[fork.name]))
        let two = try SignedObject.parse(try #require(await fork.restoredTransport.allObjects[fork.name]))
        var configuration = SyncTestClient.configuration
        configuration.maintainsLog = false
        let store = InMemoryRecordStore()
        let state = InMemorySyncStateStore()
        await state.stage(StagedObject(location: location, object: one, alternates: [two], copies: 2))
        let keyring = FakeSyncKeyring(deviceID: SyncFixtures.deviceB, keys: fork.home.keys)
        let engine = SyncEngine(
            vaultID: Household.vault, deviceID: SyncFixtures.deviceB, store: store, syncState: state,
            transport: InMemorySyncTransport(), keyring: keyring, merger: FakeItemMerger(keyring: keyring),
            configuration: configuration, judge: ScriptedJudge())
        let report = try await engine.sync()
        #expect(report.applied == 0 && report.waiting == [SyncFixtures.deviceA: 1])
        #expect(report.rejected.map(\.reason) == [.transport(.conflictingVersions(fork.name))])
    }

    @Test("a copy that verifies and does not open stops the position whole: nothing of the other copy is applied")
    func oneCopyDoesNotOpen() async throws {
        let fork = await Fork.make()
        try await fork.author.save(Household.login(title: "First"))
        try await fork.author.sync()
        // Sealed and signed by the author for this very name, but the payload inside names another position: every
        // check that needs no key passes, and the copy is refused only once it is opened.
        let location = SyncObjectLocation.segment(vaultID: Household.vault, author: SyncFixtures.deviceA, sequence: 1)
        let payload = SyncPayload(
            kind: .segment, vaultID: Household.vault, author: SyncFixtures.deviceA, number: 2, vector: [:],
            entries: [])
        let envelope = try await fork.author.keyring.seal(payload.encoded(), at: location)
        let signature = try await fork.author.keyring.sign(envelope, at: location)
        await fork.transport.plantCopy(
            fork.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())
        let report = try await fork.reader.sync()
        #expect(report.applied == 0 && report.waiting == [SyncFixtures.deviceA: 1])
        #expect(report.rejected.map(\.name) == [fork.name])
        #expect(try await fork.reader.items().isEmpty)
    }
}

/// A store whose deletions of one name fail as the object's own failure, as the iCloud Drive adapter's do when the
/// conflict versions of a file cannot be removed.
actor RefusingDeletesTransport: SyncTransport {
    let base = InMemorySyncTransport()
    var refusing = true

    func allow() { refusing = false }

    func list(prefix: String) async throws -> [String] { await base.list(prefix: prefix) }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        try await base.fetch(name, maximumLength: maximumLength)
    }

    func create(_ name: String, contents: [UInt8]) async throws { try await base.create(name, contents: contents) }

    func delete(_ name: String) async throws {
        if refusing { throw SyncTransportError.objectUnreadable(name) }
        await base.delete(name)
    }
}

@Suite("Collecting a device's own objects")
struct CollectionFailureTests {
    /// Review finding SR23. A deletion that the transport refuses for that object alone used to end the whole sync
    /// with the raw error, from the garbage collection after publishing; the account's next vaults never synced. It is
    /// reported against the name, the object is kept, and it is collected at a later sync.
    @Test("a deletion refused for one object is reported, the sync finishes, and a later sync collects it")
    func refusedDeletionIsOneObjectsFailure() async throws {
        let transport = RefusingDeletesTransport()
        var eager = SyncTestClient.configuration
        eager.snapshotThreshold = 1
        let keys = FakeAccountKeys(seed: 107)
        await keys.addVaultKey(vaultID: Household.vault)
        let (aID, bID) = (Household.deviceIDs[0], Household.deviceIDs[1])
        for id in [aID, bID] { await keys.trust(device: id) }
        let a = SyncTestClient(
            deviceID: aID, vaultID: Household.vault, keys: keys, transport: transport, configuration: eager)
        let b = SyncTestClient(deviceID: bID, vaultID: Household.vault, keys: keys, transport: transport)
        var reports: [SyncReport] = []
        for index in 0..<4 {
            try await a.save(Household.login(title: "A \(index)"))
            reports.append(try await a.sync())
            try await b.sync()
        }
        for _ in 0..<3 {
            reports.append(try await a.sync())
            try await b.sync()
        }
        #expect(reports.allSatisfy { $0.collected == 0 })
        #expect(reports.contains { !$0.rejected.isEmpty }, "the refused deletions are reported")
        await transport.allow()
        var collected = 0
        for _ in 0..<3 {
            collected += try await a.sync().collected
            try await b.sync()
        }
        #expect(collected > 0)
        #expect(try await b.items().count == 4)
    }
}
