import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// Milestone 3 adversarial obligations for sync (docs/04-test-plan.md §6.4, the parts that need no membership chain).
///
/// The adversaries, from docs/02-architecture.md §2:
/// - **A1, the sync-store attacker** (a compromised iCloud account, a provider insider): reads, writes, deletes,
///   moves, replays and withholds any object, without any key. Must learn nothing and change nothing undetected; the
///   worst it may achieve is withholding updates, which sync reports as a stream waiting on a missing segment.
/// - **An insider device**: one of the account's own devices, or (from milestone 4) a member of a shared vault (A4),
///   holding the vault key and a trusted signing key. It can write anything a valid client could, so its records are
///   still checked: no record swaps, no versions for another device, no records of another vault, no implausible
///   versions.
/// - **A former device** (A5's position for devices): holds the vault key, but its signing key is no longer trusted.
/// - **A8, the local-file attacker**: edits this device's database while the app is locked — rows, sync state and
///   staged downloads. A rollback or deletion there must not propagate, and a reconciling sync repairs it from the
///   signed log, which lives outside the file.
///
/// Signatures and encryption are the fakes of `WatchwordTestSupport` (a keyed checksum, not cryptography), so these
/// tests show that the engine checks the right thing in the right order; that the real primitives resist forgery is
/// the crypto core suite's job, and the production keyring that connects them is milestone 3's Mac half.
@Suite("Adversarial: sync log", .tags(.adversarial))
struct AdversarialSyncTests {
    static let vault = UUID(uuidString: "0A0A0A0A-0000-4000-8000-00000000000A")!
    static let otherVault = UUID(uuidString: "0B0B0B0B-0000-4000-8000-00000000000B")!
    static let a = UUID(uuidString: "D0000000-0000-4000-8000-0000000000A0")!
    static let b = UUID(uuidString: "D0000000-0000-4000-8000-0000000000B0")!
    static let former = UUID(uuidString: "D0000000-0000-4000-8000-0000000000F0")!

    struct Fixture {
        let keys: FakeAccountKeys
        let transport: InMemorySyncTransport
        let writer: SyncTestClient

        /// A fresh device that has never synced.
        func reader(_ id: UUID = AdversarialSyncTests.b) async -> SyncTestClient {
            await keys.trust(device: id)
            return SyncTestClient(deviceID: id, vaultID: AdversarialSyncTests.vault, keys: keys, transport: transport)
        }

        func segmentName(_ sequence: UInt64, author: UUID = AdversarialSyncTests.a) -> String {
            SyncObjectLocation.segment(vaultID: AdversarialSyncTests.vault, author: author, sequence: sequence).name
        }

        /// Seals and signs `payload` as `keyring` would, and plants it under `name` (default: its own location).
        func plant(_ payload: SyncPayload, signedBy keyring: FakeSyncKeyring, as name: String? = nil) async throws {
            let envelope = try await keyring.seal(payload.encoded(), at: payload.location)
            let signature = try await keyring.sign(envelope, at: payload.location)
            await transport.tamper(
                name ?? payload.location.name,
                contents: SignedObject(signature: signature, envelope: envelope).serialized())
        }
    }

    static func fixture() async throws -> Fixture {
        let keys = FakeAccountKeys(seed: 77)
        await keys.addVaultKey(vaultID: vault)
        await keys.addVaultKey(vaultID: otherVault)
        await keys.trust(device: a)
        let transport = InMemorySyncTransport()
        let writer = SyncTestClient(deviceID: a, vaultID: vault, keys: keys, transport: transport)
        return Fixture(keys: keys, transport: transport, writer: writer)
    }

    static func login(_ title: String, password: String, id: UUID = UUID()) -> Item {
        Item(
            id: id, vaultID: vault, title: title, scopes: [ServiceScope(host: "firstbank.co.uk")],
            fields: [
                Field(kind: .username, label: "Username", value: "pat"),
                Field(kind: .password, label: "Password", value: password),
            ])
    }

    /// A payload for `author`'s segment `sequence` carrying `rows` from a store.
    static func payload(_ rows: [StoredRecord], author: UUID = a, sequence: UInt64 = 1, vault: UUID = vault)
        -> SyncPayload
    {
        SyncPayload(
            kind: .segment, vaultID: vault, author: author, number: sequence, vector: [:],
            entries: rows.map(SyncEntry.init))
    }

    // MARK: - A1: the sync store

    /// Threat: A1 flips bytes in a stored segment, anywhere — container, signature, envelope header, ciphertext, tag —
    /// hoping some byte is unchecked. Every flip must be rejected and nothing applied; the stream waits.
    @Test("a byte flipped anywhere in a segment is rejected and nothing is applied")
    func byteFlips() async throws {
        let f = try await Self.fixture()
        try await f.writer.save(Self.login("Bank", password: "flip-secret"))
        try await f.writer.sync()
        let name = f.segmentName(1)
        let original = try #require(await f.transport.allObjects[name])
        let positions = Array(0..<min(original.count, 160)) + Array(stride(from: 160, to: original.count, by: 23))
        for position in positions {
            var tampered = original
            tampered[position] ^= 0x01
            await f.transport.tamper(name, contents: tampered)
            let reader = await f.reader()
            let report = try await reader.sync()
            #expect(report.applied == 0, "flip at \(position) was applied")
            #expect(report.rejected.map(\.name) == [name], "flip at \(position)")
            #expect(report.waiting[Self.a] == 1)
            #expect(try await reader.items().isEmpty)
        }
        await f.transport.tamper(name, contents: original)
        #expect(try await f.reader().sync().applied == 1, "the untouched segment still applies")
    }

    /// Threat: A1 moves a validly signed segment to another name — a later sequence number of the same stream, the
    /// same number in another device's stream, another vault, a snapshot slot — to replay it, misattribute it, or
    /// smuggle it across vaults. The location is bound into the envelope and the signature, so each copy is refused.
    @Test("a segment copied to another stream, sequence, vault or slot is refused")
    func movedSegments() async throws {
        let f = try await Self.fixture()
        try await f.writer.save(Self.login("Bank", password: "moved-secret"))
        try await f.writer.sync()
        let original = try #require(await f.transport.allObjects[f.segmentName(1)])
        await f.keys.trust(device: Self.b)
        let destinations = [
            f.segmentName(2),
            f.segmentName(1, author: Self.b),
            SyncObjectLocation.segment(vaultID: Self.otherVault, author: Self.a, sequence: 1).name,
            SyncObjectLocation.snapshot(vaultID: Self.vault, author: Self.a, lamport: 1).name,
        ]
        for destination in destinations {
            await f.transport.tamper(destination, contents: original)
        }
        await f.transport.tamper(f.segmentName(1), contents: nil)
        let reader = await f.reader(UUID(uuidString: "D0000000-0000-4000-8000-0000000000C0")!)
        let report = try await reader.sync()
        #expect(report.applied == 0)
        // In another device's stream the signature does not verify; in a snapshot slot the kind does not match. At a
        // later number of the same stream it waits behind the missing segment 1 (and `withheldSegment` shows it is
        // refused once reached).
        #expect(Set(report.rejected.map(\.name)) == [destinations[1], destinations[3]])
        #expect(report.waiting[Self.a] == 1)
        #expect(try await reader.items().isEmpty)
        let otherVaultReader = SyncTestClient(
            deviceID: UUID(), vaultID: Self.otherVault, keys: f.keys, transport: f.transport)
        let other = try await otherVaultReader.sync()
        #expect(other.applied == 0)
        #expect(other.rejected.map(\.reason) == [.envelope(.contextMismatch)])
    }

    /// Threat: A1 withholds a segment, or replaces it with an older one, to roll an item back or hide a change. The
    /// older segment does not verify at the newer number; the stream stops at the gap instead of skipping it, so no
    /// later change is applied out of order; and once the segment is served again, the device catches up.
    @Test("a withheld or replayed segment stops its stream at the gap until the real one is served")
    func withheldSegment() async throws {
        let f = try await Self.fixture()
        let item = try await f.writer.save(Self.login("Bank", password: "v1"))
        try await f.writer.sync()
        try await f.writer.edit(item.id) { $0.fields[1].value = "v2" }
        try await f.writer.sync()
        try await f.writer.edit(item.id) { $0.notes = "v3" }
        try await f.writer.sync()
        let second = try #require(await f.transport.allObjects[f.segmentName(2)])
        let first = try #require(await f.transport.allObjects[f.segmentName(1)])
        await f.transport.tamper(f.segmentName(2), contents: first)

        let reader = await f.reader()
        let report = try await reader.sync()
        #expect(report.rejected.map(\.reason) == [.envelope(.contextMismatch)])
        #expect(report.waiting[Self.a] == 2)
        #expect(try await reader.item(item.id).field(.password)?.value == "v1")
        #expect(try await reader.item(item.id).notes.isEmpty, "segment 3 is not applied over the gap")

        await f.transport.tamper(f.segmentName(2), contents: second)
        let caughtUp = try await reader.sync()
        #expect(caughtUp.waiting.isEmpty)
        #expect(try await reader.item(item.id).notes == "v3")
    }

    /// Threat: A1, holding no key, plants an object of its own: garbage, a well-formed container with a made-up
    /// signature, or a genuine signature lifted from another object.
    @Test("objects forged without the author's signing key are rejected before staging")
    func forgeries() async throws {
        let f = try await Self.fixture()
        try await f.writer.save(Self.login("Bank", password: "forge-secret"))
        try await f.writer.sync()
        let genuine = try SignedObject.parse(try #require(await f.transport.allObjects[f.segmentName(1)]))
        await f.transport.tamper(f.segmentName(2), contents: Array(repeating: 0x41, count: 300))
        await f.transport.tamper(
            f.segmentName(3),
            contents: SignedObject(signature: Array(repeating: 7, count: 64), envelope: genuine.envelope).serialized())
        let reader = await f.reader()
        await reader.keyring.lock()
        let report = try await reader.sync()
        #expect(Set(report.rejected.map(\.name)) == [f.segmentName(2), f.segmentName(3)])
        #expect(try await reader.syncState.staged(vaultID: Self.vault).map(\.location.number) == [1])
    }

    /// Threat: A1 serves an old snapshot again after newer ones (and the segments they covered) have been collected,
    /// hoping a device that is already up to date regresses. Old versions never displace newer values.
    @Test("an old snapshot served again does not roll a device back")
    func staleSnapshot() async throws {
        let keys = FakeAccountKeys(seed: 9)
        await keys.addVaultKey(vaultID: Self.vault)
        await keys.trust(device: Self.a)
        await keys.trust(device: Self.b)
        let transport = InMemorySyncTransport()
        var configuration = SyncTestClient.configuration
        configuration.snapshotThreshold = 4
        let writer = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: keys, transport: transport, configuration: configuration)
        let reader = SyncTestClient(
            deviceID: Self.b, vaultID: Self.vault, keys: keys, transport: transport, configuration: configuration)
        let item = try await writer.save(Self.login("Bank", password: "old"))
        var oldSnapshot: (String, [UInt8])?
        for round in 0..<16 {
            try await writer.edit(item.id) { $0.notes = "round \(round)" }
            try await writer.sync()
            try await reader.sync()
            if oldSnapshot == nil,
                let snapshot = await transport.allObjects.first(where: { $0.key.contains("/snapshot/") })
            {
                oldSnapshot = snapshot
            }
        }
        let (name, bytes) = try #require(oldSnapshot)
        let current = try await reader.item(item.id)
        for (other, _) in await transport.allObjects where other.contains("/snapshot/") {
            await transport.tamper(other, contents: nil)
        }
        await transport.tamper(name, contents: bytes)
        let report = try await reader.sync(reconcile: true)
        #expect(report.rejected.isEmpty)
        #expect(try await reader.item(item.id) == current)
        #expect(try await reader.item(item.id).notes == "round 15")
    }

    /// Threat: confidentiality against A1 (PRD F7.3). Nothing a device publishes contains a title, host, username or
    /// password; object names carry only vault and device IDs and counters.
    @Test("no title, host or field value reaches the transport")
    func noPlaintext() async throws {
        let f = try await Self.fixture()
        let item = try await f.writer.save(Self.login("Distinctive Credit Union", password: "pl41ntext-secret"))
        try await f.writer.edit(item.id) { $0.notes = "Recovery phrase hint: gardening" }
        try await f.writer.sync()
        let reader = await f.reader()
        try await reader.sync()
        try await reader.edit(item.id) { $0.title = "Distinctive CU" }
        try await reader.sync()
        let objects = await f.transport.allObjects
        #expect(!objects.isEmpty)
        for needle in ["Distinctive", "firstbank", "pl41ntext", "gardening", "Username"] {
            let bytes = Array(needle.utf8)
            for (name, contents) in objects {
                #expect(!name.contains(needle))
                let found = (0...(contents.count - bytes.count)).contains {
                    contents[$0..<($0 + bytes.count)].elementsEqual(bytes)
                }
                #expect(!found, "\(needle) found in \(name)")
            }
        }
    }

    // MARK: - Insider and former devices

    /// Threat: a device that held the vault key but whose signing key is no longer trusted (a removed or former
    /// device) keeps writing to its stream. Its segments are rejected even though they decrypt.
    @Test("segments from an untrusted device are rejected though they decrypt")
    func formerDevice() async throws {
        let f = try await Self.fixture()
        await f.keys.trust(device: Self.former)
        let former = SyncTestClient(deviceID: Self.former, vaultID: Self.vault, keys: f.keys, transport: f.transport)
        try await former.save(Self.login("Planted", password: "former-secret"))
        try await former.sync()
        await f.keys.revoke(device: Self.former)
        let report = try await f.reader().sync()
        #expect(report.applied == 0)
        #expect(report.rejected.map(\.reason) == [.keyring(.untrustedAuthor(Self.former))])
        #expect(report.waiting[Self.former] == 1)
    }

    /// Threat: an insider builds a segment whose entry claims to be one record while carrying another record's
    /// envelope — a record swap, or a relabel to another version — so the other record's secret is shown or filled
    /// under the wrong item. The record's own authenticated context is compared before anything is merged.
    @Test("a record envelope relabelled inside a validly signed segment is rejected")
    func recordSwapInsideSegment() async throws {
        let f = try await Self.fixture()
        let bank = try await f.writer.save(Self.login("Bank", password: "bank-secret"))
        let library = try await f.writer.save(Self.login("Library", password: "library-secret"))
        let rows = try await f.writer.store.records(in: Self.vault, kind: .item)
        let bankRow = try #require(rows.first { $0.recordID == bank.id })
        let libraryRow = try #require(rows.first { $0.recordID == library.id })
        var swapped = libraryRow
        swapped.envelope = bankRow.envelope
        var relabelled = bankRow
        relabelled.version += 5
        for (index, row) in [swapped, relabelled].enumerated() {
            try await f.plant(Self.payload([row], sequence: UInt64(index + 1)), signedBy: f.writer.keyring)
        }
        let report = try await f.reader().sync()
        #expect(report.applied == 0)
        #expect(report.rejected.first?.reason == .recordContextMismatch(library.id))
        #expect(report.waiting[Self.a] == 1)
    }

    /// Threat: an insider writes versions attributed to another device, to make its change win ties as that device or
    /// to frame it. A segment may only carry its author's versions.
    @Test("a segment carrying another device's versions is rejected")
    func versionsForAnotherDevice() async throws {
        let f = try await Self.fixture()
        await f.keys.trust(device: Self.b)
        let other = SyncTestClient(deviceID: Self.b, vaultID: Self.vault, keys: f.keys, transport: f.transport)
        try await other.save(Self.login("B's item", password: "b-secret"))
        let rows = try await other.store.records(in: Self.vault, kind: .item)
        try await f.plant(Self.payload(rows), signedBy: f.writer.keyring)
        let report = try await f.reader(UUID()).sync()
        #expect(report.applied == 0)
        #expect(report.rejected.first?.reason == .entryFromAnotherDevice(rows[0].recordID))
    }

    /// Threat: an insider (from milestone 4, a member of a shared vault) writes a record whose ID is that of a record in
    /// another vault on the reader's device, to overwrite or merge into an item it is not entitled to.
    @Test("a record whose ID belongs to another vault on this device is rejected")
    func crossVaultRecordID() async throws {
        let f = try await Self.fixture()
        let item = try await f.writer.save(Self.login("Shared vault item", password: "x"))
        let reader = await f.reader()
        let foreign = StoredRecord(
            recordID: item.id, kind: .item, vaultID: Self.otherVault, keyID: UUID(), version: 1, deviceID: Self.b,
            envelope: [1, 2, 3])
        await reader.store.tamper(foreign)
        try await f.writer.sync()
        let report = try await reader.sync()
        #expect(report.rejected.first?.reason == .recordInAnotherVault(item.id))
        #expect(try await reader.store.record(foreign.key) == foreign)
    }

    /// Threat: an insider writes a record version near `UInt64.max`, so no later version fits and the item freezes
    /// (review finding U5), or one implausibly far ahead of the vault. Both are quarantined, not merged.
    @Test("implausible version jumps are quarantined")
    func versionJumps() async throws {
        let f = try await Self.fixture()
        for (index, version) in [UInt64(1) << 30, UInt64.max - 1].enumerated() {
            var item = Self.login("Jump \(index)", password: "j")
            item.version = version
            item = ItemMerge.stamped(item, previous: nil, revision: Revision(version: version, device: Self.a))
            let row = try await f.writer.keyring.sealItem(item)
            try await f.plant(Self.payload([row], sequence: UInt64(index + 1)), signedBy: f.writer.keyring)
        }
        let reader = await f.reader()
        let report = try await reader.sync()
        #expect(report.quarantined.count == 2)
        #expect(report.applied == 0)
        #expect(try await reader.items().isEmpty)
    }

    // MARK: - A8: the local file

    /// Threat: A8 rolls a row back to an older, validly sealed version in this device's database, or deletes it, while
    /// the app is locked. Neither may propagate as a change, and a reconciling sync restores the newest version from
    /// the signed log (docs/02-architecture.md §6, "known limit until sync").
    @Test("a row rolled back or deleted in the local file is not propagated and is restored by reconciling")
    func localRollback() async throws {
        let f = try await Self.fixture()
        let item = try await f.writer.save(Self.login("Bank", password: "v1"))
        try await f.writer.sync()
        let reader = await f.reader()
        try await reader.sync()
        let key = RecordKey(recordID: item.id, kind: .item)
        let old = try #require(try await reader.store.record(key))
        try await f.writer.edit(item.id) { $0.fields[1].value = "v2" }
        try await f.writer.sync()
        try await reader.sync()

        await reader.store.tamper(old)
        #expect(try await reader.item(item.id).field(.password)?.value == "v1")
        try await reader.sync()
        #expect(try await f.writer.item(item.id).field(.password)?.value == "v2", "the rollback did not propagate")
        try await reader.sync(reconcile: true)
        #expect(try await reader.item(item.id).field(.password)?.value == "v2")

        try await reader.store.commit(StoreChange(deletions: [key]))
        try await reader.sync()
        try await f.writer.sync()
        #expect(try await f.writer.items()[item.id] != nil, "a missing row is not a deletion to publish")
        try await reader.sync(reconcile: true)
        #expect(try await reader.item(item.id).field(.password)?.value == "v2")
    }

    /// Threat: A8 edits a downloaded object in the staging area between a locked download and the merge after
    /// unlock. Staged objects are verified again before they are opened.
    @Test("a staged download edited in the local file is rejected at merge")
    func tamperedStaging() async throws {
        let f = try await Self.fixture()
        try await f.writer.save(Self.login("Bank", password: "staged-secret"))
        try await f.writer.sync()
        let reader = await f.reader()
        await reader.keyring.lock()
        try await reader.sync()
        let staged = try #require(try await reader.syncState.staged(vaultID: Self.vault).first)
        var object = staged.object
        object.envelope[object.envelope.count - 1] ^= 0x80
        await reader.syncState.stage(StagedObject(location: staged.location, object: object))
        await reader.keyring.unlock()
        let report = try await reader.sync()
        #expect(report.rejected.map(\.name) == [staged.location.name])
        #expect(report.applied == 0)
        #expect(try await reader.items().isEmpty)
        #expect(try await reader.sync().applied == 1, "the next sync fetches the genuine object again")
    }

    // MARK: - Parsers

    /// Threat: an insider's payload, or bytes from A1 that reach the parsers, crafted to crash, hang or allocate.
    /// Random mutations of valid objects are always either refused with a typed error or parsed to a value that
    /// re-encodes to exactly the input (one canonical encoding).
    @Test("mutated payloads and containers never crash and never parse non-canonically")
    func parserMutations() throws {
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 0xFA22))
        let entries = (1...4).map { n in
            SyncEntry(
                recordID: UUID(), kind: .item, keyID: UUID(), version: UInt64(n), device: Self.a,
                envelope: Array(repeating: UInt8(n), count: n * 7))
        }
        let valid = SyncPayload(
            kind: .segment, vaultID: Self.vault, author: Self.a, number: 3, vector: [Self.a: 2, Self.b: 9],
            entries: entries
        ).encoded()
        for _ in 0..<TestEnvironment.iterations(standard: 5_000, long: 500_000) {
            var bytes = valid
            for _ in 0..<Int.random(in: 1...4, using: &generator) {
                switch Int.random(in: 0..<4, using: &generator) {
                case 0:
                    bytes[Int.random(in: 0..<bytes.count, using: &generator)] = UInt8.random(
                        in: 0...255, using: &generator)
                case 1: bytes = Array(bytes.prefix(Int.random(in: 0...bytes.count, using: &generator)))
                case 2:
                    bytes.insert(
                        UInt8.random(in: 0...255, using: &generator),
                        at: Int.random(in: 0...bytes.count, using: &generator))
                default: if !bytes.isEmpty { bytes.remove(at: Int.random(in: 0..<bytes.count, using: &generator)) }
                }
                if bytes.isEmpty { break }
            }
            if let parsed = try? SyncPayload.parse(bytes, allowedKinds: [.item]) {
                #expect(parsed.encoded() == bytes)
            }
            if let object = try? SignedObject.parse(bytes) {
                #expect(object.serialized() == bytes)
            }
        }
    }

    /// Threat: anyone who can write to a shared folder (A1, or a member of a folder share) plants symbolic links in the
    /// directory a file transport reads, to make a fetch read an arbitrary local file or a create write outside the
    /// folder. No path component may be a link.
    @Test("symbolic links planted in a file transport's directory are never followed")
    func plantedSymlinks() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("watchword-adversarial-sync-\(UUID().uuidString)", isDirectory: true)
        let outside = root.deletingLastPathComponent().appendingPathComponent("outside-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        try Data("not a sync object".utf8).write(to: outside.appendingPathComponent("secret.wwe"))
        let transport = FileSyncTransport(root: root)
        let location = SyncObjectLocation.segment(vaultID: Self.vault, author: Self.a, sequence: 1)
        let streamDirectory = root.appendingPathComponent(location.name).deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: streamDirectory.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: streamDirectory, withDestinationURL: outside)

        await #expect(throws: SyncTransportError.invalidName(location.name)) {
            try await transport.create(location.name, contents: [1])
        }
        await #expect(throws: SyncTransportError.self) {
            try await transport.fetch(location.name, maximumLength: 1 << 20)
        }
        #expect(try await transport.list(prefix: SyncObjectLocation.vaultPrefix(Self.vault)).isEmpty)
        #expect(
            !FileManager.default.fileExists(atPath: outside.appendingPathComponent(location.number.description).path))

        try FileManager.default.removeItem(at: streamDirectory)
        try FileManager.default.createDirectory(at: streamDirectory, withIntermediateDirectories: true)
        let fileLink = root.appendingPathComponent(location.name + ".wwe")
        try FileManager.default.createSymbolicLink(
            at: fileLink, withDestinationURL: outside.appendingPathComponent("secret.wwe"))
        await #expect(throws: SyncTransportError.invalidName(location.name)) {
            try await transport.fetch(location.name, maximumLength: 1 << 20)
        }
        #expect(try await transport.list(prefix: SyncObjectLocation.vaultPrefix(Self.vault)).isEmpty)
    }
}
