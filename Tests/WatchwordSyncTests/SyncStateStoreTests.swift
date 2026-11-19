import Foundation
import Testing
import WatchwordEnvelope
import WatchwordStore

@testable import WatchwordSync

#if canImport(SQLite3)
    import SecureMemory
#endif

enum StateStoreKind: String, CaseIterable, CustomTestStringConvertible, Sendable {
    case inMemory
    case sqlite

    var testDescription: String { rawValue }

    static var available: [StateStoreKind] {
        #if canImport(SQLite3)
            return allCases
        #else
            return [.inMemory]
        #endif
    }

    func make() throws -> any SyncStateStore {
        switch self {
        case .inMemory: return InMemorySyncStateStore()
        case .sqlite:
            #if canImport(SQLite3)
                return try SQLiteSyncStateStore(url: StateStoreFixtures.temporaryURL())
            #else
                throw CocoaError(.featureUnsupported)
            #endif
        }
    }
}

enum StateStoreFixtures {
    static func temporaryURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("watchword-sync-state-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("sync.sqlite")
    }

    static func record(_ n: UInt8, version: UInt64 = 3) -> StoredRecord {
        StoredRecord(
            recordID: UUID(uuid: (n, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, n)), kind: .item,
            vaultID: SyncFixtures.vault, keyID: UUID(uuid: (0xEE, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 1)),
            version: version, deviceID: SyncFixtures.deviceA, envelope: Array(repeating: n, count: 40))
    }

    /// A state with something in every field.
    static func state() -> SyncState {
        var state = SyncState(vaultID: SyncFixtures.vault)
        state.nextSequence = 9
        state.lastPublishedSequence = 8
        state.merged = [SyncFixtures.deviceA: 8, SyncFixtures.deviceB: 3]
        let key = record(1).key
        state.known = [
            key: RecordStamp(version: 4, device: SyncFixtures.deviceB),
            record(2).key: RecordStamp(version: 7, device: SyncFixtures.deviceA, deleted: true),
        ]
        state.erasures = [
            record(2).key: Erasure(
                stamp: RecordStamp(version: 7, device: SyncFixtures.deviceA, deleted: true), summary: [1, 2, 3])
        ]
        state.published = [key: RecordStamp(version: 3, device: SyncFixtures.deviceA)]
        state.acknowledgements = [SyncFixtures.deviceB: [SyncFixtures.deviceA: 6, SyncFixtures.deviceB: 3]]
        state.publishedAcknowledgement = [SyncFixtures.deviceB: 3]
        let snapshot = SyncObjectLocation.snapshot(
            vaultID: SyncFixtures.vault, author: SyncFixtures.deviceB, lamport: 12)
        state.snapshots = [snapshot: [SyncFixtures.deviceA: 5, SyncFixtures.deviceB: 2]]
        state.snapshotCoverage = [SyncFixtures.deviceA: 5, SyncFixtures.deviceB: 2]
        state.stashUnsaved = true
        state.stashGeneration = 4
        state.retryUnfinished = true
        state.quarantineDropped = [SyncFixtures.deviceB]
        state.quarantineCrowded = 17
        state.collectedThrough = 2
        state.restoredUnpublished = [record(4).key: RecordStamp(version: 2, device: SyncFixtures.deviceB)]
        state.authenticator = [0xA1, 0xA2, 0xA3]
        return state
    }
}

/// What the session signs of a state row (review finding Z20): everything in it.
@Suite("Sync state authentication")
struct SyncStateAuthenticationTests {
    /// A name the transport lists with copies beside it.
    static let copied = SyncObjectLocation.snapshot(
        vaultID: SyncFixtures.vault, author: SyncFixtures.deviceA, lamport: 3)

    /// One state per field, each differing from the fixture in that field alone.
    static var variants: [(String, SyncState)] {
        let base = StateStoreFixtures.state()
        let other = StateStoreFixtures.record(3).key
        func changed(_ label: String, _ change: (inout SyncState) -> Void) -> (String, SyncState) {
            var state = base
            change(&state)
            return (label, state)
        }
        return [
            changed("vaultID") { $0.vaultID = SyncFixtures.otherVault },
            changed("nextSequence") { $0.nextSequence += 1 },
            changed("lastPublishedSequence") { $0.lastPublishedSequence += 1 },
            changed("merged") { $0.merged[SyncFixtures.deviceB] = 1 << 48 },
            changed("merged, another stream") { $0.merged[UUID()] = 300 },
            changed("known") { $0.known[other] = RecordStamp(version: 1, device: SyncFixtures.deviceA) },
            changed("erasures") {
                $0.erasures[other] = Erasure(
                    stamp: RecordStamp(version: 9, device: SyncFixtures.deviceA, deleted: true), summary: [])
            },
            changed("an erasure's summary") { $0.erasures[StateStoreFixtures.record(2).key]?.summary = [1, 2, 4] },
            changed("an erasure's stamp") { $0.erasures[StateStoreFixtures.record(2).key]?.stamp.version = 8 },
            changed("published") { $0.published[other] = RecordStamp(version: 1, device: SyncFixtures.deviceA) },
            changed("acknowledgements") { $0.acknowledgements[SyncFixtures.deviceB]?[SyncFixtures.deviceA] = 7 },
            changed("publishedAcknowledgement") { $0.publishedAcknowledgement[SyncFixtures.deviceB] = 4 },
            changed("snapshots") { $0.snapshots = [:] },
            changed("snapshotCoverage") { $0.snapshotCoverage[SyncFixtures.deviceA] = 6 },
            changed("stashUnsaved") { $0.stashUnsaved = false },
            changed("stashGeneration") { $0.stashGeneration = 5 },
            changed("retryUnfinished") { $0.retryUnfinished = false },
            changed("quarantineDropped") { $0.quarantineDropped.insert(SyncFixtures.deviceA) },
            changed("quarantineDropped, emptied") { $0.quarantineDropped = [] },
            changed("quarantineCrowded") { $0.quarantineCrowded = 18 },
            changed("quarantineCrowded, cleared") { $0.quarantineCrowded = nil },
            changed("quarantineCrowded, zero") { $0.quarantineCrowded = 0 },
            changed("collectedThrough") { $0.collectedThrough = 3 },
            // The conflict copies and the reset (docs/02-architecture.md §7.5, §7.10), signed since the merge with the
            // branch that signs the state (Z20).
            changed("examinedCopies") { $0.examinedCopies[Self.copied] = 2 },
            changed("unreadCopies") { $0.unreadCopies[Self.copied] = 3 },
            changed("unreadCopiesExamined") { $0.unreadCopiesExamined[Self.copied] = 4 },
            changed("handOnOwed") { $0.handOnOwed = true },
            changed("ownUnlistedThrough") { $0.ownUnlistedThrough = 5 },
            changed("ownUnlistedThrough, zero") { $0.ownUnlistedThrough = 0 },
            changed("handedOn") { $0.handedOn = HandedOn(snapshot: Self.copied, holding: [SyncFixtures.deviceA: 1]) },
            changed("highestOwnSnapshot") { $0.highestOwnSnapshot = 6 },
            changed("storeResetSuspected") { $0.storeResetSuspected = true },
            // The device move's fact (V49).
            changed("syncedBefore") { $0.syncedBefore = true },
            // Its one-shot companion (V52), alone and with the fact it is set with.
            changed("startedOverByMove") { $0.startedOverByMove = true },
            changed("startedOverByMove, with syncedBefore") {
                $0.syncedBefore = true
                $0.startedOverByMove = true
            },
            changed("restoredUnpublished") {
                $0.restoredUnpublished[other] = RecordStamp(version: 0, device: SyncFixtures.deviceB)
            },
            changed("restoredUnpublished, a stamp") {
                $0.restoredUnpublished[StateStoreFixtures.record(4).key]?.version = 3
            },
            changed("restoredUnpublished, emptied") { $0.restoredUnpublished = [:] },
        ]
    }

    @Test("every field of the state changes what is signed, and the authenticator does not")
    func everyFieldIsCovered() {
        let base = StateStoreFixtures.state()
        let signed = base.authenticatedBytes
        for (label, variant) in Self.variants {
            #expect(variant.authenticatedBytes != signed, "\(label) is not covered")
        }
        var resigned = base
        resigned.authenticator = [9]
        #expect(resigned.authenticatedBytes == signed)
        // A field added to the state must be added to `authenticatedBytes` and to `variants`: this count is the
        // reminder.
        #expect(Mirror(reflecting: base).children.count == 29)
        #expect(Set(Self.variants.map(\.1.authenticatedBytes)).count == Self.variants.count)
    }

    /// The two fields added after the state was first signed (review findings Z33, Z38) are written only when set,
    /// so a row saved before them, in which neither can be set, still verifies and costs no replay.
    @Test("a state with neither later field set is signed as it was before they existed")
    func laterFieldsOnlyWhenSet() {
        var state = StateStoreFixtures.state()
        state.retryUnfinished = false
        state.quarantineDropped = []
        state.quarantineCrowded = nil
        state.collectedThrough = 0
        state.restoredUnpublished = [:]
        let before = state.authenticatedBytes
        state.retryUnfinished = true
        #expect(state.authenticatedBytes.count == before.count + 1 + 8)
        #expect(Array(state.authenticatedBytes.prefix(before.count)) == before)
        // The fields of review findings Z147 and Z149 likewise: a row saved before them still verifies.
        let withRetry = state.authenticatedBytes
        state.collectedThrough = 4
        #expect(state.authenticatedBytes.count == withRetry.count + 1 + 8 + 8)
        #expect(Array(state.authenticatedBytes.prefix(withRetry.count)) == withRetry)
        // And the review of round 12's: a row saved before it still verifies.
        let withCollected = state.authenticatedBytes
        state.restoredUnpublished = [StateStoreFixtures.record(5).key: RecordStamp(version: 1, device: UUID())]
        #expect(state.authenticatedBytes.count == withCollected.count + 8 + (16 + 1) + (8 + 16 + 1))
        #expect(Array(state.authenticatedBytes.prefix(withCollected.count)) == withCollected)
    }

    /// A device move's `syncedBefore` (V49) is written only when set, after the reset's fields, so a row saved before
    /// it still verifies.
    @Test("a state a device move did not start over is signed as it was before the move's fact existed")
    func syncedBeforeOnlyWhenSet() {
        var state = StateStoreFixtures.state()
        state.storeResetSuspected = true
        let before = state.authenticatedBytes
        state.syncedBefore = true
        #expect(state.authenticatedBytes.count == before.count + 1)
        #expect(Array(state.authenticatedBytes.prefix(before.count)) == before)
        // `startedOverByMove` (V52) likewise, after it: a row saved with the fact alone still verifies.
        let withFact = state.authenticatedBytes
        state.startedOverByMove = true
        #expect(state.authenticatedBytes.count == withFact.count + 1)
        #expect(Array(state.authenticatedBytes.prefix(withFact.count)) == withFact)
    }

    /// The two branches merged here each added fields after `collectedThrough`: a restore's `restoredUnpublished`
    /// (review of round 12) and the conflict copies and the reset's (§7.5, §7.10, V49, V52). Where the reset's are
    /// written the restore's count is too, even at zero, so a state with either and a state with both are signed
    /// apart, and a row saved with the restore's alone still verifies. A row the hygiene branch saved before the merge
    /// with the reset's fields straight after `collectedThrough` does not (V55): that form is deliberately not kept,
    /// and the test pins the chosen layout byte for byte, so that a layout that would have kept it (the restore's
    /// stamps only when set, before or after the reset's fields) or any other change of this encoding fails here and
    /// is a decision someone makes, not an accident.
    @Test("a restore's entries and the reset's fields are signed apart, alone and together")
    func restoredAndResetFieldsApart() {
        var neither = StateStoreFixtures.state()
        neither.restoredUnpublished = [:]
        var restored = neither
        restored.restoredUnpublished = [StateStoreFixtures.record(5).key: RecordStamp(version: 1, device: UUID())]
        var reset = neither
        reset.storeResetSuspected = true
        var both = restored
        both.storeResetSuspected = true
        var moved = both
        moved.syncedBefore = true
        moved.startedOverByMove = true
        let forms = [neither, restored, reset, both, moved].map(\.authenticatedBytes)
        #expect(Set(forms).count == forms.count)
        // The restore's alone: its entries right after the earlier fields, nothing after them.
        #expect(
            Array(restored.authenticatedBytes.prefix(neither.authenticatedBytes.count)) == neither.authenticatedBytes)
        // The reset's alone carry an empty count of the restore's entries ahead of them.
        #expect(reset.authenticatedBytes.count > neither.authenticatedBytes.count + 8)
        // Both: the restore's entries, then the reset's fields.
        let entries = 8 + (16 + 1) + (8 + 16 + 1)
        #expect(both.authenticatedBytes.count == reset.authenticatedBytes.count + entries - 8)
        // The layout, byte for byte (V55). `earlier` is everything through `collectedThrough`, the same in all four
        // forms; the reset's fields with only `storeResetSuspected` set are three empty counts (the copies examined,
        // the unread copies, those examined), `handOnOwed`, no `ownUnlistedThrough` and its zero, no `handedOn`, a zero
        // `highestOwnSnapshot`, then `storeResetSuspected`.
        let earlier = Array(restored.authenticatedBytes.dropLast(entries))
        let zeroCount = [UInt8](repeating: 0, count: 8)
        var resetFields: [UInt8] = zeroCount + zeroCount + zeroCount
        resetFields += [0, 0] + zeroCount
        resetFields += [0] + zeroCount
        resetFields += [1]
        let restoredEntries = Array(restored.authenticatedBytes.suffix(entries))
        #expect(Array(restoredEntries.prefix(8)) == [0, 0, 0, 0, 0, 0, 0, 1])
        #expect(reset.authenticatedBytes == earlier + zeroCount + resetFields)
        #expect(both.authenticatedBytes == earlier + restoredEntries + resetFields)
        #expect(moved.authenticatedBytes == earlier + restoredEntries + resetFields + [1, 1])
        // The hygiene branch's form before the merge, the reset's fields straight after `collectedThrough`, is not
        // what is signed now, so a row saved in it no longer verifies (V55).
        #expect(reset.authenticatedBytes != earlier + resetFields)
    }

    @Test("what is signed does not depend on the order a dictionary happens to iterate in")
    func orderIndependent() {
        var first = SyncState(vaultID: SyncFixtures.vault)
        var second = SyncState(vaultID: SyncFixtures.vault)
        let devices = (0..<64).map { _ in UUID() }
        for (index, device) in devices.enumerated() { first.merged[device] = UInt64(index + 1) }
        for (index, device) in devices.enumerated().reversed() { second.merged[device] = UInt64(index + 1) }
        for n in UInt8(1)...40 {
            first.known[StateStoreFixtures.record(n).key] = RecordStamp(version: UInt64(n), device: devices[0])
        }
        for n in (UInt8(1)...40).reversed() {
            second.known[StateStoreFixtures.record(n).key] = RecordStamp(version: UInt64(n), device: devices[0])
        }
        #expect(first.authenticatedBytes == second.authenticatedBytes)
    }
}

/// The encoding `SQLiteSyncStateStore` writes, which is portable and so checked here on every platform.
@Suite("Sync state encoding")
struct SyncStateEncodingTests {
    @Test("every field survives the encoding")
    func roundTrip() throws {
        var state = StateStoreFixtures.state()
        let bytes = try JSONEncoder().encode(EncodedState(state))
        #expect(try JSONDecoder().decode(EncodedState.self, from: bytes).state == state)
        state.syncedBefore = true
        state.startedOverByMove = true
        state.storeResetSuspected = true
        let moved = try JSONEncoder().encode(EncodedState(state))
        #expect(try JSONDecoder().decode(EncodedState.self, from: moved).state == state)
    }

    @Test("a row written before the stash had a row of its own decodes as saved")
    func olderRow() throws {
        var state = StateStoreFixtures.state()
        var encoded = EncodedState(state)
        encoded.stashUnsaved = nil
        encoded.retryUnfinished = nil
        encoded.quarantineDropped = nil
        state.stashUnsaved = false
        state.retryUnfinished = false
        state.quarantineDropped = []
        let bytes = try JSONEncoder().encode(encoded)
        #expect(try JSONDecoder().decode(EncodedState.self, from: bytes).state == state)
    }
}

enum StashFixtures {
    static let record = UUID(uuidString: "5E000000-0000-4000-8000-000000000001")!
    static let key = UUID(uuidString: "5E000000-0000-4000-8000-0000000000EE")!

    static func stash() -> SyncStash {
        var stash = SyncStash()
        stash.insert(
            .init(
                entry: UnknownSyncEntry(
                    recordID: record, rawKind: 77, keyID: key, version: 5, device: SyncFixtures.deviceB,
                    envelope: [4, 5, 6]),
                author: SyncFixtures.deviceB))
        stash.insert(
            .init(
                entry: UnknownSyncEntry(
                    recordID: record, rawKind: 10, keyID: SyncPayload.zeroUUID, version: 6,
                    device: SyncFixtures.deviceA,
                    envelope: nil, erasure: [8]),
                author: SyncFixtures.deviceB))
        stash.overflow = [SyncFixtures.deviceC: [12, 99]]
        return stash
    }

    /// A stash's encoding with one entry, as `SyncStash.encoded()` lays it out, for rows `encoded()` would never write.
    static func row(kind: UInt8, keyID: UUID, version: UInt64 = 1, flags: UInt8, body: [UInt8]) -> [UInt8] {
        var out = Array("WWSK".utf8) + [2] + SyncPayload.littleEndian(UInt64(0)) + SyncPayload.littleEndian(UInt32(0))
        out += SyncPayload.littleEndian(UInt32(0)) + SyncPayload.littleEndian(UInt32(1))
        out += SyncPayload.bytes(SyncFixtures.deviceA) + SyncPayload.bytes(record) + [kind] + SyncPayload.bytes(keyID)
        out += SyncPayload.littleEndian(version) + SyncPayload.bytes(SyncFixtures.deviceA) + [flags]
        return out + SyncPayload.littleEndian(UInt32(body.count)) + body
    }
}

/// The stash's own encoding (ADR 0009): its row is in a file A8 can edit, so it is parsed as hostile.
@Suite("Sync stash encoding")
struct SyncStashEncodingTests {
    @Test("entries, their authors and what was dropped survive the encoding, in one canonical form")
    func roundTrip() throws {
        let stash = StashFixtures.stash()
        #expect(try SyncStash.parse(stash.encoded()) == stash)
        var reordered = SyncStash()
        for kept in stash.entries.reversed() { reordered.insert(kept) }
        reordered.overflow = stash.overflow
        #expect(reordered.encoded() == stash.encoded())
        #expect(stash.count == 2 && stash.usage(of: SyncFixtures.deviceB).count == 2)
    }

    @Test("every truncation is refused with a typed error")
    func truncation() {
        let bytes = StashFixtures.stash().encoded()
        for length in 0..<bytes.count {
            #expect(throws: SyncFormatError.self) { try SyncStash.parse(Array(bytes[..<length])) }
        }
        #expect(throws: SyncFormatError.trailingBytes) { try SyncStash.parse(bytes + [0]) }
    }

    /// A critical kind is never kept aside, so a row naming one was planted; processed, an item deletion would erase or
    /// trash an item.
    @Test("a row naming a critical kind, a keyed deletion, version zero or an empty envelope is refused")
    func plantedRows() {
        let zero = SyncPayload.zeroUUID
        #expect(throws: SyncFormatError.unsupportedRecordKind(0)) {
            try SyncStash.parse(StashFixtures.row(kind: 0, keyID: zero, flags: 1, body: []))
        }
        #expect(throws: SyncFormatError.unsupportedRecordKind(200)) {
            try SyncStash.parse(StashFixtures.row(kind: 200, keyID: StashFixtures.key, flags: 0, body: [1]))
        }
        #expect(throws: SyncFormatError.malformedEntry) {
            try SyncStash.parse(StashFixtures.row(kind: 10, keyID: StashFixtures.key, flags: 1, body: []))
        }
        #expect(throws: SyncFormatError.malformedEntry) {
            try SyncStash.parse(StashFixtures.row(kind: 10, keyID: StashFixtures.key, version: 0, flags: 0, body: [1]))
        }
        #expect(throws: SyncFormatError.malformedEntry) {
            try SyncStash.parse(StashFixtures.row(kind: 10, keyID: StashFixtures.key, flags: 0, body: []))
        }
        #expect(throws: SyncFormatError.unknownFlags(3)) {
            try SyncStash.parse(StashFixtures.row(kind: 10, keyID: StashFixtures.key, flags: 3, body: [1]))
        }
        var counted =
            Array("WWSK".utf8) + [2] + SyncPayload.littleEndian(UInt64(0)) + SyncPayload.littleEndian(UInt32(0))
        counted += SyncPayload.littleEndian(UInt32(0)) + SyncPayload.littleEndian(UInt32.max)
        #expect(throws: SyncFormatError.countTooLarge) { try SyncStash.parse(counted) }
    }
}

extension SyncStashEncodingTests {
    /// A row is in a file A8 can edit, and a quadratic parse of one crafted to put every entry in one slot took
    /// minutes (N16): parsing is `n log n` whatever the slots, and a declared count over the caller's cap is refused
    /// before a single entry is read.
    @Test("a row of many entries in one slot parses in time, and one over the caps is refused from its header")
    func hostileRowCost() throws {
        var stash = SyncStash()
        for version in 1...8192 {
            stash.insert(
                .init(
                    entry: UnknownSyncEntry(
                        recordID: StashFixtures.record, rawKind: 99, keyID: SyncPayload.zeroUUID,
                        version: UInt64(version), device: SyncFixtures.deviceA, envelope: nil, erasure: [7]),
                    author: SyncFixtures.deviceA))
        }
        let bytes = stash.encoded()
        let clock = ContinuousClock()
        let started = clock.now
        let parsed = try SyncStash.parse(bytes)
        #expect(clock.now - started < .seconds(5))
        #expect(parsed == stash && parsed.count == 8192)
        #expect(throws: SyncFormatError.countTooLarge) { try SyncStash.parse(bytes, maximumEntries: 4096) }
        #expect(throws: SyncFormatError.countTooLarge) { try SyncStash.parse(bytes, maximumBytes: 1 << 10) }
    }
}

/// One contract, every `SyncStateStore` (docs/02-architecture.md §6): the in-memory one the simulations use, and the
/// SQLite one the app uses.
@Suite("Sync state store contract")
struct SyncStateStoreContractTests {
    @Test("state round-trips with every field, per vault", arguments: StateStoreKind.available)
    func stateRoundTrip(_ kind: StateStoreKind) async throws {
        let store = try kind.make()
        #expect(try await store.loadState(vaultID: SyncFixtures.vault) == nil)
        let state = StateStoreFixtures.state()
        try await store.saveState(state)
        #expect(try await store.loadState(vaultID: SyncFixtures.vault) == state)
        #expect(try await store.loadState(vaultID: SyncFixtures.otherVault) == nil)
        var next = state
        next.nextSequence = 10
        try await store.saveState(next)
        #expect(try await store.loadState(vaultID: SyncFixtures.vault) == next)
    }

    @Test("the stash has a row of its own per vault, replaced whole", arguments: StateStoreKind.available)
    func stashRow(_ kind: StateStoreKind) async throws {
        let store = try kind.make()
        #expect(try await store.stash(vaultID: SyncFixtures.vault) == nil)
        let bytes = StashFixtures.stash().encoded()
        try await store.saveStash(bytes, vaultID: SyncFixtures.vault)
        try await store.saveState(StateStoreFixtures.state())
        #expect(try await store.stash(vaultID: SyncFixtures.vault) == bytes)
        #expect(try await store.stash(vaultID: SyncFixtures.otherVault) == nil)
        try await store.saveStash(SyncStash().encoded(), vaultID: SyncFixtures.vault)
        #expect(try await store.stash(vaultID: SyncFixtures.vault) == SyncStash().encoded())
        try await store.eraseAll()
        #expect(try await store.stash(vaultID: SyncFixtures.vault) == nil)
    }

    @Test("staged objects are kept by location and unstaged by location", arguments: StateStoreKind.available)
    func staging(_ kind: StateStoreKind) async throws {
        let store = try kind.make()
        let first = StagedObject(
            location: .segment(vaultID: SyncFixtures.vault, author: SyncFixtures.deviceB, sequence: 1),
            object: SignedObject(signature: [9, 9], envelope: [1, 2, 3]))
        let second = StagedObject(
            location: .snapshot(vaultID: SyncFixtures.vault, author: SyncFixtures.deviceB, lamport: 4),
            object: SignedObject(signature: [8], envelope: [4, 5]))
        try await store.stage(first)
        try await store.stage(second)
        try await store.stage(first)
        #expect(Set(try await store.staged(vaultID: SyncFixtures.vault)) == [first, second])
        #expect(try await store.staged(vaultID: SyncFixtures.otherVault).isEmpty)
        try await store.unstage([first.location])
        #expect(try await store.staged(vaultID: SyncFixtures.vault) == [second])
    }

    @Test(
        "a pending deletion is replaced only by a newer one, and removed only if unchanged",
        arguments: StateStoreKind.available)
    func pendingDeletions(_ kind: StateStoreKind) async throws {
        let store = try kind.make()
        let row = StateStoreFixtures.record(1)
        let older = PendingDeletion(
            stamp: RecordStamp(version: 4, device: SyncFixtures.deviceA, deleted: true), record: row)
        let newer = PendingDeletion(
            stamp: RecordStamp(version: 6, device: SyncFixtures.deviceA, deleted: true), record: row)
        try await store.addPendingDeletion(newer)
        try await store.addPendingDeletion(older)
        #expect(try await store.pendingDeletions(vaultID: SyncFixtures.vault) == [row.key: newer])
        try await store.removePendingDeletions([row.key: older.stamp], vaultID: SyncFixtures.vault)
        #expect(try await store.pendingDeletions(vaultID: SyncFixtures.vault) == [row.key: newer])
        try await store.removePendingDeletions([row.key: newer.stamp], vaultID: SyncFixtures.vault)
        #expect(try await store.pendingDeletions(vaultID: SyncFixtures.vault).isEmpty)
    }

    @Test("the quarantine keeps each entry once until it is discarded (F7.7)", arguments: StateStoreKind.available)
    func quarantine(_ kind: StateStoreKind) async throws {
        let store = try kind.make()
        let live = SyncFixtures.entry(1, version: 1 << 50)
        let tombstone = SyncEntry.tombstone(
            StateStoreFixtures.record(2).key, stamp: RecordStamp(version: 1 << 51, device: SyncFixtures.deviceB),
            erasure: [7, 7])
        #expect(try await store.quarantine(live, vaultID: SyncFixtures.vault))
        #expect(try await store.quarantine(tombstone, vaultID: SyncFixtures.vault))
        #expect(try await !store.quarantine(live, vaultID: SyncFixtures.vault), "held already: not added again")
        #expect(try await store.quarantined(vaultID: SyncFixtures.vault) == [live, tombstone])
        try await store.discardQuarantined([tombstone], vaultID: SyncFixtures.vault)
        #expect(try await store.quarantined(vaultID: SyncFixtures.vault) == [live])
    }

    /// Review finding Z27: an entry is found without reading the quarantine, whole entries are compared (two that
    /// differ in one byte are two), and what a vault holds is counted per writing device.
    @Test(
        "the quarantine finds an entry and counts what it holds, per vault and device",
        arguments: StateStoreKind.available)
    func quarantineLookupAndUsage(_ kind: StateStoreKind) async throws {
        let store = try kind.make()
        let first = SyncFixtures.entry(4, version: 9)
        var sameStamp = first
        sameStamp.envelope?[0] ^= 1
        let other = SyncFixtures.entry(5, version: 9, device: SyncFixtures.deviceB)
        let tombstone = SyncEntry.tombstone(
            StateStoreFixtures.record(2).key, stamp: RecordStamp(version: 12, device: SyncFixtures.deviceB),
            erasure: [7, 7, 7])
        #expect(try await store.quarantineUsage(vaultID: SyncFixtures.vault) == QuarantineUsage())
        for entry in [first, sameStamp, other, tombstone] {
            #expect(try await !store.holdsQuarantined(entry, vaultID: SyncFixtures.vault))
            #expect(try await store.quarantine(entry, vaultID: SyncFixtures.vault))
            #expect(try await store.holdsQuarantined(entry, vaultID: SyncFixtures.vault))
            #expect(try await !store.holdsQuarantined(entry, vaultID: SyncFixtures.otherVault))
        }
        let usage = try await store.quarantineUsage(vaultID: SyncFixtures.vault)
        #expect(
            usage.devices == [
                SyncFixtures.deviceA: .init(entries: 2, bytes: 2 * first.storedLength),
                SyncFixtures.deviceB: .init(entries: 2, bytes: other.storedLength + 3),
            ])
        #expect(usage.entries == 4)
        #expect(try await store.quarantineUsage(vaultID: SyncFixtures.otherVault).entries == 0)
        try await store.discardQuarantined([sameStamp, tombstone], vaultID: SyncFixtures.vault)
        #expect(try await store.quarantined(vaultID: SyncFixtures.vault) == [first, other])
        #expect(try await !store.holdsQuarantined(sameStamp, vaultID: SyncFixtures.vault))
        #expect(try await store.quarantineUsage(vaultID: SyncFixtures.vault).entries == 2)
    }

    @Test("eraseAll removes everything", arguments: StateStoreKind.available)
    func erase(_ kind: StateStoreKind) async throws {
        let store = try kind.make()
        try await store.saveState(StateStoreFixtures.state())
        try await store.addPendingDeletion(
            PendingDeletion(
                stamp: RecordStamp(version: 4, device: SyncFixtures.deviceA, deleted: true),
                record: StateStoreFixtures.record(1)))
        try await store.quarantine(SyncFixtures.entry(1), vaultID: SyncFixtures.vault)
        try await store.eraseAll()
        #expect(try await store.loadState(vaultID: SyncFixtures.vault) == nil)
        #expect(try await store.pendingDeletions(vaultID: SyncFixtures.vault).isEmpty)
        #expect(try await store.quarantined(vaultID: SyncFixtures.vault).isEmpty)
    }
}

#if canImport(SQLite3)
    @Suite("SQLite sync state store")
    struct SQLiteSyncStateStoreTests {
        @Test("everything survives closing and reopening the database")
        func persistence() async throws {
            let url = StateStoreFixtures.temporaryURL()
            let deletion = PendingDeletion(
                stamp: RecordStamp(version: 4, device: SyncFixtures.deviceA, deleted: true),
                record: StateStoreFixtures.record(1))
            do {
                let store = try SQLiteSyncStateStore(url: url)
                try store.saveState(StateStoreFixtures.state())
                try store.addPendingDeletion(deletion)
                try store.quarantine(SyncFixtures.entry(3), vaultID: SyncFixtures.vault)
            }
            let reopened = try SQLiteSyncStateStore(url: url)
            #expect(try reopened.loadState(vaultID: SyncFixtures.vault) == StateStoreFixtures.state())
            #expect(try reopened.pendingDeletions(vaultID: SyncFixtures.vault) == [deletion.record.key: deletion])
            #expect(try reopened.quarantined(vaultID: SyncFixtures.vault) == [SyncFixtures.entry(3)])
        }

        @Test("a state row that does not decode is no state, so the next sync replays the log")
        func damagedStateIsAbsent() throws {
            let url = StateStoreFixtures.temporaryURL()
            let store = try SQLiteSyncStateStore(url: url)
            try store.saveState(StateStoreFixtures.state())
            let raw = try SQLiteConnection(path: SQLiteRecordStore.resolvingSymlinks(url.path))
            try raw.query("UPDATE sync_state SET state = ?", [.blob(Array("{not json".utf8))])
            #expect(try store.loadState(vaultID: SyncFixtures.vault) == nil)
        }

        @Test("a planted trigger makes the database refuse to open (review finding S1)")
        func plantedTrigger() throws {
            let url = StateStoreFixtures.temporaryURL()
            _ = try SQLiteSyncStateStore(url: url)
            let raw = try SQLiteConnection(path: SQLiteRecordStore.resolvingSymlinks(url.path))
            try raw.execute(
                "CREATE TRIGGER keep BEFORE DELETE ON pending_deletions BEGIN SELECT RAISE(IGNORE); END")
            raw.close()
            #expect(throws: RecordStoreError.unexpectedSchema("keep")) { _ = try SQLiteSyncStateStore(url: url) }
        }

        @Test("a version 1 database gains the stash table and keeps what it held")
        func migratesFromVersion1() throws {
            let url = StateStoreFixtures.temporaryURL()
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let directory = try SQLiteRecordStore.resolvingSymlinks(url.deletingLastPathComponent().path)
            let path = URL(fileURLWithPath: directory, isDirectory: true).appendingPathComponent(url.lastPathComponent)
            let raw = try SQLiteConnection(path: path.path)
            for table in [
                SQLiteSyncStateStore.stateTable, SQLiteSyncStateStore.stagedTable, SQLiteSyncStateStore.pendingTable,
                SQLiteSyncStateStore.legacyQuarantineTable,
            ] {
                try raw.execute(table)
            }
            // What an earlier version had kept aside: a live version and a deletion.
            let kept = [SyncFixtures.entry(3, version: 1 << 40), SyncFixtures.entry(4, version: 7, deleted: true)]
            for entry in kept {
                try raw.query(
                    """
                    INSERT INTO quarantine (vault_id, record_id, kind, key_id, version, device_id, envelope, erasure)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        SQLiteRecordStore.value(SyncFixtures.vault), SQLiteRecordStore.value(entry.recordID),
                        .integer(Int64(entry.kind.rawValue)), SQLiteRecordStore.value(entry.keyID),
                        .integer(Int64(bitPattern: entry.version)), SQLiteRecordStore.value(entry.device),
                        entry.envelope.map(SQLiteValue.blob) ?? .null, .blob(entry.erasure),
                    ])
            }
            try raw.execute("PRAGMA user_version = 1")
            raw.close()

            let store = try SQLiteSyncStateStore(url: url)
            try store.saveState(StateStoreFixtures.state())
            #expect(try store.stash(vaultID: SyncFixtures.vault) == nil)
            let bytes = StashFixtures.stash().encoded()
            try store.saveStash(bytes, vaultID: SyncFixtures.vault)
            let reopened = try SQLiteSyncStateStore(url: url)
            #expect(try reopened.stash(vaultID: SyncFixtures.vault) == bytes)
            #expect(try reopened.loadState(vaultID: SyncFixtures.vault) == StateStoreFixtures.state())
            let version = try SQLiteConnection(path: path.path).query("PRAGMA user_version").first?.first
            #expect(version == .integer(3))
            // The quarantine is carried into the indexed table (Z27): nothing kept is lost, and each entry is found.
            #expect(try reopened.quarantined(vaultID: SyncFixtures.vault) == kept)
            for entry in kept {
                #expect(try reopened.holdsQuarantined(entry, vaultID: SyncFixtures.vault))
                #expect(try !reopened.quarantine(entry, vaultID: SyncFixtures.vault))
            }
            #expect(try reopened.quarantineUsage(vaultID: SyncFixtures.vault).entries == 2)
        }

        @Test("a database from a newer schema is refused, not misread")
        func newerSchema() throws {
            let url = StateStoreFixtures.temporaryURL()
            _ = try SQLiteSyncStateStore(url: url)
            try SQLiteConnection(path: SQLiteRecordStore.resolvingSymlinks(url.path)).execute("PRAGMA user_version = 4")
            #expect(throws: RecordStoreError.unsupportedSchemaVersion(4)) { _ = try SQLiteSyncStateStore(url: url) }
        }
    }
#endif
