import Foundation
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordKit
@testable import WatchwordSync

// The review of the engine's third round (docs/06-adversarial-review.md §Z, rows from Z144), with real keys.
extension AdversarialVaultSyncTests {
    /// Threat: an insider device of the account (B), which can sign a snapshot of any vault attributing entries to any
    /// device. A move's copy takes an ID derived from the original's ID, the destination, the device and the version,
    /// all known to whoever reads the source vault. B snapshots the destination with a tombstone for that ID before
    /// the copy exists. Z138 stopped it counting as published, but the stamp still went into what the sync layer
    /// knows of the record, and the deletion gate (`holdsUnpublishedWork`) took a record it knows for one that exists
    /// elsewhere: if the copy's vault could not publish in that sync, the original's deletion went out while the copy
    /// existed on this device alone. A record known only by a deletion holds the gate while its row holds an edit of
    /// this device's above what it published.
    @Test("a move's copy known only by a planted tombstone still holds its original's deletion back")
    func plantedTombstoneForAMovesCopy() async throws {
        let f = try await Self.fixture()
        try await f.a.session.sync()
        let destination = try await f.a.session.createVault(name: "Other").id
        try await f.a.session.sync()
        try await f.b.session.sync()
        let original = try await f.a.session.save(
            Item(
                vaultID: f.vaultID, title: "To move", scopes: [ServiceScope(host: "example.org")],
                fields: [Field(kind: .password, label: "Password", value: "moved")]))
        try await f.a.session.sync()
        let row = try #require(try await f.a.store.record(RecordKey(recordID: original.id, kind: .item)))
        let copyID = VaultSession.movedItemID(of: row, to: destination)
        let deviceA = try #require(try await f.a.store.loadAccount()?.deviceID)

        let summary = try ItemErasure(seen: VersionVector([deviceA: 5000]), row: 5000, device: deviceA, date: nil)
            .summary()
        let tombstone = SyncEntry.tombstone(
            RecordKey(recordID: copyID, kind: .item), stamp: RecordStamp(version: 5001, device: deviceA, deleted: true),
            erasure: summary)
        let location = SyncObjectLocation.snapshot(vaultID: destination, author: Self.deviceB, lamport: 9000)
        let payload = SyncPayload(
            kind: .snapshot, vaultID: destination, author: Self.deviceB, number: 9000, vector: [:],
            entries: [tombstone])
        let envelope = try await f.b.session.syncSeal(payload.encoded(), at: location)
        let signature = try await f.b.session.syncSign(envelope, at: location)
        await f.transport.tamper(
            location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())
        try await f.a.session.sync()
        let known = try await f.a.session.syncState?.loadState(vaultID: destination)?.known
        #expect(known?[RecordKey(recordID: copyID, kind: .item)] != nil, "the tombstone was not met: nothing is tested")

        _ = try await f.a.session.move(itemID: original.id, to: destination)
        let account = try #require(try await f.a.store.loadAccount())
        #expect(
            await f.a.session.holdsUnpublishedWork(in: destination, account: account),
            "a copy that exists on this device alone does not hold its original's deletion back")
        // And the hold ends: once the copy's vault publishes, the original's deletion goes out after it.
        try await f.a.session.sync()
        #expect(await !f.a.session.holdsUnpublishedWork(in: destination, account: account), "the gate never opens")
        try await f.b.session.sync()
        #expect((try? await f.b.session.item(id: original.id)) == nil, "the original's deletion never went out")
    }

    /// Threat: A8, who can edit the sync state's file, together with the tombstone of `plantedTombstoneForAMovesCopy`
    /// (an insider device's snapshot here; in a shared vault a writing member's, A4, or the owner's). The Z148 gate
    /// bounds a row's own edits by the higher of what this device published and its own pending deletion of the
    /// record (Z202). It read the pending deletions from the raw store, so a row planted for the move's copy, stamped
    /// by this device far above its edits and signed by nobody, raised the bound over the copy's edits, and the
    /// original's deletion went out while the copy existed on this device alone. Only a deletion the session signed
    /// counts there now (review of round 14, M1; Z203).
    @Test("a planted pending deletion of a move's copy does not let its original's deletion go out")
    func plantedPendingDeletionForAMovesCopy() async throws {
        let f = try await Self.fixture()
        try await f.a.session.sync()
        let destination = try await f.a.session.createVault(name: "Other").id
        try await f.a.session.sync()
        try await f.b.session.sync()
        let original = try await f.a.session.save(
            Item(
                vaultID: f.vaultID, title: "To move", scopes: [ServiceScope(host: "example.org")],
                fields: [Field(kind: .password, label: "Password", value: "moved")]))
        try await f.a.session.sync()
        let row = try #require(try await f.a.store.record(RecordKey(recordID: original.id, kind: .item)))
        let copyID = VaultSession.movedItemID(of: row, to: destination)
        let copyKey = RecordKey(recordID: copyID, kind: .item)
        let deviceA = try #require(try await f.a.store.loadAccount()?.deviceID)

        let summary = try ItemErasure(seen: VersionVector([deviceA: 5000]), row: 5000, device: deviceA, date: nil)
            .summary()
        let tombstone = SyncEntry.tombstone(
            copyKey, stamp: RecordStamp(version: 5001, device: deviceA, deleted: true), erasure: summary)
        let location = SyncObjectLocation.snapshot(vaultID: destination, author: Self.deviceB, lamport: 9000)
        let payload = SyncPayload(
            kind: .snapshot, vaultID: destination, author: Self.deviceB, number: 9000, vector: [:],
            entries: [tombstone])
        let envelope = try await f.b.session.syncSeal(payload.encoded(), at: location)
        let signature = try await f.b.session.syncSign(envelope, at: location)
        await f.transport.tamper(
            location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())
        try await f.a.session.sync()
        let known = try await f.a.session.syncState?.loadState(vaultID: destination)?.known
        #expect(known?[copyKey]?.deleted == true, "the tombstone was not met: nothing is tested")

        _ = try await f.a.session.move(itemID: original.id, to: destination)
        let copy = try #require(try await f.a.store.record(copyKey))
        let raw = try #require(f.a.sync?.state)
        let planted = PendingDeletion(
            stamp: RecordStamp(version: 1 << 40, device: deviceA, deleted: true), record: copy,
            authenticator: [UInt8](repeating: 0x5A, count: 64))
        try await raw.addPendingDeletion(planted)
        let stored = try await raw.pendingDeletions(vaultID: destination)
        #expect(stored[copyKey] != nil, "the row was not planted: nothing is tested")
        let checked = try await f.a.session.syncState?.pendingDeletions(vaultID: destination)
        #expect(checked?[copyKey] == nil, "the planted row verifies")

        let account = try #require(try await f.a.store.loadAccount())
        let holds = await f.a.session.holdsUnpublishedWork(in: destination, account: account)
        #expect(holds, "a planted pending deletion let the original's deletion go out ahead of its copy")
    }
}
