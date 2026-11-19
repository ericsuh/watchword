import Foundation
import Testing
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordKit
@testable import WatchwordSync

// The deletion gate and a version kept after this device's own deletion (docs/06-adversarial-review.md V44, V46).
extension AdversarialVaultSyncTests {
    /// Threat: no adversary; the rule is F7.6 (nothing exists on one device alone while a deletion elsewhere goes out)
    /// against liveness. A deletes an item for good while B's edit of it, which A had not seen, is in flight, and A's
    /// own stream is stopped (an object at its next number, which anyone who can create a file can put there), so A
    /// merges and publishes nothing. Merging keeps a version after the deletion, written by A, that waits behind the
    /// tombstone. That version holds nothing of A's the deletion had not seen and holds no other vault's deletions
    /// back (V44: counted, the two waited for each other for good). Restored from the trash and edited, it holds an
    /// edit the deletion never saw: where the vault is not published it holds them back like any unpublished edit
    /// (V46), and where it is, it goes out behind its tombstone, so the stream freed, everything goes out.
    @Test("a version kept after this device's own deletion goes out behind it, and once edited counts where it cannot")
    func keptVersionBehindOwnDeletion() async throws {
        let f = try await Self.fixture()
        let c = try await f.reader()
        try await f.a.session.sync()
        try await c.session.sync()
        let itemID = try #require(try await f.a.session.items().items.first?.id)
        let deviceA = try #require(try await f.a.store.loadAccount()?.deviceID)

        // A and C each delete the item; B's edit, which neither had seen, is concurrent with both. C's tombstone is
        // kept from B until B has published (as two devices syncing at once would), so the record's latest stamp in
        // the log is C's deletion, and A knows it only as a deletion (Z148's rule).
        try await f.a.session.trash(id: itemID)
        try await f.a.session.deletePermanently(id: itemID)
        try await c.session.trash(id: itemID)
        try await c.session.deletePermanently(id: itemID)
        let before = Set(await f.transport.allObjects.keys)
        try await c.session.sync()
        let objects = await f.transport.allObjects
        let fromC = objects.filter { !before.contains($0.key) }
        for name in fromC.keys { await f.transport.tamper(name, contents: nil) }
        var onB = try await f.b.session.item(id: itemID)
        onB.title = "Bank, renamed on B"
        _ = try await f.b.session.save(onB)
        try await f.b.session.sync()
        for (name, bytes) in fromC { await f.transport.tamper(name, contents: bytes) }

        let next = try #require(try await f.a.session.syncState?.loadState(vaultID: f.vaultID)).nextSequence
        let squatted = SyncObjectLocation.segment(vaultID: f.vaultID, author: deviceA, sequence: next).name
        await f.transport.tamper(squatted, contents: [0x57, 0x57])
        let stopped = try await f.a.session.sync()
        #expect(stopped.ownStreamConflict != nil, "A's stream was not stopped: nothing is tested")
        let pending = try await f.a.session.syncState?.pendingDeletions(vaultID: f.vaultID) ?? [:]
        #expect(pending[RecordKey(recordID: itemID, kind: .item)] != nil, "A's deletion is no longer pending")
        let kept = try await f.a.session.item(id: itemID)
        #expect(kept.keptAfterDeletion)
        let known = try await f.a.session.syncState?.loadState(vaultID: f.vaultID)?.known
        #expect(known?[RecordKey(recordID: itemID, kind: .item)]?.deleted == true, "the record is not known deleted")

        let account = try #require(try await f.a.store.loadAccount())
        let keptHolds = await f.a.session.holdsUnpublishedWork(in: f.vaultID, account: account)
        #expect(!keptHolds, "a version kept after the deletion holds every deletion back")

        try await f.a.session.restore(id: itemID)
        var edited = try await f.a.session.item(id: itemID)
        edited.title = "Bank, kept and edited on A"
        _ = try await f.a.session.save(edited)
        let editedHolds = await f.a.session.holdsUnpublishedWork(in: f.vaultID, account: account)
        #expect(editedHolds, "an edit the deletion never saw, in a vault not published, holds nothing back")
        let editedPublished = await f.a.session.holdsUnpublishedWork(
            in: f.vaultID, account: account, publishing: true)
        #expect(!editedPublished, "where the vault is published, the edited version and its deletion wait for good")

        await f.transport.tamper(squatted, contents: nil)
        try await f.a.session.sync()
        let left = try await f.a.session.syncState?.pendingDeletions(vaultID: f.vaultID) ?? [:]
        #expect(left.isEmpty, "A's deletion never went out")
        try await f.b.session.sync()
        let onBAfter = try await f.b.session.item(id: itemID)
        #expect(onBAfter.title == "Bank, kept and edited on A")
    }
}
