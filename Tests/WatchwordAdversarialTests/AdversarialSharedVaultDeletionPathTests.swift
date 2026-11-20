import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

// Review finding Z44 (docs/06-adversarial-review.md): three write paths did not ask whether this account may write.
extension AdversarialSharedVaultTests {
    /// Threat: a read-only member (A4) using the stock client; a rule the client keeps (F4.5), which it did not keep
    /// on three paths. A permanent deletion, the 30-day purge of the trash and the removal of a moved item's original
    /// never asked `writePermission`. They took effect on the member's device, where the pending deletion counts as
    /// an erasure in every merge, and stayed queued, signed, to be published the day the member was allowed to write:
    /// tombstones for things done while read-only. None of them happens now, nothing is queued, and a copy out of the
    /// vault, which writes nothing there, still works.
    @Test(
        "a read-only member's device deletes nothing from a shared vault: not for good, not by the purge, not by a move"
    )
    func readOnlyMemberDeletesNothing() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readOnly], seed: 960)
        let (owner, reader) = (home.owner, home.members[0])
        let vaultID = home.vaultID
        let kept = try await owner.session.save(Self.bank(in: vaultID))
        let trashed = try await owner.session.save(Self.bank(in: vaultID))
        try await owner.session.trash(id: trashed.id)
        try await Self.syncAll([owner, reader])
        let personal = try #require(await reader.session.personalVaultID)
        let syncState = try #require(reader.vault.sync?.state)

        await #expect(throws: SharedVaultError.writeRefused(.readOnly)) {
            try await reader.session.move(itemID: kept.id, to: personal)
        }
        await #expect(throws: SharedVaultError.writeRefused(.readOnly)) {
            try await reader.session.deletePermanently(id: trashed.id)
        }
        // The purge runs at every password unlock; thirty-one days on, the owner's trashed item is due.
        await reader.vault.clock.advance(by: 31 * 24 * 60 * 60)
        try await reader.session.purgeExpiredTrash()
        #expect(try await reader.session.items(in: vaultID).items.count == 2)
        #expect(try await reader.session.items(in: personal).items.isEmpty, "the move left its copy behind")
        #expect(try await syncState.pendingDeletions(vaultID: vaultID).isEmpty, "a deletion was queued while read-only")

        // Reading is theirs: a copy into their own vault writes nothing in the shared one.
        _ = try await reader.session.copy(itemID: kept.id, to: personal)
        #expect(try await reader.session.items(in: personal).items.count == 1)

        // Made a writer, nothing from before is published, and the same actions are now theirs to take.
        try await owner.session.changeRole(of: reader.accountID, in: vaultID, to: .readWrite)
        try await Self.syncAll([owner, reader])
        #expect(try await owner.session.items(in: vaultID).items.count == 2)
        try await reader.session.deletePermanently(id: trashed.id)
        try await Self.syncAll([reader, owner])
        #expect(try await owner.session.items(in: vaultID).items.map(\.id) == [kept.id])
    }

    /// Threat: none needed. A move is a copy in one vault's log and a deletion in another's, and the deletion must
    /// never reach other devices without the copy (PRD F7.6). A member moves an item from their Personal vault into a
    /// shared one and is made read-only there before the device syncs. The copy is then a write made after the cut:
    /// it is not published, and it is taken out of the vault and held aside for the person. Published alone, the
    /// Personal vault's deletion would erase the item on the member's other devices with its only copy in one device's
    /// quarantine. It waits; what releases it is the person discarding the held-aside copy, which is theirs to do.
    @Test("a move's deletion is not published while its copy has reached nobody")
    func moveDeletionWaitsForItsCopy() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 970)
        let (owner, member) = (home.owner, home.members[0])
        let personal = try #require(await member.session.personalVaultID)
        var own = Self.bank(in: personal)
        own.title = "Mine, moved"
        let original = try await member.session.save(own)
        try await member.session.sync()
        let syncState = try #require(member.vault.sync?.state)

        let moved = try await member.session.move(itemID: original.id, to: home.vaultID)
        try await owner.session.changeRole(of: member.accountID, in: home.vaultID, to: .readOnly)
        try await member.session.sync()
        #expect(try await owner.session.items(in: home.vaultID).items.isEmpty, "the copy was published after all")
        #expect(
            try await syncState.pendingDeletions(vaultID: personal).count == 1,
            "the original's deletion went out and its copy did not")

        // Allowed to write again, the copy is still nobody's but this device's: it was written outside the cut.
        try await owner.session.changeRole(of: member.accountID, in: home.vaultID, to: .readWrite)
        try await Self.syncAll([member, owner])
        let heldAside = try await member.session.quarantine().filter {
            $0.vaultID == home.vaultID && $0.entry.recordID == moved.id
        }
        #expect(heldAside.count == 1, "the copy is kept for the person")
        #expect(try await syncState.pendingDeletions(vaultID: personal).count == 1, "the deletion left without it")

        // The person looks at what was held aside and discards it: only then does the deletion go.
        try await member.session.discardQuarantined(heldAside)
        try await member.session.sync()
        #expect(try await syncState.pendingDeletions(vaultID: personal).isEmpty)
    }
}
