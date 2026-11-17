import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// Review findings Z54 and Z55 (docs/06-adversarial-review.md): the gate that holds deletions back for a move's copy.
extension AdversarialSharedVaultTests {
    /// Threat: a current member who may write (A4). Z44 holds every vault's deletions back while some vault holds an
    /// item of this device's that exists nowhere else, and it counted every held-aside entry that *names* this
    /// device. An entry's device is its writer's claim. The insider signs a segment into the stream named after the
    /// victim's device (S33, Z46), carrying a new item; the victim's device rightly holds it aside, and from then on
    /// it published no deletion in any vault, the Personal one included, for as long as the entry was kept or the
    /// insider cared to plant another. Only what this device's own take-out put aside is its own unpublished work.
    @Test("an entry planted under this device's name does not stop its deletions going out")
    func plantedEntryDoesNotHoldDeletionsBack() async throws {
        let setting = try await SquattedStream.make(seed: 5410)
        let (victim, rogue) = (setting.victim, setting.rogue)
        let personal = try #require(await victim.session.personalVaultID)
        let syncState = try #require(victim.vault.sync?.state)
        var own = Self.bank(in: personal)
        own.title = "The victim's own"
        own = try await victim.session.save(own)
        try await victim.session.sync()

        var planted = Self.bank(in: setting.vaultID)
        planted.title = "Planted under the victim's device ID"
        _ = try await rogue.session.save(planted)
        try await rogue.session.sync()
        try await victim.session.sync()
        #expect(try await victim.session.sharedVaultStatus(setting.vaultID).heldAside > 0)

        try await victim.session.trash(id: own.id)
        try await victim.session.deletePermanently(id: own.id)
        try await victim.session.sync()
        #expect(
            try await syncState.pendingDeletions(vaultID: personal).isEmpty,
            "the victim's own deletion is held back by an entry someone else wrote")
    }

    /// Threat: none; the order of one sync. A member moves an item from one shared vault into another and is made
    /// read-only in the second before the device syncs: the copy is a write after the cut, taken out and held aside,
    /// and the first vault's deletion waits for it (Z44). But a shared vault whose log has to be replayed a second
    /// time in the same sync (here its saved stream index was lost, so the index is rebuilt and then judged against)
    /// went through a pass that published its pending deletions without asking: the original was erased for
    /// everyone while its only copy sat in one device's quarantine. A replay defers deletions like any other pass,
    /// and they go out last, after every replay, if nothing holds them back then.
    @Test("a replay does not publish the deletions that are waiting for a move's copy")
    func replayDoesNotPublishHeldDeletions() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 5510)
        let member = try await household.account(seed: 5511)
        let first = try await owner.session.createVault(name: "First").id
        let second = try await owner.session.createVault(name: "Second").id
        for vaultID in [first, second] {
            try await owner.session.shareVault(vaultID)
            try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        }
        let item = try await owner.session.save(Self.bank(in: first))
        try await Self.syncAll([owner, member])
        let syncState = try #require(member.vault.sync?.state)

        let moved = try await member.session.move(itemID: item.id, to: second)
        // Before the member's device syncs: read-only where the copy went.
        try await owner.session.changeRole(of: member.accountID, in: second, to: .readOnly)
        // And the device starts again without its saved index of the vault the item came from.
        await member.session.lock()
        await member.state.tamper(.streamIndex, vaultID: first, value: nil)
        let relaunched = member.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)

        let report = try await relaunched.session.syncAll()
        #expect(report.deletionsHeldBack == [second], "nothing tells the person why their deletion is waiting")
        try await owner.session.sync()
        #expect(try await owner.session.items(in: second).items.isEmpty, "the copy was published after all")
        #expect(
            try await owner.session.items(in: first).items.map(\.id) == [item.id],
            "the original was erased with its copy held aside on one device")
        #expect(try await syncState.pendingDeletions(vaultID: first).count == 1)
        let heldAside = try await relaunched.session.quarantine().filter { $0.entry.recordID == moved.id }
        #expect(heldAside.count == 1)

        // The person discards the copy that was held aside: then, and only then, the deletion goes.
        try await relaunched.session.discardQuarantined(heldAside)
        try await relaunched.session.sync()
        try await owner.session.sync()
        #expect(try await syncState.pendingDeletions(vaultID: first).isEmpty)
        #expect(try await owner.session.items(in: first).items.isEmpty)
    }

    /// Threat: none needed; a member who may write deletes an item for good, and is made read-only before their
    /// device has synced (review finding Z57). The deletion is outside the cut the demotion carries, like any write
    /// of theirs the others had not seen: published late it would be held aside by everyone. Unpublished, it used to
    /// stay queued and signed on their device, where it counted as an erasure in every merge, and went out on the
    /// day they were allowed to write again, months later perhaps, with nothing asking. It is withdrawn with the
    /// rest of what no longer counts: the item is back on their device, and nothing waits to be published.
    @Test("a deletion not yet published when its author was made read-only is withdrawn, not kept for a later day")
    func deletionUnpublishedAtDemotion() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 975)
        let (owner, member) = (home.owner, home.members[0])
        let vaultID = home.vaultID
        let item = try await owner.session.save(Self.bank(in: vaultID))
        try await owner.session.trash(id: item.id)
        try await Self.syncAll([owner, member])
        let syncState = try #require(member.vault.sync?.state)

        try await member.session.deletePermanently(id: item.id)
        #expect(try await syncState.pendingDeletions(vaultID: vaultID).count == 1)
        try await owner.session.changeRole(of: member.accountID, in: vaultID, to: .readOnly)
        try await Self.syncAll([owner, member])
        try await Self.syncAll([owner, member])
        #expect(
            try await syncState.pendingDeletions(vaultID: vaultID).isEmpty,
            "the deletion is still queued, to go out when they may write again")
        #expect(try await member.session.items(in: vaultID).items.map(\.id) == [item.id])

        try await owner.session.changeRole(of: member.accountID, in: vaultID, to: .readWrite)
        try await Self.syncAll([owner, member])
        try await Self.syncAll([owner, member])
        #expect(
            try await owner.session.items(in: vaultID).items.map(\.id) == [item.id],
            "a deletion made before the demotion was published after the promotion")
        // Theirs to make again, now that it counts.
        try await member.session.deletePermanently(id: item.id)
        try await Self.syncAll([member, owner])
        #expect(try await owner.session.items(in: vaultID).items.isEmpty)
    }

    /// Threat: someone with the device's files (A8), or a restore that loses the sharing state. A member moves an
    /// item from their own vault into a shared one: a copy there, and the original's deletion queued here. Before
    /// the device syncs, its saved ledger is gone, so the shared vault is held closed and nothing is published to
    /// it (Z41). The copy exists on this device alone, and the deletion must wait for it: published now, the
    /// account's other devices would erase the original while the only copy sat here (PRD F7.6). This is the gate's
    /// first clause, a row this device wrote that its sync state does not know as published, which Z44's tests
    /// reached only through a copy held aside.
    @Test("a move's deletion waits while the copy's vault is held closed, and the sync says which vault it waits for")
    func deletionWaitsForAnUnpublishedCopy() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 990)
        let (owner, member) = (home.owner, home.members[0])
        let vaultID = home.vaultID
        let personal = try #require(await member.session.personalVaultID)
        let item = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([owner, member])
        let moved = try await member.session.move(itemID: item.id, to: vaultID)
        let syncState = try #require(member.vault.sync?.state)
        #expect(try await syncState.pendingDeletions(vaultID: personal).count == 1)

        await member.session.lock()
        await member.state.tamper(.ledger, vaultID: vaultID, value: nil)
        let device = member.vault.relaunched()
        await device.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await device.session.unlock(password: TestVault.password)
        let held = try await device.session.syncAll()
        #expect(held.deletionsHeldBack == [vaultID], "nothing said which vault the deletions are waiting for")
        #expect(
            try await syncState.pendingDeletions(vaultID: personal).count == 1,
            "the original's deletion was published while its copy had reached nobody")
        try await owner.session.sync()
        #expect(try await !owner.session.items(in: vaultID).items.contains { $0.id == moved.id })

        // The device sets the vault up again, the copy goes out, and the deletion follows it.
        try await device.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        let released = try await device.session.syncAll()
        let after = released.deletionsHeldBack.isEmpty ? released : try await device.session.syncAll()
        #expect(after.deletionsHeldBack.isEmpty)
        #expect(try await syncState.pendingDeletions(vaultID: personal).isEmpty)
        try await owner.session.sync()
        #expect(try await owner.session.items(in: vaultID).items.contains { $0.id == moved.id })
    }
}
