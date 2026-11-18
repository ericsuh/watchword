import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// Review finding Z120 (docs/06-adversarial-review.md): the replay asked for when a stream's account changes was lost
// when the change was learnt during a reconciling pass.
extension AdversarialSharedVaultTests {
    /// Threat: a current member who administers the vault (A4), with the store (A1) choosing what one device is shown
    /// and when. The insider's second device is registered under the victim's device ID (S33) and signs a segment
    /// into the stream named after it, carrying an item whose values are stamped as that device's; the insider's own
    /// device then publishes, in its own stream, a version of that item with those values verbatim. The store keeps
    /// the victim's real segments from a newly joined member's device, which therefore files the stream under the
    /// insider (the only segment it has of it) and admits the insider's version as built on the victim's device's
    /// work. Later the store shows it the victim's segments together with a change of membership: the change of head
    /// makes the first pass a replay, in which the stream turns out to be the victim's and a replay is asked for, and
    /// the end of that same pass settled the head, so the take-out that removes the version never ran and the device
    /// kept it, while every other device holds it aside.
    @Test("a replay asked for during a replaying pass is not lost at the end of that pass")
    func replayRequestedDuringAReplay() async throws {
        let setting = try await SquattedStream.make(seed: 12000)
        let (owner, victim, insider, rogue) = (setting.owner, setting.victim, setting.insider, setting.rogue)
        let (household, vaultID) = (setting.household, setting.vaultID)

        // A member who joins while the store keeps the victim's segments from them.
        let (judge, view) = try await household.withheldAccount(seed: 12010)
        await view.withhold(Set(await household.transport.list(prefix: setting.stream)))
        try await owner.invite(judge, to: vaultID, as: .readWrite, owner: owner)

        // The insider's second device signs a segment into the victim's stream, past the victim's head.
        try await Self.number(rogue, at: try await Self.head(of: victim, in: vaultID) + 1, in: vaultID)
        var planted = Self.bank(in: vaultID)
        planted.title = "Planted as the victim's device's work"
        planted = try await rogue.session.save(planted)
        try await rogue.session.sync()
        // The insider's own device publishes a version of it, values and stamps as the plant has them: a client of
        // the insider's own making, which does not judge its own rows (an honest one would take this one out at its
        // next change of head, so it is written after that change has been settled).
        try await insider.session.sync()
        let carried = try await rogue.session.item(id: planted.id)
        let account = try #require(try await insider.vault.store.loadAccount())
        let keys = try #require(await insider.session.keys)
        let vaultKey = try #require(await insider.session.currentVaultKey(vaultID, keys: keys, account: account))
        let revision = try await insider.session.nextRevision(in: vaultID, above: nil, account: account)
        try await insider.session.commitItem(
            ItemMerge.written(carried, as: revision), replacing: nil, vaultKey: vaultKey, account: account)
        try await insider.session.sync()

        try await judge.session.sync()
        #expect(
            await judge.session.streamOwner(setting.victimDevice, in: vaultID) == insider.accountID,
            "the stream was not filed under the insider: the test proves nothing")
        try #require(
            try await judge.session.items(in: vaultID).items.map(\.id).contains(planted.id),
            "the insider's version was not admitted: the test proves nothing")

        // A change of membership, and the victim's segments, in one sync.
        let newcomer = try await household.account(seed: 12011)
        try await owner.invite(newcomer, to: vaultID, as: .readOnly, owner: owner)
        await view.reveal()
        try await judge.session.sync()
        try await judge.session.sync()

        #expect(await judge.session.streamOwner(setting.victimDevice, in: vaultID) == victim.accountID)
        #expect(
            !(try await judge.session.items(in: vaultID).items.map(\.id).contains(planted.id)),
            "the insider's version, built on a write that does not count, stays on the device")
        #expect(!(try await owner.session.items(in: vaultID).items.map(\.id).contains(planted.id)))
    }
}

// Review finding Z124: "never listed anyone but its owner" was read on a device whose account is not the owner.
extension AdversarialSharedVaultTests {
    /// Threat: none beyond a store (A1) that keeps one record from one device, or lag. The owner's stale second
    /// device, not shown the record that added a member, rotates the key twice on the chain it has; the branch with
    /// more of the owner's records wins, and the member's addition is set aside, so on the member's own device the
    /// accepted chain lists only the owner. A chain that has only ever listed its owner is not judged, on the ground
    /// that only the owner's account can sign what verifies there; on this device that is false (its own account's
    /// signatures verify first), so at that change of head nothing was taken out and the member's own writes, which
    /// count nowhere now, stayed in its vault while every other device held them aside. The exemption is the owner's
    /// devices' alone.
    @Test("a chain that lists only its owner is judged on a device whose account is not the owner")
    func ownersAloneOnAMembersDevice() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 12400)
        let member = try await household.account(seed: 12401)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.session.sync()
        let view = WithholdingTransport(base: household.transport)
        let stale = try await owner.enrolledDevice(over: view, directory: household.directory)
        try await stale.session.shareVault(vaultID)
        try await stale.session.sync()

        let before = Set(await household.transport.list(prefix: SharingObjectLocation.membershipPrefix(vaultID)))
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        let added = Set(await household.transport.list(prefix: SharingObjectLocation.membershipPrefix(vaultID)))
        await view.withhold(added.subtracting(before))
        var written = Self.bank(in: vaultID)
        written.title = "The member's, written while a member"
        written = try await member.session.save(written)
        try await member.session.sync()

        // The stale device rotates twice on the chain it has: two of the owner's records beat one.
        try await stale.session.rotateVaultKey(vaultID)
        try await stale.session.rotateVaultKey(vaultID)
        try await member.session.sync()
        let status = try await member.session.sharedVaultStatus(vaultID)
        try #require(status.membership.members.count == 1, "the addition was not set aside: the test proves nothing")
        #expect(
            !(try await member.session.items(in: vaultID).items.map(\.id).contains(written.id)),
            "the member's writes, which count nowhere now, stayed in the vault on its own device")
    }
}
