import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// Review finding Z120 (docs/06-adversarial-review.md): a replay asked for while a reconciling pass ran was lost at the
// end of that pass.
extension AdversarialSharedVaultTests {
    /// Threat: the store (A1) choosing what one device is shown and when. A member who joins is kept from a writer's
    /// stream, so it holds aside the owner's version that carries the writer's values, waiting for that stream
    /// (`awaiting`). Later the store shows it the writer's segments together with a change of membership: the change
    /// of head makes the first pass a replay, recording one of the awaited stream's segments asks for another, and the
    /// end of that same pass settled the basis, so the replay owed was never made. (Before Z157 the insider's
    /// segment in the writer's stream made the request, by changing whose the stream was.) A pass settles only if no
    /// replay was asked for while it ran: the request is kept, the next replay runs, and the device ends where every
    /// other device is.
    @Test("a replay asked for during a replaying pass is not lost at the end of that pass")
    func replayRequestedDuringAReplay() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 12000)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let writer = try await household.account(seed: 12001)
        try await owner.invite(writer, to: vaultID, as: .readWrite, owner: owner)
        let (judge, view) = try await household.withheldAccount(seed: 12010)
        try await owner.invite(judge, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([owner, writer, judge])
        let writerDevice = try await Self.deviceID(of: writer)
        await view.withholdNew(under: "vault/\(vaultID.uuidString)/log/\(writerDevice.uuidString)/")

        var item = try await writer.session.save(Self.setting(.password, to: "the-writers", in: Self.bank(in: vaultID)))
        try await Self.syncAll([writer, owner])
        item = try await owner.session.item(id: item.id)
        item.title = "Renamed by the owner"
        item = try await owner.session.save(item)
        try await owner.session.sync()
        try await judge.session.sync()
        try #require(
            (try? await judge.session.item(id: item.id)) == nil, "the judge was not waiting: the test proves nothing")

        // The rule itself: a request made while a replaying pass runs keeps the replay owed when the pass ends.
        let before = await judge.session.sharedReplayRequests(vaultID)
        await judge.session.requestReplay(vaultID)
        await judge.session.sharedEngineDidRun(
            vaultID, reconciled: true, judgedAgainst: nil, report: SyncReport(), requestsBefore: before)
        #expect(await judge.session.replayIsRequested(vaultID), "the replay asked for during the pass was settled away")

        // And through the session: a change of membership, and the writer's segments, in one sync.
        let newcomer = try await household.account(seed: 12011)
        try await owner.invite(newcomer, to: vaultID, as: .readOnly, owner: owner)
        await view.reveal()
        try await judge.session.sync()
        try await judge.session.sync()
        let shown = try await judge.session.item(id: item.id)
        #expect(shown.title == item.title && shown.field(.password)?.value == "the-writers")
        #expect(await judge.session.judgementIsSettled(vaultID))
        try await judge.session.sync()
        #expect(await judge.session.judgementIsSettled(vaultID), "the log is replayed at every sync")
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
