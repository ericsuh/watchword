import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

// Review finding Z46 (docs/06-adversarial-review.md): a stream is named by a device ID alone.
extension AdversarialSharedVaultTests {
    /// Threat: a current member who may write (A4). Device IDs are chosen by devices, so the insider enrols a device
    /// of their own account under the owner's device ID (S33) and, through it, writes segments into the stream named
    /// after that ID: validly signed, by the insider's account key and their own key for that device. Every entry in
    /// such a segment must name the stream's device, so to every rule keyed by device ID these are the owner's
    /// device's versions. The owner has changed a password and not yet synced; the insider's versions claim to have
    /// seen that device's edits beyond it, and merged "like any other" in the owner's own stream they supersede the
    /// unpublished value with no conflict and no history. A device knows what it wrote: an object in its own stream
    /// that its account's keys did not sign is held aside. And for everyone else a stream belongs to the account
    /// that signed its first segment: the insider's segments in it count for nothing, and the stream carries on.
    @Test(
        "segments a member writes into another member's device stream are held aside, on that member's device and on everyone's"
    )
    func segmentsInAnotherMembersStream() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite, .readWrite], seed: 1010)
        let (owner, insider, bystander) = (home.owner, home.members[0], home.members[1])
        let vaultID = home.vaultID
        // The owner's device has a stream in the vault; the item at stake is one everybody can read.
        _ = try await owner.session.save(Self.bank(in: vaultID))
        let item = try await bystander.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, insider, bystander])
        let victimDevice = try #require(try await owner.vault.store.loadAccount()).deviceID

        // The insider's device under the owner's device ID, joined to the vault as the insider's account.
        let rogue = try await household.secondDevice(of: insider, deviceID: victimDevice)
        try await rogue.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await rogue.session.sync()

        // The owner changes the password and has not synced. The insider's device writes versions "of that device"
        // well above it, and publishes them into the stream named after it.
        _ = try await owner.session.save(
            Self.setting(.password, to: "the-owners-new-password", in: try await owner.session.item(id: item.id)))
        var planted = try await rogue.session.item(id: item.id)
        for round in 0..<3 {
            planted = try await rogue.session.save(Self.setting(.password, to: "planted-\(round)", in: planted))
        }
        let stream = "vault/\(vaultID.uuidString)/log/\(victimDevice.uuidString)/"
        let before = Set(await household.transport.list(prefix: stream))
        try await rogue.session.sync()
        #expect(
            Set(await household.transport.list(prefix: stream)).count > before.count,
            "nothing was written into the owner's stream: the test proves nothing")

        // The owner's device does not take another account's object in its own stream for its own work.
        try await owner.session.sync()
        #expect(try await owner.session.item(id: item.id).field(.password)?.value == "the-owners-new-password")
        #expect(try await owner.session.sharedVaultStatus(vaultID).heldAside > 0, "it was not kept for the person")

        // Nobody else takes it for the owner's device's either, and the owner's stream carries on past it.
        try await Self.syncAll([owner, bystander, insider], rounds: 3)
        for account in [owner, bystander, insider] {
            #expect(try await account.session.item(id: item.id).field(.password)?.value == "the-owners-new-password")
        }
        #expect(try await bystander.session.sharedVaultStatus(vaultID).heldAside > 0)
        let later = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, bystander])
        #expect(try await bystander.session.item(id: later.id).title == later.title, "the owner's stream stalled")
        #expect(try await bystander.session.syncAll().vaults[vaultID]?.waiting.isEmpty == true)
    }
}
