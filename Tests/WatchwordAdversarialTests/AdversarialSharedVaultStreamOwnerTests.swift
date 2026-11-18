import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

// Review finding Z46 (docs/06-adversarial-review.md): a stream is named by a device ID alone; since Z157 the ID commits
// to its account.
extension AdversarialSharedVaultTests {
    /// Threat: a current member who may write (A4). The insider enrols a device of their own account under the owner's
    /// device ID (S33) and, through it, writes segments into the stream named after that ID, signed by the insider's
    /// account key and their own key for that device. Every entry in such a segment names the stream's device, so to
    /// every rule keyed by device ID they were the owner's device's versions; the owner has changed a password and not
    /// yet synced, and the insider's versions claim to have seen that device's edits beyond it. Before Z46 they
    /// superseded the unpublished value, with no conflict and no history; Z46 to Z152 inferred the stream's account
    /// from its segments. The owner's device ID commits to the owner's account (Z157), so the insider's registry does
    /// not count it, and nothing the insider signs as it verifies anywhere: it is refused at download, on the owner's
    /// device and everyone's, like any object no key the ID commits to signed. It sits at the owner's next numbers, as
    /// anything anyone can create there does (A1): the owner's stream says so and waits, marking nothing sent, and goes
    /// on once the objects are gone.
    @Test(
        "segments a member writes into another member's device stream verify nowhere, on that member's device and on everyone's"
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
        let plants = Set(await household.transport.list(prefix: stream)).subtracting(before)
        #expect(!plants.isEmpty, "nothing was written into the owner's stream: the test proves nothing")

        // Nobody takes the insider's objects for the owner's device's, the owner's device included; nothing of them is
        // kept, and the owner's stream says it cannot go on past them.
        let ownerReport = try await owner.session.syncAll().vaults[vaultID]
        #expect(ownerReport?.ownStreamConflict != nil, "the owner was not told its next number is taken")
        try await Self.syncAll([owner, bystander, insider], rounds: 3)
        for account in [owner, bystander, insider] {
            let report = try await account.session.syncAll().vaults[vaultID]
            #expect(plants.allSatisfy { Self.refused($0, in: report) }, "an insider's object verified")
            #expect(try await account.session.item(id: item.id).field(.password)?.value.hasPrefix("planted") == false)
            #expect(try await account.session.sharedVaultStatus(vaultID).heldAside == 0)
            #expect(await account.session.streamOwner(victimDevice, in: vaultID) == owner.accountID)
        }
        #expect(try await owner.session.item(id: item.id).field(.password)?.value == "the-owners-new-password")

        // The objects gone, the owner's stream carries on, and its change arrives everywhere.
        for name in plants { await Self.remove(name, from: household.transport) }
        let later = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, bystander, insider], rounds: 3)
        for account in [owner, bystander, insider] {
            #expect(try await account.session.item(id: item.id).field(.password)?.value == "the-owners-new-password")
            #expect(try await account.session.item(id: later.id).title == later.title, "the owner's stream stalled")
        }
        #expect(try await bystander.session.syncAll().vaults[vaultID]?.waiting.isEmpty == true)
    }
}
