import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// Review finding Z6 (docs/06-adversarial-review.md): other members followed the highest credential generation of a
// member's device registry.
extension AdversarialSharedVaultTests {
    /// Threat: the holder of a member's laptop, stolen unlocked and since revoked by that member with a password
    /// change (the D9 adversary: the account key, the laptop's own key, the retired password). It publishes a
    /// password change of its own from the generation before its revocation, sealing a back-dated revocation of the
    /// member's phone, and a second one on top, then writes into a vault the member shares, as the member. The other
    /// members have no password to tell the two branches by. One who had already followed the member's own change
    /// keeps to it; one who sees both at once follows neither, reads neither contested device, and says so, until
    /// the person has the code from the member's own device.
    @Test("a member's revoked device does not write as that member in a shared vault by changing the password itself")
    func revokedDeviceOfAMemberForksTheRegistry() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite, .readWrite], seed: 2100)
        let (owner, member, bystander) = (home.owner, home.members[0], home.members[1])
        let vaultID = home.vaultID
        let phoneID = try #require(try await member.vault.store.loadAccount()).deviceID
        let laptopID = UUID(uuidString: "D0000000-0000-4000-8000-0000000000E7")!
        let newPassword = "an entirely different passphrase"

        // The member's laptop, joined to the vault. Its holder controls what it is shown: it never learns of its
        // revocation, as a device that does not ask never does.
        let view = WithholdingTransport(base: household.transport)
        let laptop = try await member.enrolledDevice(deviceID: laptopID, over: view, directory: household.directory)
        try await laptop.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        let before = try await laptop.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([laptop, member, owner, bystander])
        for account in [owner, bystander] {
            #expect(try await account.session.item(id: before.id).title == before.title)
        }

        // Stolen. The member revokes it with a password change; the owner's device syncs and follows that.
        await view.withholdNew(under: AccountObjectLocation.registryPrefix(member.accountID))
        let rogue = try await AdversarialAccountTests.rogueChange(
            from: laptop.vault, revoking: phoneID, passwords: [nil, nil])
        try await member.session.revokeDevice(
            laptopID, password: .change(current: TestVault.password, new: newPassword))
        try await member.session.sync()
        try await owner.session.sync()

        // The laptop's holder publishes its own branch, two generations long, and writes as the member. The member
        // writes too.
        for entry in rogue.entries {
            await household.transport.tamper(
                AccountObjectLocation.registryEntry(accountID: member.accountID, id: entry.id.hex).name,
                contents: entry.serialized())
        }
        var planted = Self.bank(in: vaultID)
        planted.title = "Planted from the stolen laptop"
        planted = try await laptop.session.save(planted)
        try await laptop.session.sync()
        var genuine = Self.bank(in: vaultID)
        genuine.title = "Saved on the member's phone"
        genuine = try await member.session.save(genuine)
        try await member.session.sync()
        let log = "vault/\(vaultID.uuidString)/log/\(laptopID.uuidString)/"
        #expect(await household.transport.list(prefix: log).count >= 2, "the laptop wrote nothing: nothing is tested")

        // The owner had followed the member's change before the forged branch appeared: it stays there.
        try await Self.syncAll([owner], rounds: 3)
        let ownerTitles = Set(try await owner.session.items().items.filter { $0.vaultID == vaultID }.map(\.title))
        #expect(ownerTitles.contains(genuine.title) && !ownerTitles.contains(planted.title))
        #expect(try await owner.session.sharedVaultStatus(vaultID).membersWithDisagreeingDevices == [member.accountID])

        // The other member last saw this account before the theft, and now sees both branches at once: neither is
        // followed, neither contested device is read, and the vault says whose devices disagree.
        try await Self.syncAll([bystander], rounds: 3)
        var titles = Set(try await bystander.session.items().items.filter { $0.vaultID == vaultID }.map(\.title))
        #expect(!titles.contains(planted.title), "the revoked laptop wrote as the member")
        #expect(!titles.contains(genuine.title), "a contested device was read before the person verified")
        #expect(titles.contains(before.title), "what the laptop wrote while it was the member's is still there")
        #expect(
            try await bystander.session.sharedVaultStatus(vaultID).membersWithDisagreeingDevices == [member.accountID])

        // Verified with the member again: the code their own device shows names their change, and only that.
        await #expect(throws: SharedVaultError.memberDevicesCodeUnknown(member.accountID)) {
            try await bystander.session.verifyMemberDevices(of: member.accountID, code: "0000 0000 0000")
        }
        let code = try await member.session.memberDevicesCode()
        try await bystander.session.verifyMemberDevices(of: member.accountID, code: code)
        try await Self.syncAll([bystander], rounds: 3)
        titles = Set(try await bystander.session.items().items.filter { $0.vaultID == vaultID }.map(\.title))
        #expect(titles.contains(genuine.title) && !titles.contains(planted.title))
        #expect(try await bystander.session.sharedVaultStatus(vaultID).membersWithDisagreeingDevices.isEmpty)

        // Across a relaunch of the sharing state the anchor holds: a session that loads it again follows the
        // member's change without being told twice.
        let pins = try #require(await bystander.state.value(.memberDevices, vaultID: vaultID))
        let saved = try #require(MemberRegistryPins.parse(pins, account: bystander.bundle, vaultID: vaultID))
        let anchored = saved.first { $0.key.accountID == member.accountID }?.value
        #expect(anchored?.settled != nil)
        #expect(
            VaultSession.devicesCode(accountID: member.accountID, credential: try #require(anchored).credential)
                == code)
    }
}
