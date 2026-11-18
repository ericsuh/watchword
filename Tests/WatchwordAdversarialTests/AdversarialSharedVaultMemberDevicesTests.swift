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
    /// members have no password to tell the two branches by. One who had followed the member's own change forward
    /// before the forged branch appeared, and one who sees both at once, alike follow neither, read neither contested
    /// device, and say so (Z12), and nothing in this version settles it (Z11).
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

        // The owner had followed the member's change forward from where it first anchored, before the forged branch
        // appeared. Being seen first earns a branch nothing (Z12): had the forged one been published first, the
        // owner would have followed that. Both now compete beyond the base: neither contested device is read.
        try await Self.syncAll([owner], rounds: 3)
        let ownerTitles = Set(try await owner.session.items().items.filter { $0.vaultID == vaultID }.map(\.title))
        #expect(!ownerTitles.contains(planted.title), "the revoked laptop wrote as the member")
        #expect(!ownerTitles.contains(genuine.title), "the branch seen first was kept in force")
        #expect(ownerTitles.contains(before.title))
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

        // Comparing safety numbers with the member again verifies their account's keys, which both branches share,
        // not which devices are theirs: it settles nothing, and nothing in this version does (Z11). The contested
        // devices stay unread and the vault keeps saying so.
        try await bystander.session.verifyContact(
            member.accountID, evidence: .safetyNumber(member.safetyNumber), replacingPin: true)
        try await Self.syncAll([bystander], rounds: 2)
        titles = Set(try await bystander.session.items().items.filter { $0.vaultID == vaultID }.map(\.title))
        #expect(!titles.contains(planted.title) && !titles.contains(genuine.title))
        #expect(
            try await bystander.session.sharedVaultStatus(vaultID).membersWithDisagreeingDevices == [member.accountID])

        // Across a relaunch of the sharing state the anchor holds where it was: before the fork, on neither branch.
        let pins = try #require(await bystander.state.value(.memberDevices, vaultID: vaultID))
        let saved = try #require(MemberRegistryPins.parse(pins, account: bystander.bundle, vaultID: vaultID))
        let anchored = try #require(saved.first { $0.key.accountID == member.accountID }?.value)
        #expect(anchored.settled == nil)
        #expect(anchored.credential == anchored.genesis, "the bystander had seen no change of the member's before")
    }

    /// Threat: a member of the vault (A4) publishes a registry that is long to replay (review finding Z10); A3 holding
    /// the unlocked device, or auto-lock, locks meanwhile. The replay runs off the session's actor, so the lock takes
    /// effect at once with the keys gone, and what the replay produced is dropped rather than believed after a lock.
    /// The hook holds the replay until the test has locked: with the replay back on the actor, the lock waits out the
    /// hook's 60-second bound and the test fails.
    @Test("a lock while another member's registry is replayed takes effect at once, and the replay is dropped")
    func lockWinsDuringMemberRegistryReplay() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 2200)
        let (owner, member) = (home.owner, home.members[0])
        try await Self.syncAll([owner, member])
        try await member.session.changePassword(current: TestVault.password, new: "an entirely different passphrase")
        try await member.session.sync()
        let before = await owner.session.sharing.registryPins

        let (reached, reaching) = AsyncStream.makeStream(of: Void.self)
        let release = DispatchSemaphore(value: 0)
        let released = Flag()
        await owner.session.setAwayWorkHook { current in
            guard current == .memberRegistry else { return }
            reaching.yield()
            if release.wait(timeout: .now() + 60) == .success { released.set() }
        }
        let work = Task { try await owner.session.sync() }
        var iterator = reached.makeAsyncIterator()
        _ = await iterator.next()
        await owner.session.lock()
        #expect(await owner.session.keys == nil)
        release.signal()
        _ = try? await work.value
        #expect(released.isSet, "lock() returned only after the replay had given up waiting")
        #expect(await owner.session.sharing.registryPins == before, "a replay finished after the lock was believed")
        await owner.session.setAwayWorkHook(nil)

        try await owner.session.unlock(password: TestVault.password)
        try await owner.session.sync()
        let anchor = try #require(
            await owner.session.sharing.registryPins.first { $0.key.accountID == member.accountID })
        #expect(anchor.value != before[anchor.key], "the member's change was never followed: nothing is tested")
    }
}
