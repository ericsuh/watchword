import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

extension VaultSession {
    /// For tests: forgets what this device recorded of every stream of `vaultID`, as a device that has seen none.
    func forgetStreamIndex(_ vaultID: UUID) {
        sharing.vaults[vaultID]?.index = SharedStreamIndex()
        sharing.vaults[vaultID]?.needsReconcile = false
    }

    func replayIsRequested(_ vaultID: UUID) -> Bool {
        sharing.vaults[vaultID]?.needsReconcile == true && sharing.vaults[vaultID]?.index.judgedHead == nil
    }

    func streamOwner(_ device: UUID, in vaultID: UUID) -> UUID? {
        sharing.vaults[vaultID]?.index.account(ofStream: device)
    }
}

// Review finding Z51 (docs/06-adversarial-review.md): a stream's owner was "the lowest segment this device recorded",
// and devices did not record the same segments.
extension AdversarialSharedVaultTests {
    /// The setting of both tests: an owner, a victim and an administrator who is the insider; the insider's second
    /// device enrolled under the victim's device ID and joined to the vault (S33).
    struct SquattedStream {
        let household: SharedVaultHousehold
        let owner: SharingAccount
        let victim: SharingAccount
        let insider: SharingAccount
        let rogue: SharingAccount
        let vaultID: UUID
        let victimDevice: UUID

        var stream: String { "vault/\(vaultID.uuidString)/log/\(victimDevice.uuidString)/" }

        static func make(seed: UInt64) async throws -> SquattedStream {
            let household = SharedVaultHousehold()
            let owner = try await household.account(seed: seed)
            let vaultID = try await owner.session.createVault(name: "Household").id
            try await owner.session.shareVault(vaultID)
            let victim = try await household.account(seed: seed + 1)
            let insider = try await household.account(seed: seed + 2)
            try await owner.invite(victim, to: vaultID, as: .readWrite, owner: owner)
            try await owner.invite(insider, to: vaultID, as: .administrator, owner: owner)
            // The victim's device has a stream in the vault before anything else happens.
            _ = try await victim.session.save(AdversarialSharedVaultTests.bank(in: vaultID))
            try await AdversarialSharedVaultTests.syncAll([owner, victim, insider])
            let victimDevice = try #require(try await victim.vault.store.loadAccount()).deviceID
            let rogue = try await household.secondDevice(of: insider, deviceID: victimDevice)
            try await rogue.session.acceptInvitation(
                Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
                ownerEvidence: .safetyNumber(owner.safetyNumber))
            try await rogue.session.sync()
            return SquattedStream(
                household: household, owner: owner, victim: victim, insider: insider, rogue: rogue, vaultID: vaultID,
                victimDevice: victimDevice)
        }

        init(
            household: SharedVaultHousehold, owner: SharingAccount, victim: SharingAccount, insider: SharingAccount,
            rogue: SharingAccount, vaultID: UUID, victimDevice: UUID
        ) {
            self.household = household
            self.owner = owner
            self.victim = victim
            self.insider = insider
            self.rogue = rogue
            self.vaultID = vaultID
            self.victimDevice = victimDevice
        }
    }

    /// Threat: a current member who administers the vault (A4), alone. The victim's device has segments in the vault
    /// sealed under the first key. The insider lists that device's ID in their own registry, rotates the key, and at
    /// once signs a segment into the stream named after it, sealed under the new key. Someone invited afterwards is
    /// entitled to the new key only and passes over everything sealed under the old one. When a stream was the
    /// account's that signed the first segment a device could *open* (before Z51), the newcomer took the insider's
    /// segment for the stream's first. Since Z157 the device ID commits to the victim's account, so the insider's
    /// segment verifies on no device, whichever keys it holds: the stream is the victim's everywhere, and the
    /// insider's versions are applied nowhere.
    @Test("a stream belongs to the same account on a device that joined after a rotation as on every other")
    func streamOwnerForSomeoneWhoJoinedAfterARotation() async throws {
        let setting = try await SquattedStream.make(seed: 5110)
        let (owner, victim, insider, rogue) = (setting.owner, setting.victim, setting.insider, setting.rogue)
        let vaultID = setting.vaultID

        try await insider.session.rotateVaultKey(vaultID)
        try await Self.syncAll([owner, victim, insider, rogue])
        var planted = Self.bank(in: vaultID)
        planted.title = "Planted in the victim's stream"
        planted = try await rogue.session.save(planted)
        let before = Set(await setting.household.transport.list(prefix: setting.stream))
        try await rogue.session.sync()
        let plants = Set(await setting.household.transport.list(prefix: setting.stream)).subtracting(before)
        #expect(!plants.isEmpty)

        let newcomer = try await setting.household.account(seed: 5119)
        try await owner.invite(newcomer, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([victim, owner, newcomer], rounds: 3)
        for account in [owner, newcomer] {
            #expect(await account.session.streamOwner(setting.victimDevice, in: vaultID) == victim.accountID)
            let titles = try await account.session.items(in: vaultID).items.map(\.title)
            #expect(!titles.contains(planted.title), "the insider's segment was applied as the victim's device's")
        }
        // Where the insider's object sits at the victim's next number, the victim's stream waits there, losing
        // nothing; gone, the victim's later work arrives on every device.
        for name in plants { await Self.remove(name, from: setting.household.transport) }
        var genuine = Self.bank(in: vaultID)
        genuine.title = "The victim's own, written afterwards"
        genuine = try await victim.session.save(genuine)
        try await Self.syncAll([victim, owner, newcomer], rounds: 3)
        for account in [owner, newcomer] {
            let titles = try await account.session.items(in: vaultID).items.map(\.title)
            #expect(titles.contains(genuine.title), "the victim's later work did not arrive")
        }
    }

    /// Threat: the same insider with the store (A1), or a transport that delivers out of order, against a device
    /// that has recorded nothing of the stream yet: it is shown the insider's segment before the victim's earlier
    /// ones. Before Z157 the stream looked like the insider's until they arrived. Now the insider's segment is
    /// recorded in no order: it does not verify as the device's, so the stream is nobody's until the victim's own
    /// first segment arrives, and the victim's from then on.
    @Test("another account's segment in a device's stream is recorded in no order of arrival")
    func anotherAccountsSegmentIsNeverRecorded() async throws {
        let setting = try await SquattedStream.make(seed: 5130)
        let (owner, rogue) = (setting.owner, setting.rogue)
        let vaultID = setting.vaultID
        var planted = Self.bank(in: vaultID)
        planted.title = "Planted"
        _ = try await rogue.session.save(planted)
        try await rogue.session.sync()

        // The stream's objects as the store holds them: the victim's first, the insider's last.
        let names = await setting.household.transport.list(prefix: setting.stream).sorted()
        func object(_ name: String) async throws -> (location: SyncObjectLocation, object: SignedObject) {
            let bytes = try #require(try await setting.household.transport.fetch(name, maximumLength: 1 << 22))
            return (try #require(SyncObjectLocation(name: name)), try SignedObject.parse(bytes))
        }
        let first = try await object(try #require(names.first))
        let last = try await object(try #require(names.last))
        try await owner.session.sync()
        await owner.session.forgetStreamIndex(vaultID)

        await owner.session.judgeRecord(
            segment: last.location, signature: last.object.signature, envelope: last.object.envelope, entries: [])
        #expect(await owner.session.streamOwner(setting.victimDevice, in: vaultID) == nil)
        await owner.session.judgeRecord(
            segment: first.location, signature: first.object.signature, envelope: first.object.envelope, entries: [])
        #expect(await owner.session.streamOwner(setting.victimDevice, in: vaultID) == setting.victim.accountID)
        await owner.session.judgeRecord(
            segment: last.location, signature: last.object.signature, envelope: last.object.envelope, entries: [])
        #expect(
            await !owner.session.recordedSegment(setting.victimDevice, last.location.number, in: vaultID),
            "the insider's segment was recorded in the victim's stream")
    }

    /// Threat: a member (A4), or the store (A1) by timing. A segment is sealed under a key ID this device has no
    /// record of: a rotation whose record has not arrived yet, or an ID someone made up. Passing over it for good
    /// (Z47 does that for a key only a losing branch introduced) would drop an honest writer's segment whenever the
    /// rotation's record is late, so a key no record held here introduced is waited for; the vault's own current key,
    /// which this account is entitled to, is not passed over either.
    @Test("a segment under a key no record here introduced is waited for, not passed over")
    func unknownKeyIsNotPassedOver() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 995)
        let member = home.members[0]
        let current = try await member.session.sharedVaultStatus(home.vaultID).membership.vaultKeyID
        #expect(await !member.session.judgePassesOver(keyID: UUID(), vaultID: home.vaultID))
        #expect(await !member.session.judgePassesOver(keyID: current, vaultID: home.vaultID))
    }
}
