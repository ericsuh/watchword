import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

// Review finding Z162 (docs/06-adversarial-review.md; round 6's L-M1): every device of a shared vault counts only the
// devices whose IDs commit to their account (Z157), so a device whose ID does not, an account's device from before IDs
// committed or one an older build approved, writes nothing there that anyone receives. It must not write there, nor
// have what it wrote there counted as published.
extension AdversarialSharedVaultTests {
    /// A member's second device whose ID commits to nothing, as an older build enrolled it; honest unless `modified`.
    static func legacyDevice(of member: SharingAccount, in household: SharedVaultHousehold, modified: Bool)
        async throws -> SharingAccount
    {
        try await member.enrolledDevice(
            deviceID: UUID(uuidString: "D1620000-0000-4000-8000-000000000162")!, over: household.transport,
            directory: household.directory, modifiedClient: modified)
    }

    /// Threat: none needed but a device of the person's own whose ID does not commit to their account (an account
    /// from before IDs committed, or a device an older build approved). Every other device refuses its objects in a
    /// shared vault (Z157), so before Z162 what it wrote there reached nobody, silently, and its rows counted as
    /// published. Now it does not accept an invitation, write, move into the vault or publish there, and says so.
    @Test("a device whose ID does not commit takes no part in a shared vault, and says so")
    func nonCommittingDeviceTakesNoPart() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 16_200)
        let member = members[0]
        let invitation = Invitation(vaultID: vaultID, ownerAccountID: owner.accountID)

        // Honest: the invitation is refused.
        let honest = try await Self.legacyDevice(of: member, in: household, modified: false)
        await #expect(throws: SharedVaultError.deviceIDDoesNotCommit) {
            try await honest.session.acceptInvitation(invitation, ownerEvidence: .safetyNumber(owner.safetyNumber))
        }

        // One that accepted under a build that did not refuse, running this build now.
        await honest.session.playModifiedClient()
        try await honest.session.acceptInvitation(invitation, ownerEvidence: .safetyNumber(owner.safetyNumber))
        await honest.session.playModifiedClient(false)
        await #expect(throws: SharedVaultError.deviceIDDoesNotCommit) {
            _ = try await honest.session.save(Self.bank(in: vaultID))
        }
        let personal = try #require(try await honest.vault.store.loadAccount()?.personalVaultID)
        let original = try await honest.session.save(Self.bank(in: personal))
        await #expect(throws: SharedVaultError.deviceIDDoesNotCommit) {
            _ = try await honest.session.move(itemID: original.id, to: vaultID)
        }
        #expect(try await honest.session.item(id: original.id).vaultID == personal, "the original left its vault")
        let report = try await honest.session.syncAll()
        #expect(report.sharing[vaultID]?.deviceIDDoesNotCommit == true)
        #expect(report.vaults[vaultID]?.segmentsWritten == 0)
        #expect(report.sharing[vaultID]?.failure == nil)

        // The account's committing device is unaffected.
        let committing = try await member.session.syncAll()
        #expect(committing.sharing[vaultID]?.deviceIDDoesNotCommit == false)
        let written = try await member.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([member, owner])
        #expect((try? await owner.session.item(id: written.id)) != nil)
    }

    /// Threat: none needed; round 6's L-M1, the move. A device whose ID does not commit, under a build that let it,
    /// moved an item from its Personal vault into a shared vault and published the copy, which no other device
    /// receives; the original's permanent deletion was held back that sync (another vault could not publish). Under
    /// this build the copy's row counted as published, so the deletion went out at the next sync and the item existed
    /// on that device alone (PRD F7.6). Nothing such a device published in a shared vault counts as published: the
    /// deletion waits, and the account's other devices keep the original.
    @Test("a move into a shared vault by a device whose ID does not commit never deletes the original elsewhere")
    func moveByANonCommittingDevice() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 16_210)
        let member = members[0]
        let device = try await Self.legacyDevice(of: member, in: household, modified: true)
        try await device.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        let personal = try #require(try await device.vault.store.loadAccount()?.personalVaultID)
        let original = try await device.session.save(Self.bank(in: personal))
        // A private vault whose next segment of this device's someone has squatted, so its deletions wait this sync.
        let other = try await device.session.createVault(name: "Other").id
        _ = try await device.session.save(Self.bank(in: other))
        try await device.session.sync()
        try await Self.syncAll([member, owner])
        #expect((try? await member.session.item(id: original.id)) != nil)
        let deviceID = try await Self.deviceID(of: device)
        let squat = SyncObjectLocation.segment(
            vaultID: other, author: deviceID, sequence: try await Self.head(of: device, in: other) + 1
        ).name
        try await household.transport.create(squat, contents: [0x57, 0x57])
        _ = try await device.session.save(Self.bank(in: other))

        let copy = try await device.session.move(itemID: original.id, to: vaultID)
        let first = try await device.session.syncAll()
        #expect(first.vaults[other]?.ownStreamConflict != nil)
        #expect(first.vaults[vaultID]?.segmentsWritten == 1, "the older build published the copy")

        // This build, and the squat gone: the other vault publishes, and the original's deletion still waits.
        await device.session.playModifiedClient(false)
        await Self.remove(squat, from: household.transport)
        let second = try await device.session.syncAll()
        #expect(second.sharing[vaultID]?.deviceIDDoesNotCommit == true)
        #expect(second.deletionsHeldBack.contains(vaultID), "what nobody received counted as published")
        try await Self.syncAll([member, owner])
        #expect((try? await member.session.item(id: original.id)) != nil, "the original was deleted everywhere")
        #expect((try? await member.session.item(id: copy.id)) == nil, "the copy reached a device after all")
    }

    /// Threat: none needed; round 7's Low (F7.6), the move of `moveByANonCommittingDevice` restored onto other hardware.
    /// The copy holds edits of the old ID only, which no member counts (Z157), so it reached nobody; the original's
    /// deletion is pending. The restore registers a new, committing ID (no device key), carries the old ID's pending
    /// deletions over to it, and before Z167 the new ID, whose rows hold nothing unpublished, sent the deletion out: the
    /// original was gone everywhere and the copy was here only, under an ID nobody counts. The deletion now stays
    /// parked, reported, while any shared vault holds an edit of the old ID; moving the copy out again from this device
    /// (written as its own) lets it go, after the new copy.
    @Test("restoring a non-committing device onto other hardware does not send a move's deletion ahead of its copy")
    func restoredNonCommittingMove() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 16_230)
        let member = members[0]
        let device = try await Self.legacyDevice(of: member, in: household, modified: true)
        try await device.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        let personal = try #require(try await device.vault.store.loadAccount()?.personalVaultID)
        let original = try await device.session.save(Self.bank(in: personal))
        let other = try await device.session.createVault(name: "Other").id
        _ = try await device.session.save(Self.bank(in: other))
        try await device.session.sync()
        try await Self.syncAll([member, owner])
        let oldID = try await Self.deviceID(of: device)
        let squat = SyncObjectLocation.segment(
            vaultID: other, author: oldID, sequence: try await Self.head(of: device, in: other) + 1
        ).name
        try await household.transport.create(squat, contents: [0x57, 0x57])
        _ = try await device.session.save(Self.bank(in: other))
        let copy = try await device.session.move(itemID: original.id, to: vaultID)
        let first = try await device.session.syncAll()
        #expect(first.vaults[vaultID]?.segmentsWritten == 1, "the older build published the copy")
        #expect(first.vaults[other]?.ownStreamConflict != nil)

        // This build, restored onto other hardware: the store and its state, and no device key.
        await device.session.playModifiedClient(false)
        await Self.remove(squat, from: household.transport)
        await device.session.lock()
        await device.vault.forgetDeviceKey(accountID: member.accountID)
        try await device.session.unlock(password: TestVault.password)
        let newID = try await Self.deviceID(of: device)
        #expect(newID != oldID, "the restore did not register a new device")
        let second = try await device.session.syncAll()
        #expect(second.sharing[vaultID]?.deviceIDDoesNotCommit == false)
        #expect(second.deletionsHeldBack.contains(vaultID), "the parked deletion was not reported")
        try await Self.syncAll([member, owner])
        #expect((try? await member.session.item(id: original.id)) != nil, "the original was deleted everywhere")

        // The person moves the copy out again from this device (confirming that the original is beside it there: it
        // came back while its deletion was parked), and the new copy is its own, and goes out first.
        let again: Item
        do {
            again = try await device.session.move(itemID: copy.id, to: personal)
        } catch VaultError.transferNeedsConfirmation(let concern) {
            again = try await device.session.move(itemID: copy.id, to: personal, confirming: concern)
        }
        let third = try await device.session.syncAll()
        #expect(third.deletionsHeldBack.isEmpty)
        try await device.session.sync()
        try await Self.syncAll([member, owner])
        #expect((try? await member.session.item(id: again.id)) != nil, "the new copy did not arrive")
        #expect((try? await member.session.item(id: original.id)) == nil, "the parked deletion never went out")
    }

    /// Threat: none needed; the review of round 7. A Keychain read of the device key that fails for a moment (the
    /// device locked, the keychain daemon busy) read as a device whose ID does not commit, and the refusal advised
    /// setting the device up again. It is now its own refusal (`deviceKeyUnreadable`), still fail-closed: nothing is
    /// written, shared or published in the vault while the key cannot be read, and the next attempt succeeds.
    @Test("a device key that cannot be read for a moment refuses as a retry, not as a device that does not commit")
    func unreadableDeviceKey() async throws {
        let transport = InMemorySyncTransport()
        let keys = UnreadableDeviceKeyStore(base: FakeDeviceKeyStore(seed: 16_240))
        let vault = TestVault(
            sync: SyncSettings(state: InMemorySyncStateStore(), transport: transport), seed: 16_240, deviceKeys: keys)
        try await vault.createAccount()
        await vault.session.configureSharing(
            SharingSettings(
                state: InMemorySharingStateStore(), contacts: InMemoryVerifiedContactStore(),
                directory: InMemoryKeyBundleDirectory(), shareAccess: RecordingShareAccess()))
        try await vault.session.sync()
        let vaultID = try await vault.session.createVault(name: "Household").id

        await keys.setUnreadable(true)
        await #expect(throws: SharedVaultError.deviceKeyUnreadable) { try await vault.session.shareVault(vaultID) }
        await keys.setUnreadable(false)
        try await vault.session.shareVault(vaultID)

        await keys.setUnreadable(true)
        await #expect(throws: SharedVaultError.deviceKeyUnreadable) {
            _ = try await vault.session.save(Self.bank(in: vaultID))
        }
        let report = try await vault.session.syncAll()
        #expect(report.sharing[vaultID]?.deviceKeyUnreadable == true)
        #expect(report.sharing[vaultID]?.deviceIDDoesNotCommit == false)
        await keys.setUnreadable(false)
        let saved = try await vault.session.save(Self.bank(in: vaultID))
        let later = try await vault.session.syncAll()
        #expect(later.sharing[vaultID]?.deviceKeyUnreadable == false)
        #expect(try await vault.session.item(id: saved.id).vaultID == vaultID)
    }

    /// Threat: none needed; an account made before the device registry existed, whose first device started the
    /// registry under its old random ID (`registryGenesis`), which commits to nothing. Shared from that device, the
    /// vault's items would carry values every member holds aside, and nothing it wrote there would reach them. It does
    /// not share until it is enrolled again as a new device (an owner decision, Z162).
    @Test("a device of an account from before IDs committed does not share a vault")
    func legacyDeviceDoesNotShare() async throws {
        let transport = InMemorySyncTransport()
        let directory = InMemoryKeyBundleDirectory()
        let vault = TestVault.syncing(over: transport, seed: 16_220)
        let kit = try await vault.createAccount()
        await vault.session.lock()
        let store = try #require(vault.store as? InMemoryRecordStore)
        let rows = await store.allRecords.filter { $0.kind == .deviceRegistry || $0.kind == .accountHeader }
        try await store.commit(StoreChange(deletions: rows.map(\.key)))
        await vault.keychain.delete(.deviceRegistryAnchor(accountID: kit.accountID))
        await vault.forgetDeviceKey(accountID: kit.accountID)
        try await vault.session.unlock(password: TestVault.password)
        try await vault.session.sync()
        #expect(try await vault.session.deviceStanding() == .active)
        await vault.session.configureSharing(
            SharingSettings(
                state: InMemorySharingStateStore(), contacts: InMemoryVerifiedContactStore(), directory: directory,
                shareAccess: RecordingShareAccess()))
        let vaultID = try await vault.session.createVault(name: "Household").id
        await #expect(throws: SharedVaultError.deviceIDDoesNotCommit) { try await vault.session.shareVault(vaultID) }
        #expect(try await vault.session.sharedVaultIDs().isEmpty)
    }
}

/// A device key store whose reads of the public key fail while `unreadable` is set, as a Keychain can for a moment.
actor UnreadableDeviceKeyStore: DeviceKeyStore {
    struct ReadFailed: Error {}

    let base: FakeDeviceKeyStore
    private var unreadable = false

    init(base: FakeDeviceKeyStore) {
        self.base = base
    }

    func setUnreadable(_ value: Bool) {
        unreadable = value
    }

    func createDevice(accountID: UUID) async throws -> DeviceIdentity {
        try await base.createDevice(accountID: accountID)
    }

    func create(accountID: UUID, deviceID: UUID) async throws -> DevicePublicKey {
        try await base.create(accountID: accountID, deviceID: deviceID)
    }

    func publicKey(accountID: UUID, deviceID: UUID) async throws -> DevicePublicKey? {
        if unreadable { throw ReadFailed() }
        return try await base.publicKey(accountID: accountID, deviceID: deviceID)
    }

    func sign(_ prepared: [UInt8], accountID: UUID, deviceID: UUID) async throws -> [UInt8] {
        try await base.sign(prepared, accountID: accountID, deviceID: deviceID)
    }

    func delete(accountID: UUID) async throws {
        await base.delete(accountID: accountID)
    }
}
