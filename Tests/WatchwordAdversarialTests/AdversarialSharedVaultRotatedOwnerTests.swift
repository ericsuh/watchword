import Foundation
import SecureMemory
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// The independent review of V31 to V37, finding M2 (docs/06-adversarial-review.md V40): on the owner's own devices
// "shared" rested on rows A8 can delete, the marker's row and the sharing state, with the store (A1) able to withhold
// the marker the next sync would bring back.
extension AdversarialSharedVaultTests {
    /// The owner's device, relaunched over a view of the store that keeps the account's markers from it, after A8
    /// deleted the vault's sharing state and the marker rows from the device's files.
    static func ownerWithoutMarker(
        _ owner: SharingAccount, household: SharedVaultHousehold, vaultID: UUID
    ) async throws -> TestVault {
        await Self.eraseSharingState(owner.state, vaultID: vaultID)
        for row in try await owner.vault.store.records(in: owner.accountID, kind: .vaultDirectory)
        where row.envelope.first == VaultSession.sharedMarkerTag {
            try await owner.vault.store.commit(StoreChange(conditionalDeletions: [row.key: row.version]))
        }
        let view = WithholdingTransport(base: household.transport)
        let markers = AccountObjectLocation.vaultsPrefix(owner.accountID) + "\(vaultID.uuidString)/shared/"
        await view.withhold(Set(await household.transport.list(prefix: markers)))
        await view.withholdNew(under: markers)
        var sync = try #require(owner.vault.sync)
        sync.transport = view
        let device = TestVault(
            store: owner.vault.store, keychain: owner.vault.keychain, biometrics: owner.vault.biometrics,
            clock: owner.vault.clock, sync: sync, seed: 11, deviceKeys: owner.vault.deviceKeys)
        await device.session.configureSharing(
            SharingSettings(
                state: owner.state, contacts: owner.contacts, directory: household.directory,
                shareAccess: owner.shareAccess))
        try await device.session.unlock(password: TestVault.password)
        return device
    }

    /// Threat: A8 (the device's files, while the app is closed) deletes a shared vault's sharing state and the
    /// account's marker rows on the owner's own device, and the store (A1) withholds the markers so the next sync does
    /// not bring them back. The vault has rotated once (a member removed, A5, who kept the key from before). The owner
    /// made the first key, so nothing of that key says the vault is shared. Run as one of the account's own, the vault
    /// would take writes unjudged, seal under the lowest key ID held (perhaps the key A5 kept), and sign a second
    /// genesis on "Share". Only a chain rotates a vault's key: a vault other than the Personal one holding more than
    /// one key ID is shared, and held closed here until it is set up again.
    @Test("an owner's rotated vault with its marker rows deleted and the marker withheld stays shared and closed")
    func rotatedOwnersVaultWithoutMarker() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 1_490)
        #expect(try await owner.session.removeMember(members[0].accountID, from: vaultID) == .complete)
        try await Self.syncAll([owner])
        let held = await owner.session.keys?.vaultKeys.values.filter { $0.vaultID == vaultID } ?? []
        try #require(held.count >= 2, "the vault did not rotate: the test proves nothing")
        // On the merged code the rotated key reaches the owner's device by a grant of its own, which already says the
        // vault is shared (Z41); the next test holds the key-count rule apart from it.
        let granted = held.contains { $0.arrivedByGrant }
        #expect(granted)
        let membership = Set(await household.transport.list(prefix: SharingObjectLocation.membershipPrefix(vaultID)))

        let device = try await Self.ownerWithoutMarker(owner, household: household, vaultID: vaultID)
        let session = device.session
        try await session.sync()
        let info = try #require(try await session.vaults().first { $0.id == vaultID })
        #expect(info.isSharedUnavailable && info.isShared)
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            _ = try await session.save(Self.bank(in: vaultID))
        }
        await #expect(throws: (any Error).self) {
            try await session.shareVault(vaultID)
        }
        let membershipAfter = Set(
            await household.transport.list(prefix: SharingObjectLocation.membershipPrefix(vaultID)))
        #expect(membershipAfter.isSubset(of: membership), "a second genesis or a record was signed")
    }

    /// The rule itself, apart from whatever else marks a vault: a vault holding more than one key ID and nothing else
    /// that says it is shared (no ledger, no marker, no key that arrived by grant) is shared; one key ID is not; the
    /// Personal vault never is.
    @Test("more than one key ID marks a vault shared, and only that")
    func moreThanOneKeyIDMarksAVaultShared() async throws {
        let vault = TestVault()
        try await vault.createAccount()
        let session = vault.session
        let personal = try #require(await session.personalVaultID)
        let own = try await session.createVault(name: "Own").id
        await session.markSharedMarkersLoadedForTest()
        #expect(await !session.isMarkedSharedForTest(own))
        await session.addOwnVaultKeyForTest(own, keyID: UUID())
        #expect(await session.isMarkedSharedForTest(own))
        await session.addOwnVaultKeyForTest(personal, keyID: UUID())
        #expect(await !session.isMarkedSharedForTest(personal))
    }
}

extension VaultSession {
    func markSharedMarkersLoadedForTest() {
        sharing.markersLoaded = true
    }

    func isMarkedSharedForTest(_ vaultID: UUID) -> Bool {
        isMarkedShared(vaultID, keys: keys, personalVaultID: account?.personalVaultID)
    }

    /// A second key of the account's own class for `vaultID`, resident only: what no path of this version makes, which
    /// is why a second key ID says a chain rotated the vault.
    func addOwnVaultKeyForTest(_ vaultID: UUID, keyID: UUID) {
        guard let current = keys else { return }
        var generator = SystemRandomNumberGenerator()
        let material = (0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        guard let key = try? EncryptionKey(keyID: keyID, material: SecureBytes(copying: material)) else { return }
        var vaultKeys = current.vaultKeys
        vaultKeys[keyID] = VaultKey(vaultID: vaultID, key: key)
        keys = UnlockedKeys(accountUnlockKey: current.accountUnlockKey, keyset: current.keyset, vaultKeys: vaultKeys)
    }
}
