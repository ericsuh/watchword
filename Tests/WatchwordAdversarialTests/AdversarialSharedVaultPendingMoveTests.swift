import Foundation
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// The review of round 19 (docs/06-adversarial-review.md Z234 to Z236): what may run while a restore's move of its
// earlier device ID's sync state is pending, which moves finish without sharing, and a chain row that cannot be read.
// In the suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// Threat: a damaged sync state file, or one edited by an attacker with the device's files (A8), on a store
    /// restored twice (E, then N, then N2) whose N state for a shared vault does not verify in N2's backup, on a
    /// session given sharing only after its unlock (review of round 19, Z234), as in
    /// `restoredTwiceWithSharingConfiguredLate`; and a caller of the public API (the app, or code driving it) that asks
    /// to stop waiting for the vault while the move waits for sharing. Stop Waiting accepted it (the vault has no key
    /// here and its state does not verify) and saved a fresh state signed for N2; the move, once sharing was
    /// configured, read that state as its own, begun, never read N's chain row (which names E), and recorded nothing
    /// for E's uncarried copy, so the hold ended and the original's deletion went out while its copy existed on this
    /// device only (PRD F7.6), with the person never shown the copy. Stop Waiting is now refused while a move is
    /// pending, and writes nothing.
    @Test("stopping the wait while a restore's move waits for sharing is refused and keeps the first restore's hold")
    func stopWaitingRefusedWhileTheMoveWaits() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 31_900)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        let first = try #require(await member.session.deviceIDForTest())
        let middle = try await Self.restoredWithVaultClosed(member, household: household, owner: owner, seed: 31_901)
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)

        // Restored again, before anything was carried, with the middle ID's state damaged in the backup.
        await middle.session.lock()
        await middle.forgetDeviceKey(accountID: member.accountID)
        var damaged = try #require(await raw.loadState(vaultID: vaultID))
        damaged.authenticator = Array(repeating: 0, count: damaged.authenticator.count)
        await raw.tamper(damaged)
        let second = TestVault(
            store: middle.store, keychain: middle.keychain, biometrics: middle.biometrics, clock: middle.clock,
            sync: middle.sync, seed: 31_902, deviceKeys: middle.deviceKeys)
        try await second.session.unlock(password: TestVault.password)
        #expect(try await second.store.loadAccount()?.migration != nil, "the move did not wait: nothing is tested")

        // No notice offers it while the move waits (the sync may not write), but the call is public.
        await #expect(throws: VaultError.deviceMigrationIncomplete) {
            try await second.session.stopWaitingForRestoredWork(in: vaultID)
        }
        #expect(await raw.loadState(vaultID: vaultID) == damaged, "the refused call replaced the state")
        #expect(try await second.store.loadAccount()?.migration != nil, "the refused call finished the move")

        await second.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        #expect(try await second.store.loadAccount()?.migration == nil, "configuring sharing did not make the move")
        let state = await raw.loadState(vaultID: vaultID)?.restoredUnpublished ?? [:]
        #expect(state[RecordKey(recordID: copy.id, kind: .item)]?.device == first, "the copy was not recorded again")
        let report = try await second.session.syncAll()
        #expect(report.deletionsHeldBack.contains(vaultID), "the hold ended without the middle ID's chain row")
        #expect(report.restoredWorkWaiting[vaultID] == [copy.id])
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original was deleted ahead of its copy")
    }
}
