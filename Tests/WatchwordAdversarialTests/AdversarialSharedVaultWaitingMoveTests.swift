import Foundation
import Testing
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// The review of the fifth merge into the hygiene branch (docs/06-adversarial-review.md V60): what may write a vault's
// sync state while a restore's move to a new device ID waits for sharing (Z229). In the suite "shared vaults through
// the session".
extension AdversarialSharedVaultTests {
    /// Threat: a damaged sync state file, or one edited by an attacker with the device's files (A8), on a store
    /// restored twice (E, then N, then N2) whose N state for a shared vault does not verify in N2's backup, as in
    /// `restoredTwiceWithSharingConfiguredLate`, and one name in that vault listed with a copy not readable yet: an
    /// iCloud conflict version not downloaded, or one file planted by A1 (R21). While the move waits for sharing a sync
    /// still downloads every vault, and the download saved its copy bookkeeping in the vault's state, started over and
    /// signed for the new ID since none verified for it. The move then read that state as one it had begun and recorded
    /// nothing of E's uncarried copy, the hold ended, and the original's deletion reached the account's other device
    /// while the copy existed on this device only (PRD F7.6); the same state lost V49's facts. Stop Waiting saved such
    /// a state too. While a move is under way nothing saves a vault's state but the move. Fails at 121589c (the waiting
    /// sync replaced the state, and the original was deleted on the other device).
    @Test("a sync while the move waits for sharing leaves the vault's state for the move")
    func downloadWhileTheMoveWaitsLeavesTheState() async throws {
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

        // One name in the shared vault with a copy listed and not readable yet.
        let junk = SyncObjectLocation.snapshot(vaultID: vaultID, author: UUID(), lamport: 1).name
        try await household.transport.create(junk, contents: [1, 2, 3])
        await household.transport.plantUnreadableCopy(junk, contents: [4, 5, 6])
        let waiting = try await second.session.syncAll()
        #expect(waiting.deviceMigrationIncomplete, "the move finished at a sync without the chain row")
        #expect(waiting.vaults[vaultID]?.copiesNotExamined ?? 0 > 0, "no copy was left unread: nothing is tested")
        await #expect(throws: VaultError.deviceMigrationIncomplete) {
            try await second.session.stopWaitingForRestoredWork(in: vaultID)
        }
        let after = try #require(await raw.loadState(vaultID: vaultID))
        #expect(after.authenticator == damaged.authenticator, "the vault's state was replaced while the move waited")

        await second.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        #expect(try await second.store.loadAccount()?.migration == nil, "configuring sharing did not make the move")
        let state = await raw.loadState(vaultID: vaultID)?.restoredUnpublished ?? [:]
        #expect(state[RecordKey(recordID: copy.id, kind: .item)]?.device == first, "the copy was not recorded again")
        let report = try await second.session.syncAll()
        #expect(report.deletionsHeldBack.contains(vaultID), "the hold ended without the middle ID's chain row")
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original was deleted ahead of its copy")
    }
}
