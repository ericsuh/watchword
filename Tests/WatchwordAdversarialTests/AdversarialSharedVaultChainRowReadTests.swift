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

// The review of round 20 (docs/06-adversarial-review.md Z239): where a restore's chain rows (`RestoredChainRow`) are
// read, so that a sharing store that cannot read them holds back only what depends on them. In the suite "shared vaults
// through the session".
extension AdversarialSharedVaultTests {
    /// Threat: none needed but a sharing store that keeps failing its reads of the chain rows (a damaged
    /// `sharing.sqlite` page, honest or by A8, an attacker with the device's files), on an ordinary restore onto other
    /// hardware: nothing left to carry, and every shared vault's state verifies for the earlier ID (review of round 20,
    /// Z239). Z236 made a row that cannot be read fail the move, and the move read a row in every vault, the Personal
    /// vault's included (which never exists), to write back what it had read: every attempt failed, the record stayed
    /// for good, and the device merged and published nothing in any vault, while the notice said it would finish by
    /// itself. A move that has nothing to add to a row reads none, and an ordinary restore reads no row at all.
    @Test("an ordinary restore's move finishes, and its deletions go out, while no chain row can be read")
    func ordinaryMoveWithEveryChainRowUnreadable() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 32_100)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let doomed = try await member.session.save(Self.bank(in: personal))
        _ = try await member.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([member, owner, other])

        await member.session.lock()
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        let restored = member.vault.relaunched(seed: 32_101)
        let failing = ChainRowUnreadableSharingStore(base: member.state)
        await failing.failNextReads(.max, in: nil)
        await restored.session.configureSharing(
            SharingSettings(state: failing, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)
        #expect(try await restored.store.loadAccount()?.migration == nil, "the ordinary move did not finish")

        try await restored.session.trash(id: doomed.id)
        try await restored.session.deletePermanently(id: doomed.id)
        let report = try await restored.session.syncAll()
        #expect(!report.deviceMigrationIncomplete, "the ordinary move waited on a row it has no use for")
        #expect(report.deletionsHeldBack.isEmpty, "a row nothing depends on held the deletions back")
        #expect(report.combined.segmentsWritten > 0, "the restored device published nothing")
        #expect(await failing.refused == 0, "a chain row was read where none can matter")
        try await other.session.sync()
        #expect((try? await other.session.item(id: doomed.id)) == nil, "the deletion never went out")
    }

    /// Threat: none needed but a sharing store that keeps failing its reads of the chain rows (as above), on a device
    /// that was never restored (review of round 20, Z239). The deletion gate read every vault's row, the Personal
    /// vault's included, and held every deletion back while any read failed, for good, under the generic notice that
    /// something moved had not reached the other devices, which was untrue. The gate now reads the rows only for a
    /// vault that may be shared whose state does not verify, or that has none, which no vault here is.
    @Test("a device never restored sends its deletions while no chain row can be read")
    func deletionsGoOutWithEveryChainRowUnreadable() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 32_110)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let doomed = try await member.session.save(Self.bank(in: personal))
        let shared = try await member.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([member, owner, other])

        let failing = ChainRowUnreadableSharingStore(base: member.state)
        await failing.failNextReads(.max, in: nil)
        await member.session.configureSharing(
            SharingSettings(state: failing, contacts: member.contacts, directory: household.directory))
        try await member.session.trash(id: doomed.id)
        try await member.session.deletePermanently(id: doomed.id)
        try await member.session.trash(id: shared.id)
        try await member.session.deletePermanently(id: shared.id)
        let report = try await member.session.syncAll()
        #expect(report.deletionsHeldBack.isEmpty, "a row nothing depends on held the deletions back")
        #expect(await failing.refused == 0, "a chain row was read where none can matter")
        try await other.session.sync()
        #expect((try? await other.session.item(id: doomed.id)) == nil, "the Personal vault's deletion never went out")
        #expect((try? await other.session.item(id: shared.id)) == nil, "the shared vault's deletion never went out")
    }

    /// Threat: a damaged sync state file, or one edited by an attacker with the device's files (A8), for a shared vault
    /// that holds a restore's uncarried copy of a move, as in `restoredChainWhateverSharingWasConfigured` (Z216),
    /// beside a sharing store that cannot read that vault's chain row, which is then the only record of the earlier ID
    /// (review of round 20, Z239; Z236). Where the row decides something, a row that cannot be read still holds every
    /// deletion back, and the original stays on the account's other device until the row reads again. No test pinned
    /// this: with the gate reading a throw as an empty chain, every suite passed (round 20's `z236-gate`). The row of a
    /// vault that is not shared, which never exists, is not read on the way.
    @Test("a chain row that cannot be read where it is the only record of a restore holds the deletions back")
    func unreadableChainRowHoldsWhereItIsTheOnlyRecord() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 32_120)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)

        await member.session.lock()
        await member.contacts.removePin(for: owner.accountID)
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        let restored = member.vault.relaunched(seed: 32_121)
        let failing = ChainRowUnreadableSharingStore(base: member.state)
        await restored.session.configureSharing(
            SharingSettings(state: failing, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)
        #expect(try await restored.store.loadAccount()?.migration == nil, "the move did not finish at the unlock")
        #expect(await member.state.value(.restoredChain, vaultID: vaultID) != nil, "the move wrote no chain row")

        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
        func damage() async throws {
            var state = try #require(await raw.loadState(vaultID: vaultID))
            #expect(!state.restoredUnpublished.isEmpty, "nothing recorded to carry")
            state.authenticator = Array(repeating: 0, count: state.authenticator.count)
            await raw.tamper(state)
        }
        try await damage()
        // Only the Personal vault's row fails: the shared vault's row is read, and names the copy.
        await failing.failNextReads(.max, in: personal)
        let named = try await restored.session.syncAll()
        #expect(named.deletionsHeldBack.contains(vaultID))
        #expect(named.restoredWorkWaiting[vaultID] == [copy.id], "the row of a vault that is not shared was read")
        #expect(await failing.refused == 0, "the row of a vault that is not shared was read")

        // The shared vault's own row fails, its state damaged again (the sync recorded it afresh).
        try await damage()
        await failing.failNextReads(.max, in: vaultID)

        let held = try await restored.session.syncAll()
        #expect(await failing.refused > 0, "no read of the chain row failed: nothing is tested")
        #expect(held.deletionsHeldBack.contains(vaultID), "the hold failed open on a row that could not be read")
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original was deleted ahead of its copy")

        await failing.readAgain()
        let report = try await restored.session.syncAll()
        #expect(report.deletionsHeldBack.contains(vaultID))
        #expect(report.restoredWorkWaiting[vaultID] == [copy.id], "the row, read again, did not name the copy")
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original was deleted ahead of its copy")
    }
}
