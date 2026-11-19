import Foundation
import Testing
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// The review of round 22 (docs/06-adversarial-review.md Z259, Z260): what a restore's move made again keeps of an
// attempt's failure and whose record it is made from (Z247), and the restore's chain failing closed on a state read
// (Z245). In the suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// Threat: none needed but a sharing store that keeps failing its reads of a chain row a restore's move needs
    /// (`lastingChainRowFailureIsReported`, Z240), and a lock, an unlock and a lock again while the move's attempt
    /// reads it; the review of round 22 (Z259). The unlock's move is turned away and asks again, the attempt throws
    /// for the row, and the attempt made again, after the second lock, throws `locked`. Since Z247 the failure kept
    /// was the latest, so the move's caller (a sync) heard `locked`, not the row, and did not say why its move failed
    /// (`restoredChainUnreadable`). The first failure is kept, and an unreadable row over any other.
    @Test("a restore's move made again after a lock keeps the unreadable chain row as its failure, not the lock")
    func turnedAwayMoveKeepsTheUnreadableRowOverALock() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 33_370)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        _ = try await member.session.move(itemID: original.id, to: vaultID)
        let middle = try await Self.restoredWithVaultClosed(member, household: household, owner: owner, seed: 33_371)
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)

        await middle.session.lock()
        await middle.forgetDeviceKey(accountID: member.accountID)
        var damaged = try #require(await raw.loadState(vaultID: vaultID))
        damaged.authenticator = Array(repeating: 0, count: damaged.authenticator.count)
        await raw.tamper(damaged)
        let failing = ChainRowUnreadableSharingStore(base: member.state)
        await failing.failNextReads(.max, in: vaultID)
        let second = TestVault(
            store: middle.store, keychain: middle.keychain, biometrics: middle.biometrics, clock: middle.clock,
            sync: middle.sync, seed: 33_372, deviceKeys: middle.deviceKeys)
        await second.session.configureSharing(
            SharingSettings(state: failing, contacts: member.contacts, directory: household.directory))
        try? await second.session.unlock(password: TestVault.password)
        let waiting = try #require(try await second.store.loadAccount())
        #expect(waiting.migration != nil, "the move finished on a row it did not read: nothing is tested")

        // Inside the attempt's failing read of the row: a lock, an unlock whose move is turned away, and a lock again.
        let session = second.session
        await failing.onNextRefusal {
            await session.lock()
            try? await session.unlock(password: TestVault.password)
            await session.lock()
        }
        await #expect(throws: VaultSession.RestoredChainRowUnreadable.self) {
            try await session.completeDeviceMigration(account: waiting)
        }
        #expect(try await second.session.state() == .locked, "the session was not locked again: nothing is tested")
        #expect(try await second.store.loadAccount()?.migration != nil, "the move finished on a row it did not read")
    }

    /// Threat: none needed but a sync state store that fails one read of a shared vault's state (a busy or damaged
    /// database) as a restore's move reads it, and that answers the next as if the row were gone; the review of round
    /// 22 (Z259; `z247-keep`, which no test pinned). The move's attempt throws, a caller turned away meanwhile has it
    /// made again, and that attempt, finding a shared vault with no state and sharing not configured, waits
    /// (`moveAwaitsSharing`) and returns without making it. The failure stands: the move is not reported made.
    @Test("a restore's move whose attempt failed is not reported made by an attempt that waits for sharing")
    func turnedAwayMoveKeepsAFailureWhenTheNextWaits() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 33_380)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        _ = try await member.session.move(itemID: original.id, to: vaultID)
        await member.session.lock()
        await member.vault.forgetDeviceKey(accountID: member.accountID)

        // Restored without sharing configured, the move failing at the unlock on every read of the vault's state.
        let store = member.vault.store
        let failing = LoadFailingSyncState(base: try #require(member.vault.sync?.state), vaultID: vaultID)
        await failing.fail { (try? await store.loadAccount())??.migration != nil }
        let restored = TestVault(
            store: store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock, sync: SyncSettings(state: failing, transport: household.transport),
            seed: 33_381, deviceKeys: member.vault.deviceKeys)
        try? await restored.session.unlock(password: TestVault.password)
        await failing.fail(while: nil)
        let waiting = try #require(try await store.loadAccount())
        #expect(waiting.migration != nil, "the move did not stay pending: nothing is tested")

        // The attempt reads the state once to see whether it waits for sharing (it does not: the state verifies for
        // the earlier ID), then fails the read of what the earlier ID left, while a caller is turned away; the attempt
        // made again for that caller finds no state, and waits.
        let session = restored.session
        await failing.script([
            .read, .fail(before: { try? await session.completeDeviceMigration(account: waiting) }), .none,
        ])
        await #expect(throws: LoadFailingSyncState.LoadFailed.self, "the failed move was reported made") {
            try await session.completeDeviceMigration(account: waiting)
        }
        #expect(try await store.loadAccount()?.migration != nil, "the move's record was cleared")

        await restored.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        #expect(try await store.loadAccount()?.migration == nil, "configuring sharing did not make the move")
        _ = try await restored.session.syncAll()
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original was deleted ahead of its copy")
    }

    /// Threat: a move record in the store replaced, while the move under way waits for sharing, by one this session did
    /// not sign (A8, with the device's files; or a registration since, which only a third restore reaches); the review
    /// of round 22 (Z259; `z247-reread`, which no test pinned: in `turnedAwayMoveIsMadeFromTheStoresRecord` the
    /// holder's record and the store's are the same). The move made again for the caller it turned away is made from
    /// the record the store holds then, not from the one the holder began with, which the store no longer holds and
    /// which would make nothing. Here the store's record is unsigned, and the move made again clears it, as every
    /// record the session did not sign is cleared (Z181): what A8 can do anyway by deleting the record.
    @Test("a restore's move made again is made from the record the store holds, not the one the holder began with")
    func turnedAwayMoveIsMadeFromTheStoreNotTheHolder() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 33_390)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        _ = try await member.session.move(itemID: original.id, to: vaultID)
        let middle = try await Self.restoredWithVaultClosed(member, household: household, owner: owner, seed: 33_391)
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)

        await middle.session.lock()
        await middle.forgetDeviceKey(accountID: member.accountID)
        var damaged = try #require(await raw.loadState(vaultID: vaultID))
        damaged.authenticator = Array(repeating: 0, count: damaged.authenticator.count)
        await raw.tamper(damaged)
        let store = DirectoryListingHookedStore(base: middle.store)
        let second = TestVault(
            store: store, keychain: middle.keychain, biometrics: middle.biometrics, clock: middle.clock,
            sync: middle.sync, seed: 33_392, deviceKeys: middle.deviceKeys)
        try await second.session.unlock(password: TestVault.password)
        let waiting = try #require(try await store.loadAccount())
        #expect(waiting.migration != nil, "the move did not wait for sharing: nothing is tested")

        // Inside `moveAwaitsSharing`, after it read that sharing is not configured: the store's record is replaced,
        // and sharing is configured, whose move is turned away.
        let session = second.session
        let base = middle.store
        let settings = SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory)
        await store.onNextDirectoryListing {
            var planted = waiting
            planted.migration = DeviceMigration(previousDeviceID: UUID(), authenticator: [])
            try? await base.commit(
                StoreChange(
                    account: .update(planted, expectedKeysetVersion: planted.keysetVersion),
                    migration: .set(DeviceMigration(previousDeviceID: UUID(), authenticator: []))))
            await session.configureSharing(settings)
        }
        try await second.session.completeDeviceMigration(account: waiting)
        #expect(await store.hookRan, "the record was not replaced during the move: nothing is tested")
        #expect(try await store.loadAccount()?.migration == nil, "the move was made again from the holder's record")
    }
}

extension AdversarialSharedVaultTests {
    /// Threat: a damaged sync state file, or one edited by an attacker with the device's files (A8), for one shared
    /// vault holding a restore's uncarried copy, with the chain rows gone (deleted, or never written), so that another
    /// shared vault's verified state is the only record naming the earlier ID, beside a sync state store whose reads of
    /// that other vault's state fail (busy or damaged); the review of round 22 (Z260, `z245-state` and `z245-rowonly`,
    /// which no test pinned). The chain's read of a vault's state must fail the chain, not read as none: read as none,
    /// the chain named nobody and the first vault's hold opened. And what failed is a state, not a chain row: the sync
    /// reports a row it could not read (`restoredChainUnreadable`), and must not report one here.
    @Test("a vault state that cannot be read as a restore's chain is read holds, and is not reported as a chain row")
    func stateReadFailingInTheChainHolds() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 33_400)
        let member = members[0]
        let otherVault = try await owner.session.createVault(name: "Second").id
        try await owner.session.shareVault(otherVault)
        try await owner.invite(member, to: otherVault, as: .readWrite, owner: owner)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let first = try await member.session.save(Self.bank(in: personal))
        let second = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner])
        let copy = try await member.session.move(itemID: first.id, to: vaultID)
        _ = try await member.session.move(itemID: second.id, to: otherVault)
        await member.session.lock()
        await member.vault.forgetDeviceKey(accountID: member.accountID)

        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
        let failing = LoadFailingSyncState(base: raw, vaultID: otherVault)
        let restored = TestVault(
            store: member.vault.store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock, sync: SyncSettings(state: failing, transport: household.transport),
            seed: 33_401, deviceKeys: member.vault.deviceKeys)
        await restored.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)
        let account = try #require(try await member.vault.store.loadAccount())
        #expect(account.migration == nil, "the move did not finish at the unlock")
        let key = RecordKey(recordID: copy.id, kind: .item)
        #expect(await raw.loadState(vaultID: vaultID)?.restoredUnpublished[key] != nil, "the copy was not recorded")
        #expect(await raw.loadState(vaultID: otherVault)?.restoredUnpublished.isEmpty == false)

        // The chain rows gone, and the first vault's state damaged: the other vault's state names the earlier ID.
        try await member.state.setValue(nil, for: .restoredChain, vaultID: vaultID)
        try await member.state.setValue(nil, for: .restoredChain, vaultID: otherVault)
        var damaged = try #require(await raw.loadState(vaultID: vaultID))
        damaged.authenticator = Array(repeating: 0, count: damaged.authenticator.count)
        await raw.tamper(damaged)
        #expect(await restored.session.holdsUnpublishedWork(in: vaultID, account: account), "no hold to begin with")

        await failing.fail { true }
        let held = await restored.session.holdsUnpublishedWork(in: vaultID, account: account)
        let waiting = await restored.session.restoredWorkWaiting(
            account: account, since: await restored.session.lockEpoch)
        await failing.fail(while: nil)
        #expect(await failing.failed > 0, "no read of the state failed: nothing is tested")
        #expect(held, "a state read that failed inside the chain's read opened the hold")
        #expect(!waiting.chainUnreadable.contains(vaultID), "a state that could not be read was reported as a row")
    }
}
