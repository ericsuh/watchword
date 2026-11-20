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
        // Refused for the pending move first, before the vault's own reasons are asked (review of round 20, Z244): a
        // vault that opens here is refused for the move, not as one whose work a sync carries.
        await #expect(throws: VaultError.deviceMigrationIncomplete) {
            try await second.session.stopWaitingForRestoredWork(in: personal)
        }

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

    /// Threat: none needed; the review of round 19 (Z235). A restore onto other hardware whose shared vault's state
    /// verifies, for the earlier ID (a first restore) or for this device's own ID (a move made again after an attempt
    /// that saved every state and failed to clear its record, Z181), needs no chain row, so its move is made without
    /// sharing configured: in a process given sync and not sharing (the AutoFill extension), a wait there would hold
    /// back everything this device publishes, in every vault, until the app ran. No test pinned either check that
    /// lets it go ahead (`moveAwaitsSharing`): with either removed, every suite passed. It still records the copy, and
    /// the hold keeps the original on the account's other device.
    @Test(
        "an ordinary restore's move finishes without sharing, at its first attempt and when made again",
        arguments: [false, true])
    func ordinaryMoveFinishesWithoutSharing(retried: Bool) async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 31_910)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        let first = try #require(await member.session.deviceIDForTest())

        await member.session.lock()
        await member.contacts.removePin(for: owner.accountID)
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        let store = MigrationClearFailingStore(base: member.vault.store, failing: retried)
        let restored = TestVault(
            store: store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock, sync: member.vault.sync, seed: 31_911, deviceKeys: member.vault.deviceKeys)
        try await restored.session.unlock(password: TestVault.password)
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
        if retried {
            #expect(await store.failed == 1, "the first attempt at the move did not fail: nothing is tested")
            #expect(try await restored.store.loadAccount()?.migration != nil, "the first attempt finished")
            let begun = await raw.loadState(vaultID: vaultID)?.restoredUnpublished ?? [:]
            #expect(!begun.isEmpty, "the first attempt saved no state of this device's: nothing is tested")
            let report = try await restored.session.syncAll()
            #expect(!report.deviceMigrationIncomplete, "a move whose own state verifies waited for sharing")
        }
        #expect(try await restored.store.loadAccount()?.migration == nil, "the ordinary move waited for sharing")

        let state = await raw.loadState(vaultID: vaultID)?.restoredUnpublished ?? [:]
        #expect(state[RecordKey(recordID: copy.id, kind: .item)]?.device == first, "the move recorded nothing")
        let report = try await restored.session.syncAll()
        #expect(!report.deviceMigrationIncomplete)
        #expect(report.deletionsHeldBack.contains(vaultID), "the hold ended without sharing")
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original was deleted ahead of its copy")
    }

    /// Threat: none needed but a sharing store that fails one read (a busy or damaged database) during a restore's
    /// move, beside a damaged sync state file, or one edited by an attacker with the device's files (A8), on a store
    /// restored twice, as in `restoredTwiceAfterADamagedState(retried: false)` (review of round 19, Z236). The move
    /// read the chain rows with `try?`, so a read that threw was read as no row: it recorded nothing for the first
    /// ID's uncarried copy, saved a state that verifies and cleared its record, and the hold ended, which is Z229's
    /// outcome with another cause. A row that cannot be read now fails the move, which is made again at the next sync.
    @Test("a chain row the sharing store fails to read during a restore's move fails the move, which is made again")
    func unreadableChainRowFailsTheMove() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 31_920)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        let first = try #require(await member.session.deviceIDForTest())
        let middle = try await Self.restoredWithVaultClosed(member, household: household, owner: owner, seed: 31_921)
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)

        await middle.session.lock()
        await middle.forgetDeviceKey(accountID: member.accountID)
        var damaged = try #require(await raw.loadState(vaultID: vaultID))
        damaged.authenticator = Array(repeating: 0, count: damaged.authenticator.count)
        await raw.tamper(damaged)
        let sharingState = ChainRowUnreadableSharingStore(base: member.state)
        let second = TestVault(
            store: middle.store, keychain: middle.keychain, biometrics: middle.biometrics, clock: middle.clock,
            sync: middle.sync, seed: 31_922, deviceKeys: middle.deviceKeys)
        await second.session.configureSharing(
            SharingSettings(state: sharingState, contacts: member.contacts, directory: household.directory))
        // Both of the move's reads (this device's row, then the middle ID's), so that the row is not found by the
        // second read, nor by the read of the chain row's own write after them.
        await sharingState.failNextReads(2, in: vaultID)
        try await second.session.unlock(password: TestVault.password)
        #expect(await sharingState.refused > 0, "no read of a chain row failed: nothing is tested")
        #expect(try await second.store.loadAccount()?.migration != nil, "the move finished on a row it did not read")
        await sharingState.readAgain()

        let report = try await second.session.syncAll()
        #expect(!report.deviceMigrationIncomplete, "the move was not made again")
        let state = await raw.loadState(vaultID: vaultID)?.restoredUnpublished ?? [:]
        #expect(state[RecordKey(recordID: copy.id, kind: .item)]?.device == first, "the copy was not recorded again")
        #expect(report.deletionsHeldBack.contains(vaultID), "the hold ended with a row the move could not read")
        #expect(report.restoredWorkWaiting[vaultID] == [copy.id])
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original was deleted ahead of its copy")
    }
}

extension AdversarialSharedVaultTests {
    /// Threat: none needed; the review of round 20 (Z241). A restore's move that would read a chain row without sharing
    /// configured waits for it (Z229), and `configureSharing` makes it. But a move begun before sharing was configured
    /// (a sync's) read that sharing was not, and while it was suspended on its next read `configureSharing`'s own move
    /// was turned away by the one under way (Z237), which then returned waiting: nobody made the move until the next
    /// sync or unlock, though the docs said `configureSharing` makes it. The move under way is now made once more for
    /// the caller it turned away.
    @Test("configuring sharing while a restore's move waits for it, mid-read, still makes the move")
    func configureSharingDuringAWaitingMoveMakesIt() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 32_140)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        let first = try #require(await member.session.deviceIDForTest())
        let middle = try await Self.restoredWithVaultClosed(member, household: household, owner: owner, seed: 32_141)
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)

        await middle.session.lock()
        await middle.forgetDeviceKey(accountID: member.accountID)
        var damaged = try #require(await raw.loadState(vaultID: vaultID))
        damaged.authenticator = Array(repeating: 0, count: damaged.authenticator.count)
        await raw.tamper(damaged)
        let store = DirectoryListingHookedStore(base: middle.store)
        let second = TestVault(
            store: store, keychain: middle.keychain, biometrics: middle.biometrics, clock: middle.clock,
            sync: middle.sync, seed: 32_142, deviceKeys: middle.deviceKeys)
        try await second.session.unlock(password: TestVault.password)
        let waiting = try #require(try await store.loadAccount())
        #expect(waiting.migration != nil, "the move did not wait for sharing: nothing is tested")

        // The move's first listing of the vault directory, in `moveAwaitsSharing`, after it read that sharing is not
        // configured: sharing is configured then.
        let session = second.session
        let settings = SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory)
        await store.onNextDirectoryListing { await session.configureSharing(settings) }
        try await second.session.completeDeviceMigration(account: waiting)
        #expect(await store.hookRan, "sharing was not configured during the move: nothing is tested")
        #expect(try await store.loadAccount()?.migration == nil, "configuring sharing did not make the move")

        let state = await raw.loadState(vaultID: vaultID)?.restoredUnpublished ?? [:]
        #expect(state[RecordKey(recordID: copy.id, kind: .item)]?.device == first, "the copy was not recorded again")
        let report = try await second.session.syncAll()
        #expect(!report.deviceMigrationIncomplete)
        #expect(report.restoredWorkWaiting[vaultID] == [copy.id])
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original was deleted ahead of its copy")
    }
}

extension AdversarialSharedVaultTests {
    /// Threat: none needed but a move recorded in the store after this session read the account (a registration as a
    /// new device since, Z234, or a record planted by A8, an attacker with the device's files, which can only make it
    /// refuse); the review of round 20 (Z244). Stop Waiting checks the pending move twice: on the account the session
    /// holds, and again from the store before its save. No test pinned the second: with it neutralised, every suite
    /// passed. Here only the store records the move, and Stop Waiting is refused and writes nothing.
    @Test("stopping the wait is refused for a move recorded in the store after the session read the account")
    func stopWaitingRereadsTheAccountBeforeItsSave() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 32_150)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        _ = try await member.session.move(itemID: original.id, to: vaultID)
        let restored = try await Self.restoredWithVaultClosed(member, household: household, owner: owner, seed: 32_151)
        let report = try await restored.session.syncAll()
        #expect(report.restoredWorkMayStopWaiting.contains(vaultID), "Stop Waiting is not offered: nothing is tested")
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
        let before = await raw.loadState(vaultID: vaultID)

        let account = try #require(try await restored.store.loadAccount())
        #expect(account.migration == nil)
        try await restored.store.commit(
            StoreChange(
                account: .update(account, expectedKeysetVersion: account.keysetVersion),
                migration: .set(DeviceMigration(previousDeviceID: UUID(), authenticator: []))))
        await #expect(throws: VaultError.deviceMigrationIncomplete) {
            try await restored.session.stopWaitingForRestoredWork(in: vaultID)
        }
        #expect(await raw.loadState(vaultID: vaultID) == before, "the refused call replaced the state")
    }
}

extension AdversarialSharedVaultTests {
    /// Threat: none needed; the review of round 21 (Z247). Since Z241 the move under way was made once more from the
    /// account of the last caller it turned away. A caller holding an account read before a registration recorded the
    /// move the store now holds (here, a record that is not the store's) made nothing, and when it came last it
    /// overwrote `configureSharing`'s request: the move that sharing had unblocked waited for the next sync or unlock.
    /// The move is now made again from the account the store holds.
    @Test("a restore's move turned away by one waiting for sharing is made from the store's record, whoever asked last")
    func turnedAwayMoveIsMadeFromTheStoresRecord() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 32_240)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        let first = try #require(await member.session.deviceIDForTest())
        let middle = try await Self.restoredWithVaultClosed(member, household: household, owner: owner, seed: 32_241)
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)

        await middle.session.lock()
        await middle.forgetDeviceKey(accountID: member.accountID)
        var damaged = try #require(await raw.loadState(vaultID: vaultID))
        damaged.authenticator = Array(repeating: 0, count: damaged.authenticator.count)
        await raw.tamper(damaged)
        let store = DirectoryListingHookedStore(base: middle.store)
        let second = TestVault(
            store: store, keychain: middle.keychain, biometrics: middle.biometrics, clock: middle.clock,
            sync: middle.sync, seed: 32_242, deviceKeys: middle.deviceKeys)
        try await second.session.unlock(password: TestVault.password)
        let waiting = try #require(try await store.loadAccount())
        #expect(waiting.migration != nil, "the move did not wait for sharing: nothing is tested")

        // Inside `moveAwaitsSharing`, after it read that sharing is not configured: sharing is configured, whose move
        // is turned away, and then a caller holding an older record is turned away too.
        var stale = waiting
        stale.migration = DeviceMigration(previousDeviceID: UUID(), authenticator: [])
        let older = stale
        let session = second.session
        let settings = SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory)
        await store.onNextDirectoryListing {
            await session.configureSharing(settings)
            try? await session.completeDeviceMigration(account: older)
        }
        try await second.session.completeDeviceMigration(account: waiting)
        #expect(await store.hookRan, "sharing was not configured during the move: nothing is tested")
        #expect(try await store.loadAccount()?.migration == nil, "the move sharing unblocked was not made")

        let state = await raw.loadState(vaultID: vaultID)?.restoredUnpublished ?? [:]
        #expect(state[RecordKey(recordID: copy.id, kind: .item)]?.device == first, "the copy was not recorded again")
        let report = try await second.session.syncAll()
        #expect(!report.deviceMigrationIncomplete)
        #expect(report.restoredWorkWaiting[vaultID] == [copy.id])
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original was deleted ahead of its copy")
    }

    /// Threat: none needed but a sharing store that keeps failing its reads of a chain row a restore's move needs (as
    /// in `lastingChainRowFailureIsReported`, Z240), and a caller of the move turned away while it fails that holds an
    /// account read before the store's record changed (review of round 21, Z247). The move under way threw, was made
    /// again from that caller's account, which named a record the store does not hold, returned without making it,
    /// and the throw became success: the sync that made it would not have said why its move failed, nor an unlock
    /// noted it. The failure now stands until an attempt makes the move.
    @Test("a restore's move that fails keeps its failure when a caller it turned away asks again with an older record")
    func turnedAwayMoveKeepsTheFailure() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 32_250)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        _ = try await member.session.move(itemID: original.id, to: vaultID)
        let middle = try await Self.restoredWithVaultClosed(member, household: household, owner: owner, seed: 32_251)
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)

        await middle.session.lock()
        await middle.forgetDeviceKey(accountID: member.accountID)
        var damaged = try #require(await raw.loadState(vaultID: vaultID))
        damaged.authenticator = Array(repeating: 0, count: damaged.authenticator.count)
        await raw.tamper(damaged)
        let failing = ChainRowUnreadableSharingStore(base: member.state)
        await failing.failNextReads(.max, in: vaultID)
        let store = DirectoryListingHookedStore(base: middle.store)
        let second = TestVault(
            store: store, keychain: middle.keychain, biometrics: middle.biometrics, clock: middle.clock,
            sync: middle.sync, seed: 32_252, deviceKeys: middle.deviceKeys)
        await second.session.configureSharing(
            SharingSettings(state: failing, contacts: member.contacts, directory: household.directory))
        try await second.session.unlock(password: TestVault.password)
        let waiting = try #require(try await store.loadAccount())
        #expect(waiting.migration != nil, "the move finished on a row it did not read: nothing is tested")

        var stale = waiting
        stale.migration = DeviceMigration(previousDeviceID: UUID(), authenticator: [])
        let older = stale
        let session = second.session
        await store.onNextDirectoryListing { try? await session.completeDeviceMigration(account: older) }
        await #expect(throws: VaultSession.RestoredChainRowUnreadable.self) {
            try await session.completeDeviceMigration(account: waiting)
        }
        #expect(await store.hookRan, "no caller was turned away during the move: nothing is tested")
        #expect(await failing.refused > 0, "no read of the chain row failed: nothing is tested")
        #expect(try await store.loadAccount()?.migration != nil, "the move finished on a row it did not read")
    }
}

/// A record store over `base` that runs a step once, the next time the account's vault directory is listed.
actor DirectoryListingHookedStore: RecordStore {
    let base: any RecordStore
    private var hook: (@Sendable () async -> Void)?
    private(set) var hookRan = false

    init(base: any RecordStore) {
        self.base = base
    }

    func onNextDirectoryListing(_ hook: @escaping @Sendable () async -> Void) { self.hook = hook }

    func loadAccount() async throws -> AccountRecord? { try await base.loadAccount() }
    func record(_ key: RecordKey) async throws -> StoredRecord? { try await base.record(key) }
    func records(in vaultID: UUID, kind: EnvelopeKind) async throws -> [StoredRecord] {
        if kind == .vaultDirectory, let hook {
            self.hook = nil
            await hook()
            hookRan = true
        }
        return try await base.records(in: vaultID, kind: kind)
    }
    func commit(_ change: StoreChange) async throws { try await base.commit(change) }
    func eraseAll() async throws { try await base.eraseAll() }
}

/// A sharing state store over `base` whose next reads of one vault's chain row (`SharingStateKey.restoredChain`), or
/// of every vault's, throw, as a busy or damaged database would.
actor ChainRowUnreadableSharingStore: SharingStateStore {
    struct ReadFailed: Error {}

    let base: InMemorySharingStateStore
    private var failing = 0
    private var failingVault: UUID?
    private(set) var refused = 0

    init(base: InMemorySharingStateStore) {
        self.base = base
    }

    /// The next `count` reads of `vaultID`'s chain row throw, or of any vault's for `nil`.
    func failNextReads(_ count: Int, in vaultID: UUID?) {
        failing = count
        failingVault = vaultID
    }

    func readAgain() { failing = 0 }

    /// Runs `step` once, inside the next read that throws, before it throws.
    func onNextRefusal(_ step: @escaping @Sendable () async -> Void) { refusalStep = step }
    private var refusalStep: (@Sendable () async -> Void)?

    func sharedVaultIDs() async throws -> [UUID] { await base.sharedVaultIDs() }

    func value(_ key: SharingStateKey, vaultID: UUID) async throws -> [UInt8]? {
        if failing > 0, key == .restoredChain, failingVault == nil || vaultID == failingVault {
            failing -= 1
            refused += 1
            if let step = refusalStep {
                refusalStep = nil
                await step()
            }
            throw ReadFailed()
        }
        return await base.value(key, vaultID: vaultID)
    }

    func setValue(_ value: [UInt8]?, for key: SharingStateKey, vaultID: UUID) async throws {
        await base.setValue(value, for: key, vaultID: vaultID)
    }
}
