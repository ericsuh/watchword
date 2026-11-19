import Foundation
import Testing
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// The review of the merge of PR #23's rounds 20 and 21 into this branch (docs/06-adversarial-review.md V66): Z249's
// scenario with what makes this branch's download save a state, a copy it cannot read. In the suite "shared vaults
// through the session".
extension AdversarialSharedVaultTests {
    /// Threat: a damaged sync state file, or one edited by an attacker with the device's files (A8), on a store
    /// restored twice whose middle ID's state for a shared vault does not verify, beside a listed name in that vault
    /// with a copy that cannot be read (iCloud Drive's ordinary state for a conflict version, or one planted by A1,
    /// R21), and a sync begun while locked (an automatic one at launch) that the person unlocks during. On this branch
    /// the download remembers what it examined of copies in the vault's state (R17, R19), and V60 decided at the sync's
    /// start whether it might: the unlock then registered a new device ID and recorded the move, and the download's
    /// save, signed for the new ID, either landed a state started over under the waiting move (which read it as begun
    /// and recorded nothing of the first restore's copy) or replaced the state the move had just saved. Either way the
    /// original's deletion went out ahead of its copy (PRD F7.6). Each half of the review's PoC, as one argument.
    @Test(
        "a sync begun locked saves no vault state across the unlock's registration where a copy is left unread",
        arguments: [false, true])
    func lockedSyncWithAnUnreadCopyAcrossTheUnlocksRegistration(sharingFirst: Bool) async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 33_310)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        let first = try #require(await member.session.deviceIDForTest())
        let middle = try await Self.restoredWithVaultClosed(member, household: household, owner: owner, seed: 33_311)
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)

        await middle.session.lock()
        await middle.forgetDeviceKey(accountID: member.accountID)
        var damaged = try #require(await raw.loadState(vaultID: vaultID))
        damaged.authenticator = Array(repeating: 0, count: damaged.authenticator.count)
        await raw.tamper(damaged)
        let hook = TransportListingHook()
        // Through `any SyncTransport`, and forwarding the copies: called on the concrete type, the listing with copies
        // would be the protocol extension's, which lists none.
        let transport: any SyncTransport = CopyListingHookedTransport(base: household.transport, hook: hook)
        let settings = SyncSettings(
            state: raw, transport: transport, configuration: try #require(middle.sync).configuration)
        let second = TestVault(
            store: middle.store, keychain: middle.keychain, biometrics: middle.biometrics, clock: middle.clock,
            sync: settings, seed: 33_312, deviceKeys: middle.deviceKeys)
        let sharingSettings = SharingSettings(
            state: member.state, contacts: member.contacts, directory: household.directory)

        let junk = SyncObjectLocation.snapshot(vaultID: vaultID, author: UUID(), lamport: 1).name
        try await household.transport.create(junk, contents: [1, 2, 3])
        await household.transport.plantUnreadableCopy(junk, contents: [4, 5, 6])
        if sharingFirst { await second.session.configureSharing(sharingSettings) }

        // The person unlocks while the locked sync lists the shared vault's log.
        let session = second.session
        await hook.onNextListing(of: SyncObjectLocation.vaultPrefix(vaultID)) {
            try? await session.unlock(password: TestVault.password)
        }
        let locked = try await second.session.syncAll()
        #expect(await hook.ran, "the unlock did not land during the sync: nothing is tested")
        #expect(try await second.session.state() == .unlocked, "the unlock did not unlock")
        #expect((locked.vaults[vaultID]?.copiesNotExamined ?? 0) > 0, "no copy was left unread: nothing is tested")
        #expect(locked.vaults[vaultID]?.deferredUntilUnlock == true, "the sync begun locked did more than download")
        let registered = try #require(await second.session.deviceIDForTest())
        #expect(registered != first, "the unlock did not register a new device ID: nothing is tested")
        if sharingFirst {
            #expect(try await second.store.loadAccount()?.migration == nil, "the move was not made at the unlock")
        } else {
            #expect(try await second.store.loadAccount()?.migration != nil, "the move did not wait for sharing")
            #expect(await raw.loadState(vaultID: vaultID) == damaged, "the state was replaced while the move waited")
            // Not even a sync begun now, for the new ID, unlocked, may sign a state while the move waits.
            let now = SyncStateWrites(deviceID: registered, epoch: await second.session.lockEpoch, permitted: true)
            await #expect(throws: SyncKeyringError.self) {
                try await second.session.signedSyncState(SyncState(vaultID: vaultID), within: now)
            }
            await second.session.configureSharing(sharingSettings)
            #expect(try await second.store.loadAccount()?.migration == nil, "configuring sharing did not make the move")
        }
        let state = await raw.loadState(vaultID: vaultID)?.restoredUnpublished ?? [:]
        #expect(state[RecordKey(recordID: copy.id, kind: .item)]?.device == first, "the move's record was lost")
        let report = try await second.session.syncAll()
        #expect(report.deletionsHeldBack.contains(vaultID), "the hold ended")
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original was deleted ahead of its copy")
    }
}

extension AdversarialSharedVaultTests {
    /// Threat: a sync that outlives what it began with (V66): the vault locked and unlocked during it, this device's ID
    /// changed by an unlock's registration, or a sync begun locked, whose engines then save a vault state they loaded,
    /// and verified, for the ID and the keys of the start, signed for whatever the session holds at the save. A local
    /// race, no adversary needed; A8's damaged state (above) is what turns it into a lost record. Each clause of the
    /// check made as the state or stash is signed is pinned here; the pending move's in the test above.
    @Test("a sync's state writes are signed only while the sync is still entitled to them")
    func syncStateWritesAreCheckedAtSigning() async throws {
        let vault = TestVault.syncing(over: InMemorySyncTransport(), seed: 33_320)
        try await vault.createAccount()
        let session = vault.session
        let vaultID = try #require(await session.personalVaultID)
        let device = try #require(await session.deviceIDForTest())
        let state = SyncState(vaultID: vaultID)
        let begun = SyncStateWrites(deviceID: device, epoch: await session.lockEpoch, permitted: true)
        _ = try await session.signedSyncState(state, within: begun)
        _ = try await session.signStash([1, 2, 3], vaultID: vaultID, within: begun)

        let locked = SyncStateWrites(deviceID: device, epoch: begun.epoch, permitted: false)
        await #expect(throws: SyncKeyringError.self, "a sync begun locked signed a state") {
            try await session.signedSyncState(state, within: locked)
        }
        let elsewhere = SyncStateWrites(deviceID: UUID(), epoch: begun.epoch, permitted: true)
        await #expect(throws: SyncKeyringError.self, "a state was signed for an ID the sync did not begin with") {
            try await session.signedSyncState(state, within: elsewhere)
        }
        await #expect(throws: SyncKeyringError.self, "a stash was signed for an ID the sync did not begin with") {
            try await session.signStash([1, 2, 3], vaultID: vaultID, within: elsewhere)
        }

        await session.lock()
        try await session.unlock(password: TestVault.password)
        await #expect(throws: SyncKeyringError.self, "a state was signed after a lock and an unlock") {
            try await session.signedSyncState(state, within: begun)
        }
        await #expect(throws: SyncKeyringError.self, "a stash was signed after a lock and an unlock") {
            try await session.signStash([1, 2, 3], vaultID: vaultID, within: begun)
        }
        let again = SyncStateWrites(deviceID: device, epoch: await session.lockEpoch, permitted: true)
        _ = try await session.signedSyncState(state, within: again)
    }
}

/// `ListingHookedTransport` with the copies passed through: the step runs in the next listing of the prefix, with or
/// without copies, before it answers.
struct CopyListingHookedTransport: SyncTransport {
    let base: any SyncTransport
    let hook: TransportListingHook

    func list(prefix: String) async throws -> [String] {
        if let step = await hook.take(prefix) { await step() }
        return try await base.list(prefix: prefix)
    }
    func listWithCopies(prefix: String) async throws -> SyncListing {
        if let step = await hook.take(prefix) { await step() }
        return try await base.listWithCopies(prefix: prefix)
    }
    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        try await base.fetch(name, maximumLength: maximumLength)
    }
    func fetchCopies(_ name: String, maximumLength: Int, maximumCopies: Int) async throws -> SyncObjectCopies {
        try await base.fetchCopies(name, maximumLength: maximumLength, maximumCopies: maximumCopies)
    }
    func create(_ name: String, contents: [UInt8]) async throws { try await base.create(name, contents: contents) }
    func delete(_ name: String) async throws { try await base.delete(name) }
}
