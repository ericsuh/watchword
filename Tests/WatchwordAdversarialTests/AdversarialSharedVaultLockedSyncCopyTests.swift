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
    /// Threat: none needed but a lock and an unlock during a sync begun unlocked, as it downloads a vault this device
    /// only downloads in (shared, with no ledger here, so no current key) beside a listed name whose copy cannot be
    /// read (iCloud Drive's ordinary state for a conflict version, or A1's one file, R21); the review of this branch's
    /// seventh merge (finding 1). On this branch that download saves what it examined of copies in the vault's state
    /// (`savingState`, which a sync begun as a writer passes as true), loaded under the keys of the sync's start and,
    /// unbound, signed after the lock by the keys of the new unlock: had that unlock registered a new ID, V66's harm.
    /// PR #23's tests reach the push and the stash, never this save. Nothing is saved after the lock now, and the next
    /// sync saves it. Fails with the engines' store unbound (`writes: nil`).
    @Test(
        "a sync locked and unlocked as it only downloads saves no copies after the lock; the next saves them")
    func lockAndUnlockAcrossADownloadThatSavesCopies() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, _, members) = try await household.household(roles: [.readWrite], seed: 33_360)
        let member = members[0]
        let hook = TransportListingHook()
        let transport: any SyncTransport = CopyListingHookedTransport(base: household.transport, hook: hook)
        // Another device of the member's, sharing never configured: the vault is marked shared and has no ledger here.
        let device = try await member.vault.enrolledDevice(over: transport, seed: 33_361)
        try await device.session.unlock(password: TestVault.password)
        let first = try await device.session.syncAll()
        #expect(
            first.vaults[vaultID]?.deferredUntilUnlock == true, "the vault was not only downloaded: nothing is tested")
        let raw = try #require(device.sync?.state as? InMemorySyncStateStore)

        let junk = SyncObjectLocation.snapshot(vaultID: vaultID, author: UUID(), lamport: 1).name
        try await household.transport.create(junk, contents: [1, 2, 3])
        await household.transport.plantUnreadableCopy(junk, contents: [4, 5, 6])
        let before = Self.unsigned(await raw.loadState(vaultID: vaultID))

        let session = device.session
        await hook.onNextListing(of: SyncObjectLocation.vaultPrefix(vaultID)) {
            await session.lock()
            try? await session.unlock(password: TestVault.password)
        }
        let report = try await device.session.syncAll()
        #expect(await hook.ran, "the vault's log was not listed: nothing is tested")
        #expect(try await device.session.state() == .unlocked, "the unlock did not unlock")
        #expect((report.vaults[vaultID]?.copiesNotExamined ?? 0) > 0, "no copy was left unread: nothing is tested")
        #expect(Self.unsigned(await raw.loadState(vaultID: vaultID)) == before, "the download saved after the lock")

        _ = try await device.session.syncAll()
        let saved = Self.unsigned(await raw.loadState(vaultID: vaultID))
        #expect(saved != before, "the next sync saved nothing of the copies: the test cannot tell a refusal")
        #expect(saved?.unreadCopies.isEmpty == false, "the next sync did not remember the unread copy")
    }

    /// A state as it reads without its signature (as `AdversarialVaultSyncTests.unsigned`): Ed25519 signing is
    /// randomised on CryptoKit, so a state signed again with the same contents compares unequal on Apple platforms.
    static func unsigned(_ state: SyncState?) -> SyncState? {
        guard var state else { return nil }
        state.authenticator = []
        return state
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
