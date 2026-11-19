import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// The check made as a sync's engines sign a vault's state or stash (`SyncStateWrites`, docs/06-adversarial-review.md
// Z253, as PR #22's V66), pinned through the session one layer at a time: the engines' store bound to the sync's
// start (`writes`), the state's signature checked, and the stash's (review of PR #22's seventh merge, Z257). In the
// suite "sync with real keys".
extension AdversarialVaultSyncTests {
    /// Threat: none needed but a lock and an unlock during a sync begun unlocked, as its first segment is created (an
    /// auto-lock and the person unlocking again while a slow store answers); the review of PR #22's seventh merge
    /// (Z257). The engine's state, loaded and verified under the keys of the sync's start, was saved after the lock,
    /// signed by the keys of the new unlock: had the unlock registered a new ID, that was Z253's lost record. Nothing
    /// of the sync is saved after the lock now, and nothing is lost: the deletion is still pending, the next sync finds
    /// the segment it does not remember publishing and says its place was taken (`ownStreamConflict`, holding the
    /// deletions back for that sync: the cost, recorded in Z257), and the one after recovers. Fails with the engines'
    /// store unbound (`writes: nil`) or the state's signature unchecked.
    @Test("a sync locked and unlocked as it publishes saves nothing after the lock, and the next syncs recover")
    func lockAndUnlockAcrossAPush() async throws {
        let hook = TransportCreateHook()
        let transport: any SyncTransport = CreateHookedTransport(base: InMemorySyncTransport(), hook: hook)
        let a = TestVault.syncing(over: transport, seed: 33_330)
        try await a.createAccount()
        let personal = try #require(await a.session.personalVaultID)
        let kept = try await a.session.save(
            Item(
                vaultID: personal, title: "Kept", scopes: [], fields: [Field(kind: .password, label: "P", value: "one")]
            ))
        let doomed = try await a.session.save(
            Item(
                vaultID: personal, title: "Doomed", scopes: [],
                fields: [Field(kind: .password, label: "P", value: "two")]))
        _ = try await a.session.syncAll()
        let b = try await a.enrolledDevice(over: transport, seed: 33_331)
        try await b.session.unlock(password: TestVault.password)
        _ = try await b.session.syncAll()
        _ = try await a.session.syncAll()
        _ = try await b.session.syncAll()

        var edited = try await b.session.item(id: kept.id)
        edited.title = "Kept, renamed on B"
        _ = try await b.session.save(edited)
        try await b.session.trash(id: doomed.id)
        try await b.session.deletePermanently(id: doomed.id)
        let raw = try #require(b.sync?.state as? InMemorySyncStateStore)
        let before = await raw.loadState(vaultID: personal)
        let pendingBefore = await raw.pendingDeletions(vaultID: personal)
        #expect(!pendingBefore.isEmpty, "no deletion pending: nothing is tested")

        let session = b.session
        await hook.onNextCreate(under: SyncObjectLocation.vaultPrefix(personal)) {
            await session.lock()
            try? await session.unlock(password: TestVault.password)
        }
        let report = try await b.session.syncAll()
        #expect(await hook.ran, "nothing was created in the vault: nothing is tested")
        #expect(await raw.loadState(vaultID: personal) == before, "the sync saved a state after the lock")
        #expect(await raw.pendingDeletions(vaultID: personal) == pendingBefore, "a pending deletion was lost")
        #expect(report.vaults[personal]?.deferredUntilUnlock == true)

        // The segment went out and the state that records it did not: the next sync merges it as one it does not
        // remember publishing and reports its place taken, which holds the deletions back for that sync.
        let second = try await b.session.syncAll()
        #expect(second.vaults[personal]?.ownStreamConflict != nil, "the state was saved after the lock after all")
        #expect(second.vaults[personal]?.ownStreamUnverified == nil, "the next sync was held")
        _ = try await b.session.syncAll()
        let after = try #require(await raw.loadState(vaultID: personal))
        let device = try #require(await b.session.deviceIDForTest())
        let locations = try await transport.list(prefix: SyncObjectLocation.vaultPrefix(personal))
            .compactMap { SyncObjectLocation(name: $0) }
        let highest = locations.filter { $0.kind == .segment && $0.author == device }.map(\.number).max() ?? 0
        #expect(after.nextSequence > highest, "the next sequence number is below the stream's highest")
        _ = try await a.session.syncAll()
        #expect(try await a.session.item(id: kept.id).title == "Kept, renamed on B", "the edit did not arrive")
        #expect((try? await a.session.item(id: doomed.id)) == nil, "the deletion did not arrive")
    }

    /// Threat: as above, a lock and an unlock during a sync begun unlocked, here as it downloads a segment carrying
    /// entries of a kind this version does not know (a later version's, kept aside, ADR 0009), so that the sync's
    /// stash changes (Z257). The stash, worked out under the keys of the sync's start, was signed after the lock by
    /// the keys of the new unlock. It is not now, and it is worked out again and saved at the next sync. Fails with
    /// the stash's signature unchecked, or the engines' store unbound.
    @Test("a sync locked and unlocked as it downloads saves no stash after the lock, and the next sync saves it")
    func lockAndUnlockBeforeAStashSave() async throws {
        let transport = InMemorySyncTransport()
        let (hygiene, _) = await HygieneSessionFixture.settings(breached: [:])
        let a = TestVault.syncing(over: transport, seed: 33_340, hygiene: hygiene)
        try await a.createAccount()
        let personal = try #require(await a.session.personalVaultID)
        let enrolled = try await a.enrolledDevice(over: transport, seed: 33_341)
        try await enrolled.session.unlock(password: TestVault.password)
        _ = try await enrolled.session.syncAll()
        await enrolled.session.lock()

        // The same device as a version that does not know breach-check results: it keeps A's aside.
        let hook = TransportListingHook()
        var known = try #require(enrolled.sync).configuration
        known.schemaVersions[.scanStatus] = nil
        let state = try #require(enrolled.sync?.state as? InMemorySyncStateStore)
        let b = TestVault(
            store: enrolled.store, keychain: enrolled.keychain, biometrics: enrolled.biometrics,
            clock: enrolled.clock,
            sync: SyncSettings(
                state: state, transport: ListingHookedTransport(base: transport, hook: hook), configuration: known),
            seed: 33_342, deviceKeys: enrolled.deviceKeys)
        try await b.session.unlock(password: TestVault.password)
        _ = try await b.session.syncAll()

        let bank = try await a.session.save(
            HygieneSessionFixture.login(personal, title: "Bank", host: "bank.example", password: "Zr8@Wn4&x7#Vq9!"))
        _ = try await HygieneSessionFixture.scanUntilIdle(a.session, clock: a.clock)
        _ = try await a.session.syncAll()
        let stashBefore = await state.stash(vaultID: personal)
        let stateBefore = await state.loadState(vaultID: personal)

        let session = b.session
        await hook.onNextListing(of: SyncObjectLocation.vaultPrefix(personal)) {
            await session.lock()
            try? await session.unlock(password: TestVault.password)
        }
        let report = try await b.session.syncAll()
        #expect(await hook.ran, "the vault's log was not listed: nothing is tested")
        #expect(report.vaults[personal]?.unknownEntriesKept ?? 0 > 0, "nothing was kept aside: nothing is tested")
        #expect(await state.stash(vaultID: personal) == stashBefore, "the sync saved a stash after the lock")
        #expect(await state.loadState(vaultID: personal) == stateBefore, "the sync saved a state after the lock")

        _ = try await b.session.syncAll()
        let saved = try #require(await state.stash(vaultID: personal), "the next sync saved no stash")
        #expect(saved != stashBefore, "the next sync did not save the stash")
        #expect(try await b.session.item(id: bank.id).title == "Bank", "the item did not arrive")
    }
}

/// Runs a step once, right after the next object created under one prefix is created.
actor TransportCreateHook {
    private var prefix: String?
    private var step: (@Sendable () async -> Void)?
    private(set) var ran = false

    func onNextCreate(under prefix: String, _ step: @escaping @Sendable () async -> Void) {
        self.prefix = prefix
        self.step = step
    }

    func take(_ name: String) -> (@Sendable () async -> Void)? {
        guard let prefix, name.hasPrefix(prefix), let step else { return nil }
        self.step = nil
        ran = true
        return step
    }
}

/// A transport over `base` whose next create under a prefix runs `hook`'s step once the object is there.
struct CreateHookedTransport: SyncTransport {
    let base: any SyncTransport
    let hook: TransportCreateHook

    func list(prefix: String) async throws -> [String] { try await base.list(prefix: prefix) }
    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        try await base.fetch(name, maximumLength: maximumLength)
    }
    func create(_ name: String, contents: [UInt8]) async throws {
        try await base.create(name, contents: contents)
        if let step = await hook.take(name) { await step() }
    }
    func delete(_ name: String) async throws { try await base.delete(name) }
}

extension AdversarialSharedVaultTests {
    /// Threat: none needed but a lock, and an unlock that registers a new device ID and makes its move, landing during
    /// the release of a restore's parked deletions (the review of PR #22's seventh merge, Z256): the release signed
    /// each deletion restamped for the device ID of the sync's start, after the awaits of its predicate, checking
    /// neither the epoch, the ID nor the move, so a deletion was recorded for an ID the move had already read and was
    /// neither published nor carried. Each is now signed only while the sync that releases it is still entitled to
    /// write (`requireEntitlement`): a release on behalf of a sync begun under another lock epoch, or another ID,
    /// releases nothing and reports the vault waiting, and writes no chain row; one for the sync as it is releases.
    @Test("a restore's parked deletions are released only while the sync that releases them is still entitled to")
    func releaseIsCheckedAtSigning() async throws {
        let restored = try await Self.restoredMove(seed: 33_350)
        let (device, personal, copy) = (restored.device, restored.personal, restored.copy)
        _ = try await device.session.syncAll()
        do {
            _ = try await device.session.move(itemID: copy.id, to: personal)
        } catch VaultError.transferNeedsConfirmation(let concern) {
            _ = try await device.session.move(itemID: copy.id, to: personal, confirming: concern)
        }
        let session = device.session
        let account = try #require(try await device.vault.store.loadAccount())
        let view = try await session.registry(account)
        let parked = try await session.parkedDeletions(of: account)
        #expect(!parked.isEmpty, "nothing is parked: nothing is tested")
        let epoch = await session.lockEpoch

        let stale = [
            SyncStateWrites(deviceID: account.deviceID, epoch: epoch &+ 1, permitted: true),
            SyncStateWrites(deviceID: UUID(), epoch: epoch, permitted: true),
            SyncStateWrites(deviceID: account.deviceID, epoch: epoch, permitted: false),
        ]
        let entry = [RecordKey(recordID: UUID(), kind: .item): RecordStamp(version: 0, device: UUID())]
        for writes in stale {
            let waiting = await session.releaseParkedDeletions(account: account, view: view, within: writes)
            #expect(!waiting.isEmpty, "a release the sync is not entitled to reported nothing waiting")
            #expect(try await session.parkedDeletions(of: account) == parked, "a deletion was released")
            // So is the chain row the carry and the re-record write within a sync.
            await #expect(throws: SyncKeyringError.self, "a chain row was signed for a sync no longer entitled") {
                try await session.noteRestoredChain(
                    entry, in: restored.vaultID, account: account, keeping: false, since: epoch, within: writes)
            }
        }
        let now = SyncStateWrites(deviceID: account.deviceID, epoch: epoch, permitted: true)
        let waiting = await session.releaseParkedDeletions(account: account, view: view, within: now)
        #expect(waiting.isEmpty, "the release the sync is entitled to waited")
        let raw = try #require(device.vault.sync?.state as? InMemorySyncStateStore)
        let deleted = try #require(parked.first).record.vaultID
        let released = await raw.pendingDeletions(vaultID: deleted).values.filter {
            $0.stamp.device == account.deviceID
        }
        #expect(!released.isEmpty, "nothing was released as this device's")
    }
}
