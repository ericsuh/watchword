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

// The review of PR #22's merge, carried to this branch (docs/06-adversarial-review.md Z249): a sync begun while locked
// that is still running when the unlock registers this restored device and makes, or waits for, the move. In the suite
// "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// Threat: a damaged sync state file, or one edited by an attacker with the device's files (A8), on a store
    /// restored twice whose middle ID's state for a shared vault does not verify (as in
    /// `stopWaitingRefusedWhileTheMoveWaits`), and a sync begun while locked (an automatic one at launch) that the
    /// person unlocks during (Z249). Found on PR #22, where a locked sync's download saved the vault's state after the
    /// unlock had registered a new device ID: signed for that ID, it was read as the move's own, begun, or it replaced
    /// the state the move had just saved, and either way the move's record of the first restore's copy was lost and
    /// the original's deletion could go out ahead of it (PRD F7.6). Here a sync decides once, at its start, whether it
    /// may write (`mayWrite`), so one begun locked only downloads, in every vault, whatever happens meanwhile, and a
    /// download saves no state. Pinned whether the unlock's move waits for sharing or is made there.
    @Test(
        "a sync begun locked saves no vault state across the unlock that registers a restored device",
        arguments: [false, true])
    func lockedSyncAcrossTheUnlocksRegistration(sharingFirst: Bool) async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 32_270)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        let first = try #require(await member.session.deviceIDForTest())
        let middle = try await Self.restoredWithVaultClosed(member, household: household, owner: owner, seed: 32_271)
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)

        await middle.session.lock()
        await middle.forgetDeviceKey(accountID: member.accountID)
        var damaged = try #require(await raw.loadState(vaultID: vaultID))
        damaged.authenticator = Array(repeating: 0, count: damaged.authenticator.count)
        await raw.tamper(damaged)
        let hook = TransportListingHook()
        let transport: any SyncTransport = ListingHookedTransport(base: household.transport, hook: hook)
        let settings = SyncSettings(
            state: raw, transport: transport, configuration: try #require(middle.sync).configuration)
        let second = TestVault(
            store: middle.store, keychain: middle.keychain, biometrics: middle.biometrics, clock: middle.clock,
            sync: settings, seed: 32_272, deviceKeys: middle.deviceKeys)
        let sharingSettings = SharingSettings(
            state: member.state, contacts: member.contacts, directory: household.directory)
        if sharingFirst { await second.session.configureSharing(sharingSettings) }

        // The person unlocks while the locked sync lists the shared vault's log.
        let session = second.session
        await hook.onNextListing(of: SyncObjectLocation.vaultPrefix(vaultID)) {
            try? await session.unlock(password: TestVault.password)
        }
        let locked = try await second.session.syncAll()
        #expect(await hook.ran, "the unlock did not land during the sync: nothing is tested")
        #expect(try await second.session.state() == .unlocked, "the unlock did not unlock")
        #expect(locked.vaults[vaultID]?.deferredUntilUnlock == true, "the sync begun locked did more than download")
        let registered = try #require(await second.session.deviceIDForTest())
        #expect(registered != first, "the unlock did not register a new device ID: nothing is tested")
        if sharingFirst {
            #expect(try await second.store.loadAccount()?.migration == nil, "the move was not made at the unlock")
        } else {
            #expect(try await second.store.loadAccount()?.migration != nil, "the move did not wait for sharing")
            #expect(await raw.loadState(vaultID: vaultID) == damaged, "the state was replaced while the move waited")
            // Not even a sync begun now, for the new ID, unlocked, may sign a state while the move waits (Z253).
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
        #expect(report.restoredWorkWaiting[vaultID] == [copy.id])
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original was deleted ahead of its copy")
    }
}

extension AdversarialSharedVaultTests {
    /// Where the unlock lands in `lockedSyncDecidesOnTheAccountAfterItsAwaits`.
    enum UnlockLanding: String, CaseIterable, Sendable {
        /// Begun in the sync's account objects' step, before its own registration step, which the unlock's
        /// registration, held in `createDevice` (by its Keychain or its transport), turns away.
        case registrationUnderWay
        /// The keys installed after the sync's own registration step and before it decides whether it may write
        /// (inside its read of the registry anchor), the unlock held just before its registration begins.
        case keysBeforeTheDecision
    }

    /// Threat: none needed but an ordinary race on the first unlock after a restore (review of round 22, Z253): an
    /// automatic sync at launch, begun locked, while the person types the password and the registration publishes
    /// over the network. `syncAll` read the account once, before its awaits, and decided `mayWrite` on the keys as they
    /// were then: an unlock that installed them meanwhile, and was registering the restored store as a new device,
    /// turned the sync's own registration away, and the account it held still named the earlier ID, active, with no
    /// move recorded. The sync then ran every writer step under the earlier ID while the unlock committed the new ID
    /// and made the move; the engine's state save, signed for the new ID, replaced the move's state, and its record of
    /// the copy, the hold and the deletion it carried were lost: the copy stayed on this device only (PRD F7.6, F7.7).
    /// Z249's test lands the unlock after the decision; this one before it, both while the registration is under way
    /// and with the keys installed and the registration not begun. A sync now writes only as an ID this installation
    /// holds a key for, with no registration under way, and signs a state only for the ID and the keys it began with
    /// (`SyncStateWrites`). In an open vault the original is then deleted, rightly, once the copy is out.
    @Test(
        "a sync begun locked writes nothing as the earlier ID while the unlock registers a restored device",
        arguments: UnlockLanding.allCases)
    func lockedSyncDecidesOnTheAccountAfterItsAwaits(landing: UnlockLanding) async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 32_970)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        let first = try #require(await member.session.deviceIDForTest())
        await member.session.lock()
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        // Something for the locked sync to download and, as a writer, merge.
        let added = try await owner.session.save(Self.bank(in: vaultID))
        try await owner.session.sync()

        // The store restored onto other hardware, with sharing configured and the vault open.
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
        let accountHook = TransportListingHook()
        let vaultHook = TransportListingHook()
        let transport: any SyncTransport = ListingHookedTransport(
            base: ListingHookedTransport(base: household.transport, hook: vaultHook), hook: accountHook)
        let settings = SyncSettings(
            state: raw, transport: transport, configuration: try #require(member.vault.sync).configuration)
        let gated = GatedDeviceKeys(base: member.vault.deviceKeys)
        let keychain = KeychainReadHook(base: member.vault.keychain)
        let session = VaultSession(
            store: member.vault.store, keychain: keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock,
            configuration: VaultConfiguration(appVersion: TestVault.appVersion, kdf: .fixed(.baseline)),
            sync: settings, deviceKeys: gated, random: SeededGenerator(seed: 32_971))
        await session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))

        let unlock = TaskBox()
        let landed = TaskBox()
        @Sendable func startUnlock() async {
            await unlock.set(Task { _ = try? await session.unlock(password: TestVault.password) })
            await gated.waitEntered()
            await landed.note(unlocked: (try? await session.state()) == .unlocked)
        }
        let accountID = member.accountID
        switch landing {
        case .registrationUnderWay:
            await gated.arm(.createDevice)
            await accountHook.onNextListing(of: AccountObjectLocation.vaultsPrefix(accountID)) { await startUnlock() }
        case .keysBeforeTheDecision:
            await accountHook.onNextListing(of: AccountObjectLocation.vaultsPrefix(accountID)) {
                await keychain.onNextRead(of: .deviceRegistryAnchor(accountID: accountID)) {
                    await gated.arm(.publicKey)
                    await startUnlock()
                }
            }
        }
        // The unlock goes on, registers and makes the move inside the locked sync's listing of the shared vault's log,
        // before that vault's engine saves anything.
        await vaultHook.onNextListing(of: SyncObjectLocation.vaultPrefix(vaultID)) {
            await gated.open()
            await unlock.wait()
        }
        let locked = try await session.syncAll()
        #expect(await accountHook.ran, "the unlock did not land during the sync: nothing is tested")
        #expect(await vaultHook.ran, "the unlock did not go on during the vault's pass: nothing is tested")
        #expect(await keychain.ran == (landing == .keysBeforeTheDecision), "the anchor's read was not hooked")
        #expect(await landed.unlocked == true, "the unlock had not installed its keys where it was held")
        #expect(await gated.entered, "the unlock was not held: nothing is tested")
        #expect(try await session.state() == .unlocked, "the unlock did not unlock")
        #expect(locked.vaults[vaultID]?.deferredUntilUnlock == true, "the sync begun locked wrote as the earlier ID")
        #expect(locked.vaults[personal]?.deferredUntilUnlock == true, "the sync begun locked wrote as the earlier ID")
        #expect(locked.vaults[vaultID]?.fetched ?? 0 > 0, "the locked sync downloaded nothing: nothing is tested")
        #expect(locked.vaults[vaultID]?.applied == 0, "the sync begun locked merged into rows the carry has to write")
        let addedKey = RecordKey(recordID: added.id, kind: .item)
        #expect(try await member.vault.store.record(addedKey) == nil, "the sync begun locked merged what it downloaded")
        let registered = try #require(await session.deviceIDForTest())
        #expect(registered != first, "the unlock did not register a new device ID: nothing is tested")
        #expect(try await member.vault.store.loadAccount()?.migration == nil, "the move was not made at the unlock")
        let state = await raw.loadState(vaultID: vaultID)?.restoredUnpublished ?? [:]
        #expect(state[RecordKey(recordID: copy.id, kind: .item)]?.device == first, "the move's record was lost")

        // The copy is carried and goes out, and only then is the original deleted.
        for _ in 0..<4 {
            _ = try await session.syncAll()
            try await other.session.sync()
            try await owner.session.sync()
            let originalGone = (try? await other.session.item(id: original.id)) == nil
            let copyOut = (try? await owner.session.item(id: copy.id)) != nil
            #expect(!originalGone || copyOut, "the original was deleted ahead of its copy")
        }
        #expect((try? await owner.session.item(id: copy.id)) != nil, "the copy never reached the owner")
        #expect((try? await other.session.item(id: original.id)) == nil, "the move's deletion never went out")
    }

    /// Threat: a sync that outlives what it began with (Z253, as PR #22's V66): the vault locked and unlocked during
    /// it, this device's ID changed by an unlock's registration, or a sync begun locked, whose engines then save a
    /// vault state they loaded, and verified, for the ID and the keys of the start, signed for whatever the session
    /// holds at the save. A local race, no adversary needed; A8's damaged state is what turns it into a lost record
    /// (`lockedSyncAcrossTheUnlocksRegistration`). Each clause of the check made as the state or stash is signed is
    /// pinned here; the pending move's in that test.
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

extension AdversarialSharedVaultTests {
    /// Threat: none needed but a sync state store whose reads of a shared vault's state keep failing (a busy or damaged
    /// database) once a restore's registration has recorded its move, so that the move fails and stays pending, and a
    /// change of the vault's membership since the backup; the review of round 22 (Z253, by reading). The sharing pass
    /// took out what no longer counts wherever the keys were here, not only in a sync that may write: during the move
    /// it read `restoredUnpublished` from no state that verifies for the new ID, and took the earlier ID's uncarried
    /// copy out into the quarantine, where the move no longer finds it and nothing carries it (PRD F7.6). The take-out
    /// now waits for a sync that may write, which a pending move is not. Here the take-out's own state read fails too
    /// (Z258), which alone keeps it from running: the gate is pinned by `pendingMoveOnAChainRowTakesNothingOut`
    /// (review of round 23, Z263).
    @Test("a sync while a restore's move is pending takes none of the earlier ID's rows out")
    func pendingMoveTakesNothingOut() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite, .readOnly], seed: 32_990)
        let member = members[0]
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, members[1]])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        let first = try #require(await member.session.deviceIDForTest())
        await member.session.lock()
        await member.vault.forgetDeviceKey(accountID: member.accountID)

        let store = member.vault.store
        let failing = LoadFailingSyncState(base: try #require(member.vault.sync?.state), vaultID: vaultID)
        await failing.fail { (try? await store.loadAccount())??.migration != nil }
        let restored = TestVault(
            store: store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock, sync: SyncSettings(state: failing, transport: household.transport),
            seed: 32_991, deviceKeys: member.vault.deviceKeys)
        await restored.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try? await restored.session.unlock(password: TestVault.password)
        #expect(try await restored.session.state() == .unlocked, "the unlock did not unlock")
        #expect(try await store.loadAccount()?.migration != nil, "the move did not stay pending: nothing is tested")
        #expect(await failing.failed > 0, "no read of the state failed: nothing is tested")

        // The vault's membership changes since the backup, so that the sharing pass judges again.
        try await owner.session.changeRole(of: members[1].accountID, in: vaultID, to: .readWrite)
        try await owner.session.sync()
        let key = RecordKey(recordID: copy.id, kind: .item)
        _ = try? await restored.session.syncAll()
        #expect(try await store.record(key)?.deviceID == first, "the earlier ID's uncarried copy was taken out")

        await failing.fail(while: nil)
        let report = try await restored.session.syncAll()
        #expect(!report.deviceMigrationIncomplete, "the move was not made once the state read again")
        // The move recorded the copy, and the sync carried it: it is the new ID's now, and goes out at the next.
        let registered = try #require(await restored.session.deviceIDForTest())
        #expect(registered != first)
        #expect(try await store.record(key)?.deviceID == registered, "the copy was not carried")
        _ = try await restored.session.syncAll()
        try await owner.session.sync()
        #expect((try? await owner.session.item(id: copy.id)) != nil, "the copy never reached the owner")
    }

    /// Threat: none needed but a sharing store that cannot read a restore's chain row (a busy or damaged database), so
    /// that the move the restore's registration recorded fails and stays pending (Z240), and a change of the vault's
    /// membership since the backup; the review of round 23 (Z263). Here the vault's state reads, and does not verify
    /// for the new ID, so the take-out reads no `restoredUnpublished`: it is kept from judging the earlier ID's
    /// uncarried copy, which no segment carried, and taking it out into the quarantine, where nothing carries it (PRD
    /// F7.6), only by waiting for a sync that may write (Z253). `pendingMoveTakesNothingOut` passed without that gate.
    @Test("a sync while a restore's move waits on a chain row takes none of the earlier ID's rows out")
    func pendingMoveOnAChainRowTakesNothingOut() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite, .readOnly], seed: 33_410)
        let member = members[0]
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, members[1]])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        let first = try #require(await member.session.deviceIDForTest())
        await member.session.lock()
        await member.vault.forgetDeviceKey(accountID: member.accountID)

        let store = member.vault.store
        let rows = ChainRowUnreadableSharingStore(base: member.state)
        await rows.failNextReads(1_000, in: nil)
        let restored = TestVault(
            store: store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock, sync: member.vault.sync, seed: 33_411, deviceKeys: member.vault.deviceKeys)
        await restored.session.configureSharing(
            SharingSettings(state: rows, contacts: member.contacts, directory: household.directory))
        try? await restored.session.unlock(password: TestVault.password)
        #expect(try await restored.session.state() == .unlocked, "the unlock did not unlock")
        #expect(try await store.loadAccount()?.migration != nil, "the move did not stay pending: nothing is tested")
        #expect(await rows.refused > 0, "no chain row read failed: nothing is tested")

        // The vault's membership changes since the backup, so that the sharing pass judges again.
        try await owner.session.changeRole(of: members[1].accountID, in: vaultID, to: .readWrite)
        try await owner.session.sync()
        let key = RecordKey(recordID: copy.id, kind: .item)
        _ = try? await restored.session.syncAll()
        #expect(try await store.record(key)?.deviceID == first, "the earlier ID's uncarried copy was taken out")

        await rows.readAgain()
        for _ in 0..<2 { _ = try? await restored.session.syncAll() }
        try await owner.session.sync()
        #expect((try? await owner.session.item(id: copy.id)) != nil, "the copy never reached the owner")
    }
}

/// A device key store over `base` whose next `createDevice`, or next `publicKey`, once armed, waits until released: a
/// registration held there, as one held by its Keychain or its transport would be.
actor GatedDeviceKeys: DeviceKeyStore {
    enum Call: Sendable { case createDevice, publicKey }

    let base: any DeviceKeyStore
    private var armed: Call?
    private(set) var entered = false
    private var released = false
    private var release: CheckedContinuation<Void, Never>?
    private var enteredWaiters: [CheckedContinuation<Void, Never>] = []

    init(base: any DeviceKeyStore) { self.base = base }

    func arm(_ call: Call) { armed = call }

    /// Returns once a call has been held.
    func waitEntered() async {
        if entered { return }
        await withCheckedContinuation { enteredWaiters.append($0) }
    }

    /// Lets the held call, and every later one, go on.
    func open() {
        released = true
        release?.resume()
        release = nil
    }

    private func hold(_ call: Call) async {
        guard armed == call else { return }
        armed = nil
        entered = true
        for waiter in enteredWaiters { waiter.resume() }
        enteredWaiters = []
        if !released { await withCheckedContinuation { release = $0 } }
    }

    func createDevice(accountID: UUID) async throws -> DeviceIdentity {
        await hold(.createDevice)
        return try await base.createDevice(accountID: accountID)
    }
    func create(accountID: UUID, deviceID: UUID) async throws -> DevicePublicKey {
        try await base.create(accountID: accountID, deviceID: deviceID)
    }
    func publicKey(accountID: UUID, deviceID: UUID) async throws -> DevicePublicKey? {
        await hold(.publicKey)
        return try await base.publicKey(accountID: accountID, deviceID: deviceID)
    }
    func sign(_ prepared: [UInt8], accountID: UUID, deviceID: UUID) async throws -> [UInt8] {
        try await base.sign(prepared, accountID: accountID, deviceID: deviceID)
    }
    func delete(accountID: UUID) async throws { try await base.delete(accountID: accountID) }
    func delete(accountID: UUID, deviceID: UUID) async throws {
        try await base.delete(accountID: accountID, deviceID: deviceID)
    }
}

/// A Keychain over `base` that runs a step once, inside the next read of one item, before the read answers.
actor KeychainReadHook: KeychainStore {
    let base: any KeychainStore
    private var item: KeychainItem?
    private var step: (@Sendable () async -> Void)?
    private(set) var ran = false

    init(base: any KeychainStore) { self.base = base }

    func onNextRead(of item: KeychainItem, _ step: @escaping @Sendable () async -> Void) {
        self.item = item
        self.step = step
    }

    func store(_ value: SecureBytes, for item: KeychainItem) async throws { try await base.store(value, for: item) }
    func read(_ item: KeychainItem, prompt: String) async throws -> SecureBytes? {
        if item == self.item, let step {
            self.item = nil
            self.step = nil
            ran = true
            await step()
        }
        return try await base.read(item, prompt: prompt)
    }
    func delete(_ item: KeychainItem) async throws { try await base.delete(item) }
}

/// The unlock's task, handed between two hooks, and what the first saw of it.
actor TaskBox {
    private var task: Task<Void, Never>?
    private(set) var unlocked: Bool?

    func set(_ task: Task<Void, Never>) { self.task = task }
    func note(unlocked: Bool) { self.unlocked = unlocked }
    func wait() async { await task?.value }
}

/// Runs a step once, inside the next listing of one prefix, before the listing answers.
actor TransportListingHook {
    private var prefix: String?
    private var step: (@Sendable () async -> Void)?
    private(set) var ran = false

    func onNextListing(of prefix: String, _ step: @escaping @Sendable () async -> Void) {
        self.prefix = prefix
        self.step = step
    }

    func take(_ prefix: String) -> (@Sendable () async -> Void)? {
        guard prefix == self.prefix, let step else { return nil }
        self.step = nil
        ran = true
        return step
    }
}

/// A transport over `base` whose listing of a prefix runs `hook`'s step first, once.
struct ListingHookedTransport: SyncTransport {
    let base: any SyncTransport
    let hook: TransportListingHook

    func list(prefix: String) async throws -> [String] {
        if let step = await hook.take(prefix) { await step() }
        return try await base.list(prefix: prefix)
    }
    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        try await base.fetch(name, maximumLength: maximumLength)
    }
    func create(_ name: String, contents: [UInt8]) async throws { try await base.create(name, contents: contents) }
    func delete(_ name: String) async throws { try await base.delete(name) }
}
