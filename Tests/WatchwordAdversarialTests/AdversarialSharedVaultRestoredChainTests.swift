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

// The review of round 17 (docs/06-adversarial-review.md Z222 to Z227): the chain row of a restore's earlier device IDs
// (`RestoredChainRow`, Z216), when it is written and what it refuses. In the suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// When sharing becomes configured, relative to the unlock that makes a restore's move (Z222).
    enum SharingConfigured: String, CaseIterable, Sendable {
        /// Before the unlock, as every fixture and the Debug app do: the move writes the row (Z216's case).
        case beforeTheUnlock
        /// After the unlock, while the session is unlocked.
        case afterTheUnlock
        /// While the session is locked after the move, then a password unlock.
        case whileLocked
        /// While the session is locked after the move, then a quick unlock.
        case beforeAQuickUnlock
        /// Before the unlock, with the row lost after the move (a failed write, or a state from a build from before
        /// Z216, which wrote none) and a sync before the damage.
        case rowLostAfterTheMove
    }

    /// Threat: a damaged sync state file, or one edited by an attacker with the device's files (A8), for a shared vault
    /// that holds a restore's uncarried copy of a move, as in `restoredWorkSurvivesAnEditedState` (Z200), on a device
    /// whose sharing was configured after the unlock that made the move (review of round 17, Z222). The chain row was
    /// written only by the move and later saves of the vault's entries, each only if sharing was configured then; the
    /// vault held closed, nothing saved its entries again, so no row was ever written. Once the state was damaged the
    /// chain was empty, the hold failed open, and the original's deletion went out while its copy existed on this
    /// device only (PRD F7.6). The row is now filled in from each vault's verified state whenever sharing and the keys
    /// are both here: when sharing is configured, at each unlock, and at each sync.
    @Test(
        "a restore's uncarried copy holds deletions back after its state is damaged, whenever sharing was configured",
        arguments: SharingConfigured.allCases)
    func restoredChainWhateverSharingWasConfigured(_ order: SharingConfigured) async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 31_000)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)

        await member.session.lock()
        await member.contacts.removePin(for: owner.accountID)
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        let restored = member.vault.relaunched(seed: 31_001)
        let settings = SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory)
        switch order {
        case .beforeTheUnlock, .rowLostAfterTheMove:
            await restored.session.configureSharing(settings)
            try await restored.session.unlock(password: TestVault.password)
        case .afterTheUnlock:
            try await restored.session.unlock(password: TestVault.password)
            #expect(await member.state.value(.restoredChain, vaultID: vaultID) == nil, "the move wrote a row")
            // The move finishes at the unlock without sharing (Z235): the earlier ID's state verifies.
            #expect(try await restored.store.loadAccount()?.migration == nil, "the ordinary move waited for sharing")
            await restored.session.configureSharing(settings)
        case .whileLocked:
            try await restored.session.unlock(password: TestVault.password)
            await restored.session.lock()
            await restored.session.configureSharing(settings)
            #expect(await member.state.value(.restoredChain, vaultID: vaultID) == nil, "a row was signed while locked")
            try await restored.session.unlock(password: TestVault.password)
        case .beforeAQuickUnlock:
            try await restored.session.unlock(password: TestVault.password)
            try await restored.session.enableQuickUnlock(password: TestVault.password)
            await restored.session.lock()
            await restored.session.configureSharing(settings)
            try await restored.session.quickUnlock()
        }
        let account = try #require(try await restored.store.loadAccount())
        #expect(account.migration == nil, "the move did not finish at the unlock")
        if order == .rowLostAfterTheMove {
            #expect(await member.state.value(.restoredChain, vaultID: vaultID) != nil, "the move wrote no row")
            await member.state.tamper(.restoredChain, vaultID: vaultID, value: nil)
            let first = try await restored.session.syncAll()
            #expect(first.deletionsHeldBack.contains(vaultID))
        }
        #expect(await member.state.value(.restoredChain, vaultID: vaultID) != nil, "no chain row was written")

        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
        var state = try #require(await raw.loadState(vaultID: vaultID))
        #expect(!state.restoredUnpublished.isEmpty, "the move recorded nothing to carry")
        state.authenticator = Array(repeating: 0, count: state.authenticator.count)
        await raw.tamper(state)

        let report = try await restored.session.syncAll()
        #expect(report.deletionsHeldBack.contains(vaultID), "the hold failed open on a state that does not verify")
        #expect(report.restoredWorkWaiting[vaultID] == [copy.id])
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original was deleted ahead of its copy")
    }

    /// Threat: A8, an attacker with the device's files, who copies into this device's sharing store a chain row that
    /// the account genuinely signed for another device of the account (a sibling restored once itself), for the
    /// earlier ID (kept from before this restore, about that ID's own earlier IDs), or for another vault; or a row of
    /// another account; or one unsigned, edited, or signed in another form (review of round 17, Z223). Each would name
    /// as earlier IDs of this installation devices that are not, whose published work the carry would write again as
    /// this device's, which every member then holds twice (Z216's attack with genuine bytes). Only the row this
    /// account signed for this device's ID, in this vault, in its one form names anything.
    @Test("a chain row signed for another device, vault or account, or not in its one form, names nothing")
    func restoredChainRowRefusesEveryOtherBinding() throws {
        let keyset = Keyset.generate(accountID: UUID())
        let signingKey = try keyset.publicKeyBundle().signingKey
        let account = keyset.accountID
        let device = UUID()
        let earlier = UUID()
        let sibling = UUID()
        let vaultID = UUID()
        let named: Set<UUID> = [earlier, UUID()]
        func parsed(_ bytes: [UInt8]) -> Set<UUID>? {
            RestoredChainRow.parse(bytes, device: device, account: account, signingKey: signingKey, vaultID: vaultID)
        }

        let genuine = try RestoredChainRow.signed(
            named, device: device, account: account, vaultID: vaultID, keyset: keyset)
        #expect(parsed(genuine) == named, "the genuine row names nothing: nothing is tested")

        let siblings = try RestoredChainRow.signed(
            named, device: sibling, account: account, vaultID: vaultID, keyset: keyset)
        #expect(parsed(siblings) == nil, "a sibling device's row named IDs for this device")
        let earliers = try RestoredChainRow.signed(
            [UUID()], device: earlier, account: account, vaultID: vaultID, keyset: keyset)
        #expect(parsed(earliers) == nil, "the earlier ID's own row named IDs for this device")
        let elsewhere = try RestoredChainRow.signed(
            named, device: device, account: account, vaultID: UUID(), keyset: keyset)
        #expect(parsed(elsewhere) == nil, "another vault's row named IDs here")

        let stranger = Keyset.generate(accountID: UUID())
        let foreign = try RestoredChainRow.signed(
            named, device: device, account: stranger.accountID, vaultID: vaultID, keyset: stranger)
        #expect(parsed(foreign) == nil, "another account's row named IDs here")
        let impostor = try RestoredChainRow.signed(
            named, device: device, account: account, vaultID: vaultID, keyset: stranger)
        #expect(parsed(impostor) == nil, "a row another account signed in this account's name named IDs here")

        var unsigned = genuine
        unsigned.replaceSubrange((unsigned.count - 64)..., with: [UInt8](repeating: 0, count: 64))
        #expect(parsed(unsigned) == nil, "an unsigned row named IDs")
        #expect(parsed(Array(genuine.dropLast(64))) == nil, "a row with no signature named IDs")
        var edited = genuine
        edited[edited.count - 65] ^= 1
        #expect(parsed(edited) == nil, "an edited row named IDs")
        #expect(parsed([]) == nil)

        // The same binding under another row's magic (the key provenance row, bound to an owner's ID).
        let provenance = try SharedKeyProvenance.signed(
            named, owner: device, account: account, vaultID: vaultID, keyset: keyset)
        #expect(parsed(provenance) == nil, "a key provenance row parsed as a chain row")

        // Signed by the account, but not in the row's one form: items out of order, repeated, or miscounted.
        func signedBody(_ items: [UUID], count: Int) throws -> [UInt8] {
            var body: [UInt8] = RestoredChainRow.magic + [SignedLocalSet.formatVersion]
            body += SharedBytes.bytes(account)
            body += SharedBytes.bytes(vaultID)
            body += SharedBytes.bytes(device)
            body += SharedBytes.littleEndian32(UInt32(count))
            for item in items { body += SharedBytes.bytes(item) }
            return body + (try keyset.sign(body, domain: .membership))
        }
        let ordered = named.sorted { SharedBytes.bytes($0).lexicographicallyPrecedes(SharedBytes.bytes($1)) }
        let handBuilt = try signedBody(ordered, count: 2)
        #expect(parsed(handBuilt) == named, "the hand-built row is not the row's form")
        let reversed: [UUID] = ordered.reversed()
        let outOfOrder = try signedBody(reversed, count: 2)
        #expect(parsed(outOfOrder) == nil, "a row with items out of order named IDs")
        let repeated: [UUID] = [ordered[0], ordered[0]]
        let twice = try signedBody(repeated, count: 2)
        #expect(parsed(twice) == nil, "a row with a repeated item named IDs")
        let overCounted = try signedBody(ordered, count: 3)
        #expect(parsed(overCounted) == nil, "a miscounted row named IDs")
        let underCounted = try signedBody(ordered, count: 1)
        #expect(parsed(underCounted) == nil, "a miscounted row named IDs")
    }

    /// Threat: none needed but a crash, or a sharing store that cannot be written, between the save of a vault's state
    /// that `recordRestoredWorkLeft` starts over and that vault's chain row (review of round 17, Z224), then the state
    /// damaged again (A8, or the disk). The earlier ID that state names came from another vault's chain, and the
    /// other vault's carry has since removed it there; the row of the vault started over is then all that names it.
    /// The row is written before the state, with the IDs the state is about to name (Z216): written only after, it
    /// was never written, the chain was empty once the state was damaged, and the hold failed open on rows the
    /// earlier ID left. Here those rows are ones that ID published, in a vault held closed, whose stream this device
    /// cannot read: they count, as Z200 accepts.
    @Test("a crash between a started-over state and its chain row leaves the chain naming the state's earlier IDs")
    func restoredChainRowWrittenBeforeTheState() async throws {
        let household = SharedVaultHousehold()
        let (open, owner, members) = try await household.household(roles: [.readWrite], seed: 31_100)
        let member = members[0]
        let closer = try await household.account(seed: 31_150)
        let closed = try await closer.session.createVault(name: "Second").id
        try await closer.session.shareVault(closed)
        try await closer.invite(member, to: closed, as: .readWrite, owner: closer)
        try await Self.syncAll([closer, member])
        let published = try await member.session.save(Self.bank(in: closed))
        try await Self.syncAll([member, owner, closer])
        let pending = try await member.session.save(Self.bank(in: open))

        // Restored without the second owner's pin: that vault is held closed here, and the first one opens.
        await member.session.lock()
        await member.contacts.removePin(for: closer.accountID)
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
        let sharingState = ChainRowFailingSharingStore(base: member.state, syncState: raw, vaultID: closed)
        let restored = member.vault.relaunched(seed: 31_101)
        await restored.session.configureSharing(
            SharingSettings(state: sharingState, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)
        #expect(try await restored.store.loadAccount()?.migration == nil, "the move did not finish at the unlock")
        let earlier = try #require(await raw.loadState(vaultID: open)?.restoredUnpublished.values.first?.device)
        #expect(await raw.loadState(vaultID: closed)?.restoredUnpublished.isEmpty == true)
        #expect(await member.state.value(.restoredChain, vaultID: closed) == nil)

        func damage(_ vaultID: UUID) async throws {
            var state = try #require(await raw.loadState(vaultID: vaultID))
            state.authenticator = Array(repeating: 0, count: state.authenticator.count)
            await raw.tamper(state)
        }
        // The closed vault's state damaged: the sync starts it over, naming the rows the earlier ID left there, and
        // every write of its row after that save fails.
        try await damage(closed)
        await sharingState.failWritesAfterTheSave()
        let first = try await restored.session.syncAll()
        #expect(first.deletionsHeldBack.contains(closed))
        #expect(await sharingState.refused > 0, "no write of the row failed after the save: nothing is tested")
        let started = try #require(await raw.loadState(vaultID: closed))
        #expect(started.restoredUnpublished[RecordKey(recordID: published.id, kind: .item)]?.device == earlier)
        // The open vault's carry removes the earlier ID from its own state and row.
        for _ in 0..<3 {
            let left = await raw.loadState(vaultID: open)?.restoredUnpublished ?? [:]
            if left.isEmpty { break }
            _ = try await restored.session.syncAll()
        }
        #expect(await raw.loadState(vaultID: open)?.restoredUnpublished.isEmpty == true, "the carry did not finish")
        #expect(await member.state.value(.restoredChain, vaultID: open) == nil)
        _ = pending

        try await damage(closed)
        let report = try await restored.session.syncAll()
        #expect(report.deletionsHeldBack.contains(closed), "the hold failed open: the chain lost the earlier ID")
        #expect(report.restoredWorkWaiting[closed] == [published.id])
    }

    /// Threat: a damaged sync state file, or one edited by an attacker with the device's files (A8), on a store
    /// restored onto other hardware twice (review of round 17, Z225 and Z226), whose first restore left the uncarried
    /// copy of a move in a shared vault held closed. The second restore's move read what the first left only from the
    /// first restore's signed state: where that state did not verify in the backup (`retried: false`), or where the
    /// second restore's own first attempt at the move saved its state, failed before it finished and that state was
    /// then damaged (`retried: true`), the move found only the rows the middle ID left, recorded nothing for the copy,
    /// and wrote a chain row that no longer named the first ID (`keeping: false`). The state then verified and named
    /// nothing, the hold ended, and the original's deletion went out while its copy existed on this device only (PRD
    /// F7.6). The move now adds to the chain row rather than replacing it, and where no state verifies it finds the
    /// rows of the IDs the vault's chain row names (its own from the failed attempt, or the middle ID's own row) again.
    @Test(
        "a store restored twice keeps its first restore's uncarried copy held when the state it was read from is lost",
        arguments: [false, true])
    func restoredTwiceAfterADamagedState(retried: Bool) async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 31_200)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        let first = try #require(await member.session.deviceIDForTest())
        let middle = try await Self.restoredWithVaultClosed(member, household: household, owner: owner, seed: 31_201)
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
        let recorded = await raw.loadState(vaultID: vaultID)?.restoredUnpublished ?? [:]
        #expect(recorded.values.contains { $0.device == first }, "the first restore recorded nothing to carry")

        func damage() async throws {
            var state = try #require(await raw.loadState(vaultID: vaultID))
            state.authenticator = Array(repeating: 0, count: state.authenticator.count)
            await raw.tamper(state)
        }
        // Restored again, before anything was carried.
        await middle.session.lock()
        await middle.forgetDeviceKey(accountID: member.accountID)
        if !retried { try await damage() }
        let store = MigrationClearFailingStore(base: middle.store, failing: retried)
        let second = TestVault(
            store: store, keychain: middle.keychain, biometrics: middle.biometrics, clock: middle.clock,
            sync: middle.sync, seed: 31_202, deviceKeys: middle.deviceKeys)
        await second.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await second.session.unlock(password: TestVault.password)
        let pending = try await second.store.loadAccount()?.migration
        if retried {
            #expect(await store.failed == 1, "the first attempt at the move did not fail: nothing is tested")
            #expect(pending != nil, "the move finished at its first attempt: nothing is tested")
            try await damage()
        } else {
            #expect(pending == nil, "the move did not finish at the unlock")
        }

        let report = try await second.session.syncAll()
        #expect(!report.deviceMigrationIncomplete, "the move was not made again")
        #expect(report.deletionsHeldBack.contains(vaultID), "the hold ended with the state the first ID was read from")
        #expect(report.restoredWorkWaiting[vaultID] == [copy.id])
        let state = await raw.loadState(vaultID: vaultID)?.restoredUnpublished ?? [:]
        #expect(state[RecordKey(recordID: copy.id, kind: .item)]?.device == first, "the copy was not recorded again")
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original was deleted ahead of its copy")

        try await second.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        _ = try await second.session.syncAll()
        _ = try await second.session.syncAll()
        try await Self.syncAll([owner, other])
        #expect(try await owner.session.item(id: copy.id).title == copy.title, "the copy never reached the owner")
        #expect((try? await other.session.item(id: original.id)) == nil, "the original's deletion never went out")
    }

    /// Threat: a damaged sync state file, or one edited by an attacker with the device's files (A8), on a store
    /// restored twice (E, then N, then N2) whose N state for a shared vault does not verify in N2's backup, as in
    /// `restoredTwiceAfterADamagedState(retried: false)`, on a session given sharing only after the unlock that makes
    /// the move: a process given sync and not sharing (the AutoFill extension is not given it) that unlocks first
    /// after the restore (review of round 18, Z229). N's chain row, bound to N and naming E, is in the sharing store,
    /// and the move can read it only through sharing: without it the move recorded nothing for E's uncarried copy,
    /// saved a state that verifies, and cleared its record; the backfill reads only verified states, so nothing read
    /// N's row again, the hold ended, and the original's deletion went out while its copy existed on this device only
    /// (PRD F7.6). The move now waits, its record kept and nothing published, while it would read a chain row and
    /// sharing is not configured; `configureSharing` makes it.
    @Test("a store restored twice keeps its first restore's uncarried copy held when sharing is configured late")
    func restoredTwiceWithSharingConfiguredLate() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 31_300)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        let first = try #require(await member.session.deviceIDForTest())
        let middle = try await Self.restoredWithVaultClosed(member, household: household, owner: owner, seed: 31_301)
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
        let recorded = await raw.loadState(vaultID: vaultID)?.restoredUnpublished ?? [:]
        #expect(recorded.values.contains { $0.device == first }, "the first restore recorded nothing to carry")
        #expect(await member.state.value(.restoredChain, vaultID: vaultID) != nil, "the middle ID wrote no row")

        // Restored again, before anything was carried, with the middle ID's state damaged in the backup.
        await middle.session.lock()
        await middle.forgetDeviceKey(accountID: member.accountID)
        var damaged = try #require(await raw.loadState(vaultID: vaultID))
        damaged.authenticator = Array(repeating: 0, count: damaged.authenticator.count)
        await raw.tamper(damaged)
        let second = TestVault(
            store: middle.store, keychain: middle.keychain, biometrics: middle.biometrics, clock: middle.clock,
            sync: middle.sync, seed: 31_302, deviceKeys: middle.deviceKeys)
        try await second.session.unlock(password: TestVault.password)
        #expect(try await second.store.loadAccount()?.migration != nil, "the move finished without the chain row")
        // A sync before sharing: the move still waits, and this device publishes nothing meanwhile.
        let waiting = try await second.session.syncAll()
        #expect(waiting.deviceMigrationIncomplete, "the move finished at a sync without the chain row")
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original went while the move waited")

        await second.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        #expect(try await second.store.loadAccount()?.migration == nil, "configuring sharing did not make the move")
        let state = await raw.loadState(vaultID: vaultID)?.restoredUnpublished ?? [:]
        #expect(state[RecordKey(recordID: copy.id, kind: .item)]?.device == first, "the copy was not recorded again")

        let report = try await second.session.syncAll()
        #expect(!report.deviceMigrationIncomplete)
        #expect(report.deletionsHeldBack.contains(vaultID), "the hold ended without the middle ID's chain row")
        #expect(report.restoredWorkWaiting[vaultID] == [copy.id])
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original was deleted ahead of its copy")

        try await second.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        _ = try await second.session.syncAll()
        _ = try await second.session.syncAll()
        try await Self.syncAll([owner, other])
        #expect(try await owner.session.item(id: copy.id).title == copy.title, "the copy never reached the owner")
        #expect((try? await other.session.item(id: original.id)) == nil, "the original's deletion never went out")
    }
}

/// A record store over `base` whose first commit that clears the account's device migration fails, when `failing`:
/// a move of an earlier device ID's sync state that saved every vault's state and then failed to finish (Z181).
actor MigrationClearFailingStore: RecordStore {
    let base: any RecordStore
    private var failing: Bool
    private(set) var failed = 0

    init(base: any RecordStore, failing: Bool) {
        self.base = base
        self.failing = failing
    }

    func loadAccount() async throws -> AccountRecord? { try await base.loadAccount() }
    func record(_ key: RecordKey) async throws -> StoredRecord? { try await base.record(key) }

    func records(in vaultID: UUID, kind: EnvelopeKind) async throws -> [StoredRecord] {
        try await base.records(in: vaultID, kind: kind)
    }

    func commit(_ change: StoreChange) async throws {
        if failing, change.migration == .clear {
            failing = false
            failed += 1
            throw RecordStoreError.checkpointIncomplete
        }
        try await base.commit(change)
    }

    func eraseAll() async throws { try await base.eraseAll() }
}

/// A sharing state store over `base` that, once armed, refuses every write of one vault's chain row
/// (`SharingStateKey.restoredChain`) made after that vault's sync state has been saved since it was last damaged
/// (its authenticator zeroed): a crash, or a store that cannot be written, between the save and the row.
actor ChainRowFailingSharingStore: SharingStateStore {
    struct WriteFailed: Error {}

    let base: InMemorySharingStateStore
    let syncState: InMemorySyncStateStore
    let vaultID: UUID
    private var armed = false
    private(set) var refused = 0

    init(base: InMemorySharingStateStore, syncState: InMemorySyncStateStore, vaultID: UUID) {
        self.base = base
        self.syncState = syncState
        self.vaultID = vaultID
    }

    func failWritesAfterTheSave() {
        armed = true
    }

    func sharedVaultIDs() async throws -> [UUID] { await base.sharedVaultIDs() }

    func value(_ key: SharingStateKey, vaultID: UUID) async throws -> [UInt8]? {
        await base.value(key, vaultID: vaultID)
    }

    func setValue(_ value: [UInt8]?, for key: SharingStateKey, vaultID: UUID) async throws {
        if armed, key == .restoredChain, vaultID == self.vaultID,
            let saved = await syncState.loadState(vaultID: vaultID), saved.authenticator.contains(where: { $0 != 0 })
        {
            refused += 1
            throw WriteFailed()
        }
        await base.setValue(value, for: key, vaultID: vaultID)
    }
}
