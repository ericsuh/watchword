import Foundation
import Testing
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

extension VaultSession {
    /// For tests: the vault as a take-out that ended at the current head earlier in this session leaves it (S65's
    /// `takenOutAgainst`), as one that returned at its first guard before a replay was asked for would.
    func markTakenOutAgainstTheCurrentHead(_ vaultID: UUID) {
        let head = sharing.vaults[vaultID]?.ledger.state.hash.bytes
        sharing.vaults[vaultID]?.takenOutAgainst = head
    }

    /// For tests: the membership head this device holds for `vaultID`.
    func sharedHead(_ vaultID: UUID) -> [UInt8]? {
        sharing.vaults[vaultID]?.ledger.state.hash.bytes
    }
}

// The review of round 22 (docs/06-adversarial-review.md Z254) and of PR #22's seventh merge (Z258): reads of a vault's
// sync state that decide whether a restore's work is carried before the vault merges, or is left alone by the
// take-out, where one that failed was read as "nothing there"; and the review of round 23 (Z262): a take-out that
// failed so is not settled away by the replay after it. In the suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// Z210's setting: a member's unpublished reorder of a shared item and the owner's concurrent reorder, with IDs
    /// that order so that only a carry made before the merge keeps the member's order, and the member's store restored
    /// onto other hardware over `state`. The item, its key, both versions, and the reference the carry should give.
    struct ReorderedRestore {
        let household: SharedVaultHousehold
        let vaultID: UUID
        let owner: SharingAccount
        let member: SharingAccount
        let item: UUID
        let expected: [UUID]
    }

    static func reorderedRestore(
        state: (any SyncStateStore, UUID) -> any SyncStateStore,
        sharing: (InMemorySharingStateStore) -> any SharingStateStore
    ) async throws -> (ReorderedRestore, TestVault) {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 30_700)
        let member = members[0]
        let saved = try await member.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([member, owner])
        let key = RecordKey(recordID: saved.id, kind: .item)
        let published = try #require(try await member.vault.store.record(key)).version
        var mine = try await member.session.item(id: saved.id)
        mine.fields.reverse()
        _ = try await member.session.save(mine)
        let a = try await member.session.item(id: saved.id)
        let aRow = try #require(try await member.vault.store.record(key))
        var theirs = try await owner.session.item(id: saved.id)
        theirs.fields.append(theirs.fields.removeFirst())
        _ = try await owner.session.save(theirs)
        try await owner.session.sync()
        let b = try await owner.session.item(id: saved.id)
        let bRow = try #require(await owner.session.storedRowForTest(key))

        await member.session.lock()
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        let restored = TestVault(
            store: member.vault.store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock,
            sync: SyncSettings(
                state: state(try #require(member.vault.sync?.state), vaultID), transport: household.transport),
            seed: 30_701, deviceKeys: member.vault.deviceKeys)
        await restored.session.configureSharing(
            SharingSettings(state: sharing(member.state), contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)
        let newID = try #require(await restored.session.deviceIDForTest())
        let carriedFirst = ItemMerge.reattributed(
            a, origin: Revision(version: aRow.version, device: aRow.deviceID), from: aRow.deviceID, above: published,
            to: newID)
        let reference = ItemMerge.merge(
            carriedFirst, origin: Revision(version: aRow.version, device: newID), b,
            origin: Revision(version: bRow.version, device: bRow.deviceID))
        #expect(reference.fields.map(\.id) == a.fields.map(\.id), "the carry's place decides nothing here")
        let setting = ReorderedRestore(
            household: household, vaultID: vaultID, owner: owner, member: member, item: saved.id,
            expected: reference.fields.map(\.id))
        return (setting, restored)
    }

    /// After a few syncs both ways: the owner holds no version aside, and both devices hold the carry's merge.
    static func expectCarriedFirst(_ setting: ReorderedRestore, restored: TestVault) async throws {
        for _ in 0..<3 {
            _ = try await restored.session.syncAll()
            try await setting.owner.session.sync()
        }
        let ownerCopy = try await setting.owner.session.item(id: setting.item)
        let here = try await restored.session.item(id: setting.item)
        #expect(try await setting.owner.session.quarantine().isEmpty, "the owner holds a version aside")
        #expect(ownerCopy.fields.map(\.id) == setting.expected, "the owner does not hold the merge of the carry")
        #expect(here.fields.map(\.id) == setting.expected, "the restored device does not hold the merge of the carry")
        #expect(ItemMerge.sameState(here, ownerCopy), "the restored device and the owner hold different items")
    }

    /// Threat: none needed but a sync state store that fails one read (a busy or damaged database), on a store
    /// restored onto other hardware whose earlier ID's reorder of a shared item nobody received, while the owner
    /// reordered it too (Z210's setting); the review of round 22 (Z254). `restoredWorkToCarry` read the vault's state
    /// with `try?`: one failed read there was "nothing to carry", and the vault's pass merged what it pulled into the
    /// row still holding the earlier ID's work, and published, before the carry: the person's order was lost on both
    /// devices (Z204's L1) and the owner held aside a version under the new ID with the earlier ID's values (Z191).
    /// A state that cannot be read now counts as something to carry. Each argument fails a different read of the sync.
    @Test(
        "one failed state read in a restored device's sync still carries its work before the vault merges",
        arguments: Array(0..<12))
    func carryWaitsForAFailedStateRead(skipping: Int) async throws {
        var wrapped: LoadFailingSyncState?
        let (setting, restored) = try await Self.reorderedRestore(
            state: { base, vaultID in
                let store = LoadFailingSyncState(base: base, vaultID: vaultID)
                wrapped = store
                return store
            }, sharing: { $0 })
        let failing = try #require(wrapped)
        let raw = try #require(setting.member.vault.sync?.state)
        let before = try await raw.loadState(vaultID: setting.vaultID)
        #expect(before?.restoredUnpublished.isEmpty == false, "nothing recorded to carry: nothing is tested")

        await failing.arm(skipping: skipping)
        _ = try? await restored.session.syncAll()
        try await Self.expectCarriedFirst(setting, restored: restored)
    }

    /// Threat: a damaged sync state file, or one edited by an attacker with the device's files (A8), for a shared vault
    /// on a store restored onto other hardware (Z210's setting), beside a sharing store that fails one read of the
    /// vault's chain row (busy or damaged); the review of round 22 (Z254, by reading). Where the state does not verify,
    /// what the restore left is recorded again from the rows before any log (`recordRestoredWorkLeft`), and that needs
    /// the chain row; one that could not be read recorded nothing, the vault was not one with anything to carry, and
    /// it merged what it pulled into the earlier ID's rows and published: the rows became the new ID's, so nothing
    /// found or carried the earlier ID's work again (the person's order lost, a version held aside). Such a vault now
    /// merges and publishes nothing in that sync, reported, and the next records and carries.
    @Test("a vault whose restored work could not be recorded again merges nothing before it is carried")
    func unrecordedVaultWaitsForTheCarry() async throws {
        var unreadable: ChainRowUnreadableSharingStore?
        let (setting, restored) = try await Self.reorderedRestore(
            state: { base, _ in base },
            sharing: { base in
                let store = ChainRowUnreadableSharingStore(base: base)
                unreadable = store
                return store
            })
        let failing = try #require(unreadable)
        let raw = try #require(setting.member.vault.sync?.state as? InMemorySyncStateStore)
        var damaged = try #require(await raw.loadState(vaultID: setting.vaultID))
        #expect(!damaged.restoredUnpublished.isEmpty, "nothing recorded to carry: nothing is tested")
        damaged.authenticator = Array(repeating: 0, count: damaged.authenticator.count)
        await raw.tamper(damaged)

        await failing.failNextReads(1, in: setting.vaultID)
        let first = try await restored.session.syncAll()
        #expect(await failing.refused > 0, "no read of the chain row failed: nothing is tested")
        #expect(first.publishingHeldForCarry.contains(setting.vaultID), "the vault was not reported waiting")
        #expect(first.vaults[setting.vaultID]?.applied == 0, "the vault merged before its work was recorded again")
        #expect(first.vaults[setting.vaultID]?.pushedEntries == 0, "the vault published before its work was carried")
        try await Self.expectCarriedFirst(setting, restored: restored)
    }

    /// Threat: none needed but a sync state store that fails one read (a busy or damaged database) on a store restored
    /// onto other hardware whose earlier ID moved an item into an open shared vault and never synced, and a change of
    /// the vault's membership since the backup; the review of PR #22's seventh merge (Z258, Z245's class). The take-out
    /// read the vault's state with `try?`: one failed read and it found no restored work, judged the earlier ID's
    /// uncarried copy, which no segment carried, and took it out into the quarantine, where nothing carries it (PRD
    /// F7.6). A state that cannot be read now leaves the take-out to the next sync. Each argument fails a different
    /// read of the sync.
    @Test(
        "one failed state read as the take-out runs takes none of a restore's uncarried work out",
        arguments: Array(0..<10))
    func takeOutWaitsForAFailedStateRead(skipping: Int) async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite, .readOnly], seed: 33_360)
        let member = members[0]
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, members[1]])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        await member.session.lock()
        await member.vault.forgetDeviceKey(accountID: member.accountID)

        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
        let failing = LoadFailingSyncState(base: raw, vaultID: vaultID)
        let restored = TestVault(
            store: member.vault.store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock, sync: SyncSettings(state: failing, transport: household.transport),
            seed: 33_361, deviceKeys: member.vault.deviceKeys)
        await restored.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)
        let key = RecordKey(recordID: copy.id, kind: .item)
        #expect(await raw.loadState(vaultID: vaultID)?.restoredUnpublished[key] != nil, "the copy was not recorded")

        // The vault's membership changes since the backup, so that the sharing pass judges again.
        try await owner.session.changeRole(of: members[1].accountID, in: vaultID, to: .readWrite)
        try await owner.session.sync()
        await failing.arm(skipping: skipping)
        _ = try? await restored.session.syncAll()
        #expect(await raw.quarantined(vaultID: vaultID).allSatisfy { $0.recordID != copy.id }, "the copy was taken out")
        for _ in 0..<2 { _ = try await restored.session.syncAll() }
        try await owner.session.sync()
        #expect((try? await owner.session.item(id: copy.id)) != nil, "the copy never reached the owner")
    }

    /// Threat: a demoted member (A4) whose late write this device merged before it learnt of the demotion, and a sync
    /// state store that fails the take-out's one read (a busy or damaged database) in a sync where a replay was
    /// already owed (a key received, a stream's account learnt); the review of round 23 (Z262, a regression of Z258).
    /// The take-out threw before taking anything out, the vault's first pass was the owed replay, and
    /// `sharedEngineDidRun` settled the judged basis after it: every later take-out returned at its first guard, and
    /// the late write stayed current on this device for good, where every other device holds it aside (§8.7 "taken
    /// out, not only kept out"), to be sealed into this device's later merges as its own work. A take-out that did not
    /// finish now leaves the basis unsettled (`takeOutsOwed`), and the next take-out, here the replay's in the same
    /// sync, acts on it.
    @Test("a take-out that fails on its state read is not settled away by the replay after it")
    func takeOutThatFailedIsNotSettledAway() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 900)
        let (demoted, demotedView) = try await household.withheldAccount(seed: 917)
        let (member, memberView) = try await household.withheldAccount(seed: 934)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(demoted, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, demoted, member])
        var before = try await demoted.session.item(id: bank.id)
        before.title = "Written while read-write"
        try await demoted.session.save(before)
        try await Self.syncAll([demoted, owner, member])

        // The demotion is withheld from both members; the demoted member writes late, and the member merges it.
        await demotedView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        await memberView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        try await owner.session.changeRole(of: demoted.accountID, in: vaultID, to: .readOnly)
        try await demoted.session.save(
            Self.setting(.password, to: "late-password", in: try await demoted.session.item(id: bank.id)))
        try await demoted.session.sync()
        try await member.session.sync()
        #expect(try await member.session.item(id: bank.id).field(.password)?.value == "late-password")
        try await owner.session.sync()

        // The member's device again, over a state store that fails one read of the vault's state: the third of the
        // next sync, which is the take-out's, with a replay already owed.
        await member.session.lock()
        let sync = try #require(member.vault.sync)
        let failing = LoadFailingSyncState(base: sync.state, vaultID: vaultID)
        let relaunched = TestVault(
            store: member.vault.store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock,
            sync: SyncSettings(state: failing, transport: sync.transport, configuration: sync.configuration),
            seed: 935, deviceKeys: member.vault.deviceKeys)
        await relaunched.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)
        await memberView.reveal()
        _ = try? await relaunched.session.sharedVaultStatus(vaultID)
        await relaunched.session.requestReplay(vaultID)
        #expect(await relaunched.session.replayIsRequested(vaultID), "no replay owed: nothing is tested")
        await failing.arm(skipping: 2)
        let first = try? await relaunched.session.syncAll()
        #expect(first?.sharing[vaultID]?.failure != nil, "the take-out did not fail: nothing is tested")
        #expect(await failing.failed == 1, "not one read failed: nothing is tested")
        for _ in 0..<3 {
            _ = try await relaunched.session.syncAll()
            try await owner.session.sync()
        }
        let settled = try await relaunched.session.item(id: bank.id)
        #expect(settled.field(.password)?.value == "bank-password", "the demoted member's late write was kept")
    }

    /// Threat: as above (A4's late write, a take-out's one failed state read, a replay owed), merged into the hygiene
    /// branch, where S65 asks of a settling pass that the take-out before it saw the head it ends on
    /// (`takenOutAgainst`). The PoC above relaunches the session, which leaves `takenOutAgainst` unset, so there S65
    /// alone settles nothing; but a take-out that returned at its first guard at the current head earlier in a session
    /// leaves it set, and a take-out that throws afterwards leaves it so. Here the demotion is ingested by a sync made
    /// while locked (no take-out), and the vault marked as such a take-out leaves it: only `takeOutsOwed` keeps the
    /// replay after the failed take-out from settling the basis, and the late write is taken out in the same sync.
    @Test("a take-out that fails at the head it last saw is not settled away by the replay after it")
    func takeOutThatFailedAtTheHeadItLastSawIsNotSettledAway() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 950)
        let (demoted, demotedView) = try await household.withheldAccount(seed: 967)
        let (member, memberView) = try await household.withheldAccount(seed: 984)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(demoted, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, demoted, member])
        var before = try await demoted.session.item(id: bank.id)
        before.title = "Written while read-write"
        try await demoted.session.save(before)
        try await Self.syncAll([demoted, owner, member])

        await demotedView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        await memberView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        try await owner.session.changeRole(of: demoted.accountID, in: vaultID, to: .readOnly)
        try await demoted.session.save(
            Self.setting(.password, to: "late-password", in: try await demoted.session.item(id: bank.id)))
        try await demoted.session.sync()
        try await member.session.sync()
        #expect(try await member.session.item(id: bank.id).field(.password)?.value == "late-password")
        try await owner.session.sync()

        await member.session.lock()
        let sync = try #require(member.vault.sync)
        let failing = LoadFailingSyncState(base: sync.state, vaultID: vaultID)
        let relaunched = TestVault(
            store: member.vault.store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock,
            sync: SyncSettings(state: failing, transport: sync.transport, configuration: sync.configuration),
            seed: 985, deviceKeys: member.vault.deviceKeys)
        await relaunched.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        // Locked, the sync ingests the demotion and takes nothing out (Z253).
        try await relaunched.session.unlock(password: TestVault.password)
        _ = try? await relaunched.session.sharedVaultStatus(vaultID)
        await relaunched.session.lock()
        let headBefore = await relaunched.session.sharedHead(vaultID)
        await memberView.reveal()
        _ = try await relaunched.session.syncAll()
        let head = await relaunched.session.sharedHead(vaultID)
        #expect(head != nil && head != headBefore, "the locked sync did not ingest the demotion: nothing is tested")
        try await relaunched.session.unlock(password: TestVault.password)
        _ = try? await relaunched.session.sharedVaultStatus(vaultID)
        await relaunched.session.markTakenOutAgainstTheCurrentHead(vaultID)
        await relaunched.session.requestReplay(vaultID)
        #expect(await relaunched.session.replayIsRequested(vaultID), "no replay owed: nothing is tested")
        await failing.arm(skipping: 2)
        let first = try? await relaunched.session.syncAll()
        #expect(first?.sharing[vaultID]?.failure != nil, "the take-out did not fail: nothing is tested")
        #expect(await failing.failed == 1, "not one read failed: nothing is tested")
        #expect(await relaunched.session.sharedHead(vaultID) == head, "the head moved: S65 alone would hold")
        let settled = try await relaunched.session.item(id: bank.id)
        #expect(settled.field(.password)?.value == "bank-password", "the demoted member's late write was kept")
    }
}
