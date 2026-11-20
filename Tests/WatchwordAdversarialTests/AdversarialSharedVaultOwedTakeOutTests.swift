import Foundation
import Testing
import WatchwordModel
import WatchwordPresentation
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

extension VaultSession {
    /// For tests: a registration of this installation under way (`registrationInFlight`), as an unlock's is while a
    /// sync reads the device's standing.
    func setRegistrationInFlightForTest(_ inFlight: Bool) {
        registrationInFlight = inFlight
    }

    /// For tests: what a take-out leaves where it took `key`'s row out (into the quarantine, out of the store) and then
    /// threw, with the vault still owed, and the basis since come back to the one judged.
    func leavePartialTakeOut(of key: RecordKey, in vaultID: UUID) async throws {
        guard let row = try await store.record(key), let syncSettings else { return }
        try await syncSettings.state.quarantine(SyncEntry(row), vaultID: vaultID)
        try await store.commit(StoreChange(conditionalDeletions: [row.key: row.version]))
        takeOutsOwed.insert(vaultID)
    }
}

// The review of round 24 (docs/06-adversarial-review.md Z267 on): a take-out that is owed (`takeOutsOwed`, Z262) and
// what the sync does meanwhile, in the suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// Z262's setting: a demoted member's late write that the member merged before learning of the demotion, the
    /// member's device relaunched over `failing` with a replay owed, and a permanent deletion in the member's Personal
    /// vault queued before that.
    struct OwedTakeOut {
        let household: SharedVaultHousehold
        let owner: SharingAccount
        let member: SharingAccount
        let vaultID: UUID
        let bank: UUID
        let personal: UUID
        let sync: SyncSettings
        let failing: LoadFailingSyncState
        let relaunched: TestVault
    }

    static func owedTakeOut(replayOwed: Bool = true) async throws -> OwedTakeOut {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 900)
        let (demoted, demotedView) = try await household.withheldAccount(seed: 917)
        let (member, memberView) = try await household.withheldAccount(seed: 934)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(demoted, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let doomed = try await member.session.save(Self.bank(in: personal))
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
        // A deletion of the member's own, in a vault the demotion does not touch.
        try await member.session.trash(id: doomed.id)
        try await member.session.deletePermanently(id: doomed.id)

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
        if replayOwed {
            await relaunched.session.requestReplay(vaultID)
            #expect(await relaunched.session.replayIsRequested(vaultID), "no replay owed: nothing is tested")
        }
        return OwedTakeOut(
            household: household, owner: owner, member: member, vaultID: vaultID, bank: bank.id, personal: personal,
            sync: sync, failing: failing, relaunched: relaunched)
    }

    /// The person's edit of the item that holds the late write, on the relaunched device, before its sync.
    static func editOverTheLateWrite(_ setting: OwedTakeOut) async throws {
        var edit = try await setting.relaunched.session.item(id: setting.bank)
        edit.title = "Edited over the late write"
        try await setting.relaunched.session.save(edit)
    }

    /// Once a take-out has finished, the edit, built on the late write, is held aside here with it, as an edit made
    /// before this device learnt of the demotion is with no failure at all (S44), and the deletions wait for it like
    /// for any work of this device's that reached nobody (Z44), until the person discards it under Held-Aside Changes,
    /// as here; then a sync sends them.
    static func discardTheHeldAsideEdit(_ setting: OwedTakeOut, after last: AccountSyncReport, in session: VaultSession)
        async throws
    {
        #expect(last.deletionsHeldBack == [setting.vaultID])
        let ownDevice = try #require(try await setting.member.vault.store.loadAccount()?.deviceID)
        let edits = try await session.quarantine().filter {
            $0.vaultID == setting.vaultID && $0.entry.recordID == setting.bank && $0.entry.device == ownDevice
        }
        #expect(!edits.isEmpty, "the edit was not held aside")
        try await session.discardQuarantined(edits)
        _ = try await session.syncAll()
    }

    /// Threat: a demoted member (A4) whose late write this device merged before it learnt of the demotion, and a sync
    /// state store that fails the reads of both take-outs of one sync, the sharing pass's and the replay loop's (a busy
    /// or damaged database); the review of round 24 (Z267, the replay loop's failure path of Z262, pinned by nothing).
    /// `prepareSharedReplay` must throw, so that no replay runs after a take-out that did not finish, and the replay
    /// loop must hold this device's deletions in every vault for that sync: what the take-out may have put aside of
    /// this device's own could be the copy half of a move whose deletion is queued (PRD F7.6). With `try?` the replay
    /// ran, and without the hold the Personal vault's deletion went out. After a relaunch over a store that reads, the
    /// owed take-out is not forgotten: the late write is taken out and the deletion goes out.
    @Test("a sync whose two take-outs fail holds every deletion, and a relaunch takes the late write out")
    func replayLoopTakeOutThatFailsHoldsDeletions() async throws {
        let setting = try await Self.owedTakeOut()
        let (vaultID, failing, relaunched) = (setting.vaultID, setting.failing, setting.relaunched)
        // The person's edit of the item, over the late write: unpublished work of this device's in the vault, which
        // a replay that runs after a take-out that did not finish would publish.
        try await Self.editOverTheLateWrite(setting)
        // The third read of the vault's state is the sharing pass's take-out, the sixth the replay loop's (as traced;
        // a change in the reads between them shows below, as a take-out that did not fail).
        await failing.script([.read, .read, .fail(before: nil), .read, .read, .fail(before: nil)])
        let first = try await relaunched.session.syncAll()
        #expect(await failing.failed == 2, "not both take-outs failed: nothing is tested")
        #expect(first.sharing[vaultID]?.failure != nil, "the take-out's failure was not reported")
        #expect(first.vaults[vaultID]?.pushedEntries == 0, "a replay ran after a take-out that did not finish")
        // Said, in words of its own (Z268): not as something moved that reached nobody.
        #expect(first.takeOutUnfinished == [vaultID], "the hold was silent")
        #expect(SyncSummary(first).notices.contains(.takeOutUnfinished))
        #expect(!SyncSummary(first).notices.contains(.deletionsHeldBack))
        let pending = try await setting.sync.state.pendingDeletions(vaultID: setting.personal)
        #expect(pending.count == 1, "the deletion went out after a take-out that did not finish")
        #expect(try await relaunched.session.item(id: setting.bank).field(.password)?.value == "late-password")

        // Relaunched again over a state store that reads: the owed take-out is not forgotten.
        await relaunched.session.lock()
        let member = setting.member
        let again = TestVault(
            store: member.vault.store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock, sync: setting.sync, seed: 936, deviceKeys: member.vault.deviceKeys)
        await again.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: setting.household.directory))
        try await again.session.unlock(password: TestVault.password)
        var last = AccountSyncReport()
        for _ in 0..<3 {
            last = try await again.session.syncAll()
            try await setting.owner.session.sync()
        }
        #expect(last.takeOutUnfinished.isEmpty, "a take-out that finished is still reported unfinished")
        let settled = try await again.session.item(id: setting.bank)
        #expect(settled.field(.password)?.value == "bank-password", "the demoted member's late write was kept")
        try await Self.discardTheHeldAsideEdit(setting, after: last, in: again.session)
        #expect(
            try await setting.sync.state.pendingDeletions(vaultID: setting.personal).isEmpty,
            "the deletion never went out")
    }

    /// Threat: none but local failure; the review of round 24 (Z269, finding 5, pre-existing). A take-out that took
    /// rows out of the vault and then threw (a conditional commit lost to a save, a quarantine write) leaves the vault
    /// owed; if the basis then comes back to the one judged (a revocation it was bound by stops counting), the next
    /// take-out returns at its judged-basis guard. It cleared the owed entry and asked for nothing, so what it had
    /// taken out stayed out of the vault, in the quarantine, until some later replay happened to rebuild it: nothing
    /// lost, but items missing meanwhile. The guard now asks for the replay when it clears an owed entry.
    @Test("an owed take-out found at the judged basis asks for the replay that rebuilds what it took out")
    func owedTakeOutAtTheJudgedBasisReplays() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 30_900)
        let member = members[0]
        let saved = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, member])
        #expect(await member.session.judgementIsSettled(vaultID), "the judgement is not settled: nothing is tested")
        let key = RecordKey(recordID: saved.id, kind: .item)
        try await member.session.leavePartialTakeOut(of: key, in: vaultID)
        #expect(try await member.vault.store.record(key) == nil, "the row was not taken out: nothing is tested")

        try await member.session.syncAll()
        #expect(try await member.vault.store.record(key) != nil, "what the take-out took out was not rebuilt")
        #expect(try await member.session.item(id: saved.id).field(.password)?.value == "bank-password")
        #expect(await member.session.judgementIsSettled(vaultID))
    }

    /// Threat: a demoted member (A4) whose late write this device merged before it learnt of the demotion, the person's
    /// edit of that item made before the sync, and a sync state store that fails the sharing pass's take-out (a busy
    /// or damaged database); the review of round 24 (Z270, finding 7, a window of the design's that Z262 made sure
    /// ends). While the take-out was owed the vault's first pass still published, so the edit went out on a version
    /// built on the late write, which every other device holds aside (S44). An owed vault's first pass now publishes
    /// nothing; where no replay follows, or its take-out fails too, the vault is named (`takeOutUnfinished`) and no
    /// deletion goes out. Not wedged: the next take-out that finishes ends it, and the vault publishes again.
    @Test(
        "an owed take-out's vault publishes nothing in its first pass, and publishes again once one finishes",
        arguments: [true, false])
    func owedTakeOutPublishesNothingFirst(replayOwed: Bool) async throws {
        let setting = try await Self.owedTakeOut(replayOwed: replayOwed)
        let (vaultID, failing, relaunched) = (setting.vaultID, setting.failing, setting.relaunched)
        try await Self.editOverTheLateWrite(setting)
        // The third read of the vault's state is the sharing pass's take-out.
        await failing.script([.read, .read, .fail(before: nil)])
        let first = try await relaunched.session.syncAll()
        #expect(await failing.failed == 1, "the take-out did not fail: nothing is tested")
        #expect(first.sharing[vaultID]?.failure != nil, "the take-out's failure was not reported")
        #expect(first.vaults[vaultID]?.pushedEntries == 0, "an owed vault published")
        if replayOwed {
            // The replay's take-out finished in the same sync: nothing is owed, and the edit was taken out with the
            // late write it was built on.
            #expect(first.takeOutUnfinished.isEmpty)
        } else {
            #expect(first.takeOutUnfinished == [vaultID], "the vault that published nothing was not named")
            #expect(
                try await setting.sync.state.pendingDeletions(vaultID: setting.personal).count == 1,
                "a deletion went out while the vault was owed")
        }

        // The next take-out finishes: nothing is owed, and the vault publishes again.
        var last = AccountSyncReport()
        for _ in 0..<2 { last = try await relaunched.session.syncAll() }
        #expect(last.takeOutUnfinished.isEmpty, "a take-out that finished is still reported unfinished")
        #expect(try await relaunched.session.item(id: setting.bank).field(.password)?.value == "bank-password")
        try await Self.discardTheHeldAsideEdit(setting, after: last, in: relaunched.session)
        #expect(try await setting.sync.state.pendingDeletions(vaultID: setting.personal).isEmpty)
        let later = try await relaunched.session.save(Self.bank(in: vaultID))
        _ = try await relaunched.session.syncAll()
        try await setting.owner.session.sync()
        #expect((try? await setting.owner.session.item(id: later.id)) != nil, "the vault never published again")
    }

    /// Threat: none but local failure, as Z262's (the review of round 24, Z270). A vault whose take-out was not owed as
    /// its first pass ran (nothing to take out then), where that pass learnt something that asks for a replay, and the
    /// replay's take-out fails on its state read: the first pass published, so only the replay loop's own hold
    /// (`takeOutFailed`) keeps the deletions back after what the take-out may have put aside. Without it the Personal
    /// vault's deletion went out in that sync.
    @Test("a replay's take-out that fails holds deletions where the vault's first pass was not owed")
    func replayTakeOutFailsAfterAPassThatPublished() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 31_100)
        let member = members[0]
        _ = try await owner.session.save(Self.bank(in: vaultID))
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let doomed = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([owner, member])
        try await member.session.trash(id: doomed.id)
        try await member.session.deletePermanently(id: doomed.id)

        await member.session.lock()
        let sync = try #require(member.vault.sync)
        let failing = LoadFailingSyncState(base: sync.state, vaultID: vaultID)
        let relaunched = TestVault(
            store: member.vault.store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock,
            sync: SyncSettings(state: failing, transport: sync.transport, configuration: sync.configuration),
            seed: 31_101, deviceKeys: member.vault.deviceKeys)
        await relaunched.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)
        // Work of this device's in the shared vault, which its first pass publishes: that pass was not owed.
        let added = try await relaunched.session.save(Self.bank(in: vaultID))
        let session = relaunched.session
        // The third read of the vault's state is its first pass's, where the replay is asked for; the seventh is the
        // replay loop's take-out (as traced; a change shows below, as a take-out that did not fail).
        await failing.script([
            .read, .read, .readAfter({ await session.requestReplay(vaultID) }), .read, .read, .read, .fail(before: nil),
        ])
        let first = try await relaunched.session.syncAll()
        #expect(await failing.failed == 1, "the replay's take-out did not fail: nothing is tested")
        #expect((first.vaults[vaultID]?.pushedEntries ?? 0) > 0, "the first pass did not publish: nothing is tested")
        #expect(first.takeOutUnfinished == [vaultID], "the hold was silent")
        #expect(
            try await sync.state.pendingDeletions(vaultID: personal).count == 1,
            "the deletion went out after a take-out that did not finish")

        // The next take-out finishes, and the deletion goes out.
        let next = try await relaunched.session.syncAll()
        #expect(next.takeOutUnfinished.isEmpty)
        #expect(try await sync.state.pendingDeletions(vaultID: personal).isEmpty, "the deletion never went out")
        try await owner.session.sync()
        #expect((try? await owner.session.item(id: added.id)) != nil)
    }

    /// Threat: none needed; the review of round 24 (Z272, finding 4). An unlocked sync whose device key is held but
    /// that a registration under way keeps download-only (a same-ID registration begun while the sync read the
    /// standing as active, Z253) is said to wait for the registration (`ownDeviceKeyWait == .registering`, Z264), not
    /// for an unlock. No other test reached the branch: a restored store registers through `.absent`.
    @Test("a held key with a registration under way says the sync waits for the registration")
    func heldKeyWhileRegistering() async throws {
        let vault = TestVault(
            sync: SyncSettings(state: InMemorySyncStateStore(), transport: InMemorySyncTransport()), seed: 31_200)
        try await vault.createAccount()
        #expect(try await vault.session.syncAll().ownDeviceKeyWait == nil)
        await vault.session.setRegistrationInFlightForTest(true)
        let report = try await vault.session.syncAll()
        #expect(report.ownDeviceKeyWait == .registering, "the registration under way was not said")
        #expect(report.combined.deferredUntilUnlock, "a sync with a registration under way wrote")
        await vault.session.setRegistrationInFlightForTest(false)
        #expect(try await vault.session.syncAll().ownDeviceKeyWait == nil)
    }
}
