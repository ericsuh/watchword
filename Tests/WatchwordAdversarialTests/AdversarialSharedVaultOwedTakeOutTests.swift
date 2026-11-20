import Foundation
import Testing
import WatchwordModel
import WatchwordPresentation
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

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

    static func owedTakeOut() async throws -> OwedTakeOut {
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
        await relaunched.session.requestReplay(vaultID)
        #expect(await relaunched.session.replayIsRequested(vaultID), "no replay owed: nothing is tested")
        return OwedTakeOut(
            household: household, owner: owner, member: member, vaultID: vaultID, bank: bank.id, personal: personal,
            sync: sync, failing: failing, relaunched: relaunched)
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
        // The third read of the vault's state is the sharing pass's take-out, the eighth the replay loop's.
        await failing.script([.read, .read, .fail(before: nil), .read, .read, .read, .read, .fail(before: nil)])
        let first = try await relaunched.session.syncAll()
        #expect(await failing.failed == 2, "not both take-outs failed: nothing is tested")
        #expect(first.sharing[vaultID]?.failure != nil, "the take-out's failure was not reported")
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
        #expect(
            try await setting.sync.state.pendingDeletions(vaultID: setting.personal).isEmpty,
            "the deletion never went out")
    }
}
