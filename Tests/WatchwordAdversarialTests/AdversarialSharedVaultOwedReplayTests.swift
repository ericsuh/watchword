import Foundation
import Testing
import WatchwordModel
import WatchwordPresentation
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// This device's registry anchor taken out of the Keychain for a window of a sync, and put back: a take-out asked
/// meanwhile works out no judged basis (`judgedBasis` is `nil` when this account's registry cannot be read) and
/// returns with nothing decided, its vault still owed.
actor AnchorWindow {
    let keychain: FakeKeychain
    let item: KeychainItem
    let session: VaultSession
    private var saved: [UInt8]?
    private(set) var readsWhileOut = 0

    init(keychain: FakeKeychain, accountID: UUID, session: VaultSession) {
        self.keychain = keychain
        self.item = .deviceRegistryAnchor(accountID: accountID)
        self.session = session
    }

    func takeOut() async {
        saved = await keychain.raw(item)
        await keychain.delete(item)
        await session.invalidateRegistry()
        let item = item
        await keychain.onRead { [weak self] read in
            guard read == item, let self else { return }
            await self.noteRead()
        }
    }

    func putBack() async {
        guard let saved else { return }
        await keychain.onRead(nil)
        await keychain.overwrite(item, with: saved)
        await session.invalidateRegistry()
        self.saved = nil
    }

    private func noteRead() {
        if saved != nil { readsWhileOut += 1 }
    }
}

// The merge of round 25 into the hygiene branch: Z270's rule for an owed vault in this branch's replay pass.
extension AdversarialSharedVaultTests {
    /// Threat: a demoted member (A4) whose late write this device merged before it learnt of the demotion, the
    /// person's edit of that item, a sync state store that fails the sharing pass's take-out, and this account's
    /// registry unreadable when the replay's take-out asks for the judged basis (the Keychain closed for a moment, as
    /// a background sync can find it). That take-out returns with nothing decided and the vault still owed, and the
    /// replay that followed it published (merged so at round 25: Z270 covered the first pass alone), sending the edit
    /// built on the late write, which every other device holds aside (S44). An owed vault publishes nothing in its
    /// replay either, is named (`takeOutUnfinished`) and holds every deletion; once a take-out finishes it publishes
    /// again.
    @Test("an owed vault whose replay's take-out decided nothing publishes nothing in the replay either")
    func owedTakeOutPublishesNothingInItsReplay() async throws {
        let setting = try await Self.owedTakeOut()
        let (vaultID, failing, relaunched) = (setting.vaultID, setting.failing, setting.relaunched)
        try await Self.editOverTheLateWrite(setting)
        let window = AnchorWindow(
            keychain: setting.member.vault.keychain, accountID: setting.member.accountID, session: relaunched.session)
        // The third read of the vault's state is the sharing pass's take-out, which fails and takes the anchor out;
        // the fourth and fifth are the first pass's; the sixth the replay's engine, which puts it back (as traced: the
        // replay's take-out reads no state when it decides nothing, and one that does shows below as a finished one).
        await failing.script([
            .read, .read, .fail(before: { await window.takeOut() }), .read, .read,
            .readAfter({ await window.putBack() }),
        ])
        let first = try await relaunched.session.syncAll()
        await window.putBack()
        #expect(await failing.failed == 1, "the take-out did not fail: nothing is tested")
        #expect(
            await window.readsWhileOut > 0, "no take-out asked for the registry while it was out: nothing is tested")
        #expect(first.vaults[vaultID]?.pushedEntries == 0, "an owed vault published in its replay")
        #expect(first.takeOutUnfinished == [vaultID], "the vault that published nothing was not named")
        // Neither pass published there, so the notice says its changes wait (Z273, merged so at round 26).
        #expect(first.takeOutUnfinishedSentNothing == [vaultID])
        #expect(SyncSummary(first).notices.contains(.takeOutUnfinished(changesWait: true)))
        // Held by the final loop alone, in its own words (`owedReplayHoldsANewItemInItsOwnWords` pins the replay's
        // part of it).
        #expect(!SyncSummary(first).notices.contains(.deletionsHeldBack), "said as something moved that went nowhere")
        #expect(
            try await setting.sync.state.pendingDeletions(vaultID: setting.personal).count == 1,
            "a deletion went out while the vault was owed")

        // The next take-out finishes: nothing is owed, the late write is taken out, and the vault publishes again.
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

    /// Threat: as `owedTakeOutPublishesNothingInItsReplay`, with an item the person added to the shared vault before
    /// the sync (review of PR #22's eighth merge, finding 3). The replay of an owed vault publishes nothing, so the new
    /// item is this device's work that reached nobody, and the replay's unpublished-work check, were it asked, would
    /// name the vault in `deletionsHeldBack` too: the generic notice, which says the vault cannot be written to now or
    /// its work was held aside, untrue beside `takeOutUnfinished`, whose notice says the vault's changes wait (Z268).
    /// The replay asks it only of a vault no longer owed (`!owedStill`), and the final loop holds this one.
    @Test("an owed vault's replay holds the deletions in the take-out's words, not the generic notice's")
    func owedReplayHoldsANewItemInItsOwnWords() async throws {
        let setting = try await Self.owedTakeOut()
        let (vaultID, failing, relaunched) = (setting.vaultID, setting.failing, setting.relaunched)
        let added = try await relaunched.session.save(Self.bank(in: vaultID))
        let window = AnchorWindow(
            keychain: setting.member.vault.keychain, accountID: setting.member.accountID, session: relaunched.session)
        // As in `owedTakeOutPublishesNothingInItsReplay`.
        await failing.script([
            .read, .read, .fail(before: { await window.takeOut() }), .read, .read,
            .readAfter({ await window.putBack() }),
        ])
        let first = try await relaunched.session.syncAll()
        await window.putBack()
        #expect(await failing.failed == 1, "the take-out did not fail: nothing is tested")
        #expect(
            await window.readsWhileOut > 0, "no take-out asked for the registry while it was out: nothing is tested")
        #expect(first.vaults[vaultID]?.pushedEntries == 0, "an owed vault published in its replay")
        #expect(first.takeOutUnfinished == [vaultID], "the vault that published nothing was not named")
        #expect(!first.deletionsHeldBack.contains(vaultID), "the owed vault was also held as unpublished work")
        let notices = SyncSummary(first).notices
        #expect(notices.contains(.takeOutUnfinished(changesWait: true)))
        #expect(!notices.contains(.deletionsHeldBack), "said as something that cannot be written or was held aside")
        #expect(
            try await setting.sync.state.pendingDeletions(vaultID: setting.personal).count == 1,
            "a deletion went out while the vault was owed")

        // Once a take-out finishes the item goes out, and so does the deletion.
        for _ in 0..<2 { _ = try await relaunched.session.syncAll() }
        try await setting.owner.session.sync()
        #expect((try? await setting.owner.session.item(id: added.id)) != nil, "the vault never published the item")
        #expect(try await setting.sync.state.pendingDeletions(vaultID: setting.personal).isEmpty)
    }

    /// Threat: a demoted member (A4) whose late write this device merged before it learnt of the demotion, and a vault
    /// whose take-out is owed only from its replay on, its first pass not owed: in production a carried vault's, whose
    /// first pass is the carry's (review of PR #22's eighth merge, finding 3), stood for by a test hook during the
    /// first pass; with this account's registry unreadable when the replay's take-out asks for the judged basis, so
    /// that it decides nothing. The replay publishes nothing and asks nothing of the vault's unpublished work
    /// (`!owedStill`), so only its joining `owedUnpublished` names it and holds every deletion: without that, the vault
    /// was named nowhere and the deletions went out after what the owed take-out had still to act on (Z262). Its first
    /// pass published, so the notice says only that changes made there may wait (`takeOutUnfinishedSentNothing`, Z273,
    /// as this branch reads it from what ran publishing).
    @Test("a vault owed only from its replay on is named and holds every deletion, its first pass's sending said")
    func vaultOwedOnlyFromItsReplayIsNamed() async throws {
        let setting = try await Self.owedTakeOut()
        let (vaultID, failing, relaunched) = (setting.vaultID, setting.failing, setting.relaunched)
        let window = AnchorWindow(
            keychain: setting.member.vault.keychain, accountID: setting.member.accountID, session: relaunched.session)
        // The third read is the sharing pass's take-out, which finishes; the fourth and fifth are the first pass's,
        // and at the fifth the vault becomes owed and the anchor goes out; the sixth to the eighth come before the
        // replay's take-out, which reads none when it decides nothing; the ninth is the replay's engine, which puts
        // the anchor back (as traced).
        await failing.script([
            .read, .read, .read, .read,
            .readAfter({
                await relaunched.session.markTakeOutOwedForTest(vaultID)
                await window.takeOut()
            }),
            .read, .read, .read, .readAfter({ await window.putBack() }),
        ])
        let first = try await relaunched.session.syncAll()
        await window.putBack()
        #expect(await failing.failed == 0)
        #expect(
            await window.readsWhileOut > 0, "no take-out asked for the registry while it was out: nothing is tested")
        #expect(first.takeOutUnfinished == [vaultID], "a vault owed from its replay on was not named")
        #expect(first.takeOutUnfinishedSentNothing.isEmpty, "a vault that published is said to have sent nothing")
        let notices = SyncSummary(first).notices
        #expect(notices.contains(.takeOutUnfinished(changesWait: false)))
        #expect(
            try await setting.sync.state.pendingDeletions(vaultID: setting.personal).count == 1,
            "a deletion went out while the vault was owed")

        // The next take-out finishes: nothing is owed, and the deletion goes out.
        var last = AccountSyncReport()
        for _ in 0..<2 { last = try await relaunched.session.syncAll() }
        #expect(last.takeOutUnfinished.isEmpty, "a take-out that finished is still reported unfinished")
        #expect(try await setting.sync.state.pendingDeletions(vaultID: setting.personal).isEmpty)
        #expect(try await relaunched.session.item(id: setting.bank).field(.password)?.value == "bank-password")
    }
}

// The review of PR #22's eighth merge (finding 1): a rotation carried on in the sync whose take-out did not finish.
extension AdversarialSharedVaultTests {
    /// Threat: a demoted member (A4) whose late write this device, an administrator's, merged before it learnt of the
    /// demotion, a sync state store that fails both take-outs of a sync (a busy or damaged database), and a rotation
    /// this device planned and saved and did not carry out (an interruption, §8.6), routine or removing the demoted
    /// member; any member can bring one about in the same pass, by a leave request an administrator turns into a
    /// departure rotation. The sync skipped the standalone reseal for a vault whose take-out did not finish, but the
    /// rotation resumed in the same pass reached `resealSharedVault` through its plan's reseal step, whose own take-out
    /// (S59) finished this time and took the late write's row out with no replay after it: the item stood missing
    /// (`itemNotFound`) at the end of a sync that said its take-out had not finished, until the next sync's replay.
    /// The reseal step waits for the next sync there too (`resealing: false`): the plan's revocation of transport
    /// access and its record still go out, the plan stays at `.resealing`, and the next sync's take-out, its replay and
    /// the reseal act together, which seals every record under the new key in that sync.
    @Test(
        "a rotation after an unfinished take-out reseals at the next sync, and nothing stands missing meanwhile",
        arguments: [false, true])
    func rotationAfterAnUnfinishedTakeOutResealsAtTheNextSync(removing: Bool) async throws {
        let setting = try await Self.owedTakeOut(replayOwed: true, memberRole: .administrator)
        let (vaultID, failing, relaunched) = (setting.vaultID, setting.failing, setting.relaunched)
        let key = RecordKey(recordID: setting.bank, kind: .item)
        let reason: RotationReason = removing ? .removal(setting.demoted.accountID) : .routine
        try await relaunched.session.planRotation(reason, in: vaultID)
        #expect(try await relaunched.session.sharedVault(vaultID).plan != nil, "no plan saved: nothing is tested")
        let oldKey = try await relaunched.session.sharedVault(vaultID).ledger.state.vaultKeyID

        // The sharing pass's take-out fails (the third read), and so does the replay loop's (the sixth).
        await failing.script([.read, .read, .fail(before: nil), .read, .read, .fail(before: nil)])
        let first = try await relaunched.session.syncAll()
        #expect(await failing.failed == 2, "the take-outs did not both fail: nothing is tested")
        #expect(first.takeOutUnfinished == [vaultID], "no take-out unfinished: nothing is tested")
        #expect(
            (try? await relaunched.session.item(id: setting.bank)) != nil,
            "the item stood missing after a sync that reported its take-out unfinished")
        // The record went out and was adopted; the reseal waits, and the plan is kept for it.
        let vault = try await relaunched.session.sharedVault(vaultID)
        #expect(vault.ledger.state.vaultKeyID != oldKey, "the rotation's record was not adopted")
        #expect(vault.plan != nil, "the plan was dropped with its reseal still to do")
        guard case .resealing(let remaining)? = first.sharing[vaultID]?.rotation else {
            Issue.record("the rotation is \(String(describing: first.sharing[vaultID]?.rotation)), not resealing")
            return
        }
        #expect(remaining > 0)
        #expect((first.sharing[vaultID]?.resealed ?? 0) == 0, "a vault whose take-out did not finish was sealed again")
        if removing {
            #expect(vault.ledger.state.member(setting.demoted.accountID) == nil)
            #expect(
                await setting.member.shareAccess.revoked.contains { $0.account == setting.demoted.accountID },
                "the removed member's transport access was not revoked")
        }

        // The next sync's take-out finishes, its replay rebuilds the item from what counts, and the rotation reseals
        // it under the new key and completes.
        let next = try await relaunched.session.syncAll()
        #expect(next.takeOutUnfinished.isEmpty)
        #expect(next.sharing[vaultID]?.rotation == .complete, "the rotation's reseal did not complete at the next sync")
        #expect(try await relaunched.session.sharedVault(vaultID).plan == nil)
        #expect(try await relaunched.session.item(id: setting.bank).field(.password)?.value == "bank-password")
        let current = try await relaunched.session.sharedVault(vaultID).ledger.state.vaultKeyID
        #expect(try await setting.member.vault.store.record(key)?.keyID == current, "the item stayed under the old key")
        let stale = try await relaunched.session.sharedVault(vaultID).ledger.recordsToReseal(
            in: try await relaunched.session.sharedInventory(vaultID))
        #expect(stale.isEmpty, "records stayed under the old key after the next sync")
    }
}
