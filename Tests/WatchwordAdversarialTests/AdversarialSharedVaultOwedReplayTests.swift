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
        #expect(SyncSummary(first).notices.contains(.takeOutUnfinished))
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
}
