import Foundation
import Testing
import WatchwordKit
import WatchwordModel
import WatchwordPresentation
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

// The review of round 11 (docs/06-adversarial-review.md Z185; M1): a restore's move of its old device ID's deletions
// when one of them is in a shared vault this device holds closed. In the suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// Threat: none needed but a shared vault this device holds closed (no verified ledger, Z41: here the owner's pin
    /// lost with the restore; a disputed owner, Z59, or a key this device does not hold does the same), in a store
    /// restored onto other hardware that holds a deletion made there and never published. The move of the old ID's
    /// deletions signs each as the new ID's, which needs a current key for its vault: that one threw, every attempt,
    /// so the move's record was never cleared and the device published nothing in any vault, Personal included, for as
    /// long as the vault stayed closed, and said nothing. The deletion is parked now: the move completes, the Personal
    /// vault's deletion goes out, and the shared vault's goes out once the vault opens here again. Nothing is lost.
    @Test("a restore's deletion in a shared vault held closed is parked, and the device still publishes elsewhere")
    func restoreWithASharedVaultHeldClosed() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 18_550)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let shared = try await member.session.save(Self.bank(in: vaultID))
        let mine = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        #expect((try? await owner.session.item(id: shared.id)) != nil)
        #expect((try? await other.session.item(id: mine.id)) != nil)

        // Both deleted, neither deletion published (each trash was: a restore's unpublished edits in a shared vault
        // are held aside on members' devices, Z191); then the store restored onto other hardware without the owner's
        // pin.
        for item in [shared, mine] { try await member.session.trash(id: item.id) }
        try await Self.syncAll([member, owner, other])
        for item in [shared, mine] { try await member.session.deletePermanently(id: item.id) }
        await member.session.lock()
        await member.contacts.removePin(for: owner.accountID)
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        let restored = member.vault.relaunched(seed: 18_551)
        await restored.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)
        let account = try #require(try await member.vault.store.loadAccount())
        #expect(account.migration == nil, "the move was left incomplete")
        #expect(try await restored.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == true)

        let report = try await restored.session.syncAll()
        #expect(!report.deviceMigrationIncomplete)
        // The deletion that waits for want of a key is said to wait (review of round 12).
        #expect(report.deletionsHeldBack.contains(vaultID), "the parked deletion was not reported")
        try await other.session.sync()
        #expect((try? await other.session.item(id: mine.id)) == nil, "the Personal vault's deletion never went out")
        try await owner.session.sync()
        #expect((try? await owner.session.item(id: shared.id)) != nil, "deleted while its vault was held closed")

        // The vault opens here again (the remedy for a lost pin, Z41): the parked deletion goes out.
        try await restored.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        _ = try await restored.session.syncAll()
        _ = try await restored.session.syncAll()
        try await owner.session.sync()
        #expect((try? await owner.session.item(id: shared.id)) == nil, "the shared vault's deletion was lost")
    }
}

// The review of round 12 (docs/06-adversarial-review.md Z192, M1; Z191): what a restore carries over from its old
// device ID in a shared vault. In the suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// A member's store, with the shared vault held closed after a restore (the owner's pin lost with it, as in
    /// `restoreWithASharedVaultHeldClosed`), restored onto other hardware.
    static func restoredWithVaultClosed(
        _ member: SharingAccount, household: SharedVaultHousehold, owner: SharingAccount, seed: UInt64
    ) async throws -> TestVault {
        await member.session.lock()
        await member.contacts.removePin(for: owner.accountID)
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        let restored = member.vault.relaunched(seed: seed)
        await restored.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)
        return restored
    }

    /// Threat: none needed but a shared vault this device cannot open after a restore (no verified ledger, Z41; the
    /// owner's pin lost with the restore), in a store restored onto other hardware whose old device moved an item from
    /// the Personal vault into the shared vault and never published the move. Registration carries over what the old
    /// ID never published only where the vault has a key, so the copy stayed the old ID's, and nothing carried it
    /// later; the move's deletion of the original, carried as the new ID's, went out, and the item was gone from the
    /// account's other device while its copy existed on this device only. Now the move records the copy in the signed
    /// sync state, every deletion waits while it is uncarried and the sync names it, and once the vault opens the copy
    /// is carried, published, and only then does the original's deletion go out.
    @Test("a restore's unpublished move into a shared vault held closed keeps the original until the copy goes out")
    func restoredMoveIntoAClosedVault() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 19_200)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        #expect((try? await other.session.item(id: original.id)) != nil)

        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        let restored = try await Self.restoredWithVaultClosed(member, household: household, owner: owner, seed: 19_201)
        #expect(try await restored.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == true)

        let report = try await restored.session.syncAll()
        #expect(report.restoredWorkWaiting[vaultID] == [copy.id], "the sync does not name the uncarried copy")
        #expect(report.deletionsHeldBack.contains(vaultID))
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original was deleted ahead of its copy")

        // The vault opens here again (the remedy for a lost pin, Z41): the copy is carried and published, then the
        // original's deletion goes out.
        try await restored.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        let opened = try await restored.session.syncAll()
        #expect(opened.restoredWorkWaiting.isEmpty)
        _ = try await restored.session.syncAll()
        try await Self.syncAll([owner, other])
        #expect(try await owner.session.item(id: copy.id).title == copy.title, "the copy never reached the owner")
        #expect(try await owner.session.quarantine().isEmpty, "the copy was held aside")
        #expect((try? await other.session.item(id: original.id)) == nil, "the original's deletion never went out")
    }

    /// Threat: none needed; the hold of `restoredMoveIntoAClosedVault` for a vault that will not open on this device
    /// (an owner its devices disagree about, Z59, holds one closed for good in this version). The person can stop
    /// waiting: the deletions go out, and the copy stays on this device as it was. Nothing else ends that hold.
    @Test("the person can stop waiting for a restore's work in a vault that will not open, and keeps it here")
    func stopWaitingForRestoredWork() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 19_220)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        let restored = try await Self.restoredWithVaultClosed(member, household: household, owner: owner, seed: 19_221)
        let waiting = try await restored.session.syncAll()
        #expect(waiting.restoredWorkWaiting[vaultID] == [copy.id])

        // Through the notice's action, as the Settings screen offers it (review of round 13, M3).
        let summary = SyncSummary(waiting)
        let notice = try #require(summary.notices.first { $0.id == "restoredWorkWaiting" })
        #expect(waiting.restoredWorkMayStopWaiting == [vaultID], "a vault that will not open offers no choice")
        let action = try #require(notice.actions.first)
        #expect(action.confirmation.contains("stay on this device only"))
        try await summary.perform(action, using: restored.session)
        let report = try await restored.session.syncAll()
        #expect(report.restoredWorkWaiting.isEmpty)
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) == nil, "the deletion still waited")
        let kept = try await member.vault.store.record(RecordKey(recordID: copy.id, kind: .item))
        #expect(kept != nil, "the copy was discarded")
    }

    /// Threat: none needed; review finding Z191. A member edits an item of a shared vault and trashes and deletes
    /// another, and the store is restored onto other hardware before either is published. Carried over unchanged, the
    /// edit kept the old ID's stamps and the deletion's summary claimed the old ID's unpublished trash, which no
    /// segment of the old ID's stream carried: every member's judge held both aside, and the restored device's own on a
    /// replay. Now what the old ID wrote above what it published is written again as the new ID's: the members end
    /// with the person's title and without the deleted item, and so does the restored device after a replay.
    @Test("a restore's unpublished edit and deletion in a shared vault reach the vault's members")
    func restoredEditAndDeletionReachMembers() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 19_100)
        let member = members[0]
        let edited = try await member.session.save(Self.bank(in: vaultID))
        let deleted = try await member.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([member, owner])

        var renamed = try await member.session.item(id: edited.id)
        renamed.title = "Bank, renamed"
        _ = try await member.session.save(renamed)
        try await member.session.trash(id: deleted.id)
        try await member.session.deletePermanently(id: deleted.id)
        await member.session.lock()
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        let restored = member.vault.relaunched(seed: 19_101)
        await restored.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)
        _ = try await restored.session.syncAll()
        _ = try await restored.session.syncAll()
        try await Self.syncAll([owner])
        #expect(try await owner.session.item(id: edited.id).title == "Bank, renamed", "the member kept the old title")
        #expect((try? await owner.session.item(id: deleted.id)) == nil, "the member kept the deleted item")
        #expect(try await owner.session.quarantine().isEmpty, "the restore's work was held aside")

        _ = try await restored.session.syncAll(reconcile: true)
        #expect(try await restored.session.item(id: edited.id).title == "Bank, renamed")
        #expect(try await restored.session.quarantine().isEmpty, "the restored device held its own work aside")
    }
}

// The review of round 13 (docs/06-adversarial-review.md Z198, M2): what a restore's carry counts as published. In the
// suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// The member's store as it was when `backup` was taken, restored onto other hardware: the item's row, the
    /// vault's sync state and the stream index put back, the device key lost.
    struct Backup {
        let row: StoredRecord
        let state: SyncState?
        let index: [UInt8]?

        static func take(of member: SharingAccount, item: UUID, vaultID: UUID) async throws -> Backup {
            let state = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
            return Backup(
                row: try #require(try await member.vault.store.record(RecordKey(recordID: item, kind: .item))),
                state: await state.loadState(vaultID: vaultID),
                index: await member.state.value(.streamIndex, vaultID: vaultID))
        }

        func restore(_ member: SharingAccount, household: SharedVaultHousehold, seed: UInt64) async throws
            -> TestVault
        {
            await member.session.lock()
            let store = try #require(member.vault.store as? InMemoryRecordStore)
            await store.tamper(row)
            let syncState = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
            if let state { await syncState.tamper(state) }
            await member.state.tamper(.streamIndex, vaultID: row.vaultID, value: index)
            await member.vault.forgetDeviceKey(accountID: member.accountID)
            let restored = member.vault.relaunched(seed: seed)
            await restored.session.configureSharing(
                SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
            try await restored.session.unlock(password: TestVault.password)
            return restored
        }
    }

    /// Threat: none needed but a backup older than the device's last publish; the review of round 13, M2. The member
    /// renames an item of a shared vault, the store is backed up before that is published, then the rename goes out
    /// and the member renames the item again. Restored from that backup onto other hardware, the device carried the
    /// first rename over as its new ID's, reading what was published from the backup's sync state: the vault's
    /// members then held it beside the second rename, which superseded only the old ID's copy, and the title the
    /// person had replaced came back as a conflict on every device. What counts as published is now also what the
    /// old ID's stream carried, read once the vault's log has been pulled: nothing is renamed, and nothing comes back.
    /// The same with the backup's sync state edited (A8), so that it says nothing was published at all.
    @Test(
        "a restore from a backup older than the device's last publish brings back nothing it replaced",
        arguments: [false, true])
    func restoreFromALaggingBackup(stateEdited: Bool) async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 19_700)
        let member = members[0]
        let saved = try await member.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([member, owner])

        var first = try await member.session.item(id: saved.id)
        first.title = "Bank, first"
        _ = try await member.session.save(first)
        var backup = try await Backup.take(of: member, item: saved.id, vaultID: vaultID)
        if stateEdited, var state = backup.state {
            state.authenticator = Array(repeating: 0, count: state.authenticator.count)
            backup = Backup(row: backup.row, state: state, index: backup.index)
        }
        try await Self.syncAll([member, owner])
        var second = try await member.session.item(id: saved.id)
        second.title = "Bank, second"
        _ = try await member.session.save(second)
        try await Self.syncAll([member, owner])

        let restored = try await backup.restore(member, household: household, seed: 19_701)
        _ = try await restored.session.syncAll()
        _ = try await restored.session.syncAll()
        try await Self.syncAll([owner])
        let atOwner = try await owner.session.item(id: saved.id)
        #expect(atOwner.title == "Bank, second")
        #expect(!atOwner.hasConflicts, "the replaced title came back beside the one that replaced it")
        #expect(try await owner.session.quarantine().isEmpty)
        let here = try await restored.session.item(id: saved.id)
        #expect(here.title == "Bank, second")
        #expect(!here.hasConflicts)
    }
}

// The review of round 13 (docs/06-adversarial-review.md Z199, Z200; M3, L-a): what holds deletions back for a restore's
// work, and what ends that hold. In the suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// Threat: a damaged sync state file, or one edited by an attacker with the device's files (A8), for a shared vault
    /// that holds a restore's uncarried copy of a move (review of round 13, L-a): the state no longer verifies. The
    /// hold read it through `try?`, and a state that does not verify reads as none: the hold saw no entry, the copy
    /// was still the old device ID's, and the original's deletion went out while the copy existed on this device only.
    /// The hold now fails closed on a state it cannot trust, and the sync finds the copy again from the row the old ID
    /// left (the old ID read from the entries the damaged state still names), records it in a state it signs, and
    /// names it; once the vault opens, the copy is carried and published first. (An attacker who can edit the file
    /// can delete the row as well; the hold is for damage, not for them.)
    @Test("a restore's uncarried copy holds deletions back even after its vault's sync state is damaged")
    func restoredWorkSurvivesAnEditedState() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 19_800)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        let restored = try await Self.restoredWithVaultClosed(member, household: household, owner: owner, seed: 19_801)

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

        try await restored.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        _ = try await restored.session.syncAll()
        _ = try await restored.session.syncAll()
        try await Self.syncAll([owner, other])
        #expect(try await owner.session.item(id: copy.id).title == copy.title, "the copy never reached the owner")
        #expect((try? await other.session.item(id: original.id)) == nil, "the original's deletion never went out")
    }

    /// Threat: none needed; review of round 13, M3. A restore's uncarried copy of a move, in a shared vault this
    /// account is then removed from: the vault's key is rotated away, so nothing can carry the copy there, and every
    /// deletion of the account's waited for it for good, the Personal vault's included, with nothing but a choice
    /// nobody was offered to end it. A vault this account is no longer a member of waits for nothing: the deletions go
    /// out, the copy stays on this device, and the sync says so.
    @Test("a restore's uncarried work in a vault this account was removed from is kept here and holds nothing back")
    func restoredWorkInAVaultLeft() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 19_900)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        await member.session.lock()
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        let restored = member.vault.relaunched(seed: 19_901)
        await restored.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)

        #expect(try await owner.session.removeMember(member.accountID, from: vaultID) == .complete)
        try await owner.session.sync()
        let report = try await restored.session.syncAll()
        #expect(report.restoredWorkWaiting.isEmpty, "the sync still waits to carry work into a vault it left")
        #expect(report.restoredWorkKeptHere[vaultID] == [copy.id], "the sync does not say the copy stays here")
        _ = try await restored.session.syncAll()
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) == nil, "the deletion still waited")
        let kept = try await member.vault.store.record(RecordKey(recordID: copy.id, kind: .item))
        #expect(kept != nil, "the copy was discarded")
        let summary = SyncSummary(report)
        #expect(summary.notices.contains { $0.id == "restoredWorkKeptHere" })
        #expect(summary.notices.allSatisfy { $0.actions.isEmpty })
    }
}

// The review of round 14 (docs/06-adversarial-review.md Z206, L3): which device IDs a restore's chain names. In the
// suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// Threat: A8, who can edit this device's sync state and sharing state files but not reach the Keychain. In a
    /// shared vault's state, which then no longer verifies, A8 names the owner's device (another account's) as an
    /// earlier ID of this installation, and deletes the stream index, so that nothing reads as published by it. The
    /// restore's chain was read from that state whatever ID it named: the take-out left the owner's rows alone as a
    /// restore's, and the carry wrote them again as this device's own, laundering another account's writes through
    /// this device's stream. Only an ID this account's registry lists as its own is read from such a state now.
    @Test("an ID planted in an edited state as a restore's earlier ID must be one of this account's devices")
    func plantedChainIDOfAnotherAccount() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 20_100)
        let member = members[0]
        let saved = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, member])
        let key = RecordKey(recordID: saved.id, kind: .item)
        let ownerDevice = try #require(try await owner.vault.store.loadAccount()?.deviceID)
        let before = try #require(try await member.vault.store.record(key))
        #expect(before.deviceID == ownerDevice, "the owner's row is not the owner's: nothing is tested")

        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
        var state = try #require(await raw.loadState(vaultID: vaultID))
        state.restoredUnpublished[key] = RecordStamp(version: 0, device: ownerDevice)
        state.authenticator = Array(repeating: 0, count: state.authenticator.count)
        await raw.tamper(state)
        await member.state.tamper(.streamIndex, vaultID: vaultID, value: nil)
        await member.session.lock()
        let relaunched = member.vault.relaunched(seed: 20_101)
        await relaunched.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)

        _ = try await relaunched.session.syncAll()
        _ = try await relaunched.session.syncAll()
        let after = try #require(try await member.vault.store.record(key))
        #expect(after.deviceID == ownerDevice, "the owner's row was written again as this device's")
        let written = try await raw.loadState(vaultID: vaultID)?.restoredUnpublished ?? [:]
        #expect(written.isEmpty, "the planted ID was recorded as a restore's earlier ID")
    }
}

/// A view of a transport that reports itself unavailable for every object under one prefix while `failing` is set:
/// one vault's log out of reach while everything else syncs.
actor PrefixUnavailableTransport: SyncTransport {
    let base: any SyncTransport
    private var failing: String?

    init(base: any SyncTransport) {
        self.base = base
    }

    func fail(under prefix: String?) {
        failing = prefix
    }

    private func check(_ name: String) throws {
        if let failing, name.hasPrefix(failing) { throw SyncTransportError.unavailable }
    }

    func list(prefix: String) async throws -> [String] {
        try check(prefix)
        return try await base.list(prefix: prefix)
    }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        try check(name)
        return try await base.fetch(name, maximumLength: maximumLength)
    }

    func create(_ name: String, contents: [UInt8]) async throws {
        try check(name)
        try await base.create(name, contents: contents)
    }

    func delete(_ name: String) async throws {
        try check(name)
        try await base.delete(name)
    }
}

// The review of round 14 (docs/06-adversarial-review.md Z205, Z207; L2, L4): a vault whose publishing waits for a
// restore's carry, and which vaults offer to stop waiting. In the suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// Threat: none needed but a shared vault's log out of reach after a restore (the transport failing for it; a
    /// failure in an earlier vault that stops the sync does the same). While a restore has work left to carry in a
    /// vault, the vault publishes nothing, new edits included, and the carry runs only once its log has been pulled:
    /// for as long as the log stays out of reach nothing of this device's goes out there, and the sync said nothing
    /// of it. The sync names the vault now, and stops naming it once the carry is done; the edit then goes out.
    @Test("a vault whose publishing waits for a restore's carry is named until the carry is done")
    func publishingHeldForTheCarryIsNamed() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 20_200)
        let member = members[0]
        let saved = try await member.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([member, owner])
        var first = try await member.session.item(id: saved.id)
        first.title = "Bank, first"
        _ = try await member.session.save(first)

        // Restored onto other hardware before the rename went out, over a view of the transport that cannot reach
        // the vault's log.
        await member.session.lock()
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        let view = PrefixUnavailableTransport(base: household.transport)
        await view.fail(under: SyncObjectLocation.vaultPrefix(vaultID))
        let state = try #require(member.vault.sync?.state)
        let restored = TestVault(
            store: member.vault.store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock, sync: SyncSettings(state: state, transport: view), seed: 20_201,
            deviceKeys: member.vault.deviceKeys)
        await restored.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)

        let held = try await restored.session.syncAll()
        #expect(held.publishingHeldForCarry == [vaultID], "the vault publishing nothing for the carry is not named")
        let summary = SyncSummary(held)
        #expect(summary.notices.contains { $0.id == "publishingHeldForCarry" })
        // The vault opens here, so the person is not offered to stop waiting for it, and the session refuses it
        // (review of round 14, L2): stopped, its rows would stay the earlier ID's, and later edits reach nobody.
        #expect(held.restoredWorkWaiting[vaultID] == [saved.id])
        #expect(held.restoredWorkMayStopWaiting.isEmpty, "Stop Waiting offered for a vault that opens here")
        #expect(summary.notices.allSatisfy { $0.actions.isEmpty })
        await #expect(throws: VaultError.restoredWorkCanBeCarried(vaultID)) {
            try await restored.session.stopWaitingForRestoredWork(in: vaultID)
        }

        await view.fail(under: nil)
        let carried = try await restored.session.syncAll()
        #expect(carried.publishingHeldForCarry.isEmpty, "named after its carry was done")
        _ = try await restored.session.syncAll()
        try await Self.syncAll([owner])
        #expect(try await owner.session.item(id: saved.id).title == "Bank, first", "the carried edit never went out")
    }
}
