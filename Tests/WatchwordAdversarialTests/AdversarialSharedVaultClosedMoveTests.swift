import Foundation
import Testing
import WatchwordEnvelope
import WatchwordKit
import WatchwordModel
import WatchwordPresentation
import WatchwordSharing
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

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

// The review of round 15 (docs/06-adversarial-review.md Z208 to Z212): what a restore's carry counts as published
// before the pulled versions are merged, and when it may merge. In the suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// The member's store restored onto other hardware before its last edit went out: the device key lost, the store
    /// and sync state kept, over `transport`.
    static func restoredOntoOtherHardware(
        _ member: SharingAccount, household: SharedVaultHousehold, transport: (any SyncTransport)? = nil,
        seed: UInt64
    ) async throws -> TestVault {
        await member.session.lock()
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        let state = try #require(member.vault.sync?.state)
        let restored = TestVault(
            store: member.vault.store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock, sync: SyncSettings(state: state, transport: transport ?? household.transport),
            seed: seed, deviceKeys: member.vault.deviceKeys)
        await restored.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)
        return restored
    }

    /// Threat: A4, a current member who may write the shared vault, with a modified client. A member's device edits an
    /// item and is restored from a backup before the edit goes out. Before that device's first sync, A4 edits another
    /// field of the item and claims, in the value's `seen` vector and the item's clock, to have seen the earlier device
    /// ID's work far beyond what its stream published. The carry read what the downloaded segments showed a third
    /// device had seen of the earlier ID as published, though no judge had looked at them: it then found nothing of
    /// the earlier ID's to carry, dropped the signed entry, and left the row the earlier ID's. The edit never reached
    /// the members (every member's judge holds it aside, Z191), every later edit of the item on the device was held
    /// aside with it, and nothing held deletions back for it. Only the earlier ID's own stream bounds the carry now:
    /// the claim is held aside by the judge when merged, and the edit, and the one after it, reach the vault's owner.
    /// The control (no claim) is the same scenario.
    @Test(
        "a member's claim to have seen a restore's earlier ID's work does not stop the carry",
        arguments: [false, true])
    func inflatedClaimInAStagedSegment(inflated: Bool) async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 30_200)
        let member = members[0]
        let saved = try await member.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([member, owner])
        var first = try await member.session.item(id: saved.id)
        first.title = "Bank, first"
        let unpublished = try await member.session.save(first).version
        let oldID = try #require(await member.session.deviceIDForTest())
        let restored = try await Self.restoredOntoOtherHardware(member, household: household, seed: 30_201)

        // The owner's modified client edits another field, claiming to have seen the old ID far ahead.
        let key = RecordKey(recordID: saved.id, kind: .item)
        let ownerDevice = try #require(await owner.session.deviceIDForTest())
        var previous = try await owner.session.item(id: saved.id)
        let stored = try #require(await owner.session.storedRowForTest(key))
        let revision = Revision(version: stored.version + 1, device: ownerDevice)
        if inflated { previous.clock.record(Revision(version: 1 << 30, device: oldID)) }
        var edited = previous
        edited.fields[0].value = "owner-user"
        var crafted = ItemMerge.stamped(edited, previous: previous, revision: revision)
        if inflated {
            crafted.revisions[.field(edited.fields[0].id)]?.seen.record(Revision(version: 1 << 30, device: oldID))
        }
        crafted.version = stored.version + 1
        if inflated {
            // Read as every merge reads it, capped at the version's own number: still all of the old ID's work.
            #expect(
                ItemMerge.seenByOthers(crafted, origin: revision, of: oldID, besides: UUID()) >= unpublished,
                "the claim covers none of the old ID's unpublished work: nothing is tested")
        }
        try await owner.session.overwriteAsAModifiedClient(crafted)
        try await owner.session.sync()

        _ = try await restored.session.syncAll()
        let row = try #require(try await member.vault.store.record(key))
        #expect(row.deviceID != oldID, "the carry left the row the earlier ID's")
        for _ in 0..<3 {
            _ = try await restored.session.syncAll()
            try await owner.session.sync()
        }
        #expect(
            Self.titles(try await owner.session.item(id: saved.id)).contains("Bank, first"),
            "the restored edit never reached the owner")

        var later = try await restored.session.item(id: saved.id)
        later.title = "Bank, second"
        _ = try await restored.session.save(later)
        for _ in 0..<3 {
            _ = try await restored.session.syncAll()
            try await owner.session.sync()
        }
        #expect(
            Self.titles(try await owner.session.item(id: saved.id)).contains("Bank, second"),
            "a later edit never reached the owner")
    }
}

extension AdversarialSharedVaultTests {
    /// Threat: A8, who can edit this device's sync state and sharing state files but not reach the Keychain (review of
    /// round 15, Z211, a variant of Z206), and in the second case also the sync store (A1), which withholds the
    /// sibling's stream from this device. In a shared vault's state, which then no longer verifies, A8 names a sibling
    /// device of the same account, current and still writing, as an earlier ID of this installation, and deletes the
    /// stream index. The chain was read from that state for any current or revoked device of the account: every row
    /// holding the sibling's published work was recorded as left by an earlier ID with nothing published, and the
    /// carry wrote what no listed segment of the sibling's stream showed again as this device's. With the stream
    /// withheld, that was all of it: every member then held the sibling's values twice, under two stamps, as conflicts
    /// in every group it wrote. No ID is read from a state that does not verify now (Z216; Z211's rule, an ID whose
    /// registration this device's own descends from, kept out this sibling, enrolled after this device, but not one
    /// enrolled before a restore): the sibling's published work is never renamed.
    @Test(
        "a sibling device named in an edited state as a restore's earlier ID keeps its published work",
        arguments: [false, true])
    func plantedChainIDOfASiblingDevice(withheld: Bool) async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 30_300)
        let member = members[0]
        let sibling = try await household.secondDevice(of: member)
        try await sibling.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await Self.syncAll([owner, member, sibling])
        let saved = try await sibling.session.save(Self.bank(in: vaultID))
        var edited = try await sibling.session.item(id: saved.id)
        edited.title = "Bank, by the sibling"
        _ = try await sibling.session.save(edited)
        try await Self.syncAll([sibling, owner, member])
        let key = RecordKey(recordID: saved.id, kind: .item)
        let siblingDevice = try #require(await sibling.session.deviceIDForTest())
        let before = try #require(try await member.vault.store.record(key))
        #expect(before.deviceID == siblingDevice, "the sibling's row is not the sibling's: nothing is tested")

        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
        var state = try #require(await raw.loadState(vaultID: vaultID))
        state.restoredUnpublished[key] = RecordStamp(version: 0, device: siblingDevice)
        state.authenticator = Array(repeating: 0, count: state.authenticator.count)
        await raw.tamper(state)
        await member.state.tamper(.streamIndex, vaultID: vaultID, value: nil)
        await member.session.lock()
        let view = WithholdingTransport(base: household.transport)
        if withheld {
            let stream = SyncObjectLocation.vaultPrefix(vaultID) + "log/\(siblingDevice.uuidString)/"
            await view.withhold(Set(await household.transport.list(prefix: stream)))
        }
        let relaunched = TestVault(
            store: member.vault.store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock, sync: SyncSettings(state: raw, transport: view), seed: 30_301,
            deviceKeys: member.vault.deviceKeys)
        await relaunched.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)

        _ = try await relaunched.session.syncAll()
        _ = try await relaunched.session.syncAll()
        // With the stream withheld, the judge finds no segment that carried the sibling's work and holds the row
        // aside until it does (S36): absent, or the sibling's, but never this device's.
        let memberDevice = try #require(await relaunched.session.deviceIDForTest())
        let after = try await member.vault.store.record(key)
        #expect(after?.deviceID != memberDevice, "the sibling's published row was written again as this device's")
        if !withheld { #expect(after?.deviceID == siblingDevice) }
        try await Self.syncAll([owner, sibling])
        let atOwner = try await owner.session.item(id: saved.id)
        #expect(atOwner.title == "Bank, by the sibling")
        #expect(!atOwner.hasConflicts, "the sibling's values came back beside themselves")
        #expect(!(try await sibling.session.item(id: saved.id)).hasConflicts)
    }

    /// Threat: A8, who can edit this device's sync state and sharing state files but not reach the Keychain, and in
    /// the second case also the sync store (A1), which withholds the sibling's stream from this device (review of
    /// round 16, Z216: Z211 on a restored device). The member's device has a sibling, enrolled before the member's
    /// store is restored onto other hardware. The restored device registers a new ID, from the registry it holds,
    /// which already lists the sibling: so the sibling's registration is an ancestor of the restored device's, and
    /// Z211's rule read it from a state that does not verify as an earlier ID of this installation. A8 names it there
    /// and deletes the stream index; with the sibling's stream withheld, the sibling's published item was recorded as
    /// a restore's unpublished work and written again as the restored device's, so that every member held the
    /// sibling's values twice. The chain is no longer read from a state that does not verify: it comes from the move's
    /// own signed record (`RestoredChainRow`) and the states that verify, and names only the IDs this installation
    /// had.
    @Test(
        "a sibling enrolled before a restore, named in an edited state as an earlier ID, keeps its published work",
        arguments: [false, true])
    func plantedChainIDOfASiblingEnrolledBeforeARestore(withheld: Bool) async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 30_900)
        let member = members[0]
        let sibling = try await household.secondDevice(of: member)
        try await sibling.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await Self.syncAll([owner, member, sibling])
        let saved = try await sibling.session.save(Self.bank(in: vaultID))
        var edited = try await sibling.session.item(id: saved.id)
        edited.title = "Bank, by the sibling"
        _ = try await sibling.session.save(edited)
        try await Self.syncAll([sibling, owner, member])
        let key = RecordKey(recordID: saved.id, kind: .item)
        let siblingDevice = try #require(await sibling.session.deviceIDForTest())
        let before = try #require(try await member.vault.store.record(key))
        #expect(before.deviceID == siblingDevice, "the sibling's row is not the sibling's: nothing is tested")

        // The member's store restored onto other hardware, with nothing left unpublished; the move done.
        let oldID = try #require(await member.session.deviceIDForTest())
        let restored = try await Self.restoredOntoOtherHardware(member, household: household, seed: 30_901)
        _ = try await restored.session.syncAll()
        _ = try await restored.session.syncAll()
        let newID = try #require(await restored.session.deviceIDForTest())
        #expect(newID != oldID, "the restore registered no new ID: nothing is tested")

        let raw = try #require(restored.sync?.state as? InMemorySyncStateStore)
        var state = try #require(await raw.loadState(vaultID: vaultID))
        state.restoredUnpublished[key] = RecordStamp(version: 0, device: siblingDevice)
        state.authenticator = Array(repeating: 0, count: state.authenticator.count)
        await raw.tamper(state)
        await member.state.tamper(.streamIndex, vaultID: vaultID, value: nil)
        await restored.session.lock()
        let view = WithholdingTransport(base: household.transport)
        if withheld {
            let stream = SyncObjectLocation.vaultPrefix(vaultID) + "log/\(siblingDevice.uuidString)/"
            await view.withhold(Set(await household.transport.list(prefix: stream)))
        }
        let relaunched = TestVault(
            store: restored.store, keychain: restored.keychain, biometrics: restored.biometrics,
            clock: restored.clock, sync: SyncSettings(state: raw, transport: view), seed: 30_902,
            deviceKeys: restored.deviceKeys)
        await relaunched.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)
        #expect(try #require(await relaunched.session.deviceIDForTest()) == newID)

        _ = try await relaunched.session.syncAll()
        _ = try await relaunched.session.syncAll()
        let after = try await restored.store.record(key)
        #expect(after?.deviceID != newID, "the sibling's published row was written again as the restored device's")
        if !withheld { #expect(after?.deviceID == siblingDevice) }
        let written = try await raw.loadState(vaultID: vaultID)?.restoredUnpublished ?? [:]
        #expect(!written.values.contains { $0.device == siblingDevice }, "the sibling was recorded as an earlier ID")
        for _ in 0..<3 {
            _ = try await relaunched.session.syncAll()
            try await Self.syncAll([owner, sibling])
        }
        let atOwner = try await owner.session.item(id: saved.id)
        #expect(atOwner.title == "Bank, by the sibling")
        #expect(!atOwner.hasConflicts, "the sibling's values came back beside themselves")
        #expect(!(try await sibling.session.item(id: saved.id)).hasConflicts)
    }
}

/// A record store that locks a session from inside the `n`-th read, from now on, of one of `keys` while that session
/// is unlocked: a lock (the person, or auto-lock) landing at each suspension of a restore's carry in turn. With no
/// session armed it only counts those reads.
/// It can also lock that session just after the `n`-th commit, from now on, that writes one of `keys` (review of round
/// 16, Z217): a lock landing inside the carry's own commit, after the row is written.
actor CarryLockingStore: RecordStore {
    let base: any RecordStore
    private var target: (session: VaultSession, keys: Set<RecordKey>, skipping: Int)?
    private var commitTarget: (session: VaultSession, keys: Set<RecordKey>, skipping: Int)?
    private(set) var reads = 0
    private(set) var commits = 0
    private(set) var locks = 0
    private var counting: Set<RecordKey> = []
    private var failing: Set<RecordKey> = []
    private(set) var failed = 0

    init(base: any RecordStore) {
        self.base = base
    }

    func count(_ keys: Set<RecordKey>) {
        counting = keys
        reads = 0
        commits = 0
    }

    func lock(_ session: VaultSession, onCommitOf keys: Set<RecordKey>, skipping: Int) {
        commitTarget = (session, keys, skipping)
    }

    func lock(_ session: VaultSession, onRead keys: Set<RecordKey>, skipping: Int) {
        target = (session, keys, skipping)
    }

    func loadAccount() async throws -> AccountRecord? { try await base.loadAccount() }

    func record(_ key: RecordKey) async throws -> StoredRecord? {
        if counting.contains(key) { reads += 1 }
        if let target, target.keys.contains(key), (try? await target.session.state()) == .unlocked {
            if target.skipping == 0 {
                self.target = nil
                locks += 1
                await target.session.lock()
            } else {
                self.target = (target.session, target.keys, target.skipping - 1)
            }
        }
        return try await base.record(key)
    }

    func records(in vaultID: UUID, kind: EnvelopeKind) async throws -> [StoredRecord] {
        try await base.records(in: vaultID, kind: kind)
    }

    /// The next commit that writes one of `keys` fails, as a database that cannot be written would; the one after
    /// succeeds.
    func failNextCommit(upserting keys: Set<RecordKey>) {
        failing = keys
    }

    func commit(_ change: StoreChange) async throws {
        if change.upserts.contains(where: { failing.contains($0.key) }) {
            failing = []
            failed += 1
            throw RecordStoreError.checkpointIncomplete
        }
        try await base.commit(change)
        guard
            change.upserts.contains(where: { counting.contains($0.key) || commitTarget?.keys.contains($0.key) == true })
        else { return }
        if change.upserts.contains(where: { counting.contains($0.key) }) { commits += 1 }
        if let commitTarget, change.upserts.contains(where: { commitTarget.keys.contains($0.key) }),
            (try? await commitTarget.session.state()) == .unlocked
        {
            if commitTarget.skipping == 0 {
                self.commitTarget = nil
                locks += 1
                await commitTarget.session.lock()
            } else {
                self.commitTarget = (commitTarget.session, commitTarget.keys, commitTarget.skipping - 1)
            }
        }
    }
    func eraseAll() async throws { try await base.eraseAll() }
}

/// A sync state store that locks a session from inside the `n`-th call, from now on, that reads or records one
/// vault's pending deletions (`pendingDeletions(vaultID:)`, `addPendingDeletion`) while that session is unlocked: a
/// lock landing at each of those suspensions of a restore's carry in turn (review of round 16, Z217). With no session
/// armed it only counts those calls.
actor CarryLockingSyncState: SyncStateStore {
    let base: any SyncStateStore
    let vaultID: UUID
    private var target: (session: VaultSession, skipping: Int)?
    private(set) var calls = 0
    private(set) var locks = 0

    init(base: any SyncStateStore, vaultID: UUID) {
        self.base = base
        self.vaultID = vaultID
    }

    func lock(_ session: VaultSession, onCall skipping: Int) {
        target = (session, skipping)
        calls = 0
    }

    private func suspend(in vault: UUID) async {
        guard vault == vaultID else { return }
        calls += 1
        guard let target, (try? await target.session.state()) == .unlocked else { return }
        if target.skipping == 0 {
            self.target = nil
            locks += 1
            await target.session.lock()
        } else {
            self.target = (target.session, target.skipping - 1)
        }
    }

    func loadState(vaultID: UUID) async throws -> SyncState? { try await base.loadState(vaultID: vaultID) }
    func saveState(_ state: SyncState) async throws { try await base.saveState(state) }
    func stage(_ object: StagedObject) async throws { try await base.stage(object) }
    func staged(vaultID: UUID) async throws -> [StagedObject] { try await base.staged(vaultID: vaultID) }
    func unstage(_ locations: [SyncObjectLocation]) async throws { try await base.unstage(locations) }
    func prepared(_ deletion: PendingDeletion) async throws -> PendingDeletion { try await base.prepared(deletion) }

    func addPendingDeletion(_ deletion: PendingDeletion) async throws {
        try await base.addPendingDeletion(deletion)
        await suspend(in: deletion.record.vaultID)
    }

    func pendingDeletions(vaultID: UUID) async throws -> [RecordKey: PendingDeletion] {
        let deletions = try await base.pendingDeletions(vaultID: vaultID)
        await suspend(in: vaultID)
        return deletions
    }

    func removePendingDeletions(_ deletions: [RecordKey: RecordStamp], vaultID: UUID) async throws {
        try await base.removePendingDeletions(deletions, vaultID: vaultID)
    }

    func quarantine(_ entry: SyncEntry, vaultID: UUID) async throws -> Bool {
        try await base.quarantine(entry, vaultID: vaultID)
    }

    func quarantined(vaultID: UUID) async throws -> [SyncEntry] { try await base.quarantined(vaultID: vaultID) }

    func discardQuarantined(_ entries: [SyncEntry], vaultID: UUID) async throws {
        try await base.discardQuarantined(entries, vaultID: vaultID)
    }

    func holdsQuarantined(_ entry: SyncEntry, vaultID: UUID) async throws -> Bool {
        try await base.holdsQuarantined(entry, vaultID: vaultID)
    }

    func quarantineUsage(vaultID: UUID) async throws -> QuarantineUsage {
        try await base.quarantineUsage(vaultID: vaultID)
    }

    func stash(vaultID: UUID) async throws -> [UInt8]? { try await base.stash(vaultID: vaultID) }
    func saveStash(_ bytes: [UInt8], vaultID: UUID) async throws { try await base.saveStash(bytes, vaultID: vaultID) }
    func eraseAll() async throws { try await base.eraseAll() }
}

/// A view of a transport that refuses, as unavailable, every object created under one prefix while `refusing` is set,
/// and passes everything else through: a device that downloads and merges a vault's log but publishes nothing there.
actor CreateRefusingTransport: SyncTransport {
    let base: any SyncTransport
    private var refusing: String?

    init(base: any SyncTransport) {
        self.base = base
    }

    func refuse(under prefix: String?) {
        refusing = prefix
    }

    func list(prefix: String) async throws -> [String] { try await base.list(prefix: prefix) }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        try await base.fetch(name, maximumLength: maximumLength)
    }

    func create(_ name: String, contents: [UInt8]) async throws {
        if let refusing, name.hasPrefix(refusing) { throw SyncTransportError.unavailable }
        try await base.create(name, contents: contents)
    }

    func delete(_ name: String) async throws { try await base.delete(name) }
}

extension AdversarialSharedVaultTests {
    /// The restore of `restoredEditAndDeletionReachMembers` over `CarryLockingStore`: an item renamed, another trashed
    /// and deleted, neither published, then the store restored onto other hardware.
    static func restoredEditAndDeletion(seed: UInt64) async throws -> (
        household: SharedVaultHousehold, owner: SharingAccount, restored: TestVault, store: CarryLockingStore,
        edited: UUID, deleted: UUID
    ) {
        let run = try await restoredEditAndDeletion(seed: seed, lockingState: false)
        return (run.household, run.owner, run.restored, run.store, run.edited, run.deleted)
    }

    /// The same, with the restored device's sync state over `CarryLockingSyncState` when `lockingState`.
    static func restoredEditAndDeletion(seed: UInt64, lockingState: Bool) async throws -> (
        household: SharedVaultHousehold, owner: SharingAccount, restored: TestVault, store: CarryLockingStore,
        state: CarryLockingSyncState?, edited: UUID, deleted: UUID
    ) {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: seed)
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
        let store = CarryLockingStore(base: member.vault.store)
        var sync = try #require(member.vault.sync)
        let state = lockingState ? CarryLockingSyncState(base: sync.state, vaultID: vaultID) : nil
        if let state { sync.state = state }
        let restored = TestVault(
            store: store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock, sync: sync, seed: seed + 1, deviceKeys: member.vault.deviceKeys)
        await restored.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)
        return (household, owner, restored, store, state, edited.id, deleted.id)
    }

    /// A restore whose carry commits a row and then rewrites the pending deletion of the same record (review of round
    /// 16, Z217): the member renames an item of a shared vault and deletes it while the owner edits another field, and
    /// syncs over a view that publishes nothing in the vault, so that the owner's edit, which the deletion had not
    /// seen, is merged and kept after the deletion beside the unpublished tombstone; then the store is restored onto
    /// other hardware. The carry writes the kept row again as the new ID's (a commit) and then the tombstone's erased
    /// row (with the keys read again after that commit).
    static func restoredDeletionBesideAKeptEdit(seed: UInt64) async throws -> (
        household: SharedVaultHousehold, owner: SharingAccount, restored: TestVault, store: CarryLockingStore,
        item: UUID
    ) {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: seed)
        let member = members[0]
        let saved = try await member.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([member, owner])
        let atOwner = try await owner.session.item(id: saved.id)
        _ = try await owner.session.save(Self.setting(.username, to: "owner-user", in: atOwner))
        try await owner.session.sync()
        var renamed = try await member.session.item(id: saved.id)
        renamed.title = "Bank, renamed"
        _ = try await member.session.save(renamed)
        try await member.session.trash(id: saved.id)
        try await member.session.deletePermanently(id: saved.id)

        // Synced over a view that publishes nothing in the vault: the owner's edit is merged, nothing goes out.
        await member.session.lock()
        let sync = try #require(member.vault.sync)
        let view = CreateRefusingTransport(base: household.transport)
        await view.refuse(under: SyncObjectLocation.vaultPrefix(vaultID))
        let offline = TestVault(
            store: member.vault.store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock, sync: SyncSettings(state: sync.state, transport: view), seed: seed + 1,
            deviceKeys: member.vault.deviceKeys)
        await offline.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await offline.session.unlock(password: TestVault.password)
        _ = try? await offline.session.syncAll()
        let key = RecordKey(recordID: saved.id, kind: .item)
        #expect(try await member.vault.store.record(key) != nil, "no version was kept after the deletion")
        #expect(
            try await sync.state.pendingDeletions(vaultID: vaultID)[key] != nil,
            "the deletion went out, or is gone: nothing is tested")
        await offline.session.lock()

        await member.vault.forgetDeviceKey(accountID: member.accountID)
        let store = CarryLockingStore(base: member.vault.store)
        let restored = TestVault(
            store: store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock, sync: sync, seed: seed + 2, deviceKeys: member.vault.deviceKeys)
        await restored.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)
        return (household, owner, restored, store, saved.id)
    }

    /// Threat: none needed but a lock (the person, or auto-lock) during a sync that carries a restore's work (review of
    /// round 15, Z212). The carry took the keys and the vault's key once per vault and used them after its reads and
    /// commits had suspended it: `lock()` zeroises both, and reading a zeroised key traps, so a lock landing there
    /// crashed the app. The lock lands at each read of the carried records in turn: each sync stops, and once unlocked
    /// again the carry finishes and the members get the edit and the deletion. The same for a lock inside each call
    /// that reads or records the vault's pending deletions (`CarryLockingSyncState`), the carry's read of them before
    /// it reads the signing key again among them, and inside the carry's commit of a row whose record also has a
    /// tombstone to rewrite (`restoredDeletionBesideAKeptEdit`), before the keys are read again for the tombstone's
    /// erased row (review of round 16, Z217): with either read replaced by keys held from before the suspension, the
    /// test traps (checked by reverting each).
    @Test("a lock at any read, deletion read or commit of a restore's carry stops the sync and loses nothing")
    func lockDuringTheCarry() async throws {
        func carried(_ run: (edited: UUID, deleted: UUID)) -> Set<RecordKey> {
            [RecordKey(recordID: run.edited, kind: .item), RecordKey(recordID: run.deleted, kind: .item)]
        }
        let dry = try await Self.restoredEditAndDeletion(seed: 30_400)
        await dry.store.count(carried((dry.edited, dry.deleted)))
        _ = try await dry.restored.session.syncAll()
        let reads = await dry.store.reads
        #expect(reads >= 2, "the carry read neither record: nothing is tested")

        for skipping in 0..<reads {
            let run = try await Self.restoredEditAndDeletion(seed: 30_400)
            await run.store.lock(run.restored.session, onRead: carried((run.edited, run.deleted)), skipping: skipping)
            _ = try? await run.restored.session.syncAll()
            #expect(await run.store.locks == 1, "no lock landed at read \(skipping)")
            try await run.restored.session.unlock(password: TestVault.password)
            _ = try await run.restored.session.syncAll()
            _ = try await run.restored.session.syncAll()
            try await Self.syncAll([run.owner])
            #expect(
                try await run.owner.session.item(id: run.edited).title == "Bank, renamed",
                "the edit never arrived after a lock at read \(skipping)")
            #expect(
                (try? await run.owner.session.item(id: run.deleted)) == nil,
                "the deletion never arrived after a lock at read \(skipping)")
        }

        // Inside each read or record of the vault's pending deletions, the carry's among them.
        let counted = try await Self.restoredEditAndDeletion(seed: 30_410, lockingState: true)
        let counter = try #require(counted.state)
        await counter.lock(counted.restored.session, onCall: .max)
        _ = try await counted.restored.session.syncAll()
        let calls = await counter.calls
        #expect(calls >= 1, "the sync read no pending deletion of the vault: nothing is tested")
        for skipping in 0..<calls {
            let run = try await Self.restoredEditAndDeletion(seed: 30_410, lockingState: true)
            let state = try #require(run.state)
            await state.lock(run.restored.session, onCall: skipping)
            _ = try? await run.restored.session.syncAll()
            #expect(await state.locks == 1, "no lock landed at deletion call \(skipping)")
            try await run.restored.session.unlock(password: TestVault.password)
            _ = try await run.restored.session.syncAll()
            _ = try await run.restored.session.syncAll()
            try await Self.syncAll([run.owner])
            #expect(
                try await run.owner.session.item(id: run.edited).title == "Bank, renamed",
                "the edit never arrived after a lock at deletion call \(skipping)")
            #expect(
                (try? await run.owner.session.item(id: run.deleted)) == nil,
                "the deletion never arrived after a lock at deletion call \(skipping)")
        }

        // Inside each commit of the carried record, the carry's among them, before its tombstone is rewritten.
        let kept = try await Self.restoredDeletionBesideAKeptEdit(seed: 30_420)
        let keptKey = RecordKey(recordID: kept.item, kind: .item)
        await kept.store.count([keptKey])
        _ = try await kept.restored.session.syncAll()
        let commits = await kept.store.commits
        #expect(commits >= 1, "the carry committed nothing of the record: nothing is tested")
        for skipping in 0..<commits {
            let run = try await Self.restoredDeletionBesideAKeptEdit(seed: 30_420)
            let key = RecordKey(recordID: run.item, kind: .item)
            await run.store.lock(run.restored.session, onCommitOf: [key], skipping: skipping)
            _ = try? await run.restored.session.syncAll()
            #expect(await run.store.locks == 1, "no lock landed at commit \(skipping)")
            try await run.restored.session.unlock(password: TestVault.password)
            for _ in 0..<3 {
                _ = try await run.restored.session.syncAll()
                try await Self.syncAll([run.owner])
            }
            let here = try await run.restored.session.item(id: run.item)
            let atOwner = try await run.owner.session.item(id: run.item)
            #expect(
                atOwner.fields.contains { $0.kind == .username && $0.value == "owner-user" },
                "the owner's edit kept after the deletion was lost after a lock at commit \(skipping)")
            #expect(
                ItemMerge.sameState(here, atOwner),
                "the restored device and the owner hold different items after a lock at commit \(skipping)")
        }
    }
}

extension AdversarialSharedVaultTests {
    /// Threat: none needed but a carry step that fails while the transport works (a commit the database refuses, a
    /// store read that fails), in a shared vault whose log a replay is asked for (review of round 15, Z209; here the
    /// stream index was lost with the restore, so it is rebuilt by one). The first pass of the sync merged nothing
    /// into the vault, but the replay pass merged what it had pulled into the rows still holding the earlier ID's
    /// work, and the next carry renamed them after that merge: L1's field order tie again. Nothing is merged into a
    /// vault whose carry has not finished, in any pass; the next sync carries, then merges, and the person's edit and
    /// the owner's both end up everywhere.
    @Test("a carry that does not finish keeps the replay pass from merging into its vault")
    func replayWaitsForTheCarry() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 30_500)
        let member = members[0]
        let saved = try await member.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([member, owner])
        var first = try await member.session.item(id: saved.id)
        first.title = "Bank, first"
        _ = try await member.session.save(first)
        let atOwner = try await owner.session.item(id: saved.id)
        _ = try await owner.session.save(Self.setting(.username, to: "owner-user", in: atOwner))
        try await owner.session.sync()

        let key = RecordKey(recordID: saved.id, kind: .item)
        let before = try #require(try await member.vault.store.record(key))
        await member.session.lock()
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        await member.state.tamper(.streamIndex, vaultID: vaultID, value: nil)
        let store = CarryLockingStore(base: member.vault.store)
        let restored = TestVault(
            store: store, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock, sync: member.vault.sync, seed: 30_501, deviceKeys: member.vault.deviceKeys)
        await restored.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)

        await store.failNextCommit(upserting: [key])
        let report = try await restored.session.syncAll()
        #expect(await store.failed == 1, "the carry's commit did not fail: nothing is tested")
        let held = try #require(try await member.vault.store.record(key))
        #expect(
            held.version == before.version && held.deviceID == before.deviceID,
            "something was merged into the row before its carry")
        #expect(report.publishingHeldForCarry == [vaultID])

        _ = try await restored.session.syncAll()
        _ = try await restored.session.syncAll()
        try await Self.syncAll([owner])
        let ownerCopy = try await owner.session.item(id: saved.id)
        #expect(ownerCopy.title == "Bank, first", "the carried edit never reached the owner")
        #expect(ownerCopy.fields.contains { $0.kind == .username && $0.value == "owner-user" })
        let here = try await restored.session.item(id: saved.id)
        #expect(here.fields.contains { $0.kind == .username && $0.value == "owner-user" })
        #expect(ItemMerge.sameState(here, ownerCopy), "the restored device and the owner hold different items")
    }
}

extension AdversarialSharedVaultTests {
    /// Threat: none needed but a restore (review of round 15, Z210, the order of review of round 14's L1). The member's
    /// device reorders an item's fields and is restored from a backup before that goes out; the owner reorders the same
    /// item concurrently, at the same version. The field order is a register whose later write wins, and two writes at
    /// one version are ordered by their writers' IDs: renamed after the merge, the person's order met the owner's under
    /// the earlier ID and then went out under the new one, so where the owner's ID falls between the two the person's
    /// reorder (which ranks above the owner's under the new ID and below it under the earlier one) was lost on every
    /// device, though every device holding the owner's version and the carry would have kept it. Carried before the
    /// merge, the restored device holds `R(a) ⊔ b`, what every device holds: the test computes that reference with
    /// `ItemMerge` for IDs that order this way, and every device must end with it. A session that merges first fails
    /// here (checked by reverting the order).
    @Test("a restore's carry before the merge leaves every device the field order the merge of the carry gives")
    func carryBeforeTheMergeKeepsTheFieldOrder() async throws {
        var tried = 0
        // The first seed is one whose IDs order this way (found by the loop); the loop covers a change of derivation.
        for seed in stride(from: UInt64(30_700), to: 30_700 + 40 * 10, by: 10) {
            let household = SharedVaultHousehold()
            let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: seed)
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
            #expect(aRow.version == bRow.version, "the two reorders are not at one version: nothing is tested")

            let oldID = aRow.deviceID
            let restored = try await Self.restoredOntoOtherHardware(member, household: household, seed: seed + 1)
            let newID = try #require(await restored.session.deviceIDForTest())
            let aOrigin = Revision(version: aRow.version, device: oldID)
            let bOrigin = Revision(version: bRow.version, device: bRow.deviceID)
            let carriedFirst = ItemMerge.reattributed(a, origin: aOrigin, from: oldID, above: published, to: newID)
            let reference = ItemMerge.merge(
                carriedFirst, origin: Revision(version: aRow.version, device: newID), b, origin: bOrigin)
            let mergedFirst = ItemMerge.reattributed(
                ItemMerge.merge(a, origin: aOrigin, b, origin: bOrigin), origin: bOrigin, from: oldID,
                above: published, to: newID)
            tried += 1
            // Only IDs that order so that the person's reorder wins under the new ID and lost under the earlier one:
            // renamed after the merge, it was gone before the rename (the other way round, the owner's order wins
            // either way once the carry is merged, and nothing tells the two orders apart).
            guard reference.fields.map(\.id) == a.fields.map(\.id), mergedFirst.fields.map(\.id) == b.fields.map(\.id)
            else { continue }

            for _ in 0..<3 {
                _ = try await restored.session.syncAll()
                try await owner.session.sync()
            }
            let expected = reference.fields.map(\.id)
            let ownerCopy = try await owner.session.item(id: saved.id)
            let here = try await restored.session.item(id: saved.id)
            #expect(ownerCopy.fields.map(\.id) == expected, "the owner does not hold the merge of the carry")
            #expect(here.fields.map(\.id) == expected, "the restored device does not hold the merge of the carry")
            #expect(ItemMerge.sameState(here, ownerCopy), "the restored device and the owner hold different items")
            return
        }
        Issue.record("no seed of \(tried) gave IDs whose order the carry's place decides")
    }
}
