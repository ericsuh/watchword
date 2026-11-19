import Foundation
import WatchwordModel
import WatchwordStore
import WatchwordSync

// What a store restored onto other hardware has still to carry over from an earlier device ID of this installation
// (review of round 12, M1 and Z191; docs/02-architecture.md §7.7). Registration carries what it can: a row in a vault
// with no current key here (a shared vault before its ledger is verified, which at an unlock before any sync is every
// shared vault, or one held closed) it cannot seal again. The move of the earlier ID's sync state records those rows,
// and the deletions it parked, in each vault's signed state (`SyncState.restoredUnpublished`) with the last version of
// each record that ID published; a sync carries them once the vault has a key, and until then every vault's
// deletions are held back and the sync names the items (`AccountSyncReport.restoredWorkWaiting`).
extension VaultSession {
    /// The records of `vaultID` holding work `previous` wrote and never published, each with the last version of it
    /// that ID published (version 0 for none): its rows that registration left (`row.deviceID` still that ID) and its
    /// pending deletions, read from the state the session signed for that ID, which the move is about to replace. A
    /// move made again after that state was replaced finds the new ID's state, and what it recorded stands. Only in a
    /// vault that may be shared (`isMarkedShared`): elsewhere every row has a key here, and no judge holds the old ID's
    /// work aside. Entries the earlier ID's own state held (a second restore's, for the ID before it) are kept.
    ///
    /// With no state signed for that ID (none, or one that does not verify: lost, or edited, A8), nothing reads as
    /// published: the carry then writes all of the earlier ID's work again, and members whose copies it published hold
    /// both, as conflicts for the person to resolve, rather than losing either.
    func restoredWork(in vaultID: UUID, leftBy previous: UUID, account: AccountRecord) async throws
        -> [RecordKey: RecordStamp]
    {
        guard let base = syncSettings?.state,
            isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID)
        else { return [:] }
        let raw = try await base.loadState(vaultID: vaultID)
        if let raw, let begun = await verifiedSyncState(raw, vaultID: vaultID, deviceID: account.deviceID) {
            return begun.restoredUnpublished
        }
        var earlier: SyncState?
        if let raw { earlier = await verifiedSyncState(raw, vaultID: vaultID, deviceID: previous) }
        var restored = earlier?.restoredUnpublished ?? [:]
        let published = earlier?.published ?? [:]
        func left(_ key: RecordKey) -> RecordStamp {
            let last = published[key].flatMap { $0.device == previous ? $0.version : nil }
            return RecordStamp(version: last ?? 0, device: previous)
        }
        for row in try await store.records(in: vaultID, kind: .item) where row.deviceID == previous {
            if let stamp = published[row.key], stamp >= RecordStamp(row) { continue }
            if restored[row.key] == nil { restored[row.key] = left(row.key) }
        }
        let parked = Self.parkedDeletionDevice(of: previous)
        for (key, deletion) in try await base.pendingDeletions(vaultID: vaultID)
        where key.kind == .item && (deletion.stamp.device == previous || deletion.stamp.device == parked) {
            if restored[key] == nil { restored[key] = left(key) }
        }
        return restored
    }

    /// Carries what a restore left in each vault that has a current key here now (`SyncState.restoredUnpublished`):
    /// each row still holding the earlier ID's work above the version it published is written again as this device's
    /// next version, that work written as this device's (`ItemMerge.reattributed`) where the earlier ID's published
    /// work counts for the vault's members (it commits; otherwise the row is only carried, and the hold for what
    /// nobody received takes over, Z170); and each pending deletion of this device's, parked or not, whose erased row
    /// holds such work has its row written the same way (one version up, so the replacement is one write), so that its
    /// erasure summary claims nothing the earlier ID did not publish and no member's judge holds the tombstone aside
    /// (Z191). An entry is dropped once nothing of it is left to carry: carried, or replaced by a version that holds
    /// none of that work, or no longer in the store, or unreadable under the vault's key.
    ///
    /// Run by `syncAll` before any vault's log, so that what it writes is published in the same sync, ahead of any
    /// deletion. A step that fails keeps its entry for the next sync; meanwhile the deletion gate holds every
    /// deletion back while a row it names holds that work (`holdsRestoredWork`).
    func carryRestoredWork(account: AccountRecord, view: RegistryView?, since epoch: UInt64) async {
        guard let syncState, let base = syncSettings?.state, let view,
            let vaults = try? await vaultDirectory(account).keys
        else { return }
        let own = account.deviceID
        let parked = Self.parkedDeletionDevice(of: own)
        for vaultID in vaults {
            guard let keys = try? requireKeys(since: epoch),
                let vaultKey = currentVaultKey(vaultID, keys: keys, account: account),
                var state = try? await syncState.loadState(vaultID: vaultID), !state.restoredUnpublished.isEmpty,
                let deletions = try? await base.pendingDeletions(vaultID: vaultID),
                let signingKey = try? keys.keyset.publicKeyBundle().signingKey
            else { continue }
            var remaining: [RecordKey: RecordStamp] = [:]
            for (key, left) in state.restoredUnpublished {
                guard (try? requireKeys(since: epoch)) != nil else { return }
                let reattributing = !Self.idsNobodyReceives(account: account, view: view, including: left.device)
                    .contains(left.device)
                let row: StoredRecord?
                do {
                    row = try await store.record(key)
                } catch {
                    // Not read now: tried again at the next sync.
                    remaining[key] = left
                    continue
                }
                var keep = false
                if let row, row.vaultID == vaultID, let item = try? openItem(row, keys: keys),
                    reattributing ? Self.holds(item, row: row, workOf: left) : row.deviceID == left.device
                {
                    let carried =
                        reattributing
                        ? ItemMerge.reattributed(
                            item, origin: Self.origin(row), from: left.device, above: left.version, to: own) : item
                    do {
                        let revision = try nextRevision(in: vaultID, above: row, account: account)
                        let sealed = try sealItem(
                            ItemMerge.written(carried, as: revision), vaultKey: vaultKey, account: account)
                        _ = try requireKeys(since: epoch)
                        try await store.commit(
                            StoreChange(upserts: [sealed], expectations: [key: .version(row.version)]))
                        highestVersionSeen[vaultID] = max(highestVersionSeen[vaultID] ?? 0, revision.version)
                    } catch {
                        keep = true
                    }
                }
                if reattributing, let deletion = deletions[key], deletion.stamp.version < .max - 1,
                    deletion.stamp.device == own || deletion.stamp.device == parked,
                    Self.isSigned(deletion, as: key, in: vaultID, signingKey: signingKey),
                    let erased = try? openItem(deletion.record, keys: keys),
                    Self.holds(erased, row: deletion.record, workOf: left)
                {
                    do {
                        let rewritten = ItemMerge.reattributed(
                            erased, origin: Self.origin(deletion.record), from: left.device, above: left.version,
                            to: own)
                        let record = try sealItem(
                            ItemMerge.written(rewritten, as: Revision(version: deletion.record.version, device: own)),
                            vaultKey: vaultKey, account: account)
                        let replacement = PendingDeletion(
                            stamp: RecordStamp(
                                version: deletion.stamp.version + 1, device: deletion.stamp.device, deleted: true),
                            record: record)
                        let signed =
                            deletion.stamp.device == own
                            ? try authenticatePendingDeletion(replacement) : try signedPendingDeletion(replacement)
                        try await base.addPendingDeletion(signed)
                    } catch {
                        keep = true
                    }
                }
                if keep { remaining[key] = left }
            }
            guard remaining != state.restoredUnpublished, (try? requireKeys(since: epoch)) != nil else { continue }
            state.restoredUnpublished = remaining
            try? await syncState.saveState(state)
        }
    }

    /// Whether `item`, read from `row`, holds work of `left.device` above `left.version`: its clock's count for that
    /// ID, which covers every value, line, removal, discard and history entry the ID wrote (`ItemMerge.effectiveClock`).
    static func holds(_ item: Item, row: StoredRecord, workOf left: RecordStamp) -> Bool {
        (ItemMerge.effectiveClock(item, origin: origin(row)).entries[left.device] ?? 0) > left.version
    }

    /// The items of `vaultID` whose rows still hold what a restore left there (`SyncState.restoredUnpublished`):
    /// a row of the vault named there that holds the earlier ID's work above the version it published, or that cannot
    /// be read for want of a current key for the vault here (registration could not carry it, and nothing has since).
    /// A row that does not open under a key this device holds carries nothing it can read, and is not counted. `nil`
    /// where the store could not be read: the gate then holds.
    func itemsHoldingRestoredWork(in vaultID: UUID, state: SyncState?, account: AccountRecord) async -> Set<UUID>? {
        guard let restored = state?.restoredUnpublished, !restored.isEmpty else { return [] }
        let keys = keys
        let vaultKey = keys.flatMap { currentVaultKey(vaultID, keys: $0, account: account) }
        var items: Set<UUID> = []
        for (key, left) in restored {
            let row: StoredRecord?
            do {
                row = try await store.record(key)
            } catch {
                return nil
            }
            guard let row, row.vaultID == vaultID, row.kind == .item else { continue }
            guard let keys, vaultKey != nil else {
                items.insert(row.recordID)
                continue
            }
            guard let item = try? openItem(row, keys: keys) else { continue }
            if Self.holds(item, row: row, workOf: left) { items.insert(row.recordID) }
        }
        return items
    }

    /// Whether `vaultID` holds what a restore left and has not carried (`itemsHoldingRestoredWork`): while any vault
    /// does, no vault's deletions go out, since one of them may be the source half of a move whose copy is that
    /// work, which has reached nobody (review of round 12, M1; Z44). Fails closed.
    func holdsRestoredWork(in vaultID: UUID, state: SyncState?, account: AccountRecord) async -> Bool {
        guard let items = await itemsHoldingRestoredWork(in: vaultID, state: state, account: account) else {
            return true
        }
        return !items.isEmpty
    }

    /// Per vault, the items holding what a restore left and has not carried, for the report
    /// (`AccountSyncReport.restoredWorkWaiting`). Read while the keys of `epoch` are here; a lock meanwhile reports
    /// none (as `copiesNobodyReceived`, Z174).
    func restoredWorkWaiting(account: AccountRecord, since epoch: UInt64) async -> [UUID: Set<UUID>] {
        guard let syncState, let vaults = try? await vaultDirectory(account).keys else { return [:] }
        var waiting: [UUID: Set<UUID>] = [:]
        for vaultID in vaults {
            let state = try? await syncState.loadState(vaultID: vaultID)
            let items = await itemsHoldingRestoredWork(in: vaultID, state: state, account: account)
            guard (try? requireKeys(since: epoch)) != nil else { return [:] }
            if let items, !items.isEmpty { waiting[vaultID] = items }
        }
        return waiting
    }

    /// Stops waiting to carry over what a restore left in `vaultID` (`AccountSyncReport.restoredWorkWaiting`), so
    /// that deletions go out again: for a vault that will not open on this device (an owner its devices disagree
    /// about, Z59, or a vault this account no longer belongs to). The person's choice, as every discard is (PRD F7.7):
    /// the rows stay on this device as they are, and what the earlier device ID wrote there and never published
    /// reaches no other device. Needs the vault unlocked.
    public func stopWaitingForRestoredWork(in vaultID: UUID) async throws {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let syncState else { throw VaultError.syncNotConfigured }
        guard var state = try await syncState.loadState(vaultID: vaultID), !state.restoredUnpublished.isEmpty else {
            return
        }
        state.restoredUnpublished = [:]
        _ = try requireKeys(since: epoch)
        try await syncState.saveState(state)
    }
}
