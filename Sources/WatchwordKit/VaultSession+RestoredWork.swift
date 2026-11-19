import Foundation
import WatchwordModel
import WatchwordStore
import WatchwordSync

// What a store restored onto other hardware has still to carry over from an earlier device ID of this installation
// (review of round 12, M1 and Z191; review of round 13; docs/02-architecture.md §7.7). Registration carries no item of
// a vault that may be shared where the earlier ID commits (what it published is known only once a sync has pulled the
// vault's log, Z198), nor a row in a vault with no current key here. The move of the earlier ID's sync state records
// those rows, and the deletions it parked, in each vault's signed state (`SyncState.restoredUnpublished`) with the last
// version of each record that ID's state says it published; a sync carries them once the vault has a key and its log
// has been pulled, and until then every vault's deletions are held back and the sync names the items
// (`AccountSyncReport.restoredWorkWaiting`), unless the vault waits for nothing any more (Z199).
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
        // Only deletions the account key signed (review of round 14, M1): one planted in the file (A8) would add an
        // entry for a row of another device's, and the carry would write that row's work of the earlier ID as this
        // device's.
        let parked = Self.parkedDeletionDevice(of: previous)
        let signingKey = try requireKeys().keyset.publicKeyBundle().signingKey
        for (key, deletion) in try await base.pendingDeletions(vaultID: vaultID)
        where key.kind == .item && (deletion.stamp.device == previous || deletion.stamp.device == parked)
            && Self.isSigned(deletion, as: key, in: vaultID, signingKey: signingKey)
        {
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
    /// What counts as published of the earlier ID's work is the most of three (review of round 13, M2): the version
    /// its own signed state recorded (`left.version`), the highest version of the record that ID's stream carried as
    /// the stream index shows it (`publishedBound`), and what the item shows a third device saw of it
    /// (`ItemMerge.reattributed`). A backup older than the earlier ID's last publish, or a state lost with the
    /// restore, so renames none of what that ID published: renamed, it would have come back beside itself, its
    /// superseded values as conflicts and an item it deleted as one kept after the deletion.
    ///
    /// Run by `syncAll` for the vaults in `vaults`: those whose log this sync has pulled, after it, so that the stream
    /// index is the transport's and not the backup's; their pass published nothing, so that no merge of the rows
    /// still holding the earlier ID's work went out before it was carried. The carried rows go out at the next sync,
    /// ahead of any deletion. A step that fails keeps its entry for the next sync; meanwhile the deletion gate holds
    /// every deletion back while a row it names holds that work (`holdsRestoredWork`).
    ///
    /// `staged` is what the vault's staged segments, downloaded and not merged yet, carry of each record
    /// (`stagedBounds`): the carry runs after the download and before the pass that merges it, so that it renames the
    /// backup's version and the pulled versions are merged into the renamed one, as every other device merges them
    /// (review of round 14, L1: renamed after the merge, a field order that had won a tie by the earlier ID's place
    /// could lose it by the new ID's, or the reverse, against an order the merge had already dropped). Returns whether
    /// every step that had something to do did it: one that failed (a row not read, a seal or commit that threw, a
    /// lock) leaves its entry, and the caller then merges nothing into the vault in this sync, so that the entry is
    /// still carried before any merge.
    @discardableResult
    func carryRestoredWork(
        account: AccountRecord, view: RegistryView?, since epoch: UInt64, in vaults: Set<UUID>,
        staged: [UUID: [RecordKey: [UUID: UInt64]]] = [:]
    ) async -> Bool {
        guard let syncState, let base = syncSettings?.state, let view else { return false }
        let own = account.deviceID
        let parked = Self.parkedDeletionDevice(of: own)
        var finished = true
        for vaultID in vaults.sorted(by: { $0.uuidString < $1.uuidString }) {
            guard !(await restoredWorkReleased(vaultID, account: account)) else { continue }
            let loaded: SyncState?
            do {
                loaded = try await syncState.loadState(vaultID: vaultID)
            } catch {
                finished = false
                continue
            }
            guard var state = loaded, !state.restoredUnpublished.isEmpty else { continue }
            guard let keys = try? requireKeys(since: epoch),
                let vaultKey = currentVaultKey(vaultID, keys: keys, account: account),
                let deletions = try? await base.pendingDeletions(vaultID: vaultID),
                let signingKey = try? keys.keyset.publicKeyBundle().signingKey
            else {
                finished = false
                continue
            }
            var remaining: [RecordKey: RecordStamp] = [:]
            for (key, recorded) in state.restoredUnpublished {
                guard (try? requireKeys(since: epoch)) != nil else { return false }
                if Self.isDismissed(recorded) {
                    // Kept while the row is still the earlier ID's (`dismissedVersion`).
                    if let row = try? await store.record(key), row.deviceID == recorded.device {
                        remaining[key] = recorded
                    }
                    continue
                }
                let pulled = staged[vaultID]?[key]?[recorded.device] ?? 0
                let indexed = publishedBound(recorded, of: key, in: vaultID)
                let left = RecordStamp(version: max(indexed.version, pulled), device: recorded.device)
                let reattributing = !Self.idsNobodyReceives(account: account, view: view, including: left.device)
                    .contains(left.device)
                let row: StoredRecord?
                do {
                    row = try await store.record(key)
                } catch {
                    // Not read now: tried again at the next sync.
                    remaining[key] = recorded
                    finished = false
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
                if keep {
                    remaining[key] = recorded
                    finished = false
                }
            }
            guard remaining != state.restoredUnpublished else { continue }
            guard (try? requireKeys(since: epoch)) != nil else { return false }
            state.restoredUnpublished = remaining
            do {
                try await syncState.saveState(state)
            } catch {
                finished = false
            }
        }
        return finished
    }

    /// What the staged segments of `vaultID`'s log, downloaded and not merged yet, show each earlier ID published of
    /// the records a restore has still to carry there (`SyncState.restoredUnpublished`), per record and earlier ID:
    /// the highest version of the record that ID's own stream carried, and the most of that ID's work a third device's
    /// version shows it had seen (`ItemMerge.seenByOthers`; whatever a third device saw, that ID published). What the
    /// stream index shows once those segments are merged, and what the merged item would show, read before the merge
    /// (review of round 14, L1). A version that does not open here shows nothing. `nil` where the state or the stage
    /// cannot be read, or while locked: the carry then waits.
    func stagedBounds(in vaultID: UUID, engine: SyncEngine, account: AccountRecord, since epoch: UInt64) async
        -> [RecordKey: [UUID: UInt64]]?
    {
        guard let syncState else { return [:] }
        let state: SyncState?
        do {
            state = try await syncState.loadState(vaultID: vaultID)
        } catch {
            return nil
        }
        let restored = (state?.restoredUnpublished ?? [:]).filter { !Self.isDismissed($0.value) }
        guard !restored.isEmpty else { return [:] }
        guard let entries = try? await engine.stagedEntries(of: Set(restored.keys)),
            let keys = try? requireKeys(since: epoch)
        else { return nil }
        var bounds: [RecordKey: [UUID: UInt64]] = [:]
        for entry in entries {
            guard let earlier = restored[entry.key]?.device else { continue }
            var seen = entry.device == earlier ? entry.version : 0
            if entry.device != earlier, entry.device != account.deviceID, entry.kind == .item,
                let row = entry.record(in: vaultID), let item = try? openItem(row, keys: keys)
            {
                seen = ItemMerge.seenByOthers(
                    item, origin: Self.origin(row), of: earlier, besides: account.deviceID)
            }
            bounds[entry.key, default: [:]][earlier] = max(bounds[entry.key]?[earlier] ?? 0, seen)
        }
        return bounds
    }

    /// `left` (an entry of `SyncState.restoredUnpublished`) with its version raised to the highest version of the
    /// record that `left.device`'s own stream carried in `vaultID`, as the stream index shows it (review of round 13,
    /// M2): whatever that stream carried was published, whatever the earlier ID's state said.
    func publishedBound(_ left: RecordStamp, of key: RecordKey, in vaultID: UUID) -> RecordStamp {
        let carried =
            sharing.vaults[vaultID]?.index.highestVersionCarried(
                by: left.device, of: key.recordID, kind: key.kind.rawValue) ?? 0
        return RecordStamp(version: max(left.version, carried), device: left.device)
    }

    /// Whether `vaultID`'s signed state records anything a restore has still to carry over there: its first pass of a
    /// sync then publishes nothing (`syncAll`, review of round 13, M2). Entries the person stopped waiting for do not
    /// count.
    func restoredWorkToCarry(in vaultID: UUID) async -> Bool {
        guard let syncState else { return false }
        guard let state = try? await syncState.loadState(vaultID: vaultID) else { return false }
        return state.restoredUnpublished.values.contains { !Self.isDismissed($0) }
    }

    /// The version an entry of `SyncState.restoredUnpublished` holds once the person has stopped waiting for it
    /// (`stopWaitingForRestoredWork`, review of round 13, M3): no version of a record reaches it, so it is never one
    /// published, and it keeps the row from being found again by `rowsLeftByEarlierIDs` while the row is the earlier
    /// ID's. Nothing carries it, holds for it or reports it.
    static let dismissedVersion = UInt64.max

    static func isDismissed(_ left: RecordStamp) -> Bool {
        left.version == dismissedVersion
    }

    /// The earlier device IDs of this installation that a restore's records name: the move under way
    /// (`AccountRecord.migration`), and every ID an entry of `SyncState.restoredUnpublished` names that the person has
    /// not stopped waiting for, in any vault, in a state that verifies or not (review of round 13, L-a). The chain is
    /// not stored anywhere else, so a state that does not verify (edited in the file, A8) is read for it too, but only
    /// ever to hold more back and to carry what a row shows is that ID's unpublished work (`rowsLeftByEarlierIDs`),
    /// never to discard: an ID planted there can at worst hold deletions back, and have this device write again as its
    /// own a row of that ID's whose work no segment of its stream carried here.
    ///
    /// From a state that does not verify, only an ID this account's registry lists as one of its own devices, current
    /// or revoked (review of round 14, L3): an earlier ID of this installation was registered under this account. Any
    /// other ID planted there, with the stream index's entry for it gone, named another account's device in a shared
    /// vault, whose rows the take-out then left alone and the carry wrote again as this device's, laundering writes
    /// every member's judge would hold aside. With the registry unreadable here such an ID still counts for the hold
    /// (`listedOwnIDs` is `nil`), and `recordRestoredWorkLeft` records nothing until it can be read.
    func restoredChain(account: AccountRecord) async -> Set<UUID> {
        var chain: Set<UUID> = []
        if let previous = account.migration?.previousDeviceID { chain.insert(previous) }
        guard let base = syncSettings?.state, let vaults = try? await vaultDirectory(account).keys else { return chain }
        let listed = await listedOwnIDs(account)
        for vaultID in vaults {
            guard let raw = try? await base.loadState(vaultID: vaultID) else { continue }
            let verified = await verifiedSyncState(raw, vaultID: vaultID) != nil
            for left in raw.restoredUnpublished.values
            where !Self.isDismissed(left) && (verified || listed?.contains(left.device) ?? true) {
                chain.insert(left.device)
            }
        }
        chain.remove(account.deviceID)
        return chain
    }

    /// Every device ID this account's registry lists, current or revoked; `nil` where the registry cannot be read.
    func listedOwnIDs(_ account: AccountRecord) async -> Set<UUID>? {
        guard let view = try? await registry(account) else { return nil }
        return Set(view.state.devices.keys).union(view.state.revoked.keys)
    }

    /// The rows of `vaultID`, if it may be shared, that an earlier ID of `chain` left and that `recorded` (the vault's
    /// signed entries) does not name: still that ID's row, holding its work above what its stream carried here
    /// (`publishedBound`), each with version 0 for an entry. What the hold derives where the vault's state that would
    /// name them is gone: lost, or one that does not verify (damaged, or edited, A8), which a sync would start over
    /// (review of round 13, L-a). Asked only then: a state that verifies is the move's record, made from what the
    /// earlier ID's own state said it published, and a row of a vault held closed, whose stream this device cannot
    /// read, would otherwise count whether that ID published it or not. A row that does not open here counts. `nil`
    /// where the store could not be read.
    func rowsLeftByEarlierIDs(
        in vaultID: UUID, chain: Set<UUID>, recorded: [RecordKey: RecordStamp], account: AccountRecord
    ) async -> [RecordKey: RecordStamp]? {
        guard !chain.isEmpty, isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID) else {
            return [:]
        }
        guard let rows = try? await store.records(in: vaultID, kind: .item) else { return nil }
        var left: [RecordKey: RecordStamp] = [:]
        for row in rows where chain.contains(row.deviceID) && recorded[row.key] == nil {
            let entry = RecordStamp(version: 0, device: row.deviceID)
            let bound = publishedBound(entry, of: row.key, in: vaultID)
            if holdsEdit(of: row.deviceID, in: row, above: bound.version) { left[row.key] = entry }
        }
        return left
    }

    /// What a restore left in `vaultID` and has still to carry, as the hold and the report read it: the entries of the
    /// vault's signed state the person has not stopped waiting for, and the rows `rowsLeftByEarlierIDs` finds. `nil`
    /// fails closed (review of round 13, L-a): the state could not be read, or the store, or, while `chain` names an
    /// earlier ID, the vault (one that may be shared) holds a state that does not verify, which may have held entries.
    func restoredEntries(in vaultID: UUID, chain: Set<UUID>, account: AccountRecord) async
        -> [RecordKey: RecordStamp]?
    {
        guard let base = syncSettings?.state else { return [:] }
        let raw: SyncState?
        do {
            raw = try await base.loadState(vaultID: vaultID)
        } catch {
            return nil
        }
        var verified: SyncState?
        if let raw { verified = await verifiedSyncState(raw, vaultID: vaultID) }
        if raw != nil, verified == nil, !chain.isEmpty,
            isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID)
        {
            return nil
        }
        let recorded = (verified?.restoredUnpublished ?? [:]).filter { !Self.isDismissed($0.value) }
        guard verified == nil else { return recorded }
        guard
            let left = await rowsLeftByEarlierIDs(in: vaultID, chain: chain, recorded: [:], account: account)
        else { return nil }
        return left
    }

    /// Records what `rowsLeftByEarlierIDs` finds in each vault whose state is lost or does not verify as entries of a
    /// state this session signs, before any log of a sync, so that the take-out leaves those rows alone and the carry
    /// writes them (review of round 13, L-a): a state of a vault that may be shared that does not verify is started
    /// over while the chain names an earlier ID, as the engine would start it over, with those entries in it.
    func recordRestoredWorkLeft(account: AccountRecord, since epoch: UInt64) async {
        guard let syncState, let base = syncSettings?.state else { return }
        // Only with the registry read, so that the chain holds no ID planted in a state that does not verify (L3).
        guard await listedOwnIDs(account) != nil else { return }
        let chain = await restoredChain(account: account)
        guard !chain.isEmpty, let vaults = try? await vaultDirectory(account).keys else { return }
        for vaultID in vaults where isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID) {
            let raw: SyncState?
            do {
                raw = try await base.loadState(vaultID: vaultID)
            } catch {
                continue
            }
            if let raw, await verifiedSyncState(raw, vaultID: vaultID) != nil { continue }
            guard let left = await rowsLeftByEarlierIDs(in: vaultID, chain: chain, recorded: [:], account: account),
                !left.isEmpty || raw != nil
            else { continue }
            var state = SyncState(vaultID: vaultID)
            state.restoredUnpublished = left
            guard (try? requireKeys(since: epoch)) != nil else { return }
            try? await syncState.saveState(state)
        }
    }

    /// Whether what a restore left in `vaultID` waits for nothing any more (review of round 13, M3): the vault is
    /// deleted, or gone from the directory, or this account's membership of it has ended. Nothing will carry it
    /// there, so it holds no deletion back; its rows stay on this device as they are, and the sync says so
    /// (`AccountSyncReport.restoredWorkKeptHere`).
    func restoredWorkReleased(_ vaultID: UUID, account: AccountRecord) async -> Bool {
        guard let directory = try? await vaultDirectory(account) else { return false }
        guard let entry = directory[vaultID] else { return true }
        return entry.isDeleted || membershipEnded(vaultID, account: account)
    }

    /// Whether `item`, read from `row`, holds work of `left.device` above `left.version`: its clock's count for that
    /// ID, which covers every value, line, removal, discard and history entry the ID wrote (`ItemMerge.effectiveClock`).
    static func holds(_ item: Item, row: StoredRecord, workOf left: RecordStamp) -> Bool {
        (ItemMerge.effectiveClock(item, origin: origin(row)).entries[left.device] ?? 0) > left.version
    }

    /// The items of `vaultID` whose rows still hold what a restore left there (`restoredEntries`): a row of the vault
    /// named there that holds the earlier ID's work above what it published (`publishedBound`), or that cannot be read
    /// for want of a current key for the vault here (registration could not carry it, and nothing has since). A row
    /// that does not open under a key this device holds carries nothing it can read, and is not counted. `nil` where
    /// the state or the store could not be read: the gate then holds.
    func itemsHoldingRestoredWork(in vaultID: UUID, chain: Set<UUID>, account: AccountRecord) async -> Set<UUID>? {
        guard let restored = await restoredEntries(in: vaultID, chain: chain, account: account) else { return nil }
        guard !restored.isEmpty else { return [] }
        let keys = keys
        let vaultKey = keys.flatMap { currentVaultKey(vaultID, keys: $0, account: account) }
        var items: Set<UUID> = []
        for (key, recorded) in restored {
            let left = publishedBound(recorded, of: key, in: vaultID)
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
    /// work, which has reached nobody (review of round 12, M1; Z44). Fails closed (review of round 13, L-a), except
    /// where nothing will carry it (`restoredWorkReleased`, M3).
    func holdsRestoredWork(in vaultID: UUID, chain: Set<UUID>, account: AccountRecord) async -> Bool {
        if await restoredWorkReleased(vaultID, account: account) { return false }
        guard let items = await itemsHoldingRestoredWork(in: vaultID, chain: chain, account: account) else {
            return true
        }
        return !items.isEmpty
    }

    /// Per vault, the items holding what a restore left and has not carried, for the report: those that wait
    /// (`AccountSyncReport.restoredWorkWaiting`) and those that stay on this device only, their vault deleted or this
    /// account's membership of it ended (`restoredWorkKeptHere`, review of round 13, M3). Read while the keys of
    /// `epoch` are here; a lock meanwhile reports none (as `copiesNobodyReceived`, Z174).
    ///
    /// `mayStopWaiting` is the waiting vaults the person may stop waiting for (`mayStopWaitingForRestoredWork`).
    func restoredWorkWaiting(account: AccountRecord, since epoch: UInt64) async -> (
        waiting: [UUID: Set<UUID>], keptHere: [UUID: Set<UUID>], mayStopWaiting: Set<UUID>
    ) {
        guard let vaults = try? await vaultDirectory(account).keys else { return ([:], [:], []) }
        let chain = await restoredChain(account: account)
        var waiting: [UUID: Set<UUID>] = [:]
        var keptHere: [UUID: Set<UUID>] = [:]
        var mayStopWaiting: Set<UUID> = []
        for vaultID in vaults {
            let items = await itemsHoldingRestoredWork(in: vaultID, chain: chain, account: account)
            let released = await restoredWorkReleased(vaultID, account: account)
            guard let keys = try? requireKeys(since: epoch) else { return ([:], [:], []) }
            guard let items, !items.isEmpty else { continue }
            if released {
                keptHere[vaultID] = items
            } else {
                waiting[vaultID] = items
                if mayStopWaitingForRestoredWork(in: vaultID, keys: keys, account: account) {
                    mayStopWaiting.insert(vaultID)
                }
            }
        }
        return (waiting, keptHere, mayStopWaiting)
    }

    /// Whether the person may stop waiting to carry over what a restore left in `vaultID` (review of round 14, L2):
    /// only where the vault will not open on this device, with no current key here (no verified ledger, Z41, or a key
    /// this device does not hold) or an owner its devices disagree about (Z59). A vault that opens here waits only on
    /// something a sync gets past (the transport, its log not pulled yet, a carry step that failed), and its carry
    /// writes the work again as this device's; stopped, its rows would stay the earlier ID's, and any later edit of one
    /// would seal that ID's unpublished values under this device's, which every member's judge holds aside, that
    /// version and every later one.
    func mayStopWaitingForRestoredWork(in vaultID: UUID, keys: UnlockedKeys, account: AccountRecord) -> Bool {
        currentVaultKey(vaultID, keys: keys, account: account) == nil || isOwnerDisputed(vaultID)
    }

    /// Stops waiting to carry over what a restore left in `vaultID` (`AccountSyncReport.restoredWorkWaiting`), so
    /// that deletions go out again: for a vault that will not open on this device (an owner its devices disagree
    /// about, Z59). The person's choice, as every discard is (PRD F7.7): the rows stay on this device as they are, and
    /// what the earlier device ID wrote there and never published reaches no other device (the notice's action,
    /// `SyncNoticeAction.stopWaitingForRestoredWork`, review of round 13, M3). A vault this account no longer belongs
    /// to, or one deleted, waits for nothing and needs no choice (`restoredWorkReleased`). Needs the vault unlocked.
    public func stopWaitingForRestoredWork(in vaultID: UUID) async throws {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let syncState, let base = syncSettings?.state else { throw VaultError.syncNotConfigured }
        await loadSharedVaultsIfNeeded()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        // Only for a vault that will not open here (review of round 14, L2).
        guard mayStopWaitingForRestoredWork(in: vaultID, keys: try requireKeys(since: epoch), account: account) else {
            throw VaultError.restoredWorkCanBeCarried(vaultID)
        }
        let chain = await restoredChain(account: account)
        let raw = try await base.loadState(vaultID: vaultID)
        var verified: SyncState?
        if let raw { verified = await verifiedSyncState(raw, vaultID: vaultID) }
        // A state that does not verify is started over, as a sync would start it over (review of round 13, L-a).
        var state = verified ?? SyncState(vaultID: vaultID)
        let found =
            verified != nil
            ? [:] : await rowsLeftByEarlierIDs(in: vaultID, chain: chain, recorded: [:], account: account) ?? [:]
        let waiting = state.restoredUnpublished.filter { !Self.isDismissed($0.value) }.merging(found) { kept, _ in kept
        }
        guard !waiting.isEmpty || (raw != nil && verified == nil) else { return }
        // Kept, marked, rather than removed: so that the rows are not found again as left by an earlier ID while
        // they are its (`rowsLeftByEarlierIDs`), and the hold derived from them ends with this choice.
        for (key, left) in waiting {
            state.restoredUnpublished[key] = RecordStamp(version: Self.dismissedVersion, device: left.device)
        }
        _ = try requireKeys(since: epoch)
        try await syncState.saveState(state)
    }
}
