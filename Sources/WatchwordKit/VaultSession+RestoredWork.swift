import Foundation
import WatchwordCrypto
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
    /// both, as conflicts for the person to resolve, rather than losing either. Nor do the entries that state held for
    /// the IDs before it: those are found again from the vault's chain row (`RestoredChainRow`), the one an earlier
    /// attempt at this move wrote, bound to this device's ID, or the earlier ID's own, from its own restore, bound to
    /// that ID, and the rows those IDs left are recorded as `rowsLeftByEarlierIDs` would find them (review of round 17,
    /// Z225 and Z226: a retried move, or a second restore, otherwise lost the chain and the hold for those rows). The
    /// chain rows are read through sharing, so the move does not get here without it where it would read them
    /// (`moveAwaitsSharing`, Z229), and a row that cannot be read (the sharing store threw) throws, so that the move
    /// fails and is made again (Z181) rather than reading it as no row (review of round 19, Z236).
    func restoredWork(in vaultID: UUID, leftBy previous: UUID, account: AccountRecord, since epoch: UInt64)
        async throws -> [RecordKey: RecordStamp]
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
        let rows = try await store.records(in: vaultID, kind: .item)
        for row in rows where row.deviceID == previous {
            if let stamp = published[row.key], stamp >= RecordStamp(row) { continue }
            if restored[row.key] == nil { restored[row.key] = left(row.key) }
        }
        if earlier == nil {
            var chain = try await restoredChainRow(in: vaultID, account: account) ?? []
            chain.formUnion(try await restoredChainRow(in: vaultID, account: account, device: previous) ?? [])
            chain.subtract([account.deviceID, previous])
            restored.merge(rowsLeft(rows, in: vaultID, by: chain, recorded: restored)) { kept, _ in kept }
        }
        // Only deletions the account key signed (review of round 14, M1): one planted in the file (A8) would add an
        // entry for a row of another device's, and the carry would write that row's work of the earlier ID as this
        // device's.
        let parked = Self.parkedDeletionDevice(of: previous)
        let signingKey = try requireKeys(since: epoch).keyset.publicKeyBundle().signingKey
        for (key, deletion) in try await base.pendingDeletions(vaultID: vaultID)
        where key.kind == .item && (deletion.stamp.device == previous || deletion.stamp.device == parked)
            && Self.isSigned(deletion, as: key, in: vaultID, signingKey: signingKey)
        {
            if restored[key] == nil { restored[key] = left(key) }
        }
        return restored
    }

    /// Whether the move from `previous` would read a chain row and cannot (review of round 18, Z229): sharing, which
    /// keeps the rows, is not configured, and a vault that may be shared holds no state that verifies for this device's
    /// ID or for `previous` (none, or one lost, damaged or edited, A8), where `restoredWork` finds what the IDs before
    /// `previous` left only through the vault's chain rows (Z225, Z226). Made then, the move recorded nothing for those
    /// rows, saved a state that verifies and cleared its record, and nothing read the earlier ID's row again (the
    /// backfill reads only verified states, Z222), so the hold ended while the rows were on this device only (PRD
    /// F7.6). So the move waits, its record kept, publishing nothing (`deviceMigrationIncomplete`), until sharing is
    /// configured: `configureSharing` makes it, and so does the next unlock or sync after it. Only that case waits,
    /// and a shared vault with no state at all (one the earlier ID joined and never synced, or a first restore's state
    /// lost), where `restoredWork` would read the rows too (review of round 19, Z238): a vault whose state verifies,
    /// for this device's ID (a move made again over what an earlier attempt saved) or for `previous` (a first
    /// restore), needs no row (the state names the IDs before it, and the backfill writes this device's row from the
    /// state the move saves), so a process that never configures sharing (the AutoFill extension) still makes those
    /// moves, and leaves this one to the app (both checks are pinned, Z235). Nothing replaces the state while it
    /// waits: a download only stages, and nothing that may write a vault's sync state or chain row runs while a move
    /// is pending (the sync's writes need `mayWrite`, Stop Waiting is refused and the backfill waits, Z234).
    func moveAwaitsSharing(from previous: UUID, account: AccountRecord) async throws -> Bool {
        guard sharing.settings == nil, let base = syncSettings?.state else { return false }
        for vaultID in try await vaultDirectory(account).keys
        where isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID) {
            guard let raw = try await base.loadState(vaultID: vaultID) else { return true }
            if await verifiedSyncState(raw, vaultID: vaultID, deviceID: account.deviceID) != nil { continue }
            if await verifiedSyncState(raw, vaultID: vaultID, deviceID: previous) != nil { continue }
            return true
        }
        return false
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
    /// its own signed state recorded (`left.version`), the highest version of the record that ID's own stream carried,
    /// as the stream index and the staged segments of that stream show it (`publishedBound`, `staged`), and what the
    /// row, whose versions were judged, shows a third device saw of it (`ItemMerge.reattributed`); never what an
    /// unmerged, unjudged version of a third device claims (review of round 15, Z208). A backup older than the earlier
    /// ID's last publish, or a state lost with the restore, so renames none of what that ID published: renamed, it
    /// would have come back beside itself, its superseded values as conflicts and an item it deleted as one kept after
    /// the deletion.
    ///
    /// Run by `syncAll` for the vaults in `vaults`: those whose log this sync has pulled, after it, so that the stream
    /// index is the transport's and not the backup's; their pass published nothing, so that no merge of the rows
    /// still holding the earlier ID's work went out before it was carried. The carried rows go out at the next sync,
    /// ahead of any deletion. A step that fails keeps its entry for the next sync; meanwhile the deletion gate holds
    /// every deletion back while a row it names holds that work (`holdsRestoredWork`).
    ///
    /// `staged` is what the earlier IDs' own staged segments, downloaded and not merged yet, carry of each record
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
            // The keys of `epoch` and the vault's current key, read again after every suspension and never kept across
            // one (review of round 15, Z212): `lock()` zeroises them, and reading a zeroised key traps, so a lock that
            // lands during the carry must find it stopping, not crashing. `nil` once locked.
            func resident() -> (keys: UnlockedKeys, vaultKey: VaultKey)? {
                guard let keys = try? requireKeys(since: epoch),
                    let vaultKey = currentVaultKey(vaultID, keys: keys, account: account)
                else { return nil }
                return (keys, vaultKey)
            }
            guard resident() != nil, let deletions = try? await base.pendingDeletions(vaultID: vaultID) else {
                finished = false
                continue
            }
            guard let signingKey = try? resident()?.keys.keyset.publicKeyBundle().signingKey else { return false }
            var remaining: [RecordKey: RecordStamp] = [:]
            for (key, recorded) in state.restoredUnpublished {
                guard resident() != nil else { return false }
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
                guard let read = resident() else { return false }
                var keep = false
                if let row, row.vaultID == vaultID, let item = try? openItem(row, keys: read.keys),
                    reattributing ? Self.holds(item, row: row, workOf: left) : row.deviceID == left.device
                {
                    let carried =
                        reattributing
                        ? ItemMerge.reattributed(
                            item, origin: Self.origin(row), from: left.device, above: left.version, to: own) : item
                    do {
                        let revision = try nextRevision(in: vaultID, above: row, account: account)
                        let sealed = try sealItem(
                            ItemMerge.written(carried, as: revision), vaultKey: read.vaultKey, account: account)
                        _ = try requireKeys(since: epoch)
                        try await store.commit(
                            StoreChange(upserts: [sealed], expectations: [key: .version(row.version)]))
                        highestVersionSeen[vaultID] = max(highestVersionSeen[vaultID] ?? 0, revision.version)
                    } catch {
                        keep = true
                    }
                }
                // After the commit's suspension, the keys again.
                guard let erasing = resident() else { return false }
                if reattributing, let deletion = deletions[key], deletion.stamp.version < .max - 1,
                    deletion.stamp.device == own || deletion.stamp.device == parked,
                    Self.isSigned(deletion, as: key, in: vaultID, signingKey: signingKey),
                    let erased = try? openItem(deletion.record, keys: erasing.keys),
                    Self.holds(erased, row: deletion.record, workOf: left)
                {
                    do {
                        let rewritten = ItemMerge.reattributed(
                            erased, origin: Self.origin(deletion.record), from: left.device, above: left.version,
                            to: own)
                        let record = try sealItem(
                            ItemMerge.written(rewritten, as: Revision(version: deletion.record.version, device: own)),
                            vaultKey: erasing.vaultKey, account: account)
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
                continue
            }
            // The chain row after the save, which may have removed IDs (Z216); one left naming more is harmless.
            guard (try? requireKeys(since: epoch)) != nil else { return false }
            try? await noteRestoredChain(remaining, in: vaultID, account: account, keeping: false, since: epoch)
        }
        return finished
    }

    /// What the staged segments of `vaultID`'s log, downloaded and not merged yet, show each earlier ID published of
    /// the records a restore has still to carry there (`SyncState.restoredUnpublished`), per record and earlier ID:
    /// the highest version of the record that ID's own stream carried (`SyncEngine.stagedEntries`), which is what the
    /// stream index shows once those segments are merged, read before the merge (review of round 14, L1). Only that
    /// ID's own stream (review of round 15, Z208): a third device's version staged here has not been judged, and a
    /// member who may write (A4) could claim in one to have seen the earlier ID's work far beyond what it published,
    /// so that the carry found nothing to carry and dropped the entry, while every member's judge then held that
    /// claim aside. A shared vault keeps its whole log from the day it was shared, so whatever an honest third device
    /// saw of the earlier ID since then is in that ID's own segments, merged (the index) or staged (here);
    /// `ItemMerge.reattributed` still reads what a third device saw from the row, whose versions were judged. Not
    /// what an owner's device published while the vault was private: those segments may have been collected, under
    /// a snapshot, before it was shared (Z144, Z151), and no own segment shows them (review of round 16, Z218). With
    /// the earlier ID's signed state, its `published` covers them; without it (lost, or edited, A8, so that each entry
    /// reads as version 0) the carry writes that work again as this device's, and members hold it twice, as
    /// conflicts, never losing either (as `restoredWork` says). `nil` where the state or the stage cannot be read, or
    /// while locked: the carry then waits.
    func stagedBounds(in vaultID: UUID, engine: SyncEngine, since epoch: UInt64) async -> [RecordKey: [UUID: UInt64]]? {
        guard let syncState else { return [:] }
        let state: SyncState?
        do {
            state = try await syncState.loadState(vaultID: vaultID)
        } catch {
            return nil
        }
        let restored = (state?.restoredUnpublished ?? [:]).filter { !Self.isDismissed($0.value) }
        guard !restored.isEmpty else { return [:] }
        let earlier = Set(restored.values.map(\.device))
        guard let entries = try? await engine.stagedEntries(of: Set(restored.keys), authoredBy: earlier),
            (try? requireKeys(since: epoch)) != nil
        else { return nil }
        var bounds: [RecordKey: [UUID: UInt64]] = [:]
        for entry in entries where restored[entry.key]?.device == entry.device {
            bounds[entry.key, default: [:]][entry.device] = max(
                bounds[entry.key]?[entry.device] ?? 0, entry.version)
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
    /// (`AccountRecord.migration`), every ID an entry the person has not stopped waiting for names in a vault's state
    /// that verifies, and every ID a vault's chain row names (`RestoredChainRow`, review of round 16, Z216), which the
    /// move and each later save of those entries wrote, signed and bound to this device's ID. The row is what keeps
    /// the chain where a vault's state no longer verifies (damaged, or edited, A8): the hold then still fails closed,
    /// and the rows the chain's IDs left are found again and recorded (`rowsLeftByEarlierIDs`, Z200).
    ///
    /// Never from a state that does not verify. The chain was read from one (review of round 13, L-a), narrowed to IDs
    /// of this account's registry (L3, Z206) and then to those whose registration this device's own descends from
    /// (Z211); but a restored device registers from the registry it holds, so every sibling device enrolled before the
    /// restore still passed (Z216). Named there by A8, with the sibling's stream withheld (A1), its published work was
    /// recorded as left by an earlier ID and written again as this device's, and every member held it twice. Only the
    /// move can tell an earlier ID of this installation from a sibling, so the chain is what it recorded, signed.
    /// The row is filled in from each vault's verified state whenever sharing and the keys are both here
    /// (`backfillRestoredChains`, review of round 17, Z222). Without sharing configured there is no chain row, and
    /// where a vault's state does not verify the chain is then only a move still under way (`AccountRecord.migration`).
    ///
    /// The move's earlier ID only from a record this session signed (`migrationVerifies`, Z227), as every other source
    /// of the chain is now: an unsigned one planted in the database (A8) could only add to the hold, which fails safe,
    /// but it is no record of this installation's.
    ///
    /// Throws where a chain row could not be read (review of round 19, Z236): read as none, a sharing store that
    /// failed once beside a state that does not verify left the chain empty and the hold open. Every caller fails
    /// closed on it: the gate holds, and nothing is recorded or stopped. So it does where the vault directory or a
    /// vault's state could not be read (review of round 21, Z245): read as none, a listing that failed once left the
    /// chain without a row or a verified entry, and the hold of a shared vault whose damaged state left its chain row
    /// the only record of a restore's copy opened.
    ///
    /// The rows only of vaults that may be shared (review of round 20, Z239): only there does a restore record
    /// anything (`restoredWork`, `recordRestoredWorkLeft`), so only there is a row written, and a row read elsewhere
    /// (the Personal vault's, which never exists) let a sharing store that kept failing hold every deletion back for
    /// good. And it is asked only where a judgement needs it (`RestoredChainRead`): a vault that may be shared whose
    /// state does not verify, or that has none.
    func restoredChain(account: AccountRecord) async throws -> Set<UUID> {
        var chain: Set<UUID> = []
        if let migration = account.migration, let signingKey = await trustedAccountSigningKey(account),
            Self.migrationVerifies(migration, to: account, signingKey: signingKey)
        {
            chain.insert(migration.previousDeviceID)
        }
        guard let base = syncSettings?.state else { return chain }
        for vaultID in try await vaultDirectory(account).keys {
            if let raw = try await base.loadState(vaultID: vaultID),
                let verified = await verifiedSyncState(raw, vaultID: vaultID)
            {
                for left in verified.restoredUnpublished.values where !Self.isDismissed(left) {
                    chain.insert(left.device)
                }
            }
            guard isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID) else { continue }
            chain.formUnion(try await restoredChainRow(in: vaultID, account: account) ?? [])
        }
        chain.remove(account.deviceID)
        return chain
    }

    /// `restoredChain`, read the first time a judgement asks for it and kept for the rest of the caller's pass, so
    /// that the chain rows are read only where they can matter (review of round 20, Z239): for a vault that may be
    /// shared whose state does not verify, or that has none (`restoredEntries`, `recordRestoredWorkLeft`). A state
    /// that verifies is the record itself, and a vault that is not shared holds nothing a restore left, so neither
    /// reads a row, and a sharing store that cannot read one holds back only what depends on it.
    struct RestoredChainRead {
        /// The chain, once read.
        fileprivate(set) var chain: Set<UUID>?
        /// The chain could not be read: asked again, it stays unread for the rest of the pass.
        fileprivate(set) var failed = false
        /// What failed was a chain row (`RestoredChainRowUnreadable`), not the directory or a state (Z245), which the
        /// sync reports as it reports any other failed read.
        fileprivate(set) var rowUnreadable = false
        /// The vaults whose judgement asked for the chain while a row could not be read: each fails closed, and the
        /// sync says so (`AccountSyncReport.restoredChainUnreadable`).
        fileprivate(set) var unreadableFor: Set<UUID> = []
    }

    /// What `restoredChainRow` throws where the sharing store could not read `vaultID`'s chain row (Z236): the vault,
    /// so that a move that fails on it is reported (`AccountSyncReport.restoredChainUnreadable`, review of round 20,
    /// Z240), as every other wait on the row is.
    struct RestoredChainRowUnreadable: Error {
        let vaultID: UUID
    }

    /// The chain `read` holds, read now if it has not been: `nil` where it cannot be read (a row, the directory or a
    /// vault's state), and `vaultID` noted where a row could not.
    func restoredChain(_ read: inout RestoredChainRead, for vaultID: UUID, account: AccountRecord) async -> Set<UUID>? {
        if let chain = read.chain { return chain }
        if !read.failed {
            do {
                let chain = try await restoredChain(account: account)
                read.chain = chain
                return chain
            } catch {
                read.failed = true
                read.rowUnreadable = error is RestoredChainRowUnreadable
            }
        }
        if read.rowUnreadable { read.unreadableFor.insert(vaultID) }
        return nil
    }

    /// The earlier IDs `vaultID`'s chain row names (`RestoredChainRow`), if it verifies for this device's ID, or for
    /// `device` (the move's earlier ID, whose own row a second restore finds, Z226). `nil` where there is none, it
    /// does not verify, sharing is not configured (the move waits for sharing where it would read one,
    /// `moveAwaitsSharing`, Z229), or no trusted signing key is at hand. Throws what the sharing store threw (review of
    /// round 19, Z236): a row that could not be read is not one that is not there, and each caller fails closed on it.
    /// What it throws is `RestoredChainRowUnreadable`, naming the vault, so that a sync can say so (review of round
    /// 20, Z240).
    func restoredChainRow(in vaultID: UUID, account: AccountRecord, device: UUID? = nil) async throws -> Set<UUID>? {
        guard let settings = sharing.settings else { return nil }
        let stored: [UInt8]?
        do {
            stored = try await settings.state.value(.restoredChain, vaultID: vaultID)
        } catch {
            throw RestoredChainRowUnreadable(vaultID: vaultID)
        }
        guard let bytes = stored, let signingKey = await trustedAccountSigningKey(account) else { return nil }
        return RestoredChainRow.parse(
            bytes, device: device ?? account.deviceID, account: account.accountID, signingKey: signingKey,
            vaultID: vaultID)
    }

    /// Fills in each vault's chain row (`RestoredChainRow`) from the vault's state, where that state verifies and
    /// names an earlier ID, one the person has not stopped waiting for, that the row lacks: added to the row, never
    /// replacing it (review of round 17, Z222). The row is written only where sharing is configured and the keys are
    /// here, so a move made before `configureSharing`, a row write that failed, or a state from a build from before
    /// Z216 left a vault whose chain rested on its state alone, and once that state was damaged (or edited, A8) the
    /// hold failed open. Run when sharing is configured on an unlocked session, after each unlock, and at each sync
    /// that may write (`recordRestoredWorkLeft`). A state damaged before any of those since the move is still lost
    /// with its chain: no row can be signed while locked, and none is kept without sharing.
    ///
    /// A state is verified only where its raw form names an entry of another device the person has not stopped
    /// waiting for (review of round 18, Z230): one that verifies is the raw state, so a raw state naming none names
    /// none verified either, and the unlock the person waits on pays one load per vault, not a signature check of
    /// every state. The row is written adding to what it names (`keeping: true`): it may rightly name more than the
    /// state (the carry's and Stop Waiting's narrowing write after their saves is `try?`), and the state was read
    /// before the awaits that follow, so replacing the row could drop what a write since added. No case found makes
    /// the difference observable (Z231): defence in depth.
    ///
    /// Not while a move is pending (`account.migration`, review of round 19, Z234): nothing that may write a vault's
    /// sync state or chain row runs then. The move writes each vault's row itself, from what it records, before the
    /// state it saves, so the backfill has nothing to add until the next unlock, sync or `configureSharing` after it.
    func backfillRestoredChains(account: AccountRecord, since epoch: UInt64) async {
        guard account.migration == nil, sharing.settings != nil, let base = syncSettings?.state,
            (try? requireKeys(since: epoch)) != nil, let vaults = try? await vaultDirectory(account).keys
        else { return }
        let own = account.deviceID
        for vaultID in vaults.sorted(by: { $0.uuidString < $1.uuidString }) {
            guard let raw = try? await base.loadState(vaultID: vaultID),
                raw.restoredUnpublished.values.contains(where: { !Self.isDismissed($0) && $0.device != own }),
                let verified = await verifiedSyncState(raw, vaultID: vaultID)
            else { continue }
            var named = Set(verified.restoredUnpublished.values.filter { !Self.isDismissed($0) }.map(\.device))
            named.remove(account.deviceID)
            guard !named.isEmpty else { continue }
            guard !named.isSubset(of: (try? await restoredChainRow(in: vaultID, account: account)) ?? []) else {
                continue
            }
            guard (try? requireKeys(since: epoch)) != nil else { return }
            try? await noteRestoredChain(
                verified.restoredUnpublished, in: vaultID, account: account, keeping: true, since: epoch)
        }
    }

    /// Writes `vaultID`'s chain row (`RestoredChainRow`, Z216): the devices that `entries` (what a restore left there,
    /// as about to be saved, or just saved, in the vault's signed state) names and the person has not stopped waiting
    /// for, with those the row names already when `keeping` (a save that only adds, written before it, so that the
    /// row never names fewer IDs than the state), or exactly those (written after a save that may remove some), and
    /// no row when that is none. Every ID it names is an earlier ID of this installation: from the move, or read from
    /// a chain that names only those. Throws where the row could not be written; without sharing configured there is
    /// nothing to write (`restoredChain`). Signed with the keys of `epoch`, read again after the row's read.
    func noteRestoredChain(
        _ entries: [RecordKey: RecordStamp], in vaultID: UUID, account: AccountRecord, keeping: Bool,
        since epoch: UInt64
    ) async throws {
        guard let settings = sharing.settings else { return }
        var devices = Set(entries.values.filter { !Self.isDismissed($0) }.map(\.device))
        devices.remove(account.deviceID)
        // A keeping write that adds nothing could only put back the row it read: it reads none (review of round 20,
        // Z239), so that a row that cannot be read, of a vault where nothing was left (the Personal vault's, which
        // never exists), does not fail the move of every ordinary restore for as long as the sharing store fails.
        if keeping, devices.isEmpty { return }
        // A row that cannot be read throws (Z236): written without it, a keeping write would drop what it named.
        if keeping { devices.formUnion(try await restoredChainRow(in: vaultID, account: account) ?? []) }
        let keyset = try requireKeys(since: epoch).keyset
        let row =
            devices.isEmpty
            ? nil
            : try RestoredChainRow.signed(
                devices, device: account.deviceID, account: account.accountID, vaultID: vaultID, keyset: keyset)
        if !keeping || row != nil { try await settings.state.setValue(row, for: .restoredChain, vaultID: vaultID) }
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
        return rowsLeft(rows, in: vaultID, by: chain, recorded: recorded)
    }

    /// Of `rows` (`vaultID`'s items), those `rowsLeftByEarlierIDs` counts: still the row of an ID of `chain`, not named
    /// in `recorded`, holding that ID's work above what its stream carried here, each with version 0 for an entry.
    func rowsLeft(_ rows: [StoredRecord], in vaultID: UUID, by chain: Set<UUID>, recorded: [RecordKey: RecordStamp])
        -> [RecordKey: RecordStamp]
    {
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
    /// fails closed (review of round 13, L-a): the state could not be read, or the store, or, while the chain names an
    /// earlier ID, the vault (one that may be shared) holds a state that does not verify, which may have held entries.
    ///
    /// The chain is asked for (`chain`, read once for the caller's pass) only by a vault that may be shared whose state
    /// does not verify, or that has none: elsewhere it decides nothing (review of round 20, Z239). One that cannot be
    /// read fails closed there (Z236).
    func restoredEntries(in vaultID: UUID, chain: inout RestoredChainRead, account: AccountRecord) async
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
        if let verified { return verified.restoredUnpublished.filter { !Self.isDismissed($0.value) } }
        guard isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID) else { return [:] }
        guard let names = await restoredChain(&chain, for: vaultID, account: account) else { return nil }
        if raw != nil, !names.isEmpty { return nil }
        return await rowsLeftByEarlierIDs(in: vaultID, chain: names, recorded: [:], account: account)
    }

    /// Records what `rowsLeftByEarlierIDs` finds in each vault whose state is lost or does not verify as entries of a
    /// state this session signs, before any log of a sync, so that the take-out leaves those rows alone and the carry
    /// writes them (review of round 13, L-a): a state of a vault that may be shared that does not verify is started
    /// over while the chain names an earlier ID, as the engine would start it over, with those entries in it.
    ///
    /// First the chain rows are filled in from the states that verify (`backfillRestoredChains`, Z222), so that the
    /// row of a vault whose state is damaged later still names its earlier IDs.
    ///
    /// The chain only once a vault needs it, its state lost or not verifying (`RestoredChainRead`, review of round 20,
    /// Z239); one that cannot be read records nothing, and the gate holds for that vault.
    func recordRestoredWorkLeft(account: AccountRecord, since epoch: UInt64) async {
        guard let syncState, let base = syncSettings?.state else { return }
        await backfillRestoredChains(account: account, since: epoch)
        guard let vaults = try? await vaultDirectory(account).keys else { return }
        var read = RestoredChainRead()
        for vaultID in vaults where isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID) {
            let raw: SyncState?
            do {
                raw = try await base.loadState(vaultID: vaultID)
            } catch {
                continue
            }
            if let raw, await verifiedSyncState(raw, vaultID: vaultID) != nil { continue }
            guard let chain = await restoredChain(&read, for: vaultID, account: account), !chain.isEmpty else { return }
            guard let left = await rowsLeftByEarlierIDs(in: vaultID, chain: chain, recorded: [:], account: account),
                !left.isEmpty || raw != nil
            else { continue }
            var state = SyncState(vaultID: vaultID)
            state.restoredUnpublished = left
            // The chain row first, so that it never names fewer IDs than the state (Z216).
            guard (try? requireKeys(since: epoch)) != nil,
                (try? await noteRestoredChain(left, in: vaultID, account: account, keeping: true, since: epoch))
                    != nil,
                (try? requireKeys(since: epoch)) != nil
            else { return }
            guard (try? await syncState.saveState(state)) != nil, (try? requireKeys(since: epoch)) != nil else {
                continue
            }
            // Then exactly the state's IDs: with the carry and Stop Waiting, the one write that narrows the row (review
            // of round 18, Z232). It drops only IDs with no row left above their bound in the vault, and a row never
            // becomes an earlier ID's again.
            try? await noteRestoredChain(left, in: vaultID, account: account, keeping: false, since: epoch)
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
    func itemsHoldingRestoredWork(in vaultID: UUID, chain: inout RestoredChainRead, account: AccountRecord) async
        -> Set<UUID>?
    {
        guard let restored = await restoredEntries(in: vaultID, chain: &chain, account: account) else { return nil }
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
    func holdsRestoredWork(in vaultID: UUID, chain: inout RestoredChainRead, account: AccountRecord) async -> Bool {
        if await restoredWorkReleased(vaultID, account: account) { return false }
        guard let items = await itemsHoldingRestoredWork(in: vaultID, chain: &chain, account: account) else {
            return true
        }
        return !items.isEmpty
    }

    /// Per vault, the items holding what a restore left and has not carried, for the report: those that wait
    /// (`AccountSyncReport.restoredWorkWaiting`) and those that stay on this device only, their vault deleted or this
    /// account's membership of it ended (`restoredWorkKeptHere`, review of round 13, M3). Read while the keys of
    /// `epoch` are here; a lock meanwhile reports none (as `copiesNobodyReceived`, Z174).
    ///
    /// `mayStopWaiting` is the waiting vaults the person may stop waiting for (`mayStopWaitingForRestoredWork`), and
    /// `chainUnreadable` those whose hold rests on a chain row that could not be read (`RestoredChainRead`, review of
    /// round 20, Z240): they hold the deletions back and name no item, and the sync says why
    /// (`AccountSyncReport.restoredChainUnreadable`) rather than leaving the generic notice to.
    func restoredWorkWaiting(account: AccountRecord, since epoch: UInt64) async -> (
        waiting: [UUID: Set<UUID>], keptHere: [UUID: Set<UUID>], mayStopWaiting: Set<UUID>, chainUnreadable: Set<UUID>
    ) {
        guard let vaults = try? await vaultDirectory(account).keys else { return ([:], [:], [], []) }
        var chain = RestoredChainRead()
        var waiting: [UUID: Set<UUID>] = [:]
        var keptHere: [UUID: Set<UUID>] = [:]
        var mayStopWaiting: Set<UUID> = []
        var chainUnreadable: Set<UUID> = []
        for vaultID in vaults {
            let items = await itemsHoldingRestoredWork(in: vaultID, chain: &chain, account: account)
            let released = await restoredWorkReleased(vaultID, account: account)
            guard let keys = try? requireKeys(since: epoch) else { return ([:], [:], [], []) }
            if items == nil, !released, chain.unreadableFor.contains(vaultID) { chainUnreadable.insert(vaultID) }
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
        return (waiting, keptHere, mayStopWaiting, chainUnreadable)
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
    ///
    /// Refused while a restore's move is pending (`VaultError.deviceMigrationIncomplete`, review of round 19, Z234):
    /// the state it would start over is the one the move is about to read, and one saved signed for this device's ID
    /// reads as the move's own, begun, so the move would read no chain row and record nothing for what the IDs before
    /// the earlier one left (Z225, Z226). No notice offers the choice then (the sync that would may not write), but the
    /// call is public. Nothing that may write a vault's sync state or chain row runs while a move is pending.
    public func stopWaitingForRestoredWork(in vaultID: UUID) async throws {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let syncState, let base = syncSettings?.state else { throw VaultError.syncNotConfigured }
        await loadSharedVaultsIfNeeded()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        guard account.migration == nil else { throw VaultError.deviceMigrationIncomplete }
        // Only for a vault that will not open here (review of round 14, L2).
        guard mayStopWaitingForRestoredWork(in: vaultID, keys: try requireKeys(since: epoch), account: account) else {
            throw VaultError.restoredWorkCanBeCarried(vaultID)
        }
        let raw = try await base.loadState(vaultID: vaultID)
        var verified: SyncState?
        if let raw { verified = await verifiedSyncState(raw, vaultID: vaultID) }
        // A state that does not verify is started over, as a sync would start it over (review of round 13, L-a). The
        // chain only then, and only for a vault that may be shared, where it decides something (review of round 20,
        // Z239, and of round 21, Z248, as the gate reads it); one that cannot be read throws.
        var state = verified ?? SyncState(vaultID: vaultID)
        var found: [RecordKey: RecordStamp] = [:]
        if verified == nil, isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID) {
            let chain = try await restoredChain(account: account)
            found = await rowsLeftByEarlierIDs(in: vaultID, chain: chain, recorded: [:], account: account) ?? [:]
        }
        let waiting = state.restoredUnpublished.filter { !Self.isDismissed($0.value) }.merging(found) { kept, _ in kept
        }
        guard !waiting.isEmpty || (raw != nil && verified == nil) else { return }
        // Kept, marked, rather than removed: so that the rows are not found again as left by an earlier ID while
        // they are its (`rowsLeftByEarlierIDs`), and the hold derived from them ends with this choice.
        for (key, left) in waiting {
            state.restoredUnpublished[key] = RecordStamp(version: Self.dismissedVersion, device: left.device)
        }
        // Read again after the awaits: a registration as a new device since would have recorded a move (Z234).
        guard let current = try await store.loadAccount(), current.deviceID == account.deviceID,
            current.migration == nil
        else { throw VaultError.deviceMigrationIncomplete }
        _ = try requireKeys(since: epoch)
        try await syncState.saveState(state)
        // The chain row after the save, which may have removed IDs (Z216); one left naming more is harmless.
        _ = try requireKeys(since: epoch)
        try? await noteRestoredChain(
            state.restoredUnpublished, in: vaultID, account: account, keeping: false, since: epoch)
    }
}
