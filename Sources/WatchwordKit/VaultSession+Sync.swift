import Foundation
import SecureMemory
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordMatching
import WatchwordModel
import WatchwordStore
import WatchwordSync

// Sync (PRD F7, docs/02-architecture.md §7): the production `SyncKeyring` and `ItemSealer` are this session, because
// they need the keys it holds and must lose them when it locks.
extension VaultSession {
    public nonisolated var isSyncConfigured: Bool {
        syncSettings != nil
    }

    /// Syncs the account and every vault (`syncAll`), and returns the vaults' reports added up: what a caller that
    /// shows one line about the last sync needs.
    @discardableResult
    public func sync(reconcile: Bool = false) async throws -> SyncReport {
        try await syncAll(reconcile: reconcile).combined
    }

    /// One sync of everything (docs/02-architecture.md §7.5–§7.8):
    ///
    /// 1. The account's own objects: device registry entries in both directions, this device's account header and
    ///    any header for a password changed elsewhere, and the vault directory (vault keys and vault deletions).
    /// 2. Every vault's log (`SyncEngine.sync`), deleted vaults included, so that what a deletion had not seen
    ///    still arrives.
    ///
    /// While locked only downloads run, with every signature checked against the registry and the account key kept
    /// in the Keychain; each report's `deferredUntilUnlock` says so (§7.4). The same holds, unlocked, while this
    /// device is not registered, has been revoked, or has seen a password change it has not been given yet: it
    /// downloads, and neither merges nor publishes.
    ///
    /// A sync never uploads again what a reset removed from the store (§7.10): it stops at a store that was reset or
    /// emptied (`transportFailure` is `storeReset`), and in a store another device has started again it publishes new
    /// edits only. The report says when the person should be asked (`AccountSyncReport.storeNeedsReupload`); only
    /// `reuploadAfterStoreReset(confirming:)`, which a screen calls on their answer, uploads.
    @discardableResult
    public func syncAll(reconcile: Bool = false) async throws -> AccountSyncReport {
        guard syncSettings != nil else { throw VaultError.syncNotConfigured }
        guard try await loadAccount() != nil else { throw VaultError.noAccount }
        guard !syncInFlight else { throw SyncError.syncInProgress }
        syncInFlight = true
        defer { syncInFlight = false }
        return try await runSync(reconcile: reconcile, reuploadingSince: nil)
    }

    /// One sync, for a caller that holds `syncInFlight`. `reuploadingSince` is the lock epoch of the person's
    /// confirmed answer to a reset and comes from `reuploadAfterStoreReset(confirming:)` alone; it counts only while
    /// the vault is unlocked at that epoch (`reuploadAnswered`, SR21): the account's objects are published into a store
    /// that holds none of them, and every vault's engine hands on what it holds that the store lacks.
    func runSync(reconcile: Bool, reuploadingSince epoch: UInt64?) async throws -> AccountSyncReport {
        guard let syncSettings, syncState != nil else { throw VaultError.syncNotConfigured }
        guard var record = try await loadAccount() else { throw VaultError.noAccount }
        var report = AccountSyncReport()
        registryView = nil

        do {
            try await startRegistryIfAccountPredatesIt(account: record, transport: syncSettings.transport)
            report.account = try await syncAccountObjects(
                account: record, transport: syncSettings.transport, reuploadingSince: epoch)
        } catch let error as SyncTransportError where error.stopsSync {
            report.transportUnavailable = true
            report.transportFailure = report.transportFailure ?? error
        } catch SyncKeyringError.locked {
            // Locked while vouching for the directory: the rest of the sync is a download.
        }
        // Which vaults are shared, before any vault's key is picked or its engine set up (V31).
        await loadSharedMarkersIfNeeded()
        // A move of an earlier device ID's sync state that an unlock could not finish is tried again; until it is
        // complete this device publishes nothing, since the move starts each vault's state over (Z181).
        if keys != nil, record.migration != nil {
            do {
                try await completeDeviceMigration(account: record)
            } catch let unreadable as RestoredChainRowUnreadable {
                // A chain row the move needs and cannot read: said, since it lasts as long as the sharing store fails
                // (review of round 20, Z240).
                report.restoredChainUnreadable.insert(unreadable.vaultID)
            } catch {}
            record = try await loadAccount() ?? record
        }
        report.deviceMigrationIncomplete = record.migration != nil
        // A device whose registration no longer counts registers again, now that it has seen why. A store restored
        // onto other hardware whose registration did not happen at the unlock (one was already under way then, or it
        // failed) registers as a new device here, as the next unlock would (review of round 13, L-b).
        if let keys, let view = try? await registry(record), view.state.pendingCredentials.isEmpty,
            !(await passwordChangePending(record))
        {
            if record.migration == nil, await ownDeviceKey(of: record) == .absent {
                try? await registerThisDevice(account: record, keys: keys, asNewDevice: true)
                record = try await loadAccount() ?? record
            } else if view.state.standing(of: record.deviceID) == .unknown {
                try? await registerThisDevice(account: record, keys: keys, asNewDevice: false)
                record = try await loadAccount() ?? record
            }
        }
        report.deviceMigrationIncomplete = record.migration != nil

        let view = try? await registry(record)
        let standing = view?.state.standing(of: record.deviceID)
        report.deviceStanding = standing
        // The registry's pending entries, and what the Keychain remembers of one whose rows the file has lost (Z3).
        let changePending = await passwordChangePending(record)
        report.awaitingNewPassword = changePending || !(view?.state.pendingCredentials.isEmpty ?? true)
        report.registryUnavailable = view == nil
        // Only for an ID this installation can sign as, and with no registration under way (review of round 22, Z253):
        // `record` was read before the awaits above, and an unlock that installs the keys during them may be
        // registering this restored store as a new device, which turns this sync's own registration away and leaves
        // `record` naming the earlier ID, still active, with no move recorded. Decided on that, a sync begun locked ran
        // every writer step under the earlier ID while the unlock committed the new one and made the move, and the
        // engines' saves, signed for the new ID, lost the move's record of a restore's copy (PRD F7.6). A restored
        // store holds no key for its earlier ID and never gets one back (`createDevice` makes the new ID's, in the
        // account's one slot), so it only downloads; a registration as the same ID changes neither the ID nor the
        // move. Read after the last await before the decision, with the keys and the flag read after it.
        let ownKey = await ownDeviceKey(of: record)
        let mayWrite =
            keys != nil && ownKey == .held && !registrationInFlight && standing == .active
            && !report.awaitingNewPassword && !report.deviceMigrationIncomplete
        // Not `epoch`, the person's answer to a reset (§7.10), which this must not shadow: named alike, every sync
        // handed on as though the person had said yes (found by the reset suites at the second merge, V45). PR #23's
        // `syncAll` names this `epoch`, having no reset answer; merged here as `keysEpoch` throughout.
        let keysEpoch = lockEpoch
        // Unlocked, and download-only for this device's own key alone: said as such, never "when you unlock" to a
        // person whose vault is open (review of round 23, Z264). A move pending is a reason of its own, said by
        // `deviceMigrationIncomplete`, and leaves this `nil`; a store that was reset (§7.10) is said beside it, since
        // the key holds the upload back too (V70), and a reset only suspected (V52) is asked about by the next sync
        // that may write.
        if keys != nil, standing == .active, !report.awaitingNewPassword, !report.deviceMigrationIncomplete {
            switch ownKey {
            case .unreadable: report.ownDeviceKeyWait = .unreadable
            case .absent: report.ownDeviceKeyWait = .registering
            case .held: if registrationInFlight { report.ownDeviceKeyWait = .registering }
            }
        }
        // Unlocked, and download-only for a move of this installation's sync records that is incomplete: said as such,
        // never "when you unlock" (found merging round 24 into PR #22, Z271, as Z264 for the key).
        report.movePendingWhileUnlocked = keys != nil && report.deviceMigrationIncomplete
        // What this sync's engines, its carry and its re-record may save of a vault's state, decided here with
        // `mayWrite` and checked again as each state or stash is signed (V66, the same mechanism as PR #23's Z253):
        // only while the lock epoch, the device ID and the absence of a move are still the ones it began with. A sync
        // begun locked saves nothing even once an unlock lands during it, which may register a new device ID and
        // record, or make, the move: a state it loaded before then, signed for the new ID, was read by a waiting move
        // as one it had begun, or replaced the state the move had just saved.
        let stateWrites = SyncStateWrites(deviceID: record.deviceID, epoch: keysEpoch, permitted: mayWrite)
        let engineState = AuthenticatedSyncState(base: syncSettings.state, session: self, writes: stateWrites)
        // Deletions an earlier ID of this installation made, parked while a shared vault holds an edit of that ID that
        // nobody received, go out once none remains; until then they are reported held back (Z167).
        if mayWrite {
            report.deletionsHeldBack.formUnion(
                await releaseParkedDeletions(account: record, view: view, within: stateWrites))
        }
        let ownDevices: Set<UUID> = view.map { Set($0.state.devices.keys) } ?? []
        // A device whose ID does not commit to its account publishes nothing in a shared vault, and says so (Z162).
        // A key that could not be read is not one that does not commit: nothing is published there, and it is reported
        // as a failure to retry, never as a reason to enrol again.
        let ownIDCommits: Bool
        var deviceKeyUnreadable = false
        do {
            ownIDCommits = try await thisDeviceCommits(record)
        } catch {
            ownIDCommits = false
            deviceKeyUnreadable = true
        }

        let adapter = VaultSyncAdapter(session: self)
        let merger = KindRoutingMerger([
            .item: ItemRecordMerger(sealer: adapter, deviceID: record.deviceID),
            .vaultMetadata: VaultMetadataMerger(sealer: adapter),
            .scanStatus: ScanStatusMerger(sealer: adapter),
        ])
        // What a restore left that no entry records any more, recorded again before the take-out and any log
        // (review of round 13, L-a). A vault where that could not be told or done merges nothing in this sync, as one
        // whose carry did not finish (review of round 22, Z254); `nil` for every vault that may be shared.
        var unrecorded: Set<UUID>? = []
        if mayWrite {
            unrecorded = await recordRestoredWorkLeft(account: record, since: keysEpoch, within: stateWrites)
        }
        func reRecordFailed(_ vaultID: UUID) -> Bool {
            guard let unrecorded else {
                return isMarkedShared(vaultID, keys: keys, personalVaultID: record.personalVaultID)
            }
            return unrecorded.contains(vaultID)
        }
        // Shared vaults: membership, keys and what no longer counts, before any log (VaultSession+SharingSync.swift).
        // Not at a store that was reset: the pass publishes this device's proposals, and nothing is published there
        // before the person has answered (§7.10).
        var sharingReports: [UUID: SharedVaultSyncReport]
        if report.transportFailure == .storeReset {
            await loadSharedVaultsIfNeeded()
            sharingReports = sharing.vaults.mapValues { _ in
                var stopped = SharedVaultSyncReport()
                stopped.transportFailure = .storeReset
                return stopped
            }
        } else {
            sharingReports = await syncSharedVaultsBeforeLogs(account: record, writing: mayWrite)
        }
        if !ownIDCommits {
            for vaultID in sharing.vaults.keys {
                if deviceKeyUnreadable {
                    sharingReports[vaultID, default: SharedVaultSyncReport()].deviceKeyUnreadable = true
                } else {
                    sharingReports[vaultID, default: SharedVaultSyncReport()].deviceIDDoesNotCommit = true
                }
            }
        }
        func engine(_ vaultID: UUID) -> SyncEngine {
            let shared = sharedEngineOptions(
                vaultID, base: syncSettings.configuration, account: record, ownDevices: ownDevices,
                ownIDCommits: ownIDCommits)
            return SyncEngine(
                vaultID: vaultID, deviceID: stateWrites.deviceID, store: store, syncState: engineState,
                transport: syncSettings.transport, keyring: adapter, merger: merger,
                configuration: shared.configuration, judge: shared.judge)
        }
        // Deletions go out last, and only once everything else this device wrote is on the transport, in every
        // vault: a move is a copy in one vault's log and a deletion in another's, and the deletion must never reach
        // other devices without the copy (PRD F7.6, F7.7; docs/02-architecture.md §7.7).
        var deferred: [UUID] = []
        var restPublished = true
        // The first failure that stops a sync stops this one: the vaults after it merge what they hold and do not ask
        // the transport again (a throttled store asked once per vault would only throttle longer).
        var stopped = report.transportFailure ?? sharingReports.values.lazy.compactMap(\.transportFailure).first
        // The vaults holding what a restore has still to carry over: they publish nothing in this sync, and carry it
        // after their log (review of round 13, M2).
        var carrying: Set<UUID> = []
        // Of those, the vaults whose carry did not run or finish in this sync: nothing is merged into them, the
        // replay pass included, until it has (review of round 15, Z209).
        var uncarried: Set<UUID> = []
        // The shared vaults whose take-out is owed (`takeOutsOwed`: it began for a judged basis and did not finish,
        // Z262) as their first pass runs: that pass publishes nothing, since what this device holds there may still be
        // built on a write the take-out is to take out, and every other device would hold such a version aside (S44);
        // the replay's take-out, or the next sync's, decides. Not to wedge: only a take-out that finishes ends it, and
        // every sync that may write and reaches the take-out runs one (review of round 24, Z270; a disputed vault and
        // a sync a transport failure stops skip it, and neither publishes, Z277).
        var owedUnpublished: Set<UUID> = []
        // The vaults where a pass of this sync ran publishing (`publishing: true`), first pass or replay: what
        // `takeOutUnfinishedSentNothing` leaves out (Z273). Not `owedUnpublished`, which on this branch also names a
        // vault found owed only at its replay, whose first pass may have published (merged so at round 26).
        var publishedIn: Set<UUID> = []
        for vaultID in try await vaultDirectory(record).keys.sorted(by: { $0.uuidString < $1.uuidString }) {
            var vaultReport: SyncReport
            var ranPublishing = false
            let shared = sharedEngineOptions(
                vaultID, base: syncSettings.configuration, account: record, ownDevices: ownDevices,
                ownIDCommits: ownIDCommits)
            let owed = sharing.vaults[vaultID] != nil && takeOutsOwed.contains(vaultID)
            if mayWrite, let keys, currentVaultKey(vaultID, keys: keys, account: record) != nil {
                let requests = sharedReplayRequests(vaultID)
                var reconciled = reconcile || shared.reconcile
                let unrecordedHere = reRecordFailed(vaultID)
                let carryPending = unrecordedHere ? true : await restoredWorkToCarry(in: vaultID)
                if carryPending {
                    // What a restore left, carried once the vault's log has been pulled since it, so that what the
                    // earlier device ID published is known (review of round 13, M2), and before anything pulled is
                    // merged into it, so that the pulled versions are merged into the renamed version as every other
                    // device merges them (review of round 14, L1); and before a replay (whose take-out leaves these
                    // rows alone, `takeOutWhatNoLongerCounts`). The bound is the earlier ID's own stream, as the stream
                    // index and its downloaded segments show it (`stagedBounds`, Z208). Published at the next sync;
                    // meanwhile the hold below keeps every deletion back. A carry that cannot run, or does not finish,
                    // merges nothing into the vault in this sync, in any pass (Z209): what was downloaded stays staged
                    // for the next. So does a vault whose state does not verify and where what a restore left could
                    // not be recorded again (Z254), which has nothing recorded to carry yet.
                    carrying.insert(vaultID)
                    let pulled = try await engine(vaultID).download(transportStopped: stopped)
                    // What this download refused or left for its copies is where the carry stops counting the
                    // earlier ID's stream as published (V58).
                    noteCopyStops(pulled, in: vaultID)
                    var carried = false
                    if !unrecordedHere, stopped == nil, !pulled.transportUnavailable, pulled.transportFailure == nil,
                        let staged = await stagedBounds(in: vaultID, engine: engine(vaultID), since: keysEpoch)
                    {
                        carried = await carryRestoredWork(
                            account: record, view: view, since: keysEpoch, in: [vaultID], staged: [vaultID: staged],
                            engine: engine(vaultID), within: stateWrites)
                    }
                    if carried {
                        let merged = try await engine(vaultID).sync(
                            reconcile: reconciled, deferringDeletions: true, publishing: false,
                            transportStopped: stopped)
                        vaultReport = Self.report(pulled, followedBy: merged)
                        noteCopyStops(vaultReport, in: vaultID)
                    } else {
                        vaultReport = pulled
                        reconciled = false
                        uncarried.insert(vaultID)
                    }
                } else {
                    if owed, shared.publishing { owedUnpublished.insert(vaultID) }
                    vaultReport = try await engine(vaultID).sync(
                        reconcile: reconciled, deferringDeletions: true, publishing: shared.publishing && !owed,
                        transportStopped: stopped, handingOn: reuploadAnswered(epoch))
                    noteCopyStops(vaultReport, in: vaultID)
                    ranPublishing = shared.publishing && !owed
                    if ranPublishing { publishedIn.insert(vaultID) }
                }
                // A replay the engine did not begin (the store was reset, §7.10) settles nothing.
                await sharedEngineDidRun(
                    vaultID, reconciled: reconciled && !vaultReport.replayPostponed, judgedAgainst: shared.head,
                    report: vaultReport, requestsBefore: requests)
                // Entries a shared vault's earlier version could not read are readable now: replayed with the judge
                // in this sync (ADR 0009), as its log is whole.
                if vaultReport.replayNeeded { sharing.vaults[vaultID]?.needsReconcile = true }
                if vaultReport.deletionsDeferred > 0 { deferred.append(vaultID) }
                if let conflict = vaultReport.ownStreamConflict, sharing.vaults[vaultID] != nil {
                    sharingReports[vaultID, default: SharedVaultSyncReport()].ownStreamSquattedBy =
                        await ownStreamSigner(at: conflict, in: vaultID, account: record)
                }
                if vaultReport.transportUnavailable || vaultReport.deferredUntilUnlock
                    || vaultReport.ownStreamConflict != nil || vaultReport.ownStreamExhausted
                    || vaultReport.ownStreamUnverified != nil
                {
                    restPublished = false
                }
            } else {
                // While a move to a new device ID is under way the download saves no state: where none verifies for
                // the new ID it would save one started over, and the move would read it as begun, recording nothing of
                // the earlier IDs' work (V60). The move starts every state over anyway. Nor does a sync that did not
                // begin as a writer (`mayWrite`: locked, or for an ID this installation holds no key for, or while a
                // registration is under way, Z253), nor one whose start the lock epoch, the device ID or a move
                // recorded since no longer matches (V66): decided at the start and checked again as the state is
                // signed (`SyncStateWrites`). What it examined of copies is examined again by the next sync that may
                // write, which is all this costs.
                vaultReport = try await engine(vaultID).download(
                    transportStopped: stopped, savingState: stateWrites.permitted)
                noteCopyStops(vaultReport, in: vaultID)
                vaultReport.deferredUntilUnlock = true
            }
            // A vault may hold the copy half of a move that this sync did not publish: it is not published to (this
            // account may not write there now, or it is shared with no ledger here), or the copy was taken out and
            // held aside before it went out. While any vault holds an item that exists nowhere else, no vault's
            // deletions go out (Z44). A vault that published nothing for an owed take-out is asked after its replay,
            // or held below (Z270).
            if restPublished, mayWrite, !owedUnpublished.contains(vaultID),
                await holdsUnpublishedWork(in: vaultID, account: record, publishing: ranPublishing)
            {
                restPublished = false
                report.deletionsHeldBack.insert(vaultID)
            }
            if stopped == nil, let failure = vaultReport.transportFailure, failure.stopsSync { stopped = failure }
            vaultReport.deviceRevoked = standing == .revoked
            vaultReport.deviceNotRegistered = standing == .unknown
            vaultReport.awaitingNewPassword = report.awaitingNewPassword
            report.vaults[vaultID] = vaultReport
        }
        // A shared vault's second replay, before any deletion goes out: its take-out can put a move's copy aside,
        // and a replay defers deletions like any other pass (review finding Z55).
        var takeOutFailed: Set<UUID> = []
        if mayWrite, stopped == nil {
            for vaultID in sharedVaultsNeedingReplay() {
                guard let first = report.vaults[vaultID], !first.deferredUntilUnlock else { continue }
                // A vault whose carry did not finish merges nothing in this sync, a replay no more than the first pass
                // (Z209): the pulled versions would be merged into rows still holding the earlier ID's work, and the
                // carry would rename after the merge (L1). Its replay stays asked for (`needsReconcile`), for the sync
                // whose carry finishes.
                guard !uncarried.contains(vaultID) else { continue }
                do {
                    try await prepareSharedReplay(vaultID)
                } catch {
                    // A take-out that did not finish: no replay in this sync, which would settle what it had still to
                    // take out, and no deletion goes out after what it may have put aside (review of round 23, Z262;
                    // held below). The replay stays asked for (`needsReconcile`), for the next sync.
                    sharingReports[vaultID, default: SharedVaultSyncReport()].failure = String(describing: error)
                    takeOutFailed.insert(vaultID)
                    continue
                }
                let shared = sharedEngineOptions(
                    vaultID, base: syncSettings.configuration, account: record, ownDevices: ownDevices,
                    ownIDCommits: ownIDCommits)
                let requests = sharedReplayRequests(vaultID)
                // A take-out that returned with nothing decided (no basis could be worked out, `judgedBasis`) leaves
                // it owed: this replay publishes nothing either, as the first pass did not (Z270), and the vault is
                // held below (review of round 25, Z276). Merged so at round 25, for every publishing pass of this
                // branch's `runSync`: the first, which hands on after a reset (`handingOn`), and this one, postponed or
                // not (`replayPostponed`).
                let owedStill = takeOutsOwed.contains(vaultID)
                let replayPublishing = shared.publishing && !carrying.contains(vaultID) && !owedStill
                if owedStill, shared.publishing { owedUnpublished.insert(vaultID) }
                let second = try await engine(vaultID).sync(
                    reconcile: true, deferringDeletions: true, publishing: replayPublishing)
                noteCopyStops(second, in: vaultID)
                if replayPublishing { publishedIn.insert(vaultID) }
                // A replay the engine did not begin (the store was reset, §7.10) settles nothing.
                await sharedEngineDidRun(
                    vaultID, reconciled: !second.replayPostponed, judgedAgainst: shared.head, report: second,
                    requestsBefore: requests)
                if second.deletionsDeferred > 0, !deferred.contains(vaultID) { deferred.append(vaultID) }
                if second.transportUnavailable || second.ownStreamConflict != nil || second.ownStreamExhausted
                    || second.ownStreamUnverified != nil
                {
                    restPublished = false
                }
                if restPublished, !owedStill,
                    await holdsUnpublishedWork(in: vaultID, account: record, publishing: replayPublishing)
                {
                    restPublished = false
                    report.deletionsHeldBack.insert(vaultID)
                }
                report.vaults[vaultID] = Self.report(first, followedBy: second)
            }
        }
        // A vault whose replay's take-out threw (Z262), or that published nothing for an owed take-out and whose
        // take-out has not finished in this sync either (no replay ran for it, or the replay's take-out threw, Z270):
        // no deletion goes out after what the take-out may have put aside, or this device holds there unpublished,
        // and the vault is named (Z268).
        for vaultID in owedUnpublished.union(takeOutFailed) where takeOutsOwed.contains(vaultID) {
            restPublished = false
            report.takeOutUnfinished.insert(vaultID)
            // No pass of this sync published there (an owed first pass and replay publish nothing, Z270, Z276): its
            // changes wait. A vault whose first pass was not owed may have published before its replay's take-out
            // failed (review of round 25, Z273), and one found owed only at its replay too.
            if !publishedIn.contains(vaultID) { report.takeOutUnfinishedSentNothing.insert(vaultID) }
        }
        if restPublished {
            for vaultID in deferred {
                guard let first = report.vaults[vaultID] else { continue }
                let last = try await engine(vaultID).sync()
                noteCopyStops(last, in: vaultID)
                report.vaults[vaultID] = Self.report(first, followedBy: last)
            }
        }
        if mayWrite, stopped == nil {
            await syncSharedVaultsAfterLogs(account: record, reports: &sharingReports)
        }
        // The copies that hold every deletion back, by item, for the screen to name (Z171), while the keys this sync
        // started with are still here (Z174).
        if mayWrite, let view, (try? requireKeys(since: keysEpoch)) != nil {
            report.copiesNobodyReceived = await copiesNobodyReceived(
                account: record, view: view, since: keysEpoch, otherwise: Array(report.vaults.keys))
            report.deletionsHeldBack.formUnion(report.copiesNobodyReceived.keys)
        }
        if mayWrite, (try? requireKeys(since: keysEpoch)) != nil {
            let restored = await restoredWorkWaiting(account: record, since: keysEpoch)
            report.restoredWorkWaiting = restored.waiting
            report.restoredWorkKeptHere = restored.keptHere
            report.restoredWorkMayStopWaiting = restored.mayStopWaiting
            report.restoredChainUnreadable.formUnion(restored.chainUnreadable)
            report.deletionsHeldBack.formUnion(report.restoredWorkWaiting.keys)
            report.deletionsHeldBack.formUnion(restored.chainUnreadable)
            // The vaults whose publishing waits for the carry, and will wait again at the next sync (L4).
            for vaultID in carrying {
                let held = reRecordFailed(vaultID) ? true : await restoredWorkToCarry(in: vaultID)
                if held { report.publishingHeldForCarry.insert(vaultID) }
            }
        }
        report.sharing = sharingReports
        // What the merges changed is shown to the hygiene engine now, not only at its next query (§13.8).
        try? await reconcileHygiene()
        return report
    }

    /// The items of each shared vault that hold an edit nobody received (`itemsHoldingEdits`), for the report
    /// (`AccountSyncReport.copiesNobodyReceived`, Z171). Read while the keys of `epoch` are here: a row that does not
    /// open counts, so after a lock every item would be named; a lock during the scan reports none (review of round 9,
    /// Z174). The vaults are the directory's, or `otherwise` (the vaults the sync ran) where it cannot be read now: a
    /// report that names too few is better than none, and the gate decided by itself (Z175).
    func copiesNobodyReceived(account: AccountRecord, view: RegistryView, since epoch: UInt64, otherwise: [UUID])
        async -> [UUID: Set<UUID>]
    {
        let nobodyReceived = Self.idsNobodyReceives(account: account, view: view)
        guard !nobodyReceived.isEmpty else { return [:] }
        let vaults = (try? await vaultDirectory(account)).map { Array($0.keys) } ?? otherwise
        var copies: [UUID: Set<UUID>] = [:]
        for vaultID in vaults {
            let items = await itemsHoldingEdits(of: nobodyReceived, in: vaultID, account: account)
            guard (try? requireKeys(since: epoch)) != nil else { return [:] }
            guard let items, !items.isEmpty else { continue }
            copies[vaultID] = items
        }
        return copies
    }

    /// Whether `vaultID` holds an item that exists nowhere but on this device: one it created, of which the sync layer
    /// has neither published nor merged any version, in the vault, or taken out of it by this device and held aside
    /// (a copy made before this device was shown the record that ended its account's permission to write). The
    /// other half of such an item may be a deletion in another vault. Not every row this device sealed: the result of
    /// a merge is its row too, in a vault it only reads, and holds nothing the others lack. And not every held-aside
    /// entry that names this device: that is its writer's claim, which a member who can have this device hold
    /// something aside would use to hold its deletions back everywhere (review finding Z54). Only what the take-out
    /// itself put aside counts (`SharedVault.ownTakenOut`, signed in a row of its own), for as long as the quarantine
    /// still keeps it: once the person has discarded it, it is theirs to have discarded.
    ///
    /// Fails closed (review finding Z121): a quarantine that cannot be read holds the deletions back and forgets
    /// nothing of the set, and while the set's own row has not loaded (deleted, refused, never written by this build)
    /// every held-aside entry naming this device that the sync state does not know counts, as before Z54, until the
    /// quarantine holds none and the set is known to be all there is.
    /// Whether `row`, this device's, holds an edit of its own above every version of the record it published: its
    /// clock's entry for this device (`ItemMerge.effectiveClock`), never merely that it sealed the row. One that does
    /// not open here counts.
    func holdsUnpublishedEdit(_ row: StoredRecord, published: RecordStamp?, account: AccountRecord) -> Bool {
        holdsEdit(of: account.deviceID, in: row, above: published?.version ?? 0)
    }

    /// Whether `row` holds an edit of `deviceID` above `version`: its clock's entry for that device
    /// (`ItemMerge.effectiveClock`). One that does not open here counts.
    func holdsEdit(of deviceID: UUID, in row: StoredRecord, above version: UInt64 = 0) -> Bool {
        guard let keys, let item = try? openItem(row, keys: keys) else { return true }
        return (ItemMerge.effectiveClock(item, origin: Self.origin(row)).entries[deviceID] ?? 0) > version
    }

    /// Whether `row` holds a value written by any of `deviceIDs`, opening it once: a value of `ItemMerge.attributedValues`
    /// (history entries included) whose stamp names one of them. One that does not open here counts.
    ///
    /// By values, never by the clock (review of round 9, Z173): a clock entry, or a stamp's `seen`, is its writer's
    /// claim, and a writing member (A4) can publish a version that claims to have seen edits of any ID, which no judge
    /// asks about when no account lists that ID as counted. A value stamped by such an ID, from another account's
    /// stream, is held aside by the judge (it is attributed to the stream of the device its stamp names, which counts
    /// nowhere), so only this account's own writes, made here or carried over, hold one in a row.
    func holdsValue(ofAny deviceIDs: Set<UUID>, in row: StoredRecord) -> Bool {
        guard let keys, let item = try? openItem(row, keys: keys) else { return true }
        return ItemMerge.attributedValues(item, origin: Self.origin(row)).contains {
            deviceIDs.contains($0.revision.device)
        }
    }

    /// Whether `row`, which holds an edit of this device's above what it published, waits only behind `deletion`, this
    /// device's own pending deletion of the same record, so that it is no work existing nowhere else: the outbox sends
    /// a version written after a deletion right behind its tombstone, and holds both while deletions are deferred.
    ///
    /// Where this sync publishes the vault (`publishing`), always: both go out in its deferred pass. Counted, the
    /// deletion waited for the row and the row for the deletion, for good (V44, found by the long vault simulation).
    /// Anywhere else only a version that holds nothing of this device's that neither the deletion nor what it published
    /// had seen: its clock's entry for this device is at most the highest of the deleted version's, the tombstone's own
    /// revision, which a version kept after the deletion carries as the deletion's write (`ItemMerge.settle`), and the
    /// version of the record this device published (`published`). That is Z202's bound (`clock[own] ≤ max(published,
    /// d)`, found by the restore step of the vault simulation, review of round 13: holding the deletion for such a
    /// version held both for good once another device's tombstone of the record had arrived) and V46's in one. A kept
    /// version restored from the trash and edited holds an edit the deletion never saw, and in a vault this sync does
    /// not publish it holds every other vault's deletions back like any unpublished edit (review of the first merge,
    /// L2; V46). One that does not open here waits for nothing but counts.
    func waitsOnlyBehind(
        _ deletion: PendingDeletion, row: StoredRecord, published: RecordStamp?, account: AccountRecord,
        publishing: Bool
    ) -> Bool {
        if publishing { return true }
        guard let keys, let deleted = try? openItem(deletion.record, keys: keys),
            let held = try? openItem(row, keys: keys)
        else { return false }
        let device = account.deviceID
        var seen = ItemMerge.effectiveClock(deleted, origin: Self.origin(deletion.record)).entries[device] ?? 0
        if deletion.stamp.device == device { seen = max(seen, deletion.stamp.version) }
        seen = max(seen, published?.version ?? 0)
        return (ItemMerge.effectiveClock(held, origin: Self.origin(row)).entries[device] ?? 0) <= seen
    }

    /// `publishing`: this sync publishes the vault (its engine ran unlocked, may write there, and is carrying nothing
    /// a restore left there, Z204), so that a version waiting only behind this device's own deletion of its record
    /// goes out with it (`waitsOnlyBehind`).
    func holdsUnpublishedWork(in vaultID: UUID, account: AccountRecord, publishing: Bool = false) async -> Bool {
        guard let base = syncSettings?.state else { return false }
        // The state this session signed (Z20). One that cannot be read holds (review of round 13, L-a).
        let raw: SyncState?
        do {
            raw = try await base.loadState(vaultID: vaultID)
        } catch {
            return true
        }
        var state: SyncState?
        if let raw { state = await verifiedSyncState(raw, vaultID: vaultID) }
        let known = state?.known ?? [:]
        // What a restore left here and could not carry yet: perhaps a move's copy, whose original's deletion is
        // another vault's (review of round 12, M1). Fails closed (review of round 13, L-a), on a chain row that cannot
        // be read too (Z236), but only where the chain decides something (review of round 20, Z239).
        var chain = RestoredChainRead()
        if await holdsRestoredWork(in: vaultID, chain: &chain, account: account) { return true }
        // In a shared vault, nothing a device whose ID does not commit to its account published there reached anyone
        // (review finding Z162): a value of its own in a row it holds is unpublished whatever its state says, such as a
        // move's copy published by a build from before this was refused. A value it stamped, never its clock's entry
        // for it: a writing member's version can claim that entry, and merged here it held every deletion back (Z180).
        // A key that cannot be read counts as one that does not commit here: the gate fails closed.
        let receivedNowhere =
            sharing.vaults[vaultID] != nil ? !((try? await thisDeviceCommits(account)) ?? false) : false
        // Nor did anything a device ID of this account's registry that does not commit wrote there, in whichever row of
        // this device it now sits (review finding Z170): an earlier ID of this installation, restored onto other
        // hardware once or more, whose copy of a move is here only. Its deletions are parked, and the new ID's own wait
        // with every other vault's while the copy is here, or one made again of an original that came back would go out.
        // A registry that cannot be read here counts as one listing such an ID.
        if isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID) {
            guard let view = try? await registry(account),
                let items = await itemsHoldingEdits(
                    of: Self.idsNobodyReceives(account: account, view: view), in: vaultID, account: account)
            else { return true }
            if !items.isEmpty { return true }
        }
        // This device's own pending deletions here, which a row may wait only behind (`waitsOnlyBehind`, V44, V46,
        // Z202). Only those the session signed (`AuthenticatedSyncState`, review of round 14, M1; Z203): a row planted
        // in the file (A8) for a move's copy, stamped by this device far above its edits, would otherwise raise the
        // bound over them, and the original's deletion would go out while the copy exists here alone. One that cannot
        // be read, or checked (locked), holds.
        let pending: [RecordKey: PendingDeletion]
        do {
            guard let syncState else { return true }
            pending = try await syncState.pendingDeletions(vaultID: vaultID).filter {
                $0.value.stamp.device == account.deviceID
            }
        } catch {
            return true
        }
        // Rows that cannot be listed hold, as a state that cannot be read does (review of round 21, Z246): read as
        // none, an edit of this device's that no sync has sent (a move's copy among them) held nothing back.
        let rows: [StoredRecord]
        do {
            rows = try await store.records(in: vaultID, kind: .item)
        } catch {
            return true
        }
        for row in rows where row.deviceID == account.deviceID {
            if receivedNowhere, holdsValue(ofAny: [account.deviceID], in: row) { return true }
            guard let stamp = known[row.key] else { return true }
            // Known only as a deletion: the log says nothing of a version of it. A move's copy has an ID anyone who
            // reads the source vault can derive, and a tombstone for it, found in the log before the copy was written,
            // made the copy look known; if the copy's vault then could not publish, the original's deletion went out
            // ahead of it (review finding Z148). Such a row holds the deletions back while it holds an edit of this
            // device's above what it published, as `unsharedWorkCount` measures it: a version a merge kept after a
            // deletion holds none, and holds nothing back.
            // Nor a row that waits only behind this device's own pending deletion of the same record
            // (`waitsOnlyBehind`, V44, V46, Z202): the outbox sends it right behind the tombstone in the vault's
            // deferred pass, and counted, the deletion waited for the row and the row for the deletion, for good.
            let published = state?.published[row.key]
            if stamp.deleted, holdsUnpublishedEdit(row, published: published, account: account),
                !(pending[row.key].map {
                    waitsOnlyBehind($0, row: row, published: published, account: account, publishing: publishing)
                } ?? false)
            {
                return true
            }
        }
        guard let vault = sharing.vaults[vaultID], !vault.ownTakenOut.isEmpty || !vault.ownTakenOutComplete else {
            return false
        }
        let entries: [SyncEntry]
        do {
            entries = try await base.quarantined(vaultID: vaultID)
        } catch {
            return true
        }
        let own = entries.filter { $0.kind == .item && !$0.isDeletion && $0.device == account.deviceID }
        if !vault.ownTakenOutComplete {
            if own.contains(where: { known[$0.key] == nil }) { return true }
            // Nothing of this device's that the sync state does not know is held aside: whatever the lost row listed
            // and the quarantine still keeps is among `own`, and none of it is waited for any more.
            sharing.vaults[vaultID]?.ownTakenOutComplete = true
            sharing.vaults[vaultID]?.indexChanged = true
        }
        var kept: Set<VersionKey> = []
        for entry in own {
            let version = VersionKey(recordID: entry.recordID, kind: entry.kind.rawValue, version: entry.version)
            if vault.ownTakenOut.contains(version) { kept.insert(version) }
        }
        if kept != vault.ownTakenOut {
            sharing.vaults[vaultID]?.ownTakenOut = kept
            sharing.vaults[vaultID]?.indexChanged = true
        }
        return !kept.isEmpty
    }

    /// Remembers what `report`'s download found a vault with a judge does not merge past for their copies
    /// (`downloadCopyStops`, V58) and what it left unfetched for want of its bound of copies (`downloadCopyWaits`,
    /// V62), where it listed the vault: a download that could not list leaves what the last one found.
    func noteCopyStops(_ report: SyncReport, in vaultID: UUID) {
        guard !report.transportUnavailable, report.transportFailure == nil else { return }
        downloadCopyStops[vaultID] = report.copyStops
        downloadCopyWaits[vaultID] = report.copyWaits
    }

    /// One vault's report for two engine runs in one sync: counts added up, state as the second left it.
    static func report(_ first: SyncReport, followedBy second: SyncReport) -> SyncReport {
        var total = second
        total.fetched += first.fetched
        total.applied += first.applied
        total.pushedEntries += first.pushedEntries
        total.segmentsWritten += first.segmentsWritten
        total.snapshotsWritten += first.snapshotsWritten
        total.collected += first.collected
        total.rejected = first.rejected + second.rejected
        total.quarantined = first.quarantined + second.quarantined
        total.heldAside = first.heldAside + second.heldAside
        total.collided = first.collided + second.collided
        total.staleSnapshots += first.staleSnapshots
        total.ignoredNames = max(first.ignoredNames, second.ignoredNames)
        total.retiredObjects = max(first.retiredObjects, second.retiredObjects)
        total.deviceRevoked = first.deviceRevoked
        total.deviceNotRegistered = first.deviceNotRegistered
        total.awaitingNewPassword = first.awaitingNewPassword
        total.unknownEntriesKept += first.unknownEntriesKept
        total.unknownEntriesDropped += first.unknownEntriesDropped
        total.unknownEntriesProcessed += first.unknownEntriesProcessed
        total.snapshotWithheld = total.snapshotWithheld || first.snapshotWithheld
        total.snapshotWithheldBy.formUnion(first.snapshotWithheldBy)
        total.snapshotWithheldForQuarantine = total.snapshotWithheldForQuarantine || first.snapshotWithheldForQuarantine
        // Either run's: a stop the second did not reach (it replayed instead, say) is still a stop to report.
        total.requiresNewerVersion = total.requiresNewerVersion || first.requiresNewerVersion
        total.replayNeeded = total.replayNeeded || first.replayNeeded
        total.copiesExamined += first.copiesExamined
        total.copiesRefused += first.copiesRefused
        total.copiesNotExamined += first.copiesNotExamined
        total.copiesLeftUnfetched = first.copiesLeftUnfetched + second.copiesLeftUnfetched
        total.forkedObjects = first.forkedObjects + second.forkedObjects
        // Whether the store lacks what this device holds is as the second run left it; what the first refused or
        // postponed still happened.
        total.reuploadRefused = second.reuploadRefused ?? first.reuploadRefused
        total.replayPostponed = total.replayPostponed || first.replayPostponed
        total.ownStreamExhausted = total.ownStreamExhausted || first.ownStreamExhausted
        total.ownStreamConflict = total.ownStreamConflict ?? first.ownStreamConflict
        total.ownStreamSteppedOver = [total.ownStreamSteppedOver, first.ownStreamSteppedOver].compactMap { $0 }.min()
        total.ownStreamUnverified = total.ownStreamUnverified ?? first.ownStreamUnverified
        total.quarantineFull += first.quarantineFull
        return total
    }

    // MARK: - Conflicts and the quarantine (PRD F7.6, F7.7)

    /// Resolves a conflict by the person's explicit choice: `group` takes `value`, which must be the value the
    /// item shows or one of those kept in `Item.conflicts`, and every other value for the group is discarded
    /// (`ItemMerge.resolve`). The only way sync's kept values are ever dropped, short of a permanent deletion.
    @discardableResult
    public func resolveConflict(itemID: UUID, group: ItemGroup, choosing value: ItemGroupValue) async throws
        -> Item
    {
        if case .scopes(let scopes) = value {
            for scope in scopes {
                do {
                    try ScopePolicy.validate(scope)
                } catch let error as ScopeValidationError {
                    throw VaultError.scopeRejected(error)
                }
            }
        }
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let record = try await loadAccount() else { throw VaultError.noAccount }
        let now = await clock.now()
        guard let row = try await store.record(RecordKey(recordID: itemID, kind: .item)) else {
            throw VaultError.itemNotFound(itemID)
        }
        let keys = try requireKeys(since: epoch)
        let item = try openItem(row, keys: keys)
        let held = [ItemMerge.currentValue(of: group, in: item)] + (item.conflicts[group] ?? []).map(\.value)
        guard held.contains(value) else { throw VaultError.conflictValueNotHeld }
        // Also in a deleted vault: choosing between kept values is how the person settles what a deletion left.
        let vaultKey = try await writableVaultKey(row.vaultID, keys: keys, account: record, allowingDeleted: true)
        _ = try requireKeys(since: epoch)
        let revision = try nextRevision(in: row.vaultID, above: row, account: record)
        var resolved = ItemMerge.resolve(
            item, group: group, choosing: value, origin: Self.origin(row), revision: revision)
        resolved.modifiedAt = max(now, resolved.modifiedAt)
        try await commitItem(resolved, replacing: row, vaultKey: vaultKey, account: record)
        return resolved
    }

    /// Remote versions sync refused as implausible (review finding U5), in any vault, kept until the person
    /// discards them.
    public func quarantinedVersions() async throws -> [SyncEntry] {
        guard let syncSettings else { return [] }
        guard let record = try await loadAccount() else { throw VaultError.noAccount }
        var entries: [SyncEntry] = []
        for vaultID in try await vaultDirectory(record).keys.sorted(by: { $0.uuidString < $1.uuidString }) {
            entries += try await syncSettings.state.quarantined(vaultID: vaultID)
        }
        return entries
    }

    /// The same versions as `quarantinedVersions()`, each with the vault it is kept in, for the screen that lists them
    /// (PRD F7.7; review finding S49, which requires held-aside versions from shared vaults to be visible). Vaults in
    /// directory order, entries in the order the state store keeps them.
    public func quarantine() async throws -> [QuarantinedVersion] {
        guard let syncSettings else { return [] }
        guard let record = try await loadAccount() else { throw VaultError.noAccount }
        var versions: [QuarantinedVersion] = []
        let configuration = syncSettings.configuration
        // From the sharing state store, so that a locked session tells held-aside versions apart too.
        let sharedIDs = Set((try? await sharing.settings?.state.sharedVaultIDs()) ?? [])
        for vaultID in try await vaultDirectory(record).keys.sorted(by: { $0.uuidString < $1.uuidString }) {
            let entries = try await syncSettings.state.quarantined(vaultID: vaultID)
            guard !entries.isEmpty else { continue }
            // The state store keeps no reason, so it is derived: a version beyond the jump the engine allows above
            // what the vault holds is U5's; in a shared vault anything else was held aside by the write judge; the
            // rest are merges that could not be sealed (Y37).
            var highWater: UInt64 = 0
            for kind in [EnvelopeKind.item, .vaultMetadata, .scanStatus] {
                for row in try await store.records(in: vaultID, kind: kind) { highWater = max(highWater, row.version) }
            }
            let (ceiling, overflow) = highWater.addingReportingOverflow(configuration.maximumVersionJump)
            let shared =
                sharedIDs.contains(vaultID) || sharing.vaults[vaultID] != nil || sharing.markers[vaultID] != nil
            for entry in entries {
                let implausible = entry.version > configuration.maximumVersion || (!overflow && entry.version > ceiling)
                var reason: QuarantineReason =
                    implausible ? .implausibleVersion : shared ? .heldAside : .unmerged
                // Told from the store as it is now, like the others: the ID is another vault's record's (Z22).
                if let holder = try await store.record(entry.key), holder.vaultID != vaultID {
                    reason = .recordInAnotherVault
                }
                versions.append(QuarantinedVersion(vaultID: vaultID, entry: entry, reason: reason))
            }
        }
        return versions
    }

    /// Discards quarantined versions from the vault each was kept in: the person's choice, so it needs the vault
    /// unlocked (PRD F7.7).
    public func discardQuarantined(_ versions: [QuarantinedVersion]) async throws {
        _ = try requireKeys()
        guard let syncSettings else { throw VaultError.syncNotConfigured }
        for (vaultID, kept) in Dictionary(grouping: versions, by: \.vaultID) {
            try await syncSettings.state.discardQuarantined(kept.map(\.entry), vaultID: vaultID)
        }
    }

    /// Discards quarantined versions: the person's choice, so it needs the vault unlocked (PRD F7.7).
    public func discardQuarantined(_ entries: [SyncEntry]) async throws {
        _ = try requireKeys()
        guard let syncSettings else { throw VaultError.syncNotConfigured }
        guard let record = try await loadAccount() else { throw VaultError.noAccount }
        for vaultID in try await vaultDirectory(record).keys {
            try await syncSettings.state.discardQuarantined(entries, vaultID: vaultID)
        }
    }

    // MARK: - Keyring (called by `VaultSyncAdapter`)

    /// The keys and the account, or `SyncKeyringError.locked`. Every caller below is synchronous from here on, so
    /// a `lock()` cannot land between this check and the use of the keys.
    private func syncKeys() throws -> (UnlockedKeys, AccountRecord) {
        guard let keys, let account else { throw SyncKeyringError.locked }
        return (keys, account)
    }

    func syncSeal(_ payload: [UInt8], at location: SyncObjectLocation) throws -> [UInt8] {
        let (keys, record) = try syncKeys()
        guard let vaultKey = currentVaultKey(location.vaultID, keys: keys, account: record) else {
            throw SyncKeyringError.unknownKey(location.vaultID)
        }
        return try RecordCipher.seal(
            payload, context: location.envelopeContext(keyID: vaultKey.key.keyID), key: vaultKey.key,
            using: &random)
    }

    func syncOpen(_ envelope: [UInt8], context: EnvelopeContext) throws -> [UInt8] {
        let (keys, _) = try syncKeys()
        guard let vaultKey = keys.vaultKeys[context.keyID], vaultKey.vaultID == context.vaultID else {
            throw SyncKeyringError.unknownKey(context.keyID)
        }
        let plaintext: SecureBytes
        do {
            plaintext = try RecordCipher.open(envelope, context: context, key: vaultKey.key)
        } catch {
            throw SyncKeyringError.authenticationFailed
        }
        defer { plaintext.zeroise() }
        // A segment's plaintext is storage locations and record envelopes, each sealed again on its own (§7.3).
        return plaintext.unprotectedCopy()
    }

    /// Signs a sync object twice: with the account's Ed25519 key and with this device's own key
    /// (docs/02-architecture.md §7.8). The keyring signs only as its own device, and only for a vault it holds.
    func syncSign(_ envelope: [UInt8], at location: SyncObjectLocation) async throws -> [UInt8] {
        let (keys, record) = try syncKeys()
        guard location.author == record.deviceID,
            currentVaultKey(location.vaultID, keys: keys, account: record) != nil
        else { throw SyncKeyringError.untrustedAuthor(location.author) }
        do {
            return try await dualSignature(
                Self.syncSignedMessage(envelope, at: location), domain: .logSegment, keys: keys, account: record)
        } catch DeviceKeyError.keyMissing {
            throw SyncKeyringError.untrustedAuthor(location.author)
        }
    }

    /// Whether `location.author` may write to `location.vaultID`, and whether the object carries its signatures.
    ///
    /// The author must be a device of this account that the registry holds as registered and not revoked: an
    /// unknown device and a revoked one are both refused (`untrustedAuthor`), for segments and snapshots alike, and
    /// while locked as while unlocked, because the registry is evaluated from public keys. Both signatures must
    /// verify: the account key's (the keyset's own while unlocked, otherwise the copy in the Keychain) and the
    /// device's, under the key the registry gives for it. With no registry or account key to trust, every object is
    /// refused as `trustedKeyUnavailable`, so the report says why rather than blaming the author. Keychain reads
    /// here cannot show UI: `SystemKeychainStore` sets `interactionNotAllowed` for every item but the Local Unlock
    /// Key.
    ///
    /// This is where a shared vault's membership check plugs in (milestone 4): a writer from another account is
    /// accepted if the vault's membership chain lists that account with a writing role and that account's own
    /// registry holds the device; nothing else here changes.
    func syncVerify(_ signature: [UInt8], over envelope: [UInt8], at location: SyncObjectLocation) async throws {
        guard let record = try await loadAccount() else { throw SyncKeyringError.untrustedAuthor(location.author) }
        guard let view = try? await registry(record) else { throw SyncKeyringError.trustedKeyUnavailable }
        guard try await vaultDirectory(record)[location.vaultID] != nil else {
            throw SyncKeyringError.untrustedAuthor(location.author)
        }
        // A shared vault with no ledger here is no vault of this account's alone: nothing in it verifies until a
        // ledger is loaded for it (V19, V31).
        if isSharedUnavailable(location.vaultID, keys: keys, personalVaultID: record.personalVaultID) {
            throw SyncKeyringError.untrustedAuthor(location.author)
        }
        if sharing.vaults[location.vaultID] != nil {
            // A writer from another account (VaultSession+SharingSync.swift).
            return try sharedVerify(signature, over: envelope, at: location, ownView: view, account: record)
        }
        try Self.verifyDual(
            signature, over: Self.syncSignedMessage(envelope, at: location), domain: .logSegment,
            author: location.author, view: view)
    }

    /// Whether an object at a location in this device's own stream carries this device's own signatures: the account
    /// key's and this device's key's, under this account's registry, in a private vault and a shared one alike. In a
    /// shared vault `syncVerify` also accepts another member's device listed under this device's ID (S33), whose
    /// object is then held aside by the judge; this device must not number its stream from such an object, which
    /// would leave a hole every reader waits at, or move its next number out of range (review finding Z30). A
    /// registry or key that cannot be read, or this device missing from the registry as read, leaves the question
    /// open (`trustedKeyUnavailable`): the engine then neither numbers from the object nor rules it out.
    ///
    /// In a shared vault this device's own objects count only if its ID commits to its account (review finding Z162):
    /// no other device counts them otherwise, so its stream there is no stream of anyone's. The question is left open
    /// (`trustedKeyUnavailable`), so the engine numbers from nothing there and holds its publishing back while its
    /// state could be behind the stream; it publishes nothing there anyway (`sharedEngineOptions`).
    func syncVerifyOwn(_ signature: [UInt8], over envelope: [UInt8], at location: SyncObjectLocation) async throws {
        guard let record = try await loadAccount(), let view = try? await registry(record),
            view.state.devices[record.deviceID] != nil
        else { throw SyncKeyringError.trustedKeyUnavailable }
        guard location.author == record.deviceID else { throw SyncKeyringError.untrustedAuthor(location.author) }
        if sharing.vaults[location.vaultID] != nil, !playsModifiedClient,
            Self.committedOwnState(view)?.devices[record.deviceID] == nil
        {
            throw SyncKeyringError.trustedKeyUnavailable
        }
        try Self.verifyDual(
            signature, over: Self.syncSignedMessage(envelope, at: location), domain: .logSegment,
            author: location.author, view: view)
    }

    /// The devices revoked from the account, whose streams sync no longer reads or waits for (review finding Y6).
    func syncRetiredAuthors(vaultID: UUID? = nil) async -> Set<UUID> {
        guard let record = try? await loadAccount(), let view = try? await registry(record) else { return [] }
        // A shared vault's are those whose revocation counts there, by the same rule as the judge's (Z150).
        if let vaultID, sharing.vaults[vaultID] != nil {
            return sharedRetiredAuthors(vaultID, ownView: view, account: record)
        }
        return Set(view.state.revoked.keys)
    }

    /// What a sync object's signature covers: its name and its envelope. The envelope already binds the location
    /// (`SyncObjectLocation.envelopeContext`), but that is checked only once the vault is unlocked; binding the
    /// name into the signature also refuses a moved object at download, while locked.
    static func syncSignedMessage(_ envelope: [UInt8], at location: SyncObjectLocation) -> [UInt8] {
        Array(location.name.utf8) + [0x00] + envelope
    }

    func syncOpenItem(_ row: StoredRecord) throws -> Item {
        let (keys, _) = try syncKeys()
        return try openItem(row, keys: keys)
    }

    func syncSealItem(_ item: Item) throws -> StoredRecord {
        let (keys, record) = try syncKeys()
        guard let vaultKey = currentVaultKey(item.vaultID, keys: keys, account: record) else {
            throw SyncKeyringError.unknownKey(item.vaultID)
        }
        let row = try sealItem(item, vaultKey: vaultKey, account: record)
        highestVersionSeen[item.vaultID] = max(highestVersionSeen[item.vaultID] ?? 0, item.version)
        return row
    }

    func syncOpenMetadata(_ row: StoredRecord) throws -> VaultMetadata {
        let (keys, _) = try syncKeys()
        return try openMetadata(row, keys: keys)
    }

    func syncSealMetadata(_ metadata: VaultMetadata) throws -> StoredRecord {
        let (keys, record) = try syncKeys()
        guard let vaultKey = currentVaultKey(metadata.vaultID, keys: keys, account: record) else {
            throw SyncKeyringError.unknownKey(metadata.vaultID)
        }
        return try sealMetadata(metadata, vaultKey: vaultKey, account: record)
    }

    // MARK: - Pending deletions (called by `AuthenticatedSyncState`)

    /// What a pending deletion's signature covers: every field of it, fixed-length fields first and the deleted
    /// row's envelope last, so the encoding is unambiguous.
    static func pendingDeletionMessage(_ deletion: PendingDeletion) -> [UInt8] {
        let row = deletion.record
        func bytes(_ id: UUID) -> [UInt8] {
            let u = id.uuid
            return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
        }
        func bytes(_ value: UInt64) -> [UInt8] {
            (0..<8).map { UInt8(truncatingIfNeeded: value >> (56 - 8 * $0)) }
        }
        return bytes(row.vaultID) + bytes(row.recordID) + [row.kind.rawValue] + bytes(deletion.stamp.version)
            + bytes(deletion.stamp.device) + bytes(row.keyID) + bytes(row.version) + bytes(row.deviceID)
            + row.envelope
    }

    /// Signs a deletion this session just committed, so the sync layer can tell it from one planted in the state
    /// store's file (A8).
    func authenticatePendingDeletion(_ deletion: PendingDeletion) throws -> PendingDeletion {
        let (keys, record) = try syncKeys()
        guard deletion.stamp.device == record.deviceID, deletion.stamp.deleted,
            currentVaultKey(deletion.record.vaultID, keys: keys, account: record) != nil
        else { throw SyncKeyringError.untrustedAuthor(deletion.stamp.device) }
        var signed = deletion
        signed.authenticator = try keys.keyset.sign(
            Self.pendingDeletionMessage(deletion), domain: .pendingDeletion)
        return signed
    }

    /// The pending deletions this device's session made: each must be this device's, in the vault asked about, and
    /// signed by the account key. Any other row is ignored — never published, never treated as an erasure — so
    /// editing the file cannot erase an item everywhere. Needs the keyset; the engine reads pending deletions only
    /// to merge or publish, both of which need the vault unlocked anyway.
    func verifiedPendingDeletions(_ deletions: [RecordKey: PendingDeletion], vaultID: UUID) throws
        -> [RecordKey: PendingDeletion]
    {
        let (keys, record) = try syncKeys()
        let signingKey = try keys.keyset.publicKeyBundle().signingKey
        return deletions.filter { key, deletion in
            deletion.stamp.device == record.deviceID
                && Self.isSigned(deletion, as: key, in: vaultID, signingKey: signingKey)
        }
    }

    /// Whether `deletion`, stored under `key` for `vaultID`, is a deletion the account key signed, whichever device
    /// ID stamped it.
    static func isSigned(_ deletion: PendingDeletion, as key: RecordKey, in vaultID: UUID, signingKey: [UInt8])
        -> Bool
    {
        guard key == deletion.record.key, deletion.stamp.deleted, deletion.record.vaultID == vaultID else {
            return false
        }
        return
            (try? Signatures.verify(
                deletion.authenticator, for: pendingDeletionMessage(deletion), domain: .pendingDeletion,
                signingKey: signingKey)) != nil
    }

    // MARK: - The stash (ADR 0009)

    /// `"WWST" ‖ vault ID ‖ device ID ‖ stash`: bound to the vault and to this device, under its own domain.
    static func stashMessage(_ stash: [UInt8], vaultID: UUID, deviceID: UUID) -> [UInt8] {
        func bytes(_ id: UUID) -> [UInt8] {
            let u = id.uuid
            return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
        }
        var message = Array("WWST".utf8)
        message.append(contentsOf: bytes(vaultID))
        message.append(contentsOf: bytes(deviceID))
        message.append(contentsOf: stash)
        return message
    }

    /// The row the state store keeps: `signatureLength u16 ‖ signature ‖ stash`.
    func signStash(_ stash: [UInt8], vaultID: UUID, within writes: SyncStateWrites? = nil) throws -> [UInt8] {
        try requireEntitlement(writes)
        let (keys, record) = try syncKeys()
        let signature = try keys.keyset.sign(
            Self.stashMessage(stash, vaultID: vaultID, deviceID: record.deviceID), domain: .syncStash)
        var row: [UInt8] = [
            UInt8(truncatingIfNeeded: signature.count), UInt8(truncatingIfNeeded: signature.count >> 8),
        ]
        row.append(contentsOf: signature)
        row.append(contentsOf: stash)
        return row
    }

    /// The stash inside a row this session signed for `vaultID` on this device, or `nil`.
    func verifiedStash(_ row: [UInt8], vaultID: UUID) async -> [UInt8]? {
        var record = account
        if record == nil { record = try? await loadAccount() }
        guard row.count >= 2, let record, let signingKey = await trustedAccountSigningKey(record) else { return nil }
        let length = Int(row[0]) | Int(row[1]) << 8
        guard length <= SignedObject.maximumSignatureLength, row.count >= 2 + length else { return nil }
        let signature = Array(row[2..<(2 + length)])
        let stash = Array(row[(2 + length)...])
        let message = Self.stashMessage(stash, vaultID: vaultID, deviceID: record.deviceID)
        guard (try? Signatures.verify(signature, for: message, domain: .syncStash, signingKey: signingKey)) != nil
        else { return nil }
        return stash
    }

    /// Throws `SyncKeyringError.locked`, which an engine takes as "locked meanwhile" and saves nothing for, unless
    /// `writes` is `nil` or the sync it describes may still save a vault's state: begun as a writer (`mayWrite`), and
    /// the lock epoch, this device's ID and the absence of a move unchanged since (V66, and PR #23's Z253, Z256).
    /// Synchronous, so nothing lands between this check and the signature that follows it on the actor.
    func requireEntitlement(_ writes: SyncStateWrites?) throws {
        guard let writes else { return }
        guard writes.permitted, writes.epoch == lockEpoch, let account, account.deviceID == writes.deviceID,
            account.migration == nil
        else { throw SyncKeyringError.locked }
    }

    // MARK: - The state row (review finding Z20)

    /// `"WWSS" ‖ vault ID ‖ device ID ‖ state`: bound to the vault and to this device, under its own domain.
    static func syncStateMessage(_ state: SyncState, deviceID: UUID) -> [UInt8] {
        var message = Array("WWSS".utf8)
        message.append(contentsOf: state.vaultID.byteArray)
        message.append(contentsOf: deviceID.byteArray)
        message.append(contentsOf: state.authenticatedBytes)
        return message
    }

    /// The state with this session's signature over all of it. Throws `SyncKeyringError.locked` while locked: a state
    /// is saved only by a sync that merged or published, which needs the keys anyway. With `writes`, also where the
    /// sync that saves it is no longer entitled to (V66, Z253).
    func signedSyncState(_ state: SyncState, within writes: SyncStateWrites? = nil) throws -> SyncState {
        try requireEntitlement(writes)
        let (keys, record) = try syncKeys()
        var signed = state
        signed.authenticator = try keys.keyset.sign(
            Self.syncStateMessage(state, deviceID: record.deviceID), domain: .syncState)
        return signed
    }

    /// `state` if this session signed it for its vault on this device, or `nil`: a row it did not write is no state.
    /// Checked with the Keychain's copy of the account key while locked, as downloads are.
    func verifiedSyncState(_ state: SyncState, vaultID: UUID) async -> SyncState? {
        await verifiedSyncState(state, vaultID: vaultID, deviceID: nil)
    }

    /// `state` if this session signed it for its vault on `deviceID`, this device's by default: the move of an earlier
    /// device ID's sync state reads what the session signed for that ID (review of round 12, M1).
    func verifiedSyncState(_ state: SyncState, vaultID: UUID, deviceID: UUID?) async -> SyncState? {
        var record = account
        if record == nil { record = try? await loadAccount() }
        guard state.vaultID == vaultID, let record, let signingKey = await trustedAccountSigningKey(record) else {
            return nil
        }
        let message = Self.syncStateMessage(state, deviceID: deviceID ?? record.deviceID)
        guard
            (try? Signatures.verify(state.authenticator, for: message, domain: .syncState, signingKey: signingKey))
                != nil
        else { return nil }
        return state
    }

    /// Copies the account's public signing key to the Keychain, for checking downloads while locked.
    ///
    /// Called after an unlock has installed `keys` and then waited on the Keychain, so a `lock()` may have zeroised
    /// them by now, and reading a zeroised key traps (review finding Z4, as W22): checked here, before the keyset is
    /// read, with no suspension between the check and the read.
    func refreshSigningKey(account: AccountRecord, keys: UnlockedKeys) async throws {
        guard !keys.keyset.isZeroised else { throw VaultError.locked }
        var signingKey = try keys.keyset.publicKeyBundle().signingKey
        try await keychain.store(
            SecureBytes(wiping: &signingKey), for: .accountSigningKey(accountID: account.accountID))
    }
}

/// What one sync may save of a vault's sync state, decided at its start (`runSync`, with `mayWrite`) and checked again,
/// on the actor, as each state or stash is signed (`VaultSession.requireEntitlement`). One mechanism under two names:
/// this branch's V66 (a review of its merge of PR #23's rounds 20 and 21) and PR #23's Z253, Z256 and Z257 (review of
/// its round 22), which ported V66 and extended it. A sync that does not begin as a writer (locked, or with a
/// restore's move pending, or for an ID this installation holds no key for) saves none; one that does saves none once
/// the vault has been locked since, or this device's ID has changed, or a move has been recorded. The state an engine
/// saves was loaded, and verified, for the ID and the keys the sync began with: signed after an unlock registered a
/// restored device as new, it was one started over for the new ID, which a waiting move read as one it had begun
/// (V60's harm), or it replaced the state the move had just saved.
///
/// The lock epoch's clause is load-bearing for the other two (review of PR #22's V66, Z255): the check is synchronous
/// with the signature, but the store's write awaits after it, and it reads the session's cached `account`, which
/// `registerThisDevice` updates one suspension after its `store.commit`. That leaves the device ID's and the move's
/// clauses open across those awaits, and they are sound only because every registration of a new device ID outside
/// `runSync` is an unlock's, which needs a `lock()` first, and `lock()` moves the epoch; the sync's own registration
/// comes before this is made. Never drop it as redundant, not even to spare a sync locked and unlocked during its
/// publish the conflict its next sync reports (docs/06-adversarial-review.md V66, Z255, Z257).
struct SyncStateWrites: Sendable {
    /// This device's ID when the sync began, which its engines were built for.
    let deviceID: UUID
    /// The lock epoch when the sync began.
    let epoch: UInt64
    /// Begun as a writer (`mayWrite`): unlocked, registered and active under an ID this installation holds a key for,
    /// with no registration under way and no move to a new device ID pending. Also what the download-only pass passes
    /// as `savingState` (V60, V66).
    let permitted: Bool
}

/// The sync state store the session and its engine use. Everything the engine acts on rather than checks again is
/// signed by the session as it is written and checked as it is read: pending deletions
/// (`PendingDeletion.authenticator`, review of milestone 3), the stash (N14) and the state row itself (Z20), whose
/// erasures, merged positions and published stamps go out signed in this device's snapshots and segments. Staged
/// objects pass through, because the engine verifies each again before merging it, and so does the quarantine, which
/// is shown to the person and never merged.
struct AuthenticatedSyncState: SyncStateStore {
    let base: any SyncStateStore
    let session: VaultSession
    /// For one sync's engines, carry and re-record, what that sync may save of a vault's state and stash (Z253, the
    /// mechanism of this branch's V66); `nil` elsewhere, where each writer checks the lock epoch and the move itself.
    var writes: SyncStateWrites? = nil

    /// The state as this session signed it for this vault on this device, or `nil` for any other row: the engine
    /// then starts from nothing and replays the log, which rebuilds the erasures too.
    func loadState(vaultID: UUID) async throws -> SyncState? {
        guard let state = try await base.loadState(vaultID: vaultID) else { return nil }
        return await session.verifiedSyncState(state, vaultID: vaultID)
    }

    /// Signs the state with the account key before it is stored; throws `SyncKeyringError.locked` while locked.
    func saveState(_ state: SyncState) async throws {
        try await base.saveState(try await session.signedSyncState(state, within: writes))
    }

    func stage(_ object: StagedObject) async throws {
        try await base.stage(object)
    }

    func staged(vaultID: UUID) async throws -> [StagedObject] {
        try await base.staged(vaultID: vaultID)
    }

    func unstage(_ locations: [SyncObjectLocation]) async throws {
        try await base.unstage(locations)
    }

    /// Signs the deletion now, while the keys are there, so that recording it after its commit needs none (Z28).
    func prepared(_ deletion: PendingDeletion) async throws -> PendingDeletion {
        try await session.authenticatePendingDeletion(deletion)
    }

    /// Records a deletion `prepared` signed; one that carries no signature yet is signed here. Either way it counts
    /// only if it verifies when it is read.
    func addPendingDeletion(_ deletion: PendingDeletion) async throws {
        guard deletion.authenticator.isEmpty else { return try await base.addPendingDeletion(deletion) }
        try await base.addPendingDeletion(try await session.authenticatePendingDeletion(deletion))
    }

    func pendingDeletions(vaultID: UUID) async throws -> [RecordKey: PendingDeletion] {
        try await session.verifiedPendingDeletions(
            try await base.pendingDeletions(vaultID: vaultID), vaultID: vaultID)
    }

    func removePendingDeletions(_ deletions: [RecordKey: RecordStamp], vaultID: UUID) async throws {
        try await base.removePendingDeletions(deletions, vaultID: vaultID)
    }

    @discardableResult
    func quarantine(_ entry: SyncEntry, vaultID: UUID) async throws -> Bool {
        try await base.quarantine(entry, vaultID: vaultID)
    }

    func holdsQuarantined(_ entry: SyncEntry, vaultID: UUID) async throws -> Bool {
        try await base.holdsQuarantined(entry, vaultID: vaultID)
    }

    func quarantineUsage(vaultID: UUID) async throws -> QuarantineUsage {
        try await base.quarantineUsage(vaultID: vaultID)
    }

    func quarantined(vaultID: UUID) async throws -> [SyncEntry] {
        try await base.quarantined(vaultID: vaultID)
    }

    func discardQuarantined(_ entries: [SyncEntry], vaultID: UUID) async throws {
        try await base.discardQuarantined(entries, vaultID: vaultID)
    }

    /// The stash as the session signed it, or `[]` (which the engine refuses, and replays the log for) when the row
    /// is not one this session wrote for this vault on this device. Checked with the Keychain's copy of the account
    /// key while locked, as downloads are.
    func stash(vaultID: UUID) async throws -> [UInt8]? {
        guard let row = try await base.stash(vaultID: vaultID) else { return nil }
        return await session.verifiedStash(row, vaultID: vaultID) ?? []
    }

    /// Signs the stash with the account key before it is stored; throws `SyncKeyringError.locked` while locked.
    func saveStash(_ bytes: [UInt8], vaultID: UUID) async throws {
        try await base.saveStash(try await signedStash(bytes, vaultID: vaultID), vaultID: vaultID)
    }

    func signedStash(_ bytes: [UInt8], vaultID: UUID) async throws -> [UInt8] {
        try await session.signStash(bytes, vaultID: vaultID, within: writes)
    }

    func eraseAll() async throws {
        try await base.eraseAll()
    }
}

/// The session as the sync engine's keyring and the item merger's sealer. Holds the session, never a key: every
/// call goes back to the actor, which throws `SyncKeyringError.locked` once `lock()` has run.
struct VaultSyncAdapter: SyncKeyring, ItemSealer {
    let session: VaultSession

    func seal(_ payload: [UInt8], at location: SyncObjectLocation) async throws -> [UInt8] {
        try await session.syncSeal(payload, at: location)
    }

    func open(_ envelope: [UInt8], context: EnvelopeContext) async throws -> [UInt8] {
        try await session.syncOpen(envelope, context: context)
    }

    func sign(_ envelope: [UInt8], at location: SyncObjectLocation) async throws -> [UInt8] {
        try await session.syncSign(envelope, at: location)
    }

    func verify(_ signature: [UInt8], over envelope: [UInt8], at location: SyncObjectLocation) async throws {
        try await session.syncVerify(signature, over: envelope, at: location)
    }

    func verifyOwn(_ signature: [UInt8], over envelope: [UInt8], at location: SyncObjectLocation) async throws {
        try await session.syncVerifyOwn(signature, over: envelope, at: location)
    }

    func retiredAuthors(vaultID: UUID) async -> Set<UUID> {
        await session.syncRetiredAuthors(vaultID: vaultID)
    }

    func openItem(_ row: StoredRecord) async throws -> Item {
        try await session.syncOpenItem(row)
    }

    func openMetadata(_ row: StoredRecord) async throws -> VaultMetadata {
        try await session.syncOpenMetadata(row)
    }

    func sealMetadata(_ metadata: VaultMetadata) async throws -> StoredRecord {
        try await session.syncSealMetadata(metadata)
    }

    func sealItem(_ item: Item) async throws -> StoredRecord {
        try await session.syncSealItem(item)
    }
}

/// A remote version sync kept aside rather than merged (`VaultSession.quarantine()`): refused as implausible (review
/// finding U5), unsealable once merged (Y37), or held aside in a shared vault because it carries work that does not
/// count (docs/02-architecture.md §8.7). Kept until the person discards it (PRD F7.7).
public struct QuarantinedVersion: Sendable, Hashable, Identifiable {
    public var vaultID: UUID
    public var entry: SyncEntry
    public var reason: QuarantineReason

    public init(vaultID: UUID, entry: SyncEntry, reason: QuarantineReason) {
        self.vaultID = vaultID
        self.entry = entry
        self.reason = reason
    }

    /// The vault, the record, the version's stamp, its key and a digest of its bytes: one kept version, distinct from
    /// another at the same stamp (two can be kept: the quarantine compares whole entries).
    public var id: String {
        let digest = ObjectDigest(hashing: (entry.envelope ?? []) + [entry.isDeletion ? 0 : 1] + entry.erasure)
        return "\(vaultID.uuidString)/\(entry.recordID.uuidString)/\(entry.kind.rawValue)/\(entry.version)/"
            + "\(entry.device.uuidString)/\(entry.keyID.uuidString)/\(digest)"
    }
}

/// Why a version is in the quarantine, as far as this device can tell (the state store keeps entries, not reasons).
public enum QuarantineReason: Sendable, Hashable {
    /// Its version is beyond the jump the engine allows above what the vault holds (review finding U5).
    case implausibleVersion
    /// In a shared vault: held aside by the write judge, as carrying work that does not count (§8.7).
    case heldAside
    /// Its merge with the local version could not be sealed (Y37), or it is no longer implausible as the vault has
    /// caught up with it.
    case unmerged
    /// A record of another vault holds its record ID on this device (the store keys records across vaults, Z22).
    case recordInAnotherVault
}

/// What the Keychain answered for this device's own key under the account's device ID (`DeviceKeyStore.publicKey`).
enum OwnDeviceKey: Equatable {
    case held
    /// It answered that it holds none: a store restored onto other hardware, before it registers as a new device.
    case absent
    /// The read threw (a device whose own lock keeps the Keychain closed, a damaged item): a failure to retry, never
    /// "no key" (review of round 23, Z265).
    case unreadable
}

extension VaultSession {
    /// This device's own key for `record`'s device ID, as the Keychain answers now, a read that throws kept apart from
    /// one that finds no key (review of round 23, Z265): only `absent` registers this installation as a new device,
    /// and anything but `held` makes a sync download only (Z253).
    func ownDeviceKey(of record: AccountRecord) async -> OwnDeviceKey {
        do {
            return try await deviceKeys.publicKey(accountID: record.accountID, deviceID: record.deviceID) == nil
                ? .absent : .held
        } catch {
            return .unreadable
        }
    }
}

/// Why a sync begun unlocked only downloaded, where this device's own key was the one reason
/// (`AccountSyncReport.ownDeviceKeyWait`, review of round 23, Z264).
public enum OwnDeviceKeyWait: Hashable, Sendable {
    /// The Keychain could not be read for this device's key (`SystemKeychainStore`'s items open only while the device
    /// itself is unlocked, so a sync in the background can find it closed). Read again at the next sync.
    case unreadable
    /// The Keychain holds no key for the device ID the account names (a store restored onto other hardware that has
    /// not registered as a new device yet), or a registration of this installation was under way. A sync and an unlock
    /// each register it.
    case registering
}

/// What one sync of the account did: the account's own objects, and each vault's log.
public struct AccountSyncReport: Sendable, Equatable {
    public var account = AccountObjectsReport()
    /// One report per vault, deleted vaults included.
    public var vaults: [UUID: SyncReport] = [:]
    /// This device's standing in the registry; `nil` if the registry could not be evaluated.
    public var deviceStanding: DeviceStanding?
    /// The account password was changed on another device and has not been entered here: downloads only.
    public var awaitingNewPassword = false
    /// The device registry cannot be evaluated here (`VaultError.deviceRegistryUnavailable`): every object from the
    /// transport is refused until a sync restores it.
    public var registryUnavailable = false
    public var transportUnavailable = false
    /// Why the transport could not be used, when it said (`SyncTransportError.stopsSync`): from the account's own
    /// objects, or else the first vault's that names one.
    public var transportFailure: SyncTransportError?
    /// What the sharing pass did for each shared vault (docs/02-architecture.md §8.8).
    public var sharing: [UUID: SharedVaultSyncReport] = [:]
    /// A vault that holds an item of this device's that exists nowhere else (a move's copy that could not be
    /// published, or was held aside): while there is one, no vault's deletions are published, so that an original is
    /// never erased ahead of its copy (PRD F7.6; review findings Z44, Z54). The first such vault found. Also every
    /// shared vault holding an edit, nobody received, of an earlier ID of this installation whose deletions are parked
    /// (`releaseParkedDeletions`, Z167).
    public var deletionsHeldBack: Set<UUID> = []
    /// Why, where it is a copy nobody received (review finding Z171): per shared vault, the items whose rows hold an
    /// edit of a device ID of this account's registry that does not commit (`idsNobodyReceives`), such as an earlier ID
    /// of this installation restored onto other hardware. Each such vault is in `deletionsHeldBack` too. The person
    /// releases the deletions by moving each item out of the shared vault from this device, which writes it as this
    /// device's, or by deleting it.
    public var copiesNobodyReceived: [UUID: Set<UUID>] = [:]
    /// Per shared vault, the items holding work an earlier device ID of this installation wrote there and never
    /// published, which a restore onto other hardware has not carried over yet for want of a current key for the
    /// vault here (`SyncState.restoredUnpublished`, review of round 12, M1): such an item exists on this device only.
    /// Each such vault is in `deletionsHeldBack` too. A sync carries them once the vault opens here (its ledger
    /// verified, or the owner's invitation accepted again), and the deletions go out after them; for a vault that will
    /// not open, the person can stop waiting (`VaultSession.stopWaitingForRestoredWork(in:)`, the notice's action).
    public var restoredWorkWaiting: [UUID: Set<UUID>] = [:]
    /// Per shared vault, items holding such work in a vault that waits for nothing any more: deleted, or one this
    /// account is no longer a member of (review of round 13, M3). They hold no deletion back, stay on this device as
    /// they are, and reach no other device.
    public var restoredWorkKeptHere: [UUID: Set<UUID>] = [:]
    /// The vaults of `restoredWorkWaiting` the person may stop waiting for: those that will not open on this device,
    /// with no current key here or an owner its devices disagree about (review of round 14, L2). Any other waits only
    /// on something a sync gets past, and is carried then.
    public var restoredWorkMayStopWaiting: Set<UUID> = []
    /// The vaults that published nothing in this sync, new edits included, and will publish nothing at the next,
    /// because a restore has still to carry over work there (`SyncState.restoredUnpublished`) and its carry did not
    /// finish: their log could not be pulled (the transport failing for them, or a failure in an earlier vault that
    /// stopped the sync), or a step of the carry failed (review of round 14, L4). The carry runs only after a vault's
    /// log is pulled, and while anything is left to carry the vault publishes nothing, so that no merge of a row still
    /// holding an earlier ID's work goes out ahead of it; nor does it merge what it pulled, which waits, staged, for
    /// the carry (L1). A carry that finishes in this sync is not named: the vault publishes at the next. Named too: a
    /// vault whose sync state does not verify, or could not be read, where what a restore left could not be recorded
    /// again in this sync (review of round 22, Z254); it is tried again at the next.
    public var publishingHeldForCarry: Set<UUID> = []
    /// This installation registered a new device ID and has not finished moving the old ID's sync state to it
    /// (`AccountRecord.migration`, review of round 10, Z181): downloads only, and the move is tried again at each
    /// unlock and sync.
    public var deviceMigrationIncomplete = false
    /// The vaults where what a restore left can be told only from the vault's chain row of earlier device IDs
    /// (`RestoredChainRow`), and the sharing store could not read it (review of round 20, Z240): a shared vault whose
    /// sync state does not verify or that has none (on any device, restored or not: review of round 21, Z250), or a
    /// restore's move that needs the row. Each fails closed: such a vault holds every vault's deletions back (it is in
    /// `deletionsHeldBack`), and a move that needs the row is not made (`deviceMigrationIncomplete`), for as long as
    /// the store fails. Tried again at each sync.
    public var restoredChainUnreadable: Set<UUID> = []
    /// The session was unlocked, and this sync only downloaded, applying and sending nothing, because of this device's
    /// own key alone (review of round 23, Z264): its standing active, no new password awaited, no move pending. `nil`
    /// otherwise, locked included, where "when you unlock" is what is true.
    public var ownDeviceKeyWait: OwnDeviceKeyWait?
    /// The session was unlocked, and this sync only downloaded because a move of this installation's sync records to
    /// its new device ID is incomplete (`deviceMigrationIncomplete`, found merging round 24 into PR #22, Z271): "when
    /// you unlock" is untrue to a person whose vault is open. `false` while locked, where the next unlock tries the
    /// move again.
    public var movePendingWhileUnlocked = false
    /// The shared vaults where this device began taking out what no longer counts (`takeOutWhatNoLongerCounts`) and
    /// could not finish, a local store failing or a lock during it (review of round 24, Z268; review of round 25,
    /// Z273): their replay waits, and no vault's deletions went out in this sync, after what the take-out may have put
    /// aside of this device's own (Z262). Not `deletionsHeldBack`, whose wording (something moved has not reached the
    /// other devices) would be untrue here. Tried again at the next sync; nothing a member or the sync storage writes
    /// can make a take-out throw. Those where nothing of this device's was published in this sync are also in
    /// `takeOutUnfinishedSentNothing`; in the others, a first pass that was not owed published before the replay's
    /// take-out failed (Z273).
    public var takeOutUnfinished: Set<UUID> = []
    /// Of `takeOutUnfinished`, the vaults whose take-out was owed as their first pass ran and still is: nothing of this
    /// device's was published there in this sync, first pass or replay (Z270, Z276), so its changes there wait too
    /// (Z273).
    public var takeOutUnfinishedSentNothing: Set<UUID> = []

    public init() {}

    /// Every vault's report added up, for a caller that shows one line about the last sync.
    public var combined: SyncReport {
        var total = SyncReport()
        total.transportUnavailable = transportUnavailable
        total.transportFailure = transportFailure
        total.awaitingNewPassword = awaitingNewPassword
        total.deviceRevoked = deviceStanding == .revoked
        total.deviceNotRegistered = deviceStanding == .unknown
        for name in account.rejected {
            total.rejected.append(SyncRejection(name: name, reason: .accountObjectRefused))
        }
        total.ignoredNames = account.ignoredNames
        for (_, report) in vaults.sorted(by: { $0.key.uuidString < $1.key.uuidString }) {
            total.fetched += report.fetched
            total.applied += report.applied
            total.pushedEntries += report.pushedEntries
            total.segmentsWritten += report.segmentsWritten
            total.snapshotsWritten += report.snapshotsWritten
            total.collected += report.collected
            total.rejected += report.rejected
            total.quarantined += report.quarantined
            total.heldAside += report.heldAside
            total.collided += report.collided
            total.waiting.merge(report.waiting, uniquingKeysWith: min)
            total.staleSnapshots += report.staleSnapshots
            total.ignoredNames += report.ignoredNames
            total.retiredObjects += report.retiredObjects
            total.deletionsDeferred += report.deletionsDeferred
            total.deferredUntilUnlock = total.deferredUntilUnlock || report.deferredUntilUnlock
            total.transportUnavailable = total.transportUnavailable || report.transportUnavailable
            total.transportFailure = total.transportFailure ?? report.transportFailure
            total.ownStreamConflict = total.ownStreamConflict ?? report.ownStreamConflict
            total.ownStreamSteppedOver = total.ownStreamSteppedOver ?? report.ownStreamSteppedOver
            total.requiresNewerVersion = total.requiresNewerVersion || report.requiresNewerVersion
            total.unknownEntriesKept += report.unknownEntriesKept
            total.unknownEntriesDropped += report.unknownEntriesDropped
            total.unknownEntriesProcessed += report.unknownEntriesProcessed
            total.snapshotWithheld = total.snapshotWithheld || report.snapshotWithheld
            total.snapshotWithheldBy.formUnion(report.snapshotWithheldBy)
            total.snapshotWithheldForQuarantine =
                total.snapshotWithheldForQuarantine || report.snapshotWithheldForQuarantine
            total.replayNeeded = total.replayNeeded || report.replayNeeded
            total.copiesExamined += report.copiesExamined
            total.copiesRefused += report.copiesRefused
            total.copiesNotExamined += report.copiesNotExamined
            total.forkedObjects += report.forkedObjects
            total.handOnOwed = total.handOnOwed || report.handOnOwed
            total.storeLacksObjects = total.storeLacksObjects || report.storeLacksObjects
            total.replayPostponed = total.replayPostponed || report.replayPostponed
            total.ownStreamExhausted = total.ownStreamExhausted || report.ownStreamExhausted
            total.ownStreamUnverified = total.ownStreamUnverified ?? report.ownStreamUnverified
            total.quarantineFull += report.quarantineFull
        }
        return total
    }

    /// The store was reset, or lacks what this device holds, and the person has not been asked or has not answered
    /// (docs/02-architecture.md §7.10): the transport says so or the store holds none of the account's objects
    /// (`storeReset`, and this sync stopped), or a vault's engine found its own objects gone and holds what nothing
    /// listed stands for. Nothing was uploaded again. A screen shows the question (`VaultSession.reuploadPlan`) and
    /// calls `reuploadAfterStoreReset(confirming:)` only on a yes. A shared vault alone never raises it: it cannot
    /// be uploaded again from one member's device (`reuploadRefusals`).
    public var storeNeedsReupload: Bool {
        if transportFailure == .storeReset { return true }
        if vaults.values.contains(where: { $0.transportFailure == .storeReset }) { return true }
        if sharing.values.contains(where: { $0.transportFailure == .storeReset }) { return true }
        return vaults.values.contains { $0.storeLacksObjects && $0.reuploadRefused == nil }
    }

    /// The vaults whose logs hold something the store lacks and were not, or cannot be, uploaded again, and why.
    public var reuploadRefusals: [UUID: ReuploadRefusal] {
        vaults.compactMapValues(\.reuploadRefused)
    }
}

/// The merger for a vault's description: a last-writer-wins register, which is all a vault's name needs
/// (docs/02-architecture.md §7.7). The stamp that decides is the description's own, the (version, device) of the
/// write that chose it (`VaultMetadata.descriptionStamp`), not the stamp of the row that carries it: a row sealed
/// again (a rotation's re-seal, the merge of two copies below, a device registered again) is a carrier, and a
/// carrier at a higher version must not bring an older name back over a newer one. In a shared vault that is what
/// keeps the choice of name with the administrators who wrote the descriptions (§8.7, review finding S54): any
/// member who may write can seal a carrier, and a description's stamp is part of what the judge checks, while a
/// carrier's version is whatever its sealer chose. Between two carriers of one description the higher row stamp
/// stands. Deterministic and commutative: every device ends on the description with the highest stamp, whatever
/// order the versions arrive in. A description is never erased by sync.
struct VaultMetadataMerger: RecordMerger {
    let sealer: VaultSyncAdapter

    func merge(local: StoredRecord, remote: StoredRecord) async throws -> MergeDecision {
        let incoming = try await sealer.openMetadata(remote)
        let chosen = incoming.descriptionStamp(carriedBy: remote)
        do {
            let current = try await sealer.openMetadata(local).descriptionStamp(carriedBy: local)
            // An older description never replaces a newer one, whatever version its row has reached.
            if chosen < current { return .keepLocal }
            // One description in two rows: the row with the higher stamp stands.
            if chosen == current, !(RecordStamp(local) < RecordStamp(remote)) { return .keepLocal }
        } catch SyncKeyringError.locked {
            throw SyncKeyringError.locked
        } catch {
            // A local row that does not open is damage, not a version: the remote one replaces it.
        }
        if remote.version > local.version { return .adoptRemote }
        // The remote description stands, in a row that is not above the local one (the same version from a device
        // that orders later, a newer description under a carrier of an older one, or a damaged row): stored again
        // above both, by this device, so versions still only move forward.
        var copy = incoming
        // Still the remote writer's description: in a shared vault the judge attributes it to them (review S37).
        copy.writtenBy = chosen
        // A local row at the last version (an edited file, Z23) has nothing above it: the object is refused.
        guard local.version < UInt64.max else { throw ItemMergeError.versionOverflow }
        copy.version = local.version + 1
        return .replace(try await sealer.sealMetadata(copy))
    }

    func erasureSummary(of record: StoredRecord) async throws -> [UInt8] {
        []
    }

    func resolveErasure(_ summary: [UInt8], of record: StoredRecord, above version: UInt64) async throws
        -> ErasureDecision
    {
        .keep
    }

    func joinErasureSummaries(_ first: [UInt8], _ second: [UInt8], kind: EnvelopeKind) async throws -> [UInt8] {
        []
    }
}
