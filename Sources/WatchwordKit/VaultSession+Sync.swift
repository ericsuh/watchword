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
    @discardableResult
    public func syncAll(reconcile: Bool = false) async throws -> AccountSyncReport {
        guard let syncSettings, let syncState else { throw VaultError.syncNotConfigured }
        guard var record = try await loadAccount() else { throw VaultError.noAccount }
        guard !syncInFlight else { throw SyncError.syncInProgress }
        syncInFlight = true
        defer { syncInFlight = false }
        var report = AccountSyncReport()
        registryView = nil

        do {
            try await startRegistryIfAccountPredatesIt(account: record, transport: syncSettings.transport)
            report.account = try await syncAccountObjects(account: record, transport: syncSettings.transport)
        } catch let error as SyncTransportError where error.stopsSync {
            report.transportUnavailable = true
            report.transportFailure = report.transportFailure ?? error
        } catch SyncKeyringError.locked {
            // Locked while vouching for the directory: the rest of the sync is a download.
        }
        // A move of an earlier device ID's sync state that an unlock could not finish is tried again; until it is
        // complete this device publishes nothing, since the move starts each vault's state over (Z181).
        if keys != nil, record.migration != nil {
            try? await completeDeviceMigration(account: record)
            record = try await loadAccount() ?? record
        }
        report.deviceMigrationIncomplete = record.migration != nil
        // A device whose registration no longer counts registers again, now that it has seen why.
        if let keys, let view = try? await registry(record), view.state.pendingCredentials.isEmpty,
            view.state.standing(of: record.deviceID) == .unknown
        {
            try? await registerThisDevice(account: record, keys: keys, asNewDevice: false)
            record = try await loadAccount() ?? record
        }

        let view = try? await registry(record)
        let standing = view?.state.standing(of: record.deviceID)
        report.deviceStanding = standing
        // The registry's pending entries, and what the Keychain remembers of one whose rows the file has lost (Z3).
        let changePending = await passwordChangePending(record)
        report.awaitingNewPassword = changePending || !(view?.state.pendingCredentials.isEmpty ?? true)
        report.registryUnavailable = view == nil
        let mayWrite =
            keys != nil && standing == .active && !report.awaitingNewPassword && !report.deviceMigrationIncomplete
        let epoch = lockEpoch
        // Deletions an earlier ID of this installation made, parked while a shared vault holds an edit of that ID that
        // nobody received, go out once none remains; until then they are reported held back (Z167).
        if mayWrite { report.deletionsHeldBack.formUnion(await releaseParkedDeletions(account: record, view: view)) }
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
        // Shared vaults: membership, keys and what no longer counts, before any log (VaultSession+SharingSync.swift).
        var sharingReports = await syncSharedVaultsBeforeLogs(account: record)
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
                vaultID: vaultID, deviceID: record.deviceID, store: store, syncState: syncState,
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
        for vaultID in try await vaultDirectory(record).keys.sorted(by: { $0.uuidString < $1.uuidString }) {
            var vaultReport: SyncReport
            let shared = sharedEngineOptions(
                vaultID, base: syncSettings.configuration, account: record, ownDevices: ownDevices,
                ownIDCommits: ownIDCommits)
            if mayWrite, let keys, currentVaultKey(vaultID, keys: keys, account: record) != nil {
                let requests = sharedReplayRequests(vaultID)
                vaultReport = try await engine(vaultID).sync(
                    reconcile: reconcile || shared.reconcile, deferringDeletions: true, publishing: shared.publishing,
                    transportStopped: stopped)
                await sharedEngineDidRun(
                    vaultID, reconciled: reconcile || shared.reconcile, report: vaultReport, requestsBefore: requests)
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
                vaultReport = try await engine(vaultID).download(transportStopped: stopped)
                vaultReport.deferredUntilUnlock = true
            }
            // A vault may hold the copy half of a move that this sync did not publish: it is not published to (this
            // account may not write there now, or it is shared with no ledger here), or the copy was taken out and
            // held aside before it went out. While any vault holds an item that exists nowhere else, no vault's
            // deletions go out (Z44).
            if restPublished, mayWrite, await holdsUnpublishedWork(in: vaultID, account: record) {
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
        if mayWrite, stopped == nil {
            for vaultID in sharedVaultsNeedingReplay() {
                guard let first = report.vaults[vaultID], !first.deferredUntilUnlock else { continue }
                await prepareSharedReplay(vaultID)
                let shared = sharedEngineOptions(
                    vaultID, base: syncSettings.configuration, account: record, ownDevices: ownDevices,
                    ownIDCommits: ownIDCommits)
                let requests = sharedReplayRequests(vaultID)
                let second = try await engine(vaultID).sync(
                    reconcile: true, deferringDeletions: true, publishing: shared.publishing)
                await sharedEngineDidRun(vaultID, reconciled: true, report: second, requestsBefore: requests)
                if second.deletionsDeferred > 0, !deferred.contains(vaultID) { deferred.append(vaultID) }
                if second.transportUnavailable || second.ownStreamConflict != nil || second.ownStreamExhausted
                    || second.ownStreamUnverified != nil
                {
                    restPublished = false
                }
                if restPublished, await holdsUnpublishedWork(in: vaultID, account: record) {
                    restPublished = false
                    report.deletionsHeldBack.insert(vaultID)
                }
                report.vaults[vaultID] = Self.report(first, followedBy: second)
            }
        }
        if restPublished {
            for vaultID in deferred {
                guard let first = report.vaults[vaultID] else { continue }
                report.vaults[vaultID] = Self.report(first, followedBy: try await engine(vaultID).sync())
            }
        }
        if mayWrite, stopped == nil {
            await syncSharedVaultsAfterLogs(account: record, reports: &sharingReports)
        }
        // The copies that hold every deletion back, by item, for the screen to name (Z171), while the keys this sync
        // started with are still here (Z174).
        if mayWrite, let view, (try? requireKeys(since: epoch)) != nil {
            report.copiesNobodyReceived = await copiesNobodyReceived(
                account: record, view: view, since: epoch, otherwise: Array(report.vaults.keys))
            report.deletionsHeldBack.formUnion(report.copiesNobodyReceived.keys)
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

    func holdsUnpublishedWork(in vaultID: UUID, account: AccountRecord) async -> Bool {
        guard let syncState, let base = syncSettings?.state else { return false }
        let state = try? await syncState.loadState(vaultID: vaultID)
        let known = state?.known ?? [:]
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
        for row in (try? await store.records(in: vaultID, kind: .item)) ?? [] where row.deviceID == account.deviceID {
            if receivedNowhere, holdsValue(ofAny: [account.deviceID], in: row) { return true }
            guard let stamp = known[row.key] else { return true }
            // Known only as a deletion: the log says nothing of a version of it. A move's copy has an ID anyone who
            // reads the source vault can derive, and a tombstone for it, found in the log before the copy was written,
            // made the copy look known; if the copy's vault then could not publish, the original's deletion went out
            // ahead of it (review finding Z148). Such a row holds the deletions back while it holds an edit of this
            // device's above what it published, as `unsharedWorkCount` measures it: a version a merge kept after a
            // deletion holds none, and holds nothing back.
            if stamp.deleted, holdsUnpublishedEdit(row, published: state?.published[row.key], account: account) {
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
    func signStash(_ stash: [UInt8], vaultID: UUID) throws -> [UInt8] {
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
    /// is saved only by a sync that merged or published, which needs the keys anyway.
    func signedSyncState(_ state: SyncState) throws -> SyncState {
        let (keys, record) = try syncKeys()
        var signed = state
        signed.authenticator = try keys.keyset.sign(
            Self.syncStateMessage(state, deviceID: record.deviceID), domain: .syncState)
        return signed
    }

    /// `state` if this session signed it for its vault on this device, or `nil`: a row it did not write is no state.
    /// Checked with the Keychain's copy of the account key while locked, as downloads are.
    func verifiedSyncState(_ state: SyncState, vaultID: UUID) async -> SyncState? {
        var record = account
        if record == nil { record = try? await loadAccount() }
        guard state.vaultID == vaultID, let record, let signingKey = await trustedAccountSigningKey(record) else {
            return nil
        }
        let message = Self.syncStateMessage(state, deviceID: record.deviceID)
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

/// The sync state store the session and its engine use. Everything the engine acts on rather than checks again is
/// signed by the session as it is written and checked as it is read: pending deletions
/// (`PendingDeletion.authenticator`, review of milestone 3), the stash (N14) and the state row itself (Z20), whose
/// erasures, merged positions and published stamps go out signed in this device's snapshots and segments. Staged
/// objects pass through, because the engine verifies each again before merging it, and so does the quarantine, which
/// is shown to the person and never merged.
struct AuthenticatedSyncState: SyncStateStore {
    let base: any SyncStateStore
    let session: VaultSession

    /// The state as this session signed it for this vault on this device, or `nil` for any other row: the engine
    /// then starts from nothing and replays the log, which rebuilds the erasures too.
    func loadState(vaultID: UUID) async throws -> SyncState? {
        guard let state = try await base.loadState(vaultID: vaultID) else { return nil }
        return await session.verifiedSyncState(state, vaultID: vaultID)
    }

    /// Signs the state with the account key before it is stored; throws `SyncKeyringError.locked` while locked.
    func saveState(_ state: SyncState) async throws {
        try await base.saveState(try await session.signedSyncState(state))
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
        try await session.signStash(bytes, vaultID: vaultID)
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
    /// This installation registered a new device ID and has not finished moving the old ID's sync state to it
    /// (`AccountRecord.migration`, review of round 10, Z181): downloads only, and the move is tried again at each
    /// unlock and sync.
    public var deviceMigrationIncomplete = false

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
            total.ownStreamExhausted = total.ownStreamExhausted || report.ownStreamExhausted
            total.ownStreamUnverified = total.ownStreamUnverified ?? report.ownStreamUnverified
            total.quarantineFull += report.quarantineFull
        }
        return total
    }
}

/// The merger for a vault's description: a last-writer-wins register on (version, device), which is all a vault's
/// name needs (docs/02-architecture.md §7.7). Deterministic and commutative: every device ends on the version with
/// the highest stamp, whatever order the versions arrive in. A description is never erased by sync.
struct VaultMetadataMerger: RecordMerger {
    let sealer: VaultSyncAdapter

    func merge(local: StoredRecord, remote: StoredRecord) async throws -> MergeDecision {
        let incoming = try await sealer.openMetadata(remote)
        let localOpens: Bool
        do {
            _ = try await sealer.openMetadata(local)
            localOpens = true
        } catch SyncKeyringError.locked {
            throw SyncKeyringError.locked
        } catch {
            // A local row that does not open is damage, not a version: the remote one replaces it.
            localOpens = false
        }
        guard !localOpens || RecordStamp(local) < RecordStamp(remote) else { return .keepLocal }
        if remote.version > local.version { return .adoptRemote }
        // The same version from a device that orders later (or over a damaged row): stored again above both, by
        // this device, so versions still only move forward.
        var copy = incoming
        // Still the remote writer's description: in a shared vault the judge attributes it to them (review S37).
        copy.writtenBy = incoming.writtenBy ?? Revision(version: remote.version, device: remote.deviceID)
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
