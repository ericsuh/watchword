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
        report.awaitingNewPassword = !(view?.state.pendingCredentials.isEmpty ?? true)
        report.registryUnavailable = view == nil
        let mayWrite = keys != nil && standing == .active && !report.awaitingNewPassword

        let adapter = VaultSyncAdapter(session: self)
        let merger = KindRoutingMerger([
            .item: ItemRecordMerger(sealer: adapter, deviceID: record.deviceID),
            .vaultMetadata: VaultMetadataMerger(sealer: adapter),
            .scanStatus: ScanStatusMerger(sealer: adapter),
        ])
        // Shared vaults: membership, keys and what no longer counts, before any log (VaultSession+SharingSync.swift).
        var sharingReports = await syncSharedVaultsBeforeLogs(account: record)
        func engine(_ vaultID: UUID) -> SyncEngine {
            let shared = sharedEngineOptions(vaultID, base: syncSettings.configuration, account: record)
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
            let shared = sharedEngineOptions(vaultID, base: syncSettings.configuration, account: record)
            if mayWrite, let keys, currentVaultKey(vaultID, keys: keys, account: record) != nil {
                vaultReport = try await engine(vaultID).sync(
                    reconcile: reconcile || shared.reconcile, deferringDeletions: true, publishing: shared.publishing,
                    transportStopped: stopped)
                sharedEngineDidRun(vaultID, reconciled: reconcile || shared.reconcile, report: vaultReport)
                // Entries a shared vault's earlier version could not read are readable now: replayed with the judge
                // in this sync (ADR 0009), as its log is whole.
                if vaultReport.replayNeeded { sharing.vaults[vaultID]?.needsReconcile = true }
                if vaultReport.deletionsDeferred > 0 { deferred.append(vaultID) }
                if vaultReport.transportUnavailable || vaultReport.deferredUntilUnlock
                    || vaultReport.ownStreamConflict != nil
                {
                    restPublished = false
                }
            } else {
                vaultReport = try await engine(vaultID).download(transportStopped: stopped)
                vaultReport.deferredUntilUnlock = true
            }
            if stopped == nil, let failure = vaultReport.transportFailure, failure.stopsSync { stopped = failure }
            vaultReport.deviceRevoked = standing == .revoked
            vaultReport.deviceNotRegistered = standing == .unknown
            vaultReport.awaitingNewPassword = report.awaitingNewPassword
            report.vaults[vaultID] = vaultReport
        }
        if restPublished {
            for vaultID in deferred {
                guard let first = report.vaults[vaultID] else { continue }
                report.vaults[vaultID] = Self.report(first, followedBy: try await engine(vaultID).sync())
            }
        }
        if mayWrite, stopped == nil {
            for vaultID in sharedVaultsNeedingReplay() {
                guard let first = report.vaults[vaultID], !first.deferredUntilUnlock else { continue }
                await prepareSharedReplay(vaultID)
                let shared = sharedEngineOptions(vaultID, base: syncSettings.configuration, account: record)
                let second = try await engine(vaultID).sync(reconcile: true, publishing: shared.publishing)
                sharedEngineDidRun(vaultID, reconciled: true, report: second)
                report.vaults[vaultID] = Self.report(first, followedBy: second)
            }
            await syncSharedVaultsAfterLogs(account: record, reports: &sharingReports)
        }
        report.sharing = sharingReports
        // What the merges changed is shown to the hygiene engine now, not only at its next query (§13.8).
        try? await reconcileHygiene()
        return report
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
        // Either run's: a stop the second did not reach (it replayed instead, say) is still a stop to report.
        total.requiresNewerVersion = total.requiresNewerVersion || first.requiresNewerVersion
        total.replayNeeded = total.replayNeeded || first.replayNeeded
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
            let shared = sharedIDs.contains(vaultID) || sharing.vaults[vaultID] != nil
            for entry in entries {
                let implausible = entry.version > configuration.maximumVersion || (!overflow && entry.version > ceiling)
                let reason: QuarantineReason =
                    implausible ? .implausibleVersion : shared ? .heldAside : .unmerged
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

    /// The devices revoked from the account, whose streams sync no longer reads or waits for (review finding Y6).
    func syncRetiredAuthors(vaultID: UUID? = nil) async -> Set<UUID> {
        guard let record = try? await loadAccount(), let view = try? await registry(record) else { return [] }
        return Set(view.state.revoked.keys).union(vaultID.map(sharedRetiredAuthors) ?? [])
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
            guard key == deletion.record.key, deletion.stamp.device == record.deviceID, deletion.stamp.deleted,
                deletion.record.vaultID == vaultID
            else { return false }
            return
                (try? Signatures.verify(
                    deletion.authenticator, for: Self.pendingDeletionMessage(deletion), domain: .pendingDeletion,
                    signingKey: signingKey)) != nil
        }
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

    /// Copies the account's public signing key to the Keychain, for checking downloads while locked.
    func refreshSigningKey(account: AccountRecord, keys: UnlockedKeys) async throws {
        var signingKey = try keys.keyset.publicKeyBundle().signingKey
        try await keychain.store(
            SecureBytes(wiping: &signingKey), for: .accountSigningKey(accountID: account.accountID))
    }
}

/// The sync state store the session and its engine use: everything passes through to `base`, except that pending
/// deletions are signed by the session as they are recorded and checked as they are read
/// (`PendingDeletion.authenticator`, review of milestone 3).
struct AuthenticatedSyncState: SyncStateStore {
    let base: any SyncStateStore
    let session: VaultSession

    func loadState(vaultID: UUID) async throws -> SyncState? {
        try await base.loadState(vaultID: vaultID)
    }

    func saveState(_ state: SyncState) async throws {
        try await base.saveState(state)
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

    func addPendingDeletion(_ deletion: PendingDeletion) async throws {
        try await base.addPendingDeletion(try await session.authenticatePendingDeletion(deletion))
    }

    func pendingDeletions(vaultID: UUID) async throws -> [RecordKey: PendingDeletion] {
        try await session.verifiedPendingDeletions(
            try await base.pendingDeletions(vaultID: vaultID), vaultID: vaultID)
    }

    func removePendingDeletions(_ deletions: [RecordKey: RecordStamp], vaultID: UUID) async throws {
        try await base.removePendingDeletions(deletions, vaultID: vaultID)
    }

    func quarantine(_ entry: SyncEntry, vaultID: UUID) async throws {
        try await base.quarantine(entry, vaultID: vaultID)
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
            total.waiting.merge(report.waiting, uniquingKeysWith: min)
            total.staleSnapshots += report.staleSnapshots
            total.ignoredNames += report.ignoredNames
            total.retiredObjects += report.retiredObjects
            total.deletionsDeferred += report.deletionsDeferred
            total.deferredUntilUnlock = total.deferredUntilUnlock || report.deferredUntilUnlock
            total.transportUnavailable = total.transportUnavailable || report.transportUnavailable
            total.transportFailure = total.transportFailure ?? report.transportFailure
            total.ownStreamConflict = total.ownStreamConflict ?? report.ownStreamConflict
            total.requiresNewerVersion = total.requiresNewerVersion || report.requiresNewerVersion
            total.unknownEntriesKept += report.unknownEntriesKept
            total.unknownEntriesDropped += report.unknownEntriesDropped
            total.unknownEntriesProcessed += report.unknownEntriesProcessed
            total.snapshotWithheld = total.snapshotWithheld || report.snapshotWithheld
            total.snapshotWithheldBy.formUnion(report.snapshotWithheldBy)
            total.replayNeeded = total.replayNeeded || report.replayNeeded
        }
        return total
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
