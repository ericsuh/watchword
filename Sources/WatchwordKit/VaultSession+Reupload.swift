import Foundation
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordStore
import WatchwordSync

/// What `VaultSession.reuploadAfterStoreReset(confirming:)` would upload from this device, for the question the
/// person is asked first (docs/02-architecture.md §7.10; owner decision, 2026-11-17: re-upload, "but ask the user
/// first"). It names no item and holds no secret: vaults, their names and how many items each holds.
public struct ReuploadPlan: Sendable, Hashable {
    public struct Vault: Sendable, Hashable, Identifiable {
        public var id: UUID
        /// Empty if the vault's description cannot be read.
        public var name: String
        public var isPersonal: Bool
        /// Deleted, here or on another device: its log is uploaded all the same, so that the deletion, and what it
        /// had not seen, reach every device.
        public var isDeleted: Bool
        /// Items this device holds in the vault, trashed ones included.
        public var itemCount: Int

        public init(id: UUID, name: String, isPersonal: Bool, isDeleted: Bool, itemCount: Int) {
            self.id = id
            self.name = name
            self.isPersonal = isPersonal
            self.isDeleted = isDeleted
            self.itemCount = itemCount
        }
    }

    /// The device that would upload: a plan confirmed on one device says nothing about another.
    public var deviceID: UUID
    /// The account's own vaults, whose logs this device can upload again, in the order of their IDs.
    public var vaults: [Vault]
    /// Shared vaults: never uploaded again from one member's device (`ReuploadRefusal.sharedVault`). They stay on
    /// this device as it holds them.
    public var sharedVaults: [Vault]

    public init(deviceID: UUID, vaults: [Vault], sharedVaults: [Vault]) {
        self.deviceID = deviceID
        self.vaults = vaults
        self.sharedVaults = sharedVaults
    }

    /// Items in the vaults that would be uploaded.
    public var itemCount: Int {
        vaults.reduce(0) { $0 + $1.itemCount }
    }
}

// Starting again after the sync store was reset (docs/02-architecture.md §7.10). Nothing here runs unless a screen
// calls it on the person's answer: no sync, timer or policy does.
extension VaultSession {
    /// What this device would upload if the person said yes: read from the local store, nothing asked of the
    /// transport. Needs the vault unlocked.
    public func reuploadPlan() async throws -> ReuploadPlan {
        _ = try requireKeys()
        guard syncSettings != nil else { throw VaultError.syncNotConfigured }
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        await loadSharedVaultsIfNeeded()
        var plan = ReuploadPlan(deviceID: account.deviceID, vaults: [], sharedVaults: [])
        for info in try await vaults(includingDeleted: true).sorted(by: { $0.id.uuidString < $1.id.uuidString }) {
            let vault = ReuploadPlan.Vault(
                id: info.id, name: info.name, isPersonal: info.isPersonal, isDeleted: info.isDeleted,
                itemCount: try await store.records(in: info.id, kind: .item).count)
            if isMarkedShared(info.id, keys: keys, personalVaultID: account.personalVaultID) {
                plan.sharedVaults.append(vault)
            } else {
                plan.vaults.append(vault)
            }
        }
        return plan
    }

    /// Uploads again, from this device's local state, what a second or a new device needs after the sync store was
    /// reset: the person's confirmed decision, and the only way anything a reset removed is ever uploaded again
    /// (docs/02-architecture.md §7.10). `plan` is the `reuploadPlan()` the person was shown; if it no longer
    /// describes this device (an item arrived or was saved since), nothing is done and they are asked again
    /// (`reuploadNotConfirmed`).
    ///
    /// The call starts the store again where the transport knows of a reset (`SyncTransport.startStoreAgain`: a
    /// CloudKit zone this device had seen and found missing is created again), then runs one sync in which the
    /// account's objects are published into a store that holds none (the device registry entries this device
    /// retains, its account header, every vault key it has opened, every vault deletion it has verified), and each
    /// of the account's own vaults whose log holds something the store lacks writes one snapshot of everything this
    /// device holds, what it had merged from other devices included. Other devices do the same on their own
    /// person's confirmation; merges are joins, so the order does not matter.
    ///
    /// Nothing local is forgotten, overwritten or deleted: sequence numbers go on from where they were, the stash
    /// and held-aside versions stay where they are, and pending deletions go out as they always do. A shared vault
    /// is not uploaded (`SyncReport.reuploadRefused`, `AccountSyncReport.reuploadRefusals`). Needs the vault
    /// unlocked, and this device registered, not revoked, and following the current password.
    @discardableResult
    public func reuploadAfterStoreReset(confirming plan: ReuploadPlan) async throws -> AccountSyncReport {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let syncSettings else { throw VaultError.syncNotConfigured }
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        // A device move that is not complete would start this device's states over after the upload began, and the
        // sync publishes nothing until it is complete: the store would be started again and left empty (V51).
        guard account.migration == nil else { throw VaultError.deviceMigrationIncomplete }
        guard let view = try? await registry(account) else { throw VaultError.deviceRegistryUnavailable }
        switch view.state.standing(of: account.deviceID) {
        case .active: break
        case .revoked: throw VaultError.deviceRevoked
        case .unknown: throw VaultError.deviceNotRegistered
        }
        guard view.state.pendingCredentials.isEmpty else { throw VaultError.passwordChangedOnAnotherDevice }
        // Held from before the plan is checked, so that no ordinary sync merges anything between the person's
        // answer and the upload, or runs between starting the store again and filling it.
        guard !syncInFlight else { throw SyncError.syncInProgress }
        syncInFlight = true
        defer { syncInFlight = false }
        guard try await reuploadPlan() == plan else { throw VaultError.reuploadNotConfirmed }
        _ = try requireKeys(since: epoch)
        // Until each vault has handed on, or the store stands for everything it holds, the question stays open on
        // this device, whatever stops the upload part-way: a lock, the network, the app killed (review finding SR21).
        // Once the store is started again and the account's objects are in it, the transport's sign and the
        // account's are gone, and only the engine's own would still ask.
        try await markUploadUnfinished(account)
        try await syncSettings.transport.startStoreAgain()
        // Locked while the store was started: nothing is published as the person's answer (SR21).
        _ = try requireKeys(since: epoch)
        return try await runSync(reconcile: false, reuploadingSince: epoch)
    }

    /// The person's answer stands only while the vault is unlocked at the epoch it was given in: a sync that a lock
    /// overtook is an ordinary sync, a download, and publishes nothing as though asked (review finding SR21).
    func reuploadAnswered(_ epoch: UInt64?) -> Bool {
        guard let epoch else { return false }
        return keys != nil && lockEpoch == epoch
    }

    /// Marks every vault of this account's own that has published or merged a log as suspected of a reset
    /// (`SyncState.storeResetSuspected`), before the store is started again: the engine clears it when the vault
    /// hands on or when the store stands for everything it holds, so an upload stopped part-way asks again
    /// (`AccountSyncReport.storeNeedsReupload`), and nothing is snapshotted, collected or replayed meanwhile unasked.
    /// A shared vault is not uploaded from one member's device and is left alone.
    func markUploadUnfinished(_ account: AccountRecord) async throws {
        // Through the session's signed state (review finding Z20): a row saved around it carries no authenticator that
        // verifies, and would be read back as no state at all, forgetting what the device published.
        guard let state = syncState else { return }
        await loadSharedVaultsIfNeeded()
        for vaultID in try await vaultDirectory(account).keys.sorted(by: { $0.uuidString < $1.uuidString })
        where !isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID) {
            guard var vault = try await state.loadState(vaultID: vaultID), !vault.storeResetSuspected,
                Self.recordsSyncing(vault)
            else { continue }
            vault.storeResetSuspected = true
            try await state.saveState(vault)
        }
    }

    /// Whether this device has ever published or merged a vault's log: what tells a store that was emptied from one
    /// that is new (`syncAccountObjects`). Read from the sync state, which a reset of the store does not touch, and
    /// which a device move starts over carrying the fact (`SyncState.syncedBefore`, V49). A device that has only ever
    /// published the account's objects reads as new; nothing but those objects was ever in such a store.
    ///
    /// Also true if a vault of the account's holds an item or a description another device ID wrote (the review of the
    /// second merge's check, V49): only a merged log brings one here, so the store this device synced with held
    /// something. It can only make the sync stop and ask, never publish; it also asks where a device move left a row
    /// of the earlier ID behind (one that did not open, or a description of a vault whose state was none), which the
    /// person's yes then uploads.
    func hasSyncedBefore(_ account: AccountRecord) async throws -> Bool {
        let vaults = try await vaultDirectory(account).keys
        // The signed state only (Z20): a row the session did not sign is no state, and says nothing either way.
        if let state = syncState {
            for vaultID in vaults {
                guard let vault = try await state.loadState(vaultID: vaultID) else { continue }
                if Self.recordsSyncing(vault) { return true }
            }
        }
        for vaultID in vaults {
            for kind in [EnvelopeKind.item, .vaultMetadata] {
                let rows = try await store.records(in: vaultID, kind: kind)
                if rows.contains(where: { $0.deviceID != account.deviceID }) { return true }
            }
        }
        return false
    }

    /// Whether a vault's state says this device published or merged its log, or was started over by a device move
    /// after the installation had (`SyncState.syncedBefore`).
    static func recordsSyncing(_ state: SyncState) -> Bool {
        state.syncedBefore || state.lastPublishedSequence > 0 || !state.merged.isEmpty || !state.snapshots.isEmpty
    }

    /// The device move's first step (`completeDeviceMigration`, Z181; V49): each vault's state saved empty for the new
    /// ID, signed through `syncState`, keeping two facts the old ID's states held that are the installation's, not
    /// the ID's. Whether it had synced before (`hasSyncedBefore`, and the old ID's states, asked before any state is
    /// emptied), so that a store the person emptied is not filled again unasked from a restore onto other hardware
    /// (§7.10); a move made again after a first attempt emptied some states finds the fact in them. And each vault's
    /// `storeResetSuspected`, so that an upload after a reset that stopped part-way before the backup still asks
    /// (SR21); the engine keeps it in such a state until this device hands on (`SyncState.startedOverByMove`, set
    /// here with the first fact and cleared by that hand-on alone, V52). Both can only make a sync stop and ask.
    func startSyncStatesOver(_ account: AccountRecord, from previous: UUID, since epoch: UInt64) async throws {
        guard let state = syncState else { return }
        let vaults = try await vaultDirectory(account).keys
        var held: [UUID: SyncState] = [:]
        for vaultID in vaults {
            if let earlier = try await movedSyncState(vaultID: vaultID, from: previous, account: account) {
                held[vaultID] = earlier
            }
        }
        let syncedBefore = try await hasSyncedBefore(account) || held.values.contains(where: Self.recordsSyncing)
        for vaultID in vaults {
            _ = try requireKeys(since: epoch)
            var fresh = SyncState(vaultID: vaultID)
            fresh.syncedBefore = syncedBefore
            fresh.startedOverByMove = syncedBefore
            fresh.storeResetSuspected = held[vaultID]?.storeResetSuspected ?? false
            try await state.saveState(fresh)
        }
    }

    /// A vault's state as this session signed it for `account`'s device ID (a move made again) or for `previous`,
    /// the ID the move is from; `nil` for any other row (Z20). Read only for the two facts the move keeps.
    func movedSyncState(vaultID: UUID, from previous: UUID, account: AccountRecord) async throws -> SyncState? {
        if let current = try await syncState?.loadState(vaultID: vaultID) { return current }
        guard let row = try await syncSettings?.state.loadState(vaultID: vaultID), row.vaultID == vaultID,
            let signingKey = await trustedAccountSigningKey(account)
        else { return nil }
        let message = Self.syncStateMessage(row, deviceID: previous)
        guard
            (try? Signatures.verify(row.authenticator, for: message, domain: .syncState, signingKey: signingKey)) != nil
        else { return nil }
        return row
    }
}
