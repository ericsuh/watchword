import Foundation
import WatchwordCrypto
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
            if sharing.vaults[info.id] != nil {
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
        guard let state = syncSettings?.state else { return }
        await loadSharedVaultsIfNeeded()
        for vaultID in try await vaultDirectory(account).keys.sorted(by: { $0.uuidString < $1.uuidString })
        where sharing.vaults[vaultID] == nil {
            guard var vault = try await state.loadState(vaultID: vaultID), !vault.storeResetSuspected,
                vault.lastPublishedSequence > 0 || !vault.merged.isEmpty || !vault.snapshots.isEmpty
            else { continue }
            vault.storeResetSuspected = true
            try await state.saveState(vault)
        }
    }

    /// Whether this device has ever published or merged a vault's log: what tells a store that was emptied from one
    /// that is new (`syncAccountObjects`). Read from the sync state, which a reset of the store does not touch. A
    /// device that has only ever published the account's objects reads as new; nothing but those objects was ever
    /// in such a store.
    func hasSyncedBefore(_ account: AccountRecord) async throws -> Bool {
        guard let state = syncSettings?.state else { return false }
        for vaultID in try await vaultDirectory(account).keys {
            guard let vault = try await state.loadState(vaultID: vaultID) else { continue }
            if vault.lastPublishedSequence > 0 || !vault.merged.isEmpty || !vault.snapshots.isEmpty { return true }
        }
        return false
    }
}
