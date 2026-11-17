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
        guard try await reuploadPlan() == plan else { throw VaultError.reuploadNotConfirmed }
        _ = try requireKeys(since: epoch)
        // Held from before the store is started again, so that no ordinary sync runs between the two steps.
        guard !syncInFlight else { throw SyncError.syncInProgress }
        syncInFlight = true
        defer { syncInFlight = false }
        try await syncSettings.transport.startStoreAgain()
        return try await runSync(reconcile: false, reuploading: true)
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
