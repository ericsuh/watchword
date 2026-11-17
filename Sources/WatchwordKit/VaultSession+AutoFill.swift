import Foundation
import WatchwordAutoFill
import WatchwordMatching
import WatchwordModel
import WatchwordStore

// The session as the AutoFill core's vault (docs/02-architecture.md §9.1, §9.2). The extension process builds a
// session over the App Group store and the shared Keychain, unlocks it with `quickUnlock(prompt:)` (the Local Unlock
// Key the Keychain releases after biometric authentication, then the AUK, then the keyset; never a boolean) or with
// the password, and hands it to `CredentialProviderModel` as its `CredentialVault`. Nothing else is exposed for the
// extension: no state that unlocks, and no read that skips the lock check.
extension VaultSession: CredentialVault {
    /// Every item of every vault the session holds, trashed and archived ones included, each read through the
    /// row it was stored in (`openItem`) and presented as the person sees it (what a vault's deletion left is in the
    /// trash). The store keeps one row per item ID whatever its vault, and sync keeps aside a record that names an ID
    /// held in another vault (`SyncReport.collided`), so an ID occurs once; a move is a copy under a derived ID plus
    /// the original trashed in one commit, so the original is never readable beside the copy as a fillable item.
    ///
    /// Not the items of a shared vault this account is no longer a member of, or of one with no ledger on this device
    /// (`vaultsWithheldFromAutoFill`, review finding Z45): they stay on the device until the person removes them, and
    /// they are not offered to a page.
    public func credentialItems() async throws -> [Item] {
        try await credentialSnapshot().items
    }

    /// The items AutoFill is given, and whose each vault is (review finding Z60).
    ///
    /// Whether a vault is shared is the session's one answer, `isMarkedShared` (through `VaultInfo.isShared`): a
    /// ledger loaded, the account's signed marker, a key that arrived by grant, a sharing state that names the
    /// vault, or markers not read yet. Never the item's claim, and never the vault's name. The vaults are described
    /// after the items are read: a vault becomes shared before any other member's item can be merged into it, so an
    /// item a member wrote is never returned beside a description from before the vault was shared. An extension
    /// process that was not given the sharing state (`configureSharing`) sees every vault but the Personal one as
    /// shared, or withheld: closed, not open.
    public func credentialSnapshot() async throws -> CredentialSnapshot {
        try await translatingForAutoFill {
            let listing = try await items().items
            let withheld = try await vaultsWithheldFromAutoFill()
            guard let personal = try await loadAccount()?.personalVaultID else { throw CredentialVaultError.noAccount }
            let described = try await vaults(includingDeleted: true).filter { !withheld.contains($0.id) }.map {
                CredentialVaultInfo(id: $0.id, name: $0.name, isShared: $0.isShared)
            }
            return CredentialSnapshot(
                items: withheld.isEmpty ? listing : listing.filter { !withheld.contains($0.vaultID) },
                vaults: described, defaultVaultID: personal)
        }
    }

    /// The actor's own lock check: the model calls it as its last suspension before it hands a secret back, so a
    /// `lock()` that ran since the items were read wins.
    public func confirmUnlocked() async throws {
        guard keys != nil else { throw CredentialVaultError.locked }
    }

    public func defaultVaultID() async throws -> UUID {
        guard keys != nil else { throw CredentialVaultError.locked }
        guard let id = try await translatingForAutoFill({ try await loadAccount()?.personalVaultID }) else {
            throw CredentialVaultError.noAccount
        }
        return id
    }

    /// WebAuthn's BS flag, true to the facts: an item stored here reaches another copy only if this session syncs.
    public func isBackedUp() async throws -> Bool {
        guard keys != nil else { throw CredentialVaultError.locked }
        return isSyncConfigured
    }

    /// A compare-and-swap inside the session's own write: the stored item must be absent (`replacingVersion == nil`)
    /// or at `replacingVersion`, checked against the row the write read and committed conditionally on it, so a save
    /// or a sync merge landing in between is refused with `versionConflict`, never merged over. The session owns the
    /// version, dates, history, trash state and sync metadata, stamps the edit through `ItemMerge.stamped`, and runs
    /// every scope through `ScopePolicy`, as `save` does.
    @discardableResult
    public func saveCredentialItem(_ item: Item, replacingVersion: UInt64?) async throws -> Item {
        try await translatingForAutoFill {
            try await save(item, expecting: replacingVersion.map(WriteExpectation.version) ?? .absent)
        }
    }

    private func translatingForAutoFill<Value: Sendable>(_ body: () async throws -> Value) async throws -> Value {
        do {
            return try await body()
        } catch let error as CredentialVaultError {
            throw error
        } catch let error as VaultError {
            switch error {
            case .locked, .lockedDuringUnlock: throw CredentialVaultError.locked
            case .noAccount: throw CredentialVaultError.noAccount
            case .itemNotFound(let id): throw CredentialVaultError.itemNotFound(id)
            case .versionConflict(let id): throw CredentialVaultError.versionConflict(id)
            case .scopeRejected(let reason): throw CredentialVaultError.scopeRejected(reason)
            default: throw CredentialVaultError.failed("VaultError")
            }
        } catch RecordStoreError.versionConflict(let id) {
            // The store's own check: a write committed between this write's read and its commit.
            throw CredentialVaultError.versionConflict(id)
        } catch {
            // The type's name only: an arbitrary error's description could carry anything.
            throw CredentialVaultError.failed(String(describing: type(of: error)))
        }
    }
}
