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
    ///
    /// Internal, for tests (review finding Z78): the items without their vaults' standing would be taken as the
    /// person's own by whatever published or ranked them. AutoFill is given `credentialSnapshot()`.
    func credentialItems() async throws -> [Item] {
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
        try await translatingForAutoFill { try await autoFillContents() }
    }

    private func autoFillContents() async throws -> CredentialSnapshot {
        let listing = try await items().items
        let withheld = try await vaultsWithheldFromAutoFill()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        let personal = account.personalVaultID
        let writtenOutside = await vaultsWrittenOutsideTheAccount(listing, account: account)
        let described = try await vaults(includingDeleted: true).filter { !withheld.contains($0.id) }.map {
            CredentialVaultInfo(id: $0.id, name: $0.name, isShared: $0.isShared || writtenOutside.contains($0.id))
        }
        return CredentialSnapshot(
            items: withheld.isEmpty ? listing : listing.filter { !withheld.contains($0.vaultID) },
            vaults: described, defaultVaultID: personal)
    }

    /// The vaults, other than Personal, holding an item whose clock names a device that is not this account's (review
    /// finding Z77). On the owner's devices a vault is shared by the account's marker row and the sharing state, which
    /// whoever edits the App Group store while the app is locked (A8) can delete, and which the extension does not
    /// sync back; an item's clock is inside its ciphertext, authenticated under the vault key, and a member's edit
    /// carries their device there for as long as the item exists. So such a vault is shared for AutoFill whatever the
    /// rows say. This account's devices are the registry's, revoked ones included; with no registry to read, only this
    /// device counts as the account's, which errs towards shared.
    func vaultsWrittenOutsideTheAccount(_ items: [Item], account: AccountRecord) async -> Set<UUID> {
        var own: Set<UUID> = [account.deviceID]
        if let view = try? await registry(account) {
            own.formUnion(view.state.devices.keys)
            own.formUnion(view.state.revoked.keys)
        }
        var vaults = Set<UUID>()
        for item in items where item.vaultID != account.personalVaultID && !vaults.contains(item.vaultID) {
            if item.clock.entries.keys.contains(where: { !own.contains($0) }) { vaults.insert(item.vaultID) }
        }
        return vaults
    }

    /// The saved items as the gate ranks among them, with the session's answer for which vaults are the person's
    /// own: what AutoFill is given, less the trash and the scopes the policy refuses. The item editor's confirmation
    /// and the import preview judge hosts against this, so that what they call a look-alike, or an account a new
    /// item would hide, is what the extension would (review findings Z61, Z62, Z65).
    public func savedSites() async throws -> SavedSites {
        let contents = try await autoFillContents()
        return SavedSites(
            stored: contents.items, ownVaults: Set(contents.vaults.filter { !$0.isShared }.map(\.id)))
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
    /// every scope through `ScopePolicy`, as `save` does, and judges every host it adds as `save` does (F11.7):
    /// only the hosts in `confirmingHosts` may need a confirmation (review finding Z78; there is no caller that
    /// answers for every host).
    @discardableResult
    public func saveCredentialItem(
        _ item: Item, replacingVersion: UInt64?, confirmingHosts: Set<String>
    ) async throws -> Item {
        try await translatingForAutoFill {
            try await save(
                item, expecting: replacingVersion.map(WriteExpectation.version) ?? .absent,
                confirmed: .hosts(confirmingHosts))
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
            case .hostsNeedConfirmation(let hosts): throw CredentialVaultError.hostsNeedConfirmation(hosts.map(\.host))
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
