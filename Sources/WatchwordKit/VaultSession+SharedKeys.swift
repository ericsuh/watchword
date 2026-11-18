import Foundation
import WatchwordCrypto
import WatchwordSharing
import WatchwordStore

// Which keys of a shared vault a device uses, and what happens when the account's own devices disagree about whose
// the vault is (docs/02-architecture.md §8.10; review finding Z59).
//
// A device that holds nothing of a vault can be led into a chain someone else signed for the same vault ID: the store
// (A1) withholds everything the account's directory holds of the vault, and whoever the person has reason to verify
// files a chain listing the person under their real keys and sends an invitation naming themselves. Nothing on the
// device can tell, so it joins (`knownOwner` has nothing to compare with). Two rules keep that from reaching the
// account's real items:
//
// - **A key is resident for a vault with a ledger only if that ledger hands it to this account.** A key the device
//   opened from a grant of the ledger is listed in `SharedVault.verifiedKeys`; one the account's directory brings from
//   another device is made resident only once a grant the ledger entitles this account to shows the same bytes. A key
//   ID alone shows nothing: key IDs are public, and the chain's signer chooses the IDs it names. A key of the
//   account's own making (the genesis key of a vault it shared) is resident only where the ledger's owner is this
//   account. So the device never opens what the account's other devices wrote under the real chain's keys, and never
//   seals it again under the other chain's.
// - **A vault whose owner the account's devices disagree about is held closed, ledger or not** (`isOwnerDisputed`):
//   its markers name two owners, or this device's ledger names an owner its account's marker does not. No current
//   key, so nothing is sealed, sealed again or published; no proposal, plan, grant or invitation; every write
//   refused (`SharedVaultError.ownerDisputed`); not offered to AutoFill; and the vault is listed as closed and
//   disputed. Both sides hold a chain verified to someone the person compared a safety number with.
//
// Nothing ends a dispute in this version. A marker is never retired: the account key signs both, and a device revoked
// since still holds that key, so a retirement it could sign would reopen what the dispute closes. What the person can
// do is read the vault's items, copy them into a vault of their own, and share that one again. A retirement the person
// chooses, signed by the account and a device registered now, is the design that would end one; it is tracked.
extension VaultSession {
    /// Whether the account's devices disagree about whose `vaultID` is: two of its markers name different owners, or
    /// the ledger this device holds names an owner other than the one its account's marker names.
    func isOwnerDisputed(_ vaultID: UUID) -> Bool {
        if sharing.markerConflicts.contains(vaultID) { return true }
        if let owner = sharing.vaults[vaultID]?.ledger.owner.accountID, let marked = sharing.markers[vaultID] {
            return owner != marked
        }
        return false
    }

    /// Throws `ownerDisputed` for a vault the account's devices disagree about.
    func requireOwnerUndisputed(_ vaultID: UUID) throws {
        if isOwnerDisputed(vaultID) { throw SharedVaultError.ownerDisputed(vaultID) }
    }

    /// Whether `key`, of a vault this device holds `vault`'s ledger for, may be used here: one that arrived by grant
    /// only if this device has seen the ledger hand it to this account; one of the account's own making only if the
    /// ledger's owner is this account.
    static func ledgerVouches(for key: VaultKey, in vault: SharedVault, account: UUID) -> Bool {
        key.arrivedByGrant ? vault.verifiedKeys.contains(key.key.keyID) : vault.ledger.owner.accountID == account
    }

    /// Takes off residency every key of a vault this device holds a ledger for that the ledger does not vouch for. Run
    /// whenever keys are made resident from the store (unlock, the directory) and whenever a ledger is loaded. The
    /// keys are dropped, not zeroised: a call that read one before a suspension may still hold it, and its bytes are
    /// zeroised when the last reference goes.
    func withholdUnvouchedKeys() {
        guard let current = keys, !sharing.vaults.isEmpty else { return }
        let me = account?.accountID ?? current.keyset.accountID
        var vaultKeys = current.vaultKeys
        for (keyID, key) in current.vaultKeys {
            guard let vault = sharing.vaults[key.vaultID] else { continue }
            if !Self.ledgerVouches(for: key, in: vault, account: me) { vaultKeys[keyID] = nil }
        }
        guard vaultKeys.count != current.vaultKeys.count else { return }
        keys = UnlockedKeys(accountUnlockKey: current.accountUnlockKey, keyset: current.keyset, vaultKeys: vaultKeys)
    }

    /// Makes resident the keys of `vaultID` this device holds wraps of and has not made resident, where the ledger
    /// vouches for them; for one that arrived by grant and is not yet known to be the ledger's, the grant of that key
    /// ID to this account is fetched and opened under the ledger, and the key is taken only if its bytes are the
    /// grant's. Returns whether a key was made resident.
    @discardableResult
    func admitVaultKeys(_ vaultID: UUID) async throws -> Bool {
        let epoch = lockEpoch
        guard keys != nil, sharing.vaults[vaultID] != nil, let account = try await loadAccount() else { return false }
        let rows = try await store.records(in: vaultID, kind: .vaultKeyWrap)
        var admitted = false
        for row in rows.sorted(by: { $0.recordID.uuidString < $1.recordID.uuidString }) where row.vaultID == vaultID {
            let current = try requireKeys(since: epoch)
            guard current.vaultKeys[row.recordID] == nil, let vault = sharing.vaults[vaultID],
                let key = try? VaultKey.unwrap(
                    row.envelope, vaultID: vaultID, keyID: row.recordID, with: current.keyset)
            else { continue }
            if !Self.ledgerVouches(for: key, in: vault, account: account.accountID) {
                guard key.arrivedByGrant, vault.ledger.keyEpoch(of: row.recordID) != nil else { continue }
                let grants = try await listSharingObjects(
                    prefix: SharingObjectLocation.grantPrefix(
                        vaultID: vaultID, keyID: row.recordID, recipient: account.accountID),
                    maximumLength: KeyGrantCodec.encodedLength)
                let keyset = try requireKeys(since: epoch).keyset
                guard let ledger = sharing.vaults[vaultID]?.ledger,
                    let granted = try? ledger.openGrant(of: row.recordID, from: grants, as: keyset)
                else { continue }
                let same = granted.hasSameMaterial(as: key)
                granted.zeroise()
                guard same else { continue }
                sharing.vaults[vaultID]?.verifiedKeys.insert(row.recordID)
                sharing.vaults[vaultID]?.indexChanged = true
            }
            let installed = try requireKeys(since: epoch)
            guard installed.vaultKeys[row.recordID] == nil else { continue }
            var vaultKeys = installed.vaultKeys
            vaultKeys[row.recordID] = key
            keys = UnlockedKeys(
                accountUnlockKey: installed.accountUnlockKey, keyset: installed.keyset, vaultKeys: vaultKeys)
            admitted = true
        }
        // Segments sealed under a key that has just been made resident were waited at: judged now (S41).
        if admitted { requestReplay(vaultID) }
        return admitted
    }
}
