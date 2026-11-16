import Foundation
import WatchwordMatching

/// Why a `VaultSession` operation refused. Wrong passwords and wrong Secret Keys are not here: they surface as
/// `CryptoError.authenticationFailed`, which deliberately cannot tell the two apart (or either from tampering).
public enum VaultError: Error, Equatable, Sendable {
    case noAccount
    case accountAlreadyExists
    case locked
    case alreadyUnlocked
    /// `lock()` ran while an unlock was in flight; the lock wins and the derived keys were discarded.
    case lockedDuringUnlock
    case passwordTooShort(minimum: Int)
    /// This device has the account's store but not its Secret Key (a restored backup, since Keychain items are
    /// device-only). Unlock with the Secret Key from the Emergency Kit (PRD F5.2).
    case secretKeyMissing
    /// The Secret Key entered belongs to another account (its setup code names a different account ID).
    case secretKeyForAnotherAccount
    case vaultKeyMissing(vaultID: UUID)
    /// The vault key's wrap is present but does not open, although the keyset (and so the password) did: the record
    /// was tampered with. Deliberately not `authenticationFailed`, which would tell the person their password is wrong.
    case vaultKeyUnreadable(vaultID: UUID)
    case quickUnlockRefused(QuickUnlockRefusal)
    case biometricAuthenticationFailed
    case itemNotFound(UUID)
    /// The item is no longer at the version the caller read: a sync merged another device's edit, or another write
    /// landed, in between. Nothing was written; reopen the item and apply the change again (docs/06 §H, Y29).
    case versionConflict(UUID)
    case unknownVault(UUID)
    /// `save` cannot change an item's vault: use `move(itemID:to:)` or `copy(itemID:to:)` (PRD F2.2).
    case vaultChangeNotSupported
    /// The vault was deleted, here or on another device. Nothing new is saved into it; what it still holds can be
    /// moved to another vault or deleted.
    case vaultDeleted(UUID)
    /// The Personal vault can be neither deleted nor shared (PRD F2.1).
    case cannotDeletePersonalVault
    /// A vault name must have between 1 and `VaultMetadataCodec.maximumNameLength` characters.
    case invalidVaultName
    /// `deleteVault` was confirmed for another number of items than the vault holds now: something arrived since the
    /// person was asked. Ask again.
    case vaultDeletionNotConfirmed(itemCount: Int)
    /// The item holds values sync kept for the person to choose between (PRD F7.6). Moving it would discard them;
    /// resolve the conflicts first.
    case itemHasUnresolvedValues(UUID)
    /// The item is in the trash; restore it before moving it.
    case itemIsTrashed(UUID)
    /// A scope that spans unrelated owners (PRD F11.2).
    case scopeRejected(ScopeValidationError)
    /// A decrypted record's own identity disagrees with where it was stored. Authentication already binds the
    /// location, so this means a writer holding the vault key lied in the plaintext.
    case recordMismatch(UUID)
    case itemNotTrashed(UUID)
    case versionOverflow
    /// The account was erased but some Keychain items could not be deleted.
    case keychainCleanupIncomplete(Int)
    /// `sync()` on a session built without `SyncSettings`.
    case syncNotConfigured
    /// A hygiene call on a session built without `HygieneSettings` (docs/02-architecture.md §13.8).
    case hygieneNotConfigured
    /// A conflict can only be resolved to a value the item holds for that group: the one shown or one kept in
    /// `Item.conflicts` (PRD F7.6).
    case conflictValueNotHeld
    /// The account password was changed on another device and this one has been told (a newer account header, signed
    /// by a registered device). The old password is refused; enter the new one (PRD F10.1).
    case passwordChangedOnAnotherDevice
    /// The account header in the local store is older than the credentials this device has already followed: the
    /// file was rolled back to before a password change (A8). Refused.
    case accountHeaderRolledBack
    /// The device registry cannot be evaluated on this device: entries are missing from the local store, or the
    /// Keychain holds no anchor for it. Nothing from the transport is trusted until a sync restores it.
    case deviceRegistryUnavailable
    /// This device has been revoked from the account. It publishes nothing; erase it, or enrol it again.
    case deviceRevoked
    case unknownDevice(UUID)
    /// A device cannot revoke itself: revoke it from another device, or delete the account from this one.
    case cannotRevokeThisDevice
    /// Enrolling a device needs an empty store and a configured sync transport.
    case enrolmentUnavailable
    /// The transport holds no account header for the account, no usable device registry, or no key for the
    /// personal vault: there is nothing to enrol from (yet).
    case accountNotOnTransport
    /// The password opened an account header, but the device registry shows the password has been changed since:
    /// the store presented an old header (A1), or the person typed an old password. Use the current one.
    case passwordSuperseded
}
