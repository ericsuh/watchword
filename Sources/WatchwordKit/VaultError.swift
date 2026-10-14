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
    case quickUnlockRefused(QuickUnlockRefusal)
    case biometricAuthenticationFailed
    case itemNotFound(UUID)
    case unknownVault(UUID)
    /// Moving an item between vaults is F2.2, which arrives with shared vaults (milestone 4).
    case vaultChangeNotSupported
    /// A scope that spans unrelated owners (PRD F11.2).
    case scopeRejected(ScopeValidationError)
    /// A decrypted record's own identity disagrees with where it was stored. Authentication already binds the
    /// location, so this means a writer holding the vault key lied in the plaintext.
    case recordMismatch(UUID)
    case itemNotTrashed(UUID)
    case versionOverflow
}
