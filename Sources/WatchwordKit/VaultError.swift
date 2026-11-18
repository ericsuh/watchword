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
    /// The save would scope the item to hosts that resemble a saved site without being it, or that cannot be verified
    /// by eye, and the caller did not say the person confirmed them (PRD F11.7; review finding Z61). Nothing was
    /// written. The UI shows a confirmation naming each host and the item, and saves again with
    /// `save(_:confirmingHosts:)`.
    case hostsNeedConfirmation([HostConfirmation])
    /// A copy or move out of a shared vault would bring a member's scopes into another vault, where they would hide
    /// or stand beside the person's accounts, or name a look-alike host (review finding Z72). Nothing was written.
    /// The UI shows the concern and calls again with `confirming:` naming it.
    case transferNeedsConfirmation(TransferConcern)
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
    /// The device ID offered for a new device does not commit to the account under the key offered with it
    /// (`DeviceIdentifier`, review findings Z157 and Z162): it was made by an older build, or edited. Such a device
    /// would count in no shared vault, and what it wrote there would reach nobody, so it is not registered; the new
    /// device makes its identity again (`prepareDeviceIdentity`).
    case deviceIDDoesNotCommit
    /// The transport holds no account header for the account, no usable device registry, or no key for the
    /// personal vault: there is nothing to enrol from (yet).
    case accountNotOnTransport
    /// The password opened an account header, but the device registry shows the password has been changed since:
    /// the store presented an old header (A1), or the person typed an old password. Use the current one.
    case passwordSuperseded
    /// The password opened a password change made on another device, and that change's own history removes this
    /// device from the account. It is not followed here: this device keeps the credentials it has, and the change
    /// stays pending (review finding Z1). If the person did remove this device, it is to be erased and enrolled
    /// again; if they did not, the device that made the change is the one to remove.
    case passwordChangeRevokesThisDevice
    /// More devices have published a password change than one unlock tries (`maximumHeaderAttempts`; each costs a
    /// key derivation whose parameters its author chose), and none of those tried opened. The password may be right
    /// for one that was not tried: unlock with the password this device still has (`ignoringPasswordChange`) and
    /// name the device that made the change (`followPasswordChange(by:current:password:)`).
    case tooManyPasswordChangesPending
    /// `followPasswordChange` named a device that has published no password change this device could follow.
    case noPasswordChangeToFollow(UUID)
    /// The Personal vault the local account row names is not the one the account header seals under the Account
    /// Unlock Key, or that binding cannot be checked: the row was edited (A8), or its key is one that reached this
    /// account by another member's grant. Refused at every unlock, before a key is installed (review finding Z5).
    case personalVaultMismatch
    /// What was asked for needs the account password in the same call (the Emergency Kit once it has been confirmed,
    /// or after a quick unlock; review finding Z86).
    case accountPasswordRequired
}

/// A host a save would add to an item's scopes that the person has to confirm by name first (PRD F11.7).
public struct HostConfirmation: Hashable, Sendable {
    /// The host as the scope stores it: what `save(_:confirmingHosts:)` takes back.
    public let host: String
    /// The saved hosts it resembles, sorted. Empty when it resembles none and simply cannot be verified by eye (a
    /// label outside ASCII, punycode, mixed scripts).
    public let resembles: [String]

    public init(host: String, resembles: [String]) {
        self.host = host
        self.resembles = resembles
    }
}

/// What copying or moving an item out of a shared vault would do to AutoFill (review finding Z72): the questions an
/// import entry raises (`ImportConcern`), asked of an item a member wrote. In the shared vault its scopes were a
/// member's word, shadowing nothing outside the vault and vouching for no look-alike (Z60); in the destination they
/// become the person's.
public struct TransferConcern: Hashable, Sendable {
    /// Saved accounts the copy would outrank on a host they are offered on now.
    public var hidden: [AffectedAccount]
    /// Saved accounts it would be offered beside.
    public var beside: [AffectedAccount]
    /// The item's scopes cover more saved hosts than were examined.
    public var overlapIsTruncated: Bool
    /// Hosts of the item that resemble a saved site without being it, or cannot be verified by eye.
    public var lookAlikeHosts: [HostConfirmation]

    public init(
        hidden: [AffectedAccount] = [], beside: [AffectedAccount] = [], overlapIsTruncated: Bool = false,
        lookAlikeHosts: [HostConfirmation] = []
    ) {
        self.hidden = hidden
        self.beside = beside
        self.overlapIsTruncated = overlapIsTruncated
        self.lookAlikeHosts = lookAlikeHosts
    }

    public var isEmpty: Bool { hidden.isEmpty && beside.isEmpty && !overlapIsTruncated && lookAlikeHosts.isEmpty }
}
