import Foundation
import WatchwordCrypto
import WatchwordInterchange
import WatchwordKit
import WatchwordSharing
import WatchwordStore
import WatchwordSync

/// The sentence a screen shows for an error a session call threw. Words only: whether to refuse was decided where
/// the error was thrown, and nothing here tells a wrong password from tampering (both are
/// `CryptoError.authenticationFailed`).
public enum ErrorWording {
    /// What the person sees. An empty string means they cancelled and nothing needs saying.
    public static func message(for error: any Error) -> String {
        switch error {
        case let error as VaultError: return vault(error)
        case let error as SharedVaultError: return sharedVault(error)
        case let error as SharingError: return sharing(error)
        case let error as InterchangeSessionError: return interchange(error)
        case is InterchangeError:
            return
                "The file could not be read. Check that it is an export from the app you chose, and not changed since."
        case is SharingFormatError:
            return "That code is not one Watchword made. Copy it again, exactly as it was sent."
        case CryptoError.authenticationFailed:
            return "Incorrect password."
        case KeychainError.userCancelled, is CancellationError:
            return ""
        case SyncError.syncInProgress:
            return "A sync is already running."
        case RecordStoreError.versionConflict:
            return "This item changed while you were editing it. Review it and try again."
        default:
            return "Something went wrong. Your vault is unchanged."
        }
    }

    static func vault(_ error: VaultError) -> String {
        switch error {
        case .locked, .lockedDuringUnlock:
            return "Watchword locked. Unlock it and try again."
        case .passwordTooShort(let minimum):
            return "Use at least \(minimum) characters."
        case .secretKeyMissing:
            return "This device does not have your Secret Key. Enter it from your Emergency Kit."
        case .secretKeyForAnotherAccount:
            return "That Secret Key belongs to another account."
        case .scopeRejected:
            return "That website address is too broad. Enter the site's own domain, such as example.com."
        case .hostsNeedConfirmation(let hosts):
            return "Check " + hosts.map { HostText.ascii($0.host) }.joined(separator: ", ")
                + " before adding it: it is not a site this item is saved for."
        case .quickUnlockRefused(let reason):
            switch reason {
            case .enrolmentChanged:
                return "Biometric settings changed. Enter your password, then turn quick unlock on again."
            case .biometryUnavailable:
                return "Biometric unlock is not available on this device."
            default:
                return "Enter your account password."
            }
        case .biometricAuthenticationFailed:
            return "Not recognised. Try again or enter your password."
        case .conflictValueNotHeld:
            return "That choice is no longer available. Review the item and try again."
        case .versionConflict:
            return "This item changed while you were editing it. Review it and try again."
        case .passwordChangedOnAnotherDevice:
            return "Your account password was changed on another device. Enter the new password."
        case .passwordSuperseded:
            return "That password has been changed since. Enter the current one."
        case .accountPasswordRequired:
            return "Enter your account password."
        case .passwordChangeRevokesThisDevice:
            return "That password belongs to a change that removed this device from your account, so it is not "
                + "used here. If you did not remove this device, unlock with the password it still has and remove "
                + "the device that made the change."
        case .tooManyPasswordChangesPending:
            return "Several devices say they changed your account password, more than can be checked from here. "
                + "Unlock with the password this device still has, then choose the device you changed it on under "
                + "Devices."
        case .noPasswordChangeToFollow:
            return "That device has not changed the account password."
        case .personalVaultMismatch:
            return "This device's copy of your account does not match your account password's record of "
                + "it, so it was not opened. Erase this device and set it up again from your Emergency Kit."
        case .deviceRevoked:
            return "This device has been removed from your account. It can no longer sync."
        case .cannotRevokeThisDevice:
            return "This device cannot remove itself. Remove it from another device."
        case .unknownDevice:
            return "That device is not part of your account any more."
        case .invalidVaultName:
            return "Give the vault a name of 1 to \(VaultMetadataCodec.maximumNameLength) characters."
        case .cannotDeletePersonalVault:
            return "The Personal vault cannot be deleted or shared."
        case .vaultDeleted:
            return "That vault was deleted. Move what it still holds to another vault."
        case .vaultDeletionNotConfirmed:
            return "Something arrived in the vault since you were asked. Review it and try again."
        case .itemHasUnresolvedValues:
            return "Choose between the item's conflicting values before moving it."
        case .itemIsTrashed:
            return "Restore the item from the Trash first."
        case .syncNotConfigured:
            return "Sync between your devices is not available in this version yet."
        case .hygieneNotConfigured:
            return "The security report is not available in this version yet."
        case .deviceRegistryUnavailable:
            return "This device cannot check your other devices yet. Sync, then try again."
        case .accountHeaderRolledBack:
            return "Watchword's files on this device are older than expected and were not trusted."
        case .vaultKeyMissing, .vaultKeyUnreadable:
            return "This device does not have that vault's key yet. Sync, then try again."
        default:
            return "Something went wrong. Your vault is unchanged."
        }
    }

    static func sharedVault(_ error: SharedVaultError) -> String {
        switch error {
        case .sharingNotConfigured, .syncNotConfigured:
            return "Sharing is not available in this version yet."
        case .personalVaultCannotBeShared:
            return "The Personal vault is never shared. Create a vault to share."
        case .notShared:
            return "That vault is not shared."
        case .writeRefused(let refusal):
            return readOnly(refusal)
        case .notOwner:
            return "Only the vault's owner can delete it. Leave it instead."
        case .awaitingKey:
            return "This device has not received the vault's current key yet. Sync, then try again."
        case .keyIDInUse:
            return "That invitation conflicts with a vault already on this device, and was refused."
        case .ownerUnknown:
            return "This device cannot yet tell whose shared vault that is, so it cannot accept an invitation to it. "
                + "Sync, then try again."
        case .ownerDisputed:
            return VaultRow.ownerDisputedReason
        case .stillAMember:
            return "You are still a member of this vault. Leave it first; its items can be removed from this device "
                + "once you are no longer a member."
        case .unsharedWork(_, let count):
            return "\(count) change(s) made on this device never reached the vault's other members. Removing the "
                + "vault's items from this device would discard them for good, so nothing was removed."
        case .historyCompacted:
            return "This vault has been in use too long to be shared as it is: its sync history was compacted. "
                + "Create a new vault, share that one, and move the items you want to share into it."
        case .ledgerUnavailable:
            return "This shared vault is not set up on this device yet, so it cannot be changed from here. "
                + "Accept its invitation on this device first."
        }
    }

    /// Why a shared vault is read-only for this account (PRD F4.5; docs/02-architecture.md §8.9).
    public static func readOnly(_ refusal: WriteRefusal) -> String {
        switch refusal {
        case .readOnly:
            return "You can read this shared vault but not change it."
        case .notAMember:
            return "You are no longer a member of this shared vault."
        case .vaultDeleted:
            return "This shared vault was deleted by its owner."
        case .removalPending, .unknownEpoch:
            return "Changes to this shared vault's members are still arriving. Sync, then try again."
        case .requiresNewerVersion:
            return "This shared vault was changed by a newer version of Watchword. It is read-only on this device "
                + "until you update the app."
        }
    }

    static func sharing(_ error: SharingError) -> String {
        switch error {
        case .unknownAccount, .directoryMismatch:
            return "No Watchword account was found for that ID."
        case .keySubstituted:
            return "This person's keys are not the ones you verified before. Do not continue until you have compared "
                + "safety numbers with them again."
        case .fingerprintMismatch:
            return "The safety number does not match. Compare it with the other person again, digit by digit."
        case .fingerprintNotVerified:
            return "Compare safety numbers first."
        case .invitationAlreadyCompleted:
            return "That invitation has already been used."
        case .vaultOwnerConflict:
            return "That invitation names a vault this device already holds under another owner, and was refused."
        case .notAMember, .grantNotFound, .notEntitledToKey:
            return "The invitation has not reached the shared storage yet, or was withdrawn. Try again later."
        case .ownKeySubstituted:
            return "The invitation was made for keys that are not yours, and was refused."
        case .notPermitted:
            return "Only the owner or an administrator can do that."
        case .ownerCannotLeave:
            return "The owner cannot leave a vault. Delete it instead."
        case .vaultDeleted:
            return "This shared vault was deleted by its owner."
        case .nothingToDo:
            return "That has already happened."
        case .requiresNewerVersion:
            return readOnly(.requiresNewerVersion)
        default:
            return "The shared vault could not be updated. Sync, then try again."
        }
    }

    static func interchange(_ error: InterchangeSessionError) -> String {
        switch error {
        case .noPendingImport:
            return "The import was cancelled or Watchword locked. Choose the file again."
        case .decisionRequired:
            return "Choose what to do with every duplicate first."
        case .unknownMatch:
            return "That item changed since the file was read. Choose the file again."
        case .passphraseTooShort(let minimum):
            return "Use an archive passphrase of at least \(minimum) characters."
        case .archiveFromAnotherAccount:
            return "This archive was made by another account. Enter the Secret Key from that account's Emergency Kit."
        case .noVaultChosen:
            return "Choose at least one vault."
        case .importInterrupted(let saved):
            return
                "Watchword locked during the import. \(saved) item(s) were saved; choose the file again for the rest."
        case .mergeNeedsConfirmation:
            return "An address a merge would add changes which account AutoFill offers. Confirm it, or leave it out."
        }
    }
}
