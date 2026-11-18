import Foundation
import WatchwordSharing

/// What a device keeps about the shared vaults it takes part in (docs/02-architecture.md §8.8), as opaque blobs by
/// vault. Every blob is either signed by the account's own key and verified again on load (the saved ledger, a
/// rotation plan, the stream index) or re-checked from what it says (a proposal is a membership record, verified by
/// the ledger before it is published again; the owner's account ID only selects which pin anchors the ledger), so a
/// file edited or planted on the device (A8) can delete trust, never add it.
///
/// Production: `SQLiteSharingStore`, a database of its own beside the record store. Tests: `InMemorySharingStateStore`.
public protocol SharingStateStore: Sendable {
    /// Every vault this device holds a membership ledger for, including those its account was removed from or left
    /// (a device keeps that ledger, review finding S26).
    func sharedVaultIDs() async throws -> [UUID]
    func value(_ key: SharingStateKey, vaultID: UUID) async throws -> [UInt8]?
    /// Stores `value`, or removes the entry when it is `nil`.
    func setValue(_ value: [UInt8]?, for key: SharingStateKey, vaultID: UUID) async throws
}

public enum SharingStateKey: String, Sendable, CaseIterable {
    /// The owner's account ID: which verified contact the saved ledger is anchored to.
    case owner
    /// `MembershipLedger.persisted(signedBy:)`.
    case ledger
    /// `RotationPlan.encoded()`, while a plan is unfinished.
    case plan
    /// The membership records this device proposed and has not seen adopted, each length-prefixed.
    case proposals
    /// Which segment of which device's stream first carried each record version, and the head the vault was last
    /// judged at (`SharedStreamIndex`), signed.
    case streamIndex
    /// What this device has anchored of the other members' device registries (`MemberRegistryPins`), signed: for each
    /// account and signing key the vault's chain lists, the genesis entry and the credential entry it follows
    /// (review finding Z6).
    case memberDevices
    /// The vault keys that arrived by grant which this device has checked against a grant its saved ledger entitles
    /// this account to, byte for byte (`SharedKeyProvenance`, review finding Z59), signed: only those are made
    /// resident for the vault.
    case vaultKeys
    /// The versions this device's own take-out held aside before they were published (`SharedStreamIndex.ownTakenOut`),
    /// signed, in a row of their own so that they survive the index being refused or rebuilt (review finding Z121).
    case ownTakenOut
}

public actor InMemorySharingStateStore: SharingStateStore {
    private var values: [UUID: [SharingStateKey: [UInt8]]] = [:]

    public init() {}

    public func sharedVaultIDs() -> [UUID] {
        values.filter { $0.value[.ledger] != nil }.keys.sorted { $0.uuidString < $1.uuidString }
    }

    public func value(_ key: SharingStateKey, vaultID: UUID) -> [UInt8]? {
        values[vaultID]?[key]
    }

    public func setValue(_ value: [UInt8]?, for key: SharingStateKey, vaultID: UUID) {
        values[vaultID, default: [:]][key] = value
    }

    /// For tests that play someone with the device's files (A8).
    public func tamper(_ key: SharingStateKey, vaultID: UUID, value: [UInt8]?) {
        values[vaultID, default: [:]][key] = value
    }
}

/// The transport's own share list (CloudKit's participants, a shared folder's members): the first step of a removal
/// takes the member off it, so that a store which honours it holds nothing more of theirs (PRD F4.3a). Adapters
/// belong with the transports (`CKShare`, milestone 4's open list); a transport with no share list has none, and the
/// step is then only the signed plan's record of whom to remove.
public protocol ShareAccessControl: Sendable {
    func revokeAccess(of accountID: UUID, to vaultID: UUID) async throws
}

/// Where a session keeps sharing state and finds other accounts' keys.
public struct SharingSettings: Sendable {
    public var state: any SharingStateStore
    public var contacts: any VerifiedContactStore
    /// Published key bundles; the adapter is the account record on the transport (milestone 4's open list).
    public var directory: any KeyBundleDirectory
    public var shareAccess: (any ShareAccessControl)?

    public init(
        state: any SharingStateStore, contacts: any VerifiedContactStore, directory: any KeyBundleDirectory,
        shareAccess: (any ShareAccessControl)? = nil
    ) {
        self.state = state
        self.contacts = contacts
        self.directory = directory
        self.shareAccess = shareAccess
    }
}

/// Why the session refused a sharing operation or a write to a shared vault.
public enum SharedVaultError: Error, Equatable, Sendable {
    case sharingNotConfigured
    /// The vault is not one this device holds a membership ledger for.
    case notShared(UUID)
    /// The Personal vault is never shared (docs/02-architecture.md §7.7).
    case personalVaultCannotBeShared
    /// Sharing needs sync: membership records, grants and the vault's log all travel over the transport.
    case syncNotConfigured
    /// This account may not write to the vault now (PRD F4.5): `MembershipLedger.writePermission`.
    case writeRefused(WriteRefusal)
    /// The vault was shared by another account: only its owner can delete it (a member leaves instead).
    case notOwner
    /// The current vault key has not been received yet (its grant is not on the transport, or not for this account).
    case awaitingKey(UUID)
    /// A vault key whose ID this device already holds for another vault (review finding S38). Key IDs are public
    /// (grant names, envelope headers) and, for a shared vault, chosen by its owner: adopting one would displace the
    /// other vault's key. Refused before anything is stored or made resident.
    case keyIDInUse(UUID)
    /// The vault is shared and this device holds no verified membership ledger for it (another device of the account
    /// shared or joined it; or the saved ledger, or the owner's pin that anchors it, is gone). Nothing is written,
    /// sealed, published or deleted there until this device accepts the vault's invitation itself (review finding
    /// Z41): a shared vault is never run as one of the account's own.
    case ledgerUnavailable(UUID)
    /// The vault's sync log was compacted before it was shared (segments collected, their work surviving only in a
    /// snapshot). A shared vault attributes every value through the segment that carried it, and nothing attributes
    /// those: shared as it is, the vault's older items would be held aside on every device (review finding Z42).
    /// Refused until there is a rule for them; a new vault can be shared and the items moved into it.
    case historyCompacted(UUID)
    /// `removeLocalCopies` was asked for a vault this account is still a member of: a member leaves first, and the
    /// copies can go once the chain says they are out.
    case stillAMember(UUID)
    /// `removeLocalCopies` was asked for a vault in which this device holds changes of its own that nobody else has,
    /// more of them than the caller said the person had been told of (review finding Z57): those are not copies,
    /// and discarding them is the person's choice, made knowing the number. Carries the number.
    case unsharedWork(UUID, Int)
    /// An invitation for a vault this device holds keys of, which arrived by grant, without knowing whose the vault
    /// is: it has no ledger for it and the account's marker has not reached it (review finding Z48). The vault has an
    /// owner, and an invitation is accepted only if it names them; one this device cannot check is not accepted,
    /// whoever it names. It waits for the marker, or for the sync that brings it. Also refused before this session has
    /// listed the account's vault directory, and for a vault that listing names: the account's other devices know the
    /// vault, and their marker is what names its owner (review finding Z59).
    case ownerUnknown(UUID)
    /// The account's own devices disagree about whose the vault is: its markers name two owners, or this device's
    /// ledger names an owner its account's marker does not (review finding Z59). Each side holds a chain verified to
    /// someone the person compared a safety number with, and nothing on the device can tell which the person meant.
    /// The vault is held closed on every device of the account, ledger or not: readable, and nothing written,
    /// sealed again, published or proposed, and its keys given to nobody.
    case ownerDisputed(UUID)
}
