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
    /// Only a shared vault's owner or an administrator may rename it (docs/02-architecture.md §8.7; owner decision of
    /// 2026-11-17): this account may write to the vault, but holds neither role on the head this device knows.
    /// Refused before anything is sealed; another device would hold such a description aside anyway.
    case renameRefused
    /// The vault was shared by another account: only its owner can delete it (a member leaves instead).
    case notOwner
    /// The current vault key has not been received yet (its grant is not on the transport, or not for this account).
    case awaitingKey(UUID)
    /// A vault key whose ID this device already holds for another vault (review finding S38). Key IDs are public
    /// (grant names, envelope headers) and, for a shared vault, chosen by its owner: adopting one would displace the
    /// other vault's key. Refused before anything is stored or made resident.
    case keyIDInUse(UUID)
}
