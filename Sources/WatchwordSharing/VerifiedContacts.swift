import Foundation
import WatchwordCrypto

/// How a fingerprint was confirmed (docs/02-architecture.md §8.4). Raw values are part of the pin format.
///
/// Raw value 3 is reserved: it was "the person compared the two numbers themselves and said they match", the unchecked
/// claim ADR 0010 (G3) removed. It is never written, and a pin that carries it is not a pin (`VerifiedContacts`
/// ignores it, so that contact is back in front of the person).
public enum VerificationMethod: UInt8, Sendable, Hashable {
    /// The person typed the other person's 60-digit fingerprint (the full vault sharing code) and the device found it
    /// matched: the fallback for two people who cannot be at their devices together.
    case safetyNumber = 1
    /// The person's device scanned the other person's QR code from their screen, and it matched.
    case scannedCode = 2
    /// A vault sharing code session completed: the code the person typed from the other device matched this device's
    /// transcript (ADR 0010).
    case sharingCode = 4
}

/// What the person offers as proof that a bundle belongs to who they think it does. Every case is checked by the
/// device; there is no case for the person's word alone (ADR 0010, G3).
public enum VerificationEvidence: Sendable, Hashable {
    /// The full vault sharing code (the 60-digit fingerprint), typed.
    case safetyNumber(String)
    /// The text of a QR code the camera read from the other person's screen (`FingerprintCode.payload`).
    case scannedCode(String)
}

/// A key bundle whose fingerprint this account's person has confirmed out of band, or the account's own.
///
/// Only `VerifiedContacts` makes one, which is how the rest of the module knows a fingerprint was checked: wrapping a
/// vault key to an invitee, and anchoring a membership chain to an owner, both take a `VerifiedContact` and nothing
/// less (PRD F4.2, SEC3). The same idea as `NormalizedHost` in the matching pipeline.
public struct VerifiedContact: Sendable, Hashable {
    public let bundle: PublicKeyBundle
    /// `nil` for the account's own bundle.
    public let method: VerificationMethod?
    /// `nil` for the account's own bundle.
    public let verifiedAt: Date?

    init(bundle: PublicKeyBundle, method: VerificationMethod?, verifiedAt: Date?) {
        self.bundle = bundle
        self.method = method
        self.verifiedAt = verifiedAt
    }

    public var accountID: UUID {
        bundle.accountID
    }
}

/// Where pins are kept: one opaque blob per contact account (docs/02-architecture.md §8.4, §15). Production: a table
/// beside the vault database. The blobs are signed (`VerifiedContacts`), so the store needs no protection of its own
/// beyond not losing them.
public protocol VerifiedContactStore: Sendable {
    func pin(for accountID: UUID) async throws -> [UInt8]?
    /// Stores `pin`, replacing any pin for the account.
    func savePin(_ pin: [UInt8], for accountID: UUID) async throws
    func removePin(for accountID: UUID) async throws
}

public actor InMemoryVerifiedContactStore: VerifiedContactStore {
    private var pins: [UUID: [UInt8]] = [:]

    public init() {}

    public func pin(for accountID: UUID) -> [UInt8]? {
        pins[accountID]
    }

    public func savePin(_ pin: [UInt8], for accountID: UUID) {
        pins[accountID] = pin
    }

    public func removePin(for accountID: UUID) {
        pins[accountID] = nil
    }
}

/// Whether a bundle is one this account has verified.
public enum ContactTrust: Sendable, Hashable {
    case verified(VerifiedContact)
    /// No pin for the account. The bundle is a candidate: show its fingerprint and ask.
    case unverified
}

/// The account's verified contacts: the pin made when a fingerprint is confirmed, and the check every later use of
/// that account's keys goes through (docs/02-architecture.md §8.4; PRD F4.2, SEC3).
///
/// Once an account is pinned, a different bundle for it is never accepted silently, wherever it comes from:
/// `trust(of:)` and `verify` throw `SharingError.keySubstituted`, which the UI reports. Three places ask. The two
/// sides of an invitation ask about the bundle the key directory returned. And `MembershipLedger.checkMemberKeys`
/// asks about every member a chain lists: its result is what `RotationPlanner.plan` and `MembershipLedger.makeGrant`
/// require before they wrap a key to the chain's bundles, so a member whose keys were swapped in the chain is
/// reported and is not wrapped to (`MemberKeyCheck`). Replacing a pin is a separate, explicit act
/// (`verify(…, replacingPin: true)`), for the case where the other person really does have new keys and has been
/// verified again.
///
/// A pin is
///
/// ```
/// magic "WWCP"  formatVersion u8 = 1  pinning account 16  method u8  verifiedAt u64 (seconds since 1970)
/// contact account 16  X25519 key 32  Ed25519 key 32  self-signature 64  signature 64
/// ```
///
/// signed by the pinning account's own key under `SignatureDomain.membership`. A pin that does not verify, or was made
/// by another account, is ignored: an attacker who can write the store's file (A8) cannot plant trust in a key of
/// their own, only remove a pin, which puts the contact back to unverified and in front of the person.
public struct VerifiedContacts: Sendable {
    static let magic: [UInt8] = Array("WWCP".utf8)
    static let formatVersion: UInt8 = 1
    static let pinLength = 4 + 1 + 16 + 1 + 8 + 16 + 32 + 32 + 64 + 64

    let store: any VerifiedContactStore
    /// This account's own bundle: whose pins these are, and the key they are checked with.
    public let account: PublicKeyBundle

    public init(store: any VerifiedContactStore, account: PublicKeyBundle) {
        self.store = store
        self.account = account
    }

    /// The account's own bundle, which needs no fingerprint comparison.
    public var myself: VerifiedContact {
        VerifiedContact(bundle: account, method: nil, verifiedAt: nil)
    }

    /// Whether `bundle` is the verified one for its account. Throws `keySubstituted` if another bundle is pinned.
    public func trust(of bundle: PublicKeyBundle) async throws -> ContactTrust {
        if bundle.accountID == account.accountID {
            guard bundle.hasSameKeys(as: account) else {
                throw SharingError.keySubstituted(accountID: bundle.accountID)
            }
            return .verified(myself)
        }
        guard let pinned = try await pinned(bundle.accountID) else { return .unverified }
        guard pinned.bundle.hasSameKeys(as: bundle) else {
            throw SharingError.keySubstituted(accountID: bundle.accountID)
        }
        return .verified(pinned)
    }

    /// The verified bundle for `accountID`, if there is a valid pin.
    public func pinned(_ accountID: UUID) async throws -> VerifiedContact? {
        guard let bytes = try await store.pin(for: accountID) else { return nil }
        return parsePin(bytes, contact: accountID)
    }

    /// Confirms `bundle`'s fingerprint with what the person supplied and pins it.
    ///
    /// - Throws: `fingerprintMismatch` if a typed number or a scanned code is not this bundle's (every kind of
    ///   evidence names the keys it is about, review finding Z40); `keySubstituted` if a different bundle is already pinned for the account and
    ///   `replacingPin` is false.
    public func verify(
        _ bundle: PublicKeyBundle, evidence: VerificationEvidence, signedBy keyset: Keyset, at now: Date,
        replacingPin: Bool = false
    ) async throws -> VerifiedContact {
        guard keyset.accountID == account.accountID else { throw SharingError.notPermitted }
        if bundle.accountID == account.accountID {
            guard bundle.hasSameKeys(as: account) else {
                throw SharingError.keySubstituted(accountID: bundle.accountID)
            }
            return myself
        }
        let method: VerificationMethod
        switch evidence {
        case .safetyNumber(let typed):
            guard bundle.fingerprint.matches(safetyNumber: typed) else { throw SharingError.fingerprintMismatch }
            method = .safetyNumber
        case .scannedCode(let payload):
            guard try FingerprintCode(scanned: payload).matches(bundle) else {
                throw SharingError.fingerprintMismatch
            }
            method = .scannedCode
        }
        return try await pin(bundle, method: method, signedBy: keyset, at: now, replacingPin: replacingPin)
    }

    /// Pins the bundle a vault sharing code session authenticated (ADR 0010). The evidence must have been made for
    /// this account: a session's evidence is refused for any other (`SharingError.notPermitted`). A different bundle
    /// already pinned is `keySubstituted` unless `replacingPin`, as for `verify(_:evidence:…)`.
    public func verify(
        _ evidence: SharingCodeEvidence, signedBy keyset: Keyset, at now: Date, replacingPin: Bool = false
    ) async throws -> VerifiedContact {
        guard keyset.accountID == account.accountID, evidence.pinningAccount == account.accountID else {
            throw SharingError.notPermitted
        }
        guard evidence.contact.accountID != account.accountID else { throw SharingError.notPermitted }
        return try await pin(
            evidence.contact, method: evidence.method, signedBy: keyset, at: now, replacingPin: replacingPin)
    }

    private func pin(
        _ bundle: PublicKeyBundle, method: VerificationMethod, signedBy keyset: Keyset, at now: Date,
        replacingPin: Bool
    ) async throws -> VerifiedContact {
        if let existing = try await pinned(bundle.accountID) {
            if existing.bundle.hasSameKeys(as: bundle) { return existing }
            guard replacingPin else { throw SharingError.keySubstituted(accountID: bundle.accountID) }
        }

        // The caller's vault may have locked while the pin was read: a zeroised keyset traps when read.
        guard !keyset.isZeroised else { throw SharingError.notPermitted }
        let seconds = VerifiedContacts.seconds(now)
        let content = VerifiedContacts.pinContent(
            pinner: account.accountID, method: method, seconds: seconds, bundle: bundle)
        try await store.savePin(
            content + (try keyset.sign(content, domain: .membership)), for: bundle.accountID)
        return VerifiedContact(
            bundle: bundle, method: method, verifiedAt: Date(timeIntervalSince1970: TimeInterval(seconds)))
    }

    /// Forgets a contact. The account is unverified again.
    public func forget(_ accountID: UUID) async throws {
        try await store.removePin(for: accountID)
    }

    static func pinContent(pinner: UUID, method: VerificationMethod, seconds: UInt64, bundle: PublicKeyBundle)
        -> [UInt8]
    {
        magic + [formatVersion] + pinner.sharingBytes + [method.rawValue] + SharingBytes.littleEndian(seconds)
            + bundle.accountID.sharingBytes + bundle.agreementKey + bundle.signingKey + bundle.selfSignature
    }

    /// A pin read from the store, or `nil` if it is not a pin this account made for `contact`.
    private func parsePin(_ bytes: [UInt8], contact: UUID) -> VerifiedContact? {
        guard bytes.count == VerifiedContacts.pinLength else { return nil }
        var reader = SharingReader(bytes)
        guard (try? reader.header(magic: VerifiedContacts.magic, version: VerifiedContacts.formatVersion)) != nil,
            let pinner = try? reader.uuid(), pinner == account.accountID,
            let rawMethod = try? reader.byte(), let method = VerificationMethod(rawValue: rawMethod),
            let seconds = try? reader.uint64(),
            let accountID = try? reader.uuid(), accountID == contact,
            let agreementKey = try? reader.read(32), let signingKey = try? reader.read(32),
            let selfSignature = try? reader.read(64), let signature = try? reader.read(64),
            let bundle = try? PublicKeyBundle(
                accountID: accountID, agreementKey: agreementKey, signingKey: signingKey,
                selfSignature: selfSignature)
        else { return nil }
        let content = VerifiedContacts.pinContent(pinner: pinner, method: method, seconds: seconds, bundle: bundle)
        guard
            (try? Signatures.verify(signature, for: content, domain: .membership, signingKey: account.signingKey))
                != nil
        else { return nil }
        return VerifiedContact(
            bundle: bundle, method: method,
            verifiedAt: Date(timeIntervalSince1970: TimeInterval(min(seconds, VerifiedContacts.latestSeconds))))
    }

    /// Far enough ahead for any real clock, and small enough to convert exactly.
    static let latestSeconds: UInt64 = 1 << 40

    /// Whole seconds since 1970, clamped, so that a clock reporting nonsense cannot trap the conversion.
    static func seconds(_ date: Date) -> UInt64 {
        let interval = date.timeIntervalSince1970
        guard interval.isFinite, interval > 0 else { return 0 }
        return UInt64(min(interval, Double(latestSeconds)))
    }
}
