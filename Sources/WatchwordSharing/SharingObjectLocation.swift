import Foundation

/// Where a sharing object lives on a transport, and therefore what it must be (docs/02-architecture.md §8.2).
///
/// Three kinds, all immutable and written once, like sync's own objects, and under a prefix of their own so that the
/// sync engine's listing of `vault/<vaultID>/` never meets them:
///
/// - `sharing/<vaultID>/membership/<epoch>-<hash>-<digest>` — a membership record. The epoch is twenty zero-padded
///   digits, so names sort in chain order; the hash is the record's own (`MembershipHash`, lower-case hex), which
///   is the same for every copy of a record and lets a device skip objects it already holds
///   (`MembershipLedger.holds`); the digest is SHA-256 of the whole object, signature included. Two administrators
///   writing the same epoch at the same moment write two objects rather than fight over one. The digest is what
///   keeps a name from being taken: most of a record's signed content is predictable to any member (a role change,
///   an invitation, a deletion), so a name made of the hash alone could be created first, by someone who cannot
///   sign the record, with a signature that does not verify, and the genuine record could then never be published
///   (review finding S20). With the digest, such a copy is one more object beside the genuine one, refused when
///   it is examined.
/// - `sharing/<vaultID>/grant/<keyID>/<recipient>/<digest>` — a vault key wrapped to one member (`KeyGrantCodec`).
///   The vault, the key and the recipient are the storage location a grant is checked against; the digest
///   (SHA-256 of the object, lower-case hex) is there, as above, so that nobody can occupy another sender's name.
/// - `sharing/<vaultID>/leave/<account>/<digest>` — a member's leave request.
///
/// UUIDs are in `UUID.uuidString`'s canonical upper-case form. Names come from a store that may be hostile (A1), so
/// parsing is exact: anything that does not re-encode to the same string is not a sharing object. This mirrors
/// `SyncObjectLocation`, and the names are valid for any `SyncTransport`.
public struct SharingObjectLocation: Hashable, Sendable {
    public enum Kind: Hashable, Sendable {
        case membership(epoch: UInt64, hash: MembershipHash, digest: [UInt8])
        case grant(keyID: UUID, recipient: UUID, digest: [UInt8])
        case leave(account: UUID, digest: [UInt8])
    }

    public let vaultID: UUID
    public let kind: Kind

    init(vaultID: UUID, kind: Kind) {
        self.vaultID = vaultID
        self.kind = kind
    }

    public static func membership(_ record: MembershipRecord) -> SharingObjectLocation {
        SharingObjectLocation(
            vaultID: record.vaultID,
            kind: .membership(epoch: record.epoch, hash: record.hash, digest: SharingBytes.sha256(record.encoded())))
    }

    public static func grant(vaultID: UUID, keyID: UUID, recipient: UUID, contents: [UInt8])
        -> SharingObjectLocation
    {
        SharingObjectLocation(
            vaultID: vaultID, kind: .grant(keyID: keyID, recipient: recipient, digest: SharingBytes.sha256(contents)))
    }

    public static func leave(_ request: LeaveRequest) -> SharingObjectLocation {
        SharingObjectLocation(
            vaultID: request.vaultID,
            kind: .leave(account: request.accountID, digest: SharingBytes.sha256(request.encoded())))
    }

    /// The prefix under which every sharing object of a vault lives.
    public static func vaultPrefix(_ vaultID: UUID) -> String {
        "sharing/\(vaultID.uuidString)/"
    }

    public static func membershipPrefix(_ vaultID: UUID) -> String {
        vaultPrefix(vaultID) + "membership/"
    }

    /// The prefix under which the grants of one key to one member live.
    public static func grantPrefix(vaultID: UUID, keyID: UUID, recipient: UUID) -> String {
        vaultPrefix(vaultID) + "grant/\(keyID.uuidString)/\(recipient.uuidString)/"
    }

    public static func leavePrefix(_ vaultID: UUID) -> String {
        vaultPrefix(vaultID) + "leave/"
    }

    public var name: String {
        switch kind {
        case .membership(let epoch, let hash, let digest):
            return Self.membershipPrefix(vaultID) + "\(Self.padded(epoch))-\(hash.hex)-\(SharingBytes.hex(digest))"
        case .grant(let keyID, let recipient, let digest):
            return Self.grantPrefix(vaultID: vaultID, keyID: keyID, recipient: recipient) + SharingBytes.hex(digest)
        case .leave(let account, let digest):
            return Self.leavePrefix(vaultID) + "\(account.uuidString)/\(SharingBytes.hex(digest))"
        }
    }

    /// Whether `contents` are what this name commits to: every kind of name ends in SHA-256 of the object. An object
    /// that fails this was not put there by an honest client under an honest store, and an integrator neither offers
    /// it to a ledger nor remembers anything about the name on its account.
    public func isName(of contents: [UInt8]) -> Bool {
        switch kind {
        case .membership(_, _, let digest), .grant(_, _, let digest), .leave(_, let digest):
            return digest == SharingBytes.sha256(contents)
        }
    }

    /// SHA-256 of an object: the digest every sharing object's name ends in, and what an integrator's `WriteCut`
    /// can use to bind the objects it speaks of.
    public static func digest(of contents: [UInt8]) -> [UInt8] {
        SharingBytes.sha256(contents)
    }

    /// The longest a sharing object's name can be; longer names are not looked at.
    static let maximumNameLength = 256

    /// Parses a name exactly; `nil` for anything that is not the canonical name of a sharing object.
    public init?(name: String) {
        guard name.utf8.count <= Self.maximumNameLength else { return nil }
        let parts = name.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 4, parts[0] == "sharing", let vaultID = Self.uuid(parts[1]) else { return nil }
        switch parts[2] {
        case "membership":
            let pieces = parts[3].split(separator: "-", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 4, pieces.count == 3, let epoch = Self.number(pieces[0]),
                let hash = Self.digest(pieces[1]), let digest = Self.digest(pieces[2])
            else { return nil }
            self.init(
                vaultID: vaultID,
                kind: .membership(epoch: epoch, hash: MembershipHash(unchecked: hash), digest: digest))
        case "grant":
            guard parts.count == 6, let keyID = Self.uuid(parts[3]), let recipient = Self.uuid(parts[4]),
                let digest = Self.digest(parts[5])
            else { return nil }
            self.init(vaultID: vaultID, kind: .grant(keyID: keyID, recipient: recipient, digest: digest))
        case "leave":
            guard parts.count == 5, let account = Self.uuid(parts[3]), let digest = Self.digest(parts[4]) else {
                return nil
            }
            self.init(vaultID: vaultID, kind: .leave(account: account, digest: digest))
        default:
            return nil
        }
        guard self.name == name else { return nil }
    }

    static let digits = 20

    static func padded(_ value: UInt64) -> String {
        let text = String(value)
        return String(repeating: "0", count: digits - text.count) + text
    }

    static func number(_ text: String) -> UInt64? {
        guard text.utf8.count == digits, text.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return nil }
        return UInt64(text)
    }

    static func uuid(_ text: String) -> UUID? {
        guard let id = UUID(uuidString: text), id.uuidString == text else { return nil }
        return id
    }

    static func digest(_ text: String) -> [UInt8]? {
        guard text.utf8.count == 64 else { return nil }
        return SharingBytes.bytes(hex: text)
    }
}

/// A sharing object ready for a transport: `create(location.name, contents)`. Creating one that already exists with
/// the same contents is success, which is what makes publishing resumable; and because every name ends in a digest
/// of the contents, a name can never already be taken by different contents that a store kept honestly.
public struct SharingObject: Hashable, Sendable {
    public let location: SharingObjectLocation
    public let contents: [UInt8]

    init(location: SharingObjectLocation, contents: [UInt8]) {
        self.location = location
        self.contents = contents
    }

    public init(_ record: MembershipRecord) {
        self.init(location: .membership(record), contents: record.encoded())
    }

    public init(_ request: LeaveRequest) {
        self.init(location: .leave(request), contents: request.encoded())
    }

    public init(_ grant: VaultKeyGrantRecord) {
        self.init(location: grant.location, contents: grant.encoded)
    }

    /// The object's name on a transport.
    public var name: String {
        location.name
    }
}
