import Foundation
import WatchwordEnvelope

/// Where a sync object lives on a transport, and therefore what it must be (docs/02-architecture.md §7.1, §7.3).
///
/// Two kinds of object exist, each written by exactly one device and never modified:
///
/// - `vault/<vaultID>/log/<deviceID>/<sequence>` — the device's log segment number `sequence` (from 1, contiguous).
/// - `vault/<vaultID>/snapshot/<lamport>-<deviceID>` — a snapshot of the vault at Lamport time `lamport`. The device ID
///   is part of the name so that two devices snapshotting at the same moment never write the same object.
///
/// Numbers are 20 zero-padded decimal digits, so names sort in numeric order. UUIDs are in `UUID.uuidString`'s
/// canonical upper-case form. Names come from a store that may be hostile (A1), so parsing is exact: anything that does
/// not re-encode to the same string is not a sync object.
///
/// The location is bound into each object's envelope (`envelopeContext(keyID:)`), so an object moved to another
/// name — another device's stream, another sequence number, another vault, from a segment slot to a snapshot slot —
/// fails before decryption.
public struct SyncObjectLocation: Hashable, Sendable {
    public enum Kind: Sendable, Hashable {
        case segment
        case snapshot
    }

    public let kind: Kind
    public let vaultID: UUID
    /// The device that wrote the object, and whose signature it must carry.
    public let author: UUID
    /// The segment's sequence number, or the snapshot's Lamport time.
    public let number: UInt64

    public static func segment(vaultID: UUID, author: UUID, sequence: UInt64) -> SyncObjectLocation {
        SyncObjectLocation(kind: .segment, vaultID: vaultID, author: author, number: sequence)
    }

    public static func snapshot(vaultID: UUID, author: UUID, lamport: UInt64) -> SyncObjectLocation {
        SyncObjectLocation(kind: .snapshot, vaultID: vaultID, author: author, number: lamport)
    }

    init(kind: Kind, vaultID: UUID, author: UUID, number: UInt64) {
        self.kind = kind
        self.vaultID = vaultID
        self.author = author
        self.number = number
    }

    /// The prefix under which every object of a vault lives.
    public static func vaultPrefix(_ vaultID: UUID) -> String {
        "vault/\(vaultID.uuidString)/"
    }

    public var name: String {
        switch kind {
        case .segment:
            return Self.vaultPrefix(vaultID) + "log/\(author.uuidString)/\(Self.padded(number))"
        case .snapshot:
            return Self.vaultPrefix(vaultID) + "snapshot/\(Self.padded(number))-\(author.uuidString)"
        }
    }

    /// Parses a name exactly; returns `nil` for anything that is not the canonical name of a sync object.
    public init?(name: String) {
        let parts = name.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 4, parts[0] == "vault", let vaultID = Self.uuid(parts[1]) else { return nil }
        switch parts[2] {
        case "log":
            guard parts.count == 5, let author = Self.uuid(parts[3]), let sequence = Self.number(parts[4]) else {
                return nil
            }
            self.init(kind: .segment, vaultID: vaultID, author: author, number: sequence)
        case "snapshot":
            let pieces = parts[3].split(separator: "-", maxSplits: 1).map(String.init)
            guard parts.count == 4, pieces.count == 2, let lamport = Self.number(pieces[0]),
                let author = Self.uuid(pieces[1])
            else { return nil }
            self.init(kind: .snapshot, vaultID: vaultID, author: author, number: lamport)
        default:
            return nil
        }
        guard self.name == name else { return nil }
    }

    public var envelopeKind: EnvelopeKind {
        switch kind {
        case .segment: return .logSegment
        case .snapshot: return .snapshot
        }
    }

    /// The authenticated context an object at this location must carry: the author as record ID, the sequence number
    /// or Lamport time as record version, under the vault key named `keyID` (docs/02-architecture.md §5).
    public func envelopeContext(keyID: UUID) -> EnvelopeContext {
        EnvelopeContext(
            recordID: author,
            vaultID: vaultID,
            schemaVersion: SyncPayload.schemaVersion,
            kind: envelopeKind,
            keyID: keyID,
            recordVersion: number
        )
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
}
