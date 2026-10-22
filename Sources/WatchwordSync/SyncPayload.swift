import Foundation
import WatchwordEnvelope
import WatchwordStore

public enum SyncFormatError: Error, Equatable, Sendable {
    case truncated
    case badMagic
    case unsupportedFormatVersion(UInt8)
    case unknownObjectKind(UInt8)
    /// An entry of a record kind sync does not carry.
    case unsupportedRecordKind(UInt8)
    case unknownFlags(UInt8)
    /// Entries or vector elements out of order or repeated: one canonical encoding per payload.
    case notCanonical
    /// A declared count larger than the bytes that remain could hold; refused before allocating (SEC9).
    case countTooLarge
    case entryTooLarge(Int)
    case trailingBytes
    /// A deletion that names a key, or a live entry with an empty envelope.
    case malformedEntry
    case signatureTooLong(Int)
}

/// One record version carried by a segment or a snapshot: a `StoredRecord` (ciphertext and storage location) or a
/// deletion of one.
public struct SyncEntry: Sendable, Hashable {
    public var recordID: UUID
    public var kind: EnvelopeKind
    /// The key the envelope is sealed under; the zero UUID for a deletion.
    public var keyID: UUID
    public var version: UInt64
    /// The device that wrote this version.
    public var device: UUID
    /// The record's envelope, or `nil` for a deletion (a tombstone).
    public var envelope: [UInt8]?

    public init(recordID: UUID, kind: EnvelopeKind, keyID: UUID, version: UInt64, device: UUID, envelope: [UInt8]?) {
        self.recordID = recordID
        self.kind = kind
        self.keyID = keyID
        self.version = version
        self.device = device
        self.envelope = envelope
    }

    public init(_ record: StoredRecord) {
        self.init(
            recordID: record.recordID, kind: record.kind, keyID: record.keyID, version: record.version,
            device: record.deviceID, envelope: record.envelope)
    }

    public static func tombstone(_ key: RecordKey, stamp: RecordStamp) -> SyncEntry {
        SyncEntry(
            recordID: key.recordID, kind: key.kind, keyID: SyncPayload.zeroUUID, version: stamp.version,
            device: stamp.device, envelope: nil)
    }

    public var key: RecordKey {
        RecordKey(recordID: recordID, kind: kind)
    }

    public var stamp: RecordStamp {
        RecordStamp(version: version, device: device, deleted: envelope == nil)
    }

    public var isDeletion: Bool {
        envelope == nil
    }

    /// The row this entry becomes in `vaultID`; `nil` for a deletion.
    public func record(in vaultID: UUID) -> StoredRecord? {
        envelope.map {
            StoredRecord(
                recordID: recordID, kind: kind, vaultID: vaultID, keyID: keyID, version: version, deviceID: device,
                envelope: $0)
        }
    }
}

/// The plaintext of a log segment or a snapshot (docs/02-architecture.md §7.1). It travels sealed under the vault key
/// in an envelope of kind `.logSegment` or `.snapshot`, which travels inside a `SignedObject`.
///
/// Binary, little-endian, one canonical encoding:
///
/// ```
/// magic "WWSP"  formatVersion u8 = 1  objectKind u8 (0 segment, 1 snapshot)
/// vaultID 16  author 16  number u64            (sequence, or Lamport time)
/// vectorCount u32, then per element: device 16, sequence u64   (strictly ascending by device)
/// entryCount u32, then per entry:
///   recordID 16  kind u8  keyID 16  version u64  device 16  flags u8 (bit 0: deletion)
///   live entries only: envelopeLength u32, envelope
/// (entries strictly ascending by record ID, then kind; nothing after the last)
/// ```
///
/// `vector` is, for a segment, the author's acknowledgement: for every stream, the highest sequence number it had
/// merged when it wrote the segment (garbage collection waits for every device's). For a snapshot it is the coverage:
/// the segments whose effects the snapshot contains.
///
/// The payload is parsed only after the signature and the AEAD have both passed, but a shared-vault member (A4) can
/// pass both, so the parser treats it as hostile: every count is checked against the bytes that remain before
/// anything is allocated, every length is capped, and anything not in canonical order is refused.
public struct SyncPayload: Sendable, Hashable {
    /// Bound into each object's envelope context as `schemaVersion`.
    public static let schemaVersion: UInt64 = 1
    static let magic: [UInt8] = Array("WWSP".utf8)
    static let formatVersion: UInt8 = 1
    static let zeroUUID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    /// The smallest an entry can encode to, used to bound declared counts.
    static let minimumEntryLength = 16 + 1 + 16 + 8 + 16 + 1
    /// One record envelope; an item is at most 1 MiB of plaintext (`ItemCodec`), so this is generous.
    public static let maximumEntryEnvelopeLength = 2 << 20

    public var kind: SyncObjectLocation.Kind
    public var vaultID: UUID
    public var author: UUID
    public var number: UInt64
    public var vector: [UUID: UInt64]
    public var entries: [SyncEntry]

    public init(
        kind: SyncObjectLocation.Kind, vaultID: UUID, author: UUID, number: UInt64, vector: [UUID: UInt64],
        entries: [SyncEntry]
    ) {
        self.kind = kind
        self.vaultID = vaultID
        self.author = author
        self.number = number
        self.vector = vector
        self.entries = entries
    }

    public var location: SyncObjectLocation {
        SyncObjectLocation(kind: kind, vaultID: vaultID, author: author, number: number)
    }

    // MARK: - Encoding

    public func encoded() -> [UInt8] {
        var out = Self.magic
        out.append(Self.formatVersion)
        out.append(kind == .segment ? 0 : 1)
        out += Self.bytes(vaultID) + Self.bytes(author) + Self.littleEndian(number)
        let vectorElements = vector.sorted { $0.key.precedes($1.key) }
        out += Self.littleEndian(UInt32(vectorElements.count))
        for (device, sequence) in vectorElements {
            out += Self.bytes(device) + Self.littleEndian(sequence)
        }
        let sortedEntries = entries.sorted(by: Self.entryOrder)
        out += Self.littleEndian(UInt32(sortedEntries.count))
        for entry in sortedEntries {
            out += Self.bytes(entry.recordID)
            out.append(entry.kind.rawValue)
            out += Self.bytes(entry.keyID) + Self.littleEndian(entry.version) + Self.bytes(entry.device)
            if let envelope = entry.envelope {
                out.append(0)
                out += Self.littleEndian(UInt32(envelope.count))
                out += envelope
            } else {
                out.append(1)
            }
        }
        return out
    }

    static func entryOrder(_ a: SyncEntry, _ b: SyncEntry) -> Bool {
        if a.recordID != b.recordID { return a.recordID.precedes(b.recordID) }
        return a.kind.rawValue < b.kind.rawValue
    }

    // MARK: - Parsing

    /// Parses a payload. `allowedKinds` are the record kinds sync carries; any other is refused here, before the entry
    /// reaches the store or a merger.
    public static func parse(
        _ bytes: [UInt8],
        allowedKinds: Set<EnvelopeKind>,
        maximumEntryEnvelopeLength: Int = SyncPayload.maximumEntryEnvelopeLength
    ) throws -> SyncPayload {
        var reader = ByteReader(bytes)
        guard try reader.read(4) == magic else { throw SyncFormatError.badMagic }
        let version = try reader.byte()
        guard version == formatVersion else { throw SyncFormatError.unsupportedFormatVersion(version) }
        let objectKind: SyncObjectLocation.Kind
        switch try reader.byte() {
        case 0: objectKind = .segment
        case 1: objectKind = .snapshot
        case let other: throw SyncFormatError.unknownObjectKind(other)
        }
        let vaultID = try reader.uuid()
        let author = try reader.uuid()
        let number = try reader.uint64()

        let vectorCount = Int(try reader.uint32())
        guard vectorCount <= reader.remaining / 24 else { throw SyncFormatError.countTooLarge }
        var vector: [UUID: UInt64] = [:]
        var previousDevice: UUID?
        for _ in 0..<vectorCount {
            let device = try reader.uuid()
            if let previousDevice, !previousDevice.precedes(device) { throw SyncFormatError.notCanonical }
            previousDevice = device
            vector[device] = try reader.uint64()
        }

        let entryCount = Int(try reader.uint32())
        guard entryCount <= reader.remaining / minimumEntryLength else { throw SyncFormatError.countTooLarge }
        var entries: [SyncEntry] = []
        entries.reserveCapacity(entryCount)
        for _ in 0..<entryCount {
            let recordID = try reader.uuid()
            let rawKind = try reader.byte()
            guard let kind = EnvelopeKind(rawValue: rawKind), allowedKinds.contains(kind) else {
                throw SyncFormatError.unsupportedRecordKind(rawKind)
            }
            let keyID = try reader.uuid()
            let recordVersion = try reader.uint64()
            let device = try reader.uuid()
            let flags = try reader.byte()
            var envelope: [UInt8]?
            switch flags {
            case 0:
                let length = Int(try reader.uint32())
                guard length <= maximumEntryEnvelopeLength else { throw SyncFormatError.entryTooLarge(length) }
                guard length > 0 else { throw SyncFormatError.malformedEntry }
                envelope = try reader.read(length)
            case 1:
                guard keyID == zeroUUID else { throw SyncFormatError.malformedEntry }
            default:
                throw SyncFormatError.unknownFlags(flags)
            }
            let entry = SyncEntry(
                recordID: recordID, kind: kind, keyID: keyID, version: recordVersion, device: device,
                envelope: envelope)
            if let last = entries.last, !entryOrder(last, entry) { throw SyncFormatError.notCanonical }
            entries.append(entry)
        }
        guard reader.remaining == 0 else { throw SyncFormatError.trailingBytes }
        return SyncPayload(
            kind: objectKind, vaultID: vaultID, author: author, number: number, vector: vector, entries: entries)
    }

    // MARK: - Helpers

    static func bytes(_ id: UUID) -> [UInt8] {
        let u = id.uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }

    static func littleEndian<T: FixedWidthInteger>(_ value: T) -> [UInt8] {
        (0..<(T.bitWidth / 8)).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
    }
}

/// A cursor over hostile bytes; every read is bounds-checked and throws `truncated` rather than trapping.
struct ByteReader {
    private let bytes: [UInt8]
    private var offset = 0

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    var remaining: Int {
        bytes.count - offset
    }

    mutating func read(_ count: Int) throws -> [UInt8] {
        guard count >= 0, count <= remaining else { throw SyncFormatError.truncated }
        defer { offset += count }
        return Array(bytes[offset..<(offset + count)])
    }

    mutating func byte() throws -> UInt8 {
        try read(1)[0]
    }

    mutating func uint16() throws -> UInt16 {
        try integer()
    }

    mutating func uint32() throws -> UInt32 {
        try integer()
    }

    mutating func uint64() throws -> UInt64 {
        try integer()
    }

    private mutating func integer<T: FixedWidthInteger>() throws -> T {
        let raw = try read(T.bitWidth / 8)
        return raw.enumerated().reduce(T.zero) { $0 | (T(truncatingIfNeeded: $1.element) << (8 * $1.offset)) }
    }

    mutating func uuid() throws -> UUID {
        let b = try read(16)
        return UUID(
            uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
        )
    }
}

/// A sealed envelope and the author's signature over it (docs/02-architecture.md §7.1): what a transport stores.
///
/// ```
/// magic "WWSO"  formatVersion u8 = 1  signatureLength u16  signature  envelope (the rest)
/// ```
///
/// The signature covers the envelope bytes exactly as stored, which embed the object's location in their
/// authenticated header, so it can be checked before anything is decrypted or parsed — including while the vault is
/// locked (§7.4), when only public keys are available.
public struct SignedObject: Sendable, Hashable {
    static let magic: [UInt8] = Array("WWSO".utf8)
    static let formatVersion: UInt8 = 1
    /// Ed25519 signatures are 64 bytes; room for a second (device) signature and some growth.
    public static let maximumSignatureLength = 512

    public var signature: [UInt8]
    public var envelope: [UInt8]

    public init(signature: [UInt8], envelope: [UInt8]) {
        self.signature = signature
        self.envelope = envelope
    }

    public func serialized() -> [UInt8] {
        Self.magic + [Self.formatVersion] + SyncPayload.littleEndian(UInt16(signature.count)) + signature + envelope
    }

    public static func parse(_ bytes: [UInt8]) throws -> SignedObject {
        var reader = ByteReader(bytes)
        guard try reader.read(4) == magic else { throw SyncFormatError.badMagic }
        let version = try reader.byte()
        guard version == formatVersion else { throw SyncFormatError.unsupportedFormatVersion(version) }
        let length = Int(try reader.uint16())
        guard length <= maximumSignatureLength else { throw SyncFormatError.signatureTooLong(length) }
        let signature = try reader.read(length)
        return SignedObject(signature: signature, envelope: try reader.read(reader.remaining))
    }
}
