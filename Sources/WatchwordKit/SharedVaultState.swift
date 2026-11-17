import Foundation
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordSharing
import WatchwordStore
import WatchwordSync

/// A record version as sync names it: which record, of which kind, at which version. Together with the device that
/// wrote it, a revision (docs/02-architecture.md §7.1).
struct VersionKey: Hashable, Sendable {
    var recordID: UUID
    var kind: UInt8
    var version: UInt64
}

/// What this device has seen of each device's stream in one shared vault: for every segment, the digest of the object
/// and the account whose keys signed it, and which record versions it carried (docs/02-architecture.md §8.8).
///
/// Two questions are answered from it. **Whose work is a value?** The account that signed a segment of the stream of
/// the device the value's stamp names that carried the value's exact bytes, stamp included (`valueCarriers`, review
/// finding S36): the stamp is the writer's claim, so a value is that device's work only where that device's own stream
/// carried it, and a device ID alone could be listed by more than one account's registry, while a signature is one
/// account's. A version's own revision is attributed the same way, through the segment that first carried it. **Is a segment inside a write cut?** The cut commits to a device's stream up to a
/// sequence number by a chain of these digests, which every device recomputes from what it holds.
///
/// Local state like the saved ledger, so it is signed by the account's own key under `SignatureDomain.membership`
/// with its own magic (`WWSI`) and refused whole on load if it does not verify (A8): a planted index could otherwise
/// say that a former member's late write was carried inside their cut.
struct SharedStreamIndex: Sendable, Hashable {
    struct Segment: Sendable, Hashable {
        var digest: [UInt8]
        var account: UUID
        var entries: [VersionKey]
        /// The values this segment carried that an earlier segment of the same stream had not (review finding S36):
        /// each the digest of an `AttributedValue`, filed under the device its stamp names.
        var values: [ValueKey] = []
    }

    /// A value as the index files it: the device its stamp names, and SHA-256 of its encoding with the whole stamp.
    struct ValueKey: Sendable, Hashable {
        var device: UUID
        var digest: [UInt8]
    }

    static let magic: [UInt8] = Array("WWSI".utf8)
    /// 3 since note-line removals, discards and history entries became attributable values (review findings S32,
    /// S43): an index of an earlier format filed none of them, so it is refused on load and rebuilt from the log by a
    /// replay, which files them, before anything is judged against it.
    static let formatVersion: UInt8 = 3
    static let maximumLength = 64 << 20

    /// By device, then sequence number.
    private(set) var streams: [UUID: [UInt64: Segment]] = [:]
    /// The lowest sequence recorded of each stream, kept beside `streams`: the segment that names the stream's
    /// account (`account(ofStream:)`), asked for with every value judged.
    private var lowest: [UUID: UInt64] = [:]
    /// The membership head the vault's items were last judged against (`MembershipHash.bytes`), so that a change of
    /// head is noticed after a restart too.
    var judgedHead: [UInt8]?
    /// The lowest sequence of each device's stream that carried each version.
    private(set) var firstCarrier: [UUID: [VersionKey: UInt64]] = [:]
    /// For each value, the streams that carried it and the lowest sequence of each. A value counts as the work of the
    /// device its stamp names only through these: its bytes, stamp included, in a segment of a stream whose signer's
    /// work counts at that sequence (S36, S37).
    private(set) var valueCarriers: [ValueKey: [UUID: UInt64]] = [:]
    /// Devices a version was held aside for because a value naming them was carried by none of their segments here:
    /// a new segment of theirs can make it count, so recording one asks for a replay (`judgedHead` cleared).
    var awaiting: Set<UUID> = []

    init() {}

    /// The account a device's stream belongs to: the one whose keys signed its lowest-numbered segment recorded here
    /// (review finding Z46). A stream is named by a device ID alone, device IDs are chosen by devices, and nothing
    /// stops a member listing another member's device ID in their own registry and signing objects into "its"
    /// stream. So the name does not say whose a stream is; its first segment does, and a shared vault keeps its whole
    /// log, so devices that hold the same segments agree. `nil` for a stream nothing was recorded of.
    func account(ofStream device: UUID) -> UUID? {
        firstSequence(ofStream: device).flatMap { streams[device]?[$0]?.account }
    }

    /// The lowest sequence number recorded of a device's stream.
    func firstSequence(ofStream device: UUID) -> UInt64? {
        lowest[device]
    }

    /// Whether the segment at `sequence` of `device`'s stream is there and signed by the account the stream belongs
    /// to. Another account's object in that position is kept, since a write cut's chain runs over every object of
    /// the stream, but nothing is attributed through it.
    func isOwnersSegment(device: UUID, sequence: UInt64) -> Bool {
        guard let segment = streams[device]?[sequence] else { return false }
        return segment.account == account(ofStream: device)
    }

    /// Remembers a segment. The first copy seen of a name is kept: objects are written once, so a second, different
    /// object under the same name is a store showing devices different streams (`forkedStream`), and the cut's chain
    /// is what tells which one its signer held. What a segment carried is filed only if the account the stream
    /// belongs to signed it (Z46); if a lower-numbered segment arrives later and is another account's, the stream is
    /// that account's after all and what was filed through it is filed again.
    mutating func record(device: UUID, sequence: UInt64, segment: Segment) {
        guard streams[device]?[sequence] == nil else { return }
        let before = account(ofStream: device)
        streams[device, default: [:]][sequence] = segment
        lowest[device] = min(lowest[device] ?? .max, sequence)
        let owner = account(ofStream: device)
        if let before, before != owner {
            firstCarrier[device] = nil
            for value in valueCarriers.keys {
                valueCarriers[value]?[device] = nil
                if valueCarriers[value]?.isEmpty == true { valueCarriers[value] = nil }
            }
            for (number, held) in (streams[device] ?? [:]).sorted(by: { $0.key < $1.key })
            where held.account == owner {
                file(held, device: device, sequence: number)
            }
        } else if segment.account == owner {
            file(segment, device: device, sequence: sequence)
        }
    }

    private mutating func file(_ segment: Segment, device: UUID, sequence: UInt64) {
        for entry in segment.entries where (firstCarrier[device]?[entry] ?? .max) > sequence {
            firstCarrier[device, default: [:]][entry] = sequence
        }
        for value in segment.values where (valueCarriers[value]?[device] ?? .max) > sequence {
            valueCarriers[value, default: [:]][device] = sequence
        }
    }

    /// Whether this device's stream already carried `value` at or before `sequence`.
    func carries(_ value: ValueKey, device: UUID, atOrBefore sequence: UInt64) -> Bool {
        (valueCarriers[value]?[device] ?? .max) <= sequence
    }

    func segment(device: UUID, sequence: UInt64) -> Segment? {
        streams[device]?[sequence]
    }

    /// The chain over a device's segments 1 through `sequence`, or `nil` if one of them is missing here.
    func chain(device: UUID, through sequence: UInt64) -> [UInt8]? {
        var link = [UInt8](repeating: 0, count: 32)
        guard sequence > 0 else { return link }
        guard let stream = streams[device], UInt64(stream.count) >= sequence else { return nil }
        for number in 1...sequence {
            guard let segment = stream[number] else { return nil }
            link = Self.link(link, sequence: number, digest: segment.digest)
        }
        return link
    }

    /// The furthest sequence through which every segment of the device's stream is held here.
    func contiguous(device: UUID, upTo limit: UInt64) -> UInt64 {
        guard let stream = streams[device] else { return 0 }
        var sequence: UInt64 = 0
        while sequence < limit, stream[sequence + 1] != nil { sequence += 1 }
        return sequence
    }

    /// The devices whose streams are this account's (`account(ofStream:)`): what a write cut for it covers.
    func devices(signedBy account: UUID) -> [UUID] {
        streams.keys.filter { self.account(ofStream: $0) == account }.sorted { $0.precedes($1) }
    }

    static func link(_ previous: [UInt8], sequence: UInt64, digest: [UInt8]) -> [UInt8] {
        ObjectDigest(hashing: Array("WW-cut-v1".utf8) + previous + SharedBytes.littleEndian(sequence) + digest).bytes
    }

    /// What identifies a segment for a cut: SHA-256 of its name and envelope, the bytes its signatures cover. Not
    /// the signatures themselves, which Ed25519 on CryptoKit randomises.
    static func digest(name: String, envelope: [UInt8]) -> [UInt8] {
        ObjectDigest(hashing: Array("WW-segment-v1".utf8) + Array(name.utf8) + [0] + envelope).bytes
    }

    // MARK: - Encoding

    func signed(account: UUID, vaultID: UUID, keyset: Keyset) throws -> [UInt8] {
        var out = Self.magic + [Self.formatVersion] + SharedBytes.bytes(account) + SharedBytes.bytes(vaultID)
        if let judgedHead {
            out += [1] + judgedHead
        } else {
            out += [0]
        }
        let devices = streams.keys.sorted { $0.precedes($1) }
        out += SharedBytes.littleEndian32(UInt32(devices.count))
        for device in devices {
            let stream = streams[device]!
            out += SharedBytes.bytes(device) + SharedBytes.littleEndian32(UInt32(stream.count))
            for sequence in stream.keys.sorted() {
                let segment = stream[sequence]!
                out += SharedBytes.littleEndian(sequence) + segment.digest + SharedBytes.bytes(segment.account)
                out += SharedBytes.littleEndian32(UInt32(segment.entries.count))
                for entry in segment.entries {
                    out += SharedBytes.bytes(entry.recordID) + [entry.kind] + SharedBytes.littleEndian(entry.version)
                }
                out += SharedBytes.littleEndian32(UInt32(segment.values.count))
                for value in segment.values { out += SharedBytes.bytes(value.device) + value.digest }
            }
        }
        let waiting = awaiting.sorted { $0.precedes($1) }
        out += SharedBytes.littleEndian32(UInt32(waiting.count))
        for device in waiting { out += SharedBytes.bytes(device) }
        return out + (try keyset.sign(out, domain: .membership))
    }

    /// Parses and verifies a saved index. Anything that does not verify, names another account or vault, or is not
    /// in the one canonical form is refused (`nil`): the index is then rebuilt by a reconciling sync.
    static func parse(_ bytes: [UInt8], account: PublicKeyBundle, vaultID: UUID) -> SharedStreamIndex? {
        guard bytes.count > 64, bytes.count <= maximumLength else { return nil }
        let body = Array(bytes[..<(bytes.count - 64)])
        guard
            (try? Signatures.verify(
                Array(bytes[(bytes.count - 64)...]), for: body, domain: .membership, signingKey: account.signingKey))
                != nil
        else { return nil }
        var reader = SharedReader(body)
        guard reader.read(4) == magic, reader.read(1) == [formatVersion], reader.uuid() == account.accountID,
            reader.uuid() == vaultID, let flag = reader.read(1)
        else { return nil }
        var index = SharedStreamIndex()
        switch flag {
        case [0]: break
        case [1]:
            guard let head = reader.read(32) else { return nil }
            index.judgedHead = head
        default: return nil
        }
        guard let deviceCount = reader.uint32(), Int(deviceCount) <= reader.remaining / 20 else { return nil }
        var previousDevice: UUID?
        for _ in 0..<deviceCount {
            guard let device = reader.uuid(), previousDevice.map({ $0.precedes(device) }) ?? true,
                let count = reader.uint32(), Int(count) <= reader.remaining / 60
            else { return nil }
            previousDevice = device
            var previousSequence: UInt64 = 0
            for _ in 0..<count {
                guard let sequence = reader.uint64(), sequence > previousSequence, let digest = reader.read(32),
                    let signer = reader.uuid(), let entryCount = reader.uint32(),
                    Int(entryCount) <= reader.remaining / 25
                else { return nil }
                previousSequence = sequence
                var entries: [VersionKey] = []
                entries.reserveCapacity(Int(entryCount))
                for _ in 0..<entryCount {
                    guard let record = reader.uuid(), let kind = reader.read(1), let version = reader.uint64() else {
                        return nil
                    }
                    entries.append(VersionKey(recordID: record, kind: kind[0], version: version))
                }
                guard let valueCount = reader.uint32(), Int(valueCount) <= reader.remaining / 48 else { return nil }
                var values: [ValueKey] = []
                values.reserveCapacity(Int(valueCount))
                for _ in 0..<valueCount {
                    guard let stampDevice = reader.uuid(), let valueDigest = reader.read(32) else { return nil }
                    values.append(ValueKey(device: stampDevice, digest: valueDigest))
                }
                index.record(
                    device: device, sequence: sequence,
                    segment: Segment(digest: digest, account: signer, entries: entries, values: values))
            }
        }
        guard let waitingCount = reader.uint32(), Int(waitingCount) <= reader.remaining / 16 else { return nil }
        var previousWaiting: UUID?
        for _ in 0..<waitingCount {
            guard let device = reader.uuid(), previousWaiting.map({ $0.precedes(device) }) ?? true else { return nil }
            previousWaiting = device
            index.awaiting.insert(device)
        }
        guard reader.remaining == 0 else { return nil }
        return index
    }
}

/// The bytes of a write cut over sync's logs (docs/02-architecture.md §8.7, §8.8): what the signing administrator's
/// device had merged of each of the departing account's devices' streams, as a sequence number and the chain of
/// segment digests through it. Opaque to `WatchwordSharing`, signed into the record with the rest.
///
/// `0x01 ‖ count u8 ‖ (device 16 ‖ sequence u64 ‖ chain 32)*`, devices in ascending byte order, at most 36 of
/// them (2 + 36 × 56 = 2,018 bytes, inside the 2,048 a cut may hold). The empty cut (`WriteCut.nothing`) holds
/// nothing. Anything else holds nothing either: a cut that does not parse cannot make a write count.
struct SyncWriteCut: Sendable, Hashable {
    struct Position: Sendable, Hashable {
        var sequence: UInt64
        var chain: [UInt8]
    }

    static let formatVersion: UInt8 = 1
    static let maximumDevices = 36

    var positions: [UUID: Position] = [:]

    init(positions: [UUID: Position]) {
        self.positions = positions
    }

    init(_ cut: WriteCut) {
        var reader = SharedReader(cut.bytes)
        guard reader.read(1) == [Self.formatVersion], let count = reader.read(1), Int(count[0]) <= Self.maximumDevices
        else { return }
        var parsed: [UUID: Position] = [:]
        var previous: UUID?
        for _ in 0..<count[0] {
            guard let device = reader.uuid(), previous.map({ $0.precedes(device) }) ?? true,
                let sequence = reader.uint64(), let chain = reader.read(32)
            else { return }
            previous = device
            parsed[device] = Position(sequence: sequence, chain: chain)
        }
        guard reader.remaining == 0 else { return }
        positions = parsed
    }

    func encoded() throws -> WriteCut {
        let devices = positions.keys.sorted { $0.precedes($1) }.prefix(Self.maximumDevices)
        var out: [UInt8] = [Self.formatVersion, UInt8(devices.count)]
        for device in devices {
            let position = positions[device]!
            out += SharedBytes.bytes(device) + SharedBytes.littleEndian(position.sequence) + position.chain
        }
        return try WriteCut(out)
    }

    /// Whether the segment of `device`'s stream at `sequence` is inside the cut, judged from the index: `nil` when
    /// that cannot be told yet, because the segments the chain covers are not all here.
    func contains(device: UUID, sequence: UInt64, index: SharedStreamIndex) -> Bool? {
        guard let position = positions[device], sequence <= position.sequence, sequence > 0 else { return false }
        guard let chain = index.chain(device: device, through: position.sequence) else { return nil }
        return chain == position.chain
    }
}

/// Little-endian encoding helpers for the session's own sharing formats.
enum SharedBytes {
    static func bytes(_ id: UUID) -> [UInt8] {
        id.byteArray
    }

    static func littleEndian(_ value: UInt64) -> [UInt8] {
        (0..<8).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
    }

    static func littleEndian32(_ value: UInt32) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
    }

    static func littleEndian16(_ value: UInt16) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value), UInt8(truncatingIfNeeded: value >> 8)]
    }

    /// Membership records, each `u16 length ‖ record`.
    static func encodeRecords(_ records: [MembershipRecord]) -> [UInt8] {
        records.flatMap { record -> [UInt8] in
            let bytes = record.encoded()
            return littleEndian16(UInt16(bytes.count)) + bytes
        }
    }

    /// The records of `encodeRecords`; one that does not parse ends the list there.
    static func decodeRecords(_ bytes: [UInt8]) -> [MembershipRecord] {
        var reader = SharedReader(bytes)
        var records: [MembershipRecord] = []
        while reader.remaining > 0, records.count < 1024, let length = reader.uint16(),
            Int(length) <= MembershipRecord.maximumLength, let body = reader.read(Int(length)),
            let record = try? MembershipRecord.parse(body)
        {
            records.append(record)
        }
        return records
    }
}

/// A bounded reader: every read checks what is left first, and a short input reads as `nil`.
struct SharedReader {
    private let bytes: [UInt8]
    private var offset = 0

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    var remaining: Int {
        bytes.count - offset
    }

    mutating func read(_ count: Int) -> [UInt8]? {
        guard count >= 0, count <= remaining else { return nil }
        defer { offset += count }
        return Array(bytes[offset..<(offset + count)])
    }

    mutating func uuid() -> UUID? {
        read(16).map(VaultSession.uuid)
    }

    mutating func uint64() -> UInt64? {
        read(8).map { $0.enumerated().reduce(0) { $0 | UInt64($1.element) << (8 * UInt64($1.offset)) } }
    }

    mutating func uint32() -> UInt32? {
        read(4).map { $0.enumerated().reduce(0) { $0 | UInt32($1.element) << (8 * UInt32($1.offset)) } }
    }

    mutating func uint16() -> UInt16? {
        read(2).map { UInt16($0[0]) | UInt16($0[1]) << 8 }
    }
}
