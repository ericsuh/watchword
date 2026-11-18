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
        /// Whether this device opened the segment. One sealed under a key it does not hold is recorded all the same,
        /// by its digest and signer, which need no key: it names the stream's account like any other and a cut's
        /// chain runs over it, but nothing is known of what it carried (review finding Z51).
        var opened = true
        /// The vault key the segment was sealed under, from its envelope header, which needs no key to read: with its
        /// signer, whether it names the stream (`NamingKey`, review finding Z152). `nil` for one recorded without it.
        var keyID: UUID?
    }

    /// An account and a vault key under which its segments name a stream: it held a role that may write when it
    /// first appeared in the chain while that key was current (review finding Z152).
    struct NamingKey: Sendable, Hashable {
        var account: UUID
        var keyID: UUID
    }

    /// A value as the index files it: the device its stamp names, and SHA-256 of its encoding with the whole stamp.
    struct ValueKey: Sendable, Hashable {
        var device: UUID
        var digest: [UInt8]
    }

    static let magic: [UInt8] = Array("WWSI".utf8)
    /// 3 since note-line removals, discards and history entries became attributable values (review findings S32,
    /// S43): an index of an earlier format filed none of them, so it is refused on load and rebuilt from the log by a
    /// replay, which files them, before anything is judged against it. 4 since segments that do not open here are
    /// recorded too, each segment saying whether it was opened (Z51): an earlier index lacks them, and names a
    /// stream's account by the first segment that happened to open. 5 since `ownTakenOut` (Z54) moved to a row of its
    /// own, which a rebuild of the index leaves alone (`OwnTakenOutRow`, Z121). 6 since `relied` (Z153): an earlier
    /// index does not say which revocations what it admitted rested on, so it is rebuilt by a replay; with it
    /// `collected` (Z151), each segment's `keyID` (Z152) and `skippedPassedOver` (Z155).
    static let formatVersion: UInt8 = 6
    static let maximumLength = 64 << 20

    /// By device, then sequence number.
    private(set) var streams: [UUID: [UInt64: Segment]] = [:]
    /// The lowest sequence recorded of each stream whose signer is not `passedOver`, kept beside `streams`, among the
    /// segments that are `naming`'s and among the rest: the segment that names the stream's account
    /// (`account(ofStream:)`), asked for with every value judged.
    private var lowestNaming: [UUID: UInt64] = [:]
    private var lowestOther: [UUID: UInt64] = [:]
    /// The highest sequence recorded of each stream whose signer is not `passedOver`.
    private var highestCounted: [UUID: UInt64] = [:]
    /// The account and key pairs whose segments name a stream before any other's (review finding Z152): the accounts
    /// that first appeared in the chain, while that key was current, in a role that may write. A member let write
    /// only later (a read-only member promoted) did not, and a segment it signed under that key may have been written
    /// while it could not: planted at segment 1 of another member's stream before that member published there, it
    /// took the stream the moment the promotion took it out of `passedOver`, and every device held aside what that
    /// member published. A function of the accepted chain, so a promotion moves nothing; the session rotates the key
    /// after one (`promotedWithinKeyEra`), so that the promoted member's own later segments name their streams. A
    /// stream with no such segment is named by its lowest other one.
    private(set) var naming: Set<NamingKey> = []
    /// The accounts whose work cannot count in the vault under its current head (`WriteStanding.nothingCounts`: a
    /// member never let write, say), whose segments name no stream's account (review finding Z146). Such a member
    /// could otherwise list another member's device ID in their own registry (S33), sign that device's segment 1
    /// before it published there, and have every device take the stream for theirs and hold aside all that device
    /// wrote; and since Z137 every device records that segment. Set from the ledger by the session before each
    /// judgement (`setNaming`), never saved: it is a function of the head, and refiling on a change keeps every
    /// device that holds the same segments and head in agreement.
    private(set) var passedOver: Set<UUID> = []
    /// The basis the vault's items were last judged against (`VaultSession.judgedBasis`: the membership head, and the
    /// revocations the judgements rested on, Z153), so that a change of either is noticed after a restart too.
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
    /// Devices whose revocation (counted or not) a judgement since the last replay asked about, for a value or an edit
    /// no segment here showed (review finding Z153). Together with `awaiting`, what the judged basis binds
    /// (`VaultSession.judgedBasis`): a revocation of one of them that starts or stops counting changes what counts.
    var relied: Set<UUID> = []
    /// For each stream, the most of it that a snapshot merged here says its author had merged (review finding Z151).
    /// A shared vault reads only its owner's snapshots, from before it was shared: what they cover of a stream whose
    /// first segments are not here was collected then, and is in the store through them. A stream whose first
    /// segments no snapshot covers is merely missing them here (a lagging listing, a store withholding them) and is
    /// waited for.
    var collected: [UUID: UInt64] = [:]
    /// For each stream, the lowest sequence of a `passedOver` account's segment that was not recorded because no
    /// segment of another account's is recorded above it there (review finding Z155). Such a segment names nothing and
    /// is filed nowhere; it matters only to a write cut's chain, which runs over a stream up to a segment of the
    /// stream's own, so it is recorded once one is above it (a replay, asked for when that segment is recorded). A
    /// member who may never write can sign any number of segments into streams of devices they list, and recording
    /// each grew the signed index without bound; now it grows only by what another account's segments sit above.
    var skippedPassedOver: [UUID: UInt64] = [:]

    init() {}

    /// Whether a segment of an account that is not `passedOver` is recorded in `device`'s stream above `sequence`.
    func hasCountedSegment(_ device: UUID, above sequence: UInt64) -> Bool {
        (highestCounted[device] ?? 0) > sequence
    }

    /// The account a device's stream belongs to: the one whose keys signed its lowest-numbered segment recorded here,
    /// passing over the segments of an account whose work cannot count (`passedOver`, Z146), and of those the lowest
    /// that `naming` holds if there is one (Z152) (review finding Z46). A stream is named by a device ID alone, device
    /// IDs are chosen by devices, and nothing
    /// stops a member listing another member's device ID in their own registry and signing objects into "its"
    /// stream. So the name does not say whose a stream is; its first segment does, and a shared vault keeps its whole
    /// log, so devices that hold the same segments agree. `nil` for a stream nothing was recorded of.
    func account(ofStream device: UUID) -> UUID? {
        firstSequence(ofStream: device).flatMap { streams[device]?[$0]?.account }
    }

    /// The sequence number of the segment that names a device's stream (`account(ofStream:)`).
    func firstSequence(ofStream device: UUID) -> UInt64? {
        lowestNaming[device] ?? lowestOther[device]
    }

    private func names(_ segment: Segment) -> Bool {
        segment.keyID.map { naming.contains(NamingKey(account: segment.account, keyID: $0)) } ?? false
    }

    private mutating func noteLowest(_ segment: Segment, device: UUID, sequence: UInt64) {
        guard !passedOver.contains(segment.account) else { return }
        highestCounted[device] = max(highestCounted[device] ?? 0, sequence)
        if names(segment) {
            lowestNaming[device] = min(lowestNaming[device] ?? .max, sequence)
        } else {
            lowestOther[device] = min(lowestOther[device] ?? .max, sequence)
        }
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
    ///
    /// A segment recorded unopened is completed by the same object once it opens (a key arrived, and the log is
    /// replayed): the same digest, now with what it carried.
    mutating func record(device: UUID, sequence: UInt64, segment: Segment) {
        if let held = streams[device]?[sequence] {
            guard !held.opened, segment.opened, held.digest == segment.digest, held.account == segment.account else {
                return
            }
            streams[device]?[sequence] = segment
            if segment.account == account(ofStream: device) { file(segment, device: device, sequence: sequence) }
            return
        }
        let before = account(ofStream: device)
        streams[device, default: [:]][sequence] = segment
        noteLowest(segment, device: device, sequence: sequence)
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

    /// Names no stream after `accounts`' segments (`passedOver`), names streams after `naming`'s first, and files
    /// again what every stream carried for the account it now belongs to. Nothing changes if both are the ones in
    /// force.
    mutating func setNaming(passedOver accounts: Set<UUID>, naming keys: Set<NamingKey>) {
        guard accounts != passedOver || keys != naming else { return }
        passedOver = accounts
        naming = keys
        lowestNaming = [:]
        lowestOther = [:]
        highestCounted = [:]
        firstCarrier = [:]
        valueCarriers = [:]
        for (device, stream) in streams {
            for (number, held) in stream { noteLowest(held, device: device, sequence: number) }
            guard let owner = account(ofStream: device) else { continue }
            for (number, held) in stream.sorted(by: { $0.key < $1.key }) where held.account == owner {
                file(held, device: device, sequence: number)
            }
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

    /// The highest record version any segment of `device`'s stream recorded here carried for the stream's account.
    func highestVersionCarried(by device: UUID) -> UInt64 {
        firstCarrier[device]?.keys.map(\.version).max() ?? 0
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
                out += [segment.opened ? 1 : 0]
                out += segment.keyID.map { [1] + SharedBytes.bytes($0) } ?? [0]
                out += SharedBytes.littleEndian32(UInt32(segment.entries.count))
                for entry in segment.entries {
                    out += SharedBytes.bytes(entry.recordID) + [entry.kind] + SharedBytes.littleEndian(entry.version)
                }
                out += SharedBytes.littleEndian32(UInt32(segment.values.count))
                for value in segment.values { out += SharedBytes.bytes(value.device) + value.digest }
            }
        }
        for set in [awaiting, relied] {
            let devices = set.sorted { $0.precedes($1) }
            out += SharedBytes.littleEndian32(UInt32(devices.count))
            for device in devices { out += SharedBytes.bytes(device) }
        }
        for map in [collected, skippedPassedOver] {
            let devices = map.keys.sorted { $0.precedes($1) }
            out += SharedBytes.littleEndian32(UInt32(devices.count))
            for device in devices { out += SharedBytes.bytes(device) + SharedBytes.littleEndian(map[device]!) }
        }
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
                let count = reader.uint32(), Int(count) <= reader.remaining / 61
            else { return nil }
            previousDevice = device
            var previousSequence: UInt64 = 0
            for _ in 0..<count {
                guard let sequence = reader.uint64(), sequence > previousSequence, let digest = reader.read(32),
                    let signer = reader.uuid(), let openedFlag = reader.read(1), openedFlag[0] <= 1,
                    let keyFlag = reader.read(1), keyFlag[0] <= 1
                else { return nil }
                var keyID: UUID?
                if keyFlag[0] == 1 {
                    guard let key = reader.uuid() else { return nil }
                    keyID = key
                }
                guard let entryCount = reader.uint32(), Int(entryCount) <= reader.remaining / 25 else { return nil }
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
                    segment: Segment(
                        digest: digest, account: signer, entries: entries, values: values,
                        opened: openedFlag[0] == 1, keyID: keyID))
            }
        }
        for keyPath in [\SharedStreamIndex.awaiting, \SharedStreamIndex.relied] {
            guard let count = reader.uint32(), Int(count) <= reader.remaining / 16 else { return nil }
            var previous: UUID?
            for _ in 0..<count {
                guard let device = reader.uuid(), previous.map({ $0.precedes(device) }) ?? true else { return nil }
                previous = device
                index[keyPath: keyPath].insert(device)
            }
        }
        for keyPath in [\SharedStreamIndex.collected, \SharedStreamIndex.skippedPassedOver] {
            guard let count = reader.uint32(), Int(count) <= reader.remaining / 24 else { return nil }
            var previous: UUID?
            for _ in 0..<count {
                guard let device = reader.uuid(), previous.map({ $0.precedes(device) }) ?? true,
                    let sequence = reader.uint64(), sequence > 0
                else { return nil }
                previous = device
                index[keyPath: keyPath][device] = sequence
            }
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

/// A set of fixed-length items this device keeps about one shared vault, as local state like the stream index:
/// `magic 4 ‖ version u8 = 1 ‖ own account 16 ‖ vault 16 ‖ binding ‖ count u32 ‖ items, in ascending byte order with
/// no repeats ‖ signature 64`, signed by the account's own key under `SignatureDomain.membership`. One that does not
/// verify, names another account, vault or binding, or is not in that one form is refused whole (`nil`), which a
/// caller treats as "not known" and never as "known to be empty" where that would open something (A8).
enum SignedLocalSet {
    static let formatVersion: UInt8 = 1
    static let maximumItems = 1 << 16

    static func signed(
        magic: [UInt8], items: [[UInt8]], account: UUID, vaultID: UUID, binding: [UInt8] = [], keyset: Keyset
    ) throws -> [UInt8] {
        let ordered = Array(Set(items)).sorted { $0.lexicographicallyPrecedes($1) }.prefix(maximumItems)
        var out = magic + [formatVersion] + SharedBytes.bytes(account) + SharedBytes.bytes(vaultID) + binding
        out += SharedBytes.littleEndian32(UInt32(ordered.count))
        for item in ordered { out += item }
        return out + (try keyset.sign(out, domain: .membership))
    }

    static func parse(
        _ bytes: [UInt8], magic: [UInt8], itemLength: Int, account: PublicKeyBundle, vaultID: UUID,
        binding: [UInt8] = []
    ) -> [[UInt8]]? {
        guard bytes.count > 64 else { return nil }
        let body = Array(bytes[..<(bytes.count - 64)])
        guard
            (try? Signatures.verify(
                Array(bytes[(bytes.count - 64)...]), for: body, domain: .membership, signingKey: account.signingKey))
                != nil
        else { return nil }
        var reader = SharedReader(body)
        guard reader.read(magic.count) == magic, reader.read(1) == [formatVersion],
            reader.uuid() == account.accountID, reader.uuid() == vaultID, reader.read(binding.count) == binding,
            let count = reader.uint32(), Int(count) <= maximumItems, Int(count) * itemLength == reader.remaining
        else { return nil }
        var items: [[UInt8]] = []
        for _ in 0..<count {
            guard let item = reader.read(itemLength),
                items.last.map({ $0.lexicographicallyPrecedes(item) }) ?? true
            else { return nil }
            items.append(item)
        }
        return items
    }
}

/// Which keys of a shared vault this device has seen to be the ones its ledger hands this account (review finding
/// Z59): each key that arrived by grant, by key ID, that this device opened from a grant the saved ledger entitles
/// this account to, or found byte for byte equal to such a grant. Bound to the ledger's owner. A key of the vault the
/// account's directory brings from another device is made resident only if it is listed here, or once a grant shows
/// it: a key ID alone shows nothing, since key IDs are public and whoever signs a chain chooses the IDs it names.
enum SharedKeyProvenance {
    static let magic: [UInt8] = Array("WWVK".utf8)

    static func signed(_ keyIDs: Set<UUID>, owner: UUID, account: UUID, vaultID: UUID, keyset: Keyset) throws
        -> [UInt8]
    {
        try SignedLocalSet.signed(
            magic: magic, items: keyIDs.map(SharedBytes.bytes), account: account, vaultID: vaultID,
            binding: SharedBytes.bytes(owner), keyset: keyset)
    }

    static func parse(_ bytes: [UInt8], owner: UUID, account: PublicKeyBundle, vaultID: UUID) -> Set<UUID>? {
        SignedLocalSet.parse(
            bytes, magic: magic, itemLength: 16, account: account, vaultID: vaultID, binding: SharedBytes.bytes(owner)
        ).map { Set($0.map(VaultSession.uuid)) }
    }
}

/// The versions this device itself wrote and had not published that its own take-out removed from a shared vault
/// and held aside (a write made before it was shown the record that ended its account's permission), in a row of
/// their own (`SharingStateKey.ownTakenOut`). The copy half of a move may be among them, and its other half, a
/// deletion in another vault, waits for it (`VaultSession.holdsUnpublishedWork`). Signed, because an entry in the
/// quarantine says only whose device its writer *claims*: anyone who can have this device hold an entry aside could
/// otherwise hold its deletions back in every vault (review finding Z54). Not in the stream index any more (Z121):
/// the take-out removed those versions from the store, so a rebuild of the index from the log cannot find them
/// again, and the gate must not open because the index was refused, outgrew its bound, or was rebuilt.
///
/// `complete` says whether the set is all of them. It is not when the row could not be read (missing, or not
/// verifying): versions may have been taken out that it does not list, and until the quarantine shows that none of
/// this device's can be among them the gate falls back to the rule before Z54.
enum OwnTakenOutRow {
    static let magic: [UInt8] = Array("WWTO".utf8)

    static func signed(_ versions: Set<VersionKey>, complete: Bool, account: UUID, vaultID: UUID, keyset: Keyset)
        throws -> [UInt8]
    {
        try SignedLocalSet.signed(
            magic: magic, items: versions.map(bytes), account: account, vaultID: vaultID,
            binding: [complete ? 1 : 0], keyset: keyset)
    }

    static func parse(_ bytes: [UInt8], account: PublicKeyBundle, vaultID: UUID)
        -> (versions: Set<VersionKey>, complete: Bool)?
    {
        for complete in [true, false] {
            guard
                let items = SignedLocalSet.parse(
                    bytes, magic: magic, itemLength: 25, account: account, vaultID: vaultID,
                    binding: [complete ? 1 : 0])
            else { continue }
            var versions: Set<VersionKey> = []
            for item in items {
                var reader = SharedReader(item)
                guard let record = reader.uuid(), let kind = reader.read(1), let version = reader.uint64() else {
                    return nil
                }
                versions.insert(VersionKey(recordID: record, kind: kind[0], version: version))
            }
            return (versions, complete)
        }
        return nil
    }

    static func bytes(_ version: VersionKey) -> [UInt8] {
        SharedBytes.bytes(version.recordID) + [version.kind] + SharedBytes.littleEndian(version.version)
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
