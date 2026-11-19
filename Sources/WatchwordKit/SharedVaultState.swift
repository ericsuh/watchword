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
/// carried it. A version's own revision is attributed the same way, through the segment that first carried it. **Is a
/// segment inside a write cut?** The cut commits to a device's stream up to a sequence number by a chain of these
/// digests, which every device recomputes from what it holds.
///
/// A stream is one account's by identity, not by inference (review finding Z157): a device's ID commits to its account
/// under its key (`DeviceIdentifier`), a shared vault counts a registry's device only if its ID commits to that
/// registry's account, and so every segment that verifies in a device's stream is signed by that one account. Which
/// account signed a stream's lowest segment, which could write when its key was current, and whose standing passes
/// it over (Z46, Z146, Z152, Z155) are no longer questions; `record` refuses a segment of any other account, which
/// cannot verify, so that no index can come to hold two.
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
        /// by its digest and signer, which need no key: a cut's chain runs over it, but nothing is known of what it
        /// carried (review finding Z51).
        var opened = true
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
    /// recorded too, each segment saying whether it was opened (Z51). 5 since `ownTakenOut` (Z54) moved to a row of
    /// its own (`OwnTakenOutRow`, Z121). 6 since `relied` (Z153) and `collected` (Z151). 7 since device IDs commit to
    /// their account (Z157): an earlier index was built while a stream's account was inferred and may file another
    /// account's segments in a stream, and every device that wrote one has an ID that commits to nothing, which no
    /// shared vault reads now, so there is nothing to carry forward and it is refused and rebuilt (round 5's L-M1 is
    /// moot: no installation of format 6 has a stream that still counts).
    static let formatVersion: UInt8 = 7
    static let maximumLength = 64 << 20

    /// By device, then sequence number.
    private(set) var streams: [UUID: [UInt64: Segment]] = [:]
    /// The lowest sequence recorded of each stream, kept beside `streams`.
    private var lowest: [UUID: UInt64] = [:]
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

    init() {}

    /// The account a device's stream belongs to: the one whose keys signed its segments recorded here, which is the
    /// account the device's ID commits to (Z157). `nil` for a stream nothing was recorded of.
    func account(ofStream device: UUID) -> UUID? {
        firstSequence(ofStream: device).flatMap { streams[device]?[$0]?.account }
    }

    /// The lowest sequence number recorded of a device's stream.
    func firstSequence(ofStream device: UUID) -> UInt64? {
        lowest[device]
    }

    /// Remembers a segment. The first copy seen of a name is kept: objects are written once, so a second, different
    /// object under the same name is a store showing devices different streams (`forkedStream`), and the cut's chain
    /// is what tells which one its signer held. A segment signed by another account than the stream's is refused: it
    /// cannot verify (Z157), and an index never holds two accounts' segments in one stream.
    ///
    /// A segment recorded unopened is completed by the same object once it opens (a key arrived, and the log is
    /// replayed): the same digest, now with what it carried.
    mutating func record(device: UUID, sequence: UInt64, segment: Segment) {
        if let held = streams[device]?[sequence] {
            guard !held.opened, segment.opened, held.digest == segment.digest, held.account == segment.account else {
                return
            }
            streams[device]?[sequence] = segment
            file(segment, device: device, sequence: sequence)
            return
        }
        if let owner = account(ofStream: device), owner != segment.account { return }
        streams[device, default: [:]][sequence] = segment
        lowest[device] = min(lowest[device] ?? .max, sequence)
        file(segment, device: device, sequence: sequence)
    }

    /// Forgets everything recorded of `device`'s stream (round 6's L3: an ID two counted registries list, recorded
    /// before the second arrived), so that the index is the one a device that never recorded it holds.
    mutating func forget(stream device: UUID) {
        streams[device] = nil
        lowest[device] = nil
        firstCarrier[device] = nil
        collected[device] = nil
        for value in Array(valueCarriers.keys) where valueCarriers[value]?[device] != nil {
            valueCarriers[value]?[device] = nil
            if valueCarriers[value]?.isEmpty == true { valueCarriers[value] = nil }
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

    /// The highest version of one record that any segment of `device`'s stream recorded here carried.
    func highestVersionCarried(by device: UUID, of recordID: UUID, kind: UInt8) -> UInt64 {
        firstCarrier[device]?.keys.filter { $0.recordID == recordID && $0.kind == kind }.map(\.version).max() ?? 0
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
        let collectedDevices = collected.keys.sorted { $0.precedes($1) }
        out += SharedBytes.littleEndian32(UInt32(collectedDevices.count))
        for device in collectedDevices {
            out += SharedBytes.bytes(device) + SharedBytes.littleEndian(collected[device]!)
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
                    let signer = reader.uuid(), let openedFlag = reader.read(1), openedFlag[0] <= 1
                else { return nil }
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
                        opened: openedFlag[0] == 1))
                // A stream holding two accounts' segments is no index this version wrote (Z157).
                guard index.segment(device: device, sequence: sequence) != nil else { return nil }
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
        guard let collectedCount = reader.uint32(), Int(collectedCount) <= reader.remaining / 24 else { return nil }
        var previousCollected: UUID?
        for _ in 0..<collectedCount {
            guard let device = reader.uuid(), previousCollected.map({ $0.precedes(device) }) ?? true,
                let sequence = reader.uint64(), sequence > 0
            else { return nil }
            previousCollected = device
            index.collected[device] = sequence
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
        parse(
            bytes, magic: magic, itemLength: itemLength, accountID: account.accountID, signingKey: account.signingKey,
            vaultID: vaultID, binding: binding)
    }

    /// As `parse(_:magic:itemLength:account:vaultID:binding:)`, with the account's public signing key alone: the
    /// Keychain's copy (`accountSigningKey`) where the session is locked.
    static func parse(
        _ bytes: [UInt8], magic: [UInt8], itemLength: Int, accountID: UUID, signingKey: [UInt8], vaultID: UUID,
        binding: [UInt8] = []
    ) -> [[UInt8]]? {
        guard bytes.count > 64 else { return nil }
        let body = Array(bytes[..<(bytes.count - 64)])
        guard
            (try? Signatures.verify(
                Array(bytes[(bytes.count - 64)...]), for: body, domain: .membership, signingKey: signingKey))
                != nil
        else { return nil }
        var reader = SharedReader(body)
        guard reader.read(magic.count) == magic, reader.read(1) == [formatVersion],
            reader.uuid() == accountID, reader.uuid() == vaultID, reader.read(binding.count) == binding,
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

/// The earlier device IDs of this installation whose work a restore left in a shared vault and has still to carry
/// there (review of round 16, Z216): the devices that the vault's signed `SyncState.restoredUnpublished` names, kept
/// in a row of their own (`SharingStateKey.restoredChain`) so that they survive that state being damaged or edited
/// (A8), which then no longer verifies (Z200). Written by the move of an earlier ID's sync state, from what verifies
/// there (`AccountRecord.migration` and the earlier ID's signed state), and by each later save of those entries; bound
/// to the vault and to this device's ID, so that a row of another device of the account, or of the earlier ID itself,
/// copied here names nothing. Signed by the account, so a row planted or edited in the file (A8) is refused: a
/// state that does not verify names no earlier ID any more (Z206, Z211 and Z216 were each an ID planted there).
enum RestoredChainRow {
    static let magic: [UInt8] = Array("WWRC".utf8)

    static func signed(_ deviceIDs: Set<UUID>, device: UUID, account: UUID, vaultID: UUID, keyset: Keyset) throws
        -> [UInt8]
    {
        try SignedLocalSet.signed(
            magic: magic, items: deviceIDs.map(SharedBytes.bytes), account: account, vaultID: vaultID,
            binding: SharedBytes.bytes(device), keyset: keyset)
    }

    static func parse(_ bytes: [UInt8], device: UUID, account: UUID, signingKey: [UInt8], vaultID: UUID)
        -> Set<UUID>?
    {
        SignedLocalSet.parse(
            bytes, magic: magic, itemLength: 16, accountID: account, signingKey: signingKey, vaultID: vaultID,
            binding: SharedBytes.bytes(device)
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
