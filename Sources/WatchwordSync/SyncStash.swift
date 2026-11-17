import Foundation
import WatchwordEnvelope

/// Entries of ignorable record kinds this version does not carry, kept aside for a version that does (ADR 0009), and
/// the kinds dropped past the caps. Kept apart from `SyncState`, in its own row (`SyncStateStore.saveStash`), so a sync
/// writes it once per pass rather than with every segment it merges.
///
/// Each entry remembers its **author**: the device whose signed segment or snapshot carried it. What a revoked device
/// carried is not read any more (§7.8), so `forgetRetired` drops it, except the revoked device's own versions from its
/// own stream, which nothing else carries and which are kept, but no longer hold back snapshots.
///
/// Every row carries a **generation**, which the engine raises at each save and records in `SyncState`: a row that is
/// not the generation the state names (an older one put back, an empty one, none at all) is not trusted to be whole,
/// and the log is replayed. The session signs each row it writes (`AuthenticatedSyncState`), so a planted one is
/// refused.
///
/// Lookups go through the slot of an entry (record, kind, writing device, deletion or not), and the counts and byte
/// totals, overall and per author, are kept as entries come and go, so keeping an entry costs a dictionary lookup.
public struct SyncStash: Sendable, Hashable {
    public struct Kept: Sendable, Hashable {
        public var entry: UnknownSyncEntry
        /// The device whose signed object carried the entry: a segment's author, or a snapshot's.
        public var author: UUID

        public init(entry: UnknownSyncEntry, author: UUID) {
            self.entry = entry
            self.author = author
        }

        /// From its writer's own stream (or its writer's own snapshot): the writer's word for its own version.
        var isAuthorsOwn: Bool {
            entry.device == author
        }

        /// The one order within a slot, so equal contents compare and encode equal: version, then carrier, then
        /// the bytes (two different entries one writer gave the same version both stay, in a fixed order).
        static func precedes(_ a: Kept, _ b: Kept) -> Bool {
            if a.entry.version != b.entry.version { return a.entry.version < b.entry.version }
            if a.author != b.author { return a.author.precedes(b.author) }
            let left = a.entry.envelope ?? a.entry.erasure
            let right = b.entry.envelope ?? b.entry.erasure
            return left.lexicographicallyPrecedes(right)
        }
    }

    struct Slot: Hashable, Sendable {
        var recordID: UUID
        var rawKind: UInt8
        var device: UUID
        var deletion: Bool

        init(_ entry: UnknownSyncEntry) {
            recordID = entry.recordID
            rawKind = entry.rawKind
            device = entry.device
            deletion = entry.isDeletion
        }

        static func precedes(_ a: Slot, _ b: Slot) -> Bool {
            if a.recordID != b.recordID { return a.recordID.precedes(b.recordID) }
            if a.rawKind != b.rawKind { return a.rawKind < b.rawKind }
            if a.device != b.device { return a.device.precedes(b.device) }
            return !a.deletion && b.deletion
        }
    }

    struct Usage: Hashable, Sendable {
        var count = 0
        var bytes = 0
    }

    /// Sorted within a slot (`Kept.precedes`), so equal contents compare equal.
    private(set) var slots: [Slot: [Kept]] = [:]
    public private(set) var count = 0
    public private(set) var bytes = 0
    private(set) var usage: [UUID: Usage] = [:]
    /// For each author, the kinds of which an entry it carried was not kept, its own share of the stash being full.
    public var overflow: [UUID: Set<UInt8>] = [:]
    /// The kinds of which an entry was not kept because the vault's whole stash was full: crowded out by what others
    /// carried, so held against nobody. Room freed later (a carrier revoked) is filled again from the log.
    public var crowdedOut: Set<UInt8> = []
    /// Raised by the engine at each save and recorded in `SyncState.stashGeneration`.
    public var generation: UInt64 = 0

    public init() {}

    public var isEmpty: Bool {
        count == 0 && overflow.isEmpty && crowdedOut.isEmpty
    }

    public var entries: [Kept] {
        slots.values.flatMap { $0 }
    }

    func held(in slot: Slot) -> [Kept] {
        slots[slot] ?? []
    }

    public func usage(of author: UUID) -> (count: Int, bytes: Int) {
        let used = usage[author] ?? Usage()
        return (used.count, used.bytes)
    }

    @discardableResult
    public mutating func insert(_ kept: Kept) -> Bool {
        let slot = Slot(kept.entry)
        var held = slots[slot] ?? []
        // Binary search for the place: a slot can be long in a hostile row, and a scan per insert is quadratic.
        var low = 0
        var high = held.count
        while low < high {
            let middle = (low + high) / 2
            if Kept.precedes(held[middle], kept) { low = middle + 1 } else { high = middle }
        }
        guard low == held.count || held[low] != kept else { return false }
        held.insert(kept, at: low)
        slots[slot] = held
        account(kept, sign: 1)
        return true
    }

    public mutating func remove(_ kept: Kept) {
        let slot = Slot(kept.entry)
        guard var held = slots[slot], let index = held.firstIndex(of: kept) else { return }
        held.remove(at: index)
        slots[slot] = held.isEmpty ? nil : held
        account(kept, sign: -1)
    }

    private mutating func account(_ kept: Kept, sign: Int) {
        count += sign
        bytes += sign * kept.entry.length
        var used = usage[kept.author] ?? Usage()
        used.count += sign
        used.bytes += sign * kept.entry.length
        usage[kept.author] = used.count == 0 ? nil : used
    }

    /// Drops what a revoked device carried, as its objects are no longer read: everything but its own versions from
    /// its own stream, which nothing else carries (kept, processed once their kind is read, and no longer holding back
    /// snapshots), and the record of what it carried that was dropped. What it carried for other devices goes too
    /// (N18): their own streams, or the snapshots of devices that read the kind, carry it. While trusted devices'
    /// entries have been crowded out, the revoked device's own versions go as well: room for what trusted devices
    /// carried comes first (N17). Returns whether anything kept was dropped, which frees room.
    @discardableResult
    public mutating func forgetRetired(_ retired: Set<UUID>) -> Bool {
        guard !retired.isEmpty else { return false }
        let before = count
        for kept in entries where retired.contains(kept.author) && (!kept.isAuthorsOwn || !crowdedOut.isEmpty) {
            remove(kept)
        }
        for author in retired { overflow[author] = nil }
        return count < before
    }

    /// Whether this device must write no ordinary snapshot (ADR 0009): it holds, or dropped, an entry carried by a
    /// device still trusted, which a snapshot of its own would cover without carrying.
    public func holdsBackSnapshots(retired: Set<UUID>) -> Bool {
        !authorsHoldingBackSnapshots(retired: retired).isEmpty || !crowdedOut.isEmpty
    }

    public func authorsHoldingBackSnapshots(retired: Set<UUID>) -> Set<UUID> {
        Set(usage.keys).union(overflow.keys).subtracting(retired)
    }

    // MARK: - Encoding

    static let magic: [UInt8] = Array("WWSK".utf8)
    static let formatVersion: UInt8 = 2
    /// Ceilings for what a row may declare, whatever the caps it is parsed with.
    public static let maximumEntries = 1 << 16
    public static let maximumBytes = 64 << 20

    /// ```
    /// magic "WWSK"  formatVersion u8 = 2  generation u64
    /// crowdedOutCount u32, then per element: kind u8                (ascending)
    /// overflowCount u32, then per element: author 16, kind u8      (ascending)
    /// entryCount u32, then per entry: author 16, recordID 16, kind u8, keyID 16, version u64, device 16, flags u8
    ///   (bit 0: deletion), length u32, envelope or erasure summary   (by slot, then within a slot)
    /// ```
    public func encoded() -> [UInt8] {
        var out = Self.magic
        out.append(Self.formatVersion)
        out.append(contentsOf: SyncPayload.littleEndian(generation))
        out.append(contentsOf: SyncPayload.littleEndian(UInt32(crowdedOut.count)))
        out.append(contentsOf: crowdedOut.sorted())
        var lost: [(UUID, UInt8)] = []
        for (author, kinds) in overflow {
            for kind in kinds { lost.append((author, kind)) }
        }
        lost.sort { $0.0 != $1.0 ? $0.0.precedes($1.0) : $0.1 < $1.1 }
        out.append(contentsOf: SyncPayload.littleEndian(UInt32(lost.count)))
        for (author, kind) in lost {
            out.append(contentsOf: SyncPayload.bytes(author))
            out.append(kind)
        }
        out.append(contentsOf: SyncPayload.littleEndian(UInt32(count)))
        for slot in slots.keys.sorted(by: Slot.precedes) {
            for kept in slots[slot] ?? [] {
                let entry = kept.entry
                out.append(contentsOf: SyncPayload.bytes(kept.author))
                out.append(contentsOf: SyncPayload.bytes(entry.recordID))
                out.append(entry.rawKind)
                out.append(contentsOf: SyncPayload.bytes(entry.keyID))
                out.append(contentsOf: SyncPayload.littleEndian(entry.version))
                out.append(contentsOf: SyncPayload.bytes(entry.device))
                out.append(entry.isDeletion ? 1 : 0)
                let body = entry.envelope ?? entry.erasure
                out.append(contentsOf: SyncPayload.littleEndian(UInt32(body.count)))
                out.append(contentsOf: body)
            }
        }
        return out
    }

    /// Parses a stored stash, held to the caller's caps. The row is in a file A8 can edit, so it is read like anything
    /// else hostile: the declared count is checked against the caps and the bytes that remain before anything is read,
    /// the bytes against the cap as they are read, and only what `encoded()` writes is accepted — ignorable kinds only
    /// (a critical kind is never kept aside, so a row naming one was planted), a positive version, a deletion with no
    /// key and an erasure summary, a live entry with a non-empty envelope of at most the payload's bound. Entries are
    /// gathered per slot and each slot sorted once, so a row costs `n log n` however its entries fall into slots.
    public static func parse(
        _ bytes: [UInt8], maximumEntries: Int = SyncStash.maximumEntries, maximumBytes: Int = SyncStash.maximumBytes
    ) throws -> SyncStash {
        var reader = ByteReader(bytes)
        guard try reader.read(4) == magic else { throw SyncFormatError.badMagic }
        let version = try reader.byte()
        guard version == formatVersion else { throw SyncFormatError.unsupportedFormatVersion(version) }
        var stash = SyncStash()
        stash.generation = try reader.uint64()

        let crowdedCount = Int(try reader.uint32())
        guard crowdedCount <= reader.remaining, crowdedCount <= 256 else { throw SyncFormatError.countTooLarge }
        for _ in 0..<crowdedCount {
            stash.crowdedOut.insert(try ignorableKind(reader.byte()))
        }

        let lostCount = Int(try reader.uint32())
        guard lostCount <= reader.remaining / 17 else { throw SyncFormatError.countTooLarge }
        for _ in 0..<lostCount {
            let author = try reader.uuid()
            stash.overflow[author, default: []].insert(try ignorableKind(reader.byte()))
        }

        let entryCount = Int(try reader.uint32())
        let smallest = 16 + SyncPayload.minimumEntryLength
        guard entryCount <= min(maximumEntries, Self.maximumEntries), entryCount <= reader.remaining / smallest else {
            throw SyncFormatError.countTooLarge
        }
        let byteCap = min(maximumBytes, Self.maximumBytes)
        var gathered: [Slot: [Kept]] = [:]
        for _ in 0..<entryCount {
            let author = try reader.uuid()
            let kept = Kept(entry: try entry(&reader), author: author)
            stash.bytes += kept.entry.length
            guard stash.bytes <= byteCap else { throw SyncFormatError.countTooLarge }
            gathered[Slot(kept.entry), default: []].append(kept)
        }
        guard reader.remaining == 0 else { throw SyncFormatError.trailingBytes }
        stash.bytes = 0
        for (slot, held) in gathered {
            var unique: [Kept] = []
            unique.reserveCapacity(held.count)
            for kept in held.sorted(by: Kept.precedes) where unique.last != kept { unique.append(kept) }
            stash.slots[slot] = unique
            for kept in unique { stash.account(kept, sign: 1) }
        }
        return stash
    }

    private static func ignorableKind(_ kind: UInt8) throws -> UInt8 {
        guard EnvelopeKind.criticality(ofRawValue: kind) == .ignorable else {
            throw SyncFormatError.unsupportedRecordKind(kind)
        }
        return kind
    }

    private static func entry(_ reader: inout ByteReader) throws -> UnknownSyncEntry {
        let recordID = try reader.uuid()
        let kind = try ignorableKind(reader.byte())
        let keyID = try reader.uuid()
        let recordVersion = try reader.uint64()
        guard recordVersion > 0 else { throw SyncFormatError.malformedEntry }
        let device = try reader.uuid()
        let flags = try reader.byte()
        let length = Int(try reader.uint32())
        switch flags {
        case 0:
            guard length <= SyncPayload.maximumEntryEnvelopeLength else { throw SyncFormatError.entryTooLarge(length) }
            guard length > 0 else { throw SyncFormatError.malformedEntry }
            return UnknownSyncEntry(
                recordID: recordID, rawKind: kind, keyID: keyID, version: recordVersion, device: device,
                envelope: try reader.read(length))
        case 1:
            guard keyID == SyncPayload.zeroUUID else { throw SyncFormatError.malformedEntry }
            guard length <= SyncPayload.maximumErasureLength else { throw SyncFormatError.erasureTooLarge(length) }
            return UnknownSyncEntry(
                recordID: recordID, rawKind: kind, keyID: keyID, version: recordVersion, device: device,
                envelope: nil, erasure: try reader.read(length))
        default:
            throw SyncFormatError.unknownFlags(flags)
        }
    }
}
