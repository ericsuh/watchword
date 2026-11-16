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
    }

    struct Usage: Hashable, Sendable {
        var count = 0
        var bytes = 0
    }

    /// Sorted within a slot (version, then author), so equal contents compare equal.
    private(set) var slots: [Slot: [Kept]] = [:]
    public private(set) var count = 0
    public private(set) var bytes = 0
    private(set) var usage: [UUID: Usage] = [:]
    /// For each author, the kinds of which an entry it carried was not kept, the stash being full.
    public var overflow: [UUID: Set<UInt8>] = [:]

    public init() {}

    public var isEmpty: Bool {
        count == 0 && overflow.isEmpty
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
        guard !held.contains(kept) else { return false }
        held.append(kept)
        held.sort { ($0.entry.version, $0.author.uuidString) < ($1.entry.version, $1.author.uuidString) }
        slots[slot] = held
        count += 1
        bytes += kept.entry.length
        usage[kept.author, default: Usage()].count += 1
        usage[kept.author, default: Usage()].bytes += kept.entry.length
        return true
    }

    public mutating func remove(_ kept: Kept) {
        let slot = Slot(kept.entry)
        guard var held = slots[slot], let index = held.firstIndex(of: kept) else { return }
        held.remove(at: index)
        slots[slot] = held.isEmpty ? nil : held
        count -= 1
        bytes -= kept.entry.length
        usage[kept.author]?.count -= 1
        usage[kept.author]?.bytes -= kept.entry.length
        if usage[kept.author]?.count == 0 { usage[kept.author] = nil }
    }

    /// Drops what a revoked device carried, as its objects are no longer read: everything but its own versions from
    /// its own stream, which nothing else carries (kept, processed once their kind is read, and no longer holding back
    /// snapshots), and the record of what it carried that was dropped.
    public mutating func forgetRetired(_ retired: Set<UUID>) {
        guard !retired.isEmpty else { return }
        for kept in entries where retired.contains(kept.author) && !kept.isAuthorsOwn {
            remove(kept)
        }
        for author in retired { overflow[author] = nil }
    }

    /// Whether this device must write no ordinary snapshot (ADR 0009): it holds, or dropped, an entry carried by a
    /// device still trusted, which a snapshot of its own would cover without carrying.
    public func holdsBackSnapshots(retired: Set<UUID>) -> Bool {
        authorsHoldingBackSnapshots(retired: retired).isEmpty == false
    }

    public func authorsHoldingBackSnapshots(retired: Set<UUID>) -> Set<UUID> {
        Set(usage.keys).union(overflow.keys).subtracting(retired)
    }

    // MARK: - Encoding

    static let magic: [UInt8] = Array("WWSK".utf8)
    static let formatVersion: UInt8 = 1
    /// Ceilings for what a row may declare, far above any cap a configuration sets (`SyncConfiguration`); the engine
    /// then holds the row to its own caps.
    public static let maximumEntries = 1 << 16
    public static let maximumBytes = 64 << 20

    /// ```
    /// magic "WWSK"  formatVersion u8 = 1
    /// overflowCount u32, then per element: author 16, kind u8     (ascending)
    /// entryCount u32, then per entry: author 16, recordID 16, kind u8, keyID 16, version u64, device 16, flags u8
    ///   (bit 0: deletion), length u32, envelope or erasure summary   (ascending)
    /// ```
    public func encoded() -> [UInt8] {
        var out = Self.magic + [Self.formatVersion]
        let lost = overflow.flatMap { author, kinds in kinds.map { (author, $0) } }.sorted {
            ($0.0.uuidString, $0.1) < ($1.0.uuidString, $1.1)
        }
        out += SyncPayload.littleEndian(UInt32(lost.count))
        for (author, kind) in lost {
            out += SyncPayload.bytes(author) + [kind]
        }
        let all = entries.sorted { Self.order($0, $1) }
        out += SyncPayload.littleEndian(UInt32(all.count))
        for kept in all {
            let entry = kept.entry
            out += SyncPayload.bytes(kept.author) + SyncPayload.bytes(entry.recordID) + [entry.rawKind]
            out += SyncPayload.bytes(entry.keyID) + SyncPayload.littleEndian(entry.version)
            out += SyncPayload.bytes(entry.device) + [entry.isDeletion ? 1 : 0]
            let body = entry.envelope ?? entry.erasure
            out += SyncPayload.littleEndian(UInt32(body.count)) + body
        }
        return out
    }

    static func order(_ a: Kept, _ b: Kept) -> Bool {
        let left = (a.author.uuidString, a.entry.recordID.uuidString, a.entry.rawKind, a.entry.device.uuidString)
        let right = (b.author.uuidString, b.entry.recordID.uuidString, b.entry.rawKind, b.entry.device.uuidString)
        if left != right { return left < right }
        if a.entry.isDeletion != b.entry.isDeletion { return !a.entry.isDeletion }
        return a.entry.version < b.entry.version
    }

    /// Parses a stored stash. The row is in a file A8 can edit, so it is read like anything else hostile: counts and
    /// lengths are checked before anything is allocated, and only what `encoded()` writes is accepted — ignorable kinds
    /// only (a critical kind is never kept aside, so a row naming one was planted), a positive version, a deletion with
    /// no key and an erasure summary, a live entry with a key-bearing envelope of at most the payload's bound.
    public static func parse(_ bytes: [UInt8]) throws -> SyncStash {
        var reader = ByteReader(bytes)
        guard try reader.read(4) == magic else { throw SyncFormatError.badMagic }
        let version = try reader.byte()
        guard version == formatVersion else { throw SyncFormatError.unsupportedFormatVersion(version) }
        var stash = SyncStash()

        let lostCount = Int(try reader.uint32())
        guard lostCount <= reader.remaining / 17 else { throw SyncFormatError.countTooLarge }
        for _ in 0..<lostCount {
            let author = try reader.uuid()
            let kind = try reader.byte()
            guard EnvelopeKind.criticality(ofRawValue: kind) == .ignorable else {
                throw SyncFormatError.unsupportedRecordKind(kind)
            }
            stash.overflow[author, default: []].insert(kind)
        }

        let entryCount = Int(try reader.uint32())
        let smallest = 16 + SyncPayload.minimumEntryLength
        guard entryCount <= maximumEntries, entryCount <= reader.remaining / smallest else {
            throw SyncFormatError.countTooLarge
        }
        for _ in 0..<entryCount {
            let author = try reader.uuid()
            let recordID = try reader.uuid()
            let kind = try reader.byte()
            guard EnvelopeKind.criticality(ofRawValue: kind) == .ignorable else {
                throw SyncFormatError.unsupportedRecordKind(kind)
            }
            let keyID = try reader.uuid()
            let recordVersion = try reader.uint64()
            guard recordVersion > 0 else { throw SyncFormatError.malformedEntry }
            let device = try reader.uuid()
            let flags = try reader.byte()
            let length = Int(try reader.uint32())
            let entry: UnknownSyncEntry
            switch flags {
            case 0:
                guard length <= SyncPayload.maximumEntryEnvelopeLength else {
                    throw SyncFormatError.entryTooLarge(length)
                }
                guard length > 0 else { throw SyncFormatError.malformedEntry }
                entry = UnknownSyncEntry(
                    recordID: recordID, rawKind: kind, keyID: keyID, version: recordVersion, device: device,
                    envelope: try reader.read(length))
            case 1:
                guard keyID == SyncPayload.zeroUUID else { throw SyncFormatError.malformedEntry }
                guard length <= SyncPayload.maximumErasureLength else { throw SyncFormatError.erasureTooLarge(length) }
                entry = UnknownSyncEntry(
                    recordID: recordID, rawKind: kind, keyID: keyID, version: recordVersion, device: device,
                    envelope: nil, erasure: try reader.read(length))
            default:
                throw SyncFormatError.unknownFlags(flags)
            }
            stash.insert(Kept(entry: entry, author: author))
            guard stash.bytes <= maximumBytes else { throw SyncFormatError.countTooLarge }
        }
        guard reader.remaining == 0 else { throw SyncFormatError.trailingBytes }
        return stash
    }
}
