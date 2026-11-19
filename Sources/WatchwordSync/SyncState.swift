import Foundation
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore

/// A record version's identity for sync: its Lamport version, the device that wrote it, and whether it is a deletion.
/// Ordered by version, then device ID byte by byte (docs/02-architecture.md §7.1); at an identical (version, device) a
/// deletion orders after a live version, so even a device that wrote both resolves the same way everywhere.
public struct RecordStamp: Hashable, Sendable, Comparable {
    public var version: UInt64
    public var device: UUID
    public var deleted: Bool

    public init(version: UInt64, device: UUID, deleted: Bool = false) {
        self.version = version
        self.device = device
        self.deleted = deleted
    }

    public init(_ record: StoredRecord) {
        self.init(version: record.version, device: record.deviceID)
    }

    public static func < (lhs: RecordStamp, rhs: RecordStamp) -> Bool {
        if lhs.version != rhs.version { return lhs.version < rhs.version }
        if lhs.device != rhs.device { return lhs.device.precedes(rhs.device) }
        return !lhs.deleted && rhs.deleted
    }

    public var revision: Revision {
        Revision(version: version, device: device)
    }
}

/// What this device knows about one vault's sync streams (docs/02-architecture.md §6, `sync_state`).
///
/// None of it is secret, and all of it except pending deletions (kept apart, in `SyncStateStore`) can be rebuilt from
/// the transport by a reconciling sync, which is also what repairs it if it is damaged or rolled back. It is believed
/// all the same, and what it says goes out signed, so production authenticates the row (`authenticator`).
public struct SyncState: Sendable, Hashable {
    public var vaultID: UUID
    /// The sequence number of this device's next segment.
    public var nextSequence: UInt64 = 1
    /// The last sequence number this device published, so a segment in its own stream that it did not write is
    /// noticed.
    public var lastPublishedSequence: UInt64 = 0
    /// For each stream, this device's included: the highest sequence number whose effects are in the local store,
    /// merged in order with no gap (or covered by a merged snapshot).
    public var merged: [UUID: UInt64] = [:]
    /// The latest stamp of every record the sync layer has merged or pushed, deletions included. A deletion here is
    /// the tombstone that stops an older version from resurrecting the record.
    public var known: [RecordKey: RecordStamp] = [:]
    /// The latest erasure of each record this device has merged or published: the tombstone that decides whether a
    /// version arriving later is one its author had seen (erased) or not (kept, in the trash).
    public var erasures: [RecordKey: Erasure] = [:]
    /// The latest version of each record this device has published (or found in the log written by it). The outbox is
    /// every row this device wrote that is newer than this; it is kept apart from `known`, because a remote version
    /// can be newer than a local one that still holds changes nobody else has (the merge kept the local version).
    public var published: [RecordKey: RecordStamp] = [:]
    /// Each stream's acknowledgement vector, from its newest merged segment.
    public var acknowledgements: [UUID: [UUID: UInt64]] = [:]
    /// The acknowledgement vector of this device's last published segment.
    public var publishedAcknowledgement: [UUID: UInt64] = [:]
    /// Every listed snapshot this device has merged or written, with the segments each covers.
    public var snapshots: [SyncObjectLocation: [UUID: UInt64]] = [:]
    /// For each stream, the most any merged snapshot covers. The effects of those segments are in the local store,
    /// so a stream whose next segment is missing (collected, or never visible) continues from here.
    public var snapshotCoverage: [UUID: UInt64] = [:]
    /// The stash (`SyncStash`, ADR 0009) changed in memory during a sync and may not have been saved: set before any
    /// state that counts a segment as merged is saved, cleared once the stash is. Found set when a sync starts, the
    /// stash may lack entries of segments counted as merged, so the log is replayed to rebuild it.
    public var stashUnsaved = false
    /// The generation of the last stash row saved (`SyncStash.generation`). A row of another generation, or none while
    /// this is above zero, is not trusted to hold what this state says was merged, and the log is replayed.
    public var stashGeneration: UInt64 = 0
    /// For each name the transport listed with copies beside its object (`SyncListing.copied`), the number of copies
    /// this device has examined and, where they verified, merged (docs/02-architecture.md §7.5, "Conflict copies").
    /// A name is looked at again only when the transport's count differs: the copies stay on the provider, and the
    /// decision about them is remembered here. Pruned to the names still listed with copies.
    public var examinedCopies: [SyncObjectLocation: Int] = [:]
    /// Names whose copies could not all be read when last examined, with the count the transport gave then (review
    /// finding R17). Such a name is looked at again (R11: nothing about it is remembered as examined, and its author
    /// does not collect it), but after every name not here, whatever count is listed now (R19: a count A1 alternates
    /// does not bring it forward), so copies that never become readable cannot spend the bound before a copy that
    /// can. Only the order changes: nothing is skipped, forgotten or deleted. Pruned to the names still listed with
    /// copies.
    public var unreadCopies: [SyncObjectLocation: Int] = [:]
    /// For each name in `unreadCopies`, when it was last examined: a number above every other one held here at the
    /// time (review finding R19). The names behind the rest are taken least recently examined first, so beyond the
    /// per-sync bound they take turns, and each is examined again within a number of syncs bounded by how many there
    /// are, rather than the same ones every time in name order. A name missing here (a row from before this was
    /// kept) counts as examined longest ago. Pruned with `unreadCopies`.
    public var unreadCopiesExamined: [SyncObjectLocation: UInt64] = [:]
    /// This device owes a snapshot of everything it holds, beyond the ones `SyncEngine` owes for a revoked device's
    /// work: its own stream forked (several verifying copies of one of its names, which no other device can be
    /// assumed to have seen both of). Cleared when the snapshot is written; until then it collects nothing.
    public var handOnOwed = false
    /// The highest sequence number of this device's own stream that it need not find listed: its segments up to here
    /// were collected, or a listed snapshot stood for them. Every later one it published must be listed (a device
    /// keeps its newest segment and sees its own objects at once), so one that is missing means the store lost it:
    /// the engine's sign of a reset (docs/02-architecture.md §7.10). `nil` in a state from before this was kept, and
    /// set from the first listing.
    public var ownUnlistedThrough: UInt64?
    /// The snapshot in which this device last handed on everything it held, on the person's decision to upload again
    /// after a reset, and what it had merged of each stream then. While that snapshot is listed it stands for all of
    /// that, whatever coverage it could claim.
    public var handedOn: HandedOn?
    /// The highest number this device has used in the name of a snapshot of its own. A snapshot that hands
    /// everything on after a reset is named above it: the store, emptied, would accept an old name again, and a
    /// device that had merged the earlier snapshot under that name would never read the new one.
    public var highestOwnSnapshot: UInt64 = 0
    /// The store looked reset when this device last listed it before merging: an object of its own that it had not
    /// deleted was missing, and it had merged something nothing listed stood for (§7.10). Remembered, because what
    /// another device uploads afterwards can stand for this device's own stream and so hide the first sign, while
    /// this device still holds more of a third stream than the store. Cleared once everything it has merged is
    /// listed or stood for again, or it has handed everything on. While set, and until the person answers, the
    /// engine writes no snapshot, collects nothing and replays nothing.
    public var storeResetSuspected = false
    /// A merge pass refused versions as beyond the version-jump ceiling, to be tried again once it had merged
    /// everything else (`SyncEngine.retryOutOfReach`, Z25), and had not done so when this state was saved: set when
    /// the first is refused, cleared once the retry has run. The list of them lives in memory, and nothing merges
    /// from the quarantine, so a sync that finds this set (a lock or a crash part-way through the pass) replays the
    /// log, which offers them again (review finding Z33).
    public var retryUnfinished = false
    /// The devices whose versions were to be kept aside and were not, the quarantine being full (Z27): past the
    /// vault's cap or that device's share. While a trusted one is here this device writes no ordinary snapshot, as
    /// while one is kept (Z26), because its snapshot would cover the segment without carrying the version; and once
    /// the quarantine has room for every one of them again, the log is replayed to offer those versions again
    /// (review finding Z38).
    public var quarantineDropped: Set<UUID> = []
    /// How many entries the quarantine held when its store last refused a version because entries crafted to share
    /// its lookup digest had crowded it (Z141), with `quarantineDropped` naming its writer; `nil` if that has not
    /// happened since the last replay. The caps then had room, so a replay at every sync would only drop it again:
    /// the log is offered again only once the quarantine holds fewer entries than this, which the person discarding
    /// the entries (or anything else leaving) brings about (review finding Z147).
    public var quarantineCrowded: UInt64?
    /// The highest number of this device's own stream it has collected: every number from its stream's first up to
    /// this one was deleted, lowest first. A listed name at or below it is no segment of its stream any more (a stale
    /// listing, or a name anyone can create), so collection's contiguous run starts above it (review finding Z149).
    public var collectedThrough: UInt64 = 0
    /// This state was started over by a move of the installation to a new device ID (a store restored onto other
    /// hardware, `VaultSession.completeDeviceMigration`) after the installation had published or merged a log: the
    /// state holds no record of what it merged, and the device's local store holds all of it (review of the second
    /// merge, V49). It tells a store that was emptied from a new one where the rest of the state no longer can
    /// (§7.10), for as long as the installation lives (`VaultSession.hasSyncedBefore`). Never cleared; kept by a
    /// replay. What the engine asks while a reset is suspected is `startedOverByMove`, which ends.
    public var syncedBefore = false
    /// This state was started over by a device move after the installation had synced (`syncedBefore` set with it),
    /// and has not handed everything on since: its `merged` says nothing of what the device's local store holds, so a
    /// reset suspected in it is not ended by finding nothing lacking, only by its own hand-on, which clears this
    /// (`SyncEngine`'s `writeSnapshotIfElected`). One-shot: once cleared, the state's `merged` stands for what the
    /// device holds as any state's does, and a later suspicion ends as anywhere else, when the store stands for
    /// everything again, whoever uploaded it (review of V49 to V51, V52). Kept by a replay.
    public var startedOverByMove = false
    /// Proof that this device's session saved this state (`authenticatedBytes`, review finding Z20): `erasures` become
    /// signed tombstones, `merged` signed coverage and acknowledgements, and the state store is a file an attacker can
    /// edit (A8). Set by the store wrapper that saves it (`VaultSession`, `SignatureDomain.syncState`, bound to the
    /// vault and the device), which hands back no state at all for a row that does not verify. Empty in the fakes.
    public var authenticator: [UInt8] = []

    public init(vaultID: UUID) {
        self.vaultID = vaultID
    }
}

/// A snapshot by this device that carries everything it held when it was written (`SyncState.handedOn`).
public struct HandedOn: Sendable, Hashable {
    public var snapshot: SyncObjectLocation
    /// What this device had merged of each stream when it wrote the snapshot: what the snapshot's entries contain.
    public var holding: [UUID: UInt64]

    public init(snapshot: SyncObjectLocation, holding: [UUID: UInt64]) {
        self.snapshot = snapshot
        self.holding = holding
    }
}

/// Why a vault's log was not uploaded again after a reset, although the person asked
/// (docs/02-architecture.md §7.10).
public enum ReuploadRefusal: Error, Sendable, Hashable {
    /// A shared vault: its write cuts are chains of digests of each device's own segments, which one member's device
    /// can neither re-create nor replace with a snapshot. It stays on this device as it is.
    case sharedVault
    /// The vault does not fit in one snapshot.
    case tooLarge
}

/// A deletion of a record, and what its author had seen of it (`RecordMerger.erasureSummary`).
public struct Erasure: Sendable, Hashable {
    public var stamp: RecordStamp
    public var summary: [UInt8]

    public init(stamp: RecordStamp, summary: [UInt8]) {
        self.stamp = stamp
        self.summary = summary
    }
}

/// A deletion made on this device and not yet published, with the row it deleted, kept locally until then so the
/// erasure can say what its author had seen.
public struct PendingDeletion: Sendable, Hashable {
    public var stamp: RecordStamp
    public var record: StoredRecord
    /// Proof that this device's session made the deletion, set by the store wrapper that records it. A pending
    /// deletion becomes a signed tombstone that erases the record on every device, and the state store is a file an
    /// attacker can edit (A8), so production checks this before publishing or merging with it: `VaultSession` signs
    /// the deletion with the account key (`SignatureDomain.pendingDeletion`) and ignores any row whose signature does
    /// not verify. Empty in the fakes, which keep their state in memory.
    public var authenticator: [UInt8]

    public init(stamp: RecordStamp, record: StoredRecord, authenticator: [UInt8] = []) {
        self.stamp = stamp
        self.record = record
        self.authenticator = authenticator
    }
}

/// An object downloaded and signature-checked, waiting for keys to be merged (§7.4: downloading needs no keys).
///
/// Where the transport held several copies under the name (§7.5, "Conflict copies"), every copy that verified is
/// staged together: `object` and `alternates`, in no order that means anything, with the transport's count in
/// `copies` so that the merge can remember the name as examined.
public struct StagedObject: Sendable, Hashable {
    public var location: SyncObjectLocation
    public var object: SignedObject
    /// The other copies under the name that verified. Empty for an object with one copy, which is nearly all.
    public var alternates: [SignedObject]
    /// The number of copies the transport listed under the name when this was staged; 0 if it listed only the object.
    public var copies: Int

    public init(location: SyncObjectLocation, object: SignedObject, alternates: [SignedObject] = [], copies: Int = 0) {
        self.location = location
        self.object = object
        self.alternates = alternates
        self.copies = copies
    }

    /// Every staged copy.
    public var all: [SignedObject] { [object] + alternates }

    static let magic: [UInt8] = Array("WWSC".utf8)
    static let formatVersion: UInt8 = 1
    /// More than any engine stages (`SyncConfiguration.maximumCopiesPerObject`); a row claiming more is not one.
    static let maximumStoredCopies = 64

    /// What a state store keeps for this object. One copy with nothing to remember is the `SignedObject` as it has
    /// always been stored; otherwise `"WWSC" ‖ version u8 = 1 ‖ copies u32 ‖ count u8 ‖ (length u32 ‖ object)…`.
    public var storageBytes: [UInt8] {
        guard !alternates.isEmpty || copies != 0 else { return object.serialized() }
        var out = Self.magic + [Self.formatVersion]
        out += SyncPayload.littleEndian(UInt32(clamping: copies))
        out.append(UInt8(clamping: all.count))
        for copy in all.prefix(Int(UInt8.max)) {
            let bytes = copy.serialized()
            out += SyncPayload.littleEndian(UInt32(clamping: bytes.count)) + bytes
        }
        return out
    }

    /// Reads `storageBytes`. The row is in a local file (A8): bounded, exact, and `nil` for anything else. What it
    /// yields is still verified copy by copy before it is merged.
    public init?(location: SyncObjectLocation, storageBytes bytes: [UInt8]) {
        guard bytes.count >= 4, Array(bytes[0..<4]) == Self.magic else {
            guard let object = try? SignedObject.parse(bytes) else { return nil }
            self.init(location: location, object: object)
            return
        }
        var reader = ByteReader(bytes)
        guard (try? reader.read(4)) != nil, (try? reader.byte()) == Self.formatVersion,
            let copies = try? reader.uint32(), let count = try? reader.byte(),
            count >= 1, Int(count) <= Self.maximumStoredCopies
        else { return nil }
        var objects: [SignedObject] = []
        for _ in 0..<count {
            guard let length = try? reader.uint32(), let raw = try? reader.read(Int(length)),
                let object = try? SignedObject.parse(raw)
            else { return nil }
            objects.append(object)
        }
        guard reader.remaining == 0 else { return nil }
        self.init(
            location: location, object: objects[0], alternates: Array(objects.dropFirst()), copies: Int(copies))
    }
}

/// Persistence for `SyncState`, staged downloads and pending deletions (docs/02-architecture.md §6).
///
/// Implementations: `InMemorySyncStateStore` here; the App Group database's `sync_state` and `changelog` tables
/// belong to milestone 3's Mac half (the SQLite store does not build on Linux, so it cannot be verified here). The
/// contents are untrusted on read like the rest of the file: staged objects are re-verified before merging, and the
/// state can be rebuilt with a reconciling sync.
public protocol SyncStateStore: Sendable {
    /// The state this device saved for the vault, or `nil`: none yet, or (in production) a row this device's session
    /// did not sign, which is no state. The engine then starts from nothing and replays the log.
    func loadState(vaultID: UUID) async throws -> SyncState?
    func saveState(_ state: SyncState) async throws

    func stage(_ object: StagedObject) async throws
    func staged(vaultID: UUID) async throws -> [StagedObject]
    func unstage(_ locations: [SyncObjectLocation]) async throws

    /// A pending deletion made ready to be recorded: production signs it here (`PendingDeletion.authenticator`),
    /// which needs the keys, so that recording it once the deletion has committed needs none. A store with nothing
    /// to sign with hands it back as it is. Throws `SyncKeyringError.locked` while locked.
    func prepared(_ deletion: PendingDeletion) async throws -> PendingDeletion
    /// Deletions made locally and not yet published. Kept apart from `SyncState` so that a sync in progress, which
    /// saves the state it loaded, can never drop a deletion recorded meanwhile.
    func addPendingDeletion(_ deletion: PendingDeletion) async throws
    func pendingDeletions(vaultID: UUID) async throws -> [RecordKey: PendingDeletion]
    /// Removes each deletion only if it is still the one given (by stamp), so a newer one recorded meanwhile survives.
    func removePendingDeletions(_ deletions: [RecordKey: RecordStamp], vaultID: UUID) async throws

    /// Record versions kept aside rather than merged: refused as implausible (U5), unsealable once merged (Y37),
    /// held aside in a shared vault, or named like another vault's record (Z22). Never discarded by sync; only the
    /// person, explicitly, may discard them (PRD F7.7). Each entry is kept once: returns whether it was added, by a
    /// lookup that does not read what the quarantine already holds (review finding Z27). The engine holds the
    /// quarantine to its caps before it calls this (`SyncConfiguration.maximumQuarantinedEntries`); the session's own
    /// use, for a local version it takes out, is not capped.
    @discardableResult
    func quarantine(_ entry: SyncEntry, vaultID: UUID) async throws -> Bool
    func quarantined(vaultID: UUID) async throws -> [SyncEntry]
    func discardQuarantined(_ entries: [SyncEntry], vaultID: UUID) async throws
    /// Whether the vault's quarantine holds exactly this entry, by the same lookup.
    func holdsQuarantined(_ entry: SyncEntry, vaultID: UUID) async throws -> Bool
    /// How many entries and bytes the vault's quarantine holds for each writing device, without reading an envelope.
    func quarantineUsage(vaultID: UUID) async throws -> QuarantineUsage

    /// The stash (`SyncStash.encoded()`), written once per sync, apart from the state saved with every segment.
    /// Rebuildable from the log; the engine parses it as hostile.
    func stash(vaultID: UUID) async throws -> [UInt8]?
    func saveStash(_ bytes: [UInt8], vaultID: UUID) async throws

    func eraseAll() async throws
}

extension SyncStateStore {
    /// A store that signs nothing records a pending deletion as it was made.
    public func prepared(_ deletion: PendingDeletion) async throws -> PendingDeletion {
        deletion
    }
}

public actor InMemorySyncStateStore: SyncStateStore {
    private var states: [UUID: SyncState] = [:]
    private var stagedObjects: [UUID: [SyncObjectLocation: StagedObject]] = [:]
    private var deletions: [UUID: [RecordKey: PendingDeletion]] = [:]
    private var quarantinedEntries: [UUID: [SyncEntry]] = [:]
    private var quarantinedIndex: [UUID: Set<SyncEntry>] = [:]
    private var stashes: [UUID: [UInt8]] = [:]
    /// How many times each vault's stash was written: a test seam for what a flood costs.
    public private(set) var stashWrites: [UUID: Int] = [:]

    public init() {}

    public func loadState(vaultID: UUID) -> SyncState? {
        states[vaultID]
    }

    public func saveState(_ state: SyncState) {
        states[state.vaultID] = state
    }

    public func stage(_ object: StagedObject) {
        stagedObjects[object.location.vaultID, default: [:]][object.location] = object
    }

    public func staged(vaultID: UUID) -> [StagedObject] {
        Array((stagedObjects[vaultID] ?? [:]).values)
    }

    public func unstage(_ locations: [SyncObjectLocation]) {
        for location in locations {
            stagedObjects[location.vaultID]?[location] = nil
        }
    }

    public func addPendingDeletion(_ deletion: PendingDeletion) {
        let key = deletion.record.key
        let vaultID = deletion.record.vaultID
        if let existing = deletions[vaultID]?[key], existing.stamp >= deletion.stamp { return }
        deletions[vaultID, default: [:]][key] = deletion
    }

    public func pendingDeletions(vaultID: UUID) -> [RecordKey: PendingDeletion] {
        deletions[vaultID] ?? [:]
    }

    public func removePendingDeletions(_ published: [RecordKey: RecordStamp], vaultID: UUID) {
        for (key, stamp) in published where deletions[vaultID]?[key]?.stamp == stamp {
            deletions[vaultID]?[key] = nil
        }
    }

    @discardableResult
    public func quarantine(_ entry: SyncEntry, vaultID: UUID) -> Bool {
        guard quarantinedIndex[vaultID, default: []].insert(entry).inserted else { return false }
        quarantinedEntries[vaultID, default: []].append(entry)
        return true
    }

    public func quarantined(vaultID: UUID) -> [SyncEntry] {
        quarantinedEntries[vaultID] ?? []
    }

    public func discardQuarantined(_ entries: [SyncEntry], vaultID: UUID) {
        let discarded = Set(entries)
        quarantinedEntries[vaultID]?.removeAll { discarded.contains($0) }
        quarantinedIndex[vaultID]?.subtract(discarded)
    }

    public func holdsQuarantined(_ entry: SyncEntry, vaultID: UUID) -> Bool {
        quarantinedIndex[vaultID]?.contains(entry) ?? false
    }

    public func quarantineUsage(vaultID: UUID) -> QuarantineUsage {
        var usage = QuarantineUsage()
        for entry in quarantinedEntries[vaultID] ?? [] { usage.add(entry) }
        return usage
    }

    public func stash(vaultID: UUID) -> [UInt8]? {
        stashes[vaultID]
    }

    public func saveStash(_ bytes: [UInt8], vaultID: UUID) {
        stashes[vaultID] = bytes
        stashWrites[vaultID, default: 0] += 1
    }

    public func eraseAll() {
        states = [:]
        stagedObjects = [:]
        deletions = [:]
        quarantinedEntries = [:]
        quarantinedIndex = [:]
        stashes = [:]
    }

    // MARK: - Test seams: what an attacker with the local file (A8) can do.

    /// Replaces the state without any checks.
    public func tamper(_ state: SyncState) {
        states[state.vaultID] = state
    }

    /// Replaces the stored stash without any checks.
    public func tamperStash(_ bytes: [UInt8], vaultID: UUID) {
        stashes[vaultID] = bytes
    }
}

/// The record store `VaultSession` writes through when sync is on: deletions it commits become explicit, pending
/// tombstones for the sync layer to publish (docs/02-architecture.md §7.1).
///
/// Deletions are recorded only here, never inferred: a record that has merely gone missing from the database — an
/// attacker with the file (A8) deleted the row, or a backup was restored — is not a deletion to propagate to every
/// other device, but damage that a reconciling sync repairs from the log. The tombstone is recorded after the deletion
/// commits, so a crash in between loses the tombstone (the record comes back from another device) rather than
/// publishing a deletion that never happened. It is *made* before the deletion commits, though
/// (`SyncStateStore.prepared`): making it needs the session's keys, and a lock that landed after the commit used to
/// leave rows deleted here with no tombstone, so that a vault deleted as the app went to the background was deleted
/// everywhere while its items stayed on every other device (review finding Z28). A lock while the tombstones are
/// being made now fails the deletion before anything changes; one after the commit changes nothing, because
/// recording a tombstone already made needs no key.
public struct DeletionRecordingStore: RecordStore {
    public let base: any RecordStore
    public let syncState: any SyncStateStore
    public let deviceID: UUID

    public init(base: any RecordStore, syncState: any SyncStateStore, deviceID: UUID) {
        self.base = base
        self.syncState = syncState
        self.deviceID = deviceID
    }

    public func loadAccount() async throws -> AccountRecord? {
        try await base.loadAccount()
    }

    public func record(_ key: RecordKey) async throws -> StoredRecord? {
        try await base.record(key)
    }

    public func records(in vaultID: UUID, kind: EnvelopeKind) async throws -> [StoredRecord] {
        try await base.records(in: vaultID, kind: kind)
    }

    public func commit(_ change: StoreChange) async throws {
        var tombstones: [PendingDeletion] = []
        for key in change.deletions + Array(change.conditionalDeletions.keys) {
            guard let row = try await base.record(key), row.version < UInt64.max else { continue }
            tombstones.append(
                try await syncState.prepared(
                    PendingDeletion(
                        stamp: RecordStamp(version: row.version + 1, device: deviceID, deleted: true), record: row)))
        }
        try await base.commit(change)
        for tombstone in tombstones { try await syncState.addPendingDeletion(tombstone) }
    }

    public func eraseAll() async throws {
        try await base.eraseAll()
        try await syncState.eraseAll()
    }
}
