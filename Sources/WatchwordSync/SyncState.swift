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
    /// Proof that this device's session saved this state (`authenticatedBytes`, review finding Z20): `erasures` become
    /// signed tombstones, `merged` signed coverage and acknowledgements, and the state store is a file an attacker can
    /// edit (A8). Set by the store wrapper that saves it (`VaultSession`, `SignatureDomain.syncState`, bound to the
    /// vault and the device), which hands back no state at all for a row that does not verify. Empty in the fakes.
    public var authenticator: [UInt8] = []

    public init(vaultID: UUID) {
        self.vaultID = vaultID
    }
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
public struct StagedObject: Sendable, Hashable {
    public var location: SyncObjectLocation
    public var object: SignedObject

    public init(location: SyncObjectLocation, object: SignedObject) {
        self.location = location
        self.object = object
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

public actor InMemorySyncStateStore: SyncStateStore {
    private var states: [UUID: SyncState] = [:]
    private var stagedObjects: [UUID: [SyncObjectLocation: SignedObject]] = [:]
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
        stagedObjects[object.location.vaultID, default: [:]][object.location] = object.object
    }

    public func staged(vaultID: UUID) -> [StagedObject] {
        (stagedObjects[vaultID] ?? [:]).map { StagedObject(location: $0.key, object: $0.value) }
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
/// publishing a deletion that never happened.
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
        var deleted: [StoredRecord] = []
        for key in change.deletions + Array(change.conditionalDeletions.keys) {
            if let row = try await base.record(key) { deleted.append(row) }
        }
        try await base.commit(change)
        for row in deleted where row.version < UInt64.max {
            try await syncState.addPendingDeletion(
                PendingDeletion(
                    stamp: RecordStamp(version: row.version + 1, device: deviceID, deleted: true), record: row))
        }
    }

    public func eraseAll() async throws {
        try await base.eraseAll()
        try await syncState.eraseAll()
    }
}
