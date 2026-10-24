import Foundation
import WatchwordEnvelope
import WatchwordStore

public struct SyncConfiguration: Sendable {
    /// The record kinds sync carries, and the schema version each record's envelope must claim (`ItemCodec.schemaVersion`
    /// for items). Entries of any other kind are refused when a payload is parsed.
    public var schemaVersions: [EnvelopeKind: UInt64]
    public var maximumEntriesPerSegment = 256
    /// Segments are split well below the envelope cap, so one large edit cannot make a segment unwritable.
    public var maximumSegmentPayloadLength = 8 << 20
    /// Remote versions above this are refused outright: far from `UInt64.max`, so no item can be frozen by a version
    /// with no room above it (review finding U5).
    public var maximumVersion: UInt64 = 1 << 62
    /// Remote versions more than this far above the highest version this device has seen in the vault are quarantined
    /// rather than merged (review finding U5: implausible jumps).
    public var maximumVersionJump: UInt64 = 1 << 20
    /// Segments not yet covered by a snapshot before the elected device writes one. Never fewer than twice the number
    /// of streams, so the acknowledgement segments a snapshot causes can never trigger the next one.
    public var snapshotThreshold = 64
    /// Sequence numbers and acknowledgement values above this are refused (a stream would need trillions of segments
    /// to reach it), so no arithmetic on them can overflow.
    public var maximumSequence: UInt64 = 1 << 48

    public init(schemaVersions: [EnvelopeKind: UInt64]) {
        self.schemaVersions = schemaVersions
    }

    /// The most a single object may be: a full envelope, a signature and the container.
    public var maximumObjectLength: Int {
        Envelope.maximumLength + SignedObject.maximumSignatureLength + 7
    }
}

public enum SyncError: Error, Equatable, Sendable {
    /// `sync` was called while another sync of the same engine was in flight.
    case syncInProgress
}

/// Why an object or a record from the transport was not merged.
public enum SyncRejectionReason: Sendable, Equatable {
    case format(SyncFormatError)
    case envelope(EnvelopeError)
    case keyring(SyncKeyringError)
    case transport(SyncTransportError)
    /// The payload names another vault, author, number or kind than the object's location.
    case locationMismatch
    /// An acknowledgement or coverage value beyond any sequence number a stream can reach.
    case vectorOutOfRange
    /// A segment carried a record version written by a device other than its author.
    case entryFromAnotherDevice(UUID)
    /// A record's envelope claims another record, vault, kind, key or version than the entry carrying it: a record
    /// swap or relabel inside a validly signed segment.
    case recordContextMismatch(UUID)
    /// The record ID belongs to a record of another vault on this device.
    case recordInAnotherVault(UUID)
    /// The merger could not merge the remote version (it does not open, or opens to another item).
    case mergeFailed(UUID)
    /// The merger returned a result the engine must not store.
    case invalidMergeResult(UUID)
    case other(String)
}

public struct SyncRejection: Sendable, Equatable {
    public var name: String
    public var reason: SyncRejectionReason
}

/// What one sync did. Nothing here is fatal: a rejected object is reported and skipped, never repaired and never
/// allowed to stop the other streams (fail closed per object).
public struct SyncReport: Sendable, Equatable {
    /// Objects downloaded.
    public var fetched = 0
    /// Local records inserted, replaced, merged or deleted.
    public var applied = 0
    /// Record versions and deletions published.
    public var pushedEntries = 0
    public var segmentsWritten = 0
    public var snapshotsWritten = 0
    /// This device's superseded segments and snapshots deleted.
    public var collected = 0
    public var rejected: [SyncRejection] = []
    /// Remote versions refused as implausible (U5). Kept in `SyncStateStore.quarantined` until the person discards
    /// them (PRD F7.7).
    public var quarantined: [RecordKey] = []
    /// Streams stopped at a missing or rejected segment: the next sequence number each is waiting for. Later segments
    /// are never applied over a gap.
    public var waiting: [UUID: UInt64] = [:]
    /// Snapshots older than what this device already holds; ignored.
    public var staleSnapshots = 0
    /// Names in the vault's prefix that are not sync objects.
    public var ignoredNames = 0
    /// The vault was locked: objects were downloaded and checked, but merging and publishing wait for unlock (§7.4).
    public var deferredUntilUnlock = false
    /// The transport could not be reached. Objects downloaded earlier were still merged; nothing was published.
    public var transportUnavailable = false
    /// This device's next sequence number was already taken: a crash after publishing, or another installation using
    /// this device ID (a restored backup). The object is merged on the next sync and nothing is overwritten.
    public var ownStreamConflict: UInt64?

    public init() {}
}

/// The sync engine for one vault on one device (docs/02-architecture.md §7, PRD F7.2–F7.5).
///
/// Each device appends signed, sealed log segments to its own stream and never writes anyone else's object, so the
/// transport never sees a write conflict. A sync:
///
/// 1. **Downloads** (`pull`): lists the vault, fetches every snapshot not yet merged and every segment past what has
///    been merged, checks each signature against its author, and stages it. Needs no keys, so it runs while locked
///    (§7.4).
/// 2. **Merges** staged objects, which needs the vault key: per stream strictly in sequence order, stopping at a gap
///    rather than skipping it unless a merged snapshot covers it. Each record version goes through the
///    `RecordMerger` (field-level and conflict-keeping, F7.4, F7.6), and each erasure through its `resolveErasure`.
///    A value is only ever replaced by one written knowing about it, so an older version can never displace a newer
///    one: the sync layer's monotonic check (§5). Nothing received is discarded (F7.7).
/// 3. **Publishes** this device's new versions and deletions as the next segment of its stream.
/// 4. **Maintains**: the elected device writes a snapshot once enough segments are uncovered, and each device deletes
///    its own segments once every other device has acknowledged them and a snapshot covers them.
///
/// `sync(reconcile: true)` forgets everything but the pending deletions and replays the whole log. Because merging is
/// idempotent that changes nothing on a healthy device, and on a damaged one it restores rows that were rolled back or
/// deleted in the local file (A8) from the signed log, which lives outside that file.
public actor SyncEngine {
    public let vaultID: UUID
    public let deviceID: UUID
    let store: any RecordStore
    let syncState: any SyncStateStore
    let transport: any SyncTransport
    let keyring: any SyncKeyring
    let merger: any RecordMerger
    let configuration: SyncConfiguration
    private var running = false

    /// `store` is the underlying record store; the session writes through a `DeletionRecordingStore` around the same
    /// store, so the engine's own deletions (applying remote tombstones) are not re-published as local ones.
    public init(
        vaultID: UUID,
        deviceID: UUID,
        store: any RecordStore,
        syncState: any SyncStateStore,
        transport: any SyncTransport,
        keyring: any SyncKeyring,
        merger: any RecordMerger,
        configuration: SyncConfiguration
    ) {
        self.vaultID = vaultID
        self.deviceID = deviceID
        self.store = store
        self.syncState = syncState
        self.transport = transport
        self.keyring = keyring
        self.merger = merger
        self.configuration = configuration
    }

    // MARK: - Entry points

    /// Downloads, merges, publishes and maintains. While locked, only the download happens and the report says so.
    public func sync(reconcile: Bool = false) async throws -> SyncReport {
        guard !running else { throw SyncError.syncInProgress }
        running = true
        defer { running = false }
        var report = SyncReport()
        var state = try await syncState.loadState(vaultID: vaultID) ?? SyncState(vaultID: vaultID)
        if reconcile {
            // Everything but what this device has done itself is rebuilt from the log. Erasures are kept too: they
            // are facts the log also holds, and keeping them stops a replay from putting an erased record back.
            let kept = state
            state = SyncState(vaultID: vaultID)
            state.nextSequence = kept.nextSequence
            state.publishedAcknowledgement = kept.publishedAcknowledgement
            state.lastPublishedSequence = kept.lastPublishedSequence
            state.erasures = kept.erasures
        }
        state.nextSequence = max(state.nextSequence, 1)
        var listing = Listing()
        do {
            listing = try await pull(state: state, report: &report)
            // Never reuse a number this stream has used: state may be older than the transport (a restored backup, a
            // rolled-back file), and a collected number would otherwise be free to create again, unseen by anyone.
            if let highest = listing.segments[deviceID]?.max() {
                state.nextSequence = max(state.nextSequence, highest + 1)
            }
        } catch SyncTransportError.unavailable {
            // Offline (PRD N3): still merge what was downloaded earlier, perhaps while locked.
            report.transportUnavailable = true
        }
        do {
            try await mergeStaged(state: &state, report: &report)
            state.nextSequence = max(state.nextSequence, (state.merged[deviceID] ?? 0) + 1)
            try await syncState.saveState(state)
            if !report.transportUnavailable {
                try await push(state: &state, report: &report)
                if report.ownStreamConflict == nil {
                    try await maintain(state: &state, listing: listing, report: &report)
                }
            }
        } catch SyncKeyringError.locked {
            report.deferredUntilUnlock = true
        } catch SyncTransportError.unavailable {
            report.transportUnavailable = true
        }
        try await syncState.saveState(state)
        return report
    }

    /// Downloads and signature-checks new objects only. Needs no keys (§7.4).
    public func download() async throws -> SyncReport {
        guard !running else { throw SyncError.syncInProgress }
        running = true
        defer { running = false }
        var report = SyncReport()
        let state = try await syncState.loadState(vaultID: vaultID) ?? SyncState(vaultID: vaultID)
        _ = try await pull(state: state, report: &report)
        return report
    }

    // MARK: - Download

    struct Listing {
        var segments: [UUID: [UInt64]] = [:]
        var snapshots: [SyncObjectLocation] = []
    }

    private func pull(state: SyncState, report: inout SyncReport) async throws -> Listing {
        var listing = Listing()
        // A listing may name an object twice (providers do); each is fetched once.
        for name in Set(try await transport.list(prefix: SyncObjectLocation.vaultPrefix(vaultID))) {
            guard let location = SyncObjectLocation(name: name), location.vaultID == vaultID,
                location.number
                    <= (location.kind == .segment
                        ? configuration.maximumSequence : configuration.maximumVersion)
            else {
                report.ignoredNames += 1
                continue
            }
            switch location.kind {
            case .segment: listing.segments[location.author, default: []].append(location.number)
            case .snapshot: listing.snapshots.append(location)
            }
        }

        // Every snapshot not yet merged, not only the newest: which one is newest is not which one covers most, and a
        // device's own garbage collection may rely on any of them.
        var wanted = listing.snapshots.filter { state.snapshots[$0] == nil }
        for (author, sequences) in listing.segments {
            let merged = state.merged[author] ?? 0
            wanted += sequences.filter { $0 > merged }.map {
                SyncObjectLocation.segment(vaultID: vaultID, author: author, sequence: $0)
            }
        }

        let alreadyStaged = Set(try await syncState.staged(vaultID: vaultID).map(\.location))
        for location in wanted where !alreadyStaged.contains(location) {
            do {
                guard
                    let bytes = try await transport.fetch(
                        location.name, maximumLength: configuration.maximumObjectLength)
                else { continue }
                report.fetched += 1
                let object = try SignedObject.parse(bytes)
                try await keyring.verify(object.signature, over: object.envelope, at: location)
                try await syncState.stage(StagedObject(location: location, object: object))
            } catch SyncTransportError.unavailable {
                throw SyncTransportError.unavailable
            } catch {
                report.rejected.append(SyncRejection(name: location.name, reason: Self.reason(error)))
                if location.kind == .segment {
                    report.waiting[location.author] = min(report.waiting[location.author] ?? .max, location.number)
                }
            }
        }
        return listing
    }

    // MARK: - Merge

    private func mergeStaged(state: inout SyncState, report: inout SyncReport) async throws {
        let staged = try await syncState.staged(vaultID: vaultID)
        guard !staged.isEmpty else { return }
        var highWater = try await vaultHighWater(state)
        // A deletion made here but not yet published is as much an erasure as a published one: without it, a
        // snapshot or segment written before the deletion would put the record back on this device only.
        let pending = try await syncState.pendingDeletions(vaultID: vaultID)
        let segments = Dictionary(grouping: staged.filter { $0.location.kind == .segment }, by: \.location.author)

        // Snapshots first: they bootstrap a new device and fill gaps left by garbage collection.
        let snapshots = staged.filter { $0.location.kind == .snapshot }.sorted {
            Self.snapshotOrder($0.location, $1.location)
        }
        for snapshot in snapshots {
            do {
                let payload = try await open(snapshot)
                try validate(payload, at: snapshot.location)
                if Self.covers(state.merged, payload.vector) {
                    report.staleSnapshots += 1  // Nothing in it this device has not merged already.
                } else {
                    for entry in payload.entries {
                        try await apply(
                            entry, pending: pending[entry.key], state: &state, highWater: &highWater, report: &report)
                    }
                }
                state.snapshots[snapshot.location] = payload.vector
                state.snapshotCoverage.merge(payload.vector, uniquingKeysWith: max)
            } catch let error where Self.isFatal(error) {
                throw error
            } catch {
                report.rejected.append(SyncRejection(name: snapshot.location.name, reason: Self.reason(error)))
            }
        }
        try await syncState.unstage(snapshots.map(\.location))

        // A stream whose next segment is not here continues from what the snapshots cover: their effects are in
        // the store. One whose next segment is here is merged from its own segments.
        for (author, covered) in state.snapshotCoverage where covered > (state.merged[author] ?? 0) {
            let next = (state.merged[author] ?? 0) + 1
            if !(segments[author] ?? []).contains(where: { $0.location.number == next }) {
                state.merged[author] = covered
            }
        }

        for author in segments.keys.sorted(by: { $0.precedes($1) }) {
            var next = (state.merged[author] ?? 0) + 1
            for object in segments[author]!.sorted(by: { $0.location.number < $1.location.number }) {
                let sequence = object.location.number
                if sequence > next, next <= (state.snapshotCoverage[author] ?? 0) {
                    // A gap the snapshots cover (the missing segment was collected after they were merged).
                    state.merged[author] = state.snapshotCoverage[author]!
                    next = state.merged[author]! + 1
                }
                if sequence < next {
                    try await syncState.unstage([object.location])
                    continue
                }
                if sequence > next {
                    report.waiting[author] = next
                    break
                }
                let acknowledgement: [UUID: UInt64]
                do {
                    let payload = try await open(object)
                    try validate(payload, at: object.location)
                    for entry in payload.entries {
                        try await apply(
                            entry, pending: pending[entry.key], state: &state, highWater: &highWater, report: &report)
                    }
                    acknowledgement = payload.vector
                } catch let error where Self.isFatal(error) {
                    throw error
                } catch {
                    report.rejected.append(SyncRejection(name: object.location.name, reason: Self.reason(error)))
                    // Unstaged, so the next sync fetches it again: a partially visible file may since have completed.
                    try await syncState.unstage([object.location])
                    if sequence <= (state.snapshotCoverage[author] ?? 0) {
                        // Its effects are in a merged snapshot already: continue past it rather than stall.
                        state.merged[author] = state.snapshotCoverage[author]!
                        next = state.merged[author]! + 1
                        continue
                    }
                    report.waiting[author] = next
                    break
                }
                state.merged[author] = sequence
                if author == deviceID {
                    // Not one this device remembers publishing: a crash after publishing, or another installation
                    // using this device ID (a restored backup). Merged like any other, and reported.
                    if sequence > state.lastPublishedSequence { report.ownStreamConflict = sequence }
                    state.nextSequence = max(state.nextSequence, sequence + 1)
                } else {
                    state.acknowledgements[author] = acknowledgement
                }
                next = sequence + 1
                try await syncState.saveState(state)
                try await syncState.unstage([object.location])
            }
        }
    }

    /// Checks and opens a staged object: kind and context before decryption, the signature again (staged objects sit
    /// in a local file an attacker may edit), then the AEAD, then the payload, whose own location must match.
    private func open(_ staged: StagedObject) async throws -> SyncPayload {
        let location = staged.location
        let header = try EnvelopeHeader.parse(staged.object.envelope, expecting: location.envelopeKind).header
        let context = location.envelopeContext(keyID: header.keyID)
        _ = try Envelope.parse(staged.object.envelope, expecting: context)
        try await keyring.verify(staged.object.signature, over: staged.object.envelope, at: location)
        let plaintext = try await keyring.open(staged.object.envelope, context: context)
        let payload = try SyncPayload.parse(plaintext, allowedKinds: Set(configuration.schemaVersions.keys))
        guard payload.location == location else { throw Rejection(reason: .locationMismatch) }
        return payload
    }

    /// Structural checks on every entry before any is applied, so a malformed segment changes nothing.
    private func validate(_ payload: SyncPayload, at location: SyncObjectLocation) throws {
        guard payload.vector.values.allSatisfy({ $0 <= configuration.maximumSequence }) else {
            throw Rejection(reason: .vectorOutOfRange)
        }
        for entry in payload.entries {
            if location.kind == .segment, entry.device != location.author {
                throw Rejection(reason: .entryFromAnotherDevice(entry.recordID))
            }
            guard entry.version > 0 else { throw SyncFormatError.malformedEntry }
            guard let envelope = entry.envelope else { continue }
            let context = EnvelopeContext(
                recordID: entry.recordID, vaultID: vaultID, schemaVersion: configuration.schemaVersions[entry.kind]!,
                kind: entry.kind, keyID: entry.keyID, recordVersion: entry.version)
            do {
                _ = try Envelope.parse(
                    envelope, expecting: context, maximumLength: SyncPayload.maximumEntryEnvelopeLength)
            } catch {
                throw Rejection(reason: .recordContextMismatch(entry.recordID))
            }
        }
    }

    private func apply(
        _ entry: SyncEntry, pending: PendingDeletion?, state: inout SyncState, highWater: inout UInt64,
        report: inout SyncReport
    ) async throws {
        let (ceiling, overflow) = highWater.addingReportingOverflow(configuration.maximumVersionJump)
        guard entry.version <= configuration.maximumVersion, overflow || entry.version <= ceiling else {
            // Not merged, but kept: only the person may discard it (PRD F7.7).
            report.quarantined.append(entry.key)
            try await syncState.quarantine(entry, vaultID: vaultID)
            return
        }
        highWater = max(highWater, entry.version)
        var erasure = state.erasures[entry.key]
        if let pending, erasure.map({ $0.stamp < pending.stamp }) ?? true {
            erasure = Erasure(stamp: pending.stamp, summary: try await summary(of: pending.record))
        }
        var attempt = 0
        while true {
            do {
                if try await applyOnce(entry, erasure: erasure) { report.applied += 1 }
                break
            } catch RecordStoreError.versionConflict where attempt < 4 {
                // The session wrote the same record while the merger ran: merge against the new local version.
                attempt += 1
            }
        }
        state.known[entry.key] = max(state.known[entry.key] ?? entry.stamp, entry.stamp)
        if entry.isDeletion, state.erasures[entry.key].map({ $0.stamp < entry.stamp }) ?? true {
            state.erasures[entry.key] = Erasure(stamp: entry.stamp, summary: entry.erasure)
        }
        if entry.device == deviceID {
            state.published[entry.key] = max(state.published[entry.key] ?? entry.stamp, entry.stamp)
        }
    }

    /// Returns whether the local store changed. `erasure` is the latest erasure of the record known here, published
    /// or not.
    private func applyOnce(_ entry: SyncEntry, erasure: Erasure?) async throws -> Bool {
        let key = entry.key
        let local = try await store.record(key)
        if let local, local.vaultID != vaultID { throw Rejection(reason: .recordInAnotherVault(entry.recordID)) }

        guard let remote = entry.record(in: vaultID) else {
            // An erasure removes the local version only if its author had seen all of it; an edit it never saw is
            // kept, in the trash (PRD F7.6).
            guard let local else { return false }
            let erasure = Erasure(stamp: entry.stamp, summary: entry.erasure)
            switch try await resolve(erasure, of: local) {
            case .erase:
                try await store.commit(StoreChange(conditionalDeletions: [key: local.version]))
            case .keep:
                return false
            case .replace(let kept):
                try validateKept(kept, above: max(local.version, entry.version), key: key)
                try await store.commit(StoreChange(upserts: [kept], expectations: [key: .version(local.version)]))
            }
            return true
        }
        guard let local else {
            var stored = remote
            if let erasure {
                switch try await resolve(erasure, of: remote) {
                case .erase: return false  // Erased by someone who had seen all of this version.
                case .keep: break
                case .replace(let kept):
                    try validateKept(kept, above: max(remote.version, erasure.stamp.version), key: key)
                    stored = kept
                }
            }
            try await store.commit(StoreChange(upserts: [stored], expectations: [key: .absent]))
            return true
        }
        if local.version == remote.version, local.deviceID == remote.deviceID, local.keyID == remote.keyID,
            local.envelope == remote.envelope
        {
            return false
        }

        let decision: MergeDecision
        do {
            decision = try await merger.merge(local: local, remote: remote)
        } catch let error where Self.isFatal(error) {
            throw error
        } catch {
            throw Rejection(reason: .mergeFailed(entry.recordID))
        }
        switch decision {
        case .keepLocal:
            return false
        case .adoptRemote:
            guard remote.version > local.version else { throw Rejection(reason: .invalidMergeResult(entry.recordID)) }
            try await store.commit(StoreChange(upserts: [remote], expectations: [key: .version(local.version)]))
        case .replace(let merged):
            guard merged.key == key, merged.vaultID == vaultID, merged.deviceID == deviceID,
                merged.version > max(local.version, remote.version), merged.version <= configuration.maximumVersion
            else { throw Rejection(reason: .invalidMergeResult(entry.recordID)) }
            try await store.commit(StoreChange(upserts: [merged], expectations: [key: .version(local.version)]))
        }
        return true
    }

    private func resolve(_ erasure: Erasure, of record: StoredRecord) async throws -> ErasureDecision {
        do {
            return try await merger.resolveErasure(erasure.summary, of: record)
        } catch let error where Self.isFatal(error) {
            throw error
        } catch {
            throw Rejection(reason: .mergeFailed(record.recordID))
        }
    }

    private func validateKept(_ kept: StoredRecord, above version: UInt64, key: RecordKey) throws {
        guard kept.key == key, kept.vaultID == vaultID, kept.deviceID == deviceID, kept.version > version,
            kept.version <= configuration.maximumVersion
        else { throw Rejection(reason: .invalidMergeResult(key.recordID)) }
    }

    /// What this device had seen of a record it erased. A summary that cannot be made (the row does not open) is
    /// empty, which claims to have seen nothing: every other version of the record is then kept, never erased.
    private func summary(of record: StoredRecord) async throws -> [UInt8] {
        do {
            return try await merger.erasureSummary(of: record)
        } catch let error where Self.isFatal(error) {
            throw error
        } catch {
            return []
        }
    }

    private func vaultHighWater(_ state: SyncState) async throws -> UInt64 {
        var highest = state.known.values.map(\.version).max() ?? 0
        for kind in configuration.schemaVersions.keys {
            highest = max(highest, try await store.records(in: vaultID, kind: kind).map(\.version).max() ?? 0)
        }
        return highest
    }

    // MARK: - Publish

    private func push(state: inout SyncState, report: inout SyncReport) async throws {
        try await settlePendingDeletions(state: state)
        var entries: [RecordKey: SyncEntry] = [:]
        for kind in configuration.schemaVersions.keys {
            for row in try await store.records(in: vaultID, kind: kind) where row.deviceID == deviceID {
                if let published = state.published[row.key], published >= RecordStamp(row) { continue }
                entries[row.key] = SyncEntry(row)
            }
        }
        let pending = try await syncState.pendingDeletions(vaultID: vaultID)
        var obsolete: [RecordKey: RecordStamp] = [:]
        // A version written after the deletion (a trashed copy kept for an edit the deletion had not seen) follows
        // the deletion in a later segment, so every device applies them in that order.
        var later: [SyncEntry] = []
        for (key, deletion) in pending {
            if let erasure = state.erasures[key], erasure.stamp >= deletion.stamp {
                obsolete[key] = deletion.stamp  // Already published.
                continue
            }
            if let row = entries.removeValue(forKey: key) { later.append(row) }
            entries[key] = .tombstone(key, stamp: deletion.stamp, erasure: try await summary(of: deletion.record))
        }
        // Another device collects its segments once every device acknowledges them and a snapshot covers them; tell
        // it when this device has merged further into that covered range than it last said.
        let needsAcknowledgement = state.merged.contains { author, merged in
            author != deviceID
                && min(merged, state.snapshotCoverage[author] ?? 0) > (state.publishedAcknowledgement[author] ?? 0)
        }
        guard !entries.isEmpty || !later.isEmpty || needsAcknowledgement else {
            try await syncState.removePendingDeletions(obsolete, vaultID: vaultID)
            return
        }

        var batches = chunks(entries.values.sorted(by: SyncPayload.entryOrder))
        if !later.isEmpty { batches += chunks(later.sorted(by: SyncPayload.entryOrder)) }
        if batches.count > 1, batches[0].isEmpty { batches.removeFirst() }
        for chunk in batches {
            let sequence = state.nextSequence
            var vector = state.merged
            vector[deviceID] = sequence - 1
            let location = SyncObjectLocation.segment(vaultID: vaultID, author: deviceID, sequence: sequence)
            let payload = SyncPayload(
                kind: .segment, vaultID: vaultID, author: deviceID, number: sequence, vector: vector, entries: chunk)
            let envelope = try await keyring.seal(payload.encoded(), at: location)
            let signature = try await keyring.sign(envelope, at: location)
            do {
                try await transport.create(
                    location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())
            } catch SyncTransportError.objectExists {
                report.ownStreamConflict = sequence
                return
            }
            state.nextSequence = sequence + 1
            state.lastPublishedSequence = sequence
            if (state.merged[deviceID] ?? 0) == sequence - 1 { state.merged[deviceID] = sequence }
            var published: [RecordKey: RecordStamp] = [:]
            for entry in chunk {
                state.known[entry.key] = max(state.known[entry.key] ?? entry.stamp, entry.stamp)
                state.published[entry.key] = max(state.published[entry.key] ?? entry.stamp, entry.stamp)
                if entry.isDeletion {
                    published[entry.key] = entry.stamp
                    state.erasures[entry.key] = Erasure(stamp: entry.stamp, summary: entry.erasure)
                }
            }
            state.publishedAcknowledgement = vector
            report.segmentsWritten += 1
            report.pushedEntries += chunk.count
            try await syncState.saveState(state)
            try await syncState.removePendingDeletions(published, vaultID: vaultID)
        }
        try await syncState.removePendingDeletions(obsolete, vaultID: vaultID)
    }

    /// A row that came back while its deletion was being made — merged from another device between the session's
    /// read and its delete — is settled the way the deletion will settle it on every other device, so this device does
    /// not keep a record everyone else erases.
    private func settlePendingDeletions(state: SyncState) async throws {
        for (key, deletion) in try await syncState.pendingDeletions(vaultID: vaultID)
        where state.erasures[key].map({ $0.stamp < deletion.stamp }) ?? true {
            guard let row = try await store.record(key), row.vaultID == vaultID else { continue }
            let erasure = Erasure(stamp: deletion.stamp, summary: try await summary(of: deletion.record))
            let decision: ErasureDecision
            do {
                decision = try await resolve(erasure, of: row)
            } catch let error where Self.isFatal(error) {
                throw error
            } catch {
                continue  // Undecidable: keep the row; nothing is erased on a guess.
            }
            switch decision {
            case .erase:
                try await store.commit(StoreChange(conditionalDeletions: [key: row.version]))
            case .keep:
                break
            case .replace(let kept):
                try validateKept(kept, above: max(row.version, deletion.stamp.version), key: key)
                try await store.commit(StoreChange(upserts: [kept], expectations: [key: .version(row.version)]))
            }
        }
    }

    /// Splits entries by count and size; always at least one chunk, so an acknowledgement-only segment can be written.
    private func chunks(_ entries: [SyncEntry]) -> [[SyncEntry]] {
        var result: [[SyncEntry]] = [[]]
        var size = 0
        for entry in entries {
            let entrySize = SyncPayload.minimumEntryLength + (entry.envelope?.count ?? entry.erasure.count)
            if !result[result.count - 1].isEmpty,
                result[result.count - 1].count >= configuration.maximumEntriesPerSegment
                    || size + entrySize > configuration.maximumSegmentPayloadLength
            {
                result.append([])
                size = 0
            }
            result[result.count - 1].append(entry)
            size += entrySize
        }
        return result
    }

    // MARK: - Snapshots and garbage collection

    /// A snapshot's coverage is what this device has merged, whatever else failed in the sync, so a rejected or
    /// missing object elsewhere never stops snapshots (or, through them, garbage collection).
    private func maintain(state: inout SyncState, listing: Listing, report: inout SyncReport) async throws {
        try await writeSnapshotIfElected(state: &state, report: &report)
        try await collectGarbage(state: &state, listing: listing, report: &report)
    }

    private func writeSnapshotIfElected(state: inout SyncState, report: inout SyncReport) async throws {
        let uncovered = state.merged.reduce(0) { total, element in
            total + Int(clamping: element.value &- min(element.value, state.snapshotCoverage[element.key] ?? 0))
        }
        guard uncovered >= max(configuration.snapshotThreshold, 2 * state.merged.count) else { return }
        // The lowest device ID among those that wrote since the last snapshot (§7.1); the others wait for it, unless
        // it has fallen so far behind (it may be offline for good) that any device steps in. Two snapshots at once
        // are harmless: each has its own name.
        let active = state.merged.filter { $0.value > (state.snapshotCoverage[$0.key] ?? 0) }.keys
        guard active.min(by: { $0.precedes($1) }) == deviceID || uncovered >= 4 * configuration.snapshotThreshold
        else { return }

        var entries: [SyncEntry] = []
        var present: Set<RecordKey> = []
        for kind in configuration.schemaVersions.keys {
            for row in try await store.records(in: vaultID, kind: kind) {
                entries.append(SyncEntry(row))
                present.insert(row.key)
            }
        }
        for (key, erasure) in state.erasures where !present.contains(key) {
            entries.append(.tombstone(key, stamp: erasure.stamp, erasure: erasure.summary))
        }
        let lamport = max(entries.map(\.version).max() ?? 0, 1)
        let location = SyncObjectLocation.snapshot(vaultID: vaultID, author: deviceID, lamport: lamport)
        let payload = SyncPayload(
            kind: .snapshot, vaultID: vaultID, author: deviceID, number: lamport, vector: state.merged,
            entries: entries
        ).encoded()
        guard payload.count < Envelope.maximumLength - 4096 else { return }
        let envelope = try await keyring.seal(payload, at: location)
        let signature = try await keyring.sign(envelope, at: location)
        do {
            try await transport.create(
                location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())
        } catch SyncTransportError.objectExists {
            return
        }
        state.snapshots[location] = state.merged
        state.snapshotCoverage.merge(state.merged, uniquingKeysWith: max)
        report.snapshotsWritten += 1
    }

    /// Deletes this device's own segments that every other known device has acknowledged merging and that some
    /// listed snapshot covers (so a device joining later gets their effects from it), always keeping the newest, so the
    /// stream's position and acknowledgement stay visible. Also deletes this device's own snapshots that another listed
    /// snapshot covers entirely. A device joining merges every listed snapshot, so it never depends on which one is
    /// "newest".
    private func collectGarbage(state: inout SyncState, listing: Listing, report: inout SyncReport) async throws {
        let listed = Set(listing.snapshots)
        state.snapshots = state.snapshots.filter { listed.contains($0.key) }
        let covered = listed.reduce(UInt64(0)) { highest, location in
            max(highest, state.snapshots[location]?[deviceID] ?? 0)
        }
        let others = state.merged.keys.filter { $0 != deviceID }
        let acknowledged = others.map { state.acknowledgements[$0]?[deviceID] ?? 0 }.min() ?? covered
        let limit = min(covered, acknowledged)
        let own = listing.segments[deviceID] ?? []
        let newest = own.max() ?? 0
        for sequence in own where sequence <= limit && sequence < newest {
            try await transport.delete(
                SyncObjectLocation.segment(vaultID: vaultID, author: deviceID, sequence: sequence).name)
            report.collected += 1
        }
        for (location, coverage) in state.snapshots where location.author == deviceID {
            let superseded = state.snapshots.contains { other, otherCoverage in
                other != location && Self.covers(otherCoverage, coverage)
                    && (!Self.covers(coverage, otherCoverage) || Self.snapshotOrder(location, other))
            }
            guard superseded else { continue }
            try await transport.delete(location.name)
            state.snapshots[location] = nil
            report.collected += 1
        }
    }

    // MARK: - Helpers

    struct Rejection: Error {
        let reason: SyncRejectionReason
    }

    /// Errors that stop the sync rather than reject one object: the vault locked, the transport went away, or the
    /// local store failed.
    static func isFatal(_ error: any Error) -> Bool {
        switch error {
        case SyncKeyringError.locked, SyncTransportError.unavailable: return true
        case is RecordStoreError: return true
        default: return false
        }
    }

    static func reason(_ error: any Error) -> SyncRejectionReason {
        switch error {
        case let rejection as Rejection: return rejection.reason
        case let error as SyncFormatError: return .format(error)
        case let error as EnvelopeError: return .envelope(error)
        case let error as SyncKeyringError: return .keyring(error)
        case let error as SyncTransportError: return .transport(error)
        default: return .other(String(describing: type(of: error)))
        }
    }

    /// Whether `vector` has merged at least everything `coverage` names (optionally ignoring one stream: a device
    /// has always merged its own).
    static func covers(_ vector: [UUID: UInt64], _ coverage: [UUID: UInt64], excluding: UUID? = nil) -> Bool {
        coverage.allSatisfy { $0.key == excluding || (vector[$0.key] ?? 0) >= $0.value }
    }

    static func snapshotOrder(_ a: SyncObjectLocation, _ b: SyncObjectLocation) -> Bool {
        if a.number != b.number { return a.number < b.number }
        return a.author.precedes(b.author)
    }
}
