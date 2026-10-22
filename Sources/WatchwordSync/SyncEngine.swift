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
    /// Remote versions refused as implausible (U5).
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
/// 1. **Downloads** (`pull`): lists the vault, fetches the newest snapshot and every segment past what has been merged,
///    checks each signature against its author, and stages it. Needs no keys, so it runs while locked (§7.4).
/// 2. **Merges** staged objects, which needs the vault key: per stream strictly in sequence order, stopping at a gap
///    rather than skipping it. Each record version goes through the `RecordMerger` (field-level, F7.4); deletions and
///    versions are resolved here. A version older than what the device holds can never displace newer values: the
///    merge only moves forward, which is the sync layer's monotonic check (§5).
/// 3. **Publishes** this device's new versions and deletions as the next segment of its stream.
/// 4. **Maintains**: the elected device writes a snapshot once enough segments are uncovered, and each device deletes
///    its own segments once a snapshot covers them and every known device has acknowledged it.
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
            let kept = state
            state = SyncState(vaultID: vaultID)
            state.nextSequence = kept.nextSequence
            state.publishedAcknowledgement = kept.publishedAcknowledgement
        }
        var listing = Listing()
        do {
            listing = try await pull(state: state, report: &report)
        } catch SyncTransportError.unavailable {
            // Offline (PRD N3): still merge what was downloaded earlier, perhaps while locked.
            report.transportUnavailable = true
        }
        do {
            try await mergeStaged(state: &state, report: &report)
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
        for name in try await transport.list(prefix: SyncObjectLocation.vaultPrefix(vaultID)) {
            guard let location = SyncObjectLocation(name: name), location.vaultID == vaultID else {
                report.ignoredNames += 1
                continue
            }
            switch location.kind {
            case .segment: listing.segments[location.author, default: []].append(location.number)
            case .snapshot: listing.snapshots.append(location)
            }
        }

        var wanted: [SyncObjectLocation] = []
        if let newest = listing.snapshots.max(by: Self.snapshotOrder),
            state.snapshot.map({ Self.snapshotOrder($0, newest) }) ?? true
        {
            wanted.append(newest)
        }
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
        // A deletion made here but not yet published is as much a tombstone as a published one: without it, a
        // snapshot or segment written before the deletion would put the record back on this device only.
        let pending = try await syncState.pendingDeletions(vaultID: vaultID)
        let segments = Dictionary(grouping: staged.filter { $0.location.kind == .segment }, by: \.location.author)

        // The newest snapshot first: it bootstraps a new device and fills gaps left by garbage collection.
        let snapshots = staged.filter { $0.location.kind == .snapshot }.sorted {
            Self.snapshotOrder($0.location, $1.location)
        }
        if let newest = snapshots.last {
            do {
                let payload = try await open(newest)
                try validate(payload, at: newest.location)
                if Self.covers(state.merged, payload.vector) {
                    if let current = state.snapshot, !Self.snapshotOrder(current, newest.location) {
                        report.staleSnapshots += 1
                    }
                } else {
                    for entry in payload.entries {
                        try await apply(
                            entry, pending: pending[entry.key], state: &state, highWater: &highWater, report: &report)
                    }
                    // A stream whose next segment is not available (collected, or not yet visible) continues from the
                    // snapshot's coverage; one whose next segment is here is merged from its own segments.
                    for (author, sequence) in payload.vector where sequence > (state.merged[author] ?? 0) {
                        let next = (state.merged[author] ?? 0) + 1
                        if !(segments[author] ?? []).contains(where: { $0.location.number == next }) {
                            state.merged[author] = sequence
                        }
                    }
                }
                if state.snapshot.map({ Self.snapshotOrder($0, newest.location) }) ?? true {
                    state.snapshot = newest.location
                    state.snapshotCoverage = payload.vector
                }
            } catch let error where Self.isFatal(error) {
                throw error
            } catch {
                report.rejected.append(SyncRejection(name: newest.location.name, reason: Self.reason(error)))
            }
        }
        try await syncState.unstage(snapshots.map(\.location))

        for author in segments.keys.sorted(by: { $0.precedes($1) }) {
            var next = (state.merged[author] ?? 0) + 1
            for object in segments[author]!.sorted(by: { $0.location.number < $1.location.number }) {
                let sequence = object.location.number
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
                    report.waiting[author] = next
                    // Unstaged, so the next sync fetches it again: a partially visible file may since have completed.
                    try await syncState.unstage([object.location])
                    break
                }
                state.merged[author] = sequence
                if author == deviceID {
                    if sequence >= state.nextSequence { report.ownStreamConflict = sequence }
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
        _ entry: SyncEntry, pending: RecordStamp?, state: inout SyncState, highWater: inout UInt64,
        report: inout SyncReport
    ) async throws {
        let (ceiling, overflow) = highWater.addingReportingOverflow(configuration.maximumVersionJump)
        guard entry.version <= configuration.maximumVersion, overflow || entry.version <= ceiling else {
            report.quarantined.append(entry.key)
            return
        }
        highWater = max(highWater, entry.version)
        let known = state.known[entry.key]
        let tombstone = [known.flatMap { $0.deleted ? $0 : nil }, pending].compactMap { $0 }.max()
        var attempt = 0
        while true {
            do {
                if try await applyOnce(entry, tombstone: tombstone) { report.applied += 1 }
                break
            } catch RecordStoreError.versionConflict where attempt < 4 {
                // The session wrote the same record while the merger ran: merge against the new local version.
                attempt += 1
            }
        }
        state.known[entry.key] = max(known ?? entry.stamp, entry.stamp)
        if entry.device == deviceID {
            state.published[entry.key] = max(state.published[entry.key] ?? entry.stamp, entry.stamp)
        }
    }

    /// Returns whether the local store changed. `tombstone` is the latest deletion of the record known here, published
    /// or not.
    private func applyOnce(_ entry: SyncEntry, tombstone: RecordStamp?) async throws -> Bool {
        let key = entry.key
        let local = try await store.record(key)
        if let local, local.vaultID != vaultID { throw Rejection(reason: .recordInAnotherVault(entry.recordID)) }

        guard let remote = entry.record(in: vaultID) else {
            // A deletion wins over the local version only if it is later; a later local edit keeps the record.
            guard let local, entry.stamp > RecordStamp(local) else { return false }
            try await store.commit(StoreChange(conditionalDeletions: [key: local.version]))
            return true
        }
        guard let local else {
            if let tombstone, tombstone >= entry.stamp { return false }  // Deleted after this version.
            try await store.commit(StoreChange(upserts: [remote], expectations: [key: .absent]))
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

    private func vaultHighWater(_ state: SyncState) async throws -> UInt64 {
        var highest = state.known.values.map(\.version).max() ?? 0
        for kind in configuration.schemaVersions.keys {
            highest = max(highest, try await store.records(in: vaultID, kind: kind).map(\.version).max() ?? 0)
        }
        return highest
    }

    // MARK: - Publish

    private func push(state: inout SyncState, report: inout SyncReport) async throws {
        var entries: [RecordKey: SyncEntry] = [:]
        for kind in configuration.schemaVersions.keys {
            for row in try await store.records(in: vaultID, kind: kind) where row.deviceID == deviceID {
                if let published = state.published[row.key], published >= RecordStamp(row) { continue }
                entries[row.key] = SyncEntry(row)
            }
        }
        let pending = try await syncState.pendingDeletions(vaultID: vaultID)
        var obsolete: [RecordKey: RecordStamp] = [:]
        for (key, stamp) in pending {
            let row = try await store.record(key)
            if let row, RecordStamp(row) > stamp {
                obsolete[key] = stamp  // Superseded by a later version (a remote edit that won).
            } else if let known = state.known[key], known >= stamp {
                obsolete[key] = stamp  // Already published, or superseded remotely.
            } else if entries[key].map({ $0.stamp < stamp }) ?? true {
                entries[key] = .tombstone(key, stamp: stamp)
            }
        }

        let needsAcknowledgement =
            state.snapshot != nil && Self.covers(state.merged, state.snapshotCoverage)
            && !Self.covers(state.publishedAcknowledgement, state.snapshotCoverage, excluding: deviceID)
        guard !entries.isEmpty || needsAcknowledgement else {
            try await syncState.removePendingDeletions(obsolete, vaultID: vaultID)
            return
        }

        for chunk in chunks(entries.values.sorted(by: SyncPayload.entryOrder)) {
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
            if (state.merged[deviceID] ?? 0) == sequence - 1 { state.merged[deviceID] = sequence }
            var published: [RecordKey: RecordStamp] = [:]
            for entry in chunk {
                state.known[entry.key] = max(state.known[entry.key] ?? entry.stamp, entry.stamp)
                state.published[entry.key] = max(state.published[entry.key] ?? entry.stamp, entry.stamp)
                if entry.isDeletion { published[entry.key] = entry.stamp }
            }
            state.publishedAcknowledgement = vector
            report.segmentsWritten += 1
            report.pushedEntries += chunk.count
            try await syncState.saveState(state)
            try await syncState.removePendingDeletions(published, vaultID: vaultID)
        }
        try await syncState.removePendingDeletions(obsolete, vaultID: vaultID)
    }

    /// Splits entries by count and size; always at least one chunk, so an acknowledgement-only segment can be written.
    private func chunks(_ entries: [SyncEntry]) -> [[SyncEntry]] {
        var result: [[SyncEntry]] = [[]]
        var size = 0
        for entry in entries {
            let entrySize = SyncPayload.minimumEntryLength + 4 + (entry.envelope?.count ?? 0)
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

    private func maintain(state: inout SyncState, listing: Listing, report: inout SyncReport) async throws {
        if report.waiting.isEmpty, report.rejected.isEmpty {
            try await writeSnapshotIfElected(state: &state, report: &report)
        }
        try await collectGarbage(state: state, listing: listing, report: &report)
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
        for (key, stamp) in state.known where stamp.deleted && !present.contains(key) {
            entries.append(.tombstone(key, stamp: stamp))
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
        state.snapshot = location
        state.snapshotCoverage = state.merged
        report.snapshotsWritten += 1
    }

    /// Deletes this device's own segments covered by the newest snapshot, once every other known stream has
    /// acknowledged merging everything it covers, and this device's own superseded snapshots. The newest segment of
    /// the stream is always kept, so the stream's position (and its acknowledgement) stays visible.
    private func collectGarbage(state: SyncState, listing: Listing, report: inout SyncReport) async throws {
        guard let snapshot = state.snapshot, Self.covers(state.merged, state.snapshotCoverage) else { return }
        let others = state.merged.keys.filter { $0 != deviceID }
        guard
            others.allSatisfy({
                Self.covers(state.acknowledgements[$0] ?? [:], state.snapshotCoverage, excluding: $0)
            })
        else { return }
        let covered = state.snapshotCoverage[deviceID] ?? 0
        let newest = state.nextSequence &- 1
        for sequence in listing.segments[deviceID] ?? [] where sequence <= covered && sequence < newest {
            try await transport.delete(
                SyncObjectLocation.segment(vaultID: vaultID, author: deviceID, sequence: sequence).name)
            report.collected += 1
        }
        for location in listing.snapshots
        where location.author == deviceID && Self.snapshotOrder(location, snapshot) {
            try await transport.delete(location.name)
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
