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
    /// Whether this device writes snapshots and collects its own segments. Off for a shared vault: a write cut is
    /// judged against the departing account's own segments, so they must stay on the transport for every device
    /// that has yet to judge it (docs/02-architecture.md §8.8, "a departed account's log").
    public var maintainsLog = true
    /// Entries of ignorable record kinds this version does not carry that one vault keeps aside (`SyncStash`, ADR
    /// 0009), and their bytes, in all and for what any one device's objects carried. Past any of them, an entry is
    /// not kept (`SyncReport.unknownEntriesDropped`, `SyncStash.overflow`): the stream still merges, the device writes
    /// no ordinary snapshot, and the version that learns the kind replays the log. Generous: one per record, writing
    /// device and deletion, a few hundred bytes each; the per-device share keeps one device from crowding out the rest.
    public var maximumStashedEntries = 4096
    public var maximumStashedBytes = 4 << 20
    public var maximumStashedEntriesPerAuthor = 2048
    public var maximumStashedBytesPerAuthor = 2 << 20
    /// Versions one vault keeps aside for the person (the quarantine), and their bytes, in all and for the versions
    /// any one device wrote (review finding Z27). Past any of them a version is not kept on this device
    /// (`SyncReport.quarantineFull`): the object that carried it is still merged or passed as before, and a shared
    /// vault's log, which is never collected, still holds it. Generous for honest use, where a kept version is rare,
    /// and small enough that someone whose segments are accepted only to be held aside (a former member, A5) cannot
    /// fill a device's disk or make each sync reread it all.
    public var maximumQuarantinedEntries = 2048
    public var maximumQuarantinedBytes = 64 << 20
    public var maximumQuarantinedEntriesPerAuthor = 512
    public var maximumQuarantinedBytesPerAuthor = 16 << 20

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
    /// The merger could not merge the remote version (it does not open, or opens to another item).
    case mergeFailed(UUID)
    /// The merger returned a result the engine must not store.
    case invalidMergeResult(UUID)
    /// An account-level object (a registry entry, an account header, a vault-directory object) that is not what its
    /// name says, or is not signed by the account key and a registered device (docs/02-architecture.md §7.7).
    case accountObjectRefused
    case other(String)
}

public struct SyncRejection: Sendable, Equatable {
    public var name: String
    public var reason: SyncRejectionReason

    public init(name: String, reason: SyncRejectionReason) {
        self.name = name
        self.reason = reason
    }
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
    /// Remote versions refused as implausible (U5), or whose merge with the local version cannot be sealed (Y37).
    /// Kept in `SyncStateStore.quarantined` until the person discards them (PRD F7.7).
    public var quarantined: [RecordKey] = []
    /// Remote versions held aside because they carry work that does not count in a shared vault (a write outside
    /// its author's write cut, docs/02-architecture.md §8.7). Kept in the quarantine like the others.
    public var heldAside: [RecordKey] = []
    /// Remote versions whose record ID a record of *another vault* holds on this device (the local store keys
    /// records by ID and kind across vaults). Not merged, and the other vault's row is not touched: kept in the
    /// quarantine like the others, while the rest of the object and its stream are merged (review finding Z22).
    public var collided: [RecordKey] = []
    /// Streams stopped at a missing or rejected segment: the next sequence number each is waiting for. Later segments
    /// are never applied over a gap.
    public var waiting: [UUID: UInt64] = [:]
    /// Snapshots whose coverage this device had already merged. Their entries are merged all the same (it is
    /// idempotent): a snapshot may carry what its author merged from a device revoked since.
    public var staleSnapshots = 0
    /// Names in the vault's prefix that are not sync objects.
    public var ignoredNames = 0
    /// The vault was locked: objects were downloaded and checked, but merging and publishing wait for unlock (§7.4).
    public var deferredUntilUnlock = false
    /// The transport could not be reached. Objects downloaded earlier were still merged; nothing was published.
    public var transportUnavailable = false
    /// Why, when the transport said: offline (`unavailable`), throttled with the wait it asked for, out of storage,
    /// signed out, or reset (`SyncTransportError.stopsSync`).
    public var transportFailure: SyncTransportError?
    /// This device's next sequence number was already taken: a crash after publishing, or another installation using
    /// this device ID (a restored backup). The object is merged on the next sync and nothing is overwritten.
    public var ownStreamConflict: UInt64?
    /// The lowest number of this device's own stream at which a shared vault's judge stepped over (held aside or passed
    /// over) a segment this device's own keys did not sign: another account's device listed under this device's ID
    /// (S33) wrote there (review finding Z146). Below this device's first segment there, every other device may take
    /// the stream for that account's and hold aside what this device publishes in it, so the person is told.
    public var ownStreamSteppedOver: UInt64?
    /// An object in this device's own stream, at or beyond its next sequence number, that could not be fetched or
    /// checked in this sync (listed and not there yet, unreadable, or no key to check it with): the lowest such
    /// number. Whether this device wrote it decides where its next segment goes — a state older than the transport
    /// must not reuse a number, and a name anyone can create must not move it — so nothing was published, and the
    /// next sync asks again (review finding Z24).
    public var ownStreamUnverified: UInt64?
    /// This device's next sequence number is beyond `SyncConfiguration.maximumSequence`, where no reader lists a
    /// segment: nothing was published, and nothing was marked as published (review finding Z21). Not reachable by
    /// publishing; it means the stream's position was damaged, and this device cannot publish in this vault.
    public var ownStreamExhausted = false
    /// Objects on the transport written by a device since revoked: not fetched, not counted as waiting, and not
    /// waited for by garbage collection (review finding Y6).
    public var retiredObjects = 0
    /// This device has been revoked: nothing it publishes would be accepted, so it publishes nothing.
    public var deviceRevoked = false
    /// This device is not in the account's device registry as it sees it (its registration has not been accepted,
    /// or was made with a password since changed): it downloads, and publishes nothing until it is registered.
    public var deviceNotRegistered = false
    /// The account password was changed on another device and has not been entered on this one yet. Until it is,
    /// this device downloads but neither merges nor publishes (docs/02-architecture.md §7.8).
    public var awaitingNewPassword = false
    /// Deletions made on this device that were held back (`sync(deferringDeletions: true)`): still pending, still
    /// counted as erasures here, published by a later sync.
    public var deletionsDeferred = 0
    /// A stream stopped at an object that carries an entry of a critical record kind this version does not know
    /// (`SyncFormatError.unsupportedRecordKind`, ADR 0009). Nothing past it is merged and nothing in it is skipped;
    /// the object stays staged, and the app must be updated to go on. Shown as "update the app".
    public var requiresNewerVersion = false
    /// Entries of ignorable record kinds this version does not know, newly kept aside (ADR 0009); the streams
    /// carrying them were merged.
    public var unknownEntriesKept = 0
    /// Such entries not kept, the stash being full. Nothing is lost for other devices; this one replays the log once
    /// it learns the kind.
    public var unknownEntriesDropped = 0
    /// Entries kept aside by an earlier version and processed now that this one carries their kind.
    public var unknownEntriesProcessed = 0
    /// This device was due to write a snapshot and did not, because it holds entries it cannot read (ADR 0009).
    public var snapshotWithheld = false
    /// The trusted devices whose objects carried those entries: the ones to update, or, if no version reads the kind,
    /// to look at (an insider can hold back snapshots this way for as long as it is trusted).
    public var snapshotWithheldBy: Set<UUID> = []
    /// This device was due to write a snapshot and did not, because its quarantine holds versions written by devices
    /// still trusted: a snapshot would cover their segments without carrying them (review finding Z26). Ends when
    /// the person discards them (they are listed as held aside), or another device steps in.
    public var snapshotWithheldForQuarantine = false
    /// Versions that were to be kept aside and were not, the vault's quarantine being full (review finding Z27). The
    /// same version offered again by a replay is counted again.
    public var quarantineFull = 0
    /// The stash was incomplete (entries of a kind this version carries dropped past the caps, or a stash not saved
    /// after a sync), or a shared vault holds kept entries this version can now read: the vault's log had to be
    /// replayed. The engine does it itself unless the vault has a judge, whose session replays it in the same sync.
    public var replayNeeded = false

    public init() {}

    /// Records that the transport could not be used, and why. The first reason in a sync is kept.
    public mutating func noteTransportFailure(_ error: SyncTransportError) {
        transportUnavailable = true
        if transportFailure == nil { transportFailure = error }
    }
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
    let judge: (any WriteJudge)?
    private var running = false
    /// The stash of the sync in progress (ADR 0009): loaded when it starts, saved once when it ends.
    private var stash = SyncStash()
    /// The stash may lack entries of segments counted as merged, and this vault's log has not been replayed yet.
    private var stashIncomplete = false
    /// What the vault's quarantine holds, as the sync in progress found it and has added to it; loaded when first
    /// needed (`keepAside`).
    private var quarantineUsage: QuarantineUsage?
    /// Entries the merge in progress refused as beyond the version-jump ceiling, to be tried again once everything
    /// else in the pass has been merged (`retryOutOfReach`, review finding Z25).
    private var outOfReach: [SyncEntry] = []
    /// A retry owed by an earlier pass (`SyncState.retryUnfinished`) that this pass, not a replay, cannot settle.
    private var retryOwedEarlier = false

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
        configuration: SyncConfiguration,
        judge: (any WriteJudge)? = nil
    ) {
        self.vaultID = vaultID
        self.deviceID = deviceID
        self.store = store
        self.syncState = syncState
        self.transport = transport
        self.keyring = keyring
        self.merger = merger
        self.configuration = configuration
        self.judge = judge
    }

    // MARK: - Entry points

    /// Downloads, merges, publishes and maintains. While locked, only the download happens and the report says so.
    ///
    /// `deferringDeletions` publishes everything but this device's pending deletions, and any version written after
    /// one of them (which must follow its deletion): they stay pending, count as erasures here as before, and go out
    /// at a later sync. The session uses it so that a deletion in one vault is never on the transport before what
    /// this device wrote in another — a move's copy before its original's deletion (docs/02-architecture.md §7.7).
    ///
    /// `publishing: false` downloads and merges and publishes nothing: a member of a shared vault who may not write
    /// keeps a merged copy and writes nothing other devices would refuse (docs/02-architecture.md §8.7).
    ///
    /// `transportStopped` is a failure the caller already met in this sync (another vault's listing was throttled,
    /// the account is signed out): the engine then makes no call to the transport, merges what it downloaded earlier,
    /// publishes nothing and reports that failure, so one sync asks a stopped transport once, not once per vault.
    public func sync(
        reconcile: Bool = false, deferringDeletions: Bool = false, publishing: Bool = true,
        transportStopped: SyncTransportError? = nil
    ) async throws -> SyncReport {
        guard !running else { throw SyncError.syncInProgress }
        running = true
        defer { running = false }
        var report = SyncReport()
        quarantineUsage = nil
        let retired = await keyring.retiredAuthors(vaultID: vaultID)
        guard !retired.contains(deviceID) else {
            report.deviceRevoked = true
            return report
        }
        var state = try await syncState.loadState(vaultID: vaultID) ?? SyncState(vaultID: vaultID)
        let (loadedStash, stashDropped) = try await loadStash(rebuilding: &state)
        stash = loadedStash
        // What a revoked device carried is not read any more (§7.8): its own versions stay, and hold nothing back.
        let freed = stash.forgetRetired(retired)
        let forgotten = stash
        var reconcile = reconcile
        let carried = carriedRawKinds
        // An earlier version dropped entries of a kind this one carries, the stash being full; the stash was not
        // saved after a sync that counted segments as merged, or its row is not the one the state names; or room was
        // freed where entries had been crowded out. The log still holds what is missing, in its segments or in a
        // snapshot by a device that read it (ADR 0009).
        let incomplete =
            state.stashUnsaved || (freed && !stash.crowdedOut.isEmpty)
            || !stash.crowdedOut.isDisjoint(with: carried)
            || stash.overflow.values.contains { !$0.isDisjoint(with: carried) }
        if incomplete {
            if judge == nil { reconcile = true } else { report.replayNeeded = true }
        }
        stashIncomplete = incomplete && !reconcile
        // A pass that refused versions as out of reach and was stopped before it tried them again (review finding
        // Z33), or versions not kept aside for want of room that now have it (Z38): only the log offers them again.
        var offerAgain = state.retryUnfinished
        if !state.quarantineDropped.isEmpty {
            let usage = try await syncState.quarantineUsage(vaultID: vaultID)
            quarantineUsage = usage
            // A version the store refused for a crowded digest is offered again only once something has left the
            // quarantine: the caps alone had room, and a replay at every sync dropped it again (review finding Z147).
            offerAgain =
                offerAgain
                || (state.quarantineDropped.allSatisfy { hasRoom(usage, for: $0) }
                    && state.quarantineCrowded.map { UInt64(usage.entries) < $0 } ?? true)
        }
        if offerAgain {
            if judge == nil { reconcile = true } else { report.replayNeeded = true }
        }
        retryOwedEarlier = state.retryUnfinished && !reconcile
        if reconcile {
            // Everything but what this device has done itself is rebuilt from the log. Erasures are kept too: they
            // are facts the log also holds, and keeping them stops a replay from putting an erased record back. Not
            // in a vault with a judge: its log is whole (no snapshots, no collection), and an erasure merged before
            // its author's work stopped counting must not outlive the replay that holds its segment aside (S40).
            let kept = state
            state = SyncState(vaultID: vaultID)
            state.nextSequence = kept.nextSequence
            state.publishedAcknowledgement = kept.publishedAcknowledgement
            state.lastPublishedSequence = kept.lastPublishedSequence
            state.collectedThrough = kept.collectedThrough
            if judge == nil { state.erasures = kept.erasures }
            state.stashGeneration = kept.stashGeneration
            // The replay brings back everything the log holds. A revoked device's own versions it no longer reads,
            // so those are kept across it.
            var replayed = SyncStash()
            for entry in stash.entries where retired.contains(entry.author) { replayed.insert(entry) }
            stash = replayed
        }
        if stash != loadedStash { state.stashUnsaved = true }
        state.nextSequence = max(state.nextSequence, 1)
        var listing = Listing()
        if let transportStopped {
            report.noteTransportFailure(transportStopped)
        } else {
            do {
                listing = try await pull(state: state, retired: retired, report: &report)
                // Never reuse a number this stream has used: state may be older than the transport (a restored backup, a
                // rolled-back file), and a collected number would otherwise be free to create again, unseen by anyone.
                // Taken from this stream's objects that verify, never from a name: anyone who can create a file
                // under the vault's prefix can list one, and a number taken from it would leave a hole no device can
                // fill, or put every later segment out of range (review finding Z24).
                state.nextSequence = max(state.nextSequence, listing.ownVerified + 1)
            } catch let error as SyncTransportError where error.stopsSync {
                // Offline (PRD N3), throttled, signed out: still merge what was downloaded earlier, perhaps locked.
                report.noteTransportFailure(error)
            }
        }
        // The furthest this device's own stream can have got: what it remembers publishing or merging of it, and
        // its own objects on the transport that verify. A snapshot's word for it counts no further (review finding
        // Z21).
        let ownHead = max(state.lastPublishedSequence, state.merged[deviceID] ?? 0, listing.ownVerified)
        do {
            try await mergeStaged(
                state: &state, retired: retired, reconciling: reconcile, ownHead: ownHead, report: &report)
            state.nextSequence = max(state.nextSequence, (state.merged[deviceID] ?? 0) + 1)
            try await syncState.saveState(state)
            // Where this device's state could be older than its stream, and the stream cannot show which numbers it
            // used: publishing waits for the sync that can tell (Z24, Z31, Z32).
            if !report.transportUnavailable {
                report.ownStreamUnverified = ownStreamHold(state: state, listing: listing, retired: retired)
            }
            if !report.transportUnavailable, publishing, report.ownStreamUnverified == nil {
                try await push(
                    state: &state, retired: retired, deferringDeletions: deferringDeletions, report: &report)
                if report.ownStreamConflict == nil, !report.ownStreamExhausted, configuration.maintainsLog {
                    try await maintain(state: &state, listing: listing, retired: retired, report: &report)
                }
            }
        } catch SyncKeyringError.locked {
            report.deferredUntilUnlock = true
        } catch let error as SyncTransportError where error.stopsSync {
            report.noteTransportFailure(error)
        }
        // The stash once per sync, under the next generation, then the state that names it. Locked, the session
        // cannot sign it: a stash changed only by forgetting what revoked devices carried is worked out again next
        // time; one changed otherwise (a replay begun) is marked, so the next sync replays.
        var stashSaved = true
        if stashDropped || stash != loadedStash {
            stash.generation = state.stashGeneration &+ 1
            do {
                try await syncState.saveStash(stash.encoded(), vaultID: vaultID)
                state.stashGeneration = stash.generation
            } catch SyncKeyringError.locked {
                stashSaved = stash == forgotten && !stashDropped
            }
        }
        state.stashUnsaved = stashIncomplete || !stashSaved
        do {
            try await syncState.saveState(state)
        } catch SyncKeyringError.locked {
            // Locked meanwhile: the session cannot sign the state (review finding Z20). The row saved after the last
            // segment merged or published stands; what this one would have added is worked out again next time.
            report.deferredUntilUnlock = true
        }
        return report
    }

    /// The stored stash, held to this engine's caps. One that does not parse or is over them (the file was edited,
    /// A8) is dropped, and the state marked so that the log is replayed to rebuild it.
    private func loadStash(rebuilding state: inout SyncState) async throws -> (SyncStash, dropped: Bool) {
        guard let bytes = try await syncState.stash(vaultID: vaultID) else {
            // None, though the state names one that was saved (A8 deleted it): not taken as empty.
            if state.stashGeneration != 0 { state.stashUnsaved = true }
            return (SyncStash(), state.stashGeneration != 0)
        }
        guard
            let parsed = try? SyncStash.parse(
                bytes, maximumEntries: configuration.maximumStashedEntries,
                maximumBytes: configuration.maximumStashedBytes),
            parsed.generation == state.stashGeneration
        else {
            state.stashUnsaved = true
            return (SyncStash(), true)
        }
        return (parsed, false)
    }

    /// Downloads and signature-checks new objects only. Needs no keys (§7.4). With `transportStopped`, does nothing
    /// but report it (see `sync`).
    public func download(transportStopped: SyncTransportError? = nil) async throws -> SyncReport {
        guard !running else { throw SyncError.syncInProgress }
        running = true
        defer { running = false }
        var report = SyncReport()
        if let transportStopped {
            report.noteTransportFailure(transportStopped)
            return report
        }
        let state = try await syncState.loadState(vaultID: vaultID) ?? SyncState(vaultID: vaultID)
        do {
            _ = try await pull(
                state: state, retired: await keyring.retiredAuthors(vaultID: vaultID), report: &report)
        } catch let error as SyncTransportError where error.stopsSync {
            report.noteTransportFailure(error)
        }
        return report
    }

    // MARK: - Download

    struct Listing {
        var segments: [UUID: [UInt64]] = [:]
        var snapshots: [SyncObjectLocation] = []
        /// The highest number in this device's own stream whose object was fetched (now or earlier) and carries this
        /// device's own signatures (`SyncKeyring.verifyOwn`). Zero if none.
        var ownVerified: UInt64 = 0
        /// Numbers listed in this device's own stream, past what it has merged, whose objects could be neither
        /// verified as this device's nor shown not to be: not fetched, unreadable, or no key to check them with.
        var ownUndecided: [UInt64] = []
        /// Whether the listing holds an object of this device's own stream that is known to be this device's: one
        /// that verified as its own in this sync, or the one at the number its signed state last published. Its
        /// segments are collected lowest first, and never the newest, so while one of them is listed none above it
        /// has been collected: a number at or past the next one is then either free or listed, and creating at a
        /// listed one is refused (objects are never overwritten), so publishing reuses nothing (review finding Z31).
        var ownAnchored = false
    }

    /// Whether a failure to stage or check an object of this device's own stream shows that this device did not write
    /// it: it was read in full and is not a signed object, it is over the size cap, or its signatures are not this
    /// device's (`untrustedAuthor` included: another account's device under this ID, Z30). Anything else (it could not
    /// be read, there is no key to check it with) leaves the question open.
    static func isNotOwn(_ error: any Error) -> Bool {
        switch error {
        case is SyncFormatError: return true
        case SyncKeyringError.authenticationFailed: return true
        case SyncKeyringError.untrustedAuthor: return true
        case SyncTransportError.objectTooLarge: return true
        default: return false
        }
    }

    /// Whether this device's own stream holds back its publishing in this vault, and from which number (review
    /// findings Z24, Z31, Z32, Z145). A device whose state may be older than the transport (a restored backup, an
    /// earlier row put back) must not publish at a number it used and collected, where no reader looks. With an object
    /// of its own stream known to be its own listed (`Listing.ownAnchored`) that cannot happen: its genuine head is
    /// never collected (Z135), so nothing above a listed own object has gone. Without one it holds back:
    ///
    /// - while an object of its stream at or past its next number cannot be told from its own (`ownUndecided`): a
    ///   name shown to be someone else's (junk, another's signatures) is not one, since anyone who can create a file
    ///   can list it, and with a snapshot's claim it held for good a device that never published there (Z145, Z139);
    /// - and, for a device that has published in a vault whose log is collected (`maintainsLog`; a shared vault's is
    ///   not, so nothing there was freed for reuse, Z154), while a device still trusted says, by a snapshot's
    ///   coverage or a segment's acknowledgement, that it merged this stream further than this state's next number.
    ///   A current state's head is listed unless the store withholds it, and nobody can have merged beyond it; an older
    ///   state whose head is missing from this listing (withheld, a stale listing, A8) would otherwise publish over a
    ///   collected number, unread by every device that merged past it (Z145). Read from the state as it is now, so a
    ///   signer revoked, or the head listed again, ends it; it never moves the numbering. A device that never
    ///   published (its signed state says so) is not held by a claim: a lost state is Z32's residual, and a claim about
    ///   a device that never wrote, which an honest device carries on, would hold it for good (Z139).
    private func ownStreamHold(state: SyncState, listing: Listing, retired: Set<UUID>) -> UInt64? {
        guard !listing.ownAnchored else { return nil }
        let next = state.nextSequence
        if let undecided = listing.ownUndecided.filter({ $0 >= next }).min() { return undecided }
        // A vault that keeps its whole log (a shared vault) collects nothing, so no number of this stream was freed
        // for reuse, and creating at a used one is refused: a claim guards nothing there, and a member's
        // acknowledgement, re-made by every replay, held the device for good once its head was gone (review finding
        // Z154).
        guard state.lastPublishedSequence > 0, configuration.maintainsLog else { return nil }
        let covered =
            state.snapshots.filter { !retired.contains($0.key.author) }.values.map { $0[deviceID] ?? 0 }.max() ?? 0
        let acknowledged =
            state.acknowledgements.filter { $0.key != deviceID && !retired.contains($0.key) }.values
            .map { $0[deviceID] ?? 0 }.max() ?? 0
        return max(covered, acknowledged) >= next ? next : nil
    }

    private func pull(state: SyncState, retired: Set<UUID>, report: inout SyncReport) async throws -> Listing {
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
            // A revoked device's objects are not read at all: what it wrote before the revocation reaches a device
            // that lacks it through a snapshot written by a device still trusted (§7.8).
            guard !retired.contains(location.author) else {
                report.retiredObjects += 1
                continue
            }
            switch location.kind {
            case .segment: listing.segments[location.author, default: []].append(location.number)
            case .snapshot: listing.snapshots.append(location)
            }
        }
        let listedOwn = Set(listing.segments[deviceID] ?? [])
        if state.lastPublishedSequence > 0, listedOwn.contains(state.lastPublishedSequence) {
            listing.ownAnchored = true
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
        // A staged snapshot no longer listed was collected by its author, who does so only once another listed
        // snapshot covers it. Mostly these are snapshots kept for a version that can read them (ADR 0009); dropping
        // them keeps what waits staged no larger than what the transport lists.
        let listedSnapshots = Set(listing.snapshots)
        let collected = alreadyStaged.filter { $0.kind == .snapshot && !listedSnapshots.contains($0) }
        if !collected.isEmpty { try await syncState.unstage(Array(collected)) }
        let isOwn = { (location: SyncObjectLocation) in location.kind == .segment && location.author == self.deviceID }
        for location in wanted where !alreadyStaged.contains(location) {
            var decided = false
            do {
                guard
                    let bytes = try await transport.fetch(
                        location.name, maximumLength: configuration.maximumObjectLength)
                else {
                    // Listed and not there (not downloaded yet, or deleted since): of this device's own stream,
                    // not known to be anyone else's.
                    if isOwn(location) { listing.ownUndecided.append(location.number) }
                    continue
                }
                report.fetched += 1
                let object = try SignedObject.parse(bytes)
                if isOwn(location) {
                    // Whether this device wrote it, asked apart from whether the vault accepts it: in a shared vault
                    // another member's device can be listed under this ID, and its object verifies (Z30).
                    decided = true
                    await classifyOwn(object, at: location, listed: true, into: &listing)
                }
                try await keyring.verify(object.signature, over: object.envelope, at: location)
                try await syncState.stage(StagedObject(location: location, object: object))
            } catch let error as SyncTransportError where error.stopsSync {
                throw error
            } catch let error where error is any StorageFailure {
                // Local storage failing (staging the object, or reading what is staged) is no fault of the object:
                // it stops the sync, as while merging (review findings Z39, Z142).
                throw error
            } catch {
                report.rejected.append(SyncRejection(name: location.name, reason: Self.reason(error)))
                if location.kind == .segment {
                    report.waiting[location.author] = min(report.waiting[location.author] ?? .max, location.number)
                }
                if isOwn(location), !decided, !Self.isNotOwn(error) { listing.ownUndecided.append(location.number) }
            }
        }
        // Staged earlier (downloaded while locked, or waiting behind a gap): checked again, since the staging area is
        // a local file (A8), before its number counts. Its name must be one a reader lists: a staged row is not bound
        // by the listing's range check (review finding Z39). The merge checks it once more and unstages what fails.
        for object in try await syncState.staged(vaultID: vaultID)
        where isOwn(object.location) && alreadyStaged.contains(object.location)
            && object.location.number <= configuration.maximumSequence
        {
            await classifyOwn(
                object.object, at: object.location, listed: listedOwn.contains(object.location.number),
                into: &listing)
        }
        return listing
    }

    /// Files an object of this device's own stream as its own (it numbers the stream, and anchors it if listed), as
    /// shown not to be its own (it moves nothing), or as undecided.
    private func classifyOwn(
        _ object: SignedObject, at location: SyncObjectLocation, listed: Bool, into listing: inout Listing
    ) async {
        do {
            try await keyring.verifyOwn(object.signature, over: object.envelope, at: location)
            listing.ownVerified = max(listing.ownVerified, location.number)
            if listed { listing.ownAnchored = true }
        } catch {
            if !Self.isNotOwn(error) { listing.ownUndecided.append(location.number) }
        }
    }

    // MARK: - Merge

    /// The raw values of the record kinds this engine carries; every other kind is unknown to it (ADR 0009).
    private var carriedRawKinds: Set<UInt8> {
        Set(configuration.schemaVersions.keys.map(\.rawValue))
    }

    private func mergeStaged(
        state: inout SyncState, retired: Set<UUID>, reconciling: Bool, ownHead: UInt64, report: inout SyncReport
    ) async throws {
        var staged = try await syncState.staged(vaultID: vaultID)
        // A staged name no reader lists (the staging area is a local file, A8): dropped, so no number past the bounds
        // reaches the arithmetic below (review finding Z39).
        let outOfRange = staged.filter {
            $0.location.number
                > ($0.location.kind == .segment ? configuration.maximumSequence : configuration.maximumVersion)
        }
        if !outOfRange.isEmpty {
            try await syncState.unstage(outOfRange.map(\.location))
            staged.removeAll {
                $0.location.number
                    > ($0.location.kind == .segment ? configuration.maximumSequence : configuration.maximumVersion)
            }
        }
        // Staged before its author was revoked: dropped unmerged, like anything else that device wrote.
        let fromRetired = staged.filter { retired.contains($0.location.author) }
        if !fromRetired.isEmpty {
            try await syncState.unstage(fromRetired.map(\.location))
            staged.removeAll { retired.contains($0.location.author) }
        }
        // Kept aside by an earlier version that did not know their kind, and readable now (ADR 0009). A vault with a
        // judge replays its whole log instead, so the judge sees every segment that carried them (§8.8); what a
        // revoked device carried, which no replay reads, is processed here in either case.
        let carried = carriedRawKinds
        var ready = stash.entries.filter { carried.contains($0.entry.rawKind) }
        if judge != nil, ready.contains(where: { !retired.contains($0.author) }) {
            report.replayNeeded = true
            ready.removeAll { !retired.contains($0.author) }
        }
        guard !staged.isEmpty || !ready.isEmpty else { return }
        var highWater = try await vaultHighWater(state)
        outOfReach = []
        // A device that holds nothing of the vault has no history to measure a jump against: the snapshots it starts
        // from are its baseline, held to `maximumVersion` alone (review finding Z25). Each is the state of a device
        // of this account that accepted every version in it; without this, a jump every earlier device accepted, or
        // a million honest writes, cut every later device off from all that was written since. Not in a vault with a
        // judge, whose log is whole and replayed from its first segment.
        let takesBaseline = highWater == 0 && judge == nil
        // A deletion made here but not yet published is as much an erasure as a published one: without it, a
        // snapshot or segment written before the deletion would put the record back on this device only.
        let pending = try await syncState.pendingDeletions(vaultID: vaultID)
        if !ready.isEmpty {
            try await processStashed(
                ready, pending: pending, reconciling: reconciling, state: &state, highWater: &highWater,
                report: &report)
        }
        let segments = Dictionary(grouping: staged.filter { $0.location.kind == .segment }, by: \.location.author)
        // What the snapshots cover of a stream, as far as it is believed. Of another device's stream, all of it: its
        // author signed for what it merged. Of this device's own, no further than the stream can have got (`ownHead`):
        // this device's next sequence number follows from it, and a snapshot that claimed 2^48 would otherwise move
        // every later segment of this device to a name no reader lists, for good (review finding Z21). Not from a
        // segment of it merely staged here: the staging area is a local file, and a row planted there at 2^48 would
        // count for as much (review finding Z39). A claim beyond it holds publishing back instead (`ownStreamHold`).
        let ownLimit = ownHead
        func covered(_ author: UUID, _ state: SyncState) -> UInt64 {
            let claimed = state.snapshotCoverage[author] ?? 0
            return author == deviceID ? min(claimed, ownLimit) : claimed
        }

        // A shared vault's judge sees every segment of the pass before it judges anything: which stream first carried
        // a version decides whose work it is, and a write cut binds a run of segments (docs/02-architecture.md §8.8).
        // Before the snapshots too, whose tombstones are judged against the same index: judged first, a device joining
        // believed their claims about members' streams it had not yet recorded (review finding Z34).
        if let judge {
            for object in segments.values.joined().sorted(by: { $0.location.name < $1.location.name }) {
                let payload: SyncPayload
                do {
                    payload = try await open(object)
                } catch SyncKeyringError.unknownKey {
                    // Signed by a device the vault's members list (`open` checks that before it asks for the key)
                    // and sealed under a key this device does not hold. Which object it is and whose keys signed it
                    // need no key, and every device must agree on both: a stream's first segment says whose the
                    // stream is, and a write cut's chain runs over every object of it (review finding Z51).
                    try await judge.recordUnopened(
                        segment: object.location, signature: object.object.signature,
                        envelope: object.object.envelope)
                    continue
                } catch {
                    continue
                }
                guard (try? validate(payload, at: object.location)) != nil else { continue }
                try await judge.record(
                    segment: object.location, signature: object.object.signature,
                    envelope: object.object.envelope, entries: payload.entries)
            }
        }

        // Snapshots first: they bootstrap a new device and fill gaps left by garbage collection.
        let snapshots = staged.filter { $0.location.kind == .snapshot }.sorted {
            Self.snapshotOrder($0.location, $1.location)
        }
        var waitingForNewerVersion: Set<SyncObjectLocation> = []
        for snapshot in snapshots {
            do {
                let payload = try await open(snapshot)
                try validate(payload, at: snapshot.location)
                try await judge?.recordSnapshot(snapshot.location, covering: payload.vector)
                // A snapshot that covers nothing new is counted, and merged all the same: merging is idempotent, and
                // a snapshot can hold what no segment this device accepts does — what its author merged from a
                // device revoked since (§7.8).
                if Self.covers(state.merged, payload.vector) { report.staleSnapshots += 1 }
                let keyID = try EnvelopeHeader.parse(
                    snapshot.object.envelope, expecting: snapshot.location.envelopeKind
                ).header.keyID
                for entry in payload.entries {
                    if entry.isDeletion, let judge,
                        !(try await judge.admitsErasure(entry, in: snapshot.location, sealedUnder: keyID))
                    {
                        // A snapshot's tombstone is its author's claim like a segment's, and is judged like one
                        // (review finding Z21): not admitted, it is kept for the person and erases nothing.
                        report.heldAside.append(entry.key)
                        try await keepAside(entry, state: &state, report: &report)
                        continue
                    }
                    try await apply(
                        entry, pending: pending[entry.key], reconciling: reconciling, exemptFromJump: takesBaseline,
                        state: &state, highWater: &highWater, report: &report)
                }
                keep(payload.unknownEntries, from: snapshot.location, state: &state, report: &report)
                state.snapshots[snapshot.location] = payload.vector
                state.snapshotCoverage.merge(payload.vector, uniquingKeysWith: max)
            } catch let error where Self.isFatal(error) {
                throw error
            } catch {
                report.rejected.append(SyncRejection(name: snapshot.location.name, reason: Self.reason(error)))
                if Self.requiresNewerVersion(error) {
                    // Complete and authentic, and unreadable by this version: kept staged, so the version that can
                    // read it merges it without downloading it again.
                    report.requiresNewerVersion = true
                    waitingForNewerVersion.insert(snapshot.location)
                }
            }
        }
        try await syncState.unstage(snapshots.map(\.location).filter { !waitingForNewerVersion.contains($0) })

        // A stream whose next segment is not here continues from what the snapshots cover: their effects are in
        // the store. One whose next segment is here is merged from its own segments.
        for author in state.snapshotCoverage.keys where covered(author, state) > (state.merged[author] ?? 0) {
            let next = (state.merged[author] ?? 0) + 1
            if !(segments[author] ?? []).contains(where: { $0.location.number == next }) {
                state.merged[author] = covered(author, state)
            }
        }

        for author in segments.keys.sorted(by: { $0.precedes($1) }) {
            var next = (state.merged[author] ?? 0) + 1
            for object in segments[author]!.sorted(by: { $0.location.number < $1.location.number }) {
                let sequence = object.location.number
                if sequence > next, next <= covered(author, state) {
                    // A gap the snapshots cover (the missing segment was collected after they were merged).
                    state.merged[author] = covered(author, state)
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
                var waitsForJudge = false
                do {
                    let payload = try await open(object)
                    try validate(payload, at: object.location)
                    let admission =
                        try await judge?.admitsSegment(
                            object.location, signature: object.object.signature, envelope: object.object.envelope)
                        ?? .apply
                    switch admission {
                    case .apply:
                        break
                    case .wait:
                        // The write cut cannot be checked yet: wait here, as at a gap.
                        report.waiting[author] = next
                        waitsForJudge = true
                    case .holdAside, .passOver:
                        // Kept for the person, never merged, never published on; the stream carries on past it and
                        // its acknowledgements count for nothing (docs/02-architecture.md §8.7). Passed over, nothing
                        // of it is kept either: its signer's work cannot count here (Z137).
                        if admission == .holdAside {
                            for entry in payload.entries {
                                report.heldAside.append(entry.key)
                                try await keepAside(entry, state: &state, report: &report)
                            }
                        }
                        if author == deviceID,
                            (try? await keyring.verifyOwn(
                                object.object.signature, over: object.object.envelope, at: object.location)) == nil
                        {
                            report.ownStreamSteppedOver = min(report.ownStreamSteppedOver ?? .max, sequence)
                        }
                        state.merged[author] = sequence
                        next = sequence + 1
                        try await syncState.saveState(state)
                        try await syncState.unstage([object.location])
                        continue
                    }
                    if waitsForJudge { break }
                    let keyID = try EnvelopeHeader.parse(
                        object.object.envelope, expecting: object.location.envelopeKind
                    ).header.keyID
                    for entry in payload.entries {
                        if entry.isDeletion, let judge,
                            !(try await judge.admitsErasure(entry, in: object.location, sealedUnder: keyID))
                        {
                            // What its author had seen does not all count (review finding S45): kept for the person,
                            // never applied, and judged again by a replay.
                            report.heldAside.append(entry.key)
                            try await keepAside(entry, state: &state, report: &report)
                            continue
                        }
                        try await apply(
                            entry, pending: pending[entry.key], reconciling: reconciling, state: &state,
                            highWater: &highWater, report: &report)
                    }
                    // Kept aside, and the stream goes on: an ignorable kind this version does not know (ADR 0009).
                    keep(payload.unknownEntries, from: object.location, state: &state, report: &report)
                    acknowledgement = payload.vector
                } catch let error where Self.isFatal(error) {
                    throw error
                } catch {
                    if case SyncKeyringError.unknownKey(let keyID) = error, let judge,
                        await judge.passesOverSegment(sealedUnder: keyID, vaultID: vaultID)
                    {
                        // Sealed under a key this account was never entitled to (a shared vault's member who joined
                        // after a rotation): it never opens here, and rotation sealed what it carried again under a
                        // later key.
                        state.merged[author] = sequence
                        next = sequence + 1
                        try await syncState.saveState(state)
                        try await syncState.unstage([object.location])
                        continue
                    }
                    report.rejected.append(SyncRejection(name: object.location.name, reason: Self.reason(error)))
                    let isCovered = sequence <= covered(author, state)
                    if Self.requiresNewerVersion(error), !isCovered {
                        // A critical kind this version does not know (ADR 0009): the stream stops here and skips
                        // nothing. The segment is complete and authentic, so it stays staged for the version that
                        // can read it. (One a merged snapshot covers is passed below, as any refused segment is.)
                        report.requiresNewerVersion = true
                    } else {
                        // Unstaged, so the next sync fetches it again: a partially visible file may since have
                        // completed.
                        try await syncState.unstage([object.location])
                    }
                    if isCovered {
                        // Its effects are in a merged snapshot already: continue past it rather than stall.
                        state.merged[author] = covered(author, state)
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
        try await retryOutOfReach(
            pending: pending, reconciling: reconciling, state: &state, highWater: &highWater, report: &report)
    }

    /// Tries again, lowest version first, what this pass refused as beyond the version-jump ceiling, now that the
    /// rest of the pass is merged (review finding Z25). A log is read one stream after another and a segment in
    /// record-ID order, so a version can be met before the ones written between it and the last this device knew;
    /// measured where the device stood then, it looked like a jump. Each entry was kept in the quarantine when it
    /// was refused, so a lock or a crash before this point loses nothing of it; and the state saved meanwhile says a
    /// retry is owed (`SyncState.retryUnfinished`), so the next sync replays the log to offer it again (review finding
    /// Z33). One that is merged now is taken out of the quarantine again, after the state that records its merge is
    /// saved (a lock in between leaves it kept, never lost, Z39); one still out of reach stays for the person. One
    /// whose merge fails now stays where it is, as it would have in the loops (Z36). Only entries of this pass,
    /// which came from objects whose signatures were just checked: the quarantine itself is a local file and is
    /// never merged from.
    private func retryOutOfReach(
        pending: [RecordKey: PendingDeletion], reconciling: Bool, state: inout SyncState, highWater: inout UInt64,
        report: inout SyncReport
    ) async throws {
        guard !outOfReach.isEmpty else { return }
        let waiting = outOfReach.sorted {
            ($0.version, $0.device.uuidString, $0.recordID.uuidString, $0.kind.rawValue)
                < ($1.version, $1.device.uuidString, $1.recordID.uuidString, $1.kind.rawValue)
        }
        outOfReach = []
        for entry in waiting {
            let (ceiling, overflow) = highWater.addingReportingOverflow(configuration.maximumVersionJump)
            // Ascending: once one is out of reach, so is every one after it.
            guard overflow || entry.version <= ceiling else { break }
            let kept = report.quarantined.count + report.heldAside.count + report.collided.count
            do {
                try await apply(
                    entry, pending: pending[entry.key], reconciling: reconciling, retrying: true, state: &state,
                    highWater: &highWater, report: &report)
            } catch let error where Self.isFatal(error) {
                throw error
            } catch {
                // It does not merge (it does not open, or the merger's result cannot be stored): it stays in the
                // quarantine, and the rest are tried.
                continue
            }
            // No longer refused as a jump: reported as whatever became of it now.
            if let index = report.quarantined.firstIndex(of: entry.key) { report.quarantined.remove(at: index) }
            if report.quarantined.count + report.heldAside.count + report.collided.count < kept {
                try await syncState.saveState(state)
                try await syncState.discardQuarantined([entry], vaultID: vaultID)
                quarantineUsage = nil
            }
        }
        // Owed by an earlier pass whose replay this sync has asked for: it stays owed until that replay has run.
        state.retryUnfinished = retryOwedEarlier
        try await syncState.saveState(state)
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
        // Entries of a kind this version does not know get every check it can make without knowing the kind: their
        // record's schema version is unknown here, so the rest of the context is checked when they are processed.
        for entry in payload.unknownEntries {
            if location.kind == .segment, entry.device != location.author {
                throw Rejection(reason: .entryFromAnotherDevice(entry.recordID))
            }
            guard entry.version > 0 else { throw SyncFormatError.malformedEntry }
            guard let envelope = entry.envelope else { continue }
            // The record's own header must name the kind and key the entry does, so a record of a known kind cannot
            // be filed under an ignorable label and passed over here.
            guard Self.headerNames(entry, envelope: envelope) else {
                throw Rejection(reason: .recordContextMismatch(entry.recordID))
            }
        }
    }

    /// Whether an envelope's header (magic, version, kind, key) is the one its entry names, read without knowing the
    /// kind. In simple steps: one long boolean of mixed operators is a type-checker risk on Swift 6.1.
    static func headerNames(_ entry: UnknownSyncEntry, envelope: [UInt8]) -> Bool {
        guard envelope.count >= EnvelopeHeader.fixedPrefixLength else { return false }
        guard Array(envelope[0..<4]) == EnvelopeHeader.magic else { return false }
        let low = UInt16(envelope[4])
        let high = UInt16(envelope[5]) << 8
        guard low | high == EnvelopeHeader.currentVersion else { return false }
        guard envelope[6] == entry.rawKind else { return false }
        return Array(envelope[7..<23]) == SyncPayload.bytes(entry.keyID)
    }

    /// Keeps entries of ignorable kinds this version does not know (ADR 0009), within the stash's caps, each with the
    /// device whose object carried it. An entry already contained in one held is not kept again: the same entry, or
    /// a lower version by the same writer (from a segment, only one its writer's own stream carried, because a
    /// snapshot may attribute a version to any device). An entry from a segment is its author's own (`validate`), and
    /// a version a device writes contains its earlier ones, so it replaces that device's lower versions of the record
    /// (a deletion only a deletion). Past a cap, overall or for that author, the entry is not kept and the kind is
    /// recorded against the author: the stream still merges, this device writes no ordinary snapshot, and the version
    /// that learns the kind replays the log, which still holds the entry. A lookup per entry, not a scan.
    private func keep(
        _ entries: [UnknownSyncEntry], from location: SyncObjectLocation, state: inout SyncState,
        report: inout SyncReport
    ) {
        guard !entries.isEmpty else { return }
        let author = location.author
        let fromSegment = location.kind == .segment
        let before = stash
        for entry in entries {
            let held = stash.held(in: SyncStash.Slot(entry))
            if held.contains(where: { $0.entry == entry }) { continue }
            // Only the writer's own word, or this carrier's, counts: an entry another carrier attributed to the
            // writer keeps out nothing (an insider's high version would otherwise suppress the genuine one, N15).
            let contained = held.contains { kept in
                kept.entry.version >= entry.version && (kept.isAuthorsOwn || kept.author == author)
            }
            if contained { continue }
            if fromSegment {
                for old in held where old.entry.version < entry.version { stash.remove(old) }
            }
            let used = stash.usage(of: author)
            guard
                used.count < configuration.maximumStashedEntriesPerAuthor,
                used.bytes + entry.length <= configuration.maximumStashedBytesPerAuthor
            else {
                // Its own share is full: held against it.
                stash.overflow[author, default: []].insert(entry.rawKind)
                report.unknownEntriesDropped += 1
                continue
            }
            guard
                stash.count < configuration.maximumStashedEntries,
                stash.bytes + entry.length <= configuration.maximumStashedBytes
            else {
                // The vault's stash is full of what others carried: held against nobody (N17).
                stash.crowdedOut.insert(entry.rawKind)
                report.unknownEntriesDropped += 1
                continue
            }
            stash.insert(SyncStash.Kept(entry: entry, author: author))
            report.unknownEntriesKept += 1
        }
        // Saved with the state that counts this object as merged, so a crash before the stash is saved is noticed.
        if stash != before { state.stashUnsaved = true }
    }

    /// Processes kept entries whose kind this version carries, as if they had just arrived: every context check, then
    /// the merger, in ascending version order, so the U5 ceiling climbs through them as it would have for a device
    /// that read them on arrival. One that does not check or merge is kept for the person in the quarantine (PRD F7.7)
    /// rather than stopping a stream that has long moved on. Only ignorable kinds are ever kept aside; an entry of a
    /// critical kind here was planted in the file (A8) and is dropped unread.
    private func processStashed(
        _ ready: [SyncStash.Kept], pending: [RecordKey: PendingDeletion], reconciling: Bool,
        state: inout SyncState, highWater: inout UInt64, report: inout SyncReport
    ) async throws {
        let order = ready.sorted {
            ($0.entry.version, $0.entry.device.uuidString, $0.entry.recordID.uuidString, $0.entry.rawKind)
                < ($1.entry.version, $1.entry.device.uuidString, $1.entry.recordID.uuidString, $1.entry.rawKind)
        }
        state.stashUnsaved = true
        for kept in order {
            let stashed = kept.entry
            guard EnvelopeKind.criticality(ofRawValue: stashed.rawKind) == .ignorable,
                let kind = EnvelopeKind(rawValue: stashed.rawKind), let schema = configuration.schemaVersions[kind]
            else {
                stash.remove(kept)
                continue
            }
            let entry = stashed.known(as: kind)
            if entry.isDeletion, judge != nil {
                // A shared vault judges a tombstone by the segment that carried it (`admitsErasure`, S45), and a kept
                // one has no segment left to judge it by: processed here, it is a revoked device's (its other kept
                // entries wait for the replay). Held aside, as one not admitted would be: the record stays.
                report.heldAside.append(entry.key)
                try await keepAside(entry, state: &state, report: &report)
                stash.remove(kept)
                report.unknownEntriesProcessed += 1
                continue
            }
            do {
                if let envelope = entry.envelope {
                    let context = EnvelopeContext(
                        recordID: entry.recordID, vaultID: vaultID, schemaVersion: schema, kind: kind,
                        keyID: entry.keyID, recordVersion: entry.version)
                    do {
                        _ = try Envelope.parse(
                            envelope, expecting: context, maximumLength: SyncPayload.maximumEntryEnvelopeLength)
                    } catch {
                        throw Rejection(reason: .recordContextMismatch(entry.recordID))
                    }
                }
                try await apply(
                    entry, pending: pending[entry.key], reconciling: reconciling, state: &state,
                    highWater: &highWater, report: &report)
            } catch let error where Self.isFatal(error) {
                throw error
            } catch {
                report.quarantined.append(entry.key)
                try await keepAside(entry, state: &state, report: &report)
            }
            // Taken out only once it is applied or quarantined: a lock part-way leaves the rest kept.
            stash.remove(kept)
            report.unknownEntriesProcessed += 1
        }
        try await syncState.saveState(state)
    }

    private func apply(
        _ entry: SyncEntry, pending: PendingDeletion?, reconciling: Bool, exemptFromJump: Bool = false,
        retrying: Bool = false, state: inout SyncState, highWater: inout UInt64, report: inout SyncReport
    ) async throws {
        let (ceiling, overflow) = highWater.addingReportingOverflow(configuration.maximumVersionJump)
        guard entry.version <= configuration.maximumVersion, exemptFromJump || overflow || entry.version <= ceiling
        else {
            // Not merged, but kept: only the person may discard it (PRD F7.7). One refused only as a jump is tried
            // once more when the pass has merged everything else (`retryOutOfReach`).
            report.quarantined.append(entry.key)
            try await keepAside(entry, state: &state, report: &report)
            if entry.version <= configuration.maximumVersion, !retrying {
                outOfReach.append(entry)
                // Saved with every state from here until the retry has run, so a lock before then is noticed.
                state.retryUnfinished = true
            }
            return
        }
        // Every erasure of the record this device knows of, taken together: the ones it merged, and its own if it
        // has one that is not published yet.
        var erasure = state.erasures[entry.key]
        if let pending {
            erasure = try await join(
                erasure, Erasure(stamp: pending.stamp, summary: try await summary(of: pending.record)),
                kind: entry.kind)
        }
        // An erasure this device already holds — the same one again in a later snapshot, or one that adds nothing to
        // what it knows — has had its say about the local version: it erased it, or it was kept. Applied a second
        // time it would put back in the trash an item the person has since restored. Only a reconciling sync judges
        // again, because it does not trust the local file.
        var alreadyJudged = false
        if entry.isDeletion, !reconciling, let known = state.erasures[entry.key], known.stamp >= entry.stamp {
            let joined = try await join(
                known, Erasure(stamp: entry.stamp, summary: entry.erasure), kind: entry.kind)
            alreadyJudged = joined.summary == known.summary
        }
        var attempt = 0
        while !alreadyJudged {
            do {
                if try await applyOnce(entry, erasure: erasure) { report.applied += 1 }
                break
            } catch RecordStoreError.versionConflict where attempt < 4 {
                // The session wrote the same record while the merger ran: merge against the new local version.
                attempt += 1
            } catch ItemMergeError.resultNotSealable {
                // The two versions are each valid and their join does not fit in one record (review finding Y37):
                // the local version stays, the remote one is kept for the person (PRD F7.7), and the stream goes on
                // to the entries and segments after it instead of waiting here for good.
                report.quarantined.append(entry.key)
                try await keepAside(entry, state: &state, report: &report)
                return
            } catch is RecordElsewhere {
                // Another vault's record holds this ID on this device (review finding Z22). Whoever got the ID into
                // the store first must not decide which vault's stream stops: this entry alone is kept for the
                // person, the other vault's row stays as it is, and the object and the stream go on.
                report.collided.append(entry.key)
                try await keepAside(entry, state: &state, report: &report)
                return
            } catch is HeldAside {
                // Carries work that does not count in this shared vault (docs/02-architecture.md §8.7): kept for the
                // person, never merged, never published on.
                report.heldAside.append(entry.key)
                try await keepAside(entry, state: &state, report: &report)
                return
            }
        }
        // The ceiling moves only for what merged (review finding Z140): raised before the merge was tried, each entry
        // that then failed lifted it a step, so a chain of them one ceiling apart carried a version past U5.
        highWater = max(highWater, entry.version)
        state.known[entry.key] = max(state.known[entry.key] ?? entry.stamp, entry.stamp)
        if entry.isDeletion {
            state.erasures[entry.key] = try await join(
                state.erasures[entry.key], Erasure(stamp: entry.stamp, summary: entry.erasure), kind: entry.kind)
        }
        if entry.device == deviceID, try await isHeldAsPublished(entry, pending: pending, state: state) {
            state.published[entry.key] = max(state.published[entry.key] ?? entry.stamp, entry.stamp)
        }
    }

    /// Whether a version found in the log under this device's name is one it need not publish: exactly the row it
    /// holds, or a deletion that is its own (pending, or already published at that stamp). The log is believed about
    /// what this device *published* only that far (review findings Z29, Z35): an entry naming this device at a stamp
    /// above its row, whose content the row already contains, changes nothing in the store, and marking its stamp as
    /// published would pass over a row that holds an edit nobody else has, and every later edit below the stamp. A
    /// row that differs is published again, which costs a segment and merges to nothing. A deletion where no row is
    /// held is no exception (Z138): a record's ID can be predicted (a move's copy), and a planted tombstone for it,
    /// counted as published, passed over the record's first version when this device wrote it, and a later genuine
    /// deletion of it as already sent. One of this device's own that a replay meets again is not marked, and costs
    /// nothing, there being no row to publish.
    private func isHeldAsPublished(_ entry: SyncEntry, pending: PendingDeletion?, state: SyncState) async throws
        -> Bool
    {
        if entry.isDeletion {
            if let pending, pending.stamp == entry.stamp { return true }
            return state.published[entry.key] == entry.stamp
        }
        guard let row = try await store.record(entry.key) else { return false }
        return row.vaultID == vaultID && row.version == entry.version && row.deviceID == entry.device
            && row.keyID == entry.keyID && row.envelope == entry.envelope
    }

    /// Returns whether the local store changed. `erasure` is the latest erasure of the record known here, published
    /// or not.
    private func applyOnce(_ entry: SyncEntry, erasure: Erasure?) async throws -> Bool {
        let key = entry.key
        let local = try await store.record(key)
        if let local, local.vaultID != vaultID { throw RecordElsewhere() }

        if let remote = entry.record(in: vaultID), let judge, !(try await judge.admits(remote)) {
            throw HeldAside()
        }
        guard let remote = entry.record(in: vaultID) else {
            // An erasure removes the local version only if its author had seen all of it; an edit it never saw is
            // kept, in the trash (PRD F7.6).
            guard let local else { return false }
            // Judged against this erasure together with every other one known: which of two erasures of a record a
            // device learns of first must not decide what it keeps.
            let erasure = try await join(
                erasure, Erasure(stamp: entry.stamp, summary: entry.erasure), kind: entry.kind)
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
        } catch ItemMergeError.resultNotSealable(let id) {
            throw ItemMergeError.resultNotSealable(id)
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

    /// Keeps an entry aside for the person (PRD F7.7), within the quarantine's caps (review finding Z27): for the
    /// vault, and for the versions any one device wrote, so that one writer cannot crowd the rest out. An entry
    /// already held is found by an indexed lookup, never by reading the quarantine. Past a cap the entry is not kept
    /// here and the report counts it; nothing else about the object changes.
    private func keepAside(_ entry: SyncEntry, state: inout SyncState, report: inout SyncReport) async throws {
        var usage: QuarantineUsage
        if let known = quarantineUsage {
            usage = known
        } else {
            usage = try await syncState.quarantineUsage(vaultID: vaultID)
        }
        quarantineUsage = usage
        guard fits(entry.storedLength, in: usage, for: entry.device) else {
            if !(try await syncState.holdsQuarantined(entry, vaultID: vaultID)) {
                report.quarantineFull += 1
                // Remembered, signed with the state: this device withholds its snapshots, and replays the log once
                // there is room (review finding Z38).
                state.quarantineDropped.insert(entry.device)
            }
            return
        }
        if try await syncState.quarantine(entry, vaultID: vaultID) {
            usage.add(entry)
            quarantineUsage = usage
        } else if !(try await syncState.holdsQuarantined(entry, vaultID: vaultID)) {
            // Neither kept nor held: the store would not keep it (the SQLite store's lookup digest is not keyed, and
            // entries crafted to share it crowd it, Z39). A drop like one past a cap, counted and, where this device
            // writes snapshots, remembered (review finding Z141). In a shared vault, which writes none and replays
            // its whole log at every change of head, remembering it would replay at every sync while the crowding
            // stands, for nothing a replay can bring back.
            report.quarantineFull += 1
            if configuration.maintainsLog {
                state.quarantineDropped.insert(entry.device)
                state.quarantineCrowded = max(state.quarantineCrowded ?? 0, UInt64(usage.entries))
            }
        }
    }

    /// Whether `length` more bytes of `device`'s versions fit the quarantine's caps. Counted without overflow: the
    /// sizes come from a local file (A8), and a sum near `Int.max` must read as full, never trap (review finding
    /// Z39).
    private func fits(_ length: Int, in usage: QuarantineUsage, for device: UUID) -> Bool {
        let share = usage.devices[device] ?? QuarantineUsage.Share()
        let (total, totalOverflow) = usage.bytes.addingReportingOverflow(length)
        let (own, ownOverflow) = share.bytes.addingReportingOverflow(length)
        return usage.entries < configuration.maximumQuarantinedEntries
            && !totalOverflow && total <= configuration.maximumQuarantinedBytes
            && share.entries < configuration.maximumQuarantinedEntriesPerAuthor
            && !ownOverflow && own <= configuration.maximumQuarantinedBytesPerAuthor
    }

    /// Whether the quarantine has room again for a version of `device`'s that was not kept (Z38), of the largest size
    /// an entry can be: a replay for less would drop it again, at every sync.
    private func hasRoom(_ usage: QuarantineUsage, for device: UUID) -> Bool {
        fits(SyncPayload.maximumEntryEnvelopeLength + SyncPayload.maximumErasureLength, in: usage, for: device)
    }

    private func resolve(_ erasure: Erasure, of record: StoredRecord) async throws -> ErasureDecision {
        do {
            // The stamp alone, not the version in question: the same for every device that knows the same erasures.
            return try await merger.resolveErasure(erasure.summary, of: record, above: erasure.stamp.version)
        } catch let error where Self.isFatal(error) {
            throw error
        } catch {
            throw Rejection(reason: .mergeFailed(record.recordID))
        }
    }

    /// Two erasures of one record as one: the later stamp, and everything either author had seen.
    private func join(_ known: Erasure?, _ other: Erasure, kind: EnvelopeKind) async throws -> Erasure {
        guard let known else { return other }
        guard known.summary != other.summary else {
            return Erasure(stamp: max(known.stamp, other.stamp), summary: known.summary)
        }
        do {
            return Erasure(
                stamp: max(known.stamp, other.stamp),
                summary: try await merger.joinErasureSummaries(known.summary, other.summary, kind: kind))
        } catch let error where Self.isFatal(error) {
            throw error
        } catch {
            // Undecidable: the one with the later stamp, as before either was joined. Nothing is erased on a guess.
            return known.stamp < other.stamp ? other : known
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

    private func push(
        state: inout SyncState, retired: Set<UUID>, deferringDeletions: Bool, report: inout SyncReport
    ) async throws {
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
            if try await isPublished(deletion, key: key, state: state) {
                obsolete[key] = deletion.stamp
                continue
            }
            if deferringDeletions {
                // Neither the deletion nor a version written after it: that one must follow the deletion.
                entries.removeValue(forKey: key)
                report.deletionsDeferred += 1
                continue
            }
            if let row = entries.removeValue(forKey: key) { later.append(row) }
            entries[key] = .tombstone(key, stamp: deletion.stamp, erasure: try await summary(of: deletion.record))
        }
        // Another device collects its segments once every device acknowledges them and a snapshot covers them; tell
        // it when this device has merged further into that covered range than it last said.
        let needsAcknowledgement = state.merged.contains { author, merged in
            author != deviceID && !retired.contains(author)
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
            guard sequence <= configuration.maximumSequence else {
                // No reader lists a name beyond this: published there, these rows would be marked as sent and never
                // seen (review finding Z21). Nothing is written and nothing marked.
                report.ownStreamExhausted = true
                return
            }
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
                    state.erasures[entry.key] = try await join(
                        state.erasures[entry.key], Erasure(stamp: entry.stamp, summary: entry.erasure),
                        kind: entry.kind)
                }
            }
            state.publishedAcknowledgement = vector
            try await judge?.record(segment: location, signature: signature, envelope: envelope, entries: chunk)
            report.segmentsWritten += 1
            report.pushedEntries += chunk.count
            try await syncState.saveState(state)
            try await syncState.removePendingDeletions(published, vaultID: vaultID)
        }
        try await syncState.removePendingDeletions(obsolete, vaultID: vaultID)
    }

    /// Whether a pending deletion is on the transport already: this device published a deletion of the record at or
    /// after its stamp, and the erasures it knows of hold everything this one had seen. Another device's erasure of
    /// the same record, however late its stamp, is not this one: its author may have seen less (W13). Nor is this
    /// device's own earlier erasure, when the person deletes a version that erasure had kept: a kept version keeps
    /// its own number, so the second deletion's stamp can be the lower of the two (W18). Both found by the vault
    /// simulation.
    private func isPublished(_ deletion: PendingDeletion, key: RecordKey, state: SyncState) async throws -> Bool {
        guard let published = state.published[key], published.deleted, published >= deletion.stamp,
            let known = state.erasures[key]
        else { return false }
        let joined = try await join(
            known, Erasure(stamp: deletion.stamp, summary: try await summary(of: deletion.record)), kind: key.kind)
        return joined.summary == known.summary
    }

    /// A row that came back while its deletion was being made — merged from another device between the session's
    /// read and its delete — is settled the way the deletion will settle it on every other device, so this device does
    /// not keep a record everyone else erases.
    private func settlePendingDeletions(state: SyncState) async throws {
        for (key, deletion) in try await syncState.pendingDeletions(vaultID: vaultID) {
            if try await isPublished(deletion, key: key, state: state) { continue }
            guard let row = try await store.record(key), row.vaultID == vaultID else { continue }
            let erasure = try await join(
                state.erasures[key], Erasure(stamp: deletion.stamp, summary: try await summary(of: deletion.record)),
                kind: key.kind)
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
    private func maintain(
        state: inout SyncState, listing: Listing, retired: Set<UUID>, report: inout SyncReport
    ) async throws {
        try await writeSnapshotIfElected(state: &state, retired: retired, report: &report)
        try await collectGarbage(state: &state, listing: listing, retired: retired, report: &report)
    }

    /// Whether this device holds something merged from a revoked device that no snapshot by a trusted device is known
    /// to carry: segments past what such snapshots cover, or a snapshot the revoked device wrote. Every other device
    /// refuses that device's objects from now on, so this one must hand on what it merged in good faith, in a
    /// snapshot of its own; otherwise devices that had not merged it yet would never converge with this one, and an
    /// edit made on the lost device before it was revoked could exist here alone (PRD F7.7).
    private func holdsUnsharedRetiredContent(_ state: SyncState, retired: Set<UUID>) -> Bool {
        guard !retired.isEmpty else { return false }
        if state.snapshots.keys.contains(where: { retired.contains($0.author) }) { return true }
        let trusted = state.snapshots.filter { !retired.contains($0.key.author) }.values
        return retired.contains { device in
            let merged = state.merged[device] ?? 0
            return merged > (trusted.map { $0[device] ?? 0 }.max() ?? 0)
        }
    }

    private func writeSnapshotIfElected(
        state: inout SyncState, retired: Set<UUID>, report: inout SyncReport
    ) async throws {
        let owed = holdsUnsharedRetiredContent(state, retired: retired)
        if !owed {
            let uncovered = state.merged.reduce(0) { total, element in
                total + Int(clamping: element.value &- min(element.value, state.snapshotCoverage[element.key] ?? 0))
            }
            guard uncovered >= max(configuration.snapshotThreshold, 2 * state.merged.count) else { return }
            // The lowest device ID among those that wrote since the last snapshot (§7.1); the others wait for it,
            // unless it has fallen so far behind (it may be offline for good) that any device steps in. A revoked
            // device is never waited for. Two snapshots at once are harmless: each has its own name.
            let active = state.merged.filter {
                !retired.contains($0.key) && $0.value > (state.snapshotCoverage[$0.key] ?? 0)
            }.keys
            guard
                active.min(by: { $0.precedes($1) }) == deviceID || uncovered >= 4 * configuration.snapshotThreshold
            else { return }
        }
        // A device holding entries it cannot read, carried by a device still trusted, writes no ordinary snapshot
        // (ADR 0009): its snapshot would cover their segments without carrying them, and once those segments were
        // collected, a device that reads the kind and has not merged them yet would never see them. Ordinary
        // snapshots come only from devices that read everything they merged, so whatever covers a segment carries
        // what it said; the others step in at four times the threshold. The one it owes for a revoked device's work
        // (§7.8) it still writes, covering only revoked devices' streams, which nobody collects or reads: it hands
        // that work on and makes nothing collectable.
        var vector = state.merged
        let holding = stash.authorsHoldingBackSnapshots(retired: retired)
        // The same holds for a version this device kept aside instead of merging (an implausible jump, a join that
        // does not fit in one record, a record ID another vault holds): its segment counts as merged, so an ordinary
        // snapshot would cover it without carrying it, and once the segment was collected a device joining later
        // would never be shown that version (review finding Z26). While the quarantine holds a version written by a
        // device still trusted, this device writes only the snapshot it owes.
        var usage: QuarantineUsage
        if let known = quarantineUsage {
            usage = known
        } else {
            usage = try await syncState.quarantineUsage(vaultID: vaultID)
        }
        quarantineUsage = usage
        // A version that was to be kept and found no room (Z38) is as uncarried as one kept.
        let keptAside =
            usage.devices.keys.contains { !retired.contains($0) }
            || state.quarantineDropped.contains { !retired.contains($0) }
        if !holding.isEmpty || !stash.crowdedOut.isEmpty || stashIncomplete || keptAside {
            guard owed else {
                report.snapshotWithheld = true
                report.snapshotWithheldBy = holding
                report.snapshotWithheldForQuarantine = keptAside
                return
            }
            vector = state.merged.filter { retired.contains($0.key) }
        }

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
        var lamport = max(entries.map(\.version).max() ?? 0, 1)
        // A snapshot this device owes must be written even if it already wrote one at this Lamport time (nothing
        // newer has been stored since): the next free number is as good a name.
        for _ in 0..<(owed ? 16 : 1) {
            guard lamport <= configuration.maximumVersion else { return }
            let location = SyncObjectLocation.snapshot(vaultID: vaultID, author: deviceID, lamport: lamport)
            let payload = SyncPayload(
                kind: .snapshot, vaultID: vaultID, author: deviceID, number: lamport, vector: vector, entries: entries
            ).encoded()
            guard payload.count < Envelope.maximumLength - 4096 else { return }
            let envelope = try await keyring.seal(payload, at: location)
            let signature = try await keyring.sign(envelope, at: location)
            do {
                try await transport.create(
                    location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())
            } catch SyncTransportError.objectExists {
                lamport += 1
                continue
            }
            state.snapshots[location] = vector
            state.snapshotCoverage.merge(vector, uniquingKeysWith: max)
            // Handed on: what this device merged from revoked devices is now in a snapshot of its own.
            state.snapshots = state.snapshots.filter { !retired.contains($0.key.author) }
            report.snapshotsWritten += 1
            return
        }
    }

    /// Deletes this device's own segments that every other known device has acknowledged merging and that some
    /// listed snapshot covers (so a device joining later gets their effects from it), always keeping the newest, so the
    /// stream's position and acknowledgement stay visible. Also deletes this device's own snapshots that another listed
    /// snapshot covers entirely. A device joining merges every listed snapshot, so it never depends on which one is
    /// "newest".
    private func collectGarbage(
        state: inout SyncState, listing: Listing, retired: Set<UUID>, report: inout SyncReport
    ) async throws {
        let listed = Set(listing.snapshots)
        // A revoked device's snapshots are not listed (they are not read); what this device merged from one is
        // remembered until it has written the snapshot that hands it on.
        state.snapshots = state.snapshots.filter { listed.contains($0.key) || retired.contains($0.key.author) }
        let covered = listed.reduce(UInt64(0)) { highest, location in
            max(highest, state.snapshots[location]?[deviceID] ?? 0)
        }
        // A revoked device's acknowledgement never comes, and is not waited for (review finding Y6).
        let others = state.merged.keys.filter { $0 != deviceID && !retired.contains($0) }
        let acknowledged = others.map { state.acknowledgements[$0]?[deviceID] ?? 0 }.min() ?? covered
        let limit = min(covered, acknowledged)
        // Lowest first: while any segment of this stream is listed, none above it has been collected, which is what
        // lets a device whose state is older than its stream publish without reusing a number (`Listing.ownAnchored`,
        // review finding Z31). A failed delete stops the loop, so a gap can never open below a listed segment; and so
        // does a number missing from the listing (a provider's listing that left it out, or a store withholding it):
        // deleting past it would leave it listed with higher numbers gone (review finding Z135). The newest kept is
        // this device's own genuine head (what it published, or what verified as its own) or the highest listed number
        // below it, never a listed name above it: anyone who can create a file can list one far ahead, and keeping
        // that in place of the head deleted the anchor.
        // The run starts above what this device has collected already (review finding Z149): a name planted below it,
        // in the range already collected, was otherwise the run's start, deleted alone at each pass, and the gap above
        // it stopped the run there for as long as the name was planted again.
        let own = (listing.segments[deviceID] ?? []).filter { $0 > state.collectedThrough }.sorted()
        let newest = min(own.last ?? 0, max(state.lastPublishedSequence, listing.ownVerified))
        var expected = own.first
        for sequence in own {
            guard sequence == expected, sequence <= limit, sequence < newest else { break }
            try await transport.delete(
                SyncObjectLocation.segment(vaultID: vaultID, author: deviceID, sequence: sequence).name)
            report.collected += 1
            state.collectedThrough = max(state.collectedThrough, sequence)
            expected = sequence + 1
        }
        for (location, coverage) in state.snapshots where location.author == deviceID {
            let superseded = state.snapshots.contains { other, otherCoverage in
                other != location && !retired.contains(other.author) && Self.covers(otherCoverage, coverage)
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

    /// A version the judge did not admit.
    struct HeldAside: Error {}

    /// An entry whose record ID a record of another vault holds on this device.
    struct RecordElsewhere: Error {}

    /// Errors that stop the sync rather than reject one object: the vault locked, the transport went away, or the
    /// local store failed.
    static func isFatal(_ error: any Error) -> Bool {
        switch error {
        case SyncKeyringError.locked: return true
        case let error as SyncTransportError: return error.stopsSync
        case is any StorageFailure: return true
        default: return false
        }
    }

    /// Whether an object was refused only because it carries a critical record kind this version does not know.
    static func requiresNewerVersion(_ error: any Error) -> Bool {
        if case SyncFormatError.unsupportedRecordKind = error { return true }
        return false
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
