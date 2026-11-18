import Foundation
import WatchwordEnvelope
import WatchwordStore

/// `SyncState` as JSON. Dictionary keys are UUID strings and record keys are spelled out, so the encoding does not
/// depend on how Foundation encodes a dictionary with non-string keys. Portable (only `SQLiteSyncStateStore` uses it,
/// on Apple platforms), so its round trip is tested on Linux too. The stash is not here: it has a row of its own
/// (`SyncStash`), so the state saved with every merged segment stays small.
struct EncodedState: Codable {
    struct Stamp: Codable {
        var record: UUID
        var kind: UInt8
        var version: UInt64
        var device: UUID
        var deleted: Bool
    }

    struct ErasureEntry: Codable {
        var stamp: Stamp
        var summary: Data
    }

    struct Snapshot: Codable {
        var name: String
        var coverage: [String: UInt64]
    }

    var vaultID: UUID
    var nextSequence: UInt64
    var lastPublishedSequence: UInt64
    var merged: [String: UInt64]
    var known: [Stamp]
    var erasures: [ErasureEntry]
    var published: [Stamp]
    var acknowledgements: [String: [String: UInt64]]
    var publishedAcknowledgement: [String: UInt64]
    var snapshots: [Snapshot]
    var snapshotCoverage: [String: UInt64]
    /// Absent in a row written before ADR 0009.
    var stashUnsaved: Bool?
    var stashGeneration: UInt64?
    /// Absent in a row written before conflict copies were examined (§7.5).
    var examinedCopies: [String: Int]?
    var handOnOwed: Bool?
    /// Absent in a row written before unread copies were put last (R17).
    var unreadCopies: [String: Int]?
    /// Absent in a row written before a reset could be answered (§7.10).
    var collectedThrough: UInt64?
    var handedOn: Snapshot?
    var storeResetSuspected: Bool?
    var highestOwnSnapshot: UInt64?

    init(_ state: SyncState) {
        func stamps(_ map: [RecordKey: RecordStamp]) -> [Stamp] {
            map.map { Stamp(key: $0.key, stamp: $0.value) }.sorted {
                ($0.record.uuidString, $0.kind) < ($1.record.uuidString, $1.kind)
            }
        }
        vaultID = state.vaultID
        nextSequence = state.nextSequence
        lastPublishedSequence = state.lastPublishedSequence
        merged = Self.strings(state.merged)
        known = stamps(state.known)
        erasures = state.erasures.map {
            ErasureEntry(stamp: Stamp(key: $0.key, stamp: $0.value.stamp), summary: Data($0.value.summary))
        }.sorted { ($0.stamp.record.uuidString, $0.stamp.kind) < ($1.stamp.record.uuidString, $1.stamp.kind) }
        published = stamps(state.published)
        acknowledgements = Dictionary(
            uniqueKeysWithValues: state.acknowledgements.map { ($0.key.uuidString, Self.strings($0.value)) })
        publishedAcknowledgement = Self.strings(state.publishedAcknowledgement)
        snapshots = state.snapshots.map { Snapshot(name: $0.key.name, coverage: Self.strings($0.value)) }
            .sorted { $0.name < $1.name }
        snapshotCoverage = Self.strings(state.snapshotCoverage)
        stashUnsaved = state.stashUnsaved
        stashGeneration = state.stashGeneration
        examinedCopies = Dictionary(uniqueKeysWithValues: state.examinedCopies.map { ($0.key.name, $0.value) })
        handOnOwed = state.handOnOwed
        unreadCopies =
            state.unreadCopies.isEmpty
            ? nil : Dictionary(uniqueKeysWithValues: state.unreadCopies.map { ($0.key.name, $0.value) })
        collectedThrough = state.collectedThrough
        handedOn = state.handedOn.map { Snapshot(name: $0.snapshot.name, coverage: Self.strings($0.holding)) }
        storeResetSuspected = state.storeResetSuspected
        highestOwnSnapshot = state.highestOwnSnapshot
    }

    /// The state, or `nil` if anything in it is not what `init(_:)` writes.
    var state: SyncState? {
        var state = SyncState(vaultID: vaultID)
        state.nextSequence = nextSequence
        state.lastPublishedSequence = lastPublishedSequence
        guard let merged = Self.uuids(merged), let snapshotCoverage = Self.uuids(snapshotCoverage),
            let publishedAcknowledgement = Self.uuids(publishedAcknowledgement)
        else { return nil }
        state.merged = merged
        state.snapshotCoverage = snapshotCoverage
        state.publishedAcknowledgement = publishedAcknowledgement
        for (key, value) in acknowledgements {
            guard let id = UUID(uuidString: key), let vector = Self.uuids(value) else { return nil }
            state.acknowledgements[id] = vector
        }
        for stamp in known {
            guard let (key, value) = stamp.decoded else { return nil }
            state.known[key] = value
        }
        for stamp in published {
            guard let (key, value) = stamp.decoded else { return nil }
            state.published[key] = value
        }
        for erasure in erasures {
            guard let (key, value) = erasure.stamp.decoded else { return nil }
            state.erasures[key] = Erasure(stamp: value, summary: Array(erasure.summary))
        }
        for snapshot in snapshots {
            guard let location = SyncObjectLocation(name: snapshot.name), location.kind == .snapshot,
                let coverage = Self.uuids(snapshot.coverage)
            else { return nil }
            state.snapshots[location] = coverage
        }
        state.stashUnsaved = stashUnsaved ?? false
        state.stashGeneration = stashGeneration ?? 0
        for (name, count) in examinedCopies ?? [:] {
            guard let location = SyncObjectLocation(name: name), count >= 0 else { return nil }
            state.examinedCopies[location] = count
        }
        state.handOnOwed = handOnOwed ?? false
        for (name, count) in unreadCopies ?? [:] {
            guard let location = SyncObjectLocation(name: name), count >= 0 else { return nil }
            state.unreadCopies[location] = count
        }
        state.collectedThrough = collectedThrough
        if let handedOn {
            guard let location = SyncObjectLocation(name: handedOn.name), location.kind == .snapshot,
                let holding = Self.uuids(handedOn.coverage)
            else { return nil }
            state.handedOn = HandedOn(snapshot: location, holding: holding)
        }
        state.storeResetSuspected = storeResetSuspected ?? false
        state.highestOwnSnapshot = highestOwnSnapshot ?? 0
        return state
    }

    static func strings(_ vector: [UUID: UInt64]) -> [String: UInt64] {
        Dictionary(uniqueKeysWithValues: vector.map { ($0.key.uuidString, $0.value) })
    }

    static func uuids(_ vector: [String: UInt64]) -> [UUID: UInt64]? {
        var result: [UUID: UInt64] = [:]
        for (key, value) in vector {
            guard let id = UUID(uuidString: key) else { return nil }
            result[id] = value
        }
        return result
    }
}

extension EncodedState.Stamp {
    init(key: RecordKey, stamp: RecordStamp) {
        self.init(
            record: key.recordID, kind: key.kind.rawValue, version: stamp.version, device: stamp.device,
            deleted: stamp.deleted)
    }

    var decoded: (RecordKey, RecordStamp)? {
        guard let kind = EnvelopeKind(rawValue: kind) else { return nil }
        return (
            RecordKey(recordID: record, kind: kind), RecordStamp(version: version, device: device, deleted: deleted)
        )
    }
}
