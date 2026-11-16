import Foundation
import WatchwordEnvelope
import WatchwordStore

/// `SyncState` as JSON. Dictionary keys are UUID strings and record keys are spelled out, so the encoding does not
/// depend on how Foundation encodes a dictionary with non-string keys. Portable (only `SQLiteSyncStateStore` uses it,
/// on Apple platforms), so its round trip is tested on Linux too.
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

    /// An entry of a kind the writing version did not know (ADR 0009), byte for byte.
    struct Unknown: Codable {
        var record: UUID
        var kind: UInt8
        var key: UUID
        var version: UInt64
        var device: UUID
        var envelope: Data?
        var erasure: Data
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
    /// Absent in a row written before ADR 0009: nothing kept, nothing dropped.
    var stashed: [Unknown]?
    var stashOverflow: [UInt8]?

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
        stashed = state.stashed.map {
            Unknown(
                record: $0.recordID, kind: $0.rawKind, key: $0.keyID, version: $0.version, device: $0.device,
                envelope: $0.envelope.map { Data($0) }, erasure: Data($0.erasure))
        }.sorted {
            ($0.record.uuidString, $0.kind, $0.device.uuidString, $0.version, $0.envelope == nil ? 1 : 0)
                < ($1.record.uuidString, $1.kind, $1.device.uuidString, $1.version, $1.envelope == nil ? 1 : 0)
        }
        stashOverflow = state.stashOverflow.sorted()
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
        for entry in stashed ?? [] {
            // Only what `init(_:)` writes: a deletion names no key and carries no envelope.
            guard entry.envelope != nil || entry.key == SyncPayload.zeroUUID, entry.envelope?.isEmpty != true
            else { return nil }
            state.stashed.insert(
                UnknownSyncEntry(
                    recordID: entry.record, rawKind: entry.kind, keyID: entry.key, version: entry.version,
                    device: entry.device, envelope: entry.envelope.map { Array($0) }, erasure: Array(entry.erasure)))
        }
        state.stashOverflow = Set(stashOverflow ?? [])
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
