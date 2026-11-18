import Foundation
import WatchwordModel
import WatchwordStore

/// What the session signs to make a vault's `SyncState` its own (`SyncState.authenticator`, review finding Z20).
///
/// The state row is rebuilt from the log when it is lost, but it is not merely a cache: `erasures` become the
/// tombstones of this device's next snapshot, `merged` its coverage vector and every segment's acknowledgements, and
/// `published` decides which rows are never sent again. Each of those is signed and believed by every other device,
/// and the file the row lives in is one an attacker can edit (A8). So the whole row is authenticated, as the stash and
/// the pending deletions beside it are, and a row that does not verify is no state at all: the log is replayed.
extension SyncState {
    /// Every field of the state but the authenticator, in one fixed encoding: fields in declaration order, each map
    /// with its count and its entries sorted by key bytes, integers big-endian, byte strings with their length. It is
    /// only ever compared with itself on one device, so it carries no version; a change of encoding costs each vault
    /// one replay.
    public var authenticatedBytes: [UInt8] {
        var writer = StateWriter()
        writer.append(vaultID)
        writer.append(nextSequence)
        writer.append(lastPublishedSequence)
        writer.append(vector: merged)
        writer.append(stamps: known)
        writer.append(UInt64(erasures.count))
        for (key, erasure) in erasures.sorted(by: { Self.precedes($0.key, $1.key) }) {
            writer.append(key)
            writer.append(erasure.stamp)
            writer.append(bytes: erasure.summary)
        }
        writer.append(stamps: published)
        writer.append(UInt64(acknowledgements.count))
        for (device, vector) in acknowledgements.sorted(by: { $0.key.precedes($1.key) }) {
            writer.append(device)
            writer.append(vector: vector)
        }
        writer.append(vector: publishedAcknowledgement)
        writer.append(UInt64(snapshots.count))
        for (location, coverage) in snapshots.sorted(by: { $0.key.name < $1.key.name }) {
            writer.append(location.name)
            writer.append(vector: coverage)
        }
        writer.append(vector: snapshotCoverage)
        writer.append(stashUnsaved)
        writer.append(stashGeneration)
        // Fields added after the state was first signed (review findings Z33, Z38), written only when one is set, so
        // a row saved before them still verifies; their length tells the two forms apart.
        if retryUnfinished || !quarantineDropped.isEmpty {
            writer.append(retryUnfinished)
            writer.append(UInt64(quarantineDropped.count))
            for device in quarantineDropped.sorted(by: { $0.precedes($1) }) { writer.append(device) }
        }
        return writer.bytes
    }

    static func precedes(_ a: RecordKey, _ b: RecordKey) -> Bool {
        if a.recordID != b.recordID { return a.recordID.precedes(b.recordID) }
        return a.kind.rawValue < b.kind.rawValue
    }
}

/// The writer for `SyncState.authenticatedBytes`: fixed-width integers and length-prefixed byte strings, so the
/// encoding is injective.
struct StateWriter {
    private(set) var bytes: [UInt8] = []

    mutating func append(_ value: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) { bytes.append(UInt8(truncatingIfNeeded: value >> shift)) }
    }

    mutating func append(_ value: Bool) {
        bytes.append(value ? 1 : 0)
    }

    mutating func append(_ value: UUID) {
        bytes.append(contentsOf: value.byteArray)
    }

    mutating func append(bytes value: [UInt8]) {
        append(UInt64(value.count))
        bytes.append(contentsOf: value)
    }

    mutating func append(_ value: String) {
        append(bytes: Array(value.utf8))
    }

    mutating func append(vector: [UUID: UInt64]) {
        append(UInt64(vector.count))
        for (device, count) in vector.sorted(by: { $0.key.precedes($1.key) }) {
            append(device)
            append(count)
        }
    }

    mutating func append(_ key: RecordKey) {
        append(key.recordID)
        bytes.append(key.kind.rawValue)
    }

    mutating func append(_ stamp: RecordStamp) {
        append(stamp.version)
        append(stamp.device)
        append(stamp.deleted)
    }

    mutating func append(stamps: [RecordKey: RecordStamp]) {
        append(UInt64(stamps.count))
        for (key, stamp) in stamps.sorted(by: { SyncState.precedes($0.key, $1.key) }) {
            append(key)
            append(stamp)
        }
    }
}
