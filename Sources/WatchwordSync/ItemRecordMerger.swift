import Foundation
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore

/// What `ItemRecordMerger` needs from whoever holds the vault key: open an item row, checking the decrypted item's
/// identity against the row, and seal an item as a row written by this device.
///
/// Production: `VaultSession`'s sync adapter, over `RecordCipher` and the vault key (milestone 3's Mac half). Tests:
/// `WatchwordTestSupport.FakeSyncKeyring`. Both throw `SyncKeyringError.locked` when no key is resident.
public protocol ItemSealer: Sendable {
    func openItem(_ row: StoredRecord) async throws -> Item
    func sealItem(_ item: Item) async throws -> StoredRecord
}

/// Why `ItemRecordMerger` refused to merge. The engine reports any of them as a rejected object and keeps the local
/// version.
public enum ItemMergeError: Error, Equatable, Sendable {
    /// The two rows did not open to versions of one item in one vault. A sealer checks each item against its row;
    /// this is the merger's own check, so that a sealer which does not cannot make the merge trap.
    case identityMismatch(UUID)
    /// No version above the ones given exists.
    case versionOverflow
    /// Both versions opened, but what merging them gives could not be sealed: in practice it is over the payload
    /// limit (SEC9), which the join of two versions that each fit can be. Nothing is wrong with either version, so
    /// this is not a reason to distrust the object that carried the remote one (docs/10-sync-correctness.md §8, Y37).
    case resultNotSealable(UUID)
    /// The join of two erasure summaries is longer than a tombstone may carry (`SyncPayload.maximumErasureLength`).
    case summaryTooLarge(Int)
}

/// The `RecordMerger` for item records: open both versions, `ItemMerge.merge`, seal the result through
/// `ItemMerge.written` (docs/02-architecture.md §7.5, PRD F7.4, F7.6).
///
/// One implementation for production and tests, so the merger the app runs is the one the N-client simulation and the
/// nightly long runs exercise; only the sealing behind `ItemSealer` differs.
public struct ItemRecordMerger: RecordMerger {
    public let sealer: any ItemSealer
    /// The device the merger writes as: merge results and kept-after-deletion versions are new versions by it.
    public let deviceID: UUID

    public init(sealer: any ItemSealer, deviceID: UUID) {
        self.sealer = sealer
        self.deviceID = deviceID
    }

    public func merge(local: StoredRecord, remote: StoredRecord) async throws -> MergeDecision {
        let remoteItem = try await sealer.openItem(remote)
        guard remoteItem.id == remote.recordID, remoteItem.vaultID == remote.vaultID,
            remote.recordID == local.recordID, remote.vaultID == local.vaultID
        else { throw ItemMergeError.identityMismatch(remote.recordID) }
        let localItem: Item
        do {
            localItem = try await sealer.openItem(local)
        } catch SyncKeyringError.locked {
            throw SyncKeyringError.locked
        } catch {
            // A local row that does not open is damage, not a version: the remote one replaces it.
            if remote.version > local.version { return .adoptRemote }
            let item = ItemMerge.written(remoteItem, as: try Self.revision(above: local.version, by: deviceID))
            return .replace(try await sealer.sealItem(item))
        }
        guard localItem.id == local.recordID, localItem.vaultID == local.vaultID else {
            throw ItemMergeError.identityMismatch(local.recordID)
        }
        let merged = ItemMerge.merge(
            localItem, origin: Self.origin(local), remoteItem, origin: Self.origin(remote))
        // Compared with the items as stored, not as the merge reads them: a version that is not in the form the merge
        // writes (older metadata, or crafted) is replaced by one that is, so every device ends up storing the same.
        if ItemMerge.sameState(merged, remoteItem), remote.version > local.version { return .adoptRemote }
        if ItemMerge.sameState(merged, localItem) { return .keepLocal }
        let item = ItemMerge.written(
            merged, as: try Self.revision(above: max(local.version, remote.version), by: deviceID))
        return .replace(try await seal(item))
    }

    /// Seals what a merge or a settlement produced. A failure that is not the vault locking is reported as
    /// `resultNotSealable`, so that a caller can tell "these two versions do not fit in one record" from "this
    /// record is not to be trusted".
    private func seal(_ item: Item) async throws -> StoredRecord {
        do {
            return try await sealer.sealItem(item)
        } catch SyncKeyringError.locked {
            throw SyncKeyringError.locked
        } catch {
            throw ItemMergeError.resultNotSealable(item.id)
        }
    }

    /// What this device had seen of the item when it erased it, and the row it erased (`ItemErasure`).
    ///
    /// At most `SyncPayload.maximumErasureLength` bytes, as the port requires: every reader refuses a segment whose
    /// tombstone carries more, and a refused segment stops its author's whole stream. An item's clock is a writer's
    /// claim and can name thousands of devices (it cannot be truncated: docs/10-sync-correctness.md §6), so a
    /// summary that would not fit says instead that this device had seen *nothing* (review finding Y36). That erases
    /// nothing anywhere else: every other device keeps its version, in the trash, marked as kept after a deletion —
    /// the direction that loses no data.
    public func erasureSummary(of record: StoredRecord) async throws -> [UInt8] {
        let item = try await sealer.openItem(record)
        let seen = ItemMerge.effectiveClock(item, origin: Self.origin(record))
        let summary = try ItemErasure(seen: seen, row: record.version, device: deviceID, date: item.modifiedAt)
            .summary()
        guard summary.count > SyncPayload.maximumErasureLength else { return summary }
        return try ItemErasure(seen: VersionVector(), row: record.version, device: deviceID, date: item.modifiedAt)
            .summary()
    }

    /// Settles a version of an erased record against every erasure of it the engine knows (`summary`, the join of
    /// their summaries), through `ItemMerge.settle`. `tombstone` is the latest stamp among them, which the engine
    /// knows and a summary does not say (review finding Y28): an erasure whose summary names a later row has seen
    /// nothing, and a version kept is written above both the tombstone and the record — never at a version taken
    /// from a summary. What is kept is a function of the item and the erasures alone, so every device that keeps a
    /// version stores the same item; only the version it writes it down at, which is its own, differs.
    public func resolveErasure(_ summary: [UInt8], of record: StoredRecord, above tombstone: UInt64) async throws
        -> ErasureDecision
    {
        let item = try await sealer.openItem(record)
        guard item.id == record.recordID, item.vaultID == record.vaultID else {
            throw ItemMergeError.identityMismatch(record.recordID)
        }
        let erasures = ItemErasures(summary: summary).believed(atOrBelow: tombstone)
        switch ItemMerge.settle(item, origin: Self.origin(record), against: erasures) {
        case .erase:
            return .erase
        case .keep:
            return .keep
        case .kept(let kept):
            let revision = try Self.revision(above: max(record.version, tombstone), by: deviceID)
            return .replace(try await seal(ItemMerge.written(kept, as: revision)))
        }
    }

    /// Every erasure either summary holds (`ItemErasures`): set union, in one canonical encoding. A summary that does
    /// not decode is a deletion that had seen nothing. Throws when the join would not fit in a tombstone
    /// (`SyncPayload.maximumErasureLength`), since a snapshot carries it and every reader would refuse that snapshot;
    /// the engine then keeps the erasure with the later stamp, which erases no more than the join would.
    public func joinErasureSummaries(_ first: [UInt8], _ second: [UInt8], kind: EnvelopeKind) async throws -> [UInt8] {
        let joined = try ItemErasures(summary: first).joined(ItemErasures(summary: second)).summary()
        guard joined.count <= SyncPayload.maximumErasureLength else {
            throw ItemMergeError.summaryTooLarge(joined.count)
        }
        return joined
    }

    static func revision(above version: UInt64, by device: UUID) throws -> Revision {
        let (next, overflow) = version.addingReportingOverflow(1)
        guard !overflow else { throw ItemMergeError.versionOverflow }
        return Revision(version: next, device: device)
    }

    static func origin(_ record: StoredRecord) -> Revision {
        Revision(version: record.version, device: record.deviceID)
    }
}
