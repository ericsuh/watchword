import Foundation
import SecureMemory
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordHygiene
import WatchwordModel
import WatchwordStore
import WatchwordSync

/// The record a vault's synced breach-check results are kept in (`SyncedScanRecord`, kind `scanStatus`).
public enum ScanStatusCodec {
    public static let schemaVersion: UInt64 = 1
    public static let maximumPayloadLength = SyncedScanRecord.maximumEncodedLength
}

// Synced breach-check results (owner decision 10; ADR 0005, amendment of 2026-11-16; docs/02-architecture.md §13.9).
//
// After every check this device completes, it writes its observation (when, and per password whether it was found)
// into the item's `scanStatus` record, sealed under the vault key beside the item: never an item version, so no
// history entry and no conflict. The sync engine carries it like any record, merged by `ScanStatusMerger`, a join.
// Reading goes the other way: the session matches each record's observations against the item's current passwords
// (`SyncedScanEvidence.matching`, under binding keys derived from the vault keys the observations name) and hands the
// engine what other devices reported. The engine decides what that is worth: a remote "not found" postpones this
// device's own check, within caps, and a remote "found" is shown and remembered in this device's own sealed ledger.
extension VaultSession {
    static func scanStatusContext(_ row: StoredRecord) -> EnvelopeContext {
        EnvelopeContext(
            recordID: row.recordID, vaultID: row.vaultID, schemaVersion: ScanStatusCodec.schemaVersion,
            kind: .scanStatus, keyID: row.keyID, recordVersion: row.version)
    }

    /// Opens an item's synced scan results. As for items, the context comes from the row, and what the plaintext says
    /// of itself (item, vault, version) must equal the row: a record moved to another item or vault, or replayed at
    /// another version, does not open.
    func openScanStatus(_ row: StoredRecord, keys: UnlockedKeys) throws -> SyncedScanRecord {
        guard row.kind == .scanStatus, let vaultKey = keys.vaultKeys[row.keyID], vaultKey.vaultID == row.vaultID else {
            throw VaultError.unknownVault(row.vaultID)
        }
        let plaintext = try RecordCipher.open(
            row.envelope, context: Self.scanStatusContext(row), key: vaultKey.key,
            maximumLength: ScanStatusCodec.maximumPayloadLength + 4096)
        defer { plaintext.zeroise() }
        // Keyed digests and counts, sealed: not key material.
        let record: SyncedScanRecord
        do {
            record = try SyncedScanRecord(decoding: plaintext.unprotectedCopy())
        } catch {
            throw ItemCodecError.malformedPayload
        }
        guard record.itemID == row.recordID, record.vaultID == row.vaultID, record.version == row.version else {
            throw VaultError.recordMismatch(row.recordID)
        }
        highestVersionSeen[row.vaultID] = max(highestVersionSeen[row.vaultID] ?? 0, row.version)
        return record
    }

    func sealScanStatus(_ record: SyncedScanRecord, vaultKey: VaultKey, account: AccountRecord) throws -> StoredRecord {
        var encoded = try record.encoded()
        let plaintext = SecureBytes(wiping: &encoded)
        defer { plaintext.zeroise() }
        var row = StoredRecord(
            recordID: record.itemID, kind: .scanStatus, vaultID: record.vaultID, keyID: vaultKey.key.keyID,
            version: record.version, deviceID: account.deviceID, envelope: [])
        row.envelope = try RecordCipher.seal(
            plaintext, context: Self.scanStatusContext(row), key: vaultKey.key, using: &random)
        highestVersionSeen[record.vaultID] = max(highestVersionSeen[record.vaultID] ?? 0, record.version)
        return row
    }

    /// What other devices reported about `item`'s current passwords, from its scan-status row: each observation's
    /// bindings compared with those of the passwords the item holds, under the binding key of the vault key the
    /// observation names (only a key this device holds for the item's own vault). This device's own observations are
    /// not read back: its own results are in its sealed ledger, out of any other writer's reach. An empty evidence if
    /// there is no row or it does not open, so the engine drops what it had.
    func scanEvidence(for item: Item, row: StoredRecord?, keys: UnlockedKeys, deviceID: UUID) -> SyncedScanEvidence {
        let empty = SyncedScanEvidence(itemID: item.id, itemVersion: item.version, fields: [:])
        guard let row, row.recordID == item.id, row.vaultID == item.vaultID,
            let record = try? openScanStatus(row, keys: keys)
        else { return empty }
        var bindingKeys: [UUID: ScanBindingKey] = [:]
        defer { for key in bindingKeys.values { key.zeroise() } }
        return SyncedScanEvidence.matching(record, item: item, ownDevice: deviceID) { keyID in
            if let key = bindingKeys[keyID] { return key }
            guard let vaultKey = keys.vaultKeys[keyID], vaultKey.vaultID == item.vaultID,
                let key = try? ScanBindingKey(HygieneKeys.scanBindingKey(vaultKey: vaultKey))
            else { return nil }
            bindingKeys[keyID] = key
            return key
        }
    }

    /// The item's scan-status row, if it has one in the item's own vault.
    func scanStatusRow(for item: Item) async throws -> StoredRecord? {
        let row = try await store.record(RecordKey(recordID: item.id, kind: .scanStatus))
        return row?.vaultID == item.vaultID ? row : nil
    }

    /// After a check of `item` this device completed: writes this device's observation into the item's scan-status
    /// record, so that the vault's other devices need not repeat it (owner decision 10). Only with sync configured,
    /// only where this device may write (a read-only member of a shared vault writes nothing; nor does a deleted vault),
    /// only for the version the ledger's entry is for, and only while still unlocked. Bindings are under the vault's
    /// current key. A failure is not an error: the result stays in this device's ledger, and the next check writes
    /// again.
    func publishScanObservation(of item: Item, since epoch: UInt64) async {
        guard syncSettings != nil, let engine = hygieneRuntime?.engine,
            let entry = try? await engine.ledger().entries[item.id], entry.itemVersion == item.version,
            epoch == lockEpoch, let account = try? await loadAccount()
        else { return }
        do {
            let existing = try await scanStatusRow(for: item)
            let keys = try requireKeys(since: epoch)
            let vaultKey = try await writableVaultKey(item.vaultID, keys: keys, account: account)
            let current = try requireKeys(since: epoch)
            var record =
                existing.flatMap { try? openScanStatus($0, keys: current) }
                ?? SyncedScanRecord(itemID: item.id, vaultID: item.vaultID, version: 0)
            let revision = try nextRevision(in: item.vaultID, above: existing, account: account)
            let bindingKey = try ScanBindingKey(HygieneKeys.scanBindingKey(vaultKey: vaultKey))
            defer { bindingKey.zeroise() }
            var results: [ScanBinding: UInt32] = [:]
            for field in ItemAnalyzer.passwordFields(of: item) {
                guard let result = entry.results[field.id] else { return }
                var occurrences: UInt32 = 0
                if case .found(let count) = result { occurrences = max(1, count) }
                let binding = bindingKey.binding(item: item.id, utf8Of: field.value)
                results[binding] = max(results[binding] ?? 0, occurrences)
            }
            guard !results.isEmpty else { return }
            record.record(
                SyncedScanRecord.Observation(
                    device: account.deviceID, revision: revision.version, keyID: vaultKey.key.keyID,
                    scannedAt: entry.scannedAt, results: results))
            record.version = revision.version
            let row = try sealScanStatus(record, vaultKey: vaultKey, account: account)
            var change = StoreChange(upserts: [row])
            change.expectations[row.key] = existing.map { .version($0.version) } ?? .absent
            try await writer(for: account).commit(change)
            if epoch == lockEpoch, let known = hygieneRuntime?.known[item.id] {
                hygieneRuntime?.known[item.id]?.scanVersion = known.version == item.version ? row.version : nil
            }
        } catch {
            return
        }
    }

    /// The scan-status rows beside the items `ids`, which go when they do: results about an item that is gone are
    /// about nothing, and left behind they would only accumulate.
    func scanStatusKeys(of ids: [UUID]) async throws -> [RecordKey] {
        var keys: [RecordKey] = []
        for id in ids {
            let key = RecordKey(recordID: id, kind: .scanStatus)
            if try await store.record(key) != nil { keys.append(key) }
        }
        return keys
    }

    // MARK: - Keyring (called by `VaultSyncAdapter`)

    func syncOpenScanStatus(_ row: StoredRecord) throws -> SyncedScanRecord {
        guard let keys, account != nil else { throw SyncKeyringError.locked }
        return try openScanStatus(row, keys: keys)
    }

    func syncSealScanStatus(_ record: SyncedScanRecord) throws -> StoredRecord {
        guard let keys, let account else { throw SyncKeyringError.locked }
        guard let vaultKey = currentVaultKey(record.vaultID, keys: keys, account: account) else {
            throw SyncKeyringError.unknownKey(record.vaultID)
        }
        return try sealScanStatus(record, vaultKey: vaultKey, account: account)
    }
}

extension VaultSyncAdapter {
    func openScanStatus(_ row: StoredRecord) async throws -> SyncedScanRecord {
        try await session.syncOpenScanStatus(row)
    }

    func sealScanStatus(_ record: SyncedScanRecord) async throws -> StoredRecord {
        try await session.syncSealScanStatus(record)
    }
}

/// The merger for an item's synced scan results: `SyncedScanRecord.joined`, a join, so every device that has merged
/// the same observations holds the same state (docs/02-architecture.md §13.9). As for items, a result that is neither
/// side is written by this device above both, and the observations in it keep their own devices and revisions.
///
/// A deletion of the record (it goes with its item) erases every observation its author can have seen, those at or
/// below the tombstone's stamp, and keeps any written after it, so an item kept after a deletion and checked again
/// keeps its results. Nothing here is the person's data: erasing results costs a check, never anything they wrote.
struct ScanStatusMerger: RecordMerger {
    let sealer: VaultSyncAdapter

    func merge(local: StoredRecord, remote: StoredRecord) async throws -> MergeDecision {
        let incoming = try await sealer.openScanStatus(remote)
        guard remote.recordID == local.recordID, remote.vaultID == local.vaultID else {
            throw ItemMergeError.identityMismatch(remote.recordID)
        }
        let current: SyncedScanRecord
        do {
            current = try await sealer.openScanStatus(local)
        } catch SyncKeyringError.locked {
            throw SyncKeyringError.locked
        } catch {
            // A local row that does not open is damage, not a version: the remote one replaces it.
            if remote.version > local.version { return .adoptRemote }
            var copy = incoming
            copy.version = try Self.version(above: local.version)
            return .replace(try await sealer.sealScanStatus(copy))
        }
        let joined = current.joined(incoming)
        if joined.sameState(incoming), remote.version > local.version { return .adoptRemote }
        if joined.sameState(current) { return .keepLocal }
        var result = joined
        result.version = try Self.version(above: max(local.version, remote.version))
        return .replace(try await sealer.sealScanStatus(result))
    }

    func erasureSummary(of record: StoredRecord) async throws -> [UInt8] {
        []
    }

    func resolveErasure(_ summary: [UInt8], of record: StoredRecord, above version: UInt64) async throws
        -> ErasureDecision
    {
        let current = try await sealer.openScanStatus(record)
        guard let kept = current.settled(afterErasureAt: version) else { return .erase }
        if kept.sameState(current) { return .keep }
        var result = kept
        result.version = try Self.version(above: max(record.version, version))
        return .replace(try await sealer.sealScanStatus(result))
    }

    func joinErasureSummaries(_ first: [UInt8], _ second: [UInt8], kind: EnvelopeKind) async throws -> [UInt8] {
        []
    }

    static func version(above version: UInt64) throws -> UInt64 {
        let (next, overflow) = version.addingReportingOverflow(1)
        guard !overflow else { throw ItemMergeError.versionOverflow }
        return next
    }
}
