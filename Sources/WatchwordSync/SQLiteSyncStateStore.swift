#if canImport(SQLite3)
    import Foundation
    import SecureMemory
    import WatchwordEnvelope
    import WatchwordStore

    /// The persistent `SyncStateStore`: a database of its own beside the record store in the App Group container
    /// (docs/02-architecture.md §6), opened with the same hardening (`SQLiteConnection`, no symlinks, `STRICT`
    /// tables, an exact schema check).
    ///
    /// Nothing here is secret, and the file is as untrusted as the record store (A8). A state row that does not decode
    /// is treated as absent, which makes the next sync a full replay from the signed log; staged objects that do not
    /// parse are skipped, and every staged object is verified again before it is merged. Pending deletions and the
    /// quarantine cannot be rebuilt from the log, so a malformed row of either is reported as `malformedRow`, never
    /// dropped.
    ///
    /// A separate file rather than tables in the record store keeps `WatchwordStore` ignorant of sync. Nothing needs
    /// both in one transaction: tombstones are recorded after the deletion commits (`DeletionRecordingStore`) and the
    /// engine's state can always be rebuilt with a reconciling sync.
    public final class SQLiteSyncStateStore: SyncStateStore {
        public static let schemaVersion = 1
        public static let databaseName = "sync.sqlite"

        private let connection: SQLiteConnection

        public init(url: URL) throws {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let directory = URL(
                fileURLWithPath: try SQLiteRecordStore.resolvingSymlinks(url.deletingLastPathComponent().path),
                isDirectory: true)
            let url = directory.appendingPathComponent(url.lastPathComponent, isDirectory: false)
            connection = try SQLiteConnection(path: url.path)
            try migrate()
            #if os(iOS) || os(watchOS) || os(visionOS)
                let protection: [FileAttributeKey: Any] = [
                    .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication
                ]
                for suffix in ["", "-wal", "-shm"] where FileManager.default.fileExists(atPath: url.path + suffix) {
                    try FileManager.default.setAttributes(protection, ofItemAtPath: url.path + suffix)
                }
            #endif
        }

        // MARK: - Schema

        static let stateTable = """
            CREATE TABLE sync_state (
                vault_id BLOB PRIMARY KEY CHECK (length(vault_id) = 16),
                state BLOB NOT NULL
            ) STRICT
            """
        static let stagedTable = """
            CREATE TABLE staged (
                vault_id BLOB NOT NULL CHECK (length(vault_id) = 16),
                name TEXT NOT NULL,
                object BLOB NOT NULL,
                PRIMARY KEY (vault_id, name)
            ) STRICT
            """
        static let pendingTable = """
            CREATE TABLE pending_deletions (
                vault_id BLOB NOT NULL CHECK (length(vault_id) = 16),
                record_id BLOB NOT NULL CHECK (length(record_id) = 16),
                kind INTEGER NOT NULL,
                stamp_version INTEGER NOT NULL,
                stamp_device BLOB NOT NULL CHECK (length(stamp_device) = 16),
                key_id BLOB NOT NULL CHECK (length(key_id) = 16),
                version INTEGER NOT NULL,
                device_id BLOB NOT NULL CHECK (length(device_id) = 16),
                envelope BLOB NOT NULL,
                PRIMARY KEY (vault_id, record_id, kind)
            ) STRICT
            """
        static let quarantineTable = """
            CREATE TABLE quarantine (
                vault_id BLOB NOT NULL CHECK (length(vault_id) = 16),
                record_id BLOB NOT NULL CHECK (length(record_id) = 16),
                kind INTEGER NOT NULL,
                key_id BLOB NOT NULL CHECK (length(key_id) = 16),
                version INTEGER NOT NULL,
                device_id BLOB NOT NULL CHECK (length(device_id) = 16),
                envelope BLOB,
                erasure BLOB NOT NULL
            ) STRICT
            """

        static let expectedSchema: Set<[SQLiteValue]> = [
            [.text("table"), .text("sync_state"), .text("sync_state"), .text(stateTable)],
            [.text("index"), .text("sqlite_autoindex_sync_state_1"), .text("sync_state"), .null],
            [.text("table"), .text("staged"), .text("staged"), .text(stagedTable)],
            [.text("index"), .text("sqlite_autoindex_staged_1"), .text("staged"), .null],
            [.text("table"), .text("pending_deletions"), .text("pending_deletions"), .text(pendingTable)],
            [.text("index"), .text("sqlite_autoindex_pending_deletions_1"), .text("pending_deletions"), .null],
            [.text("table"), .text("quarantine"), .text("quarantine"), .text(quarantineTable)],
        ]

        private func migrate() throws {
            try connection.transaction {
                guard case .integer(let version) = try connection.query("PRAGMA user_version").first?.first else {
                    throw RecordStoreError.malformedRow("user_version")
                }
                guard version >= 0, version <= Self.schemaVersion else {
                    throw RecordStoreError.unsupportedSchemaVersion(Int(version))
                }
                if version < 1 {
                    for table in [Self.stateTable, Self.stagedTable, Self.pendingTable, Self.quarantineTable] {
                        try connection.execute(table)
                    }
                    try connection.execute("PRAGMA user_version = 1")
                }
                // As in `SQLiteRecordStore`: a planted trigger could make deletions or state saves silently do nothing
                // (review finding S1), so anything but exactly this schema is refused.
                let rows = try connection.query("SELECT type, name, tbl_name, sql FROM sqlite_schema")
                for row in rows where !Self.expectedSchema.contains(row) {
                    if row.count > 1, case .text(let name) = row[1] { throw RecordStoreError.unexpectedSchema(name) }
                    throw RecordStoreError.unexpectedSchema("?")
                }
                guard rows.count == Self.expectedSchema.count else {
                    throw RecordStoreError.unexpectedSchema("missing")
                }
            }
        }

        // MARK: - State

        public func loadState(vaultID: UUID) throws -> SyncState? {
            let rows = try connection.query(
                "SELECT state FROM sync_state WHERE vault_id = ?", [SQLiteRecordStore.value(vaultID)])
            guard let row = rows.first, row.count == 1, case .blob(let bytes) = row[0] else { return nil }
            // Rebuildable from the log: a row that does not decode, or names another vault, is no state at all.
            guard let decoded = try? JSONDecoder().decode(EncodedState.self, from: Data(bytes)),
                let state = decoded.state, state.vaultID == vaultID
            else { return nil }
            return state
        }

        public func saveState(_ state: SyncState) throws {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let bytes = Array(try encoder.encode(EncodedState(state)))
            try connection.query(
                "INSERT OR REPLACE INTO sync_state (vault_id, state) VALUES (?, ?)",
                [SQLiteRecordStore.value(state.vaultID), .blob(bytes)])
        }

        // MARK: - Staged downloads

        public func stage(_ object: StagedObject) throws {
            try connection.query(
                "INSERT OR REPLACE INTO staged (vault_id, name, object) VALUES (?, ?, ?)",
                [
                    SQLiteRecordStore.value(object.location.vaultID), .text(object.location.name),
                    .blob(object.object.serialized()),
                ])
        }

        public func staged(vaultID: UUID) throws -> [StagedObject] {
            let rows = try connection.query(
                "SELECT name, object FROM staged WHERE vault_id = ? ORDER BY name", [SQLiteRecordStore.value(vaultID)])
            return rows.compactMap { row in
                guard row.count == 2, case .text(let name) = row[0], case .blob(let bytes) = row[1],
                    let location = SyncObjectLocation(name: name), location.vaultID == vaultID,
                    let object = try? SignedObject.parse(bytes)
                else { return nil }
                return StagedObject(location: location, object: object)
            }
        }

        public func unstage(_ locations: [SyncObjectLocation]) throws {
            try connection.transaction {
                for location in locations {
                    try connection.query(
                        "DELETE FROM staged WHERE vault_id = ? AND name = ?",
                        [SQLiteRecordStore.value(location.vaultID), .text(location.name)])
                }
            }
        }

        // MARK: - Pending deletions

        public func addPendingDeletion(_ deletion: PendingDeletion) throws {
            let record = deletion.record
            try connection.transaction {
                if let existing = try pendingDeletions(vaultID: record.vaultID)[record.key],
                    existing.stamp >= deletion.stamp
                {
                    return
                }
                try connection.query(
                    """
                    INSERT OR REPLACE INTO pending_deletions (vault_id, record_id, kind, stamp_version, stamp_device,
                        key_id, version, device_id, envelope)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        SQLiteRecordStore.value(record.vaultID), SQLiteRecordStore.value(record.recordID),
                        .integer(Int64(record.kind.rawValue)), .integer(Int64(bitPattern: deletion.stamp.version)),
                        SQLiteRecordStore.value(deletion.stamp.device), SQLiteRecordStore.value(record.keyID),
                        .integer(Int64(bitPattern: record.version)), SQLiteRecordStore.value(record.deviceID),
                        .blob(record.envelope),
                    ])
            }
        }

        public func pendingDeletions(vaultID: UUID) throws -> [RecordKey: PendingDeletion] {
            let rows = try connection.query(
                """
                SELECT record_id, kind, stamp_version, stamp_device, key_id, version, device_id, envelope
                FROM pending_deletions WHERE vault_id = ?
                """,
                [SQLiteRecordStore.value(vaultID)])
            var result: [RecordKey: PendingDeletion] = [:]
            for row in rows {
                guard row.count == 8 else { throw RecordStoreError.malformedRow("pending_deletions") }
                let record = StoredRecord(
                    recordID: try Self.uuid(row[0]), kind: try Self.kind(row[1]), vaultID: vaultID,
                    keyID: try Self.uuid(row[4]), version: try Self.version(row[5]), deviceID: try Self.uuid(row[6]),
                    envelope: try Self.blob(row[7]))
                result[record.key] = PendingDeletion(
                    stamp: RecordStamp(version: try Self.version(row[2]), device: try Self.uuid(row[3]), deleted: true),
                    record: record)
            }
            return result
        }

        public func removePendingDeletions(_ deletions: [RecordKey: RecordStamp], vaultID: UUID) throws {
            try connection.transaction {
                for (key, stamp) in deletions {
                    try connection.query(
                        """
                        DELETE FROM pending_deletions
                        WHERE vault_id = ? AND record_id = ? AND kind = ? AND stamp_version = ? AND stamp_device = ?
                        """,
                        [
                            SQLiteRecordStore.value(vaultID), SQLiteRecordStore.value(key.recordID),
                            .integer(Int64(key.kind.rawValue)), .integer(Int64(bitPattern: stamp.version)),
                            SQLiteRecordStore.value(stamp.device),
                        ])
                }
            }
        }

        // MARK: - Quarantine

        public func quarantine(_ entry: SyncEntry, vaultID: UUID) throws {
            try connection.transaction {
                guard try !quarantined(vaultID: vaultID).contains(entry) else { return }
                try connection.query(
                    """
                    INSERT INTO quarantine (vault_id, record_id, kind, key_id, version, device_id, envelope, erasure)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [SQLiteRecordStore.value(vaultID)] + Self.columns(entry))
            }
        }

        public func quarantined(vaultID: UUID) throws -> [SyncEntry] {
            try connection.query(
                """
                SELECT record_id, kind, key_id, version, device_id, envelope, erasure
                FROM quarantine WHERE vault_id = ? ORDER BY rowid
                """,
                [SQLiteRecordStore.value(vaultID)]
            ).map { row in
                guard row.count == 7 else { throw RecordStoreError.malformedRow("quarantine") }
                var envelope: [UInt8]?
                if case .blob(let bytes) = row[5] { envelope = bytes }
                return SyncEntry(
                    recordID: try Self.uuid(row[0]), kind: try Self.kind(row[1]), keyID: try Self.uuid(row[2]),
                    version: try Self.version(row[3]), device: try Self.uuid(row[4]), envelope: envelope,
                    erasure: try Self.blob(row[6]))
            }
        }

        public func discardQuarantined(_ entries: [SyncEntry], vaultID: UUID) throws {
            try connection.transaction {
                for entry in entries {
                    // `IS` rather than `=`, so a deletion's NULL envelope matches itself.
                    try connection.query(
                        """
                        DELETE FROM quarantine
                        WHERE vault_id = ? AND record_id = ? AND kind = ? AND key_id = ? AND version = ?
                            AND device_id = ? AND envelope IS ? AND erasure = ?
                        """,
                        [SQLiteRecordStore.value(vaultID)] + Self.columns(entry))
                }
            }
        }

        // MARK: - Erasure

        public func eraseAll() throws {
            try connection.transaction {
                try connection.execute(
                    "DELETE FROM sync_state; DELETE FROM staged; DELETE FROM pending_deletions; DELETE FROM quarantine;"
                )
            }
            // As in `SQLiteRecordStore.eraseAll`: the superseded pages must leave the write-ahead log too.
            try connection.execute("VACUUM")
            let result = try connection.query("PRAGMA wal_checkpoint(TRUNCATE)")
            guard result.first?.first == .integer(0) else { throw RecordStoreError.checkpointIncomplete }
        }

        // MARK: - Columns

        private static func columns(_ entry: SyncEntry) -> [SQLiteValue] {
            [
                SQLiteRecordStore.value(entry.recordID), .integer(Int64(entry.kind.rawValue)),
                SQLiteRecordStore.value(entry.keyID), .integer(Int64(bitPattern: entry.version)),
                SQLiteRecordStore.value(entry.device), entry.envelope.map(SQLiteValue.blob) ?? .null,
                .blob(entry.erasure),
            ]
        }

        private static func uuid(_ value: SQLiteValue) throws -> UUID {
            guard case .blob(let bytes) = value, bytes.count == 16 else { throw RecordStoreError.malformedRow("uuid") }
            return UUID(
                uuid: (
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
                    bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
                ))
        }

        private static func kind(_ value: SQLiteValue) throws -> EnvelopeKind {
            guard case .integer(let raw) = value, let byte = UInt8(exactly: raw),
                let kind = EnvelopeKind(rawValue: byte)
            else { throw RecordStoreError.malformedRow("kind") }
            return kind
        }

        private static func version(_ value: SQLiteValue) throws -> UInt64 {
            guard case .integer(let raw) = value else { throw RecordStoreError.malformedRow("integer") }
            return UInt64(bitPattern: raw)
        }

        private static func blob(_ value: SQLiteValue) throws -> [UInt8] {
            guard case .blob(let bytes) = value else { throw RecordStoreError.malformedRow("blob") }
            return bytes
        }
    }

    /// `SyncState` as JSON. Dictionary keys are UUID strings and record keys are spelled out, so the encoding does not
    /// depend on how Foundation encodes a dictionary with non-string keys.
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
#endif
