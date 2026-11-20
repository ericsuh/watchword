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
    /// dropped. A well-formed pending deletion is still not trusted: each carries the authenticator the session made
    /// (`PendingDeletion.authenticator`), and `VaultSession` ignores any that does not verify, so a row planted here
    /// cannot become a tombstone.
    ///
    /// The quarantine is found by an indexed digest and counted by a stored length (schema version 3, review finding
    /// Z27), so keeping an entry never rereads the entries already kept; the engine caps what it keeps there.
    ///
    /// A separate file rather than tables in the record store keeps `WatchwordStore` ignorant of sync. Nothing needs
    /// both in one transaction: tombstones are recorded after the deletion commits (`DeletionRecordingStore`) and the
    /// engine's state can always be rebuilt with a reconciling sync.
    public final class SQLiteSyncStateStore: SyncStateStore {
        public static let schemaVersion = 3
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
                authenticator BLOB NOT NULL,
                PRIMARY KEY (vault_id, record_id, kind)
            ) STRICT
            """
        /// The quarantine of versions 1 and 2: no way to find an entry but to read them all.
        static let legacyQuarantineTable = """
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

        /// Version 3 (review finding Z27): each entry with a digest of all of it, indexed, so that a duplicate is
        /// found without reading the rest, and with its size, so that what a vault's quarantine holds is counted
        /// without reading an envelope. The small columns come first and the envelope last: SQLite reads a row only
        /// as far as the last column asked for.
        static let quarantineTable = """
            CREATE TABLE quarantine_entries (
                vault_id BLOB NOT NULL CHECK (length(vault_id) = 16),
                digest INTEGER NOT NULL,
                size INTEGER NOT NULL,
                record_id BLOB NOT NULL CHECK (length(record_id) = 16),
                kind INTEGER NOT NULL,
                key_id BLOB NOT NULL CHECK (length(key_id) = 16),
                version INTEGER NOT NULL,
                device_id BLOB NOT NULL CHECK (length(device_id) = 16),
                erasure BLOB NOT NULL,
                envelope BLOB
            ) STRICT
            """
        static let quarantineIndex =
            "CREATE INDEX quarantine_entries_digest ON quarantine_entries (vault_id, digest)"

        /// Version 2 (ADR 0009): the stash, one row per vault, written once per sync rather than with the state.
        static let stashTable = """
            CREATE TABLE stash (
                vault_id BLOB PRIMARY KEY CHECK (length(vault_id) = 16),
                stash BLOB NOT NULL
            ) STRICT
            """

        static let expectedSchema: Set<[SQLiteValue]> = [
            [.text("table"), .text("sync_state"), .text("sync_state"), .text(stateTable)],
            [.text("index"), .text("sqlite_autoindex_sync_state_1"), .text("sync_state"), .null],
            [.text("table"), .text("staged"), .text("staged"), .text(stagedTable)],
            [.text("index"), .text("sqlite_autoindex_staged_1"), .text("staged"), .null],
            [.text("table"), .text("pending_deletions"), .text("pending_deletions"), .text(pendingTable)],
            [.text("index"), .text("sqlite_autoindex_pending_deletions_1"), .text("pending_deletions"), .null],
            [.text("table"), .text("quarantine_entries"), .text("quarantine_entries"), .text(quarantineTable)],
            [
                .text("index"), .text("quarantine_entries_digest"), .text("quarantine_entries"),
                .text(quarantineIndex),
            ],
            [.text("table"), .text("stash"), .text("stash"), .text(stashTable)],
            [.text("index"), .text("sqlite_autoindex_stash_1"), .text("stash"), .null],
        ]

        /// Rows of the earlier quarantine carried to schema version 3 per query.
        static let migrationPage = 16

        private func migrate() throws {
            try connection.transaction {
                guard case .integer(let version) = try connection.query("PRAGMA user_version").first?.first else {
                    throw RecordStoreError.malformedRow("user_version")
                }
                guard version >= 0, version <= Self.schemaVersion else {
                    throw RecordStoreError.unsupportedSchemaVersion(Int(version))
                }
                if version < 1 {
                    for table in [Self.stateTable, Self.stagedTable, Self.pendingTable, Self.legacyQuarantineTable] {
                        try connection.execute(table)
                    }
                    try connection.execute("PRAGMA user_version = 1")
                }
                if version < 2 {
                    try connection.execute(Self.stashTable)
                    try connection.execute("PRAGMA user_version = 2")
                }
                if version < 3 {
                    try connection.execute(Self.quarantineTable)
                    try connection.execute(Self.quarantineIndex)
                    // Every row of the earlier table is carried over: the quarantine holds what no replay rebuilds.
                    // One that does not read as an entry keeps its columns under digest zero, and is reported as
                    // malformed when the quarantine is listed, as before.
                    // A page at a time, by rowid: the earlier table was unbounded, envelopes included, and one query
                    // for all of it would hold all of it in memory at once (review finding Z39).
                    var after: Int64 = -1
                    while true {
                        let rows = try connection.query(
                            """
                            SELECT rowid, vault_id, record_id, kind, key_id, version, device_id, erasure, envelope
                            FROM quarantine WHERE rowid > ? ORDER BY rowid LIMIT \(Self.migrationPage)
                            """,
                            [.integer(after)])
                        guard !rows.isEmpty else { break }
                        for row in rows {
                            guard row.count == 9, case .integer(let rowid) = row[0] else {
                                throw RecordStoreError.malformedRow("quarantine")
                            }
                            after = rowid
                            let columns = Array(row[1...])
                            var digest: UInt64 = 0
                            var length = 0
                            if case .blob(let erasure) = columns[6] { length += erasure.count }
                            if case .blob(let envelope) = columns[7] { length += envelope.count }
                            if let entry = try? Self.entry(Array(columns[1...])) { digest = entry.quarantineDigest }
                            try connection.query(
                                Self.quarantineInsert,
                                [columns[0], .integer(Int64(bitPattern: digest)), .integer(Int64(length))]
                                    + columns[1...])
                        }
                    }
                    try connection.execute("DROP TABLE quarantine")
                    try connection.execute("PRAGMA user_version = 3")
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
                        key_id, version, device_id, envelope, authenticator)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        SQLiteRecordStore.value(record.vaultID), SQLiteRecordStore.value(record.recordID),
                        .integer(Int64(record.kind.rawValue)), .integer(Int64(bitPattern: deletion.stamp.version)),
                        SQLiteRecordStore.value(deletion.stamp.device), SQLiteRecordStore.value(record.keyID),
                        .integer(Int64(bitPattern: record.version)), SQLiteRecordStore.value(record.deviceID),
                        .blob(record.envelope), .blob(deletion.authenticator),
                    ])
            }
        }

        public func pendingDeletions(vaultID: UUID) throws -> [RecordKey: PendingDeletion] {
            let rows = try connection.query(
                """
                SELECT record_id, kind, stamp_version, stamp_device, key_id, version, device_id, envelope, authenticator
                FROM pending_deletions WHERE vault_id = ?
                """,
                [SQLiteRecordStore.value(vaultID)])
            var result: [RecordKey: PendingDeletion] = [:]
            for row in rows {
                guard row.count == 9 else { throw RecordStoreError.malformedRow("pending_deletions") }
                let record = StoredRecord(
                    recordID: try Self.uuid(row[0]), kind: try Self.kind(row[1]), vaultID: vaultID,
                    keyID: try Self.uuid(row[4]), version: try Self.version(row[5]), deviceID: try Self.uuid(row[6]),
                    envelope: try Self.blob(row[7]))
                result[record.key] = PendingDeletion(
                    stamp: RecordStamp(version: try Self.version(row[2]), device: try Self.uuid(row[3]), deleted: true),
                    record: record, authenticator: try Self.blob(row[8]))
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

        static let quarantineInsert = """
            INSERT INTO quarantine_entries (vault_id, digest, size, record_id, kind, key_id, version, device_id,
                erasure, envelope)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """

        /// `IS` rather than `=` for the envelope, so a deletion's NULL envelope matches itself. The digest narrows
        /// the search through the index; the other columns, compared by SQLite, decide it.
        static let quarantineMatch = """
            vault_id = ? AND digest = ? AND record_id = ? AND kind = ? AND key_id = ? AND version = ?
                AND device_id = ? AND erasure = ? AND envelope IS ?
            """

        /// The most kept entries one digest may name (review finding Z39). FNV-1a is not keyed, so a writer can make
        /// entries that share one; each lookup then compares, and reads, every row under it. Sixty-four bits collide
        /// by chance with odds that never arise in a quarantine of thousands, so a digest named more often than this
        /// is someone's doing: nothing more is kept under it, and a lookup reads no more than this many rows.
        static let maximumEntriesPerDigest = 16

        /// Whether the digest of `entry` already names `maximumEntriesPerDigest` kept entries. Reads the index only.
        private func digestCrowded(_ entry: SyncEntry, vaultID: UUID) throws -> Bool {
            let rows = try connection.query(
                """
                SELECT COUNT(*) FROM (SELECT 1 FROM quarantine_entries WHERE vault_id = ? AND digest = ? LIMIT ?)
                """,
                [
                    SQLiteRecordStore.value(vaultID), .integer(Int64(bitPattern: entry.quarantineDigest)),
                    .integer(Int64(Self.maximumEntriesPerDigest)),
                ])
            guard case .integer(let count) = rows.first?.first else { throw RecordStoreError.malformedRow("count") }
            return count >= Int64(Self.maximumEntriesPerDigest)
        }

        @discardableResult
        public func quarantine(_ entry: SyncEntry, vaultID: UUID) throws -> Bool {
            try connection.transaction {
                guard try !holdsQuarantined(entry, vaultID: vaultID) else { return false }
                // A crowded digest keeps nothing more. Answered as not added; the engine, finding it not held either,
                // counts it as not kept and remembers whose it was (review finding Z141).
                guard try !digestCrowded(entry, vaultID: vaultID) else { return false }
                try connection.query(
                    Self.quarantineInsert,
                    [
                        SQLiteRecordStore.value(vaultID), .integer(Int64(bitPattern: entry.quarantineDigest)),
                        .integer(Int64(entry.storedLength)),
                    ] + Self.columns(entry))
                return true
            }
        }

        public func holdsQuarantined(_ entry: SyncEntry, vaultID: UUID) throws -> Bool {
            try !connection.query(
                "SELECT 1 FROM quarantine_entries WHERE \(Self.quarantineMatch) LIMIT 1",
                Self.matching(entry, vaultID: vaultID)
            ).isEmpty
        }

        public func quarantined(vaultID: UUID) throws -> [SyncEntry] {
            try connection.query(
                """
                SELECT record_id, kind, key_id, version, device_id, erasure, envelope
                FROM quarantine_entries WHERE vault_id = ? ORDER BY rowid
                """,
                [SQLiteRecordStore.value(vaultID)]
            ).map { row in
                guard row.count == 7 else { throw RecordStoreError.malformedRow("quarantine") }
                return try Self.entry(row)
            }
        }

        public func discardQuarantined(_ entries: [SyncEntry], vaultID: UUID) throws {
            try connection.transaction {
                for entry in entries {
                    try connection.query(
                        "DELETE FROM quarantine_entries WHERE \(Self.quarantineMatch)",
                        Self.matching(entry, vaultID: vaultID))
                }
            }
        }

        /// What one device's share of the quarantine is counted as at most: well past every cap, far below `Int.max`.
        static let maximumCountedBytes = 1 << 40

        public func quarantineUsage(vaultID: UUID) throws -> QuarantineUsage {
            let rows = try connection.query(
                """
                SELECT device_id, COUNT(*), SUM(size) FROM quarantine_entries WHERE vault_id = ?
                GROUP BY device_id
                """,
                [SQLiteRecordStore.value(vaultID)])
            var usage = QuarantineUsage()
            for row in rows {
                guard row.count == 3, case .integer(let entries) = row[1], case .integer(let bytes) = row[2] else {
                    throw RecordStoreError.malformedRow("quarantine")
                }
                // A length the file made negative or huge counts as full rather than as room, and is held far below
                // `Int.max`, so that adding to it cannot overflow (review finding Z39; the engine adds without
                // overflow too).
                let ceiling = Int64(Self.maximumCountedBytes)
                usage.devices[try Self.uuid(row[0])] = QuarantineUsage.Share(
                    entries: Int(clamping: min(max(entries, 0), ceiling)),
                    bytes: Int(clamping: bytes < 0 ? ceiling : min(bytes, ceiling)))
            }
            return usage
        }

        // MARK: - Stash

        public func stash(vaultID: UUID) throws -> [UInt8]? {
            let rows = try connection.query(
                "SELECT stash FROM stash WHERE vault_id = ?", [SQLiteRecordStore.value(vaultID)])
            guard let row = rows.first else { return nil }
            // Rebuildable from the log: the engine parses the bytes and replays the log if they do not parse.
            guard row.count == 1, case .blob(let bytes) = row[0] else { return [] }
            return bytes
        }

        public func saveStash(_ bytes: [UInt8], vaultID: UUID) throws {
            try connection.query(
                "INSERT OR REPLACE INTO stash (vault_id, stash) VALUES (?, ?)",
                [SQLiteRecordStore.value(vaultID), .blob(bytes)])
        }

        // MARK: - Erasure

        public func eraseAll() throws {
            try connection.transaction {
                try connection.execute(
                    """
                    DELETE FROM sync_state; DELETE FROM staged; DELETE FROM pending_deletions;
                    DELETE FROM quarantine_entries; DELETE FROM stash;
                    """
                )
            }
            // As in `SQLiteRecordStore.eraseAll`: the superseded pages must leave the write-ahead log too.
            try connection.execute("VACUUM")
            let result = try connection.query("PRAGMA wal_checkpoint(TRUNCATE)")
            guard result.first?.first == .integer(0) else { throw RecordStoreError.checkpointIncomplete }
        }

        // MARK: - Columns

        /// An entry's own columns, in the table's order: record, kind, key, version, device, erasure, envelope.
        private static func columns(_ entry: SyncEntry) -> [SQLiteValue] {
            [
                SQLiteRecordStore.value(entry.recordID), .integer(Int64(entry.kind.rawValue)),
                SQLiteRecordStore.value(entry.keyID), .integer(Int64(bitPattern: entry.version)),
                SQLiteRecordStore.value(entry.device), .blob(entry.erasure),
                entry.envelope.map(SQLiteValue.blob) ?? .null,
            ]
        }

        /// The bindings of `quarantineMatch`.
        private static func matching(_ entry: SyncEntry, vaultID: UUID) -> [SQLiteValue] {
            [SQLiteRecordStore.value(vaultID), .integer(Int64(bitPattern: entry.quarantineDigest))] + columns(entry)
        }

        /// The entry in seven columns ordered as `columns(_:)` writes them.
        private static func entry(_ row: [SQLiteValue]) throws -> SyncEntry {
            guard row.count == 7 else { throw RecordStoreError.malformedRow("quarantine") }
            var envelope: [UInt8]?
            if case .blob(let bytes) = row[6] { envelope = bytes }
            return SyncEntry(
                recordID: try uuid(row[0]), kind: try kind(row[1]), keyID: try uuid(row[2]),
                version: try version(row[3]), device: try uuid(row[4]), envelope: envelope,
                erasure: try blob(row[5]))
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
#endif
