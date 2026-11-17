#if canImport(SQLite3)
    import Foundation
    import SecureMemory
    import WatchwordSharing
    import WatchwordStore

    /// The persistent `SharingStateStore` and `VerifiedContactStore`: `sharing.sqlite`, beside the record store in the
    /// App Group container (docs/02-architecture.md §6, §8.8), opened with the same hardening as `sync.sqlite`
    /// (`SQLiteConnection`, no symlinks, `STRICT` tables, an exact schema check).
    ///
    /// Nothing here is secret, and the file is as untrusted as the record store (A8): pins, the saved ledger, a plan
    /// and the stream index are each signed by the account and verified again by `VaultSession` and
    /// `WatchwordSharing` when read, so a row planted or edited here is refused, never believed.
    public final class SQLiteSharingStore: SharingStateStore, VerifiedContactStore {
        public static let schemaVersion = 1
        public static let databaseName = "sharing.sqlite"

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

        static let stateTable = """
            CREATE TABLE shared_vault_state (
                vault_id BLOB NOT NULL CHECK (length(vault_id) = 16),
                key TEXT NOT NULL,
                value BLOB NOT NULL,
                PRIMARY KEY (vault_id, key)
            ) STRICT
            """
        static let pinTable = """
            CREATE TABLE contact_pins (
                account_id BLOB PRIMARY KEY CHECK (length(account_id) = 16),
                pin BLOB NOT NULL
            ) STRICT
            """

        static let expectedSchema: Set<[SQLiteValue]> = [
            [.text("table"), .text("shared_vault_state"), .text("shared_vault_state"), .text(stateTable)],
            [.text("index"), .text("sqlite_autoindex_shared_vault_state_1"), .text("shared_vault_state"), .null],
            [.text("table"), .text("contact_pins"), .text("contact_pins"), .text(pinTable)],
            [.text("index"), .text("sqlite_autoindex_contact_pins_1"), .text("contact_pins"), .null],
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
                    try connection.execute(Self.stateTable)
                    try connection.execute(Self.pinTable)
                    try connection.execute("PRAGMA user_version = 1")
                }
                // A planted trigger could make a save silently do nothing, as in the other databases: exactly this
                // schema, or nothing.
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

        // MARK: - SharingStateStore

        public func sharedVaultIDs() throws -> [UUID] {
            let rows = try connection.query(
                "SELECT vault_id FROM shared_vault_state WHERE key = ? ORDER BY vault_id",
                [.text(SharingStateKey.ledger.rawValue)])
            return rows.compactMap { row in
                guard row.count == 1, case .blob(let bytes) = row[0], bytes.count == 16 else { return nil }
                return Self.uuid(bytes)
            }
        }

        public func value(_ key: SharingStateKey, vaultID: UUID) throws -> [UInt8]? {
            let rows = try connection.query(
                "SELECT value FROM shared_vault_state WHERE vault_id = ? AND key = ?",
                [SQLiteRecordStore.value(vaultID), .text(key.rawValue)])
            guard let row = rows.first, row.count == 1, case .blob(let bytes) = row[0] else { return nil }
            return bytes
        }

        public func setValue(_ value: [UInt8]?, for key: SharingStateKey, vaultID: UUID) throws {
            if let value {
                try connection.query(
                    "INSERT OR REPLACE INTO shared_vault_state (vault_id, key, value) VALUES (?, ?, ?)",
                    [SQLiteRecordStore.value(vaultID), .text(key.rawValue), .blob(value)])
            } else {
                try connection.query(
                    "DELETE FROM shared_vault_state WHERE vault_id = ? AND key = ?",
                    [SQLiteRecordStore.value(vaultID), .text(key.rawValue)])
            }
        }

        // MARK: - VerifiedContactStore

        public func pin(for accountID: UUID) throws -> [UInt8]? {
            let rows = try connection.query(
                "SELECT pin FROM contact_pins WHERE account_id = ?", [SQLiteRecordStore.value(accountID)])
            guard let row = rows.first, row.count == 1, case .blob(let bytes) = row[0] else { return nil }
            return bytes
        }

        public func savePin(_ pin: [UInt8], for accountID: UUID) throws {
            try connection.query(
                "INSERT OR REPLACE INTO contact_pins (account_id, pin) VALUES (?, ?)",
                [SQLiteRecordStore.value(accountID), .blob(pin)])
        }

        public func removePin(for accountID: UUID) throws {
            try connection.query(
                "DELETE FROM contact_pins WHERE account_id = ?", [SQLiteRecordStore.value(accountID)])
        }

        static func uuid(_ b: [UInt8]) -> UUID {
            UUID(
                uuid: (
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14],
                    b[15]
                ))
        }
    }
#endif
