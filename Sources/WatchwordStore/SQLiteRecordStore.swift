#if canImport(SQLite3)
    import Foundation
    import SecureMemory
    import WatchwordEnvelope

    /// The App Group ciphertext database (docs/02-architecture.md §6).
    ///
    /// Holds envelopes and storage locations only. The tables are `STRICT`, so a value of the wrong type is refused by
    /// SQLite itself, and every row read back is checked again here (UUID lengths, known kinds) before it reaches a
    /// caller: the file is outside the keys' protection, so its contents are treated as untrusted input, and anything
    /// odd is reported as `malformedRow` rather than repaired.
    ///
    /// The schema version is `PRAGMA user_version`. A database from a newer schema is refused rather than misread.
    /// Tables for the sync change log and the HIBP cache arrive with milestones 3 and 6.
    public final class SQLiteRecordStore: RecordStore {
        public static let schemaVersion = 1

        private let connection: SQLiteConnection

        /// Opens or creates the store at `url`. On iOS the directory and database files get
        /// `completeUntilFirstUserAuthentication` protection, so the AutoFill extension can read ciphertext after the
        /// first unlock since boot; key material is never in this file (§6).
        public init(url: URL) throws {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            // `SQLITE_OPEN_NOFOLLOW` refuses a symlink anywhere in the path, and system paths contain some
            // (`/var` → `/private/var`). The directory is resolved first; the database file itself must still not be a
            // link, which is the case the flag exists for.
            let directory = URL(
                fileURLWithPath: try Self.resolvingSymlinks(url.deletingLastPathComponent().path), isDirectory: true)
            let url = directory.appendingPathComponent(url.lastPathComponent, isDirectory: false)
            connection = try SQLiteConnection(path: url.path)
            try migrate()
            #if os(iOS) || os(watchOS) || os(visionOS)
                let protection: [FileAttributeKey: Any] = [
                    .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication
                ]
                try FileManager.default.setAttributes(protection, ofItemAtPath: directory.path)
                for suffix in ["", "-wal", "-shm"] where FileManager.default.fileExists(atPath: url.path + suffix) {
                    try FileManager.default.setAttributes(protection, ofItemAtPath: url.path + suffix)
                }
            #endif
        }

        private func migrate() throws {
            try connection.transaction {
                let version = try Self.int(connection.query("PRAGMA user_version").first?.first)
                guard version <= Self.schemaVersion else {
                    throw RecordStoreError.unsupportedSchemaVersion(Int(version))
                }
                if version < 1 {
                    try connection.execute(
                        """
                        CREATE TABLE account (
                            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                            account_id BLOB NOT NULL CHECK (length(account_id) = 16),
                            device_id BLOB NOT NULL CHECK (length(device_id) = 16),
                            personal_vault_id BLOB NOT NULL CHECK (length(personal_vault_id) = 16),
                            personal_vault_key_id BLOB NOT NULL CHECK (length(personal_vault_key_id) = 16),
                            kdf_algorithm TEXT NOT NULL,
                            kdf_iterations INTEGER NOT NULL,
                            kdf_salt_length INTEGER NOT NULL,
                            kdf_output_length INTEGER NOT NULL,
                            salt BLOB NOT NULL,
                            unlock_key_id BLOB NOT NULL CHECK (length(unlock_key_id) = 16),
                            wrapped_keyset BLOB NOT NULL,
                            keyset_version INTEGER NOT NULL,
                            credential_generation INTEGER NOT NULL,
                            created_at REAL NOT NULL,
                            emergency_kit_confirmed_at REAL
                        ) STRICT;
                        CREATE TABLE records (
                            record_id BLOB NOT NULL CHECK (length(record_id) = 16),
                            kind INTEGER NOT NULL,
                            vault_id BLOB NOT NULL CHECK (length(vault_id) = 16),
                            key_id BLOB NOT NULL CHECK (length(key_id) = 16),
                            version INTEGER NOT NULL,
                            device_id BLOB NOT NULL CHECK (length(device_id) = 16),
                            envelope BLOB NOT NULL,
                            PRIMARY KEY (record_id, kind)
                        ) STRICT;
                        CREATE INDEX records_by_vault ON records (vault_id, kind);
                        PRAGMA user_version = 1;
                        """)
                }
            }
        }

        // MARK: - RecordStore

        public func loadAccount() throws -> AccountRecord? {
            let rows = try connection.query(
                """
                SELECT account_id, device_id, personal_vault_id, personal_vault_key_id, kdf_algorithm, kdf_iterations,
                       kdf_salt_length, kdf_output_length, salt, unlock_key_id, wrapped_keyset, keyset_version,
                       credential_generation, created_at, emergency_kit_confirmed_at
                FROM account WHERE singleton = 1
                """)
            guard let row = rows.first else { return nil }
            guard row.count == 15 else { throw RecordStoreError.malformedRow("account") }
            guard let algorithm = KDFAlgorithm(rawValue: try Self.text(row[4])) else {
                throw RecordStoreError.malformedRow("account.kdf_algorithm")
            }
            let iterations = try Self.int(row[5])
            let saltLength = try Self.int(row[6])
            let outputLength = try Self.int(row[7])
            // Range checks only: whether the values are acceptable is `KDFParameters.validate()`'s decision, made
            // before any derivation, so a tampered header surfaces as the same typed error wherever it came from.
            guard let iterations = UInt32(exactly: iterations), let saltLength = Int(exactly: saltLength),
                let outputLength = Int(exactly: outputLength)
            else { throw RecordStoreError.malformedRow("account.kdf") }
            return AccountRecord(
                accountID: try Self.uuid(row[0]),
                deviceID: try Self.uuid(row[1]),
                personalVaultID: try Self.uuid(row[2]),
                personalVaultKeyID: try Self.uuid(row[3]),
                kdf: KDFParameters(
                    algorithm: algorithm, iterations: iterations, saltLength: saltLength, outputLength: outputLength),
                salt: try Self.blob(row[8]),
                unlockKeyID: try Self.uuid(row[9]),
                wrappedKeyset: try Self.blob(row[10]),
                keysetVersion: try Self.version(row[11]),
                credentialGeneration: try Self.version(row[12]),
                createdAt: Date(timeIntervalSince1970: try Self.real(row[13])),
                emergencyKitConfirmedAt: try Self.optionalReal(row[14]).map(Date.init(timeIntervalSince1970:))
            )
        }

        public func record(_ key: RecordKey) throws -> StoredRecord? {
            try connection.query(
                "SELECT record_id, kind, vault_id, key_id, version, device_id, envelope FROM records "
                    + "WHERE record_id = ? AND kind = ?",
                [Self.value(key.recordID), .integer(Int64(key.kind.rawValue))]
            ).first.map(Self.storedRecord)
        }

        public func records(in vaultID: UUID, kind: EnvelopeKind) throws -> [StoredRecord] {
            try connection.query(
                "SELECT record_id, kind, vault_id, key_id, version, device_id, envelope FROM records "
                    + "WHERE vault_id = ? AND kind = ? ORDER BY record_id",
                [Self.value(vaultID), .integer(Int64(kind.rawValue))]
            ).map(Self.storedRecord)
        }

        public func commit(_ change: StoreChange) throws {
            try connection.transaction {
                // Validated inside the transaction (BEGIN IMMEDIATE holds the write lock), so another process — the
                // AutoFill extension — cannot change what was checked before it is written.
                try change.validate(currentAccount: try loadAccount()) { try record($0)?.version }
                if let account = change.newAccount {
                    try connection.query(
                        """
                        INSERT OR REPLACE INTO account (singleton, account_id, device_id, personal_vault_id,
                            personal_vault_key_id, kdf_algorithm, kdf_iterations, kdf_salt_length, kdf_output_length,
                            salt, unlock_key_id, wrapped_keyset, keyset_version, credential_generation, created_at,
                            emergency_kit_confirmed_at)
                        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        [
                            Self.value(account.accountID), Self.value(account.deviceID),
                            Self.value(account.personalVaultID), Self.value(account.personalVaultKeyID),
                            .text(account.kdf.algorithm.rawValue), .integer(Int64(account.kdf.iterations)),
                            .integer(Int64(account.kdf.saltLength)), .integer(Int64(account.kdf.outputLength)),
                            .blob(account.salt), Self.value(account.unlockKeyID), .blob(account.wrappedKeyset),
                            .integer(Int64(bitPattern: account.keysetVersion)),
                            .integer(Int64(bitPattern: account.credentialGeneration)),
                            .real(account.createdAt.timeIntervalSince1970),
                            account.emergencyKitConfirmedAt.map { .real($0.timeIntervalSince1970) } ?? .null,
                        ])
                }
                for key in change.deletions {
                    try connection.query(
                        "DELETE FROM records WHERE record_id = ? AND kind = ?",
                        [Self.value(key.recordID), .integer(Int64(key.kind.rawValue))])
                }
                for record in change.upserts {
                    try connection.query(
                        """
                        INSERT OR REPLACE INTO records (record_id, kind, vault_id, key_id, version, device_id, envelope)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        [
                            Self.value(record.recordID), .integer(Int64(record.kind.rawValue)),
                            Self.value(record.vaultID), Self.value(record.keyID),
                            .integer(Int64(bitPattern: record.version)), Self.value(record.deviceID),
                            .blob(record.envelope),
                        ])
                }
            }
        }

        public func eraseAll() throws {
            try connection.transaction {
                try connection.execute("DELETE FROM records; DELETE FROM account;")
            }
            // secure_delete overwrote the rows; VACUUM also drops the freed pages and rewrites the WAL.
            try connection.execute("VACUUM")
        }

        /// The physical path of a directory. `URL.resolvingSymlinksInPath()` cannot be used: it deliberately turns
        /// `/private/var/…` back into the symlinked `/var/…`.
        static func resolvingSymlinks(_ path: String) throws -> String {
            var pending = Array((path as NSString).pathComponents.dropFirst())
            var resolved: [String] = []
            var hops = 0
            while !pending.isEmpty {
                let component = pending.removeFirst()
                if component == "." || component.isEmpty { continue }
                if component == ".." {
                    _ = resolved.popLast()
                    continue
                }
                let candidate = "/" + (resolved + [component]).joined(separator: "/")
                let type = (try? FileManager.default.attributesOfItem(atPath: candidate))?[.type] as? FileAttributeType
                guard type == .typeSymbolicLink else {
                    resolved.append(component)
                    continue
                }
                hops += 1
                guard hops <= 32 else { throw CocoaError(.fileReadInvalidFileName) }
                let destination = try FileManager.default.destinationOfSymbolicLink(atPath: candidate)
                let parts = Array((destination as NSString).pathComponents)
                if destination.hasPrefix("/") {
                    resolved = []
                    pending = Array(parts.dropFirst()) + pending
                } else {
                    pending = parts + pending
                }
            }
            return "/" + resolved.joined(separator: "/")
        }

        // MARK: - Row decoding

        private static func storedRecord(_ row: [SQLiteValue]) throws -> StoredRecord {
            guard row.count == 7 else { throw RecordStoreError.malformedRow("records") }
            let rawKind = try int(row[1])
            guard let byte = UInt8(exactly: rawKind), let kind = EnvelopeKind(rawValue: byte) else {
                throw RecordStoreError.malformedRow("records.kind")
            }
            return StoredRecord(
                recordID: try uuid(row[0]),
                kind: kind,
                vaultID: try uuid(row[2]),
                keyID: try uuid(row[3]),
                version: try version(row[4]),
                deviceID: try uuid(row[5]),
                envelope: try blob(row[6])
            )
        }

        static func value(_ uuid: UUID) -> SQLiteValue {
            let u = uuid.uuid
            return .blob([
                u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15,
            ])
        }

        private static func uuid(_ value: SQLiteValue) throws -> UUID {
            guard case .blob(let bytes) = value, bytes.count == 16 else {
                throw RecordStoreError.malformedRow("uuid")
            }
            return UUID(
                uuid: (
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
                    bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
                ))
        }

        private static func blob(_ value: SQLiteValue) throws -> [UInt8] {
            guard case .blob(let bytes) = value else { throw RecordStoreError.malformedRow("blob") }
            return bytes
        }

        private static func text(_ value: SQLiteValue) throws -> String {
            guard case .text(let text) = value else { throw RecordStoreError.malformedRow("text") }
            return text
        }

        private static func int(_ value: SQLiteValue?) throws -> Int64 {
            guard case .integer(let integer) = value else { throw RecordStoreError.malformedRow("integer") }
            return integer
        }

        /// Versions are `UInt64` stored as their `Int64` bit pattern.
        private static func version(_ value: SQLiteValue) throws -> UInt64 {
            UInt64(bitPattern: try int(value))
        }

        private static func real(_ value: SQLiteValue) throws -> Double {
            guard case .real(let real) = value, real.isFinite else { throw RecordStoreError.malformedRow("real") }
            return real
        }

        private static func optionalReal(_ value: SQLiteValue) throws -> Double? {
            if case .null = value { return nil }
            return try real(value)
        }
    }
#endif
