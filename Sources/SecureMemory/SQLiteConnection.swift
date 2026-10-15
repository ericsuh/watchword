#if canImport(SQLite3)
    import Foundation
    import SQLite3

    /// A value bound to, or read from, an SQLite statement.
    public enum SQLiteValue: Sendable, Hashable {
        case null
        case integer(Int64)
        case real(Double)
        case text(String)
        case blob([UInt8])
    }

    /// The thin SQLite wrapper behind the local ciphertext store (docs/02-architecture.md §6, "no ORM").
    ///
    /// It lives in `SecureMemory` only because every SQLite C call passes an `OpaquePointer` or a raw buffer, and ADR 0001
    /// (amended for milestone 2) confines unsafe constructs to this module. It stores ciphertext, not key material, and
    /// knows nothing about the schema: `WatchwordStore.SQLiteRecordStore` owns that.
    ///
    /// The surface is deliberately small and closes off the usual ways an SQLite wrapper goes wrong:
    ///
    /// - **No string interpolation into SQL.** Every value is a bound parameter (`SQLiteValue`), so stored data can never
    ///   become SQL. Statements are compile-time strings owned by the store.
    /// - **Hardened connection.** Opened with `SQLITE_OPEN_NOFOLLOW` (a symlink planted at the store path is refused, not
    ///   followed into another file), `trusted_schema = OFF` (a tampered database cannot make SQL functions run from
    ///   its schema), `cell_size_check = ON` (corrupt pages fail rather than over-read), `secure_delete = ON` (deleted
    ///   rows are overwritten, not left in free pages), and extension loading left disabled (SQLite's default).
    /// - **Serialised.** One recursive lock around every call; `transaction(_:)` holds it for the whole transaction, so
    ///   no other caller's statement can interleave and be committed or rolled back with it.
    /// - **Bounded reads.** A column larger than `maximumValueLength` is refused rather than copied, so a tampered
    ///   database file cannot make a read allocate without limit (SEC9).
    public final class SQLiteConnection: @unchecked Sendable {
        public enum Failure: Error, Equatable, Sendable {
            case open(code: Int32)
            case prepare(code: Int32, message: String)
            case bind(code: Int32)
            case step(code: Int32, message: String)
            case valueTooLarge(Int)
            case unsupportedColumnType(Int32)
            case closed
        }

        /// Upper bound on one column value read back; envelopes are capped at 64 MiB (`Envelope.maximumLength`).
        public static let maximumValueLength = 64 << 20

        // The handle is held as an integer, like `SecureBytes`' base address, so the class has no stored property of
        // unsafe type and every conversion back to a pointer is a marked `unsafe` expression.
        private var handleAddress: UInt
        private let lock = NSRecursiveLock()

        /// Opens (creating if needed) the database at `path`.
        public init(path: String) throws {
            var handle: OpaquePointer?
            let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW
            let code = unsafe (sqlite3_open_v2(path, &handle, flags, nil))
            guard code == SQLITE_OK, let opened = unsafe (handle) else {
                if let opened = unsafe (handle) { _ = unsafe (sqlite3_close_v2(opened)) }
                throw Failure.open(code: code)
            }
            handleAddress = UInt(bitPattern: opened)
            // SQLite's own cap on any string, blob or row, so a tampered file cannot make a read allocate far beyond
            // `maximumValueLength` before the check below ever sees the length (the default limit is about 1 GB). A
            // row may carry a full-size envelope plus its storage-location columns, hence the small margin.
            _ = unsafe (sqlite3_limit(opened, SQLITE_LIMIT_LENGTH, Int32(Self.maximumValueLength + (1 << 20))))
            // The app and the AutoFill extension share the file; wait for the other's write lock rather than failing.
            _ = unsafe (sqlite3_busy_timeout(opened, 2_000))
            do {
                try execute(
                    """
                    PRAGMA trusted_schema = OFF;
                    PRAGMA cell_size_check = ON;
                    PRAGMA secure_delete = ON;
                    PRAGMA foreign_keys = ON;
                    PRAGMA journal_mode = WAL;
                    """)
            } catch {
                close()
                throw error
            }
        }

        deinit {
            close()
        }

        /// Closes the connection; later calls throw `Failure.closed`.
        public func close() {
            lock.lock()
            defer { lock.unlock() }
            guard handleAddress != 0 else { return }
            if let handle = unsafe (OpaquePointer(bitPattern: handleAddress)) {
                _ = unsafe (sqlite3_close_v2(handle))
            }
            handleAddress = 0
        }

        /// Runs one or more statements that take no parameters (schema creation, pragmas).
        public func execute(_ sql: String) throws {
            try
                unsafe (withHandle { handle in
                    let code = unsafe (sqlite3_exec(handle, sql, nil, nil, nil))
                    guard code == SQLITE_OK else {
                        throw Failure.step(code: code, message: unsafe (Self.message(handle)))
                    }
                })
        }

        /// Runs one statement with bound parameters and returns every row.
        @discardableResult
        public func query(_ sql: String, _ bindings: [SQLiteValue] = []) throws -> [[SQLiteValue]] {
            try
                unsafe (withHandle { handle in
                    var statement: OpaquePointer?
                    let prepared = unsafe (sqlite3_prepare_v2(handle, sql, -1, &statement, nil))
                    guard prepared == SQLITE_OK, let statement = unsafe (statement) else {
                        throw Failure.prepare(code: prepared, message: unsafe (Self.message(handle)))
                    }
                    defer { _ = unsafe (sqlite3_finalize(statement)) }
                    for (offset, value) in bindings.enumerated() {
                        try unsafe (Self.bind(value, at: Int32(offset + 1), to: statement))
                    }
                    var rows: [[SQLiteValue]] = []
                    while true {
                        let code = unsafe (sqlite3_step(statement))
                        if code == SQLITE_DONE { break }
                        guard code == SQLITE_ROW else {
                            throw Failure.step(code: code, message: unsafe (Self.message(handle)))
                        }
                        let columns = unsafe (sqlite3_column_count(statement))
                        rows.append(try (0..<columns).map { try unsafe (Self.column($0, of: statement)) })
                    }
                    return rows
                })
        }

        /// Runs `body` inside `BEGIN IMMEDIATE … COMMIT`, rolling back if it throws. The connection's lock is held
        /// throughout, so statements from other callers cannot interleave with the transaction.
        public func transaction<R>(_ body: () throws -> R) throws -> R {
            lock.lock()
            defer { lock.unlock() }
            try execute("BEGIN IMMEDIATE")
            do {
                let result = try body()
                try execute("COMMIT")
                return result
            } catch {
                try? execute("ROLLBACK")
                throw error
            }
        }

        private func withHandle<R>(_ body: (OpaquePointer) throws -> R) throws -> R {
            lock.lock()
            defer { lock.unlock() }
            guard handleAddress != 0, let handle = unsafe (OpaquePointer(bitPattern: handleAddress)) else {
                throw Failure.closed
            }
            return try unsafe (body(handle))
        }

        private static func message(_ handle: OpaquePointer) -> String {
            guard let text = unsafe (sqlite3_errmsg(handle)) else { return "" }
            return unsafe (String(cString: text))
        }

        /// SQLite copies the value before the call returns (`SQLITE_TRANSIENT`), so no Swift buffer must outlive it.
        private static let transient = unsafe (unsafeBitCast(-1, to: sqlite3_destructor_type.self))

        private static func bind(_ value: SQLiteValue, at index: Int32, to statement: OpaquePointer) throws {
            let code: Int32
            switch value {
            case .null:
                code = unsafe (sqlite3_bind_null(statement, index))
            case .integer(let integer):
                code = unsafe (sqlite3_bind_int64(statement, index, integer))
            case .real(let real):
                code = unsafe (sqlite3_bind_double(statement, index, real))
            case .text(let text):
                code = unsafe (sqlite3_bind_text(statement, index, text, -1, transient))
            case .blob(let bytes):
                guard bytes.count <= maximumValueLength else { throw Failure.valueTooLarge(bytes.count) }
                // A zero-length blob still needs a non-null pointer, or SQLite stores NULL instead of an empty value.
                code =
                    bytes.isEmpty
                    ? unsafe (sqlite3_bind_zeroblob(statement, index, 0))
                    : unsafe (sqlite3_bind_blob(statement, index, bytes, Int32(bytes.count), transient))
            }
            guard code == SQLITE_OK else { throw Failure.bind(code: code) }
        }

        private static func column(_ index: Int32, of statement: OpaquePointer) throws -> SQLiteValue {
            switch unsafe (sqlite3_column_type(statement, index)) {
            case SQLITE_NULL:
                return .null
            case SQLITE_INTEGER:
                return .integer(unsafe (sqlite3_column_int64(statement, index)))
            case SQLITE_FLOAT:
                return .real(unsafe (sqlite3_column_double(statement, index)))
            case SQLITE_TEXT:
                let length = Int(unsafe (sqlite3_column_bytes(statement, index)))
                guard length <= maximumValueLength else { throw Failure.valueTooLarge(length) }
                guard let text = unsafe (sqlite3_column_text(statement, index)) else { return .text("") }
                let buffer = unsafe (UnsafeBufferPointer(start: text, count: length))
                return .text(unsafe (String(decoding: buffer, as: UTF8.self)))
            case SQLITE_BLOB:
                // `column_blob` before `column_bytes`, as the SQLite documentation requires for a stable length.
                let pointer = unsafe (sqlite3_column_blob(statement, index))
                let length = Int(unsafe (sqlite3_column_bytes(statement, index)))
                guard length <= maximumValueLength else { throw Failure.valueTooLarge(length) }
                guard let pointer = unsafe (pointer), length > 0 else { return .blob([]) }
                return .blob(unsafe (Array(UnsafeRawBufferPointer(start: pointer, count: length))))
            case let type:
                throw Failure.unsupportedColumnType(type)
            }
        }
    }
#endif
