#if canImport(SQLite3)
    import Foundation
    import SecureMemory
    import Testing
    import WatchwordEnvelope
    @testable import WatchwordStore

    @Suite("SQLite record store")
    struct SQLiteRecordStoreTests {
        @Test("data survives closing and reopening the database")
        func persistence() async throws {
            let url = StoreFixtures.temporaryDatabaseURL()
            let record = StoreFixtures.record()
            do {
                let store = try SQLiteRecordStore(url: url)
                try await store.commit(StoreChange(account: .create(StoreFixtures.account()), upserts: [record]))
            }
            let reopened = try SQLiteRecordStore(url: url)
            #expect(try await reopened.loadAccount() == StoreFixtures.account())
            #expect(try await reopened.record(record.key) == record)
        }

        @Test("a database from a newer schema is refused, not misread")
        func newerSchemaRefused() throws {
            let url = StoreFixtures.temporaryDatabaseURL()
            _ = try SQLiteRecordStore(url: url)
            try SQLiteConnection(path: SQLiteRecordStore.resolvingSymlinks(url.path)).execute("PRAGMA user_version = 2")
            #expect(throws: RecordStoreError.unsupportedSchemaVersion(2)) {
                _ = try SQLiteRecordStore(url: url)
            }
        }

        @Test("bound values are data, never SQL")
        func bindingIsNotInterpolation() throws {
            let connection = try SQLiteConnection(path: StoreFixtures.physicalTemporaryPath())
            try connection.execute("CREATE TABLE t (v TEXT) STRICT")
            let hostile = "x'); DROP TABLE t; --"
            try connection.query("INSERT INTO t (v) VALUES (?)", [.text(hostile)])
            #expect(try connection.query("SELECT v FROM t") == [[.text(hostile)]])
        }

        @Test("the connection is hardened: untrusted schema, cell size checks, secure delete")
        func pragmas() throws {
            let connection = try SQLiteConnection(path: StoreFixtures.physicalTemporaryPath())
            #expect(try connection.query("PRAGMA trusted_schema") == [[.integer(0)]])
            #expect(try connection.query("PRAGMA cell_size_check") == [[.integer(1)]])
            #expect(try connection.query("PRAGMA secure_delete") == [[.integer(1)]])
        }

        @Test("a closed connection refuses further use")
        func closed() throws {
            let connection = try SQLiteConnection(path: StoreFixtures.physicalTemporaryPath())
            connection.close()
            #expect(throws: SQLiteConnection.Failure.closed) { try connection.execute("SELECT 1") }
        }

        @Test("a transaction that throws is rolled back")
        func rollback() throws {
            let connection = try SQLiteConnection(path: StoreFixtures.physicalTemporaryPath())
            try connection.execute("CREATE TABLE t (v INTEGER) STRICT")
            struct Boom: Error {}
            #expect(throws: Boom.self) {
                try connection.transaction {
                    try connection.query("INSERT INTO t (v) VALUES (?)", [.integer(1)])
                    throw Boom()
                }
            }
            #expect(try connection.query("SELECT count(*) FROM t") == [[.integer(0)]])
        }
    }
#endif
