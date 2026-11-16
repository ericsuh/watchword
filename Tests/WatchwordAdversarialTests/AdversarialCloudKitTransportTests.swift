#if canImport(CloudKit)
    import CloudKit
    import Foundation
    import Testing
    import WatchwordPlatform
    import WatchwordSync

    /// `CloudKitTransport` against a hostile store (docs/02-architecture.md §7.2), through the fake database.
    ///
    /// Threat model: **A1, the CloudKit service or anyone with the iCloud account**, able to put any record in the
    /// zone and answer any request: records under names outside the layout, a `name` field that disagrees with the
    /// record, payloads too large, in a plain field, or two at once, and arbitrary errors (a `retryAfterSeconds` of
    /// years). The transport must hand the engine at most what a record under that exact name holds, within the
    /// reader's limit, in one reading, and turn the rest into a typed refusal; how long a stated wait lasts is bounded
    /// by `AutoSyncPolicy`. Runs on a Mac only; required there through its `darwin:` line in `adversarial-suites.txt`.
    @Suite("Adversarial: Apple adapters: CloudKit transport", .tags(.adversarial))
    struct AdversarialCloudKitTransportTests {
        typealias Transport = CloudKitTransport<FakeCloudKitDatabase>

        static let name = SyncObjectLocation.segment(vaultID: UUID(), author: UUID(), sequence: 1).name
        static var prefix: String { String(name.split(separator: "/").prefix(2).joined(separator: "/")) + "/" }

        static func record(_ recordName: String, in transport: Transport, fields: (CKRecord) -> Void) -> CKRecord {
            let record = CKRecord(
                recordType: "WWObject", recordID: CKRecord.ID(recordName: recordName, zoneID: transport.zoneID))
            fields(record)
            return record
        }

        /// A1 plants a record whose `name` field claims another object, and records whose names are not the layout's:
        /// none is listed, and the mislabelled one is refused when fetched.
        @Test("records that are not what their name says are neither listed nor read")
        func mislabelled() async throws {
            let database = FakeCloudKitDatabase()
            let transport = Transport(database: database)
            let recordName = try Transport.recordName(for: Self.name)
            let other = Self.prefix + "log/" + UUID().uuidString + "/2"
            database.plant(Self.record(recordName, in: transport) { $0["name"] = other })
            database.plant(Self.record("_planted", in: transport) { $0["name"] = Self.prefix + "x" })
            database.plant(Self.record("vault.a b", in: transport) { $0["name"] = Self.prefix + "y" })
            #expect(try await transport.list(prefix: "").isEmpty)
            await #expect(throws: SyncTransportError.invalidName(Self.name)) {
                try await transport.fetch(Self.name, maximumLength: 100)
            }
        }

        /// A1 stores bytes in a plain field, or both an inline payload and an asset, or more than the reader allows:
        /// the plain field is never read as the object, two readings are refused, and the size is enforced.
        @Test("payloads in a plain field, two payloads, or oversized ones are refused")
        func payloads() async throws {
            let database = FakeCloudKitDatabase()
            let transport = Transport(database: database)
            let recordName = try Transport.recordName(for: Self.name)
            database.plant(
                Self.record(recordName, in: transport) {
                    $0["name"] = Self.name
                    $0["payload"] = Data([1, 2, 3])
                })
            #expect(try await transport.fetch(Self.name, maximumLength: 100) == [])

            let file = FileManager.default.temporaryDirectory.appendingPathComponent("ww-adv-\(UUID().uuidString)")
            try Data([4]).write(to: file)
            database.plant(
                Self.record(recordName, in: transport) {
                    $0["name"] = Self.name
                    $0.encryptedValues["payload"] = Data([5])
                    $0["payloadAsset"] = CKAsset(fileURL: file)
                })
            await #expect(throws: SyncTransportError.invalidName(Self.name)) {
                try await transport.fetch(Self.name, maximumLength: 100)
            }

            database.plant(
                Self.record(recordName, in: transport) {
                    $0["name"] = Self.name
                    $0.encryptedValues["payload"] = Data(repeating: 6, count: 101)
                })
            await #expect(throws: SyncTransportError.objectTooLarge(Self.name)) {
                try await transport.fetch(Self.name, maximumLength: 100)
            }
        }

        /// A1 answers a listing with more records than any vault could hold: refused at the cap, not accumulated.
        @Test("a listing larger than the cap is refused")
        func listingCap() async throws {
            let database = FakeCloudKitDatabase(pageLimit: 5)
            let transport = Transport(database: database, maximumListedObjects: 8)
            for sequence in 1...12 {
                let name = Self.prefix + "log/" + UUID().uuidString + "/\(sequence)"
                database.plant(Self.record(try Transport.recordName(for: name), in: transport) { $0["name"] = name })
            }
            await #expect(throws: SyncTransportError.objectTooLarge(Self.prefix)) {
                try await transport.list(prefix: Self.prefix)
            }
        }

        /// A1 asks the client to wait for years: the transport passes the claim on, and the policy holds it to its
        /// maximum backoff, so sync is never switched off by the store.
        @Test("a wait of years asked by the store is held to the policy's maximum")
        func hostileRetryAfter() {
            let error = CloudKitErrors.transportError(
                for: CKError(.requestRateLimited, userInfo: [CKErrorRetryAfterKey: 1e12]), name: "n")
            var state = AutoSyncState()
            let now = Date(timeIntervalSince1970: 1_800_000_000)
            AutoSyncPolicy.record(.unlocked, at: now, in: &state)
            AutoSyncPolicy.record(.syncStarted, at: now, in: &state)
            AutoSyncPolicy.record(.syncThrottled(retryAfter: error.retryAfter), at: now, in: &state)
            #expect(AutoSyncPolicy.backoff(after: state, .standard) == AutoSyncSettings.standard.backoffMaximum)
        }

        /// A1 answers a create with `serverRecordChanged` for a name nobody wrote: the engine is told the object
        /// exists and never retries with an overwriting policy.
        @Test("a refused create is objectExists, and no save ever overwrites")
        func refusedCreate() async throws {
            let database = FakeCloudKitDatabase()
            let transport = Transport(database: database)
            try await transport.create(Self.name, contents: [1])
            database.injectFailure(
                CKError(
                    .partialFailure,
                    userInfo: [
                        CKPartialErrorsByItemIDKey: [
                            try transport.recordIDForAdversary(Self.prefix + "log/x/1"): CKError(.serverRecordChanged)
                        ] as [AnyHashable: any Error]
                    ]))
            await #expect(throws: SyncTransportError.objectExists(Self.prefix + "log/x/1")) {
                try await transport.create(Self.prefix + "log/x/1", contents: [2])
            }
            #expect(database.savePolicies.allSatisfy { $0 == .ifServerRecordUnchanged })
        }
    }

    extension CloudKitTransport {
        func recordIDForAdversary(_ name: String) throws -> CKRecord.ID {
            CKRecord.ID(recordName: try Self.recordName(for: name), zoneID: zoneID)
        }
    }
#endif
