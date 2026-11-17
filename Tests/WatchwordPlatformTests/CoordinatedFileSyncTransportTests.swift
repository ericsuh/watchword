#if canImport(Darwin)
    import Foundation
    import Testing
    import WatchwordModel
    import WatchwordPlatform
    import WatchwordSync
    import WatchwordTestSupport

    enum CoordinatedFixtures {
        /// A transport whose coordination deadline is never reached in a test (the deadline test passes its own).
        static func transport(_ root: URL) -> CoordinatedFileSyncTransport {
            CoordinatedFileSyncTransport(root: root) { try? await Task.sleep(for: .seconds(86_400)) }
        }

        static func temporaryRoot() -> URL {
            URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
                .appendingPathComponent("watchword-coordinated-\(UUID().uuidString)", isDirectory: true)
        }

        /// Puts iCloud's legacy placeholder for `name` under `root`, as iCloud Drive does for an object another device
        /// wrote that is not downloaded here yet.
        static func plantPlaceholder(for name: String, in root: URL) throws {
            let url = try FileSyncTransport(root: root).fileURL(for: name)
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data([0]).write(to: FileSyncTransport.placeholderURL(for: url))
        }

        /// The first `onChange` from a presenter, or `false` after `timeout` (a bound on waiting for an event, not a
        /// delay the test depends on).
        static func firstEvent(_ stream: AsyncStream<Void>, within timeout: Duration) async -> Bool {
            await withTaskGroup(of: Bool.self) { group in
                group.addTask {
                    for await _ in stream { return true }
                    return false
                }
                group.addTask {
                    try? await Task.sleep(for: timeout)
                    return false
                }
                let first = await group.next() ?? false
                group.cancelAll()
                return first
            }
        }
    }

    /// The coordinated iCloud Drive transport in a plain temporary directory (docs/02-architecture.md §7.3): the
    /// transport contract under `NSFileCoordinator`, placeholders of files not downloaded yet, create-once among
    /// concurrent coordinated writers, change notification, and two sync engines over it. A real ubiquity container
    /// needs a signed app with the iCloud entitlement, so download and eviction by iCloud itself are not exercised here.
    @Suite("Coordinated iCloud Drive transport", .serialized)
    struct CoordinatedFileSyncTransportTests {
        @Test("keeps the sync transport contract under file coordination")
        func contract() async throws {
            let violations = try await SyncTransportContract.violations {
                CoordinatedFixtures.transport(CoordinatedFixtures.temporaryRoot())
            }
            #expect(violations == [])
        }

        /// The renamed half of conflict copies (docs/02-architecture.md §7.5): `N 2.wwe` beside `N.wwe`. iCloud's own
        /// conflict versions (`NSFileVersion`) exist only in a real ubiquity container and are not exercised here.
        @Test("renamed duplicates are counted, handed over and deleted with their object under coordination")
        func renamedCopies() async throws {
            let transport = CoordinatedFixtures.transport(CoordinatedFixtures.temporaryRoot())
            var next = 2
            let violations = try await SyncTransportContract.heldCopies(transport) { name, bytes in
                let url = try transport.base.fileURL(for: name)
                let stem = url.deletingPathExtension().lastPathComponent
                try Data(bytes).write(
                    to: url.deletingLastPathComponent().appendingPathComponent("\(stem) \(next).wwe"))
                next += 1
            }
            #expect(violations == [])
        }

        @Test("an object not downloaded yet is listed, fetched as absent, blocks a create, and can be deleted")
        func placeholder() async throws {
            let root = CoordinatedFixtures.temporaryRoot()
            let transport = CoordinatedFixtures.transport(root)
            let name = SyncTransportContract.name
            try CoordinatedFixtures.plantPlaceholder(for: name, in: root)
            #expect(try await transport.list(prefix: SyncTransportContract.prefix) == [name])
            #expect(try await transport.fetch(name, maximumLength: 100) == nil)
            await #expect(throws: SyncTransportError.objectExists(name)) {
                try await transport.create(name, contents: [1])
            }
            try await transport.delete(name)
            #expect(try await transport.list(prefix: SyncTransportContract.prefix) == [])
        }

        @Test("of many concurrent creates of one name, exactly one succeeds and nothing is overwritten")
        func concurrentCreates() async throws {
            let transport = CoordinatedFixtures.transport(CoordinatedFixtures.temporaryRoot())
            let name = SyncTransportContract.name
            let outcomes = await withTaskGroup(of: UInt8?.self) { group in
                for writer in UInt8(1)...8 {
                    group.addTask {
                        do {
                            try await transport.create(name, contents: [writer, writer])
                            return writer
                        } catch {
                            return nil
                        }
                    }
                }
                var winners: [UInt8] = []
                for await outcome in group { if let outcome { winners.append(outcome) } }
                return winners
            }
            #expect(outcomes.count == 1)
            let winner = try #require(outcomes.first)
            #expect(try await transport.fetch(name, maximumLength: 10) == [winner, winner])
        }

        @Test("the folder presenter reports an object written under coordination")
        func presenter() async throws {
            let root = CoordinatedFixtures.temporaryRoot()
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            let (stream, continuation) = AsyncStream.makeStream(of: Void.self)
            let presenter = SyncFolderPresenter(root: root) { continuation.yield() }
            presenter.start()
            defer { presenter.stop() }
            try await CoordinatedFixtures.transport(root).create(SyncTransportContract.name, contents: [1])
            #expect(await CoordinatedFixtures.firstEvent(stream, within: .seconds(10)))
        }

        /// Another writer holds coordination of a file for as long as it likes (the iCloud daemon, another app, a
        /// hostile presenter): the read is given up at its deadline, with the coordinator cancelled, and is that
        /// object's failure alone (review of the adapters, finding 5). The deadline here returns at once, so the test
        /// waits on nothing but the held write.
        @Test("a read not granted coordination before its deadline is given up, as that object's failure alone")
        func deadline() async throws {
            let root = CoordinatedFixtures.temporaryRoot()
            let name = SyncTransportContract.name
            try await CoordinatedFixtures.transport(root).create(name, contents: [1])
            let url = try FileSyncTransport(root: root).fileURL(for: name)
            let (held, holding) = AsyncStream.makeStream(of: Void.self)
            let release = DispatchSemaphore(value: 0)
            let holder = NSFileCoordinator(filePresenter: nil)
            holder.coordinate(with: [.writingIntent(with: url, options: [])], queue: OperationQueue()) { _ in
                holding.yield()
                release.wait()
            }
            #expect(await CoordinatedFixtures.firstEvent(held, within: .seconds(10)))
            let impatient = CoordinatedFileSyncTransport(root: root, coordinationDeadline: {})
            await #expect(throws: SyncTransportError.objectUnreadable(name)) {
                try await impatient.fetch(name, maximumLength: 10)
            }
            release.signal()
            #expect(try await CoordinatedFixtures.transport(root).fetch(name, maximumLength: 10) == [1])
        }

        @Test("two sync engines exchange an item through the coordinated folder")
        func engines() async throws {
            let transport = CoordinatedFixtures.transport(CoordinatedFixtures.temporaryRoot())
            let keys = FakeAccountKeys(seed: 11)
            let vault = SyncTransportContract.vault
            await keys.addVaultKey(vaultID: vault)
            await keys.trust(device: SyncTransportContract.deviceA)
            await keys.trust(device: SyncTransportContract.deviceB)
            let a = SyncTestClient(
                deviceID: SyncTransportContract.deviceA, vaultID: vault, keys: keys, transport: transport)
            let b = SyncTestClient(
                deviceID: SyncTransportContract.deviceB, vaultID: vault, keys: keys, transport: transport)
            let item = try await a.save(
                Item(
                    id: UUID(), vaultID: vault, title: "Bank", scopes: [ServiceScope(host: "firstbank.co.uk")],
                    fields: [Field(id: UUID(), kind: .password, label: "Password", value: "hunter22")]))
            #expect(try await a.sync().segmentsWritten == 1)
            let report = try await b.sync()
            #expect(report.applied == 1)
            #expect(try await b.item(item.id) == item)
        }

        @Test("an engine reads the genuine object from among renamed copies in the coordinated folder")
        func engineAmongCopies() async throws {
            let transport = CoordinatedFixtures.transport(CoordinatedFixtures.temporaryRoot())
            let keys = FakeAccountKeys(seed: 12)
            let vault = SyncTransportContract.vault
            await keys.addVaultKey(vaultID: vault)
            await keys.trust(device: SyncTransportContract.deviceA)
            await keys.trust(device: SyncTransportContract.deviceB)
            let a = SyncTestClient(
                deviceID: SyncTransportContract.deviceA, vaultID: vault, keys: keys, transport: transport)
            let b = SyncTestClient(
                deviceID: SyncTransportContract.deviceB, vaultID: vault, keys: keys, transport: transport)
            let item = try await a.save(
                Item(
                    id: UUID(), vaultID: vault, title: "Bank", scopes: [ServiceScope(host: "firstbank.co.uk")],
                    fields: [Field(id: UUID(), kind: .password, label: "Password", value: "hunter22")]))
            try await a.sync()
            // The genuine object becomes the renamed copy, and junk takes its name.
            let url = try transport.base.fileURL(for: SyncTransportContract.name)
            let renamed = url.deletingLastPathComponent().appendingPathComponent(
                url.deletingPathExtension().lastPathComponent + " 2.wwe")
            try FileManager.default.moveItem(at: url, to: renamed)
            try Data([0xBA, 0xD0]).write(to: url)
            let report = try await b.sync()
            #expect(report.applied == 1 && report.rejected.isEmpty && report.copiesRefused == 1)
            #expect(try await b.item(item.id) == item)
        }
    }
#endif
