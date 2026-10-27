#if canImport(CryptoKit) && canImport(CommonCrypto)
    import Foundation
    import Testing
    import WatchwordCrypto
    import WatchwordEnvelope
    import WatchwordModel
    import WatchwordStore
    import WatchwordTestSupport

    @testable import WatchwordKit
    @testable import WatchwordSync

    /// The "sync log" threats again, against the production keyring: `VaultSession` sealing segments and records with
    /// AES-GCM under the vault key and signing them with the account's Ed25519 key (milestone 3's Mac half). The
    /// "sync log" suite shows the engine checks the right things in the right order over fakes; this one shows the
    /// real primitives are wired to those checks, so a forgery fails because the cryptography says so.
    ///
    /// Adversaries (docs/02-architecture.md §2): **A1**, the sync store, holding no key; **an insider device** of the
    /// account, holding every key; **A8**, the local-file attacker, who cannot reach the Keychain.
    @Suite("Adversarial: sync with real keys", .tags(.adversarial))
    struct AdversarialVaultSyncTests {
        static let deviceB = UUID(uuidString: "D0000000-0000-4000-8000-0000000000B0")!
        static let deviceC = UUID(uuidString: "D0000000-0000-4000-8000-0000000000C0")!

        struct Fixture {
            let transport: InMemorySyncTransport
            let a: TestVault
            let b: TestVault
            let vaultID: UUID

            /// A fresh device of the account that has never synced. It has been unlocked once, as any device in use
            /// has, so the Keychain holds its copy of the account key; `locked` locks it again.
            func reader(locked: Bool = false) async throws -> TestVault {
                let c = try await a.enrolledDevice(deviceID: AdversarialVaultSyncTests.deviceC, over: transport)
                try await c.session.unlock(password: TestVault.password)
                if locked { await c.session.lock() }
                return c
            }

            func segmentName(_ sequence: UInt64, author: UUID = AdversarialVaultSyncTests.deviceB) -> String {
                SyncObjectLocation.segment(vaultID: vaultID, author: author, sequence: sequence).name
            }
        }

        /// A creates the account; B, enrolled from it, saves one item and publishes it as its segment 1.
        static func fixture() async throws -> Fixture {
            let transport = InMemorySyncTransport()
            let a = TestVault.syncing(over: transport)
            try await a.createAccount()
            let b = try await a.enrolledDevice(deviceID: deviceB, over: transport)
            try await b.session.unlock(password: TestVault.password)
            let vaultID = try #require(await a.session.personalVaultID)
            try await b.session.save(
                Item(
                    vaultID: vaultID, title: "Bank", scopes: [ServiceScope(host: "firstbank.co.uk")],
                    fields: [Field(kind: .password, label: "Password", value: "real-key-secret")]))
            try await b.session.sync()
            return Fixture(transport: transport, a: a, b: b, vaultID: vaultID)
        }

        /// Threat: A1 flips bytes in a segment sealed and signed with real keys. Ed25519 over the name and envelope
        /// catches every flip before staging, and nothing is applied.
        @Test("a byte flipped anywhere in a really signed segment is rejected")
        func byteFlips() async throws {
            let f = try await Self.fixture()
            let name = f.segmentName(1)
            let original = try #require(await f.transport.allObjects[name])
            let reader = try await f.reader()
            for position in stride(from: 0, to: original.count, by: max(1, original.count / 48)) {
                var tampered = original
                tampered[position] ^= 0x01
                await f.transport.tamper(name, contents: tampered)
                let report = try await reader.session.sync()
                #expect(report.applied == 0, "flip at \(position) was applied")
                #expect(report.rejected.map(\.name) == [name], "flip at \(position)")
            }
            await f.transport.tamper(name, contents: original)
            #expect(try await reader.session.sync().applied == 1, "the untouched segment still applies")
        }

        /// Threat: A1, or another account, signs a genuine envelope with an Ed25519 key of its own. It verifies against
        /// nothing this account trusts, locked (the Keychain copy) or unlocked (the keyset).
        @Test("a segment signed by any key but the account's is refused, locked or unlocked")
        func foreignSigner() async throws {
            let f = try await Self.fixture()
            let genuine = try SignedObject.parse(try #require(await f.transport.allObjects[f.segmentName(1)]))
            let stranger = Keyset.generate(accountID: UUID())
            let location = SyncObjectLocation.segment(vaultID: f.vaultID, author: Self.deviceB, sequence: 1)
            let forged = SignedObject(
                signature: try stranger.sign(
                    VaultSession.syncSignedMessage(genuine.envelope, at: location), domain: .logSegment),
                envelope: genuine.envelope)
            await f.transport.tamper(location.name, contents: forged.serialized())
            for locked in [true, false] {
                let reader = try await f.reader(locked: locked)
                let report = try await reader.session.sync()
                #expect(report.rejected.map(\.reason) == [.keyring(.authenticationFailed)], "locked: \(locked)")
                #expect(try await reader.sync?.state.staged(vaultID: f.vaultID).isEmpty == true)
            }
        }

        /// Threat: A1 copies a genuine segment to another stream or a later number, to misattribute or replay it. The
        /// name is inside the signature, so every copy is refused at download, before any key is needed.
        @Test("a really signed segment moved to another name is refused while locked")
        func movedSegment() async throws {
            let f = try await Self.fixture()
            let original = try #require(await f.transport.allObjects[f.segmentName(1)])
            let destinations = [f.segmentName(2), f.segmentName(1, author: Self.deviceC)]
            for destination in destinations {
                await f.transport.tamper(destination, contents: original)
            }
            let reader = try await f.reader(locked: true)
            let report = try await reader.session.sync()
            #expect(Set(report.rejected.map(\.name)) == Set(destinations))
            let staged = try #require(try await reader.sync?.state.staged(vaultID: f.vaultID))
            #expect(staged.map(\.location.name) == [f.segmentName(1)])
        }

        /// Threat: an insider device, holding every key, publishes a validly sealed and signed segment whose entry for
        /// one item carries another item's envelope. AES-GCM's associated data binds the record's identity, so the
        /// swap is refused and neither item changes.
        @Test("an insider's record swap inside a validly signed segment is refused")
        func insiderRecordSwap() async throws {
            let f = try await Self.fixture()
            let target = try await f.b.session.save(
                Item(vaultID: f.vaultID, title: "Target", scopes: [], fields: []))
            let rows = try await f.b.store.records(in: f.vaultID, kind: .item)
            let donor = try #require(rows.first { $0.recordID != target.id })
            var entry = SyncEntry(try #require(rows.first { $0.recordID == target.id }))
            entry.envelope = donor.envelope
            entry.version += 10
            let payload = SyncPayload(
                kind: .segment, vaultID: f.vaultID, author: Self.deviceB, number: 2, vector: [:], entries: [entry])
            let envelope = try await f.b.session.syncSeal(payload.encoded(), at: payload.location)
            let signature = try await f.b.session.syncSign(envelope, at: payload.location)
            await f.transport.tamper(
                payload.location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())

            let report = try await f.a.session.sync()
            #expect(report.rejected.map(\.reason) == [.recordContextMismatch(target.id)])
            #expect(report.waiting[Self.deviceB] == 2)
            #expect(try await f.a.session.items().items.map(\.title) == ["Bank"])
        }

        /// Threat: the Keychain copy of the account key is gone (a restored device, a wiped Keychain), so a locked
        /// device has nothing to verify against. It must refuse rather than trust, and recover on the next unlock.
        @Test("with no trusted key in the Keychain, a locked download refuses everything until unlock")
        func missingKeychainKey() async throws {
            let f = try await Self.fixture()
            let reader = try await f.reader()
            let accountID = try #require(try await reader.session.status().accountID)
            await reader.session.lock()
            await reader.keychain.delete(.accountSigningKey(accountID: accountID))
            let locked = try await reader.session.sync()
            #expect(locked.rejected.map(\.reason) == [.keyring(.trustedKeyUnavailable)], "the report says why")
            #expect(try await reader.sync?.state.staged(vaultID: f.vaultID).isEmpty == true)

            try await reader.session.unlock(password: TestVault.password)
            #expect(await reader.keychain.contains(.accountSigningKey(accountID: accountID)))
            #expect(try await reader.session.sync().applied == 1)
        }

        /// Threat: A8, with the local sync state file, plants pending deletions of items that still exist — copies of
        /// their real rows, so the erasure summary would open — hoping the next sync publishes them as tombstones
        /// signed with the account key and erases the items on every device. Each row is unsigned, signed with garbage,
        /// signed by another key, or genuinely signed but for another device; none is published, and the items survive
        /// everywhere. A deletion the person makes is still published.
        @Test("a pending deletion planted in the local sync state is never published")
        func plantedPendingDeletion() async throws {
            let f = try await Self.fixture()
            try await f.a.session.sync()
            let rows = try await f.a.store.records(in: f.vaultID, kind: .item)
            let row = try #require(rows.first)
            let accountID = try #require(try await f.a.session.status().accountID)
            let deviceA = try #require(try await f.a.store.loadAccount()?.deviceID)
            let stamp = RecordStamp(version: row.version + 1, device: deviceA, deleted: true)
            let stranger = Keyset.generate(accountID: accountID)
            var foreign = PendingDeletion(stamp: stamp, record: row)
            foreign.authenticator = try stranger.sign(
                VaultSession.pendingDeletionMessage(foreign), domain: .pendingDeletion)
            // B's session signs its own deletion genuinely; copied into A's file it names the wrong device.
            let otherDevice = try await f.b.session.authenticatePendingDeletion(
                PendingDeletion(
                    stamp: RecordStamp(version: row.version + 1, device: Self.deviceB, deleted: true), record: row))
            let base = try #require(f.a.sync?.state)
            for planted in [
                PendingDeletion(stamp: stamp, record: row),
                PendingDeletion(stamp: stamp, record: row, authenticator: Array(repeating: 0x5A, count: 64)),
                foreign, otherDevice,
            ] {
                try await base.eraseAll()
                try await base.addPendingDeletion(planted)
                let report = try await f.a.session.sync(reconcile: true)
                #expect(report.pushedEntries == 0, "a planted deletion was published")
                try await f.b.session.sync()
                #expect(try await f.b.session.items().items.map(\.id) == [row.recordID])
            }

            try await f.a.session.trash(id: row.recordID)
            try await f.a.session.deletePermanently(id: row.recordID)
            let pending = try await base.pendingDeletions(vaultID: f.vaultID)
            #expect(pending[row.key]?.authenticator.isEmpty == false, "the session signs its own deletions")
            try await f.a.session.sync()
            try await f.b.session.sync()
            #expect(try await f.b.session.items().items.isEmpty, "the person's deletion still reaches B")
        }

        /// Threat: code that kept the sync adapter past a `lock()` (an engine mid-sync, a stray task) tries to use the
        /// keys. Every key operation goes back to the actor, which has zeroised them, and refuses.
        @Test("after lock, the sync adapter refuses every operation that needs a key")
        func adapterAfterLock() async throws {
            let f = try await Self.fixture()
            let adapter = VaultSyncAdapter(session: f.b.session)
            let row = try #require(try await f.b.store.records(in: f.vaultID, kind: .item).first)
            let location = SyncObjectLocation.segment(vaultID: f.vaultID, author: Self.deviceB, sequence: 9)
            _ = try await adapter.openItem(row)
            await f.b.session.lock()
            await #expect(throws: SyncKeyringError.locked) { try await adapter.openItem(row) }
            await #expect(throws: SyncKeyringError.locked) {
                try await adapter.sealItem(Item(vaultID: f.vaultID, title: "x", scopes: [], fields: []))
            }
            await #expect(throws: SyncKeyringError.locked) { try await adapter.seal([1, 2, 3], at: location) }
            await #expect(throws: SyncKeyringError.locked) { try await adapter.sign([1, 2, 3], at: location) }
        }

        /// Threat: an insider device signs an object in another device's stream. The account key would verify it, so
        /// the keyring refuses to sign as anyone but this device (the device registry, review finding D9, will make
        /// the check cryptographic).
        @Test("the keyring signs only as its own device")
        func signsOnlyAsItself() async throws {
            let f = try await Self.fixture()
            let elsewhere = SyncObjectLocation.segment(vaultID: f.vaultID, author: Self.deviceC, sequence: 1)
            await #expect(throws: SyncKeyringError.untrustedAuthor(Self.deviceC)) {
                try await f.b.session.syncSign([1, 2, 3], at: elsewhere)
            }
        }
    }
#endif
