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
/// AES-GCM under the vault key and signing them with the account's Ed25519 key and the device's own key, checked
/// against the device registry (docs/02-architecture.md §7.6, §7.8). The
/// "sync log" suite shows the engine checks the right things in the right order over fakes; this one shows the
/// real primitives are wired to those checks, so a forgery fails because the cryptography says so.
///
/// Adversaries (docs/02-architecture.md §2): **A1**, the sync store, holding no key; **an insider device** of the
/// account, holding every key; **a revoked or never-registered device**, which may hold the keyset (it knew the
/// password) but no registered device key; **A8**, the local-file attacker, who cannot reach the Keychain.
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

    /// Threat: A8, with the local sync state file, plants a stash row (ADR 0009) holding a deletion of a scan result
    /// (kind 10, an ignorable kind this version reads): no key, an erasure summary, a version within the vault's
    /// high water. Processed, it would erase the result here, be remembered as an erasure, and go out in this device's
    /// next snapshot as a tombstone signed with the account key, wiping the result across the household. Naming a
    /// revoked device as its carrier would take it past a shared vault's judge. The session signs the rows it writes,
    /// bound to the vault and the device, so a row it did not write — unsigned, signed by another key, or its own row
    /// of another vault — is refused, and the log is replayed instead; nothing in it is applied.
    @Test("a stash row planted in the local sync state is never processed")
    func plantedStashRow() async throws {
        let f = try await Self.fixture()
        try await f.a.session.sync()
        let rows = try await f.a.store.records(in: f.vaultID, kind: .item)
        let row = try #require(rows.first)
        var stash = SyncStash()
        stash.insert(
            .init(
                entry: UnknownSyncEntry(
                    recordID: row.recordID, rawKind: EnvelopeKind.scanStatus.rawValue, keyID: SyncPayload.zeroUUID,
                    version: row.version + 1, device: Self.deviceB, envelope: nil, erasure: [1, 2, 3]),
                author: Self.deviceB))
        let key = RecordKey(recordID: row.recordID, kind: .scanStatus)
        let base = try #require(f.a.sync?.state)
        let otherVault = UUID(uuidString: "0B0B0B0B-0000-4000-8000-00000000000B")!
        let genuineElsewhere = try await AuthenticatedSyncState(base: InMemorySyncStateStore(), session: f.a.session)
            .signedStash(stash.encoded(), vaultID: otherVault)
        for planted in [stash.encoded(), Array(repeating: 0x5A, count: 64) + stash.encoded(), genuineElsewhere] {
            try await base.saveStash(planted, vaultID: f.vaultID)
            let report = try await f.a.session.sync()
            #expect(report.unknownEntriesProcessed == 0, "a planted row was processed")
            #expect(await (try? base.loadState(vaultID: f.vaultID))??.erasures[key] == nil)
        }
    }

    /// Threat: A8, with the local sync state file and the record store while the app is locked, plants an *erasure*
    /// in the vault's state row for an item that exists (a summary claiming every device's edits, a stamp just above
    /// the row), deletes the item's row, and adds a made-up stream far enough ahead that this device is due a
    /// snapshot. Believed, the state would make this device seal and sign a snapshot carrying the tombstone, every
    /// other device would erase the item, and a reconciling sync would keep the planted erasure (review finding Z20).
    /// The state row is signed by the session like the stash and the pending deletions; one it did not write is no
    /// state, and the log is replayed, which puts the row back.
    @Test("an erasure planted in the local sync state signs no tombstone and erases nothing")
    func plantedErasure() async throws {
        let f = try await Self.fixture()
        try await f.a.session.sync()
        let row = try #require(try await f.a.store.records(in: f.vaultID, kind: .item).first)
        let deviceA = try #require(try await f.a.store.loadAccount()?.deviceID)
        let base = try #require(f.a.sync?.state as? InMemorySyncStateStore)
        var state = try #require(await base.loadState(vaultID: f.vaultID))
        let high = row.version + 1000
        let summary = try ItemErasure(
            seen: VersionVector([deviceA: high, Self.deviceB: high]), row: high, device: deviceA, date: nil
        ).summary()
        state.erasures[row.key] = Erasure(
            stamp: RecordStamp(version: high + 1, device: deviceA, deleted: true), summary: summary)
        state.merged[UUID()] = 300
        await base.tamper(state)
        try await f.a.store.commit(StoreChange(deletions: [row.key]))

        let report = try await f.a.session.sync()
        #expect(report.snapshotsWritten == 0, "a snapshot was signed from a planted state")
        #expect(await f.transport.allObjects.keys.allSatisfy { !$0.contains("/snapshot/") })
        try await f.b.session.sync()
        #expect(try await f.b.session.items().items.map(\.id) == [row.recordID], "the item was erased on B")
        #expect(try await f.a.session.items().items.map(\.id) == [row.recordID], "the replay put the row back")
        #expect(try await base.loadState(vaultID: f.vaultID)?.erasures.isEmpty == true)
    }

    /// Threat: A8 edits the same row's `merged` vector instead: another device of the account at 2^48, and a made-up
    /// stream to make this device due a snapshot. The snapshot's coverage and every segment's acknowledgement vector
    /// are taken from `merged`, so the forged number would be signed and published; each other device would take
    /// the coverage for its own stream, move its next sequence number to 2^48 + 1 and publish from then on under names
    /// every reader ignores, for good (Z20, Z21). No key and no insider is needed. The state row does not verify, so
    /// nothing in it is signed.
    @Test("a merged vector planted in the local sync state mutes no other device")
    func plantedMergedVector() async throws {
        let f = try await Self.fixture()
        try await f.a.session.sync()
        let base = try #require(f.a.sync?.state as? InMemorySyncStateStore)
        var state = try #require(await base.loadState(vaultID: f.vaultID))
        state.merged[Self.deviceB] = 1 << 48
        state.merged[UUID()] = 300
        await base.tamper(state)

        try await f.a.session.sync()
        try await f.b.session.sync()
        let later = try await f.b.session.save(Item(vaultID: f.vaultID, title: "Later", scopes: [], fields: []))
        let published = try await f.b.session.sync()
        #expect(published.pushedEntries == 1)
        let stateB = try #require(try await f.b.sync?.state.loadState(vaultID: f.vaultID))
        #expect(stateB.nextSequence < 16, "B's next sequence number was moved to \(stateB.nextSequence)")
        let reader = try await f.reader()
        try await reader.session.sync()
        #expect(try await reader.session.items().items.map(\.id).contains(later.id), "B's later edit never arrived")
    }

    /// Threat: A8 copies a state row this session genuinely signed to where it does not belong: another vault's row.
    /// The signature covers the vault and this device, so it is no state there either.
    @Test("a sync state row signed for one vault is no state for another")
    func stateRowOfAnotherVault() async throws {
        let f = try await Self.fixture()
        try await f.a.session.sync()
        let work = try await f.a.session.createVault(name: "Work")
        try await f.a.session.sync()
        let base = try #require(f.a.sync?.state as? InMemorySyncStateStore)
        let signed = AuthenticatedSyncState(base: base, session: f.a.session)
        var moved = try #require(await base.loadState(vaultID: f.vaultID))
        #expect(try await signed.loadState(vaultID: f.vaultID) != nil, "the session's own row verifies")
        moved.vaultID = work.id
        await base.tamper(moved)
        #expect(try await signed.loadState(vaultID: work.id) == nil)
        // And one with any field changed after signing.
        var edited = try #require(await base.loadState(vaultID: f.vaultID))
        edited.nextSequence += 1
        await base.tamper(edited)
        #expect(try await signed.loadState(vaultID: f.vaultID) == nil)
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

    /// Threat: an insider device signs an object in another device's stream. The keyring refuses to sign as anyone
    /// but this device; `insiderCannotWriteAsAnotherDevice` shows a device that signs anyway is refused by the
    /// others, because each device's signature is checked against its own key in the registry (D9).
    @Test("the keyring signs only as its own device")
    func signsOnlyAsItself() async throws {
        let f = try await Self.fixture()
        let elsewhere = SyncObjectLocation.segment(vaultID: f.vaultID, author: Self.deviceC, sequence: 1)
        await #expect(throws: SyncKeyringError.untrustedAuthor(Self.deviceC)) {
            try await f.b.session.syncSign([1, 2, 3], at: elsewhere)
        }
    }

    // MARK: - The device registry (review findings D9, Y5, Y6)

    /// An object B's session sealed for `location`, with the message its signatures must cover.
    static func sealed(_ f: Fixture, at location: SyncObjectLocation, entries: [SyncEntry] = []) async throws
        -> (envelope: [UInt8], message: [UInt8])
    {
        let payload = SyncPayload(
            kind: location.kind, vaultID: location.vaultID, author: location.author, number: location.number,
            vector: [:], entries: entries)
        let envelope = try await f.b.session.syncSeal(payload.encoded(), at: location)
        return (envelope, VaultSession.syncSignedMessage(envelope, at: location))
    }

    /// Threat: someone who opened the keyset once — a device since revoked, a thief who knew the password — holds
    /// the account's Ed25519 key and every vault key, but no registered device key (review findings D9, Y5). They
    /// write a validly sealed segment in a registered device's stream, signed with the account key alone, or with a
    /// device key of their own. Every device refuses it at download, locked or unlocked.
    @Test("the account key alone does not write: a registered device's own signature is needed too")
    func keysetAloneCannotWrite() async throws {
        let f = try await Self.fixture()
        let keys = try #require(await f.b.session.keys)
        let location = SyncObjectLocation.segment(vaultID: f.vaultID, author: Self.deviceB, sequence: 2)
        let (envelope, message) = try await Self.sealed(f, at: location)
        let accountSignature = try keys.keyset.sign(message, domain: .logSegment)
        var generator = SeededGenerator(seed: 404)
        let own = SoftwareDeviceKey.generate(using: &generator)
        let ownSignature = try own.sign(
            prepared: DeviceSignatures.signedBytes(domain: .logSegment, deviceID: Self.deviceB, message: message))
        let forgeries = [
            accountSignature,
            DualSignature.encode(account: accountSignature, device: ownSignature),
            DualSignature.encode(account: accountSignature, device: [UInt8](repeating: 0, count: 64)),
            DualSignature.encode(account: accountSignature, device: accountSignature),
        ]
        for locked in [true, false] {
            let reader = try await f.reader(locked: locked)
            for forged in forgeries {
                await f.transport.tamper(
                    location.name, contents: SignedObject(signature: forged, envelope: envelope).serialized())
                let report = try await reader.session.sync()
                #expect(
                    report.rejected.map(\.name) == [location.name]
                        && report.rejected.map(\.reason) == [.keyring(.authenticationFailed)], "locked: \(locked)")
                let staged = try #require(try await reader.sync?.state.staged(vaultID: f.vaultID))
                #expect(!staged.contains { $0.location == location })
            }
        }
    }

    /// Threat: A2 or A8 with this device's Keychain but not the account password: the device's signing key (held in
    /// software until the Secure Enclave adapter exists), and no account key. A device signature without the
    /// account's is refused.
    @Test("a device key alone does not write either: the account key's signature is needed too")
    func deviceKeyAloneCannotWrite() async throws {
        let f = try await Self.fixture()
        let accountID = try #require(try await f.b.session.status().accountID)
        let deviceKey = try #require(await f.b.extractedDeviceKey(accountID: accountID))
        let location = SyncObjectLocation.segment(vaultID: f.vaultID, author: Self.deviceB, sequence: 2)
        let (envelope, message) = try await Self.sealed(f, at: location)
        let deviceSignature = try deviceKey.sign(
            prepared: DeviceSignatures.signedBytes(domain: .logSegment, deviceID: Self.deviceB, message: message))
        let stranger = Keyset.generate(accountID: accountID)
        let forgeries = [
            DualSignature.encode(account: [UInt8](repeating: 0, count: 64), device: deviceSignature),
            DualSignature.encode(account: try stranger.sign(message, domain: .logSegment), device: deviceSignature),
            DualSignature.encode(account: deviceSignature, device: deviceSignature),
        ]
        let reader = try await f.reader(locked: true)
        for forged in forgeries {
            await f.transport.tamper(
                location.name, contents: SignedObject(signature: forged, envelope: envelope).serialized())
            #expect(try await reader.session.sync().rejected.map(\.reason) == [.keyring(.authenticationFailed)])
        }
    }

    /// Threat: an insider device of the account, registered and holding every key, writes a segment in another
    /// device's stream, signing with its own device key — as itself, and as the other device. The other device's
    /// signature is checked against the other device's key.
    @Test("a registered device cannot write in another device's stream")
    func insiderCannotWriteAsAnotherDevice() async throws {
        let f = try await Self.fixture()
        // C is registered and has said so; it is its stream B writes in.
        try await f.reader().session.sync()
        try await f.a.session.sync()
        let accountID = try #require(try await f.b.session.status().accountID)
        let keys = try #require(await f.b.session.keys)
        let deviceKey = try #require(await f.b.extractedDeviceKey(accountID: accountID))
        let location = SyncObjectLocation.segment(vaultID: f.vaultID, author: Self.deviceC, sequence: 1)
        let (envelope, message) = try await Self.sealed(f, at: location)
        let accountSignature = try keys.keyset.sign(message, domain: .logSegment)
        for signer in [Self.deviceB, Self.deviceC] {
            let device = try deviceKey.sign(
                prepared: DeviceSignatures.signedBytes(domain: .logSegment, deviceID: signer, message: message))
            await f.transport.tamper(
                location.name,
                contents: SignedObject(
                    signature: DualSignature.encode(account: accountSignature, device: device), envelope: envelope
                ).serialized())
            let report = try await f.a.session.sync()
            #expect(report.rejected.map(\.reason) == [.keyring(.authenticationFailed)])
            #expect(report.waiting[Self.deviceC] == 1)
        }
    }

    /// Threat: a device that was revoked — lost, stolen, sold — and still holds every key it ever had, its own
    /// registered device key included, keeps writing: a segment and a snapshot, both validly sealed and signed. From
    /// the moment a device knows of the revocation it refuses both, while locked as while unlocked, and what the
    /// revoked device wrote before reaches a device that lacks it through a snapshot written by a trusted one.
    @Test("a revoked device's segments and snapshots are refused, locked or unlocked")
    func revokedDevice() async throws {
        let f = try await Self.fixture()
        try await f.a.session.sync()
        try await f.a.session.revokeDevice(Self.deviceB, password: .keepPassword(current: TestVault.password))
        // B does not know yet, and writes on.
        try await f.b.session.save(
            Item(vaultID: f.vaultID, title: "Planted after revocation", scopes: [], fields: []))
        let snapshot = SyncObjectLocation.snapshot(vaultID: f.vaultID, author: Self.deviceB, lamport: 99)
        let (envelope, _) = try await Self.sealed(f, at: snapshot)
        let signature = try await f.b.session.syncSign(envelope, at: snapshot)
        await f.transport.tamper(
            snapshot.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())
        let segment = SyncObjectLocation.segment(vaultID: f.vaultID, author: Self.deviceB, sequence: 2)
        let (laterEnvelope, _) = try await Self.sealed(f, at: segment)
        let laterSignature = try await f.b.session.syncSign(laterEnvelope, at: segment)
        await f.transport.tamper(
            segment.name, contents: SignedObject(signature: laterSignature, envelope: laterEnvelope).serialized())
        // A hands on what it had merged from B before revoking it.
        #expect(try await f.a.session.sync().snapshotsWritten == 1)

        for locked in [true, false] {
            let reader = try await f.reader(locked: locked)
            let report = try await reader.session.sync()
            #expect(report.retiredObjects == 3, "B's two segments and its snapshot are not read")
            #expect(report.rejected.isEmpty && report.waiting.isEmpty)
            // And the keyring itself says no, whoever asks.
            for (location, object) in [(snapshot, (signature, envelope)), (segment, (laterSignature, laterEnvelope))] {
                await #expect(throws: SyncKeyringError.untrustedAuthor(Self.deviceB), "locked: \(locked)") {
                    try await reader.session.syncVerify(object.0, over: object.1, at: location)
                }
            }
            if locked { try await reader.session.unlock(password: TestVault.password) }
            try await reader.session.sync()
            #expect(
                try await reader.session.items().items.map(\.title) == ["Bank"],
                "what B wrote before it was revoked arrives through A's snapshot; what it wrote after never does")
        }
    }

    /// Threat: A1 withholds a device's registration from the others. Its segments are then from a device nobody
    /// knows: refused, the stream waits, and nothing is lost — when the registration arrives, they are merged.
    @Test("a device whose registration the store withholds is not trusted until it arrives; then nothing is lost")
    func withheldRegistration() async throws {
        let f = try await Self.fixture()
        let objects = await f.transport.allObjects
        let registration = try #require(
            objects.first { name, bytes in
                guard name.contains("/registry/"), let entry = try? RegistryEntry.parse(bytes),
                    case .add(let device) = entry.body
                else { return false }
                return device.id == Self.deviceB
            })
        await f.transport.tamper(registration.key, contents: nil)
        let withheld = try await f.a.session.sync()
        #expect(withheld.rejected.map(\.reason) == [.keyring(.untrustedAuthor(Self.deviceB))])
        #expect(withheld.waiting[Self.deviceB] == 1 && withheld.applied == 0)

        await f.transport.tamper(registration.key, contents: registration.value)
        #expect(try await f.a.session.sync().applied == 1)
        #expect(try await f.a.session.items().items.map(\.title) == ["Bank"])
    }

    /// Threat: an insider device, holding the keys of two of the account's vaults, publishes a validly sealed and
    /// signed segment in one vault's log that carries the other vault's item and the other vault's description.
    /// Each record's own authenticated context names its vault, so neither crosses; and A1 copying a whole log
    /// object from one vault's log to the other's is refused by the signature over the name.
    @Test("records, and a vault's description, do not cross from one vault to another")
    func recordsDoNotCrossVaults() async throws {
        let f = try await Self.fixture()
        try await f.a.session.sync()
        let work = try await f.b.session.createVault(name: "Work")
        try await f.b.session.save(Item(vaultID: work.id, title: "Payroll", scopes: [], fields: []))
        try await f.b.session.sync()
        let foreign =
            try await f.b.store.records(in: work.id, kind: .item)
            + (try await f.b.store.records(in: work.id, kind: .vaultMetadata))
        #expect(foreign.count == 2)

        for (offset, row) in foreign.enumerated() {
            let location = SyncObjectLocation.segment(
                vaultID: f.vaultID, author: Self.deviceB, sequence: UInt64(2 + offset))
            let (envelope, _) = try await Self.sealed(f, at: location, entries: [SyncEntry(row)])
            let signature = try await f.b.session.syncSign(envelope, at: location)
            await f.transport.tamper(
                location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())
        }
        let report = try await f.a.session.syncAll()
        #expect(
            report.vaults[f.vaultID]?.rejected.map(\.reason) == [.recordContextMismatch(foreign[0].recordID)],
            "the stream stops at the first; the second is never applied over the gap")
        #expect(try await f.a.session.items(in: f.vaultID).items.map(\.title) == ["Bank"])
        #expect(try await f.a.session.vaults().map(\.name) == ["Personal", "Work"])

        // A1: a genuine object of the Work vault's log, copied into the Personal vault's.
        let genuine = SyncObjectLocation.segment(vaultID: work.id, author: Self.deviceB, sequence: 1)
        let copy = SyncObjectLocation.segment(vaultID: f.vaultID, author: Self.deviceB, sequence: 2)
        await f.transport.tamper(copy.name, contents: try #require(await f.transport.allObjects[genuine.name]))
        let moved = try await f.a.session.syncAll()
        #expect(moved.vaults[f.vaultID]?.rejected.map(\.reason) == [.keyring(.authenticationFailed)])
    }
}
