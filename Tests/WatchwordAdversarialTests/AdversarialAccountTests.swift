import Foundation
import SecureMemory
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordKit
@testable import WatchwordSync

/// Everything a second device takes from the sync transport before it holds a key — the account header, the device
/// registry, the vault directory — and everything an existing device takes from it afterwards, attacked
/// (docs/02-architecture.md §7.7, §7.8; PRD F5.2, F10.2; review findings D9, Y5, Y6).
///
/// Adversaries (docs/02-architecture.md §2): **A1**, the sync store, holding every object and no key; **A8**, with
/// the local database file but not the Keychain; **a revoked device**, which opened the keyset while it was the
/// person's and so still holds the account key, every vault key it had, its own (now revoked) device key and the
/// Account Unlock Key of the password it knew; **an insider device**, registered and unlocked, in hands that do
/// not know the account password.
@Suite("Adversarial: account enrolment and device registry", .tags(.adversarial))
struct AdversarialAccountTests {
    static let deviceB = UUID(uuidString: "D0000000-0000-4000-8000-0000000000B0")!
    static let deviceC = UUID(uuidString: "D0000000-0000-4000-8000-0000000000C0")!
    static let deviceX = UUID(uuidString: "D0000000-0000-4000-8000-0000000000E0")!
    static let newPassword = "an entirely different passphrase"

    struct Fixture {
        let transport: InMemorySyncTransport
        let a: TestVault
        let kit: EmergencyKit
        let personal: UUID

        var accountID: UUID { kit.accountID }

        /// A device that has not joined anything yet.
        func fresh(seed: UInt64 = 23) -> TestVault {
            TestVault.syncing(over: transport, seed: seed, name: "New device")
        }

        /// A device enrolled from the transport, unlocked, its registration published.
        func enrolled(_ id: UUID, password: String = TestVault.password) async throws -> TestVault {
            let device = try await a.enrolledDevice(deviceID: id, over: transport, password: password)
            try await device.session.unlock(password: password)
            try await device.session.sync()
            try await a.session.sync()
            return device
        }

        func headerNames() async -> [String] {
            await transport.list(prefix: AccountObjectLocation.headerPrefix(accountID))
        }

        func registryView(_ device: TestVault) async throws -> RegistryView {
            await device.session.invalidateRegistry()
            return try await device.session.registry(try #require(await device.session.account))
        }

        func plant(_ entry: RegistryEntry) async {
            await transport.tamper(
                AccountObjectLocation.registryEntry(accountID: accountID, id: entry.id.hex).name,
                contents: entry.serialized())
        }
    }

    /// A creates the account, saves one item and syncs: the header, the registry and the directory are published.
    static func fixture(seed: UInt64 = 7) async throws -> Fixture {
        let transport = InMemorySyncTransport()
        let a = TestVault.syncing(over: transport, seed: seed, name: "First device")
        let kit = try await a.createAccount()
        let personal = try #require(await a.session.personalVaultID)
        try await a.session.save(
            Item(
                vaultID: personal, title: "Bank", scopes: [ServiceScope(host: "firstbank.co.uk")],
                fields: [Field(kind: .password, label: "Password", value: "account-secret")]))
        try await a.session.sync()
        return Fixture(transport: transport, a: a, kit: kit, personal: personal)
    }

    // MARK: - The account header (A1)

    /// Threat: A1 rewrites the published header's KDF parameters, to weaken the derivation of a device that enrols
    /// (fewer iterations, a short salt: SEC5) or to make its enrolment hang (iterations beyond any device's reach:
    /// SEC9). The parameters are bounded on both sides when the header is parsed, before any derivation — which the
    /// last case shows by finishing at all.
    @Test("a header whose KDF parameters are out of bounds is refused before any derivation (SEC5, SEC9)")
    func headerKDFBounds() async throws {
        let f = try await Self.fixture()
        let name = try #require(await f.headerNames().first)
        let genuine = try AccountHeaderObject.parse(try #require(await f.transport.allObjects[name]))
        let floor = KDFParameters.minimumIterations
        let ceiling = KDFParameters.maximumIterations
        let cases: [(AccountFormatError, (inout AccountHeaderObject) -> Void)] = [
            (.kdf(.iterationsBelowMinimum(floor - 1, minimum: floor)), { $0.kdf.iterations = floor - 1 }),
            (.kdf(.iterationsBelowMinimum(1, minimum: floor)), { $0.kdf.iterations = 1 }),
            (.kdf(.iterationsAboveMaximum(ceiling + 1, maximum: ceiling)), { $0.kdf.iterations = ceiling + 1 }),
            (.kdf(.iterationsAboveMaximum(.max, maximum: ceiling)), { $0.kdf.iterations = .max }),
            (.kdf(.saltTooShort(8, minimum: 16)), { $0.salt = Array($0.salt.prefix(8)) }),
        ]
        for (expected, edit) in cases {
            var header = genuine
            edit(&header)
            let bytes = header.serialized()
            #expect(throws: expected) { try AccountHeaderObject.parse(bytes) }
            await f.transport.tamper(name, contents: bytes)
            let device = f.fresh()
            await #expect(throws: CryptoError.authenticationFailed) {
                try await device.session.enrol(password: TestVault.password, secretKey: f.kit.setupCode)
            }
            #expect(try await device.session.state() == .noAccount)
        }
    }

    /// Threat: A1 flips a byte anywhere in the published header: the salt, the wrapped keyset, the genesis entry it
    /// names, which vault is the personal one, a signature. Nothing but the genuine header enrols a device.
    @Test("a byte flipped anywhere in the published header stops enrolment; the genuine header still enrols")
    func headerByteFlips() async throws {
        let f = try await Self.fixture()
        let name = try #require(await f.headerNames().first)
        let original = try #require(await f.transport.allObjects[name])
        for position in stride(from: 0, to: original.count, by: max(1, original.count / 24)) {
            var tampered = original
            tampered[position] ^= 0x01
            await f.transport.tamper(name, contents: tampered)
            let device = f.fresh()
            await #expect(throws: (any Error).self, "flip at \(position) enrolled a device") {
                try await device.session.enrol(password: TestVault.password, secretKey: f.kit.setupCode)
            }
            #expect(try await device.session.state() == .noAccount)
            #expect(await device.keychain.raw(.secretKey(accountID: f.accountID)) == nil)
        }
        await f.transport.tamper(name, contents: original)
        let device = f.fresh()
        try await device.session.enrol(password: TestVault.password, secretKey: f.kit.setupCode)
        #expect(try await device.session.state() == .unlocked)
    }

    /// Threat: A1, or another account's owner who can write to this store, puts another account's header (their
    /// own, whose password they know) where this account's belongs, hoping a new device ends up holding their
    /// keyset and writes the person's passwords under keys they hold. As it is, and relabelled with this account's
    /// ID, it opens for nobody: the keyset and the binding are sealed to the account they were made for.
    @Test("another account's header in this account's place enrols nobody")
    func substitutedAccount() async throws {
        let f = try await Self.fixture()
        let attacker = try await Self.fixture(seed: 1234)
        #expect(attacker.accountID != f.accountID)
        let name = try #require(await f.headerNames().first)
        let foreignName = try #require(await attacker.headerNames().first)
        let foreign = try AccountHeaderObject.parse(try #require(await attacker.transport.allObjects[foreignName]))
        var relabelled = foreign
        relabelled.accountID = f.accountID
        // Under the genuine header's name, and under the name the foreign header would have in this account.
        let fitting = AccountObjectLocation.header(
            accountID: f.accountID, generation: foreign.generation, author: foreign.author
        ).name
        for header in [foreign, relabelled] {
            await f.transport.tamper(name, contents: header.serialized())
            await f.transport.tamper(fitting, contents: header.serialized())
            for (password, secretKey) in [
                (TestVault.password, f.kit.secretKey), (TestVault.password, attacker.kit.secretKey),
            ] {
                let device = f.fresh()
                await #expect(throws: CryptoError.authenticationFailed) {
                    try await device.session.enrol(password: password, secretKey: secretKey, accountID: f.accountID)
                }
                #expect(try await device.session.state() == .noAccount)
            }
        }
    }

    /// Threat: A1 keeps the header from before a password change and presents it later. Beside the current header
    /// it is ignored. In its place, the current password opens nothing, and the old password — if the person types
    /// it — is refused, because the registry shows the change. Only a store that also withholds the registry's
    /// record of the change can show a device the account as it was; that device then holds nothing newer than
    /// that state, and from the moment it sees the change it refuses the old password like every other device.
    @Test("a replayed older header weakens nothing")
    func replayedHeader() async throws {
        let f = try await Self.fixture()
        let oldName = try #require(await f.headerNames().first)
        let oldHeader = try #require(await f.transport.allObjects[oldName])
        try await f.a.session.changePassword(current: TestVault.password, new: Self.newPassword)
        try await f.a.session.sync()
        let newName = try #require(await f.headerNames().first)
        #expect(await f.headerNames() == [newName] && newName != oldName, "the superseded header is removed")
        let newHeader = try #require(await f.transport.allObjects[newName])

        // Beside the current header.
        await f.transport.tamper(oldName, contents: oldHeader)
        let beside = f.fresh(seed: 31)
        try await beside.session.enrol(password: Self.newPassword, secretKey: f.kit.setupCode)
        #expect(await beside.session.account?.credentialGeneration == 1)

        // In its place.
        await f.transport.tamper(newName, contents: nil)
        let current = f.fresh(seed: 32)
        await #expect(throws: CryptoError.authenticationFailed) {
            try await current.session.enrol(password: Self.newPassword, secretKey: f.kit.setupCode)
        }
        let stale = f.fresh(seed: 33)
        await #expect(throws: VaultError.passwordSuperseded) {
            try await stale.session.enrol(password: TestVault.password, secretKey: f.kit.setupCode)
        }
        #expect(try await stale.session.state() == .noAccount)

        // With the registry's record of the change withheld too: the account as it was.
        let objects = await f.transport.allObjects
        let change = try #require(
            objects.first { name, bytes in
                guard name.contains("/registry/"), let entry = try? RegistryEntry.parse(bytes) else { return false }
                if case .credential = entry.body { return true }
                return false
            })
        await f.transport.tamper(change.key, contents: nil)
        let past = f.fresh(seed: 34)
        try await past.session.enrol(password: TestVault.password, secretKey: f.kit.setupCode)
        // The store can keep that up only by withholding. Once the change is visible, the old password is refused
        // here as everywhere, nothing this device wrote in between was accepted by the others, and the new password
        // makes it a device of the account.
        await f.transport.tamper(change.key, contents: change.value)
        await f.transport.tamper(newName, contents: newHeader)
        let told = try await past.session.syncAll()
        #expect(told.awaitingNewPassword && told.combined.segmentsWritten == 0)
        try await f.a.session.sync()
        let pastID = try #require(await past.session.account?.deviceID)
        #expect(try await f.registryView(f.a).state.standing(of: pastID) == .unknown)
        await past.session.lock()
        await #expect(throws: VaultError.passwordChangedOnAnotherDevice) {
            try await past.session.unlock(password: TestVault.password)
        }
        try await past.session.unlock(password: Self.newPassword)
        try await past.session.sync()
        try await f.a.session.sync()
        #expect(try await f.registryView(f.a).state.standing(of: pastID) == .active)
    }

    /// Threat: A8 puts back the account header the local file held before a password change (with the old wrapped
    /// keyset, which the old password opens), so that a password the person retired — perhaps because someone
    /// learned it — unlocks this device again. The Keychain remembers which credential generation the device already
    /// follows, and the keyset's own wrap says which generation it belongs to.
    @Test("a local account header rolled back to before a password change is refused, even with the old password")
    func localHeaderRollback() async throws {
        let f = try await Self.fixture()
        let store = try #require(f.a.store as? InMemoryRecordStore)
        let oldAccount = try #require(await store.loadAccount())
        let oldHeader = try #require(await store.record(VaultSession.headerKey(f.accountID)))
        try await f.a.session.changePassword(current: TestVault.password, new: Self.newPassword)
        await f.a.session.lock()

        await store.tamper(account: oldAccount)
        await store.tamper(oldHeader)
        // As it was; then with the registry's entries deleted too, so nothing in the file records the change; then
        // with the generation column left at its new value, so the row looks current.
        var relabelled = oldAccount
        relabelled.credentialGeneration += 1
        let registry = await store.records(in: f.accountID, kind: .deviceRegistry)
        for variant in 0..<3 {
            if variant == 1 { try await store.commit(StoreChange(deletions: registry.map(\.key))) }
            if variant == 2 { await store.tamper(account: relabelled) }
            let relaunched = f.a.relaunched()
            await #expect(throws: VaultError.accountHeaderRolledBack, "variant \(variant)") {
                try await relaunched.session.unlock(password: TestVault.password)
            }
            #expect(try await relaunched.session.state() == .locked)
            await #expect(throws: VaultError.locked) { try await relaunched.session.items() }
        }
    }

    /// Threat: A1 fills the header prefix with objects that are not headers, or are headers that open for nobody,
    /// all named as newer than the real one, so that a device spends its few key derivations on them. What does not
    /// parse costs nothing.
    @Test("planted objects among the headers do not use up a new device's derivations")
    func plantedHeaders() async throws {
        let f = try await Self.fixture()
        for generation in 1...20 {
            await f.transport.tamper(
                AccountObjectLocation.header(
                    accountID: f.accountID, generation: UInt64(generation), author: Self.deviceX
                ).name, contents: [UInt8](repeating: UInt8(generation), count: 300))
        }
        let device = f.fresh()
        try await device.session.enrol(password: TestVault.password, secretKey: f.kit.setupCode)
        #expect(try await device.session.state() == .unlocked)
        // An existing device does not even fetch them: it wants only headers the registry announces.
        let report = try await f.a.session.syncAll()
        #expect(report.account.candidateHeadersFetched == 0 && !report.awaitingNewPassword)
    }

    // MARK: - The device registry

    /// Threat: A1 writes registry entries of its own — a device added, a device revoked, a second genesis — signed
    /// with a key it made, and junk under an entry's name. None is signed by the account key, so none is admitted:
    /// not stored, not counted, not passed on.
    @Test("registry entries the account key did not sign are never admitted")
    func forgedRegistryEntries() async throws {
        let f = try await Self.fixture()
        var stranger = RegistryFixture(seed: 66, accountID: f.accountID)
        let view = try await f.registryView(f.a)
        let own = try #require(await f.a.session.account?.deviceID)
        let genesis = stranger.genesis(device: Self.deviceX)
        let forged = [
            genesis,
            stranger.signed(
                RegistryEntry(
                    accountID: f.accountID, parents: view.state.heads, author: .device(Self.deviceX),
                    body: .add(stranger.certificate(Self.deviceX)))),
            stranger.signed(
                RegistryEntry(
                    accountID: f.accountID, parents: view.state.heads, author: .device(own), body: .revoke(own))),
        ]
        for entry in forged { await f.plant(entry) }
        let misnamed = AccountObjectLocation.registryEntry(
            accountID: f.accountID, id: ObjectDigest(hashing: [1]).hex
        ).name
        await f.transport.tamper(misnamed, contents: try #require(view.entries.values.first).serialized())

        let store = try #require(f.a.store as? InMemoryRecordStore)
        let before = await store.records(in: f.accountID, kind: .deviceRegistry).count
        let report = try await f.a.session.syncAll()
        #expect(report.account.registryEntriesFetched == 0)
        #expect(report.account.rejected.count == 4)
        #expect(await store.records(in: f.accountID, kind: .deviceRegistry).count == before)
        #expect(try await f.a.session.deviceStanding() == .active)
        #expect(try await f.a.session.devices().count == 1)
        // And a device enrolling from this store is not taken in by them either.
        let device = f.fresh()
        try await device.session.enrol(password: TestVault.password, secretKey: f.kit.setupCode)
        #expect(try await device.session.devices().map(\.isRevoked) == [false, false])
    }

    /// Threat: a revoked device that kept the account key writes a whole registry of its own: a second genesis
    /// entry naming itself, validly signed by the account key, with a device added under it. An existing device
    /// trusts only the genesis entry its Keychain anchor names; a new one only the entry the header's binding
    /// names, which nobody without the current password can make.
    @Test("a second genesis entry, signed with the real account key, is nobody's registry")
    func secondGenesis() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        let keyset = try #require(await b.session.keys).keyset
        var generator = SeededGenerator(seed: 808)
        let rogueKey = SoftwareDeviceKey.generate(using: &generator)
        let rogueUnlock = EncryptionKey.generate(using: &generator)
        var genesis = RegistryEntry(
            accountID: f.accountID, parents: [], author: .device(Self.deviceX),
            body: .genesis(
                accountSigningKey: try keyset.publicKeyBundle().signingKey,
                device: RegistryDevice(id: Self.deviceX, key: try rogueKey.publicKey(), label: []),
                enrolmentKey: try EnrolmentKey.derive(from: rogueUnlock, accountID: f.accountID).publicKey()))
        genesis.accountSignature = try keyset.sign(genesis.accountMessage, domain: .deviceRegistry)
        genesis.authorSignature = try rogueKey.sign(
            prepared: DeviceSignatures.signedBytes(
                domain: .deviceRegistry, deviceID: Self.deviceX, message: genesis.deviceMessage))
        var revoke = RegistryEntry(
            accountID: f.accountID, parents: [genesis.id], author: .device(Self.deviceX), body: .revoke(Self.deviceB))
        revoke.accountSignature = try keyset.sign(revoke.accountMessage, domain: .deviceRegistry)
        revoke.authorSignature = try rogueKey.sign(
            prepared: DeviceSignatures.signedBytes(
                domain: .deviceRegistry, deviceID: Self.deviceX, message: revoke.deviceMessage))
        await f.plant(genesis)
        await f.plant(revoke)

        try await f.a.session.sync()
        let view = try await f.registryView(f.a)
        #expect(view.state.standing(of: Self.deviceX) == .unknown)
        #expect(view.state.standing(of: Self.deviceB) == .active)
        #expect(!view.state.connectedEntries.contains(genesis.id))
        let device = f.fresh()
        try await device.session.enrol(password: TestVault.password, secretKey: f.kit.setupCode)
        let enrolledView = try await f.registryView(device)
        #expect(enrolledView.state.standing(of: Self.deviceX) == .unknown)
        #expect(enrolledView.state.standing(of: Self.deviceB) == .active)
        #expect(enrolledView.state.genesis == view.state.genesis)
    }

    /// What a revoked device that kept everything can write: entries signed by the account key and by its own
    /// device key, and — while it knows the password — by the enrolment key. All of them name only parents from
    /// before its revocation, as if written then.
    static func rogueEntries(from lost: TestVault, targeting victim: UUID) async throws -> (
        sameDevice: RegistryEntry, sameKey: RegistryEntry, newDevice: RegistryEntry, revocation: RegistryEntry,
        newDeviceID: UUID
    ) {
        let session = lost.session
        let account = try #require(await session.account)
        let keys = try #require(await session.keys)
        let view = try await session.registry(account)
        let own = try #require(view.state.devices[account.deviceID])
        let parents = view.state.heads
        let certificate = RegistryDevice(id: own.id, key: own.key, label: [])
        let sameDevice = try await session.signedRegistryEntry(
            parents: parents, author: .device(own.id), body: .add(certificate), account: account,
            keyset: keys.keyset)
        let renamed = UUID(uuidString: "D0000000-0000-4000-8000-0000000000E1")!
        let sameKey = try await session.signedRegistryEntry(
            parents: parents, author: .device(own.id),
            body: .add(RegistryDevice(id: renamed, key: own.key, label: [])), account: account, keyset: keys.keyset)
        // A device of its own, with a fresh key, registered with the password it knows.
        var generator = SeededGenerator(seed: 909)
        let freshKey = SoftwareDeviceKey.generate(using: &generator)
        let newDeviceID = UUID(uuidString: "D0000000-0000-4000-8000-0000000000E2")!
        let enrolment = EnrolmentKey.derive(from: keys.accountUnlockKey, accountID: account.accountID)
        let newDevice = try await session.signedRegistryEntry(
            parents: parents, author: .enrolment(credential: view.state.credential.id),
            body: .add(RegistryDevice(id: newDeviceID, key: try freshKey.publicKey(), label: [])), account: account,
            keyset: keys.keyset, enrolment: enrolment)
        let revocation = try await session.signedRegistryEntry(
            parents: parents, author: .device(own.id), body: .revoke(victim), account: account, keyset: keys.keyset)
        return (sameDevice, sameKey, newDevice, revocation, newDeviceID)
    }

    /// Threat: the revoked device described above, after a revocation made **with a password change**. It
    /// registers itself again under its ID, under a new ID with its old key, and as a new device with the enrolment
    /// key of the password it knows; and it "revokes" the device that revoked it, back-dated. On every device that
    /// follows the new password, none of it counts: the revocation is behind a checkpoint.
    @Test("a revoked device cannot register again or back-date its way out, once the password has changed")
    func revokedDeviceCannotReturn() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        let lost = try await f.enrolled(Self.deviceX)
        let deviceA = try #require(await f.a.session.account?.deviceID)
        let rogue = try await Self.rogueEntries(from: lost, targeting: deviceA)

        try await f.a.session.revokeDevice(
            Self.deviceX, password: .change(current: TestVault.password, new: Self.newPassword))
        try await f.a.session.sync()
        for entry in [rogue.sameDevice, rogue.sameKey, rogue.newDevice, rogue.revocation] { await f.plant(entry) }

        // B has not been given the new password: it reads, and neither merges nor publishes, so nothing the revoked
        // device does in the meantime reaches the vault through it.
        let waiting = try await b.session.syncAll()
        #expect(waiting.awaitingNewPassword && waiting.combined.applied == 0)
        await b.session.lock()
        try await b.session.unlock(password: Self.newPassword)
        try await b.session.sync()
        try await f.a.session.sync()

        for device in [f.a, b] {
            let state = try await f.registryView(device).state
            #expect(state.standing(of: Self.deviceX) == .revoked)
            #expect(state.standing(of: deviceA) == .active && state.standing(of: Self.deviceB) == .active)
            #expect(state.standing(of: rogue.newDeviceID) == .unknown)
            #expect(Set(state.devices.keys) == [deviceA, Self.deviceB])
            for entry in [rogue.sameDevice, rogue.sameKey, rogue.newDevice, rogue.revocation] {
                #expect(!state.validEntries.contains(entry.id))
            }
        }
        // A device that enrols now, with the new password, sees the same.
        let late = f.fresh(seed: 61)
        try await late.session.enrol(password: Self.newPassword, secretKey: f.kit.setupCode)
        #expect(try await f.registryView(late).state.standing(of: Self.deviceX) == .revoked)
        #expect(try await f.registryView(late).state.standing(of: rogue.newDeviceID) == .unknown)
    }

    /// The limit of a revocation that keeps the password, stated as a test so it cannot be forgotten: whoever knows
    /// the account password and the Secret Key can register a device, as the person can. If the holder of a revoked
    /// device may know them, the password must change with the revocation (`RevocationPasswordChoice.change`);
    /// the same forged entries then count for nothing, as `revokedDeviceCannotReturn` shows.
    @Test("without a password change, a revoked device's own ID and key stay out, but its holder can enrol another")
    func revocationKeepingThePassword() async throws {
        let f = try await Self.fixture()
        let lost = try await f.enrolled(Self.deviceX)
        let deviceA = try #require(await f.a.session.account?.deviceID)
        let rogue = try await Self.rogueEntries(from: lost, targeting: deviceA)
        try await f.a.session.revokeDevice(Self.deviceX, password: .keepPassword(current: TestVault.password))
        try await f.a.session.sync()
        for entry in [rogue.sameDevice, rogue.sameKey, rogue.newDevice] { await f.plant(entry) }
        try await f.a.session.sync()

        let state = try await f.registryView(f.a).state
        #expect(state.standing(of: Self.deviceX) == .revoked, "its ID never returns")
        #expect(!state.devices.values.contains { $0.key == state.revoked[Self.deviceX]?.key }, "nor does its key")
        #expect(
            state.standing(of: rogue.newDeviceID) == .active,
            "but the password and Secret Key still enrol a device: the reason the app must force the change")
    }

    /// Threat: an insider device — registered, unlocked, in the wrong hands, holding the keyset and its own device
    /// key but not the account password — announces a new password of its choosing, to lock the person out of
    /// every other device. A credential change must also be signed by the enrolment key of the generation it
    /// replaces, which only the current password yields; without that the other devices do not even see a change.
    @Test("a registered device cannot change the account password for the others without knowing it")
    func passwordChangeNeedsThePassword() async throws {
        let f = try await Self.fixture()
        let insider = try await f.enrolled(Self.deviceB)
        let session = insider.session
        let account = try #require(await session.account)
        let keys = try #require(await session.keys)
        let view = try await session.registry(account)
        var generator = SeededGenerator(seed: 1010)
        let chosenUnlockKey = EncryptionKey.generate(using: &generator)
        let chosenEnrolment = EnrolmentKey.derive(from: chosenUnlockKey, accountID: f.accountID)
        let credential = try await session.signedRegistryEntry(
            parents: view.state.heads, author: .device(Self.deviceB),
            body: .credential(
                generation: 1, enrolmentKey: try chosenEnrolment.publicKey(), previous: view.state.credential.id),
            account: account, keyset: keys.keyset, previousCredential: chosenEnrolment)
        var changed = account
        changed.unlockKeyID = chosenUnlockKey.keyID
        changed.keysetVersion += 1
        changed.credentialGeneration += 1
        changed.wrappedKeyset = try keys.keyset.wrap(
            with: chosenUnlockKey, recordVersion: changed.keysetVersion, using: &generator)
        let header = try await session.makeHeader(
            account: changed, credentialID: credential.id, genesisID: view.state.genesis,
            unlockKey: chosenUnlockKey, keyset: keys.keyset)
        await f.plant(credential)
        await f.transport.tamper(
            AccountObjectLocation.header(accountID: f.accountID, generation: 1, author: Self.deviceB).name,
            contents: header.serialized())

        let report = try await f.a.session.syncAll()
        #expect(!report.awaitingNewPassword && report.account.candidateHeadersFetched == 0)
        let state = try await f.registryView(f.a).state
        #expect(state.pendingCredentials.isEmpty && state.forkedCredentials.isEmpty)
        #expect(!state.validEntries.contains(credential.id))
        await f.a.session.lock()
        try await f.a.session.unlock(password: TestVault.password)
        #expect(try await f.a.session.sync().awaitingNewPassword == false)
    }

    /// Threat: the revoked device described above, after a revocation made **with a password change**, floods the
    /// transport with registry entries the account key signs — as many as the registry's size limit — to fill
    /// every device's registry with entries nobody can apply: some with no parents and no author signature, some
    /// back-dated and signed by its own (revoked) key, some claiming another device as author without its key.
    /// None of it is stored, kept or counted: the device that revoked it still syncs, a later revocation still
    /// reaches the others, and a new device still enrols (review of the device registry, finding "flood").
    @Test("a revoked device that kept the account key cannot fill the registry with entries that never count")
    func registryFlood() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        _ = try await f.enrolled(Self.deviceC)
        let lost = try await f.enrolled(Self.deviceX)
        let deviceA = try #require(await f.a.session.account?.deviceID)

        // What the lost device holds when it leaves the person's hands: its registry view and its keys.
        let session = lost.session
        let account = try #require(await session.account)
        let keys = try #require(await session.keys)
        let heads = try await session.registry(account).state.heads

        try await f.a.session.revokeDevice(
            Self.deviceX, password: .change(current: TestVault.password, new: Self.newPassword))
        try await f.a.session.sync()
        await b.session.lock()
        try await b.session.syncAll()
        try await b.session.unlock(password: Self.newPassword)
        try await b.session.sync()
        #expect(try await f.registryView(b).state.standing(of: Self.deviceX) == .revoked)

        func junkID(_ index: Int) -> UUID {
            UUID(uuid: (0x4A, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, UInt8(index >> 8), UInt8(index & 0xFF)))
        }
        for index in 0..<DeviceRegistry.maximumEntries {
            let entry: RegistryEntry
            switch index % 3 {
            case 0:
                // As the review found it: no parents, no author signature.
                var bare = RegistryEntry(
                    accountID: f.accountID, parents: [], author: .device(Self.deviceX), body: .revoke(junkID(index)))
                bare.accountSignature = try keys.keyset.sign(bare.accountMessage, domain: .deviceRegistry)
                bare.authorSignature = [UInt8](repeating: 0, count: 64)
                entry = bare
            case 1:
                // Back-dated, and signed by its own key, which the registry once held.
                entry = try await session.signedRegistryEntry(
                    parents: heads, author: .device(Self.deviceX), body: .revoke(junkID(index)), account: account,
                    keyset: keys.keyset)
            default:
                // In another device's name, without its key.
                var forged = RegistryEntry(
                    accountID: f.accountID, parents: heads, author: .device(deviceA), body: .revoke(junkID(index)))
                forged.accountSignature = try keys.keyset.sign(forged.accountMessage, domain: .deviceRegistry)
                forged.authorSignature = [UInt8](repeating: 7, count: 64)
                entry = forged
            }
            await f.plant(entry)
        }

        try await f.a.session.sync()
        try await b.session.sync()
        for device in [f.a, b] {
            let rows = try await device.store.records(in: f.accountID, kind: .deviceRegistry)
            #expect(rows.count < 32, "none of it is stored")
        }

        // A revokes C as well, with another password change: it still syncs, and the change still spreads.
        let third = "yet another passphrase entirely"
        try await f.a.session.revokeDevice(Self.deviceC, password: .change(current: Self.newPassword, new: third))
        let revoking = try await f.a.session.syncAll()
        #expect(!revoking.registryUnavailable && revoking.account.headerPublished)
        let told = try await b.session.syncAll()
        #expect(told.awaitingNewPassword && !told.registryUnavailable)
        await b.session.lock()
        try await b.session.unlock(password: third)
        try await b.session.sync()
        let state = try await f.registryView(b).state
        #expect(state.standing(of: Self.deviceC) == .revoked && state.standing(of: Self.deviceX) == .revoked)

        // And a new device enrols with the newest password, from a transport still full of the flood.
        let late = f.fresh(seed: 77)
        try await late.session.enrol(password: third, secretKey: f.kit.setupCode)
        let joined = try await f.registryView(late).state
        #expect(joined.standing(of: Self.deviceC) == .revoked && joined.standing(of: Self.deviceX) == .revoked)
        #expect(joined.standing(of: Self.deviceB) == .active)
        #expect(try await late.store.records(in: f.accountID, kind: .deviceRegistry).count < 32)
    }

    /// Threat: the revoked device described above (account key, its own revoked device key), after a revocation made
    /// **with a password change**, with write access to the transport. It cannot write in its own name, so it
    /// registers puppets: an `add` of a device whose key it made, behind the checkpoint, once with a garbage author
    /// signature and once signed properly by its own key; and through the first puppet, a second one whose
    /// registration verifies. It then fills the registry to its size limit with entries in the puppets' names, each
    /// verifying against a registration in an ancestor, by devices nobody ever revoked. A puppet's registration
    /// never counted, so nothing that relies on it does: none of it is stored or counted, the next revocation still
    /// spreads, and a new device still enrols (review of the device registry, finding "puppets", W26).
    @Test("a revoked device cannot flood the registry in the name of devices it registered itself")
    func puppetFlood() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        _ = try await f.enrolled(Self.deviceC)
        let lost = try await f.enrolled(Self.deviceX)
        let session = lost.session
        let account = try #require(await session.account)
        let keys = try #require(await session.keys)

        try await f.a.session.revokeDevice(
            Self.deviceX, password: .change(current: TestVault.password, new: Self.newPassword))
        try await f.a.session.sync()
        await b.session.lock()
        try await b.session.syncAll()
        try await b.session.unlock(password: Self.newPassword)
        try await b.session.sync()
        // What the transport shows after the change: the revoked device names it, so its entries come after it.
        let heads = try await f.registryView(f.a).state.heads

        var generator = SeededGenerator(seed: 99)
        func puppet(_ last: UInt8) -> (UUID, SoftwareDeviceKey) {
            (
                UUID(uuidString: "D0000000-0000-4000-8000-0000000000\(String(format: "%02X", last))")!,
                SoftwareDeviceKey.generate(using: &generator)
            )
        }
        func signed(_ entry: RegistryEntry, by device: (UUID, SoftwareDeviceKey)) throws -> RegistryEntry {
            var entry = entry
            entry.accountSignature = try keys.keyset.sign(entry.accountMessage, domain: .deviceRegistry)
            entry.authorSignature = try device.1.sign(
                prepared: DeviceSignatures.signedBytes(
                    domain: .deviceRegistry, deviceID: device.0, message: entry.deviceMessage))
            return entry
        }
        let y = puppet(0xE1)
        let z = puppet(0xE2)
        let w = puppet(0xE3)
        // Y: registered by the revoked device without a valid author signature.
        var addY = RegistryEntry(
            accountID: f.accountID, parents: heads, author: .device(Self.deviceX),
            body: .add(RegistryDevice(id: y.0, key: try y.1.publicKey(), label: [])))
        addY.accountSignature = try keys.keyset.sign(addY.accountMessage, domain: .deviceRegistry)
        addY.authorSignature = [UInt8](repeating: 0, count: 64)
        // W: registered by the revoked device with its own key, which verifies.
        let addW = try await session.signedRegistryEntry(
            parents: heads, author: .device(Self.deviceX),
            body: .add(RegistryDevice(id: w.0, key: try w.1.publicKey(), label: [])), account: account,
            keyset: keys.keyset)
        // Z: registered by Y, with Y's key.
        let addZ = try signed(
            RegistryEntry(
                accountID: f.accountID, parents: [addY.id], author: .device(y.0),
                body: .add(RegistryDevice(id: z.0, key: try z.1.publicKey(), label: []))), by: y)
        for registration in [addY, addW, addZ] { await f.plant(registration) }
        let puppets = [(y, addY), (z, addZ), (w, addW)]
        for index in 0..<DeviceRegistry.maximumEntries {
            let (author, registration) = puppets[index % puppets.count]
            let junk = UUID(
                uuid: (0x4A, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, UInt8(index >> 8), UInt8(index & 0xFF)))
            await f.plant(
                try signed(
                    RegistryEntry(
                        accountID: f.accountID, parents: [registration.id], author: .device(author.0),
                        body: .revoke(junk)), by: author))
        }

        try await f.a.session.sync()
        try await b.session.sync()
        for device in [f.a, b] {
            let rows = try await device.store.records(in: f.accountID, kind: .deviceRegistry)
            #expect(rows.count < 32, "none of it is stored")
            let state = try await f.registryView(device).state
            #expect([y.0, z.0, w.0].allSatisfy { state.standing(of: $0) == .unknown })
            #expect(state.retainedEntries.count < 32)
        }

        // A revokes C as well, with another password change: it still syncs, and the change still spreads.
        let third = "yet another passphrase entirely"
        try await f.a.session.revokeDevice(Self.deviceC, password: .change(current: Self.newPassword, new: third))
        let revoking = try await f.a.session.syncAll()
        #expect(!revoking.registryUnavailable && revoking.account.headerPublished)
        let told = try await b.session.syncAll()
        #expect(told.awaitingNewPassword && !told.registryUnavailable)
        await b.session.lock()
        try await b.session.unlock(password: third)
        try await b.session.sync()
        #expect(try await f.registryView(b).state.standing(of: Self.deviceC) == .revoked)

        // And a new device enrols with the newest password, from a transport still full of puppets.
        let late = f.fresh(seed: 77)
        try await late.session.enrol(password: third, secretKey: f.kit.setupCode)
        let joined = try await f.registryView(late).state
        #expect(joined.standing(of: Self.deviceC) == .revoked && joined.standing(of: Self.deviceX) == .revoked)
        #expect([y.0, z.0, w.0].allSatisfy { joined.standing(of: $0) == .unknown })
        #expect(try await late.store.records(in: f.accountID, kind: .deviceRegistry).count < 32)
    }

    /// Threat: the revoked device described above (account key and its own device key), once a password change
    /// has sealed its revocation. One of its entries, written at the same time as its revocation, was seen by an
    /// honest device and so sealed by the checkpoint, behind the revocation. It appends a revocation of its own that
    /// names that entry, which would put it first in the replay — the order puts first what a revocation had seen —
    /// and ahead of its revocation. A checkpoint seals the order of what it had seen: nothing appended after it
    /// moves anything there.
    @Test("an entry that arrives after a checkpoint cannot reorder what the checkpoint sealed")
    func sealedOrder() throws {
        let (a, b, x, d) = (
            RegistryFixture.deviceID(0xA0), RegistryFixture.deviceID(0xB0), RegistryFixture.deviceID(0xC0),
            RegistryFixture.deviceID(0xD0)
        )
        var exercised = false
        for seed in UInt64(1)...16 {
            var f = RegistryFixture(seed: seed)
            let genesis = f.genesis(device: a)
            let addB = f.add(b, by: a, parents: [genesis])
            let addX = f.add(x, by: a, parents: [addB])
            let seenByRevocation = f.add(RegistryFixture.deviceID(0xE4), by: a, parents: [addX])
            let revokeX = f.revoke(x, by: a, parents: [seenByRevocation])
            // X's own entry, at the same time as its revocation; B saw both, and A's password change saw B's entry.
            let backdated = f.add(d, by: x, parents: [addX])
            let sawBoth = f.add(RegistryFixture.deviceID(0xE5), by: b, parents: [backdated, revokeX])
            _ = f.nextUnlockKey()
            let change = f.credential(generation: 1, previous: genesis, by: a, parents: [sawBoth])
            let entries = [genesis, addB, addX, seenByRevocation, revokeX, backdated, sawBoth, change]
            let sealed = try f.evaluate(entries, genesis: genesis, credential: change)
            #expect(sealed.standing(of: d) == .unknown, "seed \(seed)")

            // Later, X names its back-dated entry in a revocation of its own.
            let promoter = f.revoke(b, by: x, parents: [backdated])
            exercised = exercised || backdated.id < seenByRevocation.id
            let after = try f.evaluate(entries + [promoter], genesis: genesis, credential: change)
            #expect(after.devices == sealed.devices && after.validEntries == sealed.validEntries, "seed \(seed)")
        }
        #expect(exercised, "no seed put the back-dated entry ahead of what the revocation had seen")
    }

    // MARK: - The vault directory

    /// Threats to the vault directory, each against a device that reads it:
    /// - A1 copies one vault's wrapped key to another vault's name, so a device seals that vault's items under a key
    ///   other devices do not use for it.
    /// - An insider device re-signs one vault's wrap under another vault's name; the signature then verifies, and
    ///   the wrap's own authenticated context does not.
    /// - A1 plants another account's wrap, and deletions nobody signed, signed by a stranger, or copied from a
    ///   vault that really was deleted.
    /// - An insider device signs a deletion of the Personal vault.
    /// - A revoked device vouches for a deletion.
    /// None of them changes which vaults a device has, or their keys.
    @Test(
        "vault keys and deletions cannot be swapped between vaults or accounts, forged, or aimed at the Personal vault")
    func vaultDirectory() async throws {
        let f = try await Self.fixture()
        let work = try await f.a.session.createVault(name: "Work")
        let spare = try await f.a.session.createVault(name: "Spare")
        let doomed = try await f.a.session.createVault(name: "Doomed")
        try await f.a.session.sync()
        let insider = try await f.enrolled(Self.deviceB)
        let lost = try await f.enrolled(Self.deviceX)
        let deviceA = try #require(await f.a.session.account?.deviceID)
        try await f.a.session.deleteVault(id: doomed.id, confirmingItemCount: 0)
        try await f.a.session.sync()
        let objects = await f.transport.allObjects
        func object(_ location: AccountObjectLocation) throws -> [UInt8] { try #require(objects[location.name]) }
        let store = try #require(f.a.store as? InMemoryRecordStore)
        func keyID(of vault: UUID) async throws -> UUID {
            try #require(await store.records(in: vault, kind: .vaultKeyWrap).first).recordID
        }
        let workKey = try await keyID(of: work.id)
        let genuineWrap = try SignedObject.parse(
            try object(.vaultKey(accountID: f.accountID, vaultID: work.id, keyID: workKey, author: deviceA)))
        let genuineDeletion = try object(
            .vaultDeletion(accountID: f.accountID, vaultID: doomed.id, author: deviceA))

        /// Signs `body` under `name` as the insider device does: both signatures, validly.
        func insiderSigned(_ location: AccountObjectLocation, body: [UInt8], by device: TestVault) async throws
            -> [UInt8]
        {
            let account = try #require(await device.session.account)
            let signature = try await device.session.dualSignature(
                VaultSession.directoryMessage(name: location.name, body: body), domain: .vaultDirectory,
                keys: try #require(await device.session.keys), account: account)
            return SignedObject(signature: signature, envelope: body).serialized()
        }
        var planted: [(AccountObjectLocation, [UInt8])] = []
        // A1: Work's key object under Spare's name, with a key ID no vault has, so it would be new to the reader.
        let unusedKey = UUID()
        planted.append(
            (
                .vaultKey(accountID: f.accountID, vaultID: spare.id, keyID: workKey, author: deviceA),
                genuineWrap.serialized()
            ))
        // Insider: Work's wrap, re-signed for Spare and for a key ID of its own choosing.
        for location in [
            AccountObjectLocation.vaultKey(
                accountID: f.accountID, vaultID: spare.id, keyID: workKey, author: Self.deviceB),
            .vaultKey(accountID: f.accountID, vaultID: work.id, keyID: unusedKey, author: Self.deviceB),
        ] {
            planted.append((location, try await insiderSigned(location, body: genuineWrap.envelope, by: insider)))
        }
        // Another account's wrap, as it is.
        let other = try await Self.fixture(seed: 1234)
        let otherObjects = await other.transport.allObjects
        let foreign = try #require(otherObjects.first { $0.key.contains("/key/") })
        planted.append(
            (.vaultKey(accountID: f.accountID, vaultID: UUID(), keyID: UUID(), author: deviceA), foreign.value))
        // Deletions: unsigned, signed by nobody known, copied from the vault that was deleted, and of the Personal
        // vault by a registered device.
        planted.append(
            (
                .vaultDeletion(accountID: f.accountID, vaultID: work.id, author: deviceA),
                SignedObject(signature: [], envelope: VaultSession.deletionMarker).serialized()
            ))
        planted.append(
            (.vaultDeletion(accountID: f.accountID, vaultID: work.id, author: Self.deviceC), genuineDeletion))
        planted.append(
            (.vaultDeletion(accountID: f.accountID, vaultID: spare.id, author: deviceA), genuineDeletion))
        let personalDeletion = AccountObjectLocation.vaultDeletion(
            accountID: f.accountID, vaultID: f.personal, author: Self.deviceB)
        planted.append(
            (
                personalDeletion,
                try await insiderSigned(personalDeletion, body: VaultSession.deletionMarker, by: insider)
            ))
        // A deletion vouched for by a device that is then revoked.
        let lostDeletion = AccountObjectLocation.vaultDeletion(
            accountID: f.accountID, vaultID: work.id, author: Self.deviceX)
        let lostObject = try await insiderSigned(lostDeletion, body: VaultSession.deletionMarker, by: lost)
        try await f.a.session.revokeDevice(Self.deviceX, password: .keepPassword(current: TestVault.password))
        try await f.a.session.sync()
        planted.append((lostDeletion, lostObject))
        // The reader's own name is where its own vouching goes; a deletion planted there is not its own.
        for (location, contents) in planted { await f.transport.tamper(location.name, contents: contents) }

        for locked in [true, false] {
            let reader = try await f.a.enrolledDevice(deviceID: Self.deviceC, over: f.transport)
            if !locked { try await reader.session.unlock(password: TestVault.password) }
            let report = try await reader.session.syncAll()
            #expect(report.account.vaultKeysFetched == 0 && report.account.vaultDeletionsFetched == 0)
            #expect(report.account.rejected.count >= 5, "\(report.account.rejected)")
            if locked { try await reader.session.unlock(password: TestVault.password) }
            try await reader.session.sync()
            let vaults = try await reader.session.vaults(includingDeleted: true)
            #expect(vaults.map(\.name) == ["Personal", "Doomed", "Spare", "Work"])
            #expect(vaults.map(\.isDeleted) == [false, true, false, false])
            let readerStore = try #require(reader.store as? InMemoryRecordStore)
            for vault in [work.id, spare.id] {
                let wraps = await readerStore.records(in: vault, kind: .vaultKeyWrap)
                #expect(wraps.map(\.recordID) == [try await keyID(of: vault)], "one key per vault, the genuine one")
            }
            try await reader.session.save(Item(vaultID: work.id, title: "Still writable", scopes: [], fields: []))
        }
    }

    /// Threat: A8, with the local database file but not the Keychain, edits the vault-key wrap rows: Work's wrap
    /// moved under Spare's vault ID (so that Spare's items might be read, or written, under Work's key), Spare's own
    /// wrap deleted, and another account's wrap planted under a vault ID of its own with a directory row to list it.
    /// A wrap takes its identity from the row, and its authenticated context names the vault, so a moved wrap opens
    /// nothing; a vault whose key does not open is not listed or written, its items are reported unreadable, never
    /// opened under another key; and the next sync puts back the genuine wraps, signed on the transport.
    @Test("vault-key wraps edited in the local file open nothing, and the next sync restores the genuine ones")
    func localVaultKeyWraps() async throws {
        let f = try await Self.fixture()
        let work = try await f.a.session.createVault(name: "Work")
        let spare = try await f.a.session.createVault(name: "Spare")
        try await f.a.session.save(Item(vaultID: work.id, title: "Work item", scopes: [], fields: []))
        try await f.a.session.save(Item(vaultID: spare.id, title: "Spare item", scopes: [], fields: []))
        try await f.a.session.sync()
        let store = try #require(f.a.store as? InMemoryRecordStore)
        let workWrap = try #require(await store.records(in: work.id, kind: .vaultKeyWrap).first)
        let spareWrap = try #require(await store.records(in: spare.id, kind: .vaultKeyWrap).first)

        var moved = workWrap
        moved.vaultID = spare.id
        await store.tamper(moved)
        try await store.commit(StoreChange(deletions: [spareWrap.key]))
        let other = try await Self.fixture(seed: 1234)
        let otherStore = try #require(other.a.store as? InMemoryRecordStore)
        _ = try await other.a.session.createVault(name: "Foreign")
        let foreignWrap = try #require(
            await otherStore.allRecords.first { $0.kind == .vaultKeyWrap && $0.vaultID != other.personal })
        await store.tamper(foreignWrap)
        await store.tamper(
            VaultSession.directoryRow(
                vaultID: foreignWrap.vaultID, accountID: f.accountID, deviceID: workWrap.deviceID))

        let relaunched = f.a.relaunched()
        try await relaunched.session.unlock(password: TestVault.password)
        let listed = try await relaunched.session.vaults().map(\.id)
        #expect(listed == [f.personal], "no vault is listed under a key that does not open for it")
        let everything = try await relaunched.session.items(inVaults: [f.personal, work.id, spare.id])
        #expect(everything.items.map(\.title) == ["Bank"])
        #expect(everything.unreadable.count == 2, "both items are reported, neither is opened")
        for vault in [work.id, spare.id, foreignWrap.vaultID] {
            await #expect(throws: VaultError.unknownVault(vault)) {
                try await relaunched.session.save(Item(vaultID: vault, title: "Planted", scopes: [], fields: []))
            }
        }

        let report = try await relaunched.session.syncAll()
        #expect(report.account.vaultKeysFetched == 2, "\(report.account)")
        #expect(Set(try await relaunched.session.vaults().map(\.id)) == [f.personal, work.id, spare.id])
        let restored = try await relaunched.session.items()
        #expect(Set(restored.items.map(\.title)) == ["Bank", "Work item", "Spare item"])
        #expect(restored.unreadable.isEmpty)
        for vault in [work.id, spare.id] {
            #expect(await store.records(in: vault, kind: .vaultKeyWrap).count == 1)
        }
    }

    /// Threat: a member of a vault (from milestone 4), or an insider device, seals a vault description that is not
    /// one: megabytes long, or with a name of thousands of characters, to exhaust or break the device that lists
    /// vaults. The description is bounded before it is decoded and its name after; one that is refused leaves the
    /// vault listed, without a name.
    @Test("a vault description that is too large, or has an endless name, is refused; the vault is still listed")
    func vaultDescriptionBounds() async throws {
        #expect(throws: ItemCodecError.payloadTooLarge(VaultMetadataCodec.maximumPayloadLength + 1)) {
            try VaultMetadataCodec.decode([UInt8](repeating: 0x20, count: VaultMetadataCodec.maximumPayloadLength + 1))
        }
        let long = VaultMetadata(
            vaultID: UUID(), name: String(repeating: "n", count: VaultMetadataCodec.maximumNameLength + 1),
            createdAt: Date(timeIntervalSince1970: 0), modifiedAt: Date(timeIntervalSince1970: 0), version: 1)
        #expect(throws: ItemCodecError.malformedPayload) {
            try VaultMetadataCodec.decode(try VaultMetadataCodec.encode(long))
        }
        #expect(throws: ItemCodecError.malformedPayload) { try VaultMetadataCodec.decode(Array("{}".utf8)) }

        let f = try await Self.fixture()
        let work = try await f.a.session.createVault(name: "Work")
        let account = try #require(await f.a.session.account)
        let keys = try #require(await f.a.session.keys)
        let vaultKey = try #require(await f.a.session.currentVaultKey(work.id, keys: keys, account: account))
        var hostile = long
        hostile.vaultID = work.id
        hostile.version = 9
        let row = try await f.a.session.sealMetadata(hostile, vaultKey: vaultKey, account: account)
        try await f.a.store.commit(StoreChange(upserts: [row]))
        let listed = try await f.a.session.vaults()
        #expect(listed.map(\.id).contains(work.id))
        #expect(listed.first { $0.id == work.id }?.name == "")
    }
}
