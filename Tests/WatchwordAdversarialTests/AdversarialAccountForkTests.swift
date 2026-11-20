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

/// Password changes that are not the person's (review findings Z1 to Z3; docs/02-architecture.md §7.8).
///
/// The adversary throughout is **the holder of a device the person revoked with a password change**: they opened the
/// keyset while the device was the person's, so they hold the account key, the device's own signing key, the Secret
/// Key, and the password the person has just retired (and so the enrolment key of the generation it belonged to),
/// and they can still write to the sync store. To a device that has not been given the new password yet, a change
/// they publish from the generation before their revocation carries every signature the genuine one does.
extension AdversarialAccountTests {
    static let deviceP1 = UUID(uuidString: "D0000000-0000-4000-8000-0000000000F1")!
    static let deviceP2 = UUID(uuidString: "D0000000-0000-4000-8000-0000000000F2")!
    static let deviceP3 = UUID(uuidString: "D0000000-0000-4000-8000-0000000000F3")!

    /// A password change of an adversary's making, published from `device` with what that device holds: registry
    /// entries naming only parents it had seen, and the account header of each generation.
    struct RogueChange {
        var entries: [RegistryEntry] = []
        var credentials: [RegistryEntry] = []
        var headers: [AccountHeaderObject] = []
    }

    /// A chain of credential changes written by `device` on top of the registry as it sees it now, one generation
    /// per element of `passwords`: a password derives that generation's Account Unlock Key with the account's Secret
    /// Key and a new salt, `nil` is a key nobody can derive. With `revoking`, the chain starts with a revocation of
    /// that device, so every change in it seals the revocation.
    static func rogueChange(
        from device: TestVault, revoking victim: UUID? = nil, passwords: [String?], seed: UInt64 = 2020
    ) async throws -> RogueChange {
        let session = device.session
        let account = try #require(await session.account)
        let keys = try #require(await session.keys)
        let view = try await session.registry(account)
        let secretKey = try await session.storedSecretKey(accountID: account.accountID)
        var generator = SeededGenerator(seed: seed)
        var change = RogueChange()
        var parents = view.state.heads
        if let victim {
            let revocation = try await session.signedRegistryEntry(
                parents: parents, author: .device(account.deviceID), body: .revoke(victim), account: account,
                keyset: keys.keyset)
            change.entries.append(revocation)
            parents = [revocation.id]
        }
        var previous = view.state.credential.id
        var previousEnrolment = EnrolmentKey.derive(from: keys.accountUnlockKey, accountID: account.accountID)
        var generation = account.credentialGeneration
        for password in passwords {
            generation += 1
            let salt = (0..<account.kdf.saltLength).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
            let unlockKey: EncryptionKey
            if let password {
                unlockKey = try TwoSecretKeyDerivation.accountUnlockKey(
                    password: password, secretKey: secretKey, accountID: account.accountID, parameters: account.kdf,
                    salt: salt, keyID: EncryptionKey.generate(using: &generator).keyID)
            } else {
                unlockKey = EncryptionKey.generate(using: &generator)
            }
            let enrolment = EnrolmentKey.derive(from: unlockKey, accountID: account.accountID)
            let credential = try await session.signedRegistryEntry(
                parents: parents, author: .device(account.deviceID),
                body: .credential(generation: generation, enrolmentKey: try enrolment.publicKey(), previous: previous),
                account: account, keyset: keys.keyset, previousCredential: previousEnrolment)
            var changed = account
            changed.salt = salt
            changed.unlockKeyID = unlockKey.keyID
            changed.keysetVersion = generation
            changed.credentialGeneration = generation
            changed.wrappedKeyset = try keys.keyset.wrap(with: unlockKey, recordVersion: generation, using: &generator)
            change.headers.append(
                try await session.makeHeader(
                    account: changed, credentialID: credential.id, genesisID: view.state.genesis,
                    unlockKey: unlockKey, keyset: keys.keyset))
            change.entries.append(credential)
            change.credentials.append(credential)
            parents = [credential.id]
            previous = credential.id
            previousEnrolment = enrolment
        }
        return change
    }

    static func plant(_ change: RogueChange, in f: Fixture) async {
        for entry in change.entries { await f.plant(entry) }
        for header in change.headers {
            await f.transport.tamper(
                AccountObjectLocation.header(
                    accountID: f.accountID, generation: header.generation, author: header.author
                ).name, contents: header.serialized())
        }
    }

    // MARK: - A change that is not the person's (Z1)

    /// Threat: the adversary above publishes, back-dated to before its revocation, a revocation of the device that
    /// revoked it and a "password change" whose password is the one the person has just retired, under a new salt.
    /// On a device that has not been given the new password, the person (or anyone at it who knows the retired
    /// password) types what they always typed. That must be refused as retired, not taken as confirmation of the
    /// adversary's change: following it would hold the revoker revoked, the revoked device active, and the genuine
    /// change dead for good. `ignoringPasswordChange` must open the device as it is and follow nothing.
    @Test("a change made with the retired password is never adopted by typing that password")
    func retiredPasswordFork() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        let lost = try await f.enrolled(Self.deviceX)
        let deviceA = try #require(await f.a.session.account?.deviceID)
        let rogue = try await Self.rogueChange(from: lost, revoking: deviceA, passwords: [TestVault.password])

        try await f.a.session.revokeDevice(
            Self.deviceX, password: .change(current: TestVault.password, new: Self.newPassword))
        try await f.a.session.sync()
        let genuine = try await f.registryView(f.a).state.credential.id
        await Self.plant(rogue, in: f)

        let told = try await b.session.syncAll()
        #expect(told.awaitingNewPassword && told.account.candidateHeadersFetched == 2)
        let before = try await f.registryView(b).state
        #expect(Set(before.pendingCredentials.map(\.id)) == [genuine, rogue.credentials[0].id])
        await b.session.lock()

        await #expect(throws: VaultError.passwordChangedOnAnotherDevice) {
            try await b.session.unlock(password: TestVault.password)
        }
        #expect(try await b.session.state() == .locked)
        #expect(await b.session.account?.credentialGeneration == 0)

        // The person who did not change it: the device opens as it is, and follows nothing.
        try await b.session.unlock(password: TestVault.password, ignoringPasswordChange: true)
        let ignoring = try await f.registryView(b).state
        #expect(ignoring.credential.id == before.credential.id && ignoring.credential.generation == 0)
        #expect(Set(ignoring.pendingCredentials.map(\.id)) == [genuine, rogue.credentials[0].id])
        #expect(await b.session.account?.credentialGeneration == 0)
        #expect(try await b.session.isAwaitingNewPassword())
        // What the screen can show of the two: who made each, and what each would take away.
        let described = try await b.session.pendingPasswordChanges()
        #expect(Set(described.map(\.device)) == [deviceA, Self.deviceX])
        #expect(described.first { $0.device == deviceA }?.revokedDevices == [Self.deviceX])
        #expect(described.first { $0.device == Self.deviceX }?.revokedDevices == [deviceA])
        #expect(described.allSatisfy { $0.canBeFollowed && !$0.isFork && !$0.revokesThisDevice })
        await b.session.lock()

        // The new password still reaches the genuine change, and that settles it.
        try await b.session.unlock(password: Self.newPassword)
        let after = try await f.registryView(b).state
        #expect(after.credential.id == genuine)
        #expect(after.standing(of: Self.deviceX) == .revoked && after.standing(of: deviceA) == .active)
        #expect(after.pendingCredentials.isEmpty && after.forkedCredentials.isEmpty)
        await b.session.lock()
        await #expect(throws: CryptoError.authenticationFailed) {
            try await b.session.unlock(password: TestVault.password)
        }
        await #expect(throws: CryptoError.authenticationFailed) {
            try await b.session.unlock(password: TestVault.password, ignoringPasswordChange: true)
        }
    }

    /// Threat: the same adversary chains changes of its own (generations 1 to 4, each under a key nobody derives and
    /// parameters of its choosing), so that their headers sort ahead of the genuine one and use up the derivations an
    /// unlock spends, and the new password reports as wrong. Each authoring device gets one attempt, so the device
    /// that really changed the password is reached; and a new device enrolling with the new password is not kept out
    /// by the same chain.
    @Test("a chain of planted changes does not use up the attempts the genuine change needs")
    func plantedChain() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        let lost = try await f.enrolled(Self.deviceX)
        let deviceA = try #require(await f.a.session.account?.deviceID)
        let rogue = try await Self.rogueChange(from: lost, revoking: deviceA, passwords: [nil, nil, nil, nil])
        try await f.a.session.revokeDevice(
            Self.deviceX, password: .change(current: TestVault.password, new: Self.newPassword))
        try await f.a.session.sync()
        await Self.plant(rogue, in: f)

        #expect(try await b.session.syncAll().awaitingNewPassword)
        await b.session.lock()
        await #expect(throws: CryptoError.authenticationFailed) {
            try await b.session.unlock(password: "neither the old nor the new")
        }
        try await b.session.unlock(password: Self.newPassword)
        let state = try await f.registryView(b).state
        #expect(state.standing(of: Self.deviceX) == .revoked && state.standing(of: deviceA) == .active)

        let late = f.fresh(seed: 62)
        try await late.session.enrol(password: Self.newPassword, secretKey: f.kit.setupCode)
        #expect(try await f.registryView(late).state.standing(of: Self.deviceX) == .revoked)
    }

    /// Threat: beside the genuine change, the adversary publishes one whose history revokes the very device it is
    /// offered to, made with a password the person might be talked into typing there. A device does not follow a
    /// change whose own history removes it: it would hold itself revoked, and its revoker's entries as sealed, on
    /// that branch's word alone. The genuine change is still followed with its own password.
    @Test("a change whose own history revokes this device is refused here, and changes nothing")
    func changeThatRevokesThisDevice() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        let lost = try await f.enrolled(Self.deviceX)
        let deviceA = try #require(await f.a.session.account?.deviceID)
        let rogue = try await Self.rogueChange(
            from: lost, revoking: Self.deviceB, passwords: ["the password in the message"])
        try await f.a.session.revokeDevice(
            Self.deviceX, password: .change(current: TestVault.password, new: Self.newPassword))
        try await f.a.session.sync()
        let genuine = try await f.registryView(f.a).state.credential.id
        await Self.plant(rogue, in: f)

        #expect(try await b.session.syncAll().awaitingNewPassword)
        await b.session.lock()
        await #expect(throws: VaultError.passwordChangeRevokesThisDevice) {
            try await b.session.unlock(password: "the password in the message")
        }
        #expect(try await b.session.state() == .locked)
        #expect(try await f.registryView(b).state.credential.generation == 0)
        #expect(await b.session.account?.credentialGeneration == 0)
        let described = try await b.session.pendingPasswordChanges()
        #expect(described.first { $0.device == Self.deviceX }?.revokesThisDevice == true)
        #expect(described.first { $0.device == deviceA }?.revokesThisDevice == false)

        try await b.session.unlock(password: Self.newPassword)
        let state = try await f.registryView(b).state
        #expect(state.credential.id == genuine)
        #expect(state.standing(of: Self.deviceB) == .active && state.standing(of: Self.deviceX) == .revoked)
    }

    /// Threat: before the lost device was revoked, its holder enrolled devices of their own with the password they
    /// knew. Each publishes changes too, so more devices claim a change than one unlock tries, and all of theirs sort
    /// ahead of the genuine one: made, here, on a device the person added after the password this device has was
    /// set, so that the checkpoint this device follows seals none of them (Z13 puts the ones it seals first). The
    /// unlock says so rather than calling the new password wrong, and the person reaches the genuine change by
    /// naming the device they made it on.
    @Test("more devices claiming a change than an unlock tries is reported, and the genuine one is reached by name")
    func moreAuthorsThanAttempts() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        let lost = try await f.enrolled(Self.deviceX)
        let c = try await f.enrolled(Self.deviceC)
        var rogues: [RogueChange] = []
        for (index, id) in [Self.deviceP1, Self.deviceP2, Self.deviceP3].enumerated() {
            let puppet = try await f.enrolled(id)
            rogues.append(
                try await Self.rogueChange(from: puppet, passwords: [nil, nil], seed: 3000 + UInt64(index)))
        }
        try await lost.session.sync()
        try await c.session.sync()
        try await b.session.sync()
        try await c.session.revokeDevice(
            Self.deviceX, password: .change(current: TestVault.password, new: Self.newPassword))
        try await c.session.sync()
        let genuine = try await f.registryView(c).state.credential.id
        for rogue in rogues { await Self.plant(rogue, in: f) }

        #expect(try await b.session.syncAll().awaitingNewPassword)
        await b.session.lock()
        let listed = try await b.session.pendingPasswordChanges()
        #expect(listed.count == 4 && listed.allSatisfy { !$0.registeredBeforeFollowed })
        await #expect(throws: VaultError.tooManyPasswordChangesPending) {
            try await b.session.unlock(password: Self.newPassword)
        }
        #expect(try await b.session.state() == .locked)

        try await b.session.unlock(password: TestVault.password, ignoringPasswordChange: true)
        await #expect(throws: VaultError.noPasswordChangeToFollow(Self.deviceB)) {
            try await b.session.followPasswordChange(
                by: Self.deviceB, current: TestVault.password, password: Self.newPassword)
        }
        await #expect(throws: CryptoError.authenticationFailed) {
            try await b.session.followPasswordChange(
                by: Self.deviceC, current: TestVault.password, password: TestVault.password)
        }
        try await b.session.followPasswordChange(
            by: Self.deviceC, current: TestVault.password, password: Self.newPassword)
        #expect(try await f.registryView(b).state.credential.id == genuine)
        #expect(try await b.session.state() == .unlocked)
        #expect(try await !b.session.isAwaitingNewPassword())
        try await b.session.sync()
        await b.session.lock()
        await #expect(throws: CryptoError.authenticationFailed) {
            try await b.session.unlock(password: TestVault.password)
        }
        try await b.session.unlock(password: Self.newPassword)
    }

    /// Threat: a device that is still registered, in hands that know a password the person has since retired (a
    /// device the lost one's holder enrolled before the revocation, say), publishes a change that branches off
    /// before the current credentials, made with the retired password. On a device that already follows the new
    /// password, the retired one must simply be wrong: a fork is followed only from an unlocked session, by someone
    /// who has first given the password the device follows now.
    @Test("a fork made with a retired password does not open a device that follows the new one")
    func forkNeedsTheCurrentPassword() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        let insider = try await f.enrolled(Self.deviceP1)
        let rogue = try await Self.rogueChange(from: insider, passwords: [TestVault.password])
        try await f.a.session.changePassword(current: TestVault.password, new: Self.newPassword)
        try await f.a.session.sync()
        try await b.session.sync()
        await b.session.lock()
        try await b.session.unlock(password: Self.newPassword)
        let followed = try await f.registryView(b).state.credential.id

        await Self.plant(rogue, in: f)
        let report = try await b.session.syncAll()
        #expect(!report.awaitingNewPassword)
        #expect(try await f.registryView(b).state.forkedCredentials.map(\.id) == [rogue.credentials[0].id])
        await b.session.lock()
        await #expect(throws: CryptoError.authenticationFailed) {
            try await b.session.unlock(password: TestVault.password)
        }
        #expect(try await f.registryView(b).state.credential.id == followed)
        try await b.session.unlock(password: Self.newPassword)
        #expect(try await b.session.pendingPasswordChanges().map(\.isFork) == [true])
        // Bringing this device over to the other change is the person's to do, unlocked, with that change's password.
        try await b.session.followPasswordChange(
            by: Self.deviceP1, current: Self.newPassword, password: TestVault.password)
        #expect(try await f.registryView(b).state.credential.id == rogue.credentials[0].id)
        await b.session.lock()
        try await b.session.unlock(password: TestVault.password)
    }

    // MARK: - No number of planted changes hides the genuine one (Z2)

    /// Threat: the same adversary plants credential entries by the dozen on a device still at the old generation,
    /// with entry IDs below the genuine change's. Half carry no valid signature of the previous generation's
    /// enrolment key (it needs no password to make those), half are complete. The registry looked at sixteen
    /// candidates in entry-ID order and counted each before judging it, so the genuine change was never looked at:
    /// not pending, its header never fetched, the old password still good, sync still merging and publishing.
    @Test("planted password changes, however many, cannot keep the genuine one off the list")
    func plantedChangesCannotHideTheGenuineOne() throws {
        let (a, b, x) = (RegistryFixture.deviceID(0xA0), RegistryFixture.deviceID(0xB0), RegistryFixture.deviceID(0xE0))
        var exercised = false
        for seed in UInt64(1)...4 {
            var f = RegistryFixture(seed: seed)
            var generator = SeededGenerator(seed: seed &+ 500)
            let genesis = f.genesis(device: a)
            let addB = f.add(b, by: a, parents: [genesis])
            let addX = f.add(x, by: a, parents: [addB])
            let revokeX = f.revoke(x, by: a, parents: [addX])
            _ = f.nextUnlockKey()
            let change = f.credential(generation: 1, previous: genesis, by: a, parents: [revokeX])
            func planted(valid: Bool) throws -> RegistryEntry {
                let key = EnrolmentKey.derive(from: EncryptionKey.generate(using: &generator), accountID: f.accountID)
                let entry = RegistryEntry(
                    accountID: f.accountID, parents: [addX.id], author: .device(x),
                    body: .credential(generation: 1, enrolmentKey: try key.publicKey(), previous: genesis.id))
                return f.signed(entry, previousGeneration: valid ? 0 : nil)
            }
            let junk = try (0..<48).map { _ in try planted(valid: false) }
            let forks = try (0..<48).map { _ in try planted(valid: true) }
            exercised = exercised || (junk + forks).filter { $0.id < change.id }.count >= 16

            let behind = try f.evaluate([genesis, addB, addX, revokeX, change] + junk + forks, genesis: genesis)
            let pending = Set(behind.pendingCredentials.map(\.id))
            #expect(pending.contains(change.id), "seed \(seed): the genuine change is not listed")
            #expect(pending.isDisjoint(with: junk.map(\.id)), "one made without the previous password is listed")
            #expect(pending.isSuperset(of: forks.map(\.id)))
            // Following the genuine one still settles everything, and leaves none of the rest to follow.
            let followed = try f.evaluate(
                [genesis, addB, addX, revokeX, change] + junk + forks, genesis: genesis, credential: change)
            #expect(followed.standing(of: x) == .revoked && Set(followed.devices.keys) == [a, b])
            #expect(followed.pendingCredentials.isEmpty && followed.forkedCredentials.isEmpty)
        }
        #expect(exercised, "no seed put sixteen planted entries in front of the genuine change")
    }

    // MARK: - A pending change is remembered in the Keychain (Z3)

    /// Threat: A8, with the local database of a locked device and the retired password, removes what the file holds
    /// of a password change the device has been told of and not given: the candidate header's row; that and the
    /// credential entry; or any registry row the anchor names, so that the registry cannot be evaluated at all. Or
    /// A1 withholds the change's header from the start. In each case the device must still refuse the retired
    /// password and quick unlock, because the Keychain remembers that a change was seen.
    @Test(
        "a password change this device was told of is remembered in the Keychain, whatever the file holds",
        arguments: ["header row", "header and credential rows", "a registry row the anchor names", "header withheld"])
    func pendingChangeOutlivesTheFile(variant: String) async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        try await b.session.enableQuickUnlock(password: TestVault.password)
        await b.session.lock()
        try await f.a.session.changePassword(current: TestVault.password, new: Self.newPassword)
        try await f.a.session.sync()
        let change = try await f.registryView(f.a).state.credential
        if variant == "header withheld" {
            let name = AccountObjectLocation.header(accountID: f.accountID, generation: 1, author: change.author).name
            await f.transport.tamper(name, contents: nil)
        }
        let told = try await b.session.syncAll()
        #expect(told.awaitingNewPassword)
        #expect(told.account.candidateHeadersFetched == (variant == "header withheld" ? 0 : 1))

        let store = try #require(b.store as? InMemoryRecordStore)
        let headers = await store.records(in: f.accountID, kind: .accountHeader).filter { $0.recordID != f.accountID }
        let registry = await store.records(in: f.accountID, kind: .deviceRegistry)
        var deletions: [RecordKey] = []
        switch variant {
        case "header row":
            deletions = headers.map(\.key)
        case "header and credential rows":
            deletions =
                headers.map(\.key) + registry.filter { ObjectDigest(hashing: $0.envelope) == change.id }.map(\.key)
        case "a registry row the anchor names":
            deletions = registry.filter { ObjectDigest(hashing: $0.envelope) != change.id }.prefix(1).map(\.key)
        default:
            break
        }
        if !deletions.isEmpty { try await store.commit(StoreChange(deletions: deletions)) }

        let relaunched = b.relaunched()
        #expect(try await relaunched.session.isAwaitingNewPassword())
        await #expect(throws: VaultError.passwordChangedOnAnotherDevice) {
            try await relaunched.session.unlock(password: TestVault.password)
        }
        await #expect(throws: VaultError.quickUnlockRefused(.credentialsChanged)) {
            try await relaunched.session.quickUnlock()
        }
        #expect(try await relaunched.session.state() == .locked)
        #expect(await !b.keychain.contains(.quickUnlockKey(accountID: f.accountID)))
        // A sync puts back what was taken, and the new password is then followed as ever.
        if variant == "header withheld" {
            let accountA = try #require(await f.a.session.account)
            let header = try #require(try await f.a.session.storedHeader(accountA))
            await f.transport.tamper(
                AccountObjectLocation.header(accountID: f.accountID, generation: 1, author: change.author).name,
                contents: header.row.envelope)
        }
        _ = try await relaunched.session.syncAll()
        try await relaunched.session.unlock(password: Self.newPassword)
        #expect(try await !relaunched.session.isAwaitingNewPassword())
        await relaunched.session.lock()
        await #expect(throws: CryptoError.authenticationFailed) {
            try await relaunched.session.unlock(password: TestVault.password)
        }
    }

    /// The anchor's encoding (Z3): what it records of pending changes survives a round trip, an anchor written
    /// before it recorded any is read as having seen none, and anything else is no anchor at all, which leaves the
    /// registry unavailable rather than trusted.
    @Test("the Keychain anchor round-trips its pending changes, reads its earlier form, and refuses anything else")
    func anchorEncoding() throws {
        let digests = (1...20).map { ObjectDigest(hashing: [UInt8($0)]) }
        let anchor = RegistryAnchor(
            genesis: digests[0], credential: digests[1], generation: 7, heads: [digests[3], digests[2]],
            pending: Array(digests[4...]))
        #expect(anchor.pending.count == RegistryAnchor.maximumPending, "bounded, and still not empty")
        let encoded = anchor.encoded()
        #expect(RegistryAnchor(bytes: encoded) == anchor)
        #expect(RegistryAnchor(bytes: encoded + [0]) == nil)
        #expect(RegistryAnchor(bytes: Array(encoded.dropLast())) == nil)
        #expect(RegistryAnchor(bytes: []) == nil)

        // The form before pending changes were recorded: the same fields, another magic, nothing after the heads.
        var earlier = Array("WWRA1".utf8) + digests[0].bytes + digests[1].bytes
        earlier += (0..<8).map { UInt8(truncatingIfNeeded: UInt64(7) >> (8 * $0)) }
        earlier += [2, 0] + digests[2].bytes + digests[3].bytes
        let read = try #require(RegistryAnchor(bytes: earlier))
        #expect(read.pending.isEmpty && read.generation == 7 && Set(read.heads) == [digests[2], digests[3]])
        #expect(read.genesis == digests[0] && read.credential == digests[1])
        #expect(RegistryAnchor(bytes: earlier + [0]) == nil, "an earlier anchor with anything after its heads")
        #expect(RegistryAnchor(bytes: Array("WWRA4".utf8) + Array(earlier.dropFirst(5))) == nil)
    }

    // MARK: - Which vault is the Personal one (Z5)

    /// Threat: A8 (or an altered backup that is restored), acting for someone who can read another of the account's
    /// vaults: a member of a vault the person shares, say. One edit to the account row of a locked device names that
    /// vault as the Personal one, with its key, and a planted directory row keeps the real Personal vault in view.
    /// The row's two columns were sealed by nothing, so the next unlock took them: every new item, every login
    /// AutoFill saves and every new passkey went into the other vault, under a key its members hold. The account
    /// header has always sealed the Personal vault's ID under the Account Unlock Key; an unlock now requires the row
    /// to say the same, by the password and by quick unlock alike.
    @Test(
        "the Personal vault is the one the account header seals, whatever the account row says",
        arguments: ["row redirected", "row redirected and header row removed", "header row replaced by another's"])
    func personalVaultIsTheHeadersNotTheRows(variant: String) async throws {
        let vault = TestVault()
        try await vault.createAccount()
        let session = vault.session
        let personal = try #require(await session.personalVaultID)
        let work = try await session.createVault(name: "Work")
        try await session.enableQuickUnlock(password: TestVault.password)
        await session.lock()

        let store = try #require(vault.store as? InMemoryRecordStore)
        let genuine = try #require(await store.loadAccount())
        let genuineHeader = try #require(await store.record(VaultSession.headerKey(genuine.accountID)))
        let workKey = try #require(await store.records(in: work.id, kind: .vaultKeyWrap).first)
        var redirected = genuine
        redirected.personalVaultID = work.id
        redirected.personalVaultKeyID = workKey.recordID
        await store.tamper(account: redirected)
        await store.tamper(
            VaultSession.directoryRow(vaultID: personal, accountID: genuine.accountID, deviceID: genuine.deviceID))
        switch variant {
        case "row redirected and header row removed":
            try await store.commit(StoreChange(deletions: [genuineHeader.key]))
        case "header row replaced by another's":
            // A header of another account's making, renamed: it parses, and opens under no key this account has.
            let other = TestVault(seed: 99)
            try await other.createAccount()
            let otherAccount = try #require(await other.session.account)
            let otherStore = try #require(other.store as? InMemoryRecordStore)
            let foreign = try #require(
                await otherStore.records(in: otherAccount.accountID, kind: .accountHeader).first)
            var header = try AccountHeaderObject.parse(foreign.envelope)
            header.accountID = genuine.accountID
            header.unlockKeyID = genuine.unlockKeyID
            var row = genuineHeader
            row.envelope = header.serialized()
            await store.tamper(row)
        default:
            break
        }

        let relaunched = vault.relaunched()
        await #expect(throws: VaultError.personalVaultMismatch) {
            try await relaunched.session.unlock(password: TestVault.password)
        }
        #expect(try await relaunched.session.state() == .locked)
        await #expect(throws: VaultError.personalVaultMismatch) { try await relaunched.session.quickUnlock() }
        #expect(try await relaunched.session.state() == .locked)
        #expect(await relaunched.session.keys == nil)

        // As it was: the same password opens the same Personal vault.
        await store.tamper(account: genuine)
        await store.tamper(genuineHeader)
        let restored = vault.relaunched()
        try await restored.session.unlock(password: TestVault.password)
        #expect(try await restored.session.defaultVaultID() == personal)
    }

    /// Threat: the same edit, pointing the row at a vault whose key reached this account by another member's grant
    /// (a vault someone else shares with the person), on a store with no header row and no Keychain anchor to check
    /// the row against: restored onto other hardware, with the header removed. A granted key says so in its wrap's
    /// authenticated context, and the Personal vault's key is never one.
    @Test("a key that arrived by another member's grant is never the Personal vault's key")
    func grantedKeyIsNeverThePersonalKey() async throws {
        let vault = TestVault()
        let kit = try await vault.createAccount()
        let session = vault.session
        let account = try #require(await session.account)
        let keys = try #require(await session.keys)
        var generator = SeededGenerator(seed: 77)
        let shared = UUID(uuidString: "5A000000-0000-4000-8000-0000000000BB")!
        let granted = VaultKey(vaultID: shared, key: EncryptionKey.generate(using: &generator), arrivedByGrant: true)
        let wrap = StoredRecord(
            recordID: granted.key.keyID, kind: .vaultKeyWrap, vaultID: shared,
            keyID: keys.keyset.symmetricKey.keyID, version: 1, deviceID: account.deviceID,
            envelope: try granted.wrap(for: keys.keyset, using: &generator))
        await session.lock()

        let store = try #require(vault.store as? InMemoryRecordStore)
        try await store.commit(
            StoreChange(
                upserts: [
                    wrap,
                    VaultSession.directoryRow(
                        vaultID: shared, accountID: account.accountID, deviceID: account.deviceID),
                ], deletions: [VaultSession.headerKey(account.accountID)]))
        var redirected = account
        redirected.personalVaultID = shared
        redirected.personalVaultKeyID = granted.key.keyID
        await store.tamper(account: redirected)
        await vault.keychain.delete(.deviceRegistryAnchor(accountID: account.accountID))

        let relaunched = vault.relaunched()
        await #expect(throws: VaultError.personalVaultMismatch) {
            try await relaunched.session.unlock(password: TestVault.password, secretKey: kit.secretKey)
        }
        #expect(try await relaunched.session.state() == .locked)
    }

    // MARK: - Another member's registry (Z6)

    /// A member's registry as the other members of a shared vault see it, and what the holder of the laptop that
    /// member revoked can add to it: a back-dated revocation of the phone that revoked it, and password changes of
    /// its own from the generation before, to any generation it likes.
    struct MemberRegistryScenario {
        static let phone = RegistryFixture.deviceID(0xA0)
        static let laptop = RegistryFixture.deviceID(0xE0)
        static let tablet = RegistryFixture.deviceID(0xB0)

        var f: RegistryFixture
        var genesis: RegistryEntry
        /// Genesis, the laptop and the tablet registered: what everyone saw before the theft.
        var before: [RegistryEntry]
        /// The member's own step: the laptop revoked, then the password changed.
        var genuine: [RegistryEntry]
        var change: RegistryEntry
        /// The laptop holder's: the phone revoked (back-dated), then two password changes of its own.
        var forged: [RegistryEntry]
        var forgedTip: RegistryEntry

        init(seed: UInt64 = 9) throws {
            var f = RegistryFixture(seed: seed)
            var generator = SeededGenerator(seed: seed &+ 900)
            let genesis = f.genesis(device: Self.phone)
            let addLaptop = f.add(Self.laptop, by: Self.phone, parents: [genesis])
            let addTablet = f.add(Self.tablet, by: Self.phone, parents: [addLaptop])
            let revokeLaptop = f.revoke(Self.laptop, by: Self.phone, parents: [addTablet])
            _ = f.nextUnlockKey()
            let change = f.credential(generation: 1, previous: genesis, by: Self.phone, parents: [revokeLaptop])

            let revokePhone = f.revoke(Self.phone, by: Self.laptop, parents: [addTablet])
            let first = EnrolmentKey.derive(from: EncryptionKey.generate(using: &generator), accountID: f.accountID)
            let second = EnrolmentKey.derive(from: EncryptionKey.generate(using: &generator), accountID: f.accountID)
            let forgedOne = f.signed(
                RegistryEntry(
                    accountID: f.accountID, parents: [revokePhone.id], author: .device(Self.laptop),
                    body: .credential(generation: 1, enrolmentKey: try first.publicKey(), previous: genesis.id)),
                previousGeneration: 0)
            var forgedTwo = f.signed(
                RegistryEntry(
                    accountID: f.accountID, parents: [forgedOne.id], author: .device(Self.laptop),
                    body: .credential(generation: 2, enrolmentKey: try second.publicKey(), previous: forgedOne.id)))
            forgedTwo.previousCredentialSignature = try first.sign(
                forgedTwo.previousCredentialMessage, domain: .deviceRegistry)

            self.f = f
            self.genesis = genesis
            before = [genesis, addLaptop, addTablet]
            genuine = [revokeLaptop, change]
            self.change = change
            forged = [revokePhone, forgedOne, forgedTwo]
            forgedTip = forgedTwo
        }

        func raw(_ entries: [RegistryEntry]) -> [[UInt8]] { entries.map { $0.serialized() } }

        func evaluate(_ entries: [RegistryEntry], pin: MemberRegistryPin?) -> VaultSession.MemberRegistryEvaluation {
            VaultSession.evaluateMemberRegistry(
                raw(entries), accountID: f.accountID, signingKey: f.accountSigningKey, pin: pin)
        }
    }

    /// Threat: the D9 adversary against the *other* members of a shared vault. A member's laptop is stolen unlocked;
    /// the member revokes it with a password change. Its holder still has the account key, the laptop's device key
    /// and the enrolment key of the generation before, so it publishes a competing password change from that
    /// generation, sealing a back-dated revocation of the member's phone, and a second one on top to reach a higher
    /// generation. Other members have no password to tell the two by, and followed the highest generation: the
    /// laptop wrote as the member in every vault they share, and the member's own devices were no longer read.
    ///
    /// Now: a device that already follows the member's change is unmoved and says what it saw; one that had not got
    /// that far follows neither, counts only the devices both branches keep, and says so; nothing anchors on a
    /// second genesis entry; and only the code from the member's own device moves the anchor.
    @Test("a member's revoked device cannot un-revoke itself in the other members' eyes by outbidding the generation")
    func memberRegistryFork() throws {
        typealias S = MemberRegistryScenario
        let s = try S()

        // The member's own history, seen first: followed to the change, nothing to report.
        let honest = s.evaluate(s.before + s.genuine, pin: nil)
        #expect(honest.pin?.credential == s.change.id && honest.disagreement.isEmpty && !honest.unsettled)
        #expect(honest.state?.standing(of: S.laptop) == .revoked && honest.state?.standing(of: S.phone) == .active)

        // Anchored there, then the forged branch arrives, two generations long: dead, whatever its generation.
        let anchored = s.evaluate(s.before + s.genuine + s.forged, pin: honest.pin)
        #expect(anchored.pin?.credential == s.change.id)
        #expect(anchored.state?.standing(of: S.laptop) == .revoked && anchored.state?.standing(of: S.phone) == .active)
        #expect(anchored.state?.standing(of: S.tablet) == .active)
        #expect(anchored.unsettled && !anchored.disagreement.isEmpty, "a fork seen is reported")

        // Anchored before the theft, both branches arrive together; and nothing anchored at all. Neither is followed:
        // the phone and the laptop are both in question, the tablet that neither branch touches still counts.
        let early = s.evaluate(s.before, pin: nil)
        #expect(early.pin?.credential == s.genesis.id && !early.unsettled)
        for pin in [early.pin, nil] {
            let contested = s.evaluate(s.before + s.genuine + s.forged, pin: pin)
            #expect(contested.pin?.credential == s.genesis.id, "it anchors neither branch")
            #expect(contested.unsettled)
            #expect(contested.state?.devices[S.laptop] == nil && contested.state?.devices[S.phone] == nil)
            #expect(contested.state?.standing(of: S.tablet) == .active)
            // Still listed, so that what they wrote before stays their account's work.
            #expect(contested.state?.revoked[S.laptop] != nil && contested.state?.revoked[S.phone] != nil)
        }

        // The forged branch alone is all a device has seen (the store withheld the rest): it is followed, as nothing
        // tells it from the member's own. When the member's change appears, the device says so and stays put. A pin
        // settled by an earlier version (which took a code, Z11) still reads as settled.
        let deceived = s.evaluate(s.before + s.forged, pin: nil)
        #expect(deceived.pin?.credential == s.forgedTip.id && deceived.state?.standing(of: S.laptop) == .active)
        let shown = s.evaluate(s.before + s.forged + s.genuine, pin: deceived.pin)
        #expect(shown.pin?.credential == s.forgedTip.id && shown.unsettled)
        var settled = s.evaluate(
            s.before + s.forged + s.genuine,
            pin: MemberRegistryPin(genesis: s.genesis.id, credential: s.change.id, settled: nil))
        #expect(settled.state?.standing(of: S.laptop) == .revoked && settled.state?.standing(of: S.phone) == .active)
        // Settled, it is not reported again; one more forged entry is.
        settled.pin?.settled = VaultSession.disagreementDigest(settled.disagreement)
        #expect(!s.evaluate(s.before + s.forged + s.genuine, pin: settled.pin).unsettled)
        var f = s.f
        let another = f.signed(
            RegistryEntry(
                accountID: f.accountID, parents: [s.forged[0].id], author: .device(S.laptop),
                body: .credential(
                    generation: 1, enrolmentKey: try f.enrolmentKey(generation: 1).publicKey(), previous: s.genesis.id)),
            previousGeneration: 0)
        let again = s.evaluate(s.before + s.forged + s.genuine + [another], pin: settled.pin)
        #expect(again.unsettled && again.pin?.credential == s.change.id)
        #expect(again.state?.standing(of: S.laptop) == .revoked)
    }

    /// Threat: the same key holder writes a second genesis entry under the member's account key. One genesis entry
    /// was required exactly, so one more removed the member's registry for everyone else after their next relaunch,
    /// and nothing the member's devices signed was read. The genesis entry a device anchored is the only one it
    /// uses; with none anchored, two anchor neither.
    @Test("a second genesis entry under a member's account key neither replaces nor removes the registry anchored")
    func memberRegistrySecondGenesis() throws {
        typealias S = MemberRegistryScenario
        let s = try S()
        var f = s.f
        let second = f.genesis(device: S.laptop)
        #expect(second.id != s.genesis.id)

        let anchored = s.evaluate(s.before + s.genuine, pin: nil)
        let after = s.evaluate(s.before + s.genuine + [second], pin: anchored.pin)
        #expect(after.pin?.genesis == s.genesis.id && after.pin?.credential == s.change.id)
        #expect(after.state?.standing(of: S.phone) == .active && after.state?.standing(of: S.laptop) == .revoked)
        #expect(after.unsettled && after.disagreement == [second.id])

        let fresh = s.evaluate(s.before + s.genuine + [second], pin: nil)
        #expect(fresh.state == nil && fresh.pin == nil && fresh.unsettled)
        // What was anchored is not on the transport now: nothing new is believed, and the anchor stays.
        let withheld = s.evaluate([second], pin: anchored.pin)
        #expect(!withheld.complete && withheld.pin == anchored.pin && withheld.state == nil)
    }

    /// Threat: A8 edits the file that remembers what this device anchored of the other members' registries, to move
    /// an anchor onto a branch of its choosing or back before a revocation. The file is signed by the account, for
    /// one vault: anything else is refused whole, and the device anchors again from what the transport shows.
    @Test("the saved anchors of other members' registries are signed, and refused whole if they do not verify")
    func memberRegistryPinsAreSigned() throws {
        typealias S = MemberRegistryScenario
        let s = try S()
        var generator = SeededGenerator(seed: 4)
        let me = Keyset.generate(
            accountID: UUID(uuidString: "AC000000-0000-4000-8000-0000000000BB")!, using: &generator)
        let bundle = try me.publicKeyBundle()
        let vaultID = UUID(uuidString: "5A000000-0000-4000-8000-0000000000CC")!
        let anchor = MemberRegistryAnchor(accountID: s.f.accountID, signingKey: s.f.accountSigningKey)
        let pins = [
            anchor: MemberRegistryPin(
                genesis: s.genesis.id, credential: s.change.id,
                settled: VaultSession.disagreementDigest([s.forgedTip.id]))
        ]
        let saved = try MemberRegistryPins.signed(pins, account: bundle.accountID, vaultID: vaultID, keyset: me)
        #expect(MemberRegistryPins.parse(saved, account: bundle, vaultID: vaultID) == pins)
        #expect(MemberRegistryPins.parse(saved, account: bundle, vaultID: UUID()) == nil, "another vault's")
        #expect(MemberRegistryPins.parse(saved + [0], account: bundle, vaultID: vaultID) == nil)
        #expect(MemberRegistryPins.parse(Array(saved.dropLast()), account: bundle, vaultID: vaultID) == nil)
        for position in stride(from: 0, to: saved.count, by: 7) {
            var edited = saved
            edited[position] ^= 0x01
            #expect(MemberRegistryPins.parse(edited, account: bundle, vaultID: vaultID) == nil, "byte \(position)")
        }
        let other = Keyset.generate(accountID: bundle.accountID, using: &generator)
        let forged = try MemberRegistryPins.signed(pins, account: bundle.accountID, vaultID: vaultID, keyset: other)
        #expect(MemberRegistryPins.parse(forged, account: bundle, vaultID: vaultID) == nil)
    }
}
