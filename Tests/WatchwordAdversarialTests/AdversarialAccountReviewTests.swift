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

/// What the review of the keys fixes (Z1 to Z8) found still open (docs/06-adversarial-review.md, Z9 onwards).
extension AdversarialAccountTests {
    /// Writes `header` into `device`'s file as the account's own header, with the account row's columns to match:
    /// what A8 can do to the database of a locked device.
    static func plantOwnHeader(_ header: AccountHeaderObject, entries: [RegistryEntry], in device: TestVault)
        async throws
    {
        let store = try #require(device.store as? InMemoryRecordStore)
        var account = try #require(await store.loadAccount())
        let existing = try #require(await store.record(VaultSession.headerKey(account.accountID)))
        await store.tamper(VaultSession.headerRow(header, recordID: account.accountID, version: existing.version + 1))
        account.kdf = header.kdf
        account.salt = header.salt
        account.unlockKeyID = header.unlockKeyID
        account.wrappedKeyset = header.wrappedKeyset
        account.keysetVersion = header.keysetVersion
        account.credentialGeneration = header.generation
        await store.tamper(account: account)
        for entry in entries { await store.tamper(VaultSession.registryRow(entry, account: account)) }
    }

    // MARK: - A header one generation ahead of the anchor (Z9)

    /// Threat: the holder of a device the person revoked with a password change (account key, the device's key, the
    /// Secret Key and the retired password), together with A8 on a laptop that has not been given the new password.
    /// They make a change of their own from the generation before, with the retired password under a new salt,
    /// sealing a back-dated revocation of the phone that revoked them, and write its header into the laptop's file
    /// as the laptop's *own* header, one generation ahead of what the Keychain anchors. The laptop took a row ahead
    /// of its anchor as its own interrupted step: the retired password opened it, nothing was pending along the
    /// planted branch, and the anchor moved onto it for good, with the phone revoked and the genuine change a fork.
    @Test(
        "a header planted one generation ahead of the anchor is not this device's own step",
        arguments: ["told of the genuine change", "not told of it"])
    func headerAheadOfTheAnchor(variant: String) async throws {
        let f = try await Self.fixture()
        let laptop = try await f.enrolled(Self.deviceB)
        let lost = try await f.enrolled(Self.deviceX)
        let phone = try #require(await f.a.session.account?.deviceID)
        let rogue = try await Self.rogueChange(from: lost, revoking: phone, passwords: [TestVault.password])
        try await f.a.session.revokeDevice(
            Self.deviceX, password: .change(current: TestVault.password, new: Self.newPassword))
        try await f.a.session.sync()
        let genuine = try await f.registryView(f.a).state.credential.id
        let told = variant == "told of the genuine change"
        if told { #expect(try await laptop.session.syncAll().awaitingNewPassword) }
        await laptop.session.lock()
        let anchored = try #require(await laptop.session.readAnchor(f.accountID))

        // Every entry the revoked device holds, as A8 would copy them from the transport, and its own.
        let lostStore = try #require(lost.store as? InMemoryRecordStore)
        let known = await lostStore.records(in: f.accountID, kind: .deviceRegistry).compactMap {
            try? RegistryEntry.parse($0.envelope)
        }
        try await Self.plantOwnHeader(rogue.headers[0], entries: known + rogue.entries, in: laptop)
        let relaunched = laptop.relaunched()
        await #expect(throws: VaultError.passwordChangedOnAnotherDevice) {
            try await relaunched.session.unlock(password: TestVault.password)
        }
        #expect(try await relaunched.session.state() == .locked)
        #expect(await relaunched.session.readAnchor(f.accountID)?.credential == anchored.credential)
        #expect(try await relaunched.session.isAwaitingNewPassword())

        // The person who did not change it opens the device as it is: nothing is followed, nothing moves.
        try await relaunched.session.unlock(password: TestVault.password, ignoringPasswordChange: true)
        let after = try #require(await relaunched.session.readAnchor(f.accountID))
        #expect(after.credential == anchored.credential && after.generation == anchored.generation)
        #expect(try await relaunched.session.isAwaitingNewPassword())
        let report = try await relaunched.session.syncAll()
        #expect(report.awaitingNewPassword)
        #expect(await relaunched.session.readAnchor(f.accountID)?.credential == anchored.credential)
        await relaunched.session.lock()

        // The new password still reaches the genuine change.
        try await relaunched.session.unlock(password: Self.newPassword)
        let state = try await f.registryView(relaunched).state
        #expect(state.credential.id == genuine)
        #expect(state.standing(of: phone) == .active && state.standing(of: Self.deviceX) == .revoked)
        await relaunched.session.lock()
        await #expect(throws: CryptoError.authenticationFailed) {
            try await relaunched.session.unlock(password: TestVault.password)
        }
    }

    /// The anchor as a crash between a step's commit and its pin leaves it: the anchor from before, with the intent
    /// the step wrote first, naming the credential entry and the header row now in the file.
    static func interruptedStep(_ device: TestVault, before: RegistryAnchor) async throws -> RegistryAnchor {
        let account = try #require(await device.session.account)
        let row = try #require(try await device.session.storedHeader(account)).row
        var interrupted = before
        interrupted.intent = RegistryAnchor.Intent(
            credential: try AccountHeaderObject.parse(row.envelope).credentialID,
            header: ObjectDigest(hashing: row.envelope))
        await device.keychain.overwrite(
            .deviceRegistryAnchor(accountID: account.accountID), with: interrupted.encoded())
        return interrupted
    }

    /// Threat: a device still registered, in hands that know the password the person retired, has published a fork
    /// from the generation before, made with that password. The person changes the password on this device and the
    /// app dies between the commit and the anchor's pin. The anchor still followed the old credential entry, so the
    /// fork counted as *pending* along it, and the retired password, typed at the lock screen, adopted it (Z8's
    /// outcome, by a crash). The intent written before the commit makes the anchor follow the change at the next
    /// read: the fork is a fork, never tried from the lock screen, and the new password opens as it should.
    @Test("a password change interrupted before its pin is completed from the intent, and a fork stays a fork")
    func interruptedPasswordChange() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        let insider = try await f.enrolled(Self.deviceP1)
        let fork = try await Self.rogueChange(from: insider, passwords: [TestVault.password])
        try await b.session.sync()
        let before = try #require(await b.session.readAnchor(f.accountID))
        try await b.session.changePassword(current: TestVault.password, new: Self.newPassword)
        let changed = try await f.registryView(b).state.credential.id
        await b.session.lock()
        let interrupted = try await Self.interruptedStep(b, before: before)
        #expect(interrupted.intent?.credential == changed)

        // The fork arrives, and a sync keeps its header.
        await Self.plant(fork, in: f)
        let relaunched = b.relaunched()
        _ = try await relaunched.session.syncAll()
        await #expect(throws: CryptoError.authenticationFailed) {
            try await relaunched.session.unlock(password: TestVault.password)
        }
        let settled = try #require(await relaunched.session.readAnchor(f.accountID))
        #expect(settled.credential == changed && settled.intent == nil && settled.generation == 1)
        #expect(try await f.registryView(relaunched).state.forkedCredentials.map(\.id) == [fork.credentials[0].id])
        try await relaunched.session.unlock(password: Self.newPassword)
        #expect(try await !relaunched.session.isAwaitingNewPassword())
    }

    /// The other own step, adoption, interrupted the same way, on a device whose anchor had recorded the change as
    /// pending: the pending list must not outlive the step that followed it (a device locked out by its own
    /// adoption), and the step is completed, not taken for a change made elsewhere.
    @Test("an adoption interrupted before its pin is completed from the intent, not refused as pending")
    func interruptedAdoption() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        try await f.a.session.changePassword(current: TestVault.password, new: Self.newPassword)
        try await f.a.session.sync()
        let genuine = try await f.registryView(f.a).state.credential.id
        #expect(try await b.session.syncAll().awaitingNewPassword)
        await b.session.lock()
        let before = try #require(await b.session.readAnchor(f.accountID))
        #expect(before.pending == [genuine])
        try await b.session.unlock(password: Self.newPassword)
        await b.session.lock()
        _ = try await Self.interruptedStep(b, before: before)

        let relaunched = b.relaunched()
        #expect(try await !relaunched.session.isAwaitingNewPassword())
        try await relaunched.session.unlock(password: Self.newPassword)
        let settled = try #require(await relaunched.session.readAnchor(f.accountID))
        #expect(settled.credential == genuine && settled.pending.isEmpty && settled.intent == nil)
    }

    /// An intent for a step that was never committed (the app died before the commit) is dropped, and the device
    /// follows what it followed. One naming a header the file does not hold, while the file holds a header ahead of
    /// the anchor that no intent named (A8 writing a planted header into the window), is no step of this device's:
    /// a change is pending, and the intent is not dropped on the file's word.
    @Test("an intent the file does not bear out is dropped if nothing was committed, and is no licence otherwise")
    func intentNotBorneOut() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        let lost = try await f.enrolled(Self.deviceX)
        await b.session.lock()
        var anchor = try #require(await b.session.readAnchor(f.accountID))
        anchor.intent = RegistryAnchor.Intent(
            credential: ObjectDigest(hashing: [1]), header: ObjectDigest(hashing: [2]))
        await b.keychain.overwrite(.deviceRegistryAnchor(accountID: f.accountID), with: anchor.encoded())
        let relaunched = b.relaunched()
        try await relaunched.session.unlock(password: TestVault.password)
        #expect(await relaunched.session.readAnchor(f.accountID)?.intent == nil)
        await relaunched.session.lock()

        await b.keychain.overwrite(.deviceRegistryAnchor(accountID: f.accountID), with: anchor.encoded())
        let rogue = try await Self.rogueChange(from: lost, passwords: [TestVault.password])
        let lostStore = try #require(lost.store as? InMemoryRecordStore)
        let known = await lostStore.records(in: f.accountID, kind: .deviceRegistry).compactMap {
            try? RegistryEntry.parse($0.envelope)
        }
        try await Self.plantOwnHeader(rogue.headers[0], entries: known + rogue.entries, in: b)
        let planted = b.relaunched()
        await #expect(throws: VaultError.passwordChangedOnAnotherDevice) {
            try await planted.session.unlock(password: TestVault.password)
        }
        #expect(await planted.session.readAnchor(f.accountID) == anchor)
    }

    /// The anchor's third form (Z9): an intent round-trips, the second form reads as having none, and an intent
    /// flag other than 0 or 1, or an intent cut short, is no anchor.
    @Test("the Keychain anchor round-trips an intent, reads its second form, and refuses a malformed intent")
    func anchorIntentEncoding() throws {
        let digests = (1...8).map { ObjectDigest(hashing: [UInt8($0)]) }
        let intent = RegistryAnchor.Intent(credential: digests[5], header: digests[6])
        let anchor = RegistryAnchor(
            genesis: digests[0], credential: digests[1], generation: 3, heads: [digests[2]], pending: [digests[3]],
            intent: intent)
        let encoded = anchor.encoded()
        #expect(Array(encoded.prefix(5)) == Array("WWRA3".utf8))
        #expect(RegistryAnchor(bytes: encoded) == anchor)
        var none = anchor
        none.intent = nil
        #expect(RegistryAnchor(bytes: none.encoded()) == none && none.encoded().count == encoded.count - 64)
        #expect(RegistryAnchor(bytes: Array(encoded.dropLast())) == nil)
        #expect(RegistryAnchor(bytes: Array(encoded.dropLast(64))) == nil, "flag set, intent missing")
        #expect(RegistryAnchor(bytes: encoded + [0]) == nil)
        var badFlag = none.encoded()
        badFlag[badFlag.count - 1] = 2
        #expect(RegistryAnchor(bytes: badFlag) == nil)

        // The second form: as the third, with no intent flag at all.
        let second = Array("WWRA2".utf8) + Array(none.encoded().dropFirst(5).dropLast())
        #expect(RegistryAnchor(bytes: second) == none)
        #expect(RegistryAnchor(bytes: second + [0]) == nil, "a second-form anchor with anything after its pending")
    }

    // MARK: - Another member's registry, walked a bounded number of steps at a time (Z10)

    /// A member's registry with `changes` password changes in a row, all by `device`: what anyone the chain lists can
    /// publish for nothing but the signatures they already make.
    static func longChain(_ changes: Int, seed: UInt64 = 31) -> (f: RegistryFixture, entries: [RegistryEntry]) {
        var f = RegistryFixture(seed: seed)
        let phone = RegistryFixture.deviceID(0xA0)
        let genesis = f.genesis(device: phone)
        var entries = [genesis]
        var previous = genesis
        for generation in 1...changes {
            _ = f.nextUnlockKey()
            previous = f.credential(generation: generation, previous: previous, by: phone, parents: [previous])
            entries.append(previous)
        }
        return (f, entries)
    }

    /// Threat: a member of a shared vault (A4), or anyone a chain lists or listed, publishes a legitimate chain of
    /// thousands of password changes in their own registry. Each refresh of another member's device walked it to the
    /// end, one to eight full replays a step, on the session's actor and before any vault's log, so first sight (or
    /// a lost pin) held `lock()`, AutoFill and every vault's sync behind tens of minutes of work, and a process killed
    /// meanwhile started again from the same place. Now one refresh takes a bounded number of steps and the pin
    /// carries the progress to the next.
    @Test("one refresh follows a member's password changes a bounded number of steps, and the pin carries on")
    func memberRegistryWalkIsBounded() throws {
        let (f, entries) = Self.longChain(20)
        let raw = entries.map { $0.serialized() }
        var pin: MemberRegistryPin?
        var reached: UInt64 = 0
        var refreshes = 0
        while reached < 20, refreshes < 10 {
            let evaluated = VaultSession.evaluateMemberRegistry(
                raw, accountID: f.accountID, signingKey: f.accountSigningKey, pin: pin)
            refreshes += 1
            let generation = try #require(evaluated.state?.credential.generation)
            #expect(
                generation - reached <= VaultSession.memberRegistryStepsPerRefresh,
                "refresh \(refreshes) walked \(generation - reached) steps")
            #expect(!evaluated.unsettled)
            reached = generation
            pin = evaluated.pin
        }
        #expect(reached == 20 && refreshes == 3)
    }

    // MARK: - The branch published first is not the branch trusted (Z12)

    /// Threat: the D9 adversary of Z6, on a device that anchored the member's registry long before the theft. The
    /// laptop's holder publishes the forged branch first (they have the keys from the moment of theft; no collusion
    /// with the store is needed), and exactly one change then follows the anchored entry, so the device moved
    /// forward onto it and pinned it. When the member's own change arrived it "left the chain at or before the
    /// anchored entry": never followed, reported only, and the takeover stood (the laptop writing as the member, the
    /// phone revoked) on every member's device that had been anchored before. Now the entry first anchored is kept as
    /// the base, apart from the tip followed: a change beside any followed entry beyond the base is a competing
    /// branch, and only devices every branch keeps count.
    @Test("a branch followed forward does not win over a sibling that arrives later, beyond the entry first anchored")
    func firstPublishedBranchDoesNotWin() throws {
        typealias S = MemberRegistryScenario
        let s = try S()
        let early = s.evaluate(s.before, pin: nil)
        #expect(early.pin?.credential == s.genesis.id)

        let forward = s.evaluate(s.before + s.forged, pin: early.pin)
        #expect(forward.pin?.credential == s.forgedTip.id, "one change followed the anchored entry: followed")
        #expect(forward.state?.standing(of: S.laptop) == .active && !forward.unsettled)

        let late = s.evaluate(s.before + s.forged + s.genuine, pin: forward.pin)
        #expect(late.unsettled && late.disagreement.contains(s.change.id))
        #expect(late.state?.devices[S.laptop] == nil && late.state?.devices[S.phone] == nil, "a branch was taken")
        #expect(late.state?.standing(of: S.tablet) == .active)
        #expect(late.state?.credential.id == s.genesis.id, "the registry stands at the entry both branches leave")
        // The tip followed is kept: if the member's change is withheld again, nothing new is believed of it.
        #expect(late.pin?.credential == s.forgedTip.id && late.pin?.genesis == s.genesis.id)
    }

    /// The saved pins' second format (Z12) carries the base; one saved in the first, before the base existed, is read
    /// with the base at the credential it followed, which is what that version trusted. Signed as before: an edited
    /// blob of either format is refused whole.
    @Test("member pins round-trip their base, and pins of the first format read with the base at the tip")
    func memberPinsCarryTheBase() throws {
        typealias S = MemberRegistryScenario
        let s = try S()
        var generator = SeededGenerator(seed: 5)
        let me = Keyset.generate(
            accountID: UUID(uuidString: "AC000000-0000-4000-8000-0000000000BC")!, using: &generator)
        let bundle = try me.publicKeyBundle()
        let vaultID = UUID(uuidString: "5A000000-0000-4000-8000-0000000000CD")!
        let anchor = MemberRegistryAnchor(accountID: s.f.accountID, signingKey: s.f.accountSigningKey)
        let pin = MemberRegistryPin(genesis: s.genesis.id, base: s.genesis.id, credential: s.forgedTip.id, settled: nil)
        let saved = try MemberRegistryPins.signed(
            [anchor: pin], account: bundle.accountID, vaultID: vaultID, keyset: me)
        #expect(saved[4] == 2)
        #expect(MemberRegistryPins.parse(saved, account: bundle, vaultID: vaultID) == [anchor: pin])

        var first = Array("WWMD".utf8) + [1] + SharedBytes.bytes(bundle.accountID) + SharedBytes.bytes(vaultID)
        first += SharedBytes.littleEndian16(1)
        first += SharedBytes.bytes(anchor.accountID) + anchor.signingKey + s.genesis.id.bytes + s.change.id.bytes + [0]
        let signed = first + (try me.sign(first, domain: .membership))
        let read = try #require(MemberRegistryPins.parse(signed, account: bundle, vaultID: vaultID)?[anchor])
        #expect(read.base == s.change.id && read.credential == s.change.id && read.genesis == s.genesis.id)
        var edited = signed
        edited[4] = 2
        #expect(MemberRegistryPins.parse(edited, account: bundle, vaultID: vaultID) == nil)
    }

    // MARK: - The way out of too many pending changes is not spent in the adversary's order (Z13)

    /// Devices the holder of a revoked device registers with the enrolment key of the generation it knew (the retired
    /// password's), each publishing a two-step chain of password changes under keys nobody derives, with headers:
    /// what it takes to sort every one of them ahead of a genuine change one generation up.
    static func puppetChanges(from lost: TestVault, count: Int, seed: UInt64 = 4040) async throws -> RogueChange {
        let session = lost.session
        let account = try #require(await session.account)
        let keys = try #require(await session.keys)
        let view = try await session.registry(account)
        var generator = SeededGenerator(seed: seed)
        let enrolment = EnrolmentKey.derive(from: keys.accountUnlockKey, accountID: account.accountID)
        var change = RogueChange()
        for index in 0..<count {
            let id = UUID(uuidString: String(format: "D1000000-0000-4000-8000-%012X", index + 1))!
            let key = SoftwareDeviceKey.generate(using: &generator)
            var registration = RegistryEntry(
                accountID: account.accountID, parents: view.state.heads,
                author: .enrolment(credential: view.state.credential.id),
                body: .add(RegistryDevice(id: id, key: try key.publicKey(), label: [])))
            registration.accountSignature = try keys.keyset.sign(registration.accountMessage, domain: .deviceRegistry)
            registration.authorSignature = try enrolment.sign(registration.enrolmentMessage, domain: .deviceRegistry)
            change.entries.append(registration)
            var parents = [registration.id]
            var previous = view.state.credential.id
            var previousEnrolment = enrolment
            var generation = account.credentialGeneration
            for _ in 0..<2 {
                generation += 1
                let unlockKey = EncryptionKey.generate(using: &generator)
                let next = EnrolmentKey.derive(from: unlockKey, accountID: account.accountID)
                var credential = RegistryEntry(
                    accountID: account.accountID, parents: parents, author: .device(id),
                    body: .credential(generation: generation, enrolmentKey: try next.publicKey(), previous: previous))
                credential.accountSignature = try keys.keyset.sign(credential.accountMessage, domain: .deviceRegistry)
                credential.authorSignature = try key.sign(
                    prepared: DeviceSignatures.signedBytes(
                        domain: .deviceRegistry, deviceID: id, message: credential.deviceMessage))
                credential.previousCredentialSignature = try previousEnrolment.sign(
                    credential.previousCredentialMessage, domain: .deviceRegistry)
                let salt = (0..<account.kdf.saltLength).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
                var header = AccountHeaderObject(
                    accountID: account.accountID, generation: generation, author: id, kdf: account.kdf, salt: salt,
                    unlockKeyID: unlockKey.keyID, keysetVersion: generation, credentialID: credential.id,
                    genesisID: view.state.genesis,
                    wrappedKeyset: try keys.keyset.wrap(with: unlockKey, recordVersion: generation, using: &generator))
                try header.bind(personalVaultID: account.personalVaultID, unlockKey: unlockKey, using: &generator)
                header.accountSignature = try keys.keyset.sign(header.signedPart, domain: .accountHeader)
                header.deviceSignature = try key.sign(
                    prepared: DeviceSignatures.signedBytes(
                        domain: .accountHeader, deviceID: id, message: header.signedPart))
                change.entries.append(credential)
                change.credentials.append(credential)
                change.headers.append(header)
                parents = [credential.id]
                previous = credential.id
                previousEnrolment = next
            }
        }
        return change
    }

    /// Threat: the holder of the device the person revoked knows the retired password, so holds that generation's
    /// enrolment key. It registers seventeen puppets with it, and each publishes a two-step chain of changes. On a
    /// device still at the old generation, the three attempts of the lock screen went to puppets (their changes sort
    /// first by generation and ID, both the adversary's choice), then `tooManyPasswordChangesPending`; and the list
    /// the person was to choose from held sixteen puppets and not the genuine change, so it could not be followed.
    /// Every author is listed, and those whose registration the checkpoint this device follows had sealed go first,
    /// in the list and in the lock screen's attempts.
    @Test("puppets registered with the retired password do not crowd the genuine change out of the way out")
    func puppetsDoNotCrowdOutTheGenuineChange() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        let lost = try await f.enrolled(Self.deviceX)
        let phone = try #require(await f.a.session.account?.deviceID)
        let puppets = try await Self.puppetChanges(from: lost, count: 17)
        try await f.a.session.revokeDevice(
            Self.deviceX, password: .change(current: TestVault.password, new: Self.newPassword))
        try await f.a.session.sync()
        let genuine = try await f.registryView(f.a).state.credential.id
        await Self.plant(puppets, in: f)

        #expect(try await b.session.syncAll().awaitingNewPassword)
        await b.session.lock()
        let listed = try await b.session.pendingPasswordChanges()
        #expect(listed.count == 18, "every author is listed")
        #expect(listed.first?.device == phone, "the device the followed checkpoint sealed goes first")
        #expect(listed.first?.registeredBeforeFollowed == true)
        #expect(listed.dropFirst().allSatisfy { !$0.registeredBeforeFollowed })
        #expect(listed.filter(\.isDescribed).count == VaultSession.maximumChangesDescribed)
        // A row the list did not work out is worked out when the person selects it.
        let last = try #require(listed.last)
        #expect(!last.isDescribed)
        let described = try await b.session.describePasswordChange(by: last.device)
        #expect(described.isDescribed && described.canBeFollowed && !described.revokesThisDevice)

        try await b.session.unlock(password: Self.newPassword)
        #expect(try await f.registryView(b).state.credential.id == genuine)
    }

    // MARK: - Following a change takes the password this device follows (Z14)

    /// Threat: Z8's adversary (a registered device in hands that know a retired password, which has published a fork
    /// made with it), with a minute at the person's unlocked device, or one opened by quick unlock (A3). Following a
    /// change asked only for an unlocked session, so they moved the device onto their fork. It now takes the
    /// password the device follows, re-derived under the stored header, as removing a device does.
    @Test("following a password change from a quick-unlocked session takes the password this device follows")
    func followNeedsTheCurrentPassword() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        let insider = try await f.enrolled(Self.deviceP1)
        let rogue = try await Self.rogueChange(from: insider, passwords: ["the insider's password"])
        try await f.a.session.changePassword(current: TestVault.password, new: Self.newPassword)
        try await f.a.session.sync()
        try await b.session.sync()
        await b.session.lock()
        try await b.session.unlock(password: Self.newPassword)
        try await b.session.enableQuickUnlock(password: Self.newPassword)
        await Self.plant(rogue, in: f)
        try await b.session.sync()
        await b.session.lock()
        try await b.session.quickUnlock()
        let followed = try #require(await b.session.readAnchor(f.accountID))

        for current in ["the insider's password", TestVault.password] {
            await #expect(throws: CryptoError.authenticationFailed) {
                try await b.session.followPasswordChange(
                    by: Self.deviceP1, current: current, password: "the insider's password")
            }
        }
        #expect(await b.session.readAnchor(f.accountID) == followed)
        try await b.session.followPasswordChange(
            by: Self.deviceP1, current: Self.newPassword, password: "the insider's password")
        #expect(try await f.registryView(b).state.credential.id == rogue.credentials[0].id)
    }

    /// Not an attack: a sync that receives a vault key, or a vault created, while a change is being followed puts
    /// another object in the session's keys. The follow had committed, and returned success with the retired
    /// Account Unlock Key still resident (so an enrolment of quick unlock, or a registration, made with it later
    /// would be under credentials the account no longer has). What must match is the keyset, not the object.
    @Test("keys replaced while a change is followed still end with the new Account Unlock Key resident")
    func followWithKeysReplacedMeanwhile() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        try await f.a.session.changePassword(current: TestVault.password, new: Self.newPassword)
        try await f.a.session.sync()
        try await b.session.sync()
        await b.session.lock()
        try await b.session.unlock(password: TestVault.password, ignoringPasswordChange: true)
        let session = b.session
        let fired = Flag()
        await b.keychain.onStore { item in
            guard case .deviceRegistryAnchor = item, !fired.isSet else { return }
            fired.set()
            _ = try? await session.createVault(name: "Meanwhile")
        }
        let phone = try #require(await f.a.session.account?.deviceID)
        try await b.session.followPasswordChange(by: phone, current: TestVault.password, password: Self.newPassword)
        await b.keychain.onStore(nil)
        #expect(fired.isSet, "nothing replaced the keys: nothing is tested")
        let account = try #require(await b.session.account)
        #expect(await b.session.keys?.accountUnlockKey.keyID == account.unlockKeyID)
        #expect(try await b.session.vaults().contains { $0.name == "Meanwhile" })
    }

    /// A3 or auto-lock locks while a candidate header's derivation runs, at its author's parameters: from an
    /// unlocked session following a change, and at the lock screen. The derivation is off the actor, so the lock
    /// takes effect at once, and nothing is adopted after it. The hook holds the derivation until the test has
    /// locked; with the derivation back on the actor the lock waits out the hook's 60-second bound.
    @Test("a lock while a candidate header's key is derived takes effect at once, and nothing is adopted")
    func lockWinsDuringCandidateDerivation() async throws {
        for fromLockScreen in [false, true] {
            let f = try await Self.fixture()
            let b = try await f.enrolled(Self.deviceB)
            try await f.a.session.changePassword(current: TestVault.password, new: Self.newPassword)
            try await f.a.session.sync()
            try await b.session.sync()
            await b.session.lock()
            if !fromLockScreen {
                try await b.session.unlock(password: TestVault.password, ignoringPasswordChange: true)
            }
            let before = try #require(await b.session.readAnchor(f.accountID))
            let phone = try #require(await f.a.session.account?.deviceID)

            let (reached, reaching) = AsyncStream.makeStream(of: Void.self)
            let release = DispatchSemaphore(value: 0)
            let released = Flag()
            await b.session.setAwayWorkHook { current in
                guard current == .candidateDerivation else { return }
                reaching.yield()
                if release.wait(timeout: .now() + 60) == .success { released.set() }
            }
            let session = b.session
            let work = Task {
                if fromLockScreen {
                    try await session.unlock(password: Self.newPassword)
                } else {
                    try await session.followPasswordChange(
                        by: phone, current: TestVault.password, password: Self.newPassword)
                }
            }
            var iterator = reached.makeAsyncIterator()
            _ = await iterator.next()
            await b.session.lock()
            #expect(await b.session.keys == nil)
            release.signal()
            await #expect(throws: fromLockScreen ? VaultError.lockedDuringUnlock : VaultError.locked) {
                try await work.value
            }
            #expect(released.isSet, "lock() returned only after the derivation had given up waiting")
            #expect(await b.session.readAnchor(f.accountID) == before)
            #expect(await b.session.account?.credentialGeneration == 0)
            await b.session.setAwayWorkHook(nil)
        }
    }
}
