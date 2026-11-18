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
}
