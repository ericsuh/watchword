import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordSharing
import WatchwordSync
import WatchwordTestSupport

/// The sharing board as A1 runs it, able to hold one fetch until released, so a test can act while a session's step
/// is suspended there. Test code only.
actor GatedBoard: SharingBoard {
    let base: InMemorySharingBoard
    private var holding = false
    private var reached: CheckedContinuation<Void, Never>?
    private var held: CheckedContinuation<Void, Never>?
    private var arrived = false

    init(base: InMemorySharingBoard) {
        self.base = base
    }

    func holdNextFetch() {
        holding = true
        arrived = false
    }

    /// Returns once a held fetch has arrived.
    func waitUntilHeld() async {
        if arrived { return }
        await withCheckedContinuation { reached = $0 }
    }

    func release() {
        held?.resume()
        held = nil
    }

    func create(_ name: String, contents: [UInt8]) async throws {
        try await base.create(name, contents: contents)
    }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        if holding {
            holding = false
            arrived = true
            reached?.resume()
            reached = nil
            await withCheckedContinuation { held = $0 }
        }
        return try await base.fetch(name, maximumLength: maximumLength)
    }
}

/// Vault sharing codes through real sessions (ADR 0010, security analysis: "Lock", "No vouching", "A4, A5", and the
/// session's own rules). In the suite "shared vaults through the session"; the adversaries are those of §2.
extension AdversarialSharedVaultTests {
    /// The number a starter's status shows, parsed.
    static func number(_ status: SharingCodeStatus) throws -> SharingSessionNumber {
        let text = try #require(status.number)
        return try #require(SharingSessionNumber(typed: text))
    }

    /// An account whose sharing board is `board` rather than the household's.
    static func account(_ household: SharedVaultHousehold, seed: UInt64, board: any SharingBoard) async throws
        -> SharingAccount
    {
        try await SharingAccount.make(
            over: household.transport, directory: household.directory, seed: seed, board: board)
    }

    /// Threat: a lock (auto-lock, the person switching away) while a step waits on the board, which A1 can stretch
    /// as it likes (ADR 0010, "Lock": `lock()` wins). The session is dropped at the lock; the step that resumes
    /// afterwards throws, keeps nothing and pins nothing, and the next step finds no session.
    @Test("a lock while a step waits on the board ends the session, and nothing the step saw is kept or pinned")
    func lockMidSession() async throws {
        let household = SharedVaultHousehold()
        let gated = GatedBoard(base: household.board)
        let starter = try await Self.account(household, seed: 1_201, board: gated)
        let joiner = try await household.account(seed: 1_202)
        let started = try await starter.session.startSharingCodeSession()
        _ = try await joiner.session.joinSharingCodeSession(number: try #require(started.number))

        await gated.holdNextFetch()
        let step = Task { try await starter.session.refreshSharingCodeSession() }
        await gated.waitUntilHeld()
        await starter.session.lock()
        await gated.release()
        await #expect(throws: VaultError.locked) { _ = try await step.value }
        #expect(await starter.session.sharingCodeStatus() == nil)
        try await starter.session.unlock(password: TestVault.password)
        await #expect(throws: SharingCodeError.notReady) { _ = try await starter.session.refreshSharingCodeSession() }
        let reveal = SharingBoardName.reveal(try Self.number(started))
        #expect(await household.board.allObjects[reveal] == nil, "no reveal was made")
        let pins = VerifiedContacts(store: starter.contacts, account: starter.bundle)
        #expect(try await pins.pinned(joiner.accountID) == nil)
    }

    /// Threat: two steps of one session at once (a screen's timer and a tap, or a hostile UI): with two replies read,
    /// a starter could reveal for the second after its nonce was public (ADR 0010, "The reveal is made once"). The
    /// session runs one step at a time and refuses the other (`busy`), which changes nothing.
    @Test("a second step while one is running is refused and changes nothing")
    func oneStepAtATime() async throws {
        let household = SharedVaultHousehold()
        let gated = GatedBoard(base: household.board)
        let starter = try await Self.account(household, seed: 1_211, board: gated)
        let joiner = try await household.account(seed: 1_212)
        let started = try await starter.session.startSharingCodeSession()
        _ = try await joiner.session.joinSharingCodeSession(number: try #require(started.number))

        await gated.holdNextFetch()
        let first = Task { try await starter.session.refreshSharingCodeSession() }
        await gated.waitUntilHeld()
        await #expect(throws: SharingCodeError.busy) { _ = try await starter.session.refreshSharingCodeSession() }
        await #expect(throws: SharingCodeError.busy) { _ = try await starter.session.enterSharingCode("123456") }
        await gated.release()
        let status = try await first.value
        #expect(status.step == .typeTheirCode && status.attemptsLeft == 3)
        let shown = try await joiner.session.refreshSharingCodeSession()
        #expect(try await starter.session.enterSharingCode(try #require(shown.ownCode)).pinned)
    }

    /// Threat: an administrator (A4 with the role, or an honest one) vouching for the owner (ADR 0010, "No
    /// vouching"): the invitee checked the administrator in a session, and the invitation names the vault's owner,
    /// whom the invitee has not checked. Accepting needs the owner pinned by the invitee's own check: refused until
    /// then, and accepted after a session with the owner.
    @Test("an administrator's invitation is accepted only once the invitee checked the owner themselves")
    func noVouching() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.administrator], seed: 1_220)
        let administrator = members[0]
        let invitee = try await household.account(seed: 1_229)
        try await administrator.checkSharingCode(with: invitee)
        let invitation = try await administrator.session.inviteThroughSharingCode(to: vaultID, as: .readWrite)
        try await administrator.session.sync()
        let received = try #require(try await invitee.session.sharingCodeInvitation())
        #expect(received == invitation && received.ownerAccountID == owner.accountID)
        await #expect(throws: SharingError.fingerprintNotVerified) {
            try await invitee.session.acceptInvitation(received)
        }
        #expect(
            try await VerifiedContacts(store: invitee.contacts, account: invitee.bundle).pinned(owner.accountID) == nil,
            "the administrator's word pinned nobody")

        try await owner.checkSharingCode(with: invitee)
        try await invitee.session.acceptInvitation(received)
        try await invitee.session.sync()
        #expect(try await invitee.session.sharedVaultStatus(vaultID).role == .readWrite)
    }

    /// Threat: A1 swaps the directory's bundle for the invitee between the session and the invitation (ADR 0010:
    /// the pin is what a session evidenced, and every later use of the account's keys is checked against it). The
    /// invitation is refused as a substitution; nothing is wrapped to the new keys.
    @Test("a directory that changes the invitee's keys after the session gets no key wrapped to them")
    func directoryChangesAfterTheSession() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 1_231)
        let invitee = try await household.account(seed: 1_232)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.checkSharingCode(with: invitee)
        let fake = try SharingParty(accountID: invitee.accountID, seed: 1_239)
        await household.directory.publish(fake.bundle)
        await #expect(throws: SharingError.keySubstituted(accountID: invitee.accountID)) {
            _ = try await owner.session.inviteThroughSharingCode(to: vaultID, as: .readWrite)
        }
        #expect(await household.board.allObjects.keys.contains { $0.hasSuffix("/invitation") } == false)
    }

    /// Threat: A1 plants an invitation in a session's slot: before the joiner has checked the starter, or signed by
    /// someone else, or genuine but from another session. Nothing opens before the starter is pinned, and nothing
    /// opens that the session's starter did not sign for this session and this joiner.
    @Test("an invitation planted in a session's slot opens only if its starter signed it for this session")
    func plantedInvitation() async throws {
        let household = SharedVaultHousehold()
        let starter = try await household.account(seed: 1_241)
        let joiner = try await household.account(seed: 1_242)
        let attacker = try SharingParty(seed: 1_249)
        let started = try await starter.session.startSharingCodeSession()
        let number = try Self.number(started)
        _ = try await joiner.session.joinSharingCodeSession(number: try #require(started.number))
        await #expect(throws: SharingError.fingerprintNotVerified) {
            _ = try await joiner.session.sharingCodeInvitation()
        }

        _ = try await starter.session.refreshSharingCodeSession()
        let shown = try await joiner.session.refreshSharingCodeSession()
        let accepted = try await starter.session.enterSharingCode(try #require(shown.ownCode))
        _ = try await joiner.session.enterSharingCode(try #require(accepted.ownCode))
        let junk = Array(repeating: UInt8(0x57), count: SharingCodeJoiner.invitationLength)
        await household.board.tamper(SharingBoardName.invitation(number), contents: junk)
        await #expect(throws: SharingCodeError.invitationInvalid) {
            _ = try await joiner.session.sharingCodeInvitation()
        }
        // Signed by an attacker over a well-formed content naming an attacker's vault.
        var forged = Array(junk.prefix(SharingCodeJoiner.invitationLength - 64))
        forged = forged + (try attacker.keyset.sign(forged, domain: .membership))
        await household.board.tamper(SharingBoardName.invitation(number), contents: forged)
        await #expect(throws: SharingCodeError.invitationInvalid) {
            _ = try await joiner.session.sharingCodeInvitation()
        }
        await household.board.tamper(
            SharingBoardName.invitation(number), contents: Array(repeating: 0, count: 1 << 12))
        await #expect(throws: SharingBoardError.tooLarge) { _ = try await joiner.session.sharingCodeInvitation() }
    }

    /// Threat: settling a "keys changed" warning by a session with the wrong device (ADR 0010, A4: someone persuades
    /// the person to check with a device of theirs under the member's account, and A1 publishes its keys). The
    /// session's keys differ from the pin, so nothing is pinned on its word; the pin is replaced only on the person's
    /// explicit choice and only to keys the vault's chain lists for that member. Keys the chain does not list are
    /// refused, and the warning stays.
    @Test("a keys-changed warning is settled by a session only to the keys the vault's chain lists")
    func keysChangedSettledOnlyToListedKeys() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 1_250)
        let member = members[0]
        // The owner's pin for the member is replaced with other keys (as if an earlier check had been of the wrong
        // device): the chain's listing now differs from the pin.
        let earlier = try SharingParty(accountID: member.accountID, seed: 1_258)
        await household.directory.publish(earlier.bundle)
        try await owner.session.verifyContact(
            member.accountID, evidence: .safetyNumber(earlier.bundle.fingerprint.safetyNumber), replacingPin: true)
        try await owner.session.sync()
        #expect(try await owner.session.sharedVaultStatus(vaultID).substitutedMembers == [member.accountID])

        // A session with a device holding other keys again, under the member's account.
        let impostor = try SharingParty(accountID: member.accountID, seed: 1_259)
        await household.directory.publish(impostor.bundle)
        let started = try await owner.session.startSharingCodeSession()
        var generator = SeededGenerator(seed: 1_260)
        var joiner = try await SharingCodeJoiner.join(
            try Self.number(started), as: impostor.bundle,
            board: household.board, directory: household.directory, nonce: SharingNonce.draw(using: &generator),
            at: Date())
        _ = try await owner.session.refreshSharingCodeSession()
        try await joiner.poll(board: household.board, at: Date())
        let checked = try await owner.session.enterSharingCode(try #require(joiner.code))
        #expect(checked.step == .verified && !checked.pinned && checked.keysDifferFromPin)
        await #expect(throws: SharedVaultError.sharingCodeKeysNotListed) {
            try await owner.session.replacePinFromSharingCode(listedIn: vaultID)
        }
        await #expect(throws: SharedVaultError.sharingCodeKeysNotListed) {
            try await owner.session.replacePinFromSharingCode()
        }
        #expect(try await owner.session.sharedVaultStatus(vaultID).substitutedMembers == [member.accountID])

        // A session with the member's own device: their keys are the chain's, and the person's choice settles it.
        await household.directory.publish(member.bundle)
        try await owner.checkSharingCode(with: member)
        #expect(await owner.session.sharingCodeStatus()?.keysDifferFromPin == true)
        try await owner.session.replacePinFromSharingCode(listedIn: vaultID)
        let status = try await owner.session.sharedVaultStatus(vaultID)
        #expect(status.substitutedMembers.isEmpty && status.verifiedMembers?.contains(member.accountID) == true)
    }
}
