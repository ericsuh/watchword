import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordSharing
import WatchwordSync
import WatchwordTestSupport

/// The sharing board as A1 runs it, able to hold one fetch and one create until each is released, so a test can act
/// while a session's step is suspended there. Test code only.
actor GatedBoard: SharingBoard {
    let base: InMemorySharingBoard
    private var fetchGate = Gate()
    private var createGate = Gate()

    /// One operation held: whether the next call is to be held, whether one arrived, and who waits on what.
    struct Gate {
        var holding = false
        var arrived = false
        var reached: CheckedContinuation<Void, Never>?
        var held: CheckedContinuation<Void, Never>?
    }

    init(base: InMemorySharingBoard) {
        self.base = base
    }

    func holdNextFetch() {
        fetchGate.holding = true
        fetchGate.arrived = false
    }

    func holdNextCreate() {
        createGate.holding = true
        createGate.arrived = false
    }

    /// Returns once a held fetch has arrived.
    func waitUntilHeld() async {
        if fetchGate.arrived { return }
        await withCheckedContinuation { fetchGate.reached = $0 }
    }

    /// Returns once a held create has arrived.
    func waitUntilCreateHeld() async {
        if createGate.arrived { return }
        await withCheckedContinuation { createGate.reached = $0 }
    }

    func release() {
        fetchGate.held?.resume()
        fetchGate.held = nil
    }

    func releaseCreate() {
        createGate.held?.resume()
        createGate.held = nil
    }

    func create(_ name: String, contents: [UInt8]) async throws {
        if createGate.holding {
            createGate.holding = false
            createGate.arrived = true
            createGate.reached?.resume()
            createGate.reached = nil
            await withCheckedContinuation { createGate.held = $0 }
        }
        try await base.create(name, contents: contents)
    }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        if fetchGate.holding {
            fetchGate.holding = false
            fetchGate.arrived = true
            fetchGate.reached?.resume()
            fetchGate.reached = nil
            await withCheckedContinuation { fetchGate.held = $0 }
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

    /// Where a session's invitation goes on `board`: named after the session its commit names, as A1 reads it there.
    static func invitationName(_ number: SharingSessionNumber, on board: InMemorySharingBoard) async throws -> String {
        let bytes = try #require(await board.allObjects[SharingBoardName.commit(number)])
        let commit = try SharingSessionMessage.parse(bytes, expecting: .commit)
        return SharingBoardName.invitation(number, session: commit.session)
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
        let (checked, _) = try await administrator.checkSharingCode(with: invitee)
        let invitation = try await administrator.session.inviteThroughSharingCode(
            to: vaultID, as: .readWrite, checked: checked)
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
        let (checked, _) = try await owner.checkSharingCode(with: invitee)
        let fake = try SharingParty(accountID: invitee.accountID, seed: 1_239)
        await household.directory.publish(fake.bundle)
        await #expect(throws: SharingError.keySubstituted(accountID: invitee.accountID)) {
            _ = try await owner.session.inviteThroughSharingCode(to: vaultID, as: .readWrite, checked: checked)
        }
        #expect(await household.board.allObjects.keys.contains { $0.contains("/invitation/") } == false)
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
        let slot = try await Self.invitationName(number, on: household.board)
        await household.board.tamper(slot, contents: junk)
        await #expect(throws: SharingCodeError.invitationInvalid) {
            _ = try await joiner.session.sharingCodeInvitation()
        }
        // Signed by an attacker over a well-formed content naming an attacker's vault.
        var forged = Array(junk.prefix(SharingCodeJoiner.invitationLength - 64))
        forged = forged + (try attacker.keyset.sign(forged, domain: .membership))
        await household.board.tamper(slot, contents: forged)
        await #expect(throws: SharingCodeError.invitationInvalid) {
            _ = try await joiner.session.sharingCodeInvitation()
        }
        await household.board.tamper(slot, contents: Array(repeating: 0, count: 1 << 12))
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

    /// Threat: a nearby person (A4 at the table, with an ordinary account and a live session of their own) holds their
    /// QR code where the joiner's camera reads it, or A1 withholds or spoils the reveal (ADR 0010, Scans: "the device
    /// names what it is about to pin"; G2: nothing is pinned by a failed attempt). A joiner's scan is evidence only
    /// once the scanned account's device has revealed the nonce it committed to, and is pinned only on the person's
    /// yes to the account the screen names: until then the screen never says "verified", and an ending of any kind
    /// (the session ended, a reveal that does not open, a lock) pins nothing.
    @Test("a joiner's scan pins nothing before the starter's reveal and the person's yes to the account named")
    func scannedJoinWaitsForRevealAndYes() async throws {
        let household = SharedVaultHousehold()
        let starter = try await household.account(seed: 1_261)
        let joiner = try await household.account(seed: 1_262)
        let pins = VerifiedContacts(store: joiner.contacts, account: joiner.bundle)

        // Scanned, and the session ended before any reveal.
        let first = try await starter.session.startSharingCodeSession()
        let joined = try await joiner.session.joinSharingCodeSession(scanned: try #require(first.scanPayload))
        #expect(joined.step == .waiting && !joined.pinned)
        #expect(try await pins.pinned(starter.accountID) == nil)
        await joiner.session.endSharingCodeSession()
        #expect(try await pins.pinned(starter.accountID) == nil)

        // A reveal that does not open the commitment.
        let second = try await starter.session.startSharingCodeSession()
        _ = try await joiner.session.joinSharingCodeSession(scanned: try #require(second.scanPayload))
        _ = try await starter.session.refreshSharingCodeSession()
        let revealName = SharingBoardName.reveal(try Self.number(second))
        var spoiled = try #require(await household.board.allObjects[revealName])
        spoiled[spoiled.count - 1] ^= 0x01
        await household.board.tamper(revealName, contents: spoiled)
        await #expect(throws: SharingCodeError.commitmentMismatch) {
            _ = try await joiner.session.refreshSharingCodeSession()
        }
        #expect(try await pins.pinned(starter.accountID) == nil)

        // An honest reveal: the account is named, nothing is pinned yet, and a lock drops it.
        let third = try await starter.session.startSharingCodeSession()
        _ = try await joiner.session.joinSharingCodeSession(scanned: try #require(third.scanPayload))
        _ = try await starter.session.refreshSharingCodeSession()
        let named = try await joiner.session.refreshSharingCodeSession()
        #expect(named.step == .confirmScannedAccount && named.partner == starter.accountID && !named.pinned)
        #expect(try await pins.pinned(starter.accountID) == nil)
        await joiner.session.lock()
        try await joiner.session.unlock(password: TestVault.password)
        #expect(await joiner.session.sharingCodeStatus() == nil)
        #expect(try await pins.pinned(starter.accountID) == nil)

        // The person's yes, for the account named and no other, pins it as a scan.
        let fourth = try await starter.session.startSharingCodeSession()
        _ = try await joiner.session.joinSharingCodeSession(scanned: try #require(fourth.scanPayload))
        _ = try await starter.session.refreshSharingCodeSession()
        _ = try await joiner.session.refreshSharingCodeSession()
        await #expect(throws: SharingCodeError.notReady) {
            _ = try await joiner.session.confirmScannedSharingPartner(joiner.accountID)
        }
        let confirmed = try await joiner.session.confirmScannedSharingPartner(starter.accountID)
        #expect(confirmed.step == .verified && confirmed.pinned)
        #expect(try await pins.pinned(starter.accountID)?.method == .scannedCode)
    }

    /// Threat: a lock while the joiner's step waits on the board or the directory, which A1 can stretch (ADR 0010,
    /// "Lock"; the joiner's half of V9, `beforeReply`). The lock wins: no reply reaches the board, no session is
    /// installed, and nothing is pinned.
    @Test("a lock while a joiner waits on the board publishes no reply and installs nothing")
    func lockWhileJoining() async throws {
        let household = SharedVaultHousehold()
        let starter = try await household.account(seed: 1_281)
        let gated = GatedBoard(base: household.board)
        let joiner = try await Self.account(household, seed: 1_282, board: gated)
        let started = try await starter.session.startSharingCodeSession()
        let number = try Self.number(started)

        await gated.holdNextFetch()
        let joining = Task { try await joiner.session.joinSharingCodeSession(number: try #require(started.number)) }
        await gated.waitUntilHeld()
        await joiner.session.lock()
        await gated.release()
        await #expect(throws: VaultError.locked) { _ = try await joining.value }
        #expect(await household.board.allObjects[SharingBoardName.reply(number)] == nil, "no reply was published")
        #expect(await joiner.session.sharingCodeStatus() == nil)
        let pins = VerifiedContacts(store: joiner.contacts, account: joiner.bundle)
        #expect(try await pins.pinned(starter.accountID) == nil)
    }

    /// Threat: the person cancels (Start Over, "Paste an Invitation Instead", or another window starting a session)
    /// while a start or a join waits on the board, which A1 can hold as long as it likes (V20). The cancel wins: the
    /// step that resumes installs no session, and the screen is not taken back to it.
    @Test("an end while a start or a join waits on the board is not undone when the board answers")
    func endWhileStartingOrJoining() async throws {
        let household = SharedVaultHousehold()
        let gatedStarter = GatedBoard(base: household.board)
        let starter = try await Self.account(household, seed: 1_291, board: gatedStarter)
        let gatedJoiner = GatedBoard(base: household.board)
        let joiner = try await Self.account(household, seed: 1_292, board: gatedJoiner)

        await gatedStarter.holdNextCreate()
        let starting = Task { try await starter.session.startSharingCodeSession() }
        await gatedStarter.waitUntilCreateHeld()
        await starter.session.endSharingCodeSession()
        await gatedStarter.releaseCreate()
        await #expect(throws: SharingCodeError.notReady) { _ = try await starting.value }
        #expect(await starter.session.sharingCodeStatus() == nil, "the ended start was installed after all")

        let started = try await starter.session.startSharingCodeSession()
        await gatedJoiner.holdNextCreate()
        let joining = Task { try await joiner.session.joinSharingCodeSession(number: try #require(started.number)) }
        await gatedJoiner.waitUntilCreateHeld()
        await joiner.session.endSharingCodeSession()
        await gatedJoiner.releaseCreate()
        await #expect(throws: SharingCodeError.notReady) { _ = try await joining.value }
        #expect(await joiner.session.sharingCodeStatus() == nil, "the ended join was installed after all")
    }

    /// Threat: a starter's step of a session the person has just replaced with a new one resumes while the new one is
    /// still being put on the board (A1 holds both answers; V20, "a restart abandons the old session"). The old step
    /// finds another session in place and reveals nothing for the session the person abandoned.
    @Test("a step of a replaced session reveals nothing, even while the new session is still being published")
    func replacedSessionRevealsNothing() async throws {
        let household = SharedVaultHousehold()
        let gated = GatedBoard(base: household.board)
        let starter = try await Self.account(household, seed: 1_301, board: gated)
        let joiner = try await household.account(seed: 1_302)
        let old = try await starter.session.startSharingCodeSession()
        _ = try await joiner.session.joinSharingCodeSession(number: try #require(old.number))

        await gated.holdNextFetch()
        let oldStep = Task { try await starter.session.refreshSharingCodeSession() }
        await gated.waitUntilHeld()
        await gated.holdNextCreate()
        let replacing = Task { try await starter.session.startSharingCodeSession() }
        await gated.waitUntilCreateHeld()
        await gated.release()
        await #expect(throws: SharingCodeError.notReady) { _ = try await oldStep.value }
        #expect(
            await household.board.allObjects[SharingBoardName.reveal(try Self.number(old))] == nil,
            "a reveal was published for the abandoned session")
        await gated.releaseCreate()
        let replaced = try await replacing.value
        #expect(replaced.step == .showNumber && replaced.number != old.number)
    }

    /// Threat: someone who heard the eight digits (a shoulder-surfer, a sniper, A1) takes the session's invitation slot
    /// before the starter sends (V22). The invitation is issued (the joiner added, the grant published) and then cannot
    /// be delivered: the starter is told so and given the invitation as text, a retry never invites a second time, and
    /// the joiner, who checked the starter in the session, accepts the text.
    @Test("a taken invitation slot leaves the invitation to hand over as text, and a retry invites nobody again")
    func invitationSlotTaken() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 1_311)
        let invitee = try await household.account(seed: 1_312)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let (checked, _) = try await owner.checkSharingCode(with: invitee)
        let slot = try await Self.invitationName(try Self.number(checked), on: household.board)
        await household.board.tamper(slot, contents: Array(repeating: 0x57, count: 40))

        var issued: Invitation?
        do {
            _ = try await owner.session.inviteThroughSharingCode(to: vaultID, as: .readWrite, checked: checked)
            Issue.record("delivered into a taken slot")
        } catch SharedVaultError.invitationNotDelivered(let invitation) {
            issued = invitation
        }
        let invitation = try #require(issued)
        #expect(invitation == Invitation(vaultID: vaultID, ownerAccountID: owner.accountID))
        await #expect(throws: SharedVaultError.invitationNotDelivered(invitation), "a retry only delivers again") {
            _ = try await owner.session.inviteThroughSharingCode(to: vaultID, as: .readWrite, checked: checked)
        }
        try await owner.session.sync()
        let status = try await owner.session.sharedVaultStatus(vaultID)
        #expect(status.membership.members.count == 2)
        try await invitee.session.acceptInvitation(invitation)
        try await invitee.session.sync()
        #expect(try await invitee.session.sharedVaultStatus(vaultID).role == .readWrite)
    }

    /// Threat: A1 holds the board and the directory and runs V1's adversary in the middle (V23). The starter's session
    /// is fixed once it has revealed; toward the joiner A1 runs a session of its own under the same number. After a
    /// wrong code, the joiner's person starts over and types the same eight digits again; an honest board refuses the
    /// second answer (the reply slot is taken), but A1's serves a fresh commit, so the joiner would show a new,
    /// independent code for the starter's still-open session: three tries in one starter session, not one. The joiner
    /// remembers the numbers it answered, across Start Over and a lock, and refuses to answer one again.
    @Test("a joiner never answers the same number twice, so a fresh commit buys the middle no second try")
    func noSecondAnswerToOneNumber() async throws {
        let household = SharedVaultHousehold()
        let starter = try await household.account(seed: 1_321)
        let joiner = try await household.account(seed: 1_322)
        let started = try await starter.session.startSharingCodeSession()
        let number = try Self.number(started)
        _ = try await joiner.session.joinSharingCodeSession(number: try #require(started.number))

        // A1 makes the number look new: a fresh commit of a session of its own, and the reply slot emptied.
        let elsewhere = InMemorySharingBoard()
        let middle = try SharingParty(seed: 1_329)
        await household.directory.publish(middle.bundle)
        var generator = SeededGenerator(seed: 1_330)
        var fresh = SharingCodeStarter.draw(as: middle.bundle, using: &generator, at: Date())
        try await fresh.publish(on: elsewhere, at: Date())
        let freshCommit = try #require(await elsewhere.allObjects[SharingBoardName.commit(fresh.number)])
        await household.board.tamper(SharingBoardName.commit(number), contents: freshCommit)
        await household.board.tamper(SharingBoardName.reply(number), contents: nil)

        await joiner.session.endSharingCodeSession()
        await #expect(throws: SharingCodeError.numberAlreadyAnswered) {
            _ = try await joiner.session.joinSharingCodeSession(number: try #require(started.number))
        }
        await joiner.session.lock()
        try await joiner.session.unlock(password: TestVault.password)
        await #expect(throws: SharingCodeError.numberAlreadyAnswered, "a lock does not forget it") {
            _ = try await joiner.session.joinSharingCodeSession(number: try #require(started.number))
        }
        #expect(await household.board.allObjects[SharingBoardName.reply(number)] == nil, "no second answer")

        // A number that found no session was not answered, and can be typed again.
        await #expect(throws: SharingCodeError.sessionNotFound) {
            _ = try await joiner.session.joinSharingCodeSession(number: "0000 0001")
        }
        await #expect(throws: SharingCodeError.sessionNotFound) {
            _ = try await joiner.session.joinSharingCodeSession(number: "0000 0001")
        }
    }
}
