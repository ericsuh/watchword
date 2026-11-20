import Foundation
import Testing
import WatchwordCrypto
import WatchwordTestSupport

@testable import WatchwordSharing

/// Vault sharing codes (ADR 0010, security analysis), against the protocol core with real keys. The adversary is A1
/// holding the sharing board and the key directory: it reads, drops, delays, replaces and invents every object and
/// answers each device differently. The people's channel (each reads the other's screen) is authentic and public.
/// In the suite "sharing and membership".
extension AdversarialSharingTests {
    /// Both sides as an adversary in the middle sees them: each device on a board and directory of its own, which A1
    /// writes as it likes.
    struct Middle {
        let rig: SharingCodeRig
        let starterBoard = InMemorySharingBoard()
        let joinerBoard = InMemorySharingBoard()
        let starterDirectory = InMemoryKeyBundleDirectory()
        let joinerDirectory = InMemoryKeyBundleDirectory()
        /// The keys A1 substitutes for the joiner (toward the starter) and for the starter (toward the joiner), under
        /// the real account IDs.
        let fakeJoiner: SharingParty
        let fakeStarter: SharingParty

        init(seed: UInt64) async throws {
            rig = try await SharingCodeRig(seed: seed)
            fakeJoiner = try SharingParty(accountID: rig.joiner.accountID, seed: seed + 100)
            fakeStarter = try SharingParty(accountID: rig.starter.accountID, seed: seed + 200)
            await starterDirectory.publish(rig.starter.bundle)
            await starterDirectory.publish(fakeJoiner.bundle)
            await joinerDirectory.publish(fakeStarter.bundle)
            await joinerDirectory.publish(rig.joiner.bundle)
        }
    }

    /// Threat: A1 in the middle of a session it runs back to back (ADR 0010, "An adversary in the middle"): toward the
    /// starter it is the joiner, with keys of its own published under the joiner's account; toward the joiner it is
    /// the starter, likewise. It may interleave the two either way, and it knows every value on both boards. Each
    /// side's transcript is fixed by a nonce the other side committed to before it could be seen, so the code each
    /// device shows is not the code the other device expects (here, with fixed seeds; in general, but for 10^-6 per
    /// direction), every try fails, the third ends the session, and neither device holds evidence of anything.
    @Test(
        "an adversary in the middle, either interleaving, gets codes that do not match, and nothing is evidenced",
        arguments: [false, true])
    func middle(joinerFirst: Bool) async throws {
        let m = try await Middle(seed: joinerFirst ? 800 : 820)
        var generator = SeededGenerator(seed: 5)
        var starter = try await m.rig.start(seed: 801, on: m.starterBoard)
        // A1's own session toward the joiner, under the starter's account and the same number.
        let attackerNonce = SharingNonce.draw(using: &generator).bytes
        let attackerSession = Array(SharingNonce.draw(using: &generator).bytes.prefix(16))
        let attackerCommit = SharingTranscript.commitment(
            session: attackerSession, starter: m.rig.starter.accountID, nonce: attackerNonce)
        try await m.joinerBoard.create(
            SharingBoardName.commit(starter.number),
            contents: SharingSessionMessage(
                kind: .commit, session: attackerSession, account: m.rig.starter.accountID, value: attackerCommit
            ).encoded())
        func answerStarter() async throws {
            // A1's reply to the starter as the joiner, its nonce chosen freely.
            let commit = try #require(
                try await m.starterBoard.fetch(SharingBoardName.commit(starter.number), maximumLength: 100))
            let session = try SharingSessionMessage.parse(commit, expecting: .commit).session
            try await m.starterBoard.create(
                SharingBoardName.reply(starter.number),
                contents: SharingSessionMessage(
                    kind: .reply, session: session, account: m.rig.joiner.accountID,
                    value: SharingNonce.draw(using: &generator).bytes
                ).encoded())
            try await starter.poll(board: m.starterBoard, directory: m.starterDirectory, at: Self.now)
        }
        if !joinerFirst { try await answerStarter() }
        var joiner = try await m.rig.join(
            starter.number, seed: 802, board: m.joinerBoard, directory: m.joinerDirectory)
        try await m.joinerBoard.create(
            SharingBoardName.reveal(starter.number),
            contents: SharingSessionMessage(kind: .reveal, session: attackerSession, account: nil, value: attackerNonce)
                .encoded())
        try await joiner.poll(board: m.joinerBoard, at: Self.now)
        if joinerFirst { try await answerStarter() }
        #expect(starter.phase == .awaitingJoinerCode && joiner.phase == .awaitingStarterCode)
        #expect(starter.joiner?.hasSameKeys(as: m.fakeJoiner.bundle) == true, "the starter holds A1's keys")

        // The joiner's person reads their code; the starter's person types it. Three times.
        let shown = try #require(joiner.code)
        #expect(try !starter.enterJoinerCode(shown, at: Self.now))
        #expect(try !starter.enterJoinerCode(shown, at: Self.now))
        #expect(throws: SharingCodeError.tooManyAttempts) { try starter.enterJoinerCode(shown, at: Self.now) }
        #expect(starter.evidence == nil && starter.code == nil)
        #expect(starter.phase == .failed(.tooManyAttempts))
        // Whatever code A1 computes for the starter's side, the starter never shows one; and the joiner's expected
        // code is not one the people can read off the starter's screen.
        #expect(joiner.evidence == nil)
        #expect(throws: SharingCodeError.tooManyAttempts) {
            try starter.enterJoinerCode(SharingCodeRig.wrong(shown), at: Self.now)
        }
    }

    /// Threat: A1 lies to one side only (ADR 0010, "Substituted bundles"): the board is honest, but the directory
    /// gives the starter A1's keys under the joiner's account. The transcript covers both bundles as each device
    /// holds them, so the codes disagree and nothing is evidenced; the joiner's code is refused.
    @Test("a directory that lies to one side makes the codes disagree")
    func directoryLiesToOneSide() async throws {
        let m = try await Middle(seed: 840)
        var starter = try await m.rig.start(seed: 841)
        var joiner = try await m.rig.join(starter.number, seed: 842)
        try await starter.poll(board: m.rig.board, directory: m.starterDirectory, at: Self.now)
        try await joiner.poll(board: m.rig.board, at: Self.now)
        #expect(try !starter.enterJoinerCode(try #require(joiner.code), at: Self.now))
        #expect(starter.evidence == nil)
    }

    /// Threat: A1 changes the directory's answer after a device fixed the bundle it uses (ADR 0010: a bundle chosen
    /// after the reveal could be searched for). Each device looks a bundle up once, before its own nonce is public,
    /// and the evidence names that bundle, whatever the directory says later.
    @Test("a bundle published after the one a device fixed changes nothing the session evidences")
    func bundleFetchedLater() async throws {
        let m = try await Middle(seed: 850)
        var starter = try await m.rig.start(seed: 851)
        var joiner = try await m.rig.join(starter.number, seed: 852)
        try await starter.poll(board: m.rig.board, directory: m.rig.directory, at: Self.now)
        // Now A1 publishes its own keys under both accounts.
        await m.rig.directory.publish(m.fakeJoiner.bundle)
        await m.rig.directory.publish(m.fakeStarter.bundle)
        try await joiner.poll(board: m.rig.board, at: Self.now)
        try await starter.poll(board: m.rig.board, directory: m.rig.directory, at: Self.now)
        #expect(try starter.enterJoinerCode(try #require(joiner.code), at: Self.now))
        #expect(try joiner.enterStarterCode(try #require(starter.code), at: Self.now))
        #expect(starter.evidence?.contact.hasSameKeys(as: m.rig.joiner.bundle) == true)
        #expect(joiner.evidence?.contact.hasSameKeys(as: m.rig.starter.bundle) == true)
    }

    /// Threat: A1 replaces the reply after the starter revealed, hoping it reveals again for a reply chosen once its
    /// nonce is public (ADR 0010, "The reveal is made once"). The starter holds the one reply it read, never reads the
    /// slot again, and its expected code is the one fixed with that reply.
    @Test("a reply replaced after the reveal is never read, and the reveal is not made again")
    func replyReplacedAfterTheReveal() async throws {
        let rig = try await SharingCodeRig(seed: 860)
        var starter = try await rig.start(seed: 861)
        var joiner = try await rig.join(starter.number, seed: 862)
        try await starter.poll(board: rig.board, directory: rig.directory, at: Self.now)
        let reveal = await rig.board.allObjects[SharingBoardName.reveal(starter.number)]
        let other = try SharingParty(seed: 869)
        await rig.directory.publish(other.bundle)
        var generator = SeededGenerator(seed: 868)
        let commit = try SharingSessionMessage.parse(
            try #require(await rig.board.allObjects[SharingBoardName.commit(starter.number)]), expecting: .commit)
        await rig.board.tamper(
            SharingBoardName.reply(starter.number),
            contents: SharingSessionMessage(
                kind: .reply, session: commit.session, account: other.accountID,
                value: SharingNonce.draw(using: &generator).bytes
            ).encoded())
        #expect(try await !starter.poll(board: rig.board, directory: rig.directory, at: Self.now))
        #expect(starter.joiner?.accountID == rig.joiner.accountID)
        #expect(await rig.board.allObjects[SharingBoardName.reveal(starter.number)] == reveal)
        try await joiner.poll(board: rig.board, at: Self.now)
        #expect(try starter.enterJoinerCode(try #require(joiner.code), at: Self.now), "the honest joiner's code")
    }

    /// Threat: A1 puts something under the reveal's name before the starter reveals (a reveal made early, or junk),
    /// so a joiner reads its value. The starter finds the slot taken by other bytes and ends the session; a joiner
    /// that read the early value finds it does not open the commitment.
    @Test("a reveal planted early ends the session on both sides")
    func earlyReveal() async throws {
        let rig = try await SharingCodeRig(seed: 870)
        var starter = try await rig.start(seed: 871)
        var joiner = try await rig.join(starter.number, seed: 872)
        let commit = try SharingSessionMessage.parse(
            try #require(await rig.board.allObjects[SharingBoardName.commit(starter.number)]), expecting: .commit)
        await rig.board.tamper(
            SharingBoardName.reveal(starter.number),
            contents: SharingSessionMessage(
                kind: .reveal, session: commit.session, account: nil, value: Array(repeating: 0x42, count: 32)
            ).encoded())
        await #expect(throws: SharingCodeError.commitmentMismatch) {
            try await joiner.poll(board: rig.board, at: Self.now)
        }
        await #expect(throws: SharingCodeError.boardInterference) {
            try await starter.poll(board: rig.board, directory: rig.directory, at: Self.now)
        }
        #expect(starter.phase == .failed(.boardInterference) && joiner.phase == .failed(.commitmentMismatch))
        #expect(starter.evidence == nil && joiner.evidence == nil)
    }

    /// Threat: A1 replays a reply from another session, verbatim, into this one's slot; or a commitment and its reveal
    /// from an old session to a joiner (ADR 0010, "Substituted bundles": a replayed message meets fresh nonces). The
    /// reply names another session and ends this one; the replayed old session gives the joiner codes the starter's
    /// current session does not have.
    @Test("messages replayed from another session are refused or meet fresh nonces")
    func replay() async throws {
        let rig = try await SharingCodeRig(seed: 880)
        // An old session, run to the end.
        var old = try await rig.start(seed: 881)
        var oldJoiner = try await rig.join(old.number, seed: 882)
        try await old.poll(board: rig.board, directory: rig.directory, at: Self.now)
        try await oldJoiner.poll(board: rig.board, at: Self.now)
        let oldReply = try #require(await rig.board.allObjects[SharingBoardName.reply(old.number)])
        let oldCommit = try #require(await rig.board.allObjects[SharingBoardName.commit(old.number)])
        let oldReveal = try #require(await rig.board.allObjects[SharingBoardName.reveal(old.number)])

        var fresh = try await rig.start(seed: 883)
        await rig.board.tamper(SharingBoardName.reply(fresh.number), contents: oldReply)
        await #expect(throws: SharingCodeError.malformedMessage) {
            try await fresh.poll(board: rig.board, directory: rig.directory, at: Self.now)
        }
        #expect(fresh.evidence == nil)

        // The old commitment and reveal, replayed to a joiner under a number nobody uses now.
        let current = try await rig.start(seed: 884)
        let replayBoard = InMemorySharingBoard()
        await replayBoard.tamper(SharingBoardName.commit(current.number), contents: oldCommit)
        var replayed = try await rig.join(current.number, seed: 885, board: replayBoard)
        await replayBoard.tamper(SharingBoardName.reveal(current.number), contents: oldReveal)
        try await replayed.poll(board: replayBoard, at: Self.now)
        #expect(replayed.code != oldJoiner.code, "a fresh nonce makes fresh codes")
        _ = try old.enterJoinerCode(try #require(oldJoiner.code), at: Self.now)
        #expect(try !replayed.enterStarterCode(try #require(old.code), at: Self.now), "the old session's code")
        #expect(replayed.evidence == nil)
    }

    /// Threat: anyone who guesses or overhears the number answers first (ADR 0010, "Sniping"). The honest joiner is
    /// told the session was taken; the starter holds the sniper's reply, and the code on the honest joiner's screen
    /// (none, here) or any other is refused: the sniper is evidenced only if the starter's person types the code the
    /// sniper's own device shows, which the people's channel rules out.
    @Test("a sniper who answers first gets nothing, and the joiner is told")
    func sniping() async throws {
        let rig = try await SharingCodeRig(seed: 890)
        let sniper = try SharingParty(seed: 899)
        await rig.directory.publish(sniper.bundle)
        var starter = try await rig.start(seed: 891)
        var sniping = try await rig.join(starter.number, seed: 892, as: sniper)
        await #expect(throws: SharingCodeError.sessionTaken) { _ = try await rig.join(starter.number, seed: 893) }
        try await starter.poll(board: rig.board, directory: rig.directory, at: Self.now)
        try await sniping.poll(board: rig.board, at: Self.now)
        #expect(starter.joiner?.accountID == sniper.accountID)
        // The people type what the honest joiner's screen shows: it shows no code at all, so whatever they type is
        // not the sniper's.
        let snipersCode = try #require(sniping.code)
        for _ in 0..<2 { #expect(try !starter.enterJoinerCode(SharingCodeRig.wrong(snipersCode), at: Self.now)) }
        #expect(starter.evidence == nil)
    }

    /// Threat: wrong codes (a slip, or A1's guess). Each wrong code uses one of three tries; what is not six digits
    /// compares nothing and uses none; the third wrong one ends the session for good, and a right code afterwards
    /// changes nothing.
    @Test("three wrong codes end the session, and input that is not a code uses no try")
    func wrongCodes() async throws {
        let rig = try await SharingCodeRig(seed: 900)
        var starter = try await rig.start(seed: 901)
        var joiner = try await rig.join(starter.number, seed: 902)
        try await starter.poll(board: rig.board, directory: rig.directory, at: Self.now)
        try await joiner.poll(board: rig.board, at: Self.now)
        let right = try #require(joiner.code)
        for junk in ["12345", "1234567", "12a456", "１２３４５６", ""] {
            #expect(throws: SharingCodeError.malformedCode) { try starter.enterJoinerCode(junk, at: Self.now) }
        }
        #expect(starter.attemptsLeft == 3)
        #expect(try !starter.enterJoinerCode(SharingCodeRig.wrong(right), at: Self.now))
        #expect(try !starter.enterJoinerCode(SharingCodeRig.wrong(right), at: Self.now))
        #expect(throws: SharingCodeError.tooManyAttempts) {
            try starter.enterJoinerCode(SharingCodeRig.wrong(right), at: Self.now)
        }
        #expect(throws: SharingCodeError.tooManyAttempts) { try starter.enterJoinerCode(right, at: Self.now) }
        #expect(starter.evidence == nil)
        // The joiner's side likewise: the starter never showed a code, so nothing typed there is it.
        #expect(try !joiner.enterStarterCode("000000", at: Self.now))
        #expect(try !joiner.enterStarterCode("999999", at: Self.now))
        #expect(throws: SharingCodeError.tooManyAttempts) { try joiner.enterStarterCode("123456", at: Self.now) }
        #expect(joiner.evidence == nil)
    }

    /// Threat: A1 stalls (ADR 0010: ten minutes without progress abandons a session). A late reply, reveal or code is
    /// refused, and the session cannot be revived; progress resets the clock.
    @Test("ten minutes without progress end the session, and progress resets the clock")
    func timing() async throws {
        let rig = try await SharingCodeRig(seed: 910)
        var starter = try await rig.start(seed: 911)
        let nine = Self.now.addingTimeInterval(540)
        var joiner = try await rig.join(starter.number, seed: 912, at: nine)
        try await starter.poll(board: rig.board, directory: rig.directory, at: nine)
        let eighteen = nine.addingTimeInterval(540)
        try await joiner.poll(board: rig.board, at: eighteen)
        let late = eighteen.addingTimeInterval(SharingCodeLimits.lifetime + 1)
        #expect(throws: SharingCodeError.expired) { try starter.enterJoinerCode(try #require(joiner.code), at: late) }
        #expect(throws: SharingCodeError.expired) { try starter.enterJoinerCode(try #require(joiner.code), at: nine) }
        #expect(starter.evidence == nil && starter.phase == .failed(.expired))

        var waiting = try await rig.start(seed: 913)
        await #expect(throws: SharingCodeError.expired) {
            try await waiting.poll(
                board: rig.board, directory: rig.directory,
                at: Self.now.addingTimeInterval(SharingCodeLimits.lifetime + 1))
        }
    }

    /// Threat: the same account on both ends (a person's two devices, or A1 echoing the starter's own account back).
    /// Refused on both sides: a session authenticates two accounts to each other, never one to itself.
    @Test("the same account on both ends is refused on both sides")
    func sameAccount() async throws {
        let rig = try await SharingCodeRig(seed: 920)
        let starter = try await rig.start(seed: 921)
        await #expect(throws: SharingCodeError.sameAccount) {
            _ = try await rig.join(starter.number, seed: 922, as: rig.starter)
        }
        var other = try await rig.start(seed: 923)
        let commit = try SharingSessionMessage.parse(
            try #require(await rig.board.allObjects[SharingBoardName.commit(other.number)]), expecting: .commit)
        await rig.board.tamper(
            SharingBoardName.reply(other.number),
            contents: SharingSessionMessage(
                kind: .reply, session: commit.session, account: rig.starter.accountID,
                value: Array(repeating: 1, count: 32)
            ).encoded())
        await #expect(throws: SharingCodeError.sameAccount) {
            try await other.poll(board: rig.board, directory: rig.directory, at: Self.now)
        }
    }

    /// Threat: a scanned code that is not the session's (ADR 0010, Scans): the wrong person's screen, a code for
    /// another account, or A1's keys under the right account. A joiner's scan must name the commit's account and match
    /// the directory's bundle; a starter's scan must name the reply's account and match its bundle, or it counts as a
    /// wrong code.
    @Test("a scanned code for another account or other keys authenticates nothing")
    func wrongScans() async throws {
        let m = try await Middle(seed: 930)
        let starter = try await m.rig.start(seed: 931)
        let stranger = try SharingParty(seed: 939)
        // The joiner scans a code whose fingerprint is a stranger's, under the session's number.
        let foreign = ScannedSharingCode(number: starter.number, bundle: stranger.bundle)
        await #expect(throws: SharingCodeError.scannedCodeMismatch) {
            _ = try await m.rig.join(starter.number, seed: 932, scanned: foreign)
        }
        // The starter's true code, while the directory gives the joiner A1's keys for the starter.
        let genuine = try ScannedSharingCode(scanned: starter.scanPayload)
        await #expect(throws: SharingCodeError.scannedCodeMismatch) {
            _ = try await m.rig.join(starter.number, seed: 933, scanned: genuine, directory: m.joinerDirectory)
        }
        // A number other than the scan's.
        await #expect(throws: SharingCodeError.scannedCodeMismatch) {
            _ = try await m.rig.join(try #require(SharingSessionNumber(typed: "00000000")), seed: 934, scanned: genuine)
        }

        var second = try await m.rig.start(seed: 935)
        _ = try await m.rig.join(second.number, seed: 936)
        try await second.poll(board: m.rig.board, directory: m.rig.directory, at: Self.now)
        #expect(try !second.scanJoinerCode(FingerprintCode(bundle: stranger.bundle).payload, at: Self.now))
        #expect(try !second.scanJoinerCode(FingerprintCode(bundle: m.fakeJoiner.bundle).payload, at: Self.now))
        #expect(throws: SharingCodeError.malformedCode) { try second.scanJoinerCode("WWFP1-junk", at: Self.now) }
        #expect(second.evidence == nil && second.attemptsLeft == 1)
    }

    /// Threat: evidence or an invitation used outside the session that made it (ADR 0010: "a session's evidence
    /// refused for any other session or account"). Evidence pins only for the account it was made for; an invitation
    /// object opens only in its own session, for its own joiner, under the starter's key.
    @Test("a session's evidence and invitation are refused for any other account or session")
    func evidenceStaysInItsSession() async throws {
        let rig = try await SharingCodeRig(seed: 940)
        var starter = try await rig.start(seed: 941)
        var joiner = try await rig.join(starter.number, seed: 942)
        try await starter.poll(board: rig.board, directory: rig.directory, at: Self.now)
        try await joiner.poll(board: rig.board, at: Self.now)
        _ = try starter.enterJoinerCode(try #require(joiner.code), at: Self.now)
        _ = try joiner.enterStarterCode(try #require(starter.code), at: Self.now)
        let evidence = try #require(starter.evidence)

        let bystander = try SharingParty(seed: 949)
        let theirs = VerifiedContacts(store: InMemoryVerifiedContactStore(), account: bystander.bundle)
        await #expect(throws: SharingError.notPermitted) {
            _ = try await theirs.verify(evidence, signedBy: bystander.keyset, at: Self.now)
        }
        let joinersOwn = VerifiedContacts(store: InMemoryVerifiedContactStore(), account: rig.joiner.bundle)
        await #expect(throws: SharingError.notPermitted, "evidence about oneself pins nothing") {
            _ = try await joinersOwn.verify(evidence, signedBy: rig.joiner.keyset, at: Self.now)
        }

        let invitation = Invitation(vaultID: UUID(), ownerAccountID: rig.starter.accountID)
        let object = try starter.invitationObject(invitation, signedBy: rig.starter.keyset)
        // Another session between the same two accounts.
        var again = try await rig.start(seed: 943)
        var againJoiner = try await rig.join(again.number, seed: 944)
        try await again.poll(board: rig.board, directory: rig.directory, at: Self.now)
        try await againJoiner.poll(board: rig.board, at: Self.now)
        _ = try again.enterJoinerCode(try #require(againJoiner.code), at: Self.now)
        _ = try againJoiner.enterStarterCode(try #require(again.code), at: Self.now)
        #expect(throws: SharingCodeError.invitationInvalid) { try againJoiner.openInvitation(object.contents) }
        // Signed by someone else, over the right content.
        let content = Array(object.contents.prefix(object.contents.count - 64))
        let forged = content + (try bystander.keyset.sign(content, domain: .membership))
        #expect(throws: SharingCodeError.invitationInvalid) { try joiner.openInvitation(forged) }
        // A different invitation under the starter's genuine signature of another one, and every truncation.
        var altered = object.contents
        altered[SessionInvitationCodec.contentLength - 1] ^= 1
        #expect(throws: SharingCodeError.invitationInvalid) { try joiner.openInvitation(altered) }
        for cut in [0, 1, object.contents.count - 1] {
            #expect(throws: SharingCodeError.invitationInvalid) {
                try joiner.openInvitation(Array(object.contents.prefix(cut)))
            }
        }
        #expect(try joiner.openInvitation(object.contents) == invitation)
    }

    /// Threat: A1 fills the board's objects for a session with what is not a message: every truncation and extension
    /// of a genuine one, another kind, junk. Each is refused before anything is believed, and refused for good where
    /// the slot is created once.
    @Test("junk under a session's names ends the session without evidence")
    func junkOnTheBoard() async throws {
        let rig = try await SharingCodeRig(seed: 950)
        for junk: [UInt8] in [[], [0x57], Array(repeating: 0, count: 70), Array(repeating: 0, count: 71)] {
            var starter = try await rig.start(seed: 951 + UInt64(junk.count))
            await rig.board.tamper(SharingBoardName.reply(starter.number), contents: junk)
            await #expect(throws: (any Error).self) {
                try await starter.poll(board: rig.board, directory: rig.directory, at: Self.now)
            }
            #expect(starter.evidence == nil)
        }
        let number = try #require(SharingSessionNumber(typed: "99999999"))
        await rig.board.tamper(SharingBoardName.commit(number), contents: Array(repeating: 0x57, count: 70))
        await #expect(throws: SharingCodeError.malformedMessage) { _ = try await rig.join(number, seed: 959) }
        await rig.board.tamper(SharingBoardName.commit(number), contents: Array(repeating: 0x57, count: 1 << 16))
        await #expect(throws: SharingBoardError.tooLarge) { _ = try await rig.join(number, seed: 960) }
    }
}
