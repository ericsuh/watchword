import Foundation
import SecureMemory
import WatchwordCrypto

// Vault sharing codes (ADR 0010, docs/02-architecture.md §8.4): two people authenticate each other's key bundles
// with a short authentication string over a commitment. The starter S shows an eight-digit number, the vault sharing
// code; the joiner J types it (or scans it); each device then derives a six-digit confirmation code from everything
// it saw, and each person types the other's. An adversary in the middle (A1, holding the board and the directory)
// gets one blind try per session at making the two transcripts agree in six digits: 10^-6 per direction.
//
// ```
// S: number, session (16), Ns (32);  C = SHA-256("WWSC1-commit" ‖ session ‖ S.account ‖ Ns)
//    create board[number]/commit = session ‖ S.account ‖ C
// J: fetch commit; bundleS' = directory(S.account)      (fixed before J's nonce is published)
//    create board[number]/reply  = session ‖ J.account ‖ Nj
// S: fetch reply; bundleJ' = directory(J.account)       (fixed before S's nonce is published)
//    create board[number]/reveal = session ‖ Ns          (once, for the one reply held)
// J: fetch reveal; check C
// both: T = SHA-256("WWSC1-code" ‖ session ‖ number ‖ S.account ‖ keys(S) ‖ J.account ‖ keys(J) ‖ C ‖ Ns ‖ Nj)
//       joiner's code = T[0..<8] as big-endian UInt64 mod 10^6, starter's = T[8..<16]
// ```
//
// `keys(B)` is `accountID ‖ X25519 key ‖ Ed25519 key`: the fingerprint's inputs. The ADR writes `bundle(S)` "in
// `KeyBundleCodec` bytes", which would hash the self-signature too; Ed25519 signing is randomised on CryptoKit, so a
// device's own bundle and the directory's copy of it carry different self-signatures and the codes would never agree
// on a Mac (a Linux pass, on deterministic BoringSSL signing, would not show it). The self-signature says nothing about
// whose keys these are, so leaving it out costs nothing.

/// The eight digits that name a session on the board and that the starter's person reads out: the vault sharing code.
/// Not a secret and not a key: it finds the session, nothing more (ADR 0010, "Sniping").
public struct SharingSessionNumber: Hashable, Sendable {
    public static let digitCount = 8
    /// Exactly eight ASCII digits.
    public let digits: String

    init(validated digits: String) {
        self.digits = digits
    }

    /// The number a person typed: exactly eight ASCII digits, with ASCII spaces, tabs and hyphens between them
    /// ignored. Anything else (another script's digits, a letter, nine digits) is `nil`, as is any input longer than
    /// `SharingTypedDigits.maximumLength` bytes.
    public init?(typed text: String) {
        guard let digits = SharingTypedDigits.digits(in: text, count: Self.digitCount) else { return nil }
        self.digits = String(decoding: digits, as: UTF8.self)
    }

    /// A number drawn uniformly from the 10^8 possible.
    public static func draw<R: RandomNumberGenerator>(using random: inout R) -> SharingSessionNumber {
        let value = UInt32.random(in: 0..<100_000_000, using: &random)
        let text = String(value)
        return SharingSessionNumber(validated: String(repeating: "0", count: digitCount - text.count) + text)
    }

    /// "1234 5678", for reading aloud.
    public var grouped: String {
        String(digits.prefix(4)) + " " + String(digits.suffix(4))
    }

    var bytes: [UInt8] { Array(digits.utf8) }
}

/// Parsing what a person types as digits: bounded, exact, ASCII only.
public enum SharingTypedDigits {
    /// The longest input looked at.
    public static let maximumLength = 64

    /// The ASCII digits of `text` if it is exactly `count` of them with ASCII spaces, tabs and hyphens between; `nil`
    /// otherwise.
    public static func digits(in text: String, count: Int) -> [UInt8]? {
        guard text.utf8.count <= maximumLength else { return nil }
        var digits: [UInt8] = []
        for byte in text.utf8 {
            switch byte {
            case 0x30...0x39: digits.append(byte)
            case 0x20, 0x09, 0x2D: continue
            default: return nil
            }
        }
        return digits.count == count ? digits : nil
    }
}

/// What the starter's device shows as a QR code: `"WWSC1-" ‖ number ‖ FingerprintCode.payload` (ADR 0010, Scanning).
/// One scan gives the joiner the number and authenticates the starter's bundle by its whole fingerprint, so the joiner
/// types nothing in that direction. A scanned payload is hostile input: exactly one spelling of exactly one length.
public struct ScannedSharingCode: Sendable, Equatable {
    static let prefix = Array("WWSC1-".utf8)
    public static let payloadLength = prefix.count + SharingSessionNumber.digitCount + FingerprintCode.payloadLength

    public let number: SharingSessionNumber
    public let fingerprint: FingerprintCode

    public init(number: SharingSessionNumber, bundle: PublicKeyBundle) {
        self.number = number
        fingerprint = FingerprintCode(bundle: bundle)
    }

    public var payload: String {
        String(decoding: Self.prefix, as: UTF8.self) + number.digits + fingerprint.payload
    }

    /// Parses a payload the camera read. Looks at no more than one byte past the one length it accepts.
    public init(scanned payload: String) throws {
        let utf8 = Array(payload.utf8.prefix(Self.payloadLength + 1))
        guard utf8.count == Self.payloadLength, Array(utf8.prefix(Self.prefix.count)) == Self.prefix else {
            throw SharingFormatError.malformedText
        }
        let digits = Array(utf8[Self.prefix.count..<(Self.prefix.count + SharingSessionNumber.digitCount)])
        guard digits.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { throw SharingFormatError.malformedText }
        number = SharingSessionNumber(validated: String(decoding: digits, as: UTF8.self))
        fingerprint = try FingerprintCode(
            scanned: String(
                decoding: utf8.dropFirst(Self.prefix.count + SharingSessionNumber.digitCount), as: UTF8.self)
        )
    }
}

/// Why a vault sharing code session refused or ended. Every ending is seen by the person on that device (G2), and
/// nothing is pinned by a session that ended this way.
public enum SharingCodeError: Error, Hashable, Sendable {
    /// No session under that number: mistyped, finished, or never started.
    case sessionNotFound
    /// Someone answered the session first (anyone who guesses the number can; the session then fails at the first
    /// code, ADR 0010 "Sniping"). Start a new one.
    case sessionTaken
    /// Eight random numbers in a row were taken on the board.
    case numbersExhausted
    /// The same account on both ends.
    case sameAccount
    /// An object on the board is not exactly what the format allows, or belongs to another session.
    case malformedMessage
    /// The starter's revealed nonce does not open its commitment: the board changed something.
    case commitmentMismatch
    /// The board holds something else where only this device writes (the reveal).
    case boardInterference
    /// Three wrong codes: the session is over.
    case tooManyAttempts
    /// Ten minutes without progress.
    case expired
    /// A scanned code that is not the directory's bundle for the account the session names.
    case scannedCodeMismatch
    /// What was typed is not six (or eight) digits; nothing was compared and no attempt was used.
    case malformedCode
    /// The step was taken before the session reached it, or after it ended.
    case notReady
    /// The joiner's invitation did not verify under the starter's key, or names another session or account.
    case invitationInvalid
    /// Another step of the same session is still running; nothing was done.
    case busy
}

/// A session's nonce, drawn from the generator the caller injects (production: the system's), never chosen.
public struct SharingNonce: Sendable {
    static let length = 32
    let bytes: [UInt8]

    public static func draw<R: RandomNumberGenerator>(using random: inout R) -> SharingNonce {
        SharingNonce(bytes: (0..<length).map { _ in UInt8.random(in: .min ... .max, using: &random) })
    }
}

/// Evidence that a completed vault sharing code session authenticated `contact` to `pinningAccount`
/// (`VerificationMethod.sharingCode`, or `.scannedCode` for a scan inside a session). Only `SharingCodeStarter` and
/// `SharingCodeJoiner` make one, and only after the code this device's person typed matched, or a scan matched: the
/// typing discipline of `VerifiedContact` and `NormalizedHost`. It names the keys it is about and the account it was
/// made for, so it is never a bare "yes", and `VerifiedContacts.verify(_:)` refuses it for any other account.
public struct SharingCodeEvidence: Sendable, Hashable {
    public let contact: PublicKeyBundle
    public let pinningAccount: UUID
    public let method: VerificationMethod
    /// The session that produced it.
    let session: [UInt8]

    init(contact: PublicKeyBundle, pinningAccount: UUID, method: VerificationMethod, session: [UInt8]) {
        self.contact = contact
        self.pinningAccount = pinningAccount
        self.method = method
        self.session = session
    }
}

// MARK: - Messages

/// The three board objects of a session: `"WWVS" ‖ version u8 = 1 ‖ kind u8 ‖ session 16 ‖ …`, each of one fixed
/// length, parsed exactly. Public for the fuzzing harness (`Fuzz/`), which reads board bytes as A1 writes them;
/// nothing outside this module builds a session from it.
public struct SharingSessionMessage: Equatable, Sendable {
    static let magic: [UInt8] = Array("WWVS".utf8)
    static let formatVersion: UInt8 = 1
    static let headerLength = 4 + 1 + 1 + 16

    public enum Kind: UInt8, Sendable, CaseIterable {
        /// account 16 ‖ commitment 32
        case commit = 1
        /// account 16 ‖ nonce 32
        case reply = 2
        /// nonce 32
        case reveal = 3

        var bodyLength: Int { self == .reveal ? 32 : 48 }
    }

    public let kind: Kind
    public let session: [UInt8]
    /// The starter (commit) or the joiner (reply); `nil` for a reveal.
    public let account: UUID?
    /// The commitment (commit) or the nonce (reply, reveal).
    public let value: [UInt8]

    init(kind: Kind, session: [UInt8], account: UUID?, value: [UInt8]) {
        self.kind = kind
        self.session = session
        self.account = account
        self.value = value
    }

    public static func length(of kind: Kind) -> Int { headerLength + kind.bodyLength }

    public func encoded() -> [UInt8] {
        Self.magic + [Self.formatVersion, kind.rawValue] + session + (account?.sharingBytes ?? []) + value
    }

    /// The message of `kind` in `bytes`, exactly.
    public static func parse(_ bytes: [UInt8], expecting kind: Kind) throws -> SharingSessionMessage {
        guard bytes.count <= length(of: kind) else { throw SharingFormatError.tooLarge(bytes.count) }
        var reader = SharingReader(bytes)
        try reader.header(magic: magic, version: formatVersion)
        guard try reader.byte() == kind.rawValue else { throw SharingFormatError.unknownOperation(bytes[5]) }
        let session = try reader.read(16)
        let account = kind == .reveal ? nil : try reader.uuid()
        let value = try reader.read(32)
        try reader.finish()
        return SharingSessionMessage(kind: kind, session: session, account: account, value: value)
    }
}

/// The hashes of ADR 0010: the commitment, the transcript, and the six-digit codes.
enum SharingTranscript {
    static let commitDomain = Array("WWSC1-commit".utf8)
    static let codeDomain = Array("WWSC1-code".utf8)
    static let codeDigits = 6
    /// Where each code is read from in the transcript.
    static let joinerCodeOffset = 0
    static let starterCodeOffset = 8

    static func commitment(session: [UInt8], starter: UUID, nonce: [UInt8]) -> [UInt8] {
        SharingBytes.sha256(commitDomain, session, starter.sharingBytes, nonce)
    }

    static func keys(_ bundle: PublicKeyBundle) -> [UInt8] {
        bundle.accountID.sharingBytes + bundle.agreementKey + bundle.signingKey
    }

    static func transcript(
        session: [UInt8], number: SharingSessionNumber, starter: PublicKeyBundle, joiner: PublicKeyBundle,
        commitment: [UInt8], starterNonce: [UInt8], joinerNonce: [UInt8]
    ) -> [UInt8] {
        SharingBytes.sha256(
            codeDomain, session, number.bytes, starter.accountID.sharingBytes, keys(starter),
            joiner.accountID.sharingBytes, keys(joiner), commitment, starterNonce, joinerNonce)
    }

    /// Six decimal digits from `transcript[offset..<offset + 8]`, big-endian, mod 10^6, zero-padded (the bias is below
    /// 2^-44).
    static func code(_ transcript: [UInt8], at offset: Int) -> [UInt8] {
        let value = transcript[offset..<(offset + 8)].reduce(UInt64(0)) { $0 << 8 | UInt64($1) } % 1_000_000
        let text = String(value)
        return Array((String(repeating: "0", count: codeDigits - text.count) + text).utf8)
    }

    /// "123 456", for reading aloud.
    static func grouped(_ code: [UInt8]) -> String {
        String(decoding: code.prefix(3), as: UTF8.self) + " " + String(decoding: code.suffix(3), as: UTF8.self)
    }
}

/// The invitation a starter sends inside a completed session (ADR 0010, After the session), so nothing is pasted:
///
/// ```
/// magic "WWVI"  formatVersion u8 = 1  session 16  number 8 (ASCII)  joiner 16  invitation 37  signature 64
/// ```
///
/// signed by the starter's account key under `SignatureDomain.membership`. Bound to the session, its number and the
/// joiner, so it is refused anywhere else; verified only under the bundle the session authenticated.
enum SessionInvitationCodec {
    static let magic: [UInt8] = Array("WWVI".utf8)
    static let formatVersion: UInt8 = 1
    static let contentLength = 4 + 1 + 16 + SharingSessionNumber.digitCount + 16 + Invitation.encodedLength
    static let encodedLength = contentLength + 64

    static func content(session: [UInt8], number: SharingSessionNumber, joiner: UUID, invitation: Invitation)
        -> [UInt8]
    {
        magic + [formatVersion] + session + number.bytes + joiner.sharingBytes + invitation.encoded()
    }

    static func open(
        _ bytes: [UInt8], session: [UInt8], number: SharingSessionNumber, joiner: UUID, starter: PublicKeyBundle
    ) throws -> Invitation {
        guard bytes.count == encodedLength else { throw SharingCodeError.invitationInvalid }
        let content = Array(bytes.prefix(contentLength))
        let signature = Array(bytes.suffix(64))
        // The signature first, under the key the session authenticated; only then is anything in it read.
        guard
            (try? Signatures.verify(signature, for: content, domain: .membership, signingKey: starter.signingKey))
                != nil
        else { throw SharingCodeError.invitationInvalid }
        let invitationBytes = Array(content.suffix(Invitation.encodedLength))
        guard let invitation = try? Invitation.parse(invitationBytes),
            content == Self.content(session: session, number: number, joiner: joiner, invitation: invitation)
        else { throw SharingCodeError.invitationInvalid }
        return invitation
    }
}

// MARK: - The two sides

/// How long a session waits for the next step: ten minutes without progress abandons it (ADR 0010).
public enum SharingCodeLimits {
    public static let lifetime: TimeInterval = 600
    /// Wrong codes allowed in one session; the third ends it.
    public static let attempts = 3
    /// Numbers drawn before giving up on a board where every one is taken.
    public static let numberDraws = 8
}

/// The starter's side of a vault sharing code session (ADR 0010): the inviter, or whoever shows the number.
///
/// ```
/// drawn ──publish──► awaitingReply ──poll──► awaitingJoinerCode ──enter / scan──► verified
///                    (show the number)        (reveal made once)  (type their code)   (show own code, pin)
/// ```
///
/// The reveal is made once, only after the reply and the joiner's directory bundle are held, and never for a second
/// reply: the state that holds them is never reset, and the session driving it must not run two steps at once
/// (`VaultSession` refuses that). Everything here is in memory; nothing is a key.
public struct SharingCodeStarter: Sendable {
    public enum Phase: Sendable, Hashable {
        /// The commitment is not on the board yet.
        case drawn
        /// Showing the number; waiting for someone to answer.
        case awaitingReply
        /// Answered and revealed: type the code on the other person's screen, or scan it.
        case awaitingJoinerCode
        /// Their code matched: show this device's code; the joiner's bundle is evidenced.
        case verified
        case failed(SharingCodeError)
    }

    public private(set) var number: SharingSessionNumber
    public let account: PublicKeyBundle
    private(set) var session: [UInt8]
    private(set) var nonce: [UInt8]
    private(set) var commitment: [UInt8]
    public private(set) var phase: Phase = .drawn
    public private(set) var attemptsLeft = SharingCodeLimits.attempts
    /// The joiner's account and the directory's bundle for it, fixed before the reveal.
    public private(set) var joiner: PublicKeyBundle?
    private var joinerNonce: [UInt8]?
    private var transcript: [UInt8]?
    private var revealPublished = false
    private var lastProgress: Date
    public private(set) var evidence: SharingCodeEvidence?

    /// A new session for `account`, everything drawn fresh; nothing is on the board yet.
    public static func draw<R: RandomNumberGenerator>(as account: PublicKeyBundle, using random: inout R, at now: Date)
        -> SharingCodeStarter
    {
        SharingCodeStarter(account: account, using: &random, at: now)
    }

    private init<R: RandomNumberGenerator>(account: PublicKeyBundle, using random: inout R, at now: Date) {
        self.account = account
        number = SharingSessionNumber.draw(using: &random)
        session = SharingNonce.draw(using: &random).bytes.prefix(16).map { $0 }
        nonce = SharingNonce.draw(using: &random).bytes
        commitment = SharingTranscript.commitment(session: session, starter: account.accountID, nonce: nonce)
        lastProgress = now
    }

    /// The QR code this device shows: the number and this account's fingerprint.
    public var scanPayload: String {
        ScannedSharingCode(number: number, bundle: account).payload
    }

    /// This device's six-digit code, shown only once the joiner's was accepted (ADR 0010), for the joiner to type.
    public var code: String? {
        guard phase == .verified, let transcript else { return nil }
        return SharingTranscript.grouped(SharingTranscript.code(transcript, at: SharingTranscript.starterCodeOffset))
    }

    /// Puts the commitment on the board. A number already taken throws `sessionTaken`: draw again.
    public mutating func publish(on board: any SharingBoard, at now: Date) async throws {
        guard phase == .drawn else { throw SharingCodeError.notReady }
        try checkAlive(now)
        let commit = SharingSessionMessage(
            kind: .commit, session: session, account: account.accountID, value: commitment)
        do {
            try await board.create(SharingBoardName.commit(number), contents: commit.encoded())
        } catch SharingBoardError.taken {
            throw SharingCodeError.sessionTaken
        }
        phase = .awaitingReply
        lastProgress = now
    }

    /// Looks for the reply and, once it and the joiner's bundle are held, reveals; or publishes a reveal that did not
    /// reach the board before. Returns whether anything changed.
    ///
    /// `beforeReveal` runs after the reply and the bundle are read and before anything is held or published; a throw
    /// there leaves the session as it was. The session passes its lock check, so a lock while the board or the
    /// directory answers reveals nothing (ADR 0010, "Lock").
    @discardableResult
    public mutating func poll(
        board: any SharingBoard, directory: any KeyBundleDirectory, at now: Date,
        beforeReveal: @Sendable () async throws -> Void = {}
    ) async throws -> Bool {
        try checkAlive(now)
        switch phase {
        case .awaitingReply:
            guard
                let bytes = try await board.fetch(
                    SharingBoardName.reply(number), maximumLength: SharingSessionMessage.length(of: .reply))
            else { return false }
            // The reply slot is created once, so junk there, or another session's reply, ends this session.
            guard let reply = try? SharingSessionMessage.parse(bytes, expecting: .reply), reply.session == session,
                let joinerID = reply.account
            else { throw fail(.malformedMessage) }
            guard joinerID != account.accountID else { throw fail(.sameAccount) }
            // The joiner's bundle as the directory gives it now, before anything that depends on it is public. Not
            // looked up again: a bundle chosen after the reveal could be searched for (ADR 0010, security analysis).
            let candidate = try await directory.candidateBundle(for: joinerID)
            try await beforeReveal()
            try checkAlive(now)
            guard case .awaitingReply = phase else { throw SharingCodeError.notReady }
            joiner = candidate
            joinerNonce = reply.value
            transcript = SharingTranscript.transcript(
                session: session, number: number, starter: account, joiner: candidate, commitment: commitment,
                starterNonce: nonce, joinerNonce: reply.value)
            phase = .awaitingJoinerCode
            lastProgress = now
            try await publishReveal(on: board)
            return true
        case .awaitingJoinerCode, .verified:
            guard !revealPublished else { return false }
            try await beforeReveal()
            try await publishReveal(on: board)
            return true
        case .drawn:
            throw SharingCodeError.notReady
        case .failed(let error):
            throw error
        }
    }

    /// The one reveal, of the one reply held. A reveal already there that is this one (a create whose answer was lost)
    /// is taken as made; anything else there is interference.
    private mutating func publishReveal(on board: any SharingBoard) async throws {
        let reveal = SharingSessionMessage(kind: .reveal, session: session, account: nil, value: nonce).encoded()
        do {
            try await board.create(SharingBoardName.reveal(number), contents: reveal)
        } catch SharingBoardError.taken {
            let there = try await board.fetch(
                SharingBoardName.reveal(number), maximumLength: SharingSessionMessage.length(of: .reveal))
            guard there == reveal else { throw fail(.boardInterference) }
        }
        revealPublished = true
    }

    /// The code the person typed from the joiner's screen. `true` if it matched (the joiner is evidenced and this
    /// device's code can be shown), `false` for a wrong code with attempts left; the last wrong one ends the session.
    /// Input that is not six digits compares nothing and uses no attempt.
    public mutating func enterJoinerCode(_ typed: String, at now: Date) throws -> Bool {
        try checkAlive(now)
        guard case .awaitingJoinerCode = phase, revealPublished, let transcript, let joiner else {
            throw SharingCodeError.notReady
        }
        guard let digits = SharingTypedDigits.digits(in: typed, count: SharingTranscript.codeDigits) else {
            throw SharingCodeError.malformedCode
        }
        let expected = SharingTranscript.code(transcript, at: SharingTranscript.joinerCodeOffset)
        guard ConstantTime.equal(digits, expected) else { return try wrongCode() }
        accept(joiner, method: .sharingCode, at: now)
        return true
    }

    /// The joiner's fingerprint code, read by this device's camera from their screen (`FingerprintCode.payload`), in
    /// place of typing their code: it authenticates the joiner's bundle by its whole fingerprint. A code of another
    /// account, or other keys, counts as a wrong code.
    public mutating func scanJoinerCode(_ payload: String, at now: Date) throws -> Bool {
        try checkAlive(now)
        guard case .awaitingJoinerCode = phase, let joiner else { throw SharingCodeError.notReady }
        guard let code = try? FingerprintCode(scanned: payload) else { throw SharingCodeError.malformedCode }
        guard code.accountID == joiner.accountID, code.matches(joiner) else { return try wrongCode() }
        accept(joiner, method: .scannedCode, at: now)
        return true
    }

    /// The invitation to send the joiner inside this session, signed by this account (`keyset`). Only once the joiner
    /// was accepted: it is for the bundle the session authenticated.
    public func invitationObject(_ invitation: Invitation, signedBy keyset: Keyset) throws -> (
        name: String, contents: [UInt8]
    ) {
        guard case .verified = phase, let joiner else { throw SharingCodeError.notReady }
        guard keyset.accountID == account.accountID else { throw SharingError.notPermitted }
        let content = SessionInvitationCodec.content(
            session: session, number: number, joiner: joiner.accountID, invitation: invitation)
        return (SharingBoardName.invitation(number), content + (try keyset.sign(content, domain: .membership)))
    }

    private mutating func accept(_ joiner: PublicKeyBundle, method: VerificationMethod, at now: Date) {
        evidence = SharingCodeEvidence(
            contact: joiner, pinningAccount: account.accountID, method: method, session: session)
        phase = .verified
        lastProgress = now
    }

    private mutating func wrongCode() throws -> Bool {
        attemptsLeft -= 1
        guard attemptsLeft > 0 else { throw fail(.tooManyAttempts) }
        return false
    }

    /// Ends the session with `error`, which the caller throws.
    private mutating func fail(_ error: SharingCodeError) -> SharingCodeError {
        phase = .failed(error)
        evidence = nil
        return error
    }

    private mutating func checkAlive(_ now: Date) throws {
        if case .failed(let error) = phase { throw error }
        if now.timeIntervalSince(lastProgress) > SharingCodeLimits.lifetime { throw fail(.expired) }
    }
}

/// The joiner's side of a vault sharing code session (ADR 0010): the invitee, or whoever types the number.
///
/// ```
/// join ──► awaitingReveal ──poll──► awaitingStarterCode ──enter──► verified
///  (reply)   (fetch, check C)        (show own code; type theirs)   (pin)
/// ```
///
/// The starter's bundle is looked up once, before the reply goes out, and is the one evidenced. A scan of the
/// starter's QR code authenticates that bundle at once (`.scannedCode`), and this device then types nothing.
public struct SharingCodeJoiner: Sendable {
    public enum Phase: Sendable, Hashable {
        /// Answered; waiting for the starter's reveal.
        case awaitingReveal
        /// Revealed and checked: show this device's code, and type the starter's.
        case awaitingStarterCode
        /// The starter is evidenced (their code matched, or the scan did).
        case verified
        case failed(SharingCodeError)
    }

    public let number: SharingSessionNumber
    public let account: PublicKeyBundle
    let session: [UInt8]
    /// The directory's bundle for the starter, fixed before this device's nonce was published.
    public let starter: PublicKeyBundle
    let commitment: [UInt8]
    let nonce: [UInt8]
    public let scanned: Bool
    public private(set) var phase: Phase = .awaitingReveal
    public private(set) var attemptsLeft = SharingCodeLimits.attempts
    private var transcript: [UInt8]?
    private var lastProgress: Date
    public private(set) var evidence: SharingCodeEvidence?

    /// Answers the session under `number`, or under the number of a scanned code (`scanned`, which must be for the
    /// same number), with `nonce` drawn fresh for this attempt. `beforeReply` runs once the commitment and the
    /// starter's bundle are read and checked, before the reply is published (the session's lock check).
    public static func join(
        _ number: SharingSessionNumber, scanned: ScannedSharingCode? = nil, as account: PublicKeyBundle,
        board: any SharingBoard, directory: any KeyBundleDirectory, nonce: SharingNonce, at now: Date,
        beforeReply: @Sendable () async throws -> Void = {}
    ) async throws -> SharingCodeJoiner {
        if let scanned, scanned.number != number { throw SharingCodeError.scannedCodeMismatch }
        guard
            let bytes = try await board.fetch(
                SharingBoardName.commit(number), maximumLength: SharingSessionMessage.length(of: .commit))
        else { throw SharingCodeError.sessionNotFound }
        guard let commit = try? SharingSessionMessage.parse(bytes, expecting: .commit), let starterID = commit.account
        else { throw SharingCodeError.malformedMessage }
        guard starterID != account.accountID else { throw SharingCodeError.sameAccount }
        if let scanned, scanned.fingerprint.accountID != starterID { throw SharingCodeError.scannedCodeMismatch }
        // Before this device's nonce is public: the bundle every later step uses.
        let candidate = try await directory.candidateBundle(for: starterID)
        if let scanned, !scanned.fingerprint.matches(candidate) { throw SharingCodeError.scannedCodeMismatch }
        try await beforeReply()
        let reply = SharingSessionMessage(
            kind: .reply, session: commit.session, account: account.accountID, value: nonce.bytes)
        do {
            try await board.create(SharingBoardName.reply(number), contents: reply.encoded())
        } catch SharingBoardError.taken {
            throw SharingCodeError.sessionTaken
        }
        var joiner = SharingCodeJoiner(
            number: number, account: account, session: commit.session, starter: candidate,
            commitment: commit.value, nonce: nonce.bytes, scanned: scanned != nil, lastProgress: now)
        if scanned != nil {
            joiner.evidence = SharingCodeEvidence(
                contact: candidate, pinningAccount: account.accountID, method: .scannedCode, session: commit.session)
        }
        return joiner
    }

    private init(
        number: SharingSessionNumber, account: PublicKeyBundle, session: [UInt8], starter: PublicKeyBundle,
        commitment: [UInt8], nonce: [UInt8], scanned: Bool, lastProgress: Date
    ) {
        self.number = number
        self.account = account
        self.session = session
        self.starter = starter
        self.commitment = commitment
        self.nonce = nonce
        self.scanned = scanned
        self.lastProgress = lastProgress
    }

    /// The QR code this device shows for the starter to scan in place of typing this device's code.
    public var scanPayload: String {
        FingerprintCode(bundle: account).payload
    }

    /// This device's six-digit code, once the reveal was checked, for the starter to type.
    public var code: String? {
        transcript.map {
            SharingTranscript.grouped(SharingTranscript.code($0, at: SharingTranscript.joinerCodeOffset))
        }
    }

    /// Looks for the starter's reveal and checks it opens the commitment. Returns whether anything changed.
    @discardableResult
    public mutating func poll(board: any SharingBoard, at now: Date) async throws -> Bool {
        try checkAlive(now)
        guard case .awaitingReveal = phase else { return false }
        guard
            let bytes = try await board.fetch(
                SharingBoardName.reveal(number), maximumLength: SharingSessionMessage.length(of: .reveal))
        else { return false }
        try checkAlive(now)
        guard case .awaitingReveal = phase else { return false }
        guard let reveal = try? SharingSessionMessage.parse(bytes, expecting: .reveal), reveal.session == session else {
            throw fail(.malformedMessage)
        }
        let opened = SharingTranscript.commitment(session: session, starter: starter.accountID, nonce: reveal.value)
        guard ConstantTime.equal(opened, commitment) else { throw fail(.commitmentMismatch) }
        transcript = SharingTranscript.transcript(
            session: session, number: number, starter: starter, joiner: account, commitment: commitment,
            starterNonce: reveal.value, joinerNonce: nonce)
        phase = scanned ? .verified : .awaitingStarterCode
        lastProgress = now
        return true
    }

    /// The code the person typed from the starter's screen: `true` if it matched, `false` for a wrong one with
    /// attempts left; the last wrong one ends the session.
    public mutating func enterStarterCode(_ typed: String, at now: Date) throws -> Bool {
        try checkAlive(now)
        guard case .awaitingStarterCode = phase, let transcript else { throw SharingCodeError.notReady }
        guard let digits = SharingTypedDigits.digits(in: typed, count: SharingTranscript.codeDigits) else {
            throw SharingCodeError.malformedCode
        }
        let expected = SharingTranscript.code(transcript, at: SharingTranscript.starterCodeOffset)
        guard ConstantTime.equal(digits, expected) else {
            attemptsLeft -= 1
            guard attemptsLeft > 0 else { throw fail(.tooManyAttempts) }
            return false
        }
        evidence = SharingCodeEvidence(
            contact: starter, pinningAccount: account.accountID, method: .sharingCode, session: session)
        phase = .verified
        lastProgress = now
        return true
    }

    /// The invitation the starter sent in this session, verified under the starter's bundle the session evidenced
    /// and bound to this session and this account. Throws `notReady` before the starter is evidenced.
    public func openInvitation(_ bytes: [UInt8]) throws -> Invitation {
        guard let evidence, case .verified = phase else { throw SharingCodeError.notReady }
        return try SessionInvitationCodec.open(
            bytes, session: session, number: number, joiner: account.accountID, starter: evidence.contact)
    }

    /// The most bytes `openInvitation` takes: fetch no more.
    public static var invitationLength: Int { SessionInvitationCodec.encodedLength }

    /// Ends the session with `error`, which the caller throws.
    private mutating func fail(_ error: SharingCodeError) -> SharingCodeError {
        phase = .failed(error)
        evidence = nil
        return error
    }

    private mutating func checkAlive(_ now: Date) throws {
        if case .failed(let error) = phase { throw error }
        if now.timeIntervalSince(lastProgress) > SharingCodeLimits.lifetime { throw fail(.expired) }
    }
}
