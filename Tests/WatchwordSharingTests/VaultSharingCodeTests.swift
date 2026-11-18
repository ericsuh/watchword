import Foundation
import Testing
import WatchwordCrypto
import WatchwordTestSupport

@testable import WatchwordSharing

/// Vault sharing codes (ADR 0010, docs/02-architecture.md §8.4): the eight-digit number, the scanned code, the board
/// messages, the transcript, and both sides of a session with real keys. The adversarial cases are in "sharing and
/// membership".
@Suite("Vault sharing codes")
struct VaultSharingCodeTests {
    static let now = SharingCodeRig.now

    // MARK: Parsing what people type and scan

    @Test("a typed number is exactly eight ASCII digits, with spaces, tabs and hyphens between ignored")
    func typedNumber() {
        #expect(SharingSessionNumber(typed: "1234 5678")?.digits == "12345678")
        #expect(SharingSessionNumber(typed: "12-34-56-78")?.digits == "12345678")
        #expect(SharingSessionNumber(typed: "\t00000001")?.digits == "00000001")
        for bad in ["1234567", "123456789", "1234 567a", "１２３４５６７８", "١٢٣٤٥٦٧٨", "1234\n5678", "", "+12345678"] {
            #expect(SharingSessionNumber(typed: bad) == nil, "\(bad)")
        }
        #expect(SharingSessionNumber(typed: String(repeating: " ", count: 60) + "12345678") == nil, "over the bound")
        #expect(SharingSessionNumber(typed: "1234 5678")?.grouped == "1234 5678")
    }

    @Test("numbers are drawn from all 10^8 and always have eight digits")
    func drawnNumbers() {
        var generator = SeededGenerator(seed: 3)
        var seen: Set<String> = []
        for _ in 0..<500 {
            let number = SharingSessionNumber.draw(using: &generator)
            #expect(number.digits.count == 8 && number.digits.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 })
            seen.insert(number.digits)
        }
        #expect(seen.count > 495)
        #expect(seen.contains { $0.hasPrefix("0") }, "leading zeros are kept")
    }

    @Test("the starter's QR code round-trips and parses exactly one spelling of one length")
    func scannedCode() throws {
        let party = try SharingParty(seed: 7)
        let number = try #require(SharingSessionNumber(typed: "01234567"))
        let code = ScannedSharingCode(number: number, bundle: party.bundle)
        #expect(code.payload.hasPrefix("WWSC1-01234567WWFP1-"))
        #expect(code.payload.utf8.count == ScannedSharingCode.payloadLength)
        let parsed = try ScannedSharingCode(scanned: code.payload)
        #expect(parsed == code && parsed.fingerprint.matches(party.bundle))
        let payload = code.payload
        let bad = [
            String(payload.dropLast()), payload + "0", payload.lowercased(), "WWSC2-" + payload.dropFirst(6),
            "WWSC1-0123456A" + payload.dropFirst(14), "WWSC1-" + payload.dropFirst(14), "",
        ]
        for text in bad {
            #expect(throws: SharingFormatError.malformedText) { try ScannedSharingCode(scanned: text) }
        }
    }

    // MARK: Messages and transcript

    @Test("the commitment and the codes match an independent implementation (Python hashlib)")
    func knownAnswers() {
        let session = Array(1...16).map(UInt8.init)
        let starter = UUID(uuidString: "00112233-4455-6677-8899-AABBCCDDEEFF")!
        let commitment = SharingTranscript.commitment(
            session: session, starter: starter, nonce: Array(repeating: 0xA5, count: 32))
        #expect(SharingBytes.hex(commitment) == "b911422fa0ae19c39400c029c8f2bb728bfb421f077b35edee869adb9bdee759")
        // SHA-256("transcript"), read at both offsets.
        let transcript = SharingBytes.bytes(
            hex: "54e6289e14c7b0e7ad9acc2dfc4c1e3d027d0eef7f5c4c3fe7c292761d0e06a6")!
        #expect(String(decoding: SharingTranscript.code(transcript, at: 0), as: UTF8.self) == "972583")
        #expect(String(decoding: SharingTranscript.code(transcript, at: 8), as: UTF8.self) == "415485")
        #expect(SharingTranscript.grouped(Array("972583".utf8)) == "972 583")
    }

    @Test("every board message parses only at its own length, magic, version and kind")
    func messagesAreExact() throws {
        let session = Array(repeating: UInt8(7), count: 16)
        let messages: [SharingSessionMessage] = [
            SharingSessionMessage(
                kind: .commit, session: session, account: UUID(), value: Array(repeating: 1, count: 32)),
            SharingSessionMessage(
                kind: .reply, session: session, account: UUID(), value: Array(repeating: 2, count: 32)),
            SharingSessionMessage(kind: .reveal, session: session, account: nil, value: Array(repeating: 3, count: 32)),
        ]
        for message in messages {
            let bytes = message.encoded()
            #expect(bytes.count == SharingSessionMessage.length(of: message.kind))
            #expect(try SharingSessionMessage.parse(bytes, expecting: message.kind) == message)
            for cut in 0..<bytes.count {
                #expect(throws: (any Error).self) {
                    try SharingSessionMessage.parse(Array(bytes.prefix(cut)), expecting: message.kind)
                }
            }
            #expect(throws: (any Error).self) { try SharingSessionMessage.parse(bytes + [0], expecting: message.kind) }
            for kind in [SharingSessionMessage.Kind.commit, .reply, .reveal] where kind != message.kind {
                #expect(throws: (any Error).self) { try SharingSessionMessage.parse(bytes, expecting: kind) }
            }
            for index in [0, 4] {
                var altered = bytes
                altered[index] ^= 1
                #expect(throws: (any Error).self) { try SharingSessionMessage.parse(altered, expecting: message.kind) }
            }
        }
    }

    @Test("the transcript changes with every input, and the two codes are read from different bytes")
    func transcriptBindsEverything() async throws {
        let rig = try await SharingCodeRig(seed: 20)
        let other = try SharingParty(seed: 99)
        let number = try #require(SharingSessionNumber(typed: "12345678"))
        let base: [UInt8] = Array(repeating: 9, count: 32)
        func t(
            session: [UInt8] = Array(repeating: 1, count: 16), number: SharingSessionNumber? = nil,
            starter: PublicKeyBundle? = nil, joiner: PublicKeyBundle? = nil, commitment: [UInt8]? = nil,
            ns: [UInt8]? = nil, nj: [UInt8]? = nil
        ) -> [UInt8] {
            SharingTranscript.transcript(
                session: session, number: number ?? SharingSessionNumber(typed: "12345678")!,
                starter: starter ?? rig.starter.bundle, joiner: joiner ?? rig.joiner.bundle,
                commitment: commitment ?? base, starterNonce: ns ?? base, joinerNonce: nj ?? base)
        }
        let reference = t()
        // Built one at a time with its type named: as one literal, Swift 6.0 (Xcode 16.4) gives up type-checking it.
        let changed: [UInt8] = Array(repeating: 8, count: 32)
        var variants: [[UInt8]] = []
        variants.append(t(session: Array(repeating: 2, count: 16)))
        variants.append(t(number: SharingSessionNumber(typed: "12345679")))
        variants.append(t(starter: other.bundle))
        variants.append(t(joiner: other.bundle))
        variants.append(t(starter: rig.joiner.bundle, joiner: rig.starter.bundle))
        variants.append(t(commitment: changed))
        variants.append(t(ns: changed))
        variants.append(t(nj: changed))
        let distinct: Set<[UInt8]> = Set(variants).union([reference])
        let expected: Int = variants.count + 1
        #expect(distinct.count == expected)
        // The same keys with a fresh self-signature (Ed25519 signing is randomised on CryptoKit) change nothing.
        let resigned = try rig.starter.keyset.publicKeyBundle()
        #expect(t(starter: resigned) == reference)
        _ = number
    }

    // MARK: A session

    @Test("a session between two honest devices ends with each holding the other's true bundle as evidence")
    func honestSession() async throws {
        let rig = try await SharingCodeRig(seed: 30)
        var starter = try await rig.start(seed: 31)
        #expect(starter.phase == .awaitingReply && starter.code == nil)
        #expect(try await !starter.poll(board: rig.board, directory: rig.directory, at: Self.now), "nothing yet")

        var joiner = try await rig.join(starter.number, seed: 32)
        #expect(
            joiner.phase == .awaitingReveal && joiner.code == nil && joiner.starter.hasSameKeys(as: rig.starter.bundle))
        #expect(try await !joiner.poll(board: rig.board, at: Self.now), "not revealed yet")

        #expect(try await starter.poll(board: rig.board, directory: rig.directory, at: Self.now))
        #expect(starter.phase == .awaitingJoinerCode && starter.joiner?.hasSameKeys(as: rig.joiner.bundle) == true)
        #expect(starter.code == nil, "the starter's code is shown only after the joiner's was accepted")
        #expect(try await joiner.poll(board: rig.board, at: Self.now))
        #expect(joiner.phase == .awaitingStarterCode)
        let joinerCode = try #require(joiner.code)
        #expect(joinerCode.count == 7 && joinerCode.contains(" "))

        #expect(try starter.enterJoinerCode(joinerCode, at: Self.now))
        #expect(starter.phase == .verified)
        let starterCode = try #require(starter.code)
        #expect(try joiner.enterStarterCode(starterCode, at: Self.now))
        #expect(joiner.phase == .verified)

        let toStarter = try #require(starter.evidence)
        let toJoiner = try #require(joiner.evidence)
        #expect(toStarter.contact.hasSameKeys(as: rig.joiner.bundle) && toStarter.method == .sharingCode)
        #expect(toStarter.pinningAccount == rig.starter.accountID)
        #expect(toJoiner.contact.hasSameKeys(as: rig.starter.bundle) && toJoiner.pinningAccount == rig.joiner.accountID)

        // Evidence pins through VerifiedContacts, for the account it was made for only.
        let pins = VerifiedContacts(store: InMemoryVerifiedContactStore(), account: rig.starter.bundle)
        let pinned = try await pins.verify(toStarter, signedBy: rig.starter.keyset, at: Self.now)
        #expect(pinned.method == .sharingCode && pinned.bundle.hasSameKeys(as: rig.joiner.bundle))
        #expect(try await pins.trust(of: rig.joiner.bundle) == .verified(pinned))
    }

    @Test("a scan replaces typing in either direction, and each direction stands alone")
    func scannedSession() async throws {
        let rig = try await SharingCodeRig(seed: 40)
        var starter = try await rig.start(seed: 41)
        let scanned = try ScannedSharingCode(scanned: starter.scanPayload)
        var joiner = try await rig.join(scanned.number, seed: 42, scanned: scanned)
        #expect(joiner.evidence == nil, "a scan is no evidence before the starter's device has revealed (V18)")
        #expect(joiner.phase == .awaitingReveal)

        try await starter.poll(board: rig.board, directory: rig.directory, at: Self.now)
        try await joiner.poll(board: rig.board, at: Self.now)
        #expect(joiner.phase == .verified, "nothing to type after a scan")
        #expect(joiner.evidence?.method == .scannedCode, "the reveal opened the commitment: the scan is evidence")
        #expect(joiner.evidence?.contact.hasSameKeys(as: rig.starter.bundle) == true)
        #expect(joiner.code != nil, "its own code is still shown, for a starter that types")
        #expect(try starter.scanJoinerCode(joiner.scanPayload, at: Self.now))
        #expect(starter.evidence?.method == .scannedCode)
        #expect(starter.evidence?.contact.hasSameKeys(as: rig.joiner.bundle) == true)
    }

    @Test("the invitation sent inside a session opens only in that session, for that joiner")
    func invitationInsideTheSession() async throws {
        let rig = try await SharingCodeRig(seed: 50)
        var starter = try await rig.start(seed: 51)
        var joiner = try await rig.join(starter.number, seed: 52)
        try await starter.poll(board: rig.board, directory: rig.directory, at: Self.now)
        try await joiner.poll(board: rig.board, at: Self.now)
        let invitation = Invitation(vaultID: UUID(), ownerAccountID: rig.starter.accountID)
        #expect(throws: SharingCodeError.notReady, "before the joiner is accepted") {
            try starter.invitationObject(invitation, signedBy: rig.starter.keyset)
        }
        _ = try starter.enterJoinerCode(try #require(joiner.code), at: Self.now)
        let object = try starter.invitationObject(invitation, signedBy: rig.starter.keyset)
        #expect(object.name == SharingBoardName.invitation(starter.number, session: starter.session))
        #expect(object.name == joiner.invitationName, "both ends name the slot after the session")
        #expect(object.name.hasSuffix("/invitation/" + SharingBytes.hex(starter.session)))
        #expect(throws: SharingCodeError.notReady, "before the starter is evidenced") {
            try joiner.openInvitation(object.contents)
        }
        _ = try joiner.enterStarterCode(try #require(starter.code), at: Self.now)
        #expect(try joiner.openInvitation(object.contents) == invitation)
        #expect(throws: SharingError.notPermitted) {
            try starter.invitationObject(invitation, signedBy: rig.joiner.keyset)
        }
    }
}
