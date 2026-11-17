import Foundation
import Testing
import WatchwordCrypto
import WatchwordTestSupport

@testable import WatchwordSharing

/// Fingerprints, pinned contacts and the invitation state machine (docs/02-architecture.md §8.4; PRD F4.1, F4.2,
/// SEC3).
@Suite("Fingerprint verification and invitations")
struct VerificationAndInvitationTests {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)

    static func book(for party: SharingParty) -> (VerifiedContacts, InMemoryVerifiedContactStore) {
        let store = InMemoryVerifiedContactStore()
        return (VerifiedContacts(store: store, account: party.bundle), store)
    }

    // MARK: - Fingerprints

    @Test("a typed safety number matches with or without its spaces, and nothing else does")
    func typedSafetyNumber() throws {
        let alice = try SharingParty(seed: 1)
        let bob = try SharingParty(seed: 2)
        let fingerprint = alice.bundle.fingerprint
        let number = fingerprint.safetyNumber
        #expect(fingerprint.matches(safetyNumber: number))
        #expect(fingerprint.matches(safetyNumber: number.replacingOccurrences(of: " ", with: "")))
        #expect(fingerprint.matches(safetyNumber: "  " + number.replacingOccurrences(of: " ", with: "\n") + "\t"))

        #expect(!fingerprint.matches(safetyNumber: bob.bundle.fingerprint.safetyNumber))
        #expect(!fingerprint.matches(safetyNumber: ""))
        #expect(!fingerprint.matches(safetyNumber: String(number.dropLast())))
        #expect(!fingerprint.matches(safetyNumber: number + "0"))
        #expect(!fingerprint.matches(safetyNumber: number.replacingOccurrences(of: " ", with: "-")))
        var digits = Array(number)
        digits[0] = digits[0] == "9" ? "0" : "9"
        #expect(!fingerprint.matches(safetyNumber: String(digits)))
        // Digits of another script are not these digits.
        let arabicIndic = String(
            number.map { digit -> Character in
                guard let value = digit.wholeNumberValue else { return digit }
                return Character(UnicodeScalar(0x0660 + UInt32(value))!)
            })
        #expect(!fingerprint.matches(safetyNumber: arabicIndic))
        #expect(!fingerprint.matches(safetyNumber: number + String(repeating: " ", count: 500)), "over the bound")
    }

    @Test("a scanned code matches the bundle it was made from and no other")
    func scannedCode() throws {
        let alice = try SharingParty(seed: 1)
        let bob = try SharingParty(seed: 2)
        let code = FingerprintCode(bundle: alice.bundle)
        let scanned = try FingerprintCode(scanned: code.payload)
        #expect(scanned == code)
        #expect(scanned.accountID == alice.accountID)
        #expect(scanned.matches(alice.bundle))
        #expect(!scanned.matches(bob.bundle))
        #expect(code.payload.utf8.count == FingerprintCode.payloadLength)
        #expect(code.payload.allSatisfy { $0.isASCII && ($0.isNumber || $0.isUppercase || $0 == "-") })
    }

    @Test("a scanned payload that is not exactly a code is refused")
    func scannedCodeRefusals() throws {
        let payload = FingerprintCode(bundle: try SharingParty(seed: 1).bundle).payload
        let bad = [
            "", "WWFP1-", payload.lowercased(), String(payload.dropLast()), payload + "0", " " + payload,
            payload.replacingOccurrences(of: "WWFP1-", with: "WWFP2-"),
            payload.replacingOccurrences(of: "WWFP1-", with: "WWFP1_"),
            String(payload.dropLast()) + "G", String(payload.dropLast(2)) + "é",
            "https://example.com/" + payload, String(repeating: "A", count: 1_000_000),
        ]
        for candidate in bad {
            #expect(throws: SharingFormatError.malformedText, "\(candidate.prefix(40))") {
                _ = try FingerprintCode(scanned: candidate)
            }
        }
    }

    // MARK: - The key directory

    @Test("the directory's answer is parsed, validated, and must be for the account asked about")
    func directoryLookup() async throws {
        let alice = try SharingParty(seed: 1)
        let bob = try SharingParty(seed: 2)
        let directory = InMemoryKeyBundleDirectory()
        await directory.publish(alice.bundle)

        #expect(try await directory.candidateBundle(for: alice.accountID) == alice.bundle)
        await #expect(throws: SharingError.unknownAccount(bob.accountID)) {
            _ = try await directory.candidateBundle(for: bob.accountID)
        }

        await directory.tamper(bob.accountID, contents: KeyBundleCodec.encode(alice.bundle))
        await #expect(throws: SharingError.directoryMismatch(asked: bob.accountID, returned: alice.accountID)) {
            _ = try await directory.candidateBundle(for: bob.accountID)
        }

        let encoded = KeyBundleCodec.encode(alice.bundle)
        #expect(encoded.count == KeyBundleCodec.encodedLength)
        for length in 0..<encoded.count {
            #expect(throws: SharingFormatError.self) {
                _ = try KeyBundleCodec.parse(Array(encoded[0..<length]), expecting: alice.accountID)
            }
        }
        #expect(throws: SharingFormatError.tooLarge(encoded.count + 1)) {
            _ = try KeyBundleCodec.parse(encoded + [0], expecting: alice.accountID)
        }
        var badSignature = encoded
        badSignature[encoded.count - 1] ^= 1
        #expect(throws: CryptoError.signatureInvalid) {
            _ = try KeyBundleCodec.parse(badSignature, expecting: alice.accountID)
        }
    }

    // MARK: - Verified contacts

    @Test("each kind of evidence pins the contact, and the pin is what later lookups trust")
    func pinning() async throws {
        let me = try SharingParty(seed: 1)
        for (index, method) in [VerificationMethod.safetyNumber, .scannedCode, .comparedByEye].enumerated() {
            let (contacts, _) = Self.book(for: me)
            let them = try SharingParty(seed: 10 + UInt64(index))
            #expect(try await contacts.trust(of: them.bundle) == .unverified)
            let evidence: VerificationEvidence
            switch method {
            case .safetyNumber: evidence = .safetyNumber(them.bundle.fingerprint.safetyNumber)
            case .scannedCode: evidence = .scannedCode(FingerprintCode(bundle: them.bundle).payload)
            case .comparedByEye: evidence = .comparedByEye(shown: them.bundle.fingerprint)
            }
            let contact = try await contacts.verify(them.bundle, evidence: evidence, signedBy: me.keyset, at: Self.now)
            #expect(contact.bundle == them.bundle)
            #expect(contact.method == method)
            #expect(contact.verifiedAt == Self.now)
            #expect(contact.accountID == them.accountID)
            #expect(try await contacts.trust(of: them.bundle) == .verified(contact))
            #expect(try await contacts.pinned(them.accountID) == contact)
        }
    }

    @Test("evidence that does not match the bundle pins nothing")
    func mismatchedEvidence() async throws {
        let me = try SharingParty(seed: 1)
        let them = try SharingParty(seed: 2)
        let other = try SharingParty(seed: 3)
        let (contacts, store) = Self.book(for: me)
        let wrong: [VerificationEvidence] = [
            .safetyNumber(other.bundle.fingerprint.safetyNumber), .safetyNumber(""),
            .scannedCode(FingerprintCode(bundle: other.bundle).payload),
        ]
        for evidence in wrong {
            await #expect(throws: SharingError.fingerprintMismatch) {
                _ = try await contacts.verify(them.bundle, evidence: evidence, signedBy: me.keyset, at: Self.now)
            }
        }
        await #expect(throws: SharingFormatError.malformedText) {
            _ = try await contacts.verify(
                them.bundle, evidence: .scannedCode("junk"), signedBy: me.keyset, at: Self.now)
        }
        await #expect(throws: SharingError.notPermitted, "pins are signed by the account they belong to") {
            _ = try await contacts.verify(
                them.bundle, evidence: .comparedByEye(shown: them.bundle.fingerprint), signedBy: other.keyset,
                at: Self.now)
        }
        #expect(await store.pin(for: them.accountID) == nil)
        #expect(try await contacts.trust(of: them.bundle) == .unverified)
    }

    @Test("a different bundle for a pinned account is reported, until the person verifies it again on purpose")
    func keyChange() async throws {
        let me = try SharingParty(seed: 1)
        let them = try SharingParty(seed: 2)
        let (contacts, _) = Self.book(for: me)
        _ = try await contacts.verify(
            them.bundle, evidence: .comparedByEye(shown: them.bundle.fingerprint), signedBy: me.keyset, at: Self.now)

        // The same account ID with other keys: what a store substituting a key would publish.
        let replacement = try SharingParty(accountID: them.accountID, seed: 900).bundle
        await #expect(throws: SharingError.keySubstituted(accountID: them.accountID)) {
            _ = try await contacts.trust(of: replacement)
        }
        await #expect(throws: SharingError.keySubstituted(accountID: them.accountID)) {
            _ = try await contacts.verify(
                replacement, evidence: .safetyNumber(replacement.fingerprint.safetyNumber), signedBy: me.keyset,
                at: Self.now)
        }
        #expect(try await contacts.pinned(them.accountID)?.bundle == them.bundle, "the pin is untouched")

        let again = try await contacts.verify(
            replacement, evidence: .safetyNumber(replacement.fingerprint.safetyNumber), signedBy: me.keyset,
            at: Self.now, replacingPin: true)
        #expect(again.bundle == replacement)
        #expect(try await contacts.trust(of: replacement) == .verified(again))
        await #expect(throws: SharingError.keySubstituted(accountID: them.accountID)) {
            _ = try await contacts.trust(of: them.bundle)
        }

        try await contacts.forget(them.accountID)
        #expect(try await contacts.trust(of: them.bundle) == .unverified)
    }

    @Test("the account's own bundle is verified without a pin, and an impostor of it is a substitution")
    func ownAccount() async throws {
        let me = try SharingParty(seed: 1)
        let (contacts, store) = Self.book(for: me)
        #expect(try await contacts.trust(of: me.bundle) == .verified(contacts.myself))
        #expect(try await contacts.trust(of: me.keyset.publicKeyBundle()) == .verified(contacts.myself))
        #expect(contacts.myself.method == nil)
        let impostor = try SharingParty(accountID: me.accountID, seed: 901).bundle
        await #expect(throws: SharingError.keySubstituted(accountID: me.accountID)) {
            _ = try await contacts.trust(of: impostor)
        }
        #expect(await store.pin(for: me.accountID) == nil)
    }

    // MARK: - Invitations

    struct Setup {
        var household: SharingHousehold
        let directory = InMemoryKeyBundleDirectory()
        let guest: SharingParty
        let guestContacts: VerifiedContacts

        static func make() async throws -> Setup {
            let household = try await SharingHousehold.make()
            let guest = try SharingParty(seed: 500)
            let setup = Setup(
                household: household, guest: guest,
                guestContacts: VerifiedContacts(store: InMemoryVerifiedContactStore(), account: guest.bundle))
            for party in [household.owner, household.administrator, guest] {
                await setup.directory.publish(party.bundle)
            }
            return setup
        }
    }

    @Test("inviting: nothing is wrapped until the invitee's fingerprint is confirmed, and each step happens once")
    func outgoingStateMachine() async throws {
        let setup = try await Setup.make()
        let household = setup.household
        let owner = household.owner
        var invitation = try await OutgoingInvitation.begin(
            vaultID: household.vaultID, inviting: setup.guest.accountID, as: .readWrite, directory: setup.directory,
            contacts: household.contacts)
        #expect(invitation.state == .awaitingVerification(setup.guest.bundle))
        #expect(invitation.fingerprintToConfirm == setup.guest.bundle.fingerprint)

        #expect(throws: SharingError.fingerprintNotVerified) {
            _ = try invitation.issue(ledger: household.ledger, vaultKey: household.vaultKey, signedBy: owner.keyset)
        }
        await #expect(throws: SharingError.fingerprintMismatch) {
            try await invitation.confirm(
                .safetyNumber(owner.bundle.fingerprint.safetyNumber), contacts: household.contacts,
                signedBy: owner.keyset, at: Self.now)
        }
        #expect(invitation.state == .awaitingVerification(setup.guest.bundle), "a failed confirmation changes nothing")

        try await invitation.confirm(
            .safetyNumber(setup.guest.bundle.fingerprint.safetyNumber), contacts: household.contacts,
            signedBy: owner.keyset, at: Self.now)
        #expect(invitation.fingerprintToConfirm == nil)
        await #expect(throws: SharingError.invitationAlreadyCompleted) {
            try await invitation.confirm(
                .comparedByEye(shown: setup.guest.bundle.fingerprint), contacts: household.contacts,
                signedBy: owner.keyset, at: Self.now)
        }

        var generator = SeededGenerator(seed: 5)
        let staleKey = VaultKey.generate(vaultID: household.vaultID, using: &generator)
        #expect(throws: SharingError.notCurrentKey) {
            _ = try invitation.issue(ledger: household.ledger, vaultKey: staleKey, signedBy: owner.keyset)
        }
        let package = try invitation.issue(
            ledger: household.ledger, vaultKey: household.vaultKey, signedBy: owner.keyset)
        #expect(invitation.state == .issued(package))
        #expect(package.invitation == Invitation(vaultID: household.vaultID, ownerAccountID: owner.accountID))
        #expect(package.objects == [package.grant, package.record], "the grant is published before the record")
        #expect(throws: SharingError.invitationAlreadyCompleted) {
            _ = try invitation.issue(ledger: household.ledger, vaultKey: household.vaultKey, signedBy: owner.keyset)
        }

        let record = try MembershipRecord.parse(package.record.contents)
        #expect(record.operation == .addMember(setup.guest.accountID, role: .readWrite))
        #expect(record.epoch == household.state.epoch + 1)
    }

    @Test("inviting someone already verified needs no second comparison; nobody is invited as owner")
    func outgoingShortcuts() async throws {
        let setup = try await Setup.make()
        let household = setup.household
        _ = try await household.contact(setup.guest)
        let invitation = try await OutgoingInvitation.begin(
            vaultID: household.vaultID, inviting: setup.guest.accountID, as: .readOnly, directory: setup.directory,
            contacts: household.contacts)
        guard case .verified(let contact) = invitation.state else {
            Issue.record("expected the pinned contact")
            return
        }
        #expect(contact.bundle == setup.guest.bundle)

        await #expect(throws: MembershipError.ownerIsFixed) {
            _ = try await OutgoingInvitation.begin(
                vaultID: household.vaultID, inviting: setup.guest.accountID, as: .owner,
                directory: setup.directory, contacts: household.contacts)
        }
        await #expect(throws: SharingError.unknownAccount(household.outsider.accountID)) {
            _ = try await OutgoingInvitation.begin(
                vaultID: household.vaultID, inviting: household.outsider.accountID, as: .readOnly,
                directory: setup.directory, contacts: household.contacts)
        }
    }

    /// The owner issues an invitation to the guest; returns what a store would then hold.
    static func issued(_ setup: inout Setup, by inviter: SharingParty, as role: MemberRole = .readWrite) async throws
        -> (invitation: Invitation, records: [[UInt8]], grants: [(name: String, contents: [UInt8])])
    {
        let contacts =
            inviter.accountID == setup.household.owner.accountID
            ? setup.household.contacts
            : VerifiedContacts(store: InMemoryVerifiedContactStore(), account: inviter.bundle)
        var outgoing = try await OutgoingInvitation.begin(
            vaultID: setup.household.vaultID, inviting: setup.guest.accountID, as: role,
            directory: setup.directory, contacts: contacts)
        try await outgoing.confirm(
            .comparedByEye(shown: setup.guest.bundle.fingerprint), contacts: contacts, signedBy: inviter.keyset,
            at: now)
        let package = try outgoing.issue(
            ledger: setup.household.ledger, vaultKey: setup.household.vaultKey, signedBy: inviter.keyset)
        try setup.household.adopt(package.record.contents)
        return (
            package.invitation, setup.household.ledger.chain.map(\.encoded),
            [(name: package.grant.name, contents: package.grant.contents)]
        )
    }

    @Test("accepting: the key is opened only after the owner's fingerprint is confirmed, and once")
    func incomingStateMachine() async throws {
        var setup = try await Setup.make()
        let guest = setup.guest
        let owner = setup.household.owner
        let (invitation, records, grants) = try await Self.issued(&setup, by: owner)

        var incoming = try await IncomingInvitation.begin(
            invitation, knownOwner: nil, directory: setup.directory, contacts: setup.guestContacts)
        #expect(incoming.state == .awaitingVerification(owner.bundle))
        #expect(incoming.fingerprintToConfirm == owner.bundle.fingerprint)
        #expect(throws: SharingError.fingerprintNotVerified) {
            _ = try incoming.accept(membership: records, grants: grants, as: guest.keyset, continuing: nil)
        }
        await #expect(throws: SharingError.fingerprintMismatch) {
            try await incoming.confirm(
                .safetyNumber(guest.bundle.fingerprint.safetyNumber), contacts: setup.guestContacts,
                signedBy: guest.keyset, at: Self.now)
        }
        try await incoming.confirm(
            .scannedCode(FingerprintCode(bundle: owner.bundle).payload), contacts: setup.guestContacts,
            signedBy: guest.keyset, at: Self.now)

        let joined = try incoming.accept(membership: records, grants: grants, as: guest.keyset, continuing: nil)
        #expect(incoming.state == .accepted)
        #expect(joined.ledger.state == setup.household.state)
        #expect(joined.vaultKey.key.keyID == setup.household.vaultKey.key.keyID)
        #expect(joined.vaultKey.key.material.constantTimeEquals(setup.household.vaultKey.key.material))
        #expect(joined.vaultKey.vaultID == setup.household.vaultID)
        #expect(throws: SharingError.invitationAlreadyCompleted) {
            _ = try incoming.accept(membership: records, grants: grants, as: guest.keyset, continuing: nil)
        }
        #expect(try await setup.guestContacts.pinned(owner.accountID)?.method == .scannedCode)
    }

    @Test(
        "an administrator can invite; the invitee still verifies the owner, whose chain vouches for the administrator")
    func invitedByAdministrator() async throws {
        var setup = try await Setup.make()
        let guest = setup.guest
        let (invitation, records, grants) = try await Self.issued(&setup, by: setup.household.administrator)
        #expect(invitation.ownerAccountID == setup.household.owner.accountID)

        var incoming = try await IncomingInvitation.begin(
            invitation, knownOwner: nil, directory: setup.directory, contacts: setup.guestContacts)
        try await incoming.confirm(
            .comparedByEye(shown: setup.household.owner.bundle.fingerprint), contacts: setup.guestContacts,
            signedBy: guest.keyset, at: Self.now)
        let joined = try incoming.accept(membership: records, grants: grants, as: guest.keyset, continuing: nil)
        #expect(joined.ledger.state.member(guest.accountID)?.role == .readWrite)
        #expect(
            try joined.ledger.grantSender(forKey: joined.vaultKey.key.keyID, to: guest.accountID).accountID
                == setup.household.administrator.accountID)
    }

    @Test("accepting fails closed when the chain or the grant offered is not for this account")
    func incomingRefusals() async throws {
        var setup = try await Setup.make()
        let guest = setup.guest
        let beforeInvitation = setup.household.ledger.chain.map(\.encoded)
        let (invitation, records, grants) = try await Self.issued(&setup, by: setup.household.owner)
        func verified() async throws -> IncomingInvitation {
            var incoming = try await IncomingInvitation.begin(
                invitation, knownOwner: nil, directory: setup.directory, contacts: setup.guestContacts)
            if incoming.fingerprintToConfirm != nil {
                try await incoming.confirm(
                    .comparedByEye(shown: setup.household.owner.bundle.fingerprint), contacts: setup.guestContacts,
                    signedBy: guest.keyset, at: Self.now)
            }
            return incoming
        }

        var incoming = try await verified()
        #expect(throws: SharingError.notAMember(guest.accountID), "the record adding the invitee was withheld") {
            _ = try incoming.accept(membership: beforeInvitation, grants: grants, as: guest.keyset, continuing: nil)
        }
        #expect(throws: SharingError.grantNotFound) {
            _ = try incoming.accept(membership: records, grants: [], as: guest.keyset, continuing: nil)
        }
        #expect(throws: LedgerError.noGenesis) {
            _ = try incoming.accept(membership: [], grants: grants, as: guest.keyset, continuing: nil)
        }
        #expect(incoming.state != .accepted, "nothing was accepted, and a later attempt may still succeed")
        _ = try incoming.accept(membership: records, grants: grants, as: guest.keyset, continuing: nil)

        // An invitation whose vault ID was altered on the way finds no chain for that vault.
        var misdirected = try await IncomingInvitation.begin(
            Invitation(vaultID: UUID(), ownerAccountID: invitation.ownerAccountID), knownOwner: nil,
            directory: setup.directory, contacts: setup.guestContacts)
        #expect(throws: LedgerError.noGenesis) {
            _ = try misdirected.accept(membership: records, grants: grants, as: guest.keyset, continuing: nil)
        }
    }

    @Test("the invitation descriptor has one fixed encoding")
    func invitationEncoding() throws {
        let invitation = Invitation(vaultID: UUID(), ownerAccountID: UUID())
        let bytes = invitation.encoded()
        #expect(bytes.count == Invitation.encodedLength)
        #expect(try Invitation.parse(bytes) == invitation)
        for length in 0..<bytes.count {
            #expect(throws: SharingFormatError.self) { _ = try Invitation.parse(Array(bytes[0..<length])) }
        }
        #expect(throws: SharingFormatError.tooLarge(bytes.count + 1)) { _ = try Invitation.parse(bytes + [0]) }
        var wrongMagic = bytes
        wrongMagic[0] ^= 1
        #expect(throws: SharingFormatError.badMagic) { _ = try Invitation.parse(wrongMagic) }
    }
}
