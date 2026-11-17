import Foundation
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordTestSupport

@testable import WatchwordSharing

/// Milestone 4 adversarial obligations (docs/04-test-plan.md §6.4), against the sharing protocol core with real keys.
/// The adversaries are those of docs/02-architecture.md §2: the sync store and key directory (A1), a current member
/// of the vault (A4), a former member (A5), and someone who can write this device's files (A8). Each test says which,
/// and with what access.
@Suite("Adversarial: sharing and membership", .tags(.adversarial))
struct AdversarialSharingTests {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)

    static func trusted(_ party: SharingParty) -> VerifiedContact {
        VerifiedContact(bundle: party.bundle, method: .comparedByEye, verifiedAt: nil)
    }

    /// A device that has seen nothing yet and is offered `records`.
    static func freshDevice(_ household: SharingHousehold, _ records: [[UInt8]]) throws -> MembershipLedger {
        try MembershipLedger.join(
            vaultID: household.vaultID, owner: trusted(household.owner), candidates: records
        ).ledger
    }

    /// A rotation by `signer` on `ledger`'s head whose record hashes below `target`: what someone who wants to win a
    /// hash comparison would grind for.
    static func groundRotation(
        below target: MembershipHash, on ledger: MembershipLedger, by signer: SharingParty, seed: UInt64
    ) throws -> RotationPlan {
        var generator = SeededGenerator(seed: seed)
        for _ in 0..<2_000 {
            let plan = try RotationPlanner.plan(.routine, ledger: ledger, signedBy: signer.keyset, using: &generator)
            if plan.recordHash < target { return plan }
        }
        throw MembershipError.signatureInvalid
    }

    // MARK: - Forged membership records

    /// A1, with write access to the store: alters a genuine membership record that members have not seen yet, one
    /// bit at a time, hoping some altered form is accepted with a different meaning.
    @Test("flipping any bit of a genuine membership record gets it refused; the genuine record is then accepted")
    func everyBitFlip() async throws {
        let household = try await SharingHousehold.make()
        let guest = try SharingParty(seed: 40)
        let genuine = try household.ledger.proposeAddition(
            of: await household.contact(guest), as: .readWrite, signedBy: household.administrator.keyset
        ).encoded()
        var ledger = household.ledger
        for position in genuine.indices {
            for mask: UInt8 in [0x01, 0x80] {
                var mutated = genuine
                mutated[position] ^= mask
                let report = ledger.ingest([mutated])
                #expect(report.rejected.count == 1, "flip \(mask) at byte \(position)")
                #expect(ledger.state == household.state, "flip \(mask) at byte \(position)")
            }
        }
        #expect(ledger.ingest([genuine]).adopted.count == 1)
        #expect(ledger.state.member(guest.accountID)?.role == .readWrite)
    }

    /// A1, with write access to the store and keys of its own: writes membership records that are unsigned, signed
    /// with its own key under an administrator's name, or signed by an account that was never a member.
    @Test("a membership record not signed by an administrator of the previous state is refused")
    func forgedRecords() async throws {
        let household = try await SharingHousehold.make()
        let attacker = household.outsider
        var ledger = household.ledger
        let addsAttacker = household.forgery(
            .addMember(attacker.accountID, role: .readWrite), signer: household.owner, adding: attacker.bundle)
        let asThemselves = household.forgery(
            .addMember(attacker.accountID, role: .readWrite), signer: attacker, adding: attacker.bundle)
        let report = ledger.ingest([
            addsAttacker.withSignature([UInt8](repeating: 0, count: 64)),
            try addsAttacker.signed(by: attacker.keyset),
            try asThemselves.signed(by: attacker.keyset),
            addsAttacker.content,
        ])
        #expect(
            report.rejected.map(\.reason) == [
                .invalid(.signatureInvalid), .invalid(.signatureInvalid),
                .invalid(.signerNotAMember(attacker.accountID)), .malformed(.truncated),
            ])
        #expect(ledger.state == household.state)
    }

    /// A1, towards someone accepting an invitation: offers a genesis for the vault signed by a key of its own, under
    /// the real owner's account ID or under an account of its own, so that the chain the invitee builds is the
    /// attacker's.
    @Test("a genesis that the verified owner did not sign founds nothing")
    func forgedGenesis() async throws {
        let household = try await SharingHousehold.make()
        let attacker = household.outsider
        let impostor = try SharingParty(accountID: household.owner.accountID, seed: 41)
        let ownGenesis = ForgedRecord(genesisOf: household.vaultID, owner: attacker.bundle, vaultKeyID: UUID())
        let impostorGenesis = ForgedRecord(genesisOf: household.vaultID, owner: impostor.bundle, vaultKeyID: UUID())
        var realOwnerAttackerKey = ForgedRecord(
            genesisOf: household.vaultID, owner: household.owner.bundle, vaultKeyID: UUID())
        realOwnerAttackerKey.entries[0].agreementKey = attacker.bundle.agreementKey

        let unsignedByOwner = ForgedRecord(
            genesisOf: household.vaultID, owner: household.owner.bundle, vaultKeyID: UUID())

        let forged = [
            try ownGenesis.signed(by: attacker.keyset), try impostorGenesis.signed(by: impostor.keyset),
            try realOwnerAttackerKey.signed(by: attacker.keyset), try unsignedByOwner.signed(by: attacker.keyset),
        ]
        #expect(throws: LedgerError.noGenesis) { _ = try Self.freshDevice(household, forged) }

        // Beside the real chain, they are reported and ignored.
        let genuine = household.ledger.chain.map(\.encoded)
        let (ledger, report) = try MembershipLedger.join(
            vaultID: household.vaultID, owner: Self.trusted(household.owner), candidates: forged + genuine)
        #expect(ledger.state == household.state)
        #expect(
            report.rejected.map(\.reason) == [
                .invalid(.ownerMismatch), .invalid(.ownerMismatch), .invalid(.ownerMismatch),
                .invalid(.signatureInvalid),
            ])
    }

    /// A1: serves a copy of the next genuine record with its signature spoilt, listed ahead of the genuine one. The
    /// two have the same hash (the hash leaves the signature out), so a ledger that kept one candidate per hash would
    /// examine the spoilt copy, refuse it, and never look at the real record (review finding S4).
    @Test("a copy of a record with a spoilt signature does not shadow the genuine record")
    func shadowCopy() async throws {
        let household = try await SharingHousehold.make()
        let genuine = try household.ledger.proposeRoleChange(
            of: household.reader.accountID, to: .readWrite, signedBy: household.owner.keyset
        ).encoded()
        var spoilt = genuine
        spoilt[spoilt.count - 1] ^= 1
        var ledger = household.ledger
        let report = ledger.ingest([spoilt, genuine, spoilt])
        #expect(ledger.state.member(household.reader.accountID)?.role == .readWrite)
        #expect(report.rejected.map(\.index) == [0])
        #expect(report.rejected.map(\.reason) == [.invalid(.signatureInvalid)])

        // And once the genuine record is held, the spoilt copy is just a copy.
        #expect(ledger.ingest([spoilt]).rejected.isEmpty)
    }

    /// A4, a member with their account key: tries to pass one kind of signature off as another, a signature they
    /// can make legitimately (over a log segment, a key grant, their own leave request) as the signature on a
    /// membership record.
    @Test("a signature made for another purpose does not sign a membership record")
    func signatureDomains() async throws {
        let household = try await SharingHousehold.make()
        let admin = household.administrator
        let forged = household.forgery(.rotateKey, signer: admin, newKeyID: UUID())
        var ledger = household.ledger
        for domain in SignatureDomain.allCases where domain != .membership {
            let signature = try admin.keyset.sign(forged.content, domain: domain)
            let report = ledger.ingest([forged.withSignature(signature)])
            #expect(report.rejected.map(\.reason) == [.invalid(.signatureInvalid)], "domain \(domain)")
        }
        // Their own leave request, signed under the membership domain, is not a membership record either.
        let request = try LeaveRequest.make(leaving: household.state, as: household.writer.keyset)
        #expect(throws: SharingFormatError.badMagic) { _ = try MembershipRecord.parse(request.encoded()) }
        #expect(throws: SharingFormatError.badMagic) {
            _ = try LeaveRequest.parse(Array(forged.content.prefix(LeaveRequest.encodedLength)))
        }
        #expect(ledger.state == household.state)
    }

    // MARK: - Stale administrators and former members

    /// A5, a former administrator who kept their account key and can still write to the store: signs new membership
    /// records after the owner demoted or removed them.
    @Test("an administrator's signature stops counting at the record that demotes or removes them")
    func staleAdministratorSignsOn() async throws {
        var household = try await SharingHousehold.make()
        let former = household.administrator

        try household.adopt(
            household.ledger.proposeRoleChange(
                of: former.accountID, to: .readWrite, signedBy: household.owner.keyset
            ).encoded())
        var ledger = household.ledger
        var report = ledger.ingest([
            try household.forgery(.rotateKey, signer: former, newKeyID: UUID()).signed(by: former.keyset)
        ])
        #expect(report.rejected.map(\.reason) == [.invalid(.signerNotAdministrator(former.accountID))])
        #expect(throws: SharingError.notPermitted) {
            _ = try RotationPlanner.plan(.routine, ledger: household.ledger, signedBy: former.keyset)
        }

        try household.rotate(.removal(former.accountID), by: household.owner)
        ledger = household.ledger
        report = ledger.ingest([
            try household.forgery(.rotateKey, signer: former, newKeyID: UUID()).signed(by: former.keyset),
            try household.forgery(
                .addMember(former.accountID, role: .administrator), signer: former, adding: former.bundle
            ).signed(by: former.keyset),
        ])
        #expect(
            report.rejected.map(\.reason) == [
                .invalid(.signerNotAMember(former.accountID)), .invalid(.signerNotAMember(former.accountID)),
            ])
        #expect(ledger.state == household.state)
    }

    /// A5, a former administrator with their key and store write access, possibly with the store's help (A1): goes
    /// back to an epoch at which they still were an administrator and publishes a competing record there, ground
    /// until its hash is lower than the accepted one's, to reorganise the chain past their own removal and be a
    /// member again (review finding S1).
    @Test("a former administrator cannot rewrite history from before their removal, on any device, in any order")
    func staleAdministratorRewritesHistory() async throws {
        var household = try await SharingHousehold.make()
        let former = household.administrator
        let second = try SharingParty(seed: 42)
        try await household.add(second, as: .administrator, by: household.owner)
        let forkPoint = household.ledger

        // The chain goes on: another administrator acts, then the owner removes the former administrator.
        try household.adopt(
            household.ledger.proposeRoleChange(
                of: household.reader.accountID, to: .readWrite, signedBy: second.keyset
            ).encoded())
        let overwritten = household.state.hash
        try household.rotate(.removal(former.accountID), by: household.owner)
        try household.rotate(.routine, by: second)
        #expect(household.state.member(former.accountID) == nil)

        // The attack: a record of the former administrator's at the fork point with a lower hash than the one
        // every device accepted there, and a branch built on it.
        let rewrite = try Self.groundRotation(below: overwritten, on: forkPoint, by: former, seed: 43)
        var branch = forkPoint
        branch.ingest([rewrite.record.contents])
        let further = try RotationPlanner.plan(.routine, ledger: branch, signedBy: former.keyset)
        let attack = [rewrite.record.contents, further.record.contents]

        // A device that has the real chain is not moved.
        var informed = household.ledger
        let report = informed.ingest(attack)
        #expect(informed.state == household.state)
        #expect(!report.changedHead)
        #expect(report.outranked.count == 2)

        // A device meeting everything at once, in either order, lands on the real chain.
        let genuine = household.ledger.chain.map(\.encoded)
        #expect(try Self.freshDevice(household, attack + genuine).state == household.state)
        #expect(try Self.freshDevice(household, genuine + attack).state == household.state)

        // A device the store showed only the attacker's branch follows it (it cannot know better: until it sees the
        // removal, the former administrator is one), and comes back the moment the owner's record arrives.
        var misled = forkPoint
        misled.ingest(attack)
        #expect(misled.state.member(former.accountID) != nil)
        let correction = misled.ingest(genuine)
        #expect(misled.state == household.state)
        #expect(correction.superseded.count == 2)
    }

    /// A5, a former member (ordinary or administrator) with their key and store write access: adds themselves back,
    /// by a new record of their own or by replaying the genuine records that once added them.
    @Test("a former member cannot add themselves back")
    func formerMemberReAddsThemselves() async throws {
        var household = try await SharingHousehold.make()
        let former = household.writer
        let originalAddition = household.ledger.chain[2].encoded
        try household.rotate(.removal(former.accountID), by: household.administrator)

        let relinked = ForgedRecord(
            after: household.state, signer: household.owner.accountID,
            operation: .addMember(former.accountID, role: .readWrite), adding: former.bundle)
        var ledger = household.ledger
        let attempts: [[UInt8]] = [
            try household.forgery(
                .addMember(former.accountID, role: .readWrite), signer: former, adding: former.bundle
            ).signed(by: former.keyset),
            // The owner's old signature, from the record that first added them, under a record for the new head.
            relinked.withSignature(household.ledger.chain[2].record.signature),
            // And that old record itself, as it was.
            originalAddition,
        ]
        let report = ledger.ingest(attempts)
        #expect(
            report.rejected.map(\.reason) == [
                .invalid(.signerNotAMember(former.accountID)), .invalid(.signatureInvalid),
            ])
        #expect(ledger.state == household.state, "the original addition is a record already in the chain")
        #expect(ledger.state.member(former.accountID) == nil)
        #expect(ledger.writePermission(for: former.accountID, atEpoch: ledger.state.epoch) == .refused(.notAMember))
    }

    // MARK: - Key substitution

    /// A1, running the key directory: answers a lookup of the invitee with a bundle of its own under the invitee's
    /// account ID (valid self-signature and all), so that the vault key would be wrapped to the attacker.
    @Test("a substituted invitee key is caught by the fingerprint comparison, and nothing is wrapped to it")
    func substitutedInviteeKey() async throws {
        let world = SharingWorld()
        var owner = try await world.member("owner", seed: 1)
        let invitee = try await world.member("invitee", seed: 2)
        let vault = try await owner.createVault()
        let attacker = try SharingParty(accountID: invitee.accountID, seed: 44)
        await world.directory.tamper(invitee.accountID, contents: KeyBundleCodec.encode(attacker.bundle))
        let objectsBefore = await world.store.allObjects.count

        await #expect(throws: SharingError.fingerprintMismatch) {
            try await owner.invite(invitee.accountID, to: vault, as: .readWrite, safetyNumber: invitee.safetyNumber)
        }
        var invitation = try await OutgoingInvitation.begin(
            vaultID: vault, inviting: invitee.accountID, as: .readWrite, directory: world.directory,
            contacts: owner.contacts)
        #expect(throws: SharingError.fingerprintNotVerified) {
            _ = try invitation.issue(
                ledger: owner.ledger(vault), vaultKey: owner.currentKey(vault), signedBy: owner.keyset)
        }
        #expect(await world.store.allObjects.count == objectsBefore, "no record and no grant were produced")
        #expect(try owner.ledger(vault).state.members.count == 1)
        #expect(try await owner.contacts.pinned(invitee.accountID) == nil)
    }

    /// A1, running the key directory, after two people have verified each other: replaces a pinned contact's
    /// published bundle with its own, to be used the next time that contact is invited to a vault.
    @Test("a key substituted after verification is refused and reported, not silently adopted")
    func substitutionAfterPinning() async throws {
        let world = SharingWorld()
        var (_, owner, members) = try await world.household(roles: [.readWrite])
        let friend = members[0]
        let attacker = try SharingParty(accountID: friend.accountID, seed: 45)
        await world.directory.tamper(friend.accountID, contents: KeyBundleCodec.encode(attacker.bundle))

        let second = try await owner.createVault()
        await #expect(throws: SharingError.keySubstituted(accountID: friend.accountID)) {
            try await owner.invite(friend.accountID, to: second, as: .readWrite, safetyNumber: friend.safetyNumber)
        }
        #expect(try owner.ledger(second).state.members.count == 1)
        #expect(try await owner.contacts.pinned(friend.accountID)?.bundle == friend.bundle)

        // Bundles the directory has no business returning at all.
        await world.directory.tamper(friend.accountID, contents: KeyBundleCodec.encode(owner.bundle))
        await #expect(throws: SharingError.directoryMismatch(asked: friend.accountID, returned: owner.accountID)) {
            _ = try await world.directory.candidateBundle(for: friend.accountID)
        }
        var lowOrder = KeyBundleCodec.encode(friend.bundle)
        lowOrder.replaceSubrange(21..<53, with: [UInt8](repeating: 0, count: 32))
        await world.directory.tamper(friend.accountID, contents: lowOrder)
        await #expect(throws: CryptoError.invalidPublicKey) {
            _ = try await world.directory.candidateBundle(for: friend.accountID)
        }
    }

    /// A1, running the key directory and the store, towards an invitee: publishes its own bundle as the owner's and
    /// offers a chain and a grant of its own making, so that the invitee joins the attacker's vault believing it the
    /// owner's.
    @Test("a substituted owner key is caught by the invitee's fingerprint comparison before anything is accepted")
    func substitutedOwnerKey() async throws {
        let world = SharingWorld()
        var owner = try await world.member("owner", seed: 1)
        var invitee = try await world.member("invitee", seed: 2)
        let vault = try await owner.createVault()
        let invitation = try await owner.invite(
            invitee.accountID, to: vault, as: .readWrite, safetyNumber: invitee.safetyNumber)

        let attacker = try SharingParty(accountID: owner.accountID, seed: 46)
        await world.directory.tamper(owner.accountID, contents: KeyBundleCodec.encode(attacker.bundle))
        await #expect(throws: SharingError.fingerprintMismatch) {
            try await invitee.accept(invitation, ownerSafetyNumber: owner.safetyNumber)
        }
        #expect(invitee.ledgers[vault] == nil && invitee.keys[vault] == nil)
        #expect(try await invitee.contacts.pinned(owner.accountID) == nil)

        // With the real bundle back, the same invitation goes through.
        await world.directory.publish(owner.bundle)
        try await invitee.accept(invitation, ownerSafetyNumber: owner.safetyNumber)
        #expect(try invitee.currentKey(vault).key.keyID == owner.currentKey(vault).key.keyID)
    }

    /// A4, a malicious administrator: adds the invitee's account to the chain with a key bundle of the
    /// administrator's own making, to read what is later wrapped to "the invitee", or to act as them.
    @Test("an invitee whose key was swapped in the chain refuses to join")
    func swappedKeyInChain() async throws {
        var household = try await SharingHousehold.make()
        let guest = try SharingParty(seed: 47)
        let swapped = try SharingParty(accountID: guest.accountID, seed: 48)
        try household.adopt(
            household.forgery(
                .addMember(guest.accountID, role: .readWrite), signer: household.administrator,
                adding: swapped.bundle
            ).signed(by: household.administrator.keyset))
        let grant = try household.ledger.makeGrant(
            of: household.vaultKey, to: guest.accountID, from: household.administrator.keyset)

        let contacts = VerifiedContacts(store: InMemoryVerifiedContactStore(), account: guest.bundle)
        let directory = InMemoryKeyBundleDirectory()
        await directory.publish(household.owner.bundle)
        var incoming = try await IncomingInvitation.begin(
            Invitation(vaultID: household.vaultID, ownerAccountID: household.owner.accountID), knownOwner: nil,
            directory: directory, contacts: contacts)
        try await incoming.confirm(.comparedByEye, contacts: contacts, signedBy: guest.keyset, at: Self.now)
        #expect(throws: SharingError.ownKeySubstituted) {
            _ = try incoming.accept(
                membership: household.ledger.chain.map(\.encoded),
                grants: [(name: grant.location.name, contents: grant.encoded)], as: guest.keyset, continuing: nil)
        }
        #expect(throws: CryptoError.grantMismatch, "and the grant is not addressed to their real key") {
            _ = try household.ledger.openGrant(grant.encoded, at: grant.location, as: guest.keyset)
        }
    }

    /// A4, someone the victim knows and has verified: invites the victim to a "new" vault whose ID is that of a
    /// vault the victim already holds (their own, or another owner's), so that the victim's device files the
    /// attacker's chain and key under that vault (review finding S6).
    @Test("an invitation to a vault ID already held under another owner is refused")
    func vaultIDCollision() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.readWrite])
        var victim = members[0]
        let attacker = try await world.member("attacker", seed: 49)
        _ = try await victim.contacts.verify(
            attacker.bundle, evidence: .comparedByEye, signedBy: victim.keyset, at: Self.now)

        let before = try victim.ledger(vault).state
        await #expect(throws: SharingError.vaultOwnerConflict(vaultID: vault)) {
            try await victim.accept(
                Invitation(vaultID: vault, ownerAccountID: attacker.accountID),
                ownerSafetyNumber: attacker.safetyNumber)
        }
        #expect(try victim.ledger(vault).state == before)
        #expect(try victim.ledger(vault).owner == owner.bundle)

        // The owner's own vault, the same way.
        let mine = try await owner.createVault()
        await #expect(throws: SharingError.vaultOwnerConflict(vaultID: mine)) {
            try await owner.accept(
                Invitation(vaultID: mine, ownerAccountID: attacker.accountID),
                ownerSafetyNumber: attacker.safetyNumber)
        }
    }

    // MARK: - Keys and grants after revocation

    /// A5, a former member holding the vault key of their time and every ciphertext the store has: tries the old key
    /// on records written after their removal.
    @Test("the key a former member holds opens nothing sealed after the rotation")
    func oldKeyAfterRotation() async throws {
        var household = try await SharingHousehold.make()
        let oldKey = household.vaultKey
        try household.rotate(.removal(household.writer.accountID), by: household.owner)
        let newKey = household.vaultKey
        #expect(newKey.key.keyID != oldKey.key.keyID)
        #expect(!newKey.key.material.constantTimeEquals(oldKey.key.material))

        var generator = SeededGenerator(seed: 50)
        let context = EnvelopeContext(
            recordID: UUID(), vaultID: household.vaultID, schemaVersion: 1, kind: .item, keyID: newKey.key.keyID,
            recordVersion: 1)
        let sealed = try RecordCipher.seal(Array("after".utf8), context: context, key: newKey.key, using: &generator)
        #expect(throws: CryptoError.keyMismatch(expected: oldKey.key.keyID, actual: newKey.key.keyID)) {
            _ = try RecordCipher.open(sealed, context: context, key: oldKey.key)
        }
        // Even claiming their old key has the new key's ID.
        let relabelled = try EncryptionKey(keyID: newKey.key.keyID, material: oldKey.key.material)
        #expect(throws: CryptoError.authenticationFailed) {
            _ = try RecordCipher.open(sealed, context: context, key: relabelled)
        }
    }

    /// A5, a former member with their keyset, the grants of their time and store write access: replays an old grant
    /// where the new key's grants live, asks for a grant of the new key, or (a former administrator) wraps a key of
    /// their own choosing to a remaining member under the new key's ID, so that member seals to a key they know.
    @Test("old grants, and new grants from someone no longer entitled, are refused")
    func grantsAfterRevocation() async throws {
        var household = try await SharingHousehold.make()
        let former = household.administrator
        let victim = household.writer
        let oldKey = household.vaultKey
        let firstRotation = try household.rotate(.routine, by: former)
        let oldGrant = try #require(
            firstRotation.grants.first {
                if case .grant(_, let recipient, _) = $0.location.kind { return recipient == victim.accountID }
                return false
            })
        let secondRotation = try household.rotate(.removal(former.accountID), by: household.owner)
        let newKeyID = secondRotation.newKeyID

        // The former administrator's own grant of the earlier key, replayed under the new key's name.
        let replayed = SharingObjectLocation.grant(
            vaultID: household.vaultID, keyID: newKeyID, recipient: victim.accountID, contents: oldGrant.contents)
        #expect(throws: CryptoError.grantMismatch) {
            _ = try household.ledger.openGrant(oldGrant.contents, at: replayed, as: victim.keyset)
        }

        // A fresh grant of a key the attacker knows, labelled as the new key.
        let planted = VaultKey(
            vaultID: household.vaultID, key: try EncryptionKey(keyID: newKeyID, material: oldKey.key.material))
        let forged = try VaultKeyGrant.seal(planted, to: victim.bundle, from: former.keyset)
        let forgedBytes = try KeyGrantCodec.encode(forged)
        let forgedLocation = SharingObjectLocation.grant(
            vaultID: household.vaultID, keyID: newKeyID, recipient: victim.accountID, contents: forgedBytes)
        #expect(throws: CryptoError.grantMismatch, "the chain entitles the owner, who rotated, and nobody else") {
            _ = try household.ledger.openGrant(forgedBytes, at: forgedLocation, as: victim.keyset)
        }
        #expect(throws: SharingError.notPermitted) {
            _ = try household.ledger.makeGrant(of: planted, to: victim.accountID, from: former.keyset)
        }

        // Junk beside the genuine grant does not hide it, and the member ends with the real key.
        let listing =
            [(name: replayed.name, contents: oldGrant.contents), (name: forgedLocation.name, contents: forgedBytes)]
            + secondRotation.grants.map { (name: $0.name, contents: $0.contents) }
        let opened = try household.ledger.openGrant(of: newKeyID, from: listing, as: victim.keyset)
        #expect(opened.key.material.constantTimeEquals(household.vaultKey.key.material))

        // Nobody is entitled to grant the new key to the former member.
        #expect(throws: SharingError.notEntitledToKey(former.accountID)) {
            _ = try household.ledger.openGrant(of: newKeyID, from: listing, as: former.keyset)
        }
        #expect(throws: SharingError.notEntitledToKey(former.accountID)) {
            _ = try household.ledger.makeGrant(
                of: household.vaultKey, to: former.accountID, from: household.owner.keyset)
        }
    }

    /// A4, a member with write access to the store: fills the vault's grant directory with objects for other keys
    /// and other recipients, and the victim's own grant directory with objects that are filed correctly and are
    /// not their grant, more than any bound a reader might put on what it examines, so that a newly invited member
    /// never reaches their own grant (review findings S10 and S24).
    @Test("a flood of grant objects, for other keys and members or filed as the member's own, does not hide the grant")
    func grantFlood() async throws {
        var household = try await SharingHousehold.make()
        let plan = try household.rotate(.routine, by: household.owner)
        let victim = household.writer
        let elsewhere = (0..<5_000).map { index -> (name: String, contents: [UInt8]) in
            let contents = [UInt8(truncatingIfNeeded: index), UInt8(truncatingIfNeeded: index >> 8)]
            let location = SharingObjectLocation.grant(
                vaultID: household.vaultID, keyID: index.isMultiple(of: 2) ? plan.newKeyID : UUID(),
                recipient: index.isMultiple(of: 2) ? household.outsider.accountID : victim.accountID,
                contents: contents)
            return (location.name, contents)
        }
        // Filed exactly where the victim's grant belongs, under their own digests: somebody else's genuine grant,
        // and grants of the right shape that nobody entitled signed.
        let others = plan.grants.filter {
            if case .grant(_, let recipient, _) = $0.location.kind { return recipient != victim.accountID }
            return false
        }
        var generator = SeededGenerator(seed: 52)
        let planted = VaultKey.generate(vaultID: household.vaultID, using: &generator)
        let forged = try KeyGrantCodec.encode(
            VaultKeyGrant.seal(
                VaultKey(
                    vaultID: household.vaultID,
                    key: try EncryptionKey(keyID: plan.newKeyID, material: planted.key.material)),
                to: victim.bundle, from: household.reader.keyset))
        let inPlace =
            ((0..<400).map { index -> [UInt8] in
                var junk = forged
                junk[junk.count - 1 - index % 64] ^= UInt8(truncatingIfNeeded: index / 64 + 1)
                return junk
            } + others.map(\.contents) + [forged]).map { contents -> (name: String, contents: [UInt8]) in
                let location = SharingObjectLocation.grant(
                    vaultID: household.vaultID, keyID: plan.newKeyID, recipient: victim.accountID, contents: contents)
                return (location.name, contents)
            }
        let listing = elsewhere + inPlace + plan.grants.map { (name: $0.name, contents: $0.contents) }
        let key = try household.ledger.openGrant(of: plan.newKeyID, from: listing, as: victim.keyset)
        #expect(key.key.material.constantTimeEquals(household.vaultKey.key.material))
        #expect(!key.key.material.constantTimeEquals(planted.key.material))
        #expect(throws: SharingError.grantNotFound) {
            _ = try household.ledger.openGrant(of: plan.newKeyID, from: elsewhere + inPlace, as: victim.keyset)
        }
    }

    /// A4, an administrator who was demoted to an ordinary member (so no rotation happened, and the key is one they
    /// introduced): wraps a key of their choosing to a member added after their demotion. "An administrator when
    /// the key was introduced" would still describe them (review finding S5).
    @Test("a demoted administrator cannot grant the key they introduced to a member added since")
    func demotedAdministratorGrants() async throws {
        var household = try await SharingHousehold.make()
        let demoted = household.administrator
        try household.rotate(.routine, by: demoted)
        try household.adopt(
            household.ledger.proposeRoleChange(
                of: demoted.accountID, to: .readWrite, signedBy: household.owner.keyset
            ).encoded())
        let newcomer = try SharingParty(seed: 51)
        try await household.add(newcomer, as: .readWrite, by: household.owner)

        let keyID = household.state.vaultKeyID
        #expect(household.ledger.keyEpoch(of: keyID) == 4)
        #expect(
            try household.ledger.grantSender(forKey: keyID, to: newcomer.accountID).accountID
                == household.owner.accountID)
        let planted = VaultKey(
            vaultID: household.vaultID,
            key: try EncryptionKey(keyID: keyID, material: household.vaultKey.key.material))
        let forged = try KeyGrantCodec.encode(VaultKeyGrant.seal(planted, to: newcomer.bundle, from: demoted.keyset))
        let location = SharingObjectLocation.grant(
            vaultID: household.vaultID, keyID: keyID, recipient: newcomer.accountID, contents: forged)
        #expect(throws: CryptoError.grantMismatch) {
            _ = try household.ledger.openGrant(forged, at: location, as: newcomer.keyset)
        }
    }

    /// A4, an administrator of one vault who is an ordinary member of another: files a grant under the other vault,
    /// a genuine one from their own vault or a fresh one labelled with the other vault's ID and key, to plant a key
    /// they know there.
    @Test("a grant from an administrator of another vault is refused, however it is labelled or filed")
    func crossVaultGrants() async throws {
        var mine = try await SharingHousehold.make(seed: 1)
        // The attacker administers their own vault and is the read-write member of the victim's.
        let attacker = mine.writer
        let victim = mine.reader
        var generator = SeededGenerator(seed: 52)
        let theirKey = VaultKey.generate(vaultID: UUID(), using: &generator)
        var theirs = try MembershipLedger.create(vaultKey: theirKey, owner: attacker.keyset)
        let victimContact = VerifiedContact(bundle: victim.bundle, method: .comparedByEye, verifiedAt: nil)
        theirs.ingest([
            try theirs.proposeAddition(of: victimContact, as: .readWrite, signedBy: attacker.keyset).encoded()
        ])
        let genuine = try theirs.makeGrant(of: theirKey, to: victim.accountID, from: attacker.keyset)
        #expect(
            try theirs.openGrant(genuine.encoded, at: genuine.location, as: victim.keyset).vaultID == theirKey.vaultID)

        let targetKeyID = try mine.rotate(.routine, by: mine.owner).newKeyID

        // Their genuine grant, moved under the victim vault's name.
        let moved = SharingObjectLocation.grant(
            vaultID: mine.vaultID, keyID: targetKeyID, recipient: victim.accountID, contents: genuine.encoded)
        #expect(throws: CryptoError.grantMismatch) {
            _ = try mine.ledger.openGrant(genuine.encoded, at: moved, as: victim.keyset)
        }
        #expect(throws: SharingError.grantMisfiled, "and their own ledger will not open it from there") {
            _ = try theirs.openGrant(genuine.encoded, at: moved, as: victim.keyset)
        }

        // A fresh grant labelled with the victim vault and its current key ID, carrying a key the attacker knows.
        let planted = VaultKey(
            vaultID: mine.vaultID, key: try EncryptionKey(keyID: targetKeyID, material: theirKey.key.material))
        let forged = try KeyGrantCodec.encode(VaultKeyGrant.seal(planted, to: victim.bundle, from: attacker.keyset))
        let location = SharingObjectLocation.grant(
            vaultID: mine.vaultID, keyID: targetKeyID, recipient: victim.accountID, contents: forged)
        #expect(throws: CryptoError.grantMismatch) {
            _ = try mine.ledger.openGrant(forged, at: location, as: victim.keyset)
        }
        #expect(throws: SharingError.grantNotFound) {
            _ = try mine.ledger.openGrant(
                of: targetKeyID, from: [(name: location.name, contents: forged)], as: victim.keyset)
        }
    }

    // MARK: - Writes

    /// A5, a former member with the old vault key, their account key and a store that still takes their writes
    /// (a shared folder, or a store that ignores its own share list); and A4, a read-only member doing the same.
    /// Every remaining member here has seen the removal; `writeAfterUnseenRemoval` is the device that has not.
    @Test("writes by a former member or a read-only member reach the store and count for no remaining member")
    func postRevocationWrites() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.readWrite, .readWrite, .readOnly])
        var remaining = members[0]
        var former = members[1]
        var readOnly = members[2]
        try await former.sync(vault)
        try await readOnly.sync(vault)
        let record = UUID()
        try await owner.write("genuine", to: vault, recordID: record, version: 1)
        let oldKey = try former.currentKey(vault)

        try await owner.remove(former.accountID, from: vault)
        try await remaining.sync(vault)
        try await readOnly.sync(vault)

        // The store honours nothing: both writes land.
        try await former.write("overwritten", to: vault, recordID: record, version: 99, under: oldKey)
        try await former.write("planted", to: vault, recordID: UUID(), version: 1, under: oldKey)
        try await readOnly.write(
            "not allowed", to: vault, recordID: record, version: 100, under: readOnly.currentKey(vault))

        for reader in [owner, remaining, readOnly] {
            let items = try await reader.items(in: vault)
            #expect(items.filter { $0.author == former.accountID }.allSatisfy { $0.outcome == .refused(.notAMember) })
            #expect(
                items.filter { $0.author == readOnly.accountID }.allSatisfy { $0.outcome == .refused(.readOnly) })
            #expect(try await reader.readable(in: vault) == [record: "genuine"], "\(reader.name)")
        }

        // A store that does honour its share list refuses the former member outright (F4.3a).
        await world.store.setEnforcesShareMembership(true)
        await #expect(throws: SharingSimulationError.forbidden(former.accountID)) {
            try await former.write("again", to: vault, recordID: UUID(), version: 1, under: oldKey)
        }
    }

    /// A5 and A1 together: a former member with the old vault key and their account key, and a store that still
    /// takes their writes and withholds the removal record from one remaining member's device. That device merges
    /// the write, because in its ledger the author is still a member. If writes were judged only when merged, and
    /// what was merged stayed merged, the device would go on to seal the write again under its own name once it
    /// learned of the removal, and every other member would accept it (review finding S28).
    @Test("a write made after a removal counts for nobody, not even through a device that merged it before it knew")
    func writeAfterUnseenRemoval() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.readWrite, .readWrite])
        var device = members[0]
        var former = members[1]
        try await device.sync(vault)
        try await former.sync(vault)
        let record = UUID()
        try await former.write("theirs", to: vault, recordID: record, version: 1)
        let oldKey = try former.currentKey(vault)
        #expect(try await owner.remove(former.accountID, from: vault) == .complete)
        let removal = SharingObjectLocation.membership(try #require(try owner.ledger(vault).chain.last).record).name
        await world.store.hide([removal], from: device.accountID)

        try await former.write("planted", to: vault, recordID: record, version: 50, under: oldKey)
        let elsewhere = UUID()
        try await former.write("planted too", to: vault, recordID: elsewhere, version: 1, under: oldKey)
        try await device.maintain(vault)
        #expect(
            try await device.readable(in: vault) == [record: "planted", elsewhere: "planted too"],
            "nothing this device has seen says the author may not write")

        // The device learns of the removal. The record says which of the member's writes count, and these are not
        // among them, whenever and wherever they were merged.
        await world.store.reveal(to: device.accountID)
        try await device.maintain(vault)
        try await owner.maintain(vault)
        try await device.maintain(vault)
        var newcomer = try await world.member("newcomer", seed: 902)
        let invitation = try await owner.invite(
            newcomer.accountID, to: vault, as: .readWrite, safetyNumber: newcomer.safetyNumber)
        try await newcomer.accept(invitation, ownerSafetyNumber: owner.safetyNumber)
        for reader in [owner, device, newcomer] {
            #expect(try await reader.readable(in: vault) == [record: "theirs"], "\(reader.name)")
            let planted = try await reader.items(in: vault).filter {
                $0.author == former.accountID && !($0.recordID == record && $0.version == 1)
            }
            #expect(planted.count == 2 && planted.allSatisfy { $0.outcome == .refused(.notAMember) })
        }
        let afterwards = await world.store.allObjects.keys.filter { $0.hasSuffix(device.accountID.uuidString) }
        #expect(afterwards.isEmpty, "the device published nothing of it under its own name")

        // Not destroyed either: the device holds what it had merged aside, for its person to look at.
        #expect(
            try await device.setAside(in: vault)
                == [
                    SetAsideItem(
                        recordID: elsewhere, version: 1, origin: former.accountID, text: "planted too",
                        refusal: .notAMember),
                    SetAsideItem(
                        recordID: record, version: 50, origin: former.accountID, text: "planted", refusal: .notAMember),
                ].sorted { $0.recordID.uuidString < $1.recordID.uuidString })
    }

    /// A4 and A1 together: a member made read-only, whose client is not the honest one, and a store that withholds
    /// the demotion from another member's device. A demotion has no transport step and rotates nothing, so the
    /// member's later writes are sealed under the current key and reach everyone.
    @Test("a write made after a demotion counts for nobody, not even through a device that merged it before it knew")
    func writeAfterUnseenDemotion() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.readWrite, .readWrite])
        var device = members[0]
        var demoted = members[1]
        try await device.sync(vault)
        try await demoted.sync(vault)
        let record = UUID()
        try await demoted.write("before", to: vault, recordID: record, version: 1)
        try await owner.changeRole(of: demoted.accountID, to: .readOnly, in: vault)
        let demotion = SharingObjectLocation.membership(try #require(try owner.ledger(vault).chain.last).record).name
        await world.store.hide([demotion], from: device.accountID)

        try await demoted.write("after", to: vault, recordID: record, version: 2, under: demoted.currentKey(vault))
        try await device.maintain(vault)
        #expect(try await device.readable(in: vault) == [record: "after"])

        await world.store.reveal(to: device.accountID)
        try await device.maintain(vault)
        try await owner.maintain(vault)
        for reader in [owner, device] {
            #expect(try await reader.readable(in: vault) == [record: "before"], "\(reader.name)")
            #expect(try await reader.items(in: vault).map(\.outcome) == [.read("before"), .refused(.readOnly)])
        }
        #expect(
            try await device.setAside(in: vault) == [
                SetAsideItem(recordID: record, version: 2, origin: demoted.accountID, text: "after", refusal: .readOnly)
            ])

        // Made read-write again, the owner's choice: everything they signed counts, as it does for any member.
        try await owner.changeRole(of: demoted.accountID, to: .readWrite, in: vault)
        try await device.sync(vault)
        #expect(try await device.readable(in: vault) == [record: "after"])
        #expect(try await device.setAside(in: vault).isEmpty)
    }

    /// A5 and A1 as above, and an honest device that passes the write on before it knows: it is still sealing
    /// records again after an earlier, routine rotation, so it publishes the former member's write as a version of
    /// its own, under a key and a name every member accepts. A rule that looked only at who signed an object would
    /// let the write through in that version.
    @Test("a former member's late write does not come back inside a version that an unknowing member sealed again")
    func lateWriteSealedAgainByAnother() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.readWrite, .readWrite])
        var device = members[0]
        var former = members[1]
        try await device.sync(vault)
        try await former.sync(vault)
        let record = UUID()
        try await owner.write("genuine", to: vault, recordID: record, version: 1)
        let firstKey = try former.currentKey(vault)

        // A routine rotation everyone sees, then the removal, which the store keeps from the device.
        try await owner.planRotation(.routine, in: vault)
        #expect(try await owner.resumeRotation(in: vault) == .complete)
        try await device.sync(vault)
        try await former.sync(vault)
        #expect(try await owner.remove(former.accountID, from: vault) == .complete)
        let removal = SharingObjectLocation.membership(try #require(try owner.ledger(vault).chain.last).record).name
        await world.store.hide([removal], from: device.accountID)

        // Under the first key, so that the device, catching up on the routine rotation, seals it again.
        try await former.write("planted", to: vault, recordID: record, version: 50, under: firstKey)
        try await device.maintain(vault)
        let relayed = SimulatedMember.itemName(vault: vault, recordID: record, version: 51, author: device.accountID)
        #expect(await world.store.allObjects[relayed] != nil, "sealed again by a member in good standing")
        #expect(try await device.readable(in: vault) == [record: "planted"])

        await world.store.reveal(to: device.accountID)
        try await device.maintain(vault)
        try await owner.maintain(vault)
        try await device.maintain(vault)
        for reader in [owner, device] {
            #expect(try await reader.readable(in: vault) == [record: "genuine"], "\(reader.name)")
            let seen = try await reader.items(in: vault).first { $0.author == device.accountID && $0.version == 51 }
            #expect(seen?.origin == former.accountID, "it says whose work it carries")
            #expect(seen?.outcome == .refused(.notAMember), "and that work is outside the cut")
        }
        let current = try owner.ledger(vault).state.vaultKeyID
        #expect(try await owner.inventory(of: vault).allSatisfy { $0.keyID == current })
        #expect(try await device.inventory(of: vault).allSatisfy { $0.keyID == current })
    }

    /// A5 with store write access, after their removal: writes objects that claim places in their own stream which
    /// the cut covers (a second "first object", a second object after their first) instead of continuing it, hoping
    /// that a cut is only a count. And A1, withholding part of the stream from a member who joins later.
    @Test("a former member cannot place a write inside their cut, and a withheld stream delays what counts")
    func forkedStream() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.readWrite, .readWrite])
        var remaining = members[0]
        var former = members[1]
        try await remaining.sync(vault)
        try await former.sync(vault)
        let record = UUID()
        try await former.write("one", to: vault, recordID: record, version: 1)
        let afterOne = try #require(former.streams[vault])
        try await former.write("two", to: vault, recordID: record, version: 2)
        let tip = SimulatedMember.itemName(vault: vault, recordID: record, version: 2, author: former.accountID)
        let oldKey = try former.currentKey(vault)
        #expect(try await owner.remove(former.accountID, from: vault) == .complete)
        try await remaining.sync(vault)

        former.streams[vault] = afterOne
        try await former.write("second second", to: vault, recordID: record, version: 60, under: oldKey)
        former.streams[vault] = nil
        try await former.write("second first", to: vault, recordID: record, version: 61, under: oldKey)
        former.streams[vault] = ItemStreamPosition(count: 0, last: afterOne.last)
        try await former.write("first after first", to: vault, recordID: record, version: 62, under: oldKey)
        for reader in [owner, remaining] {
            #expect(try await reader.readable(in: vault) == [record: "two"], "\(reader.name)")
            let late = try await reader.items(in: vault).filter { $0.version >= 60 }
            #expect(late.count == 3 && late.allSatisfy { $0.outcome == .refused(.notAMember) })
        }

        // A member who joins later is not shown the object the cut names. Without it they cannot tell what is
        // inside, so nothing of the former member's counts for them yet, the owner's re-sealed copy included; shown
        // it, they agree with everyone else. Withholding delays; it never puts a write inside the cut.
        var newcomer = try await world.member("newcomer", seed: 903)
        await world.store.hide([tip], from: newcomer.accountID)
        let invitation = try await owner.invite(
            newcomer.accountID, to: vault, as: .readWrite, safetyNumber: newcomer.safetyNumber)
        try await newcomer.accept(invitation, ownerSafetyNumber: owner.safetyNumber)
        #expect(try await newcomer.readable(in: vault).isEmpty)
        #expect(try await newcomer.reseal(vault) == 0)
        await world.store.reveal(to: newcomer.accountID)
        try await newcomer.sync(vault)
        #expect(try await newcomer.readable(in: vault) == [record: "two"])
    }

    /// A4 who expects to be removed, with A1: prepares a stream of writes, and has the store show the removing
    /// device only the last object, which names the rest by digest. If the cut were that object's digest, everything
    /// before it would be inside the cut unseen, to be brought out after the removal.
    @Test("a cut covers only a stream the removing device holds whole, so nothing is brought out later inside it")
    func preparedStream() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.readWrite])
        var former = members[0]
        try await former.sync(vault)
        let record = UUID()
        try await former.write("kept back", to: vault, recordID: record, version: 1)
        try await former.write("shown", to: vault, recordID: record, version: 2)
        let first = SimulatedMember.itemName(vault: vault, recordID: record, version: 1, author: former.accountID)
        await world.store.hide([first], from: owner.accountID)

        #expect(try await owner.remove(former.accountID, from: vault) == .complete)
        #expect(try owner.ledger(vault).chain.last?.record.writeCut == .nothing)
        await world.store.reveal(to: owner.accountID)
        try await owner.maintain(vault)
        #expect(try await owner.readable(in: vault).isEmpty)
        #expect(try await owner.setAside(in: vault).map(\.text) == ["kept back", "shown"], "held aside, not lost")
    }

    /// A4, an administrator, or anyone holding an administrator's key: signs records that carry a write cut where
    /// neither a permission to write nor an administrator's role ends, so that one record would have two encodings or
    /// a later reader would take the cut for something it is not. And A1, altering the cut of a genuine record or
    /// swapping in a longer one.
    @Test("a write cut is accepted only on the record that ends a permission or a role, exactly as it was signed")
    func misplacedWriteCut() async throws {
        let household = try await SharingHousehold.make()
        let owner = household.owner
        var keys = household
        let misplaced: [(MembershipRecord.Operation, PublicKeyBundle?, UUID?)] = [
            (.addMember(household.outsider.accountID, role: .readWrite), household.outsider.bundle, nil),
            (.changeRole(household.reader.accountID, to: .readWrite), nil, nil),
            (.changeRole(household.writer.accountID, to: .administrator), nil, nil),
            (.rotateKey, nil, keys.newKeyID()),
            (.removeMember(household.reader.accountID), nil, keys.newKeyID()),
            (.deleteVault, nil, nil),
        ]
        for (operation, adding, newKeyID) in misplaced {
            var forged = household.forgery(operation, signer: owner, adding: adding, newKeyID: newKeyID)
            var device = household
            // The honest record for the operation, from the tests' own encoder, is one the ledger takes.
            try device.adopt(forged.signed(by: owner.keyset))
            forged.writeCut = [1]
            device = household
            #expect(throws: MembershipError.unexpectedWriteCut, "\(operation)") {
                try device.adopt(forged.signed(by: owner.keyset))
            }
            #expect(device.state == household.state)
        }
        var genesis = ForgedRecord(
            genesisOf: household.vaultID, owner: owner.bundle, vaultKeyID: household.ledger.chain[0].state.vaultKeyID)
        genesis.writeCut = [1]
        #expect(throws: LedgerError.noGenesis) {
            _ = try Self.freshDevice(household, [genesis.signed(by: owner.keyset)])
        }

        // Where a permission or an administrator's role does end, the cut is the signer's, to the byte.
        for operation in [
            MembershipRecord.Operation.removeMember(household.writer.accountID),
            .changeRole(household.writer.accountID, to: .readOnly),
            .changeRole(household.administrator.accountID, to: .readWrite),
        ] {
            let newKeyID = operation == .removeMember(household.writer.accountID) ? keys.newKeyID() : nil
            var forged = household.forgery(operation, signer: owner, newKeyID: newKeyID)
            forged.writeCut = [1, 2, 3]
            let genuine = try forged.signed(by: owner.keyset)
            var altered = forged
            altered.writeCut = [1, 2, 4]
            var device = household
            #expect(throws: MembershipError.signatureInvalid) {
                try device.adopt(altered.withSignature(Array(genuine.suffix(64))))
            }
            altered.writeCut = [UInt8](repeating: 1, count: MembershipLimits.maximumWriteCutLength + 1)
            #expect(throws: SharingFormatError.tooLarge(MembershipLimits.maximumWriteCutLength + 1)) {
                try device.adopt(altered.signed(by: owner.keyset))
            }
            try device.adopt(genuine)
            #expect(device.ledger.chain.last?.record.writeCut.bytes == [1, 2, 3])
            if operation == .changeRole(household.administrator.accountID, to: .readWrite) {
                #expect(device.ledger.administratorStanding(of: household.administrator.accountID) != .holdsRole)
            } else {
                #expect(device.ledger.writeStanding(of: household.writer.accountID).refusal != nil)
            }
        }
    }

    /// A5 as to the role: an administrator the owner demoted to read-write, who may still write items and holds
    /// their account key. Only the owner and administrators name the vault (§8.7), so which of their descriptions
    /// count must be the cut in the owner's record on every device. They try what would move it: a branch of their
    /// own from before the demotion, longer than the chain, on which they still hold the role; the store (A1) alters
    /// the cut of the genuine record; and an administrator who is not the owner (A4) tries to end the role with a cut
    /// of nothing, to erase the names they chose.
    @Test("a former administrator's descriptions count as the owner's record cut them, on any device, in any order")
    func administratorStandingFollowsTheOwnersRecord() async throws {
        var household = try await SharingHousehold.make()
        let former = household.administrator
        let second = try SharingParty(seed: 47)
        try await household.add(second, as: .administrator, by: household.owner)
        let forkPoint = household.ledger
        let listed = try #require(household.state.member(former.accountID))

        // Only the owner ends an administrator's role, with or without a cut.
        #expect(throws: MembershipError.ownerOnly) {
            _ = try household.ledger.proposeRoleChange(
                of: former.accountID, to: .readWrite, writeCut: .nothing, signedBy: second.keyset)
        }
        var bySecond = household.forgery(.changeRole(former.accountID, to: .readWrite), signer: second)
        bySecond.writeCut = []
        var refusing = household
        #expect(throws: MembershipError.ownerOnly) { try refusing.adopt(bySecond.signed(by: second.keyset)) }

        // The owner's demotion, with the cut; the same record with another cut does not verify.
        var demotion = household.forgery(.changeRole(former.accountID, to: .readWrite), signer: household.owner)
        demotion.writeCut = [4, 2]
        let genuine = try demotion.signed(by: household.owner.keyset)
        var altered = demotion
        altered.writeCut = [4, 2, 1]
        #expect(throws: MembershipError.signatureInvalid) {
            try refusing.adopt(altered.withSignature(Array(genuine.suffix(64))))
        }
        try household.adopt(genuine)
        let cut = try WriteCut([4, 2])
        let standing = AdministratorStanding.ended(cut: cut, author: listed)
        #expect(household.ledger.administratorStanding(of: former.accountID) == standing)
        #expect(household.ledger.writeStanding(of: former.accountID) == .mayWrite)

        // Their branch from before the demotion, three records long: it lacks the owner's record and loses.
        var branch = forkPoint
        var attack: [[UInt8]] = []
        for _ in 0..<3 {
            let rotation = try RotationPlanner.plan(.routine, ledger: branch, signedBy: former.keyset)
            branch.ingest([rotation.record.contents])
            attack.append(rotation.record.contents)
        }
        #expect(branch.administratorStanding(of: former.accountID) == .holdsRole, "on their own branch alone")
        var informed = household.ledger
        informed.ingest(attack)
        #expect(informed.administratorStanding(of: former.accountID) == standing)
        let chain = household.ledger.chain.map(\.encoded)
        for records in [attack + chain, chain + attack, Array((attack + chain).reversed())] {
            let device = try Self.freshDevice(household, records)
            #expect(device.administratorStanding(of: former.accountID) == standing)
            #expect(device.writeStanding(of: former.accountID) == .mayWrite)
        }
        // A device shown only their branch follows it until the owner's record arrives, and then agrees.
        var misled = branch
        misled.ingest(chain)
        #expect(misled.administratorStanding(of: former.accountID) == standing)
    }

    /// A1 with two honest administrators, as in `withheldSiblingReleasedLate`: a fork displaces the record that
    /// removed a member, so that the member is listed again. If their writes counted again in full while the removal
    /// is owed, the store could reopen the door for them by timing a fork.
    @Test("while a removal is owed, the member's writes count exactly as the displaced record's branch left them")
    func owedRemovalKeepsItsCut() async throws {
        var household = try await SharingHousehold.make()
        let second = try SharingParty(seed: 42)
        try await household.add(second, as: .administrator, by: household.owner)
        let fork = household.ledger
        let target = household.writer.accountID
        let listed = try #require(household.state.member(target))
        var generator = SeededGenerator(seed: 46)

        // The removal carries the cut.
        let cut = try WriteCut([5, 5, 5])
        let removal = try RotationPlanner.plan(
            .removal(target), ledger: fork, memberKeys: .findingNothing(in: fork), writeCut: cut,
            signedBy: second.keyset, using: &generator)
        var device = fork
        device.ingest([removal.record.contents])
        #expect(device.writeStanding(of: target) == .ended(cut: cut, author: listed, refusal: .notAMember))
        let stale = try Self.groundRotation(below: removal.recordHash, on: fork, by: household.administrator, seed: 47)
        device.ingest([stale.record.contents])
        #expect(
            device.state.member(target)?.role == .readWrite, "listed again, and able to write as far as the state says")
        #expect(device.owedRemovals.map(\.record) == [removal.proposal])
        #expect(device.writePermission(for: target) == .refused(.removalPending))
        #expect(device.writeStanding(of: target) == .ended(cut: cut, author: listed, refusal: .removalPending))
        #expect(device.owedRemovals.first?.standing == device.writeStanding(of: target))
        #expect(try Self.restored(device, household).writeStanding(of: target) == device.writeStanding(of: target))

        // The branch made them read-only first, with the cut there, and then removed them with none.
        let demotion = try fork.proposeRoleChange(of: target, to: .readOnly, writeCut: cut, signedBy: second.keyset)
        var branch = fork
        branch.ingest([demotion.encoded()])
        let later = try RotationPlanner.plan(
            .removal(target), ledger: branch, memberKeys: .findingNothing(in: branch), writeCut: nil,
            signedBy: second.keyset, using: &generator)
        branch.ingest([later.record.contents])
        #expect(branch.writeStanding(of: target) == .ended(cut: cut, author: listed, refusal: .notAMember))
        let first = try Self.groundRotation(below: demotion.hash, on: fork, by: household.administrator, seed: 48)
        var other = fork
        other.ingest([first.record.contents])
        let next = try RotationPlanner.plan(.routine, ledger: other, signedBy: household.administrator.keyset)
        device = branch
        let report = device.ingest([first.record.contents, next.record.contents])
        #expect(report.superseded == [demotion, later.proposal])
        #expect(device.state.member(target)?.role == .readWrite)
        #expect(device.owedRemovals.map(\.record) == [later.proposal])
        #expect(device.writeStanding(of: target) == .ended(cut: cut, author: listed, refusal: .removalPending))
    }

    /// A5, a former administrator with their key and store write access: takes a member's genuine, pending leave
    /// request and carries the departure out on a branch from before their own removal, with a write cut of their
    /// choosing (nothing). A departure is owed whoever signed it, because the member asked; if the cut of the record
    /// that carried it out were believed as well, every device would set the leaving member's work aside on a
    /// former administrator's say-so, and the administrator who plans the departure again would sign that.
    @Test("a former administrator's cut on a dead branch decides nothing about a leaving member's work")
    func deadBranchDepartureCut() async throws {
        var household = try await SharingHousehold.make()
        let fork = household.ledger
        let writer = household.writer.accountID
        let listed = try #require(household.state.member(writer))
        try household.rotate(.removal(household.administrator.accountID), by: household.owner)
        let request = try LeaveRequest.make(leaving: household.state, as: household.writer.keyset)
        var generator = SeededGenerator(seed: 49)
        let dead = try RotationPlanner.plan(
            .departure(request), ledger: fork, memberKeys: .findingNothing(in: fork), writeCut: .nothing,
            signedBy: household.administrator.keyset, using: &generator)

        var device = household.ledger
        let report = device.ingest([dead.record.contents])
        #expect(report.outranked == [dead.proposal] && !report.changedHead)
        #expect(device.owedRemovals.map(\.reason) == [.departure(request)], "the member did ask to leave")
        #expect(device.owedRemovals.first?.standing == .mayWrite)
        #expect(device.writeStanding(of: writer) == .mayWrite, "what they wrote goes on counting")
        #expect(device.writePermission(for: writer) == .refused(.removalPending), "their own device writes no more")

        // The owner's device carries the departure out, and its cut is the one that counts.
        let cut = try WriteCut([8])
        let again = try RotationPlanner.plan(
            .departure(request), ledger: device, memberKeys: .findingNothing(in: device), writeCut: cut,
            signedBy: household.owner.keyset, using: &generator)
        device.ingest([again.record.contents])
        #expect(device.owedRemovals.isEmpty)
        #expect(device.writeStanding(of: writer) == .ended(cut: cut, author: listed, refusal: .notAMember))

        // Had a current administrator signed the displaced departure, its cut would have stood meanwhile
        // (`owedRemovalKeepsItsCut`); a former one's removal, without the member's signature, is not owed at all.
        let removal = try RotationPlanner.plan(
            .removal(writer), ledger: fork, memberKeys: .findingNothing(in: fork), writeCut: .nothing,
            signedBy: household.administrator.keyset, using: &generator)
        device = household.ledger
        device.ingest([removal.record.contents])
        #expect(device.owedRemovals.isEmpty)
        #expect(device.writeStanding(of: writer) == .mayWrite)
    }

    static func restored(_ ledger: MembershipLedger, _ household: SharingHousehold) throws -> MembershipLedger {
        try MembershipLedger.restore(
            ledger.persisted(signedBy: household.owner.keyset), vaultID: household.vaultID,
            owner: trusted(household.owner), account: household.owner.bundle)
    }

    /// A5 with store write access: signs an item as a remaining member (whose signature they cannot make), or under
    /// a remaining member's name with their own key.
    @Test("a former member cannot write in a remaining member's name")
    func writesInAnothersName() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.readWrite, .readWrite])
        var remaining = members[0]
        let former = members[1]
        let oldKey = try owner.currentKey(vault)
        try await owner.remove(former.accountID, from: vault)
        try await remaining.sync(vault)

        // Sealed under the key they still hold, signed with their own key, filed under the owner's name.
        let recordID = UUID()
        var generator = SeededGenerator(seed: 53)
        let envelope = try RecordCipher.seal(
            Array("forged".utf8),
            context: EnvelopeContext(
                recordID: recordID, vaultID: vault, schemaVersion: 1, kind: .item, keyID: oldKey.key.keyID,
                recordVersion: 5),
            key: oldKey.key, using: &generator)
        let name = SimulatedMember.itemName(vault: vault, recordID: recordID, version: 5, author: owner.accountID)
        let object = try SimulatedMember.itemObject(
            name: name, sequence: 1, previous: [UInt8](repeating: 0, count: 32), envelope: envelope,
            signedBy: former.keyset)
        await world.store.tamper(name, contents: object)

        let seen = try await remaining.items(in: vault).first { $0.recordID == recordID }
        #expect(seen?.outcome == .forged)
        #expect(try await remaining.readable(in: vault)[recordID] == nil)
    }

    // MARK: - Fork and rollback

    /// A1, serving the store: answers a member's listing with an earlier state of the membership directory (a shorter
    /// chain), to make a removed member look current again.
    @Test("a store serving an older chain rolls nothing back")
    func rollback() async throws {
        var household = try await SharingHousehold.make()
        let earlier = household.ledger.chain.map(\.encoded)
        try household.rotate(.removal(household.writer.accountID), by: household.owner)
        var ledger = household.ledger
        for offered in [earlier, [earlier[0]], Array(earlier.reversed()), []] {
            let report = ledger.ingest(offered)
            #expect(!report.changedHead && report.rejected.isEmpty)
            #expect(ledger.state == household.state)
        }
        #expect(ledger.state.member(household.writer.accountID) == nil)
    }

    /// A8, with write access to this device's files (and A1 beside it): replaces the saved ledger with a shorter one,
    /// alters it, or plants one made for another account or by another key, so that the device restarts from a
    /// state in which a removed member is still a member.
    @Test("a saved ledger that was truncated, altered or planted is refused on restore")
    func tamperedSavedLedger() async throws {
        var household = try await SharingHousehold.make()
        let device = household.reader
        let owner = Self.trusted(household.owner)
        func restore(_ blob: [UInt8]) throws -> MembershipLedger {
            try MembershipLedger.restore(blob, vaultID: household.vaultID, owner: owner, account: device.bundle)
        }
        let earlier = try household.ledger.persisted(signedBy: device.keyset)
        try household.rotate(.removal(household.writer.accountID), by: household.owner)
        let blob = try household.ledger.persisted(signedBy: device.keyset)
        #expect(try restore(blob).state == household.state)

        // The newer checkpoint over the older records: the head it names is not reached.
        let checkpointLength = 4 + 1 + 16 + 16 + 32 + 8 + 32 + 64
        let spliced = Array(blob[..<checkpointLength]) + Array(earlier[checkpointLength...])
        #expect(throws: LedgerError.rolledBack(expectedEpoch: household.state.epoch)) { _ = try restore(spliced) }

        // Any single byte altered.
        for position in stride(from: 0, to: blob.count, by: 3) {
            var altered = blob
            altered[position] ^= 0x01
            #expect(throws: (any Error).self, "byte \(position)") { _ = try restore(altered) }
        }

        // A ledger signed by someone else's key, or by this account for an attacker's chain.
        #expect(throws: LedgerError.checkpointInvalid) {
            _ = try restore(household.ledger.persisted(signedBy: household.outsider.keyset))
        }
        var generator = SeededGenerator(seed: 54)
        let attackerKey = VaultKey.generate(vaultID: household.vaultID, using: &generator)
        let attackerChain = try MembershipLedger.create(vaultKey: attackerKey, owner: household.outsider.keyset)
        #expect(throws: LedgerError.checkpointInvalid, "the checkpoint names the owner it was verified against") {
            _ = try restore(attackerChain.persisted(signedBy: household.outsider.keyset))
        }

        // The honest limit of a signature: this device's own older blob still restores, as that older state, and
        // the next ingest brings it forward again.
        var stale = try restore(earlier)
        #expect(stale.state.epoch == 3)
        stale.ingest(household.ledger.chain.map(\.encoded))
        #expect(stale.state == household.state)
    }

    /// A1, with two honest administrators acting at once: shows each half of the household a different one of the two
    /// records for as long as it likes, then lets them see both, hoping they stay apart.
    @Test("a store that shows different members different branches cannot keep them apart once both are seen")
    func partitionedFork() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.administrator, .readWrite, .readOnly])
        var admin = members[0]
        var bystander = members[1]
        try await admin.sync(vault)
        try await bystander.sync(vault)

        let ownersRecord = try owner.ledger(vault).proposeRoleChange(
            of: members[2].accountID, to: .readWrite, signedBy: owner.keyset)
        let adminsRecord = try admin.ledger(vault).proposeRoleChange(
            of: members[1].accountID, to: .readOnly, signedBy: admin.keyset)
        for record in [ownersRecord, adminsRecord] {
            try await world.store.create(SharingObject(record).name, contents: record.encoded(), by: owner.accountID)
        }
        await world.store.hide([SharingObject(ownersRecord).name], from: admin.accountID)
        await world.store.hide([SharingObject(ownersRecord).name], from: bystander.accountID)
        await world.store.hide([SharingObject(adminsRecord).name], from: owner.accountID)

        try await owner.sync(vault)
        try await admin.sync(vault)
        try await bystander.sync(vault)
        #expect(try owner.ledger(vault).state.hash == ownersRecord.hash)
        #expect(try bystander.ledger(vault).state.hash == adminsRecord.hash, "shown only one branch, it follows it")

        for viewer in [owner.accountID, admin.accountID, bystander.accountID] {
            await world.store.reveal(to: viewer)
        }
        try await owner.sync(vault)
        let adminReport = try await admin.sync(vault)
        try await bystander.sync(vault)
        try await owner.sync(vault)
        #expect(adminReport.superseded == [adminsRecord])
        // Everyone is on the owner's record. The administrator's change lost its place, so the administrator's
        // device made it again on top (review finding S27); nothing either of them did is missing.
        let state = try owner.ledger(vault).state
        for member in [owner, admin, bystander] {
            #expect(try member.ledger(vault).contains(ownersRecord.hash), "\(member.name)")
            #expect(try !member.ledger(vault).contains(adminsRecord.hash), "\(member.name)")
            #expect(try member.ledger(vault).state == state, "\(member.name)")
        }
        #expect(state.epoch == 5)
        #expect(state.member(members[2].accountID)?.role == .readWrite)
        #expect(state.member(members[1].accountID)?.role == .readOnly)
    }

    // MARK: - Role escalation

    /// A4, a read-write member and then an administrator, each with their own account key and store write access:
    /// sign records that would give themselves or an accomplice more than their role allows, directly or tucked
    /// into the member list of a record that claims to do something else.
    @Test("no member can raise their own role or anyone else's beyond what their role may grant")
    func roleEscalation() async throws {
        let household = try await SharingHousehold.make()
        let member = household.writer
        let admin = household.administrator
        let accomplice = household.outsider
        var ledger = household.ledger

        var selfPromotionOnTheSide = household.forgery(.rotateKey, signer: admin, newKeyID: UUID())
        for index in selfPromotionOnTheSide.entries.indices
        where selfPromotionOnTheSide.entries[index].accountID == admin.accountID {
            selfPromotionOnTheSide.entries[index].role = MemberRole.owner.rawValue
        }
        var demotesOwnerOnTheSide = household.forgery(
            .addMember(accomplice.accountID, role: .readOnly), signer: admin, adding: accomplice.bundle)
        for index in demotesOwnerOnTheSide.entries.indices
        where demotesOwnerOnTheSide.entries[index].accountID == household.owner.accountID {
            demotesOwnerOnTheSide.entries[index].role = MemberRole.readOnly.rawValue
        }

        let attempts: [(ForgedRecord, SharingParty, MembershipError)] = [
            (
                household.forgery(.changeRole(member.accountID, to: .administrator), signer: member), member,
                .signerNotAdministrator(member.accountID)
            ),
            (
                household.forgery(
                    .addMember(accomplice.accountID, role: .readWrite), signer: member, adding: accomplice.bundle),
                member, .signerNotAdministrator(member.accountID)
            ),
            (
                household.forgery(
                    .changeRole(household.reader.accountID, to: .readWrite), signer: household.reader),
                household.reader, .signerNotAdministrator(household.reader.accountID)
            ),
            (
                household.forgery(.changeRole(member.accountID, to: .administrator), signer: admin), admin,
                .ownerOnly
            ),
            (
                household.forgery(
                    .addMember(accomplice.accountID, role: .administrator), signer: admin,
                    adding: accomplice.bundle), admin, .ownerOnly
            ),
            (household.forgery(.changeRole(admin.accountID, to: .owner), signer: admin), admin, .ownerIsFixed),
            (
                household.forgery(.changeRole(household.owner.accountID, to: .readOnly), signer: admin), admin,
                .ownerIsFixed
            ),
            (
                household.forgery(.removeMember(household.owner.accountID), signer: admin, newKeyID: UUID()), admin,
                .ownerIsFixed
            ),
            (household.forgery(.deleteVault, signer: admin), admin, .ownerOnly),
            (selfPromotionOnTheSide, admin, .resultingMembersMismatch),
            (demotesOwnerOnTheSide, admin, .resultingMembersMismatch),
        ]
        for (forged, signer, expected) in attempts {
            let report = ledger.ingest([try forged.signed(by: signer.keyset)])
            #expect(report.rejected.map(\.reason) == [.invalid(expected)])
        }
        #expect(ledger.state == household.state)
        #expect(ledger.state.members.filter { $0.role.isAdministrator }.count == 2)
    }

    /// A4, a malicious administrator: writes records until the chain's epochs run out, so that the owner can never
    /// again sign the record that would remove them.
    @Test("an administrator cannot use up the chain: its last epochs take only the owner's signature")
    func epochExhaustion() async throws {
        let household = try await SharingHousehold.make()
        let nearTheEnd = MembershipState(
            vaultID: household.vaultID, epoch: MembershipLimits.maximumAdministratorEpoch,
            hash: household.state.hash, members: household.state.members, vaultKeyID: household.state.vaultKeyID,
            keyEpoch: 0, isDeleted: false)
        func attempt(by party: SharingParty, _ operation: MembershipRecord.Operation, newKeyID: UUID?) throws
            -> MembershipState
        {
            let forged = ForgedRecord(
                after: nearTheEnd, signer: party.accountID, operation: operation, newKeyID: newKeyID)
            let record = try MembershipRecord.parse(forged.signed(by: party.keyset))
            return try MembershipRules.nextState(
                record, hash: record.hash, after: nearTheEnd, keyUsedBefore: { _ in false })
        }
        #expect(throws: MembershipError.epochReservedForOwner) {
            _ = try attempt(by: household.administrator, .rotateKey, newKeyID: UUID())
        }
        let removed = try attempt(
            by: household.owner, .removeMember(household.administrator.accountID), newKeyID: UUID())
        #expect(removed.member(household.administrator.accountID) == nil)
        #expect(MembershipLimits.maximumEpoch - MembershipLimits.maximumAdministratorEpoch >= 1_000)
    }

    // MARK: - Leave requests

    /// A1 or A5, holding a leave request a member once published: replays it after the member has been invited
    /// back, or into another vault the member is in, to have an administrator's device remove them again.
    @Test("a leave request is spent with the membership it was made for, and worthless in any other vault")
    func replayedLeaveRequests() async throws {
        var household = try await SharingHousehold.make()
        let member = household.writer
        let request = try LeaveRequest.make(leaving: household.state, as: member.keyset)
        try household.rotate(.departure(request), by: household.administrator)
        try await household.add(member, as: .readWrite, by: household.owner)
        #expect(household.state.member(member.accountID)?.since == 5)

        #expect(household.ledger.pendingLeaveRequests(among: [request]).isEmpty)
        #expect(throws: SharingError.leaveRequestInvalid) { try request.validate(against: household.state) }
        #expect(throws: SharingError.leaveRequestInvalid) {
            _ = try RotationPlanner.plan(
                .departure(request), ledger: household.ledger, signedBy: household.owner.keyset)
        }
        // An administrator who goes around the planner and signs the departure with the old request anyway.
        var ledger = household.ledger
        let forged = household.forgery(
            .memberLeft(member.accountID, requestSignature: request.signature), signer: household.administrator,
            newKeyID: UUID())
        #expect(
            ledger.ingest([try forged.signed(by: household.administrator.keyset)]).rejected.map(\.reason)
                == [.invalid(.leaveRequestInvalid)])

        // Another vault with the same owner, in which the same member was added at the same epoch.
        let elsewhere = try LeaveRequest.make(leaving: household.state, as: household.reader.keyset)
        var generator = SeededGenerator(seed: 55)
        let thirdKey = VaultKey.generate(vaultID: UUID(), using: &generator)
        var third = try MembershipLedger.create(vaultKey: thirdKey, owner: household.owner.keyset)
        for (party, role) in [
            (household.administrator, MemberRole.administrator), (household.writer, .readWrite),
            (household.reader, .readOnly),
        ] {
            let record = try third.proposeAddition(
                of: Self.trusted(party), as: role, signedBy: household.owner.keyset)
            third.ingest([record.encoded()])
        }
        #expect(third.state.member(household.reader.accountID)?.since == elsewhere.memberSince)
        #expect(third.pendingLeaveRequests(among: [elsewhere]).isEmpty)
        #expect(throws: SharingError.leaveRequestInvalid) {
            _ = try RotationPlanner.plan(.departure(elsewhere), ledger: third, signedBy: household.owner.keyset)
        }
        let relabelled = LeaveRequest(
            vaultID: third.vaultID, accountID: elsewhere.accountID, memberSince: elsewhere.memberSince,
            signature: elsewhere.signature)
        #expect(third.pendingLeaveRequests(among: [relabelled]).isEmpty)
        #expect(throws: SharingError.leaveRequestInvalid) { try relabelled.validate(against: third.state) }
        #expect(household.ledger.pendingLeaveRequests(among: [elsewhere]) == [elsewhere], "valid at home")

        // A request signed by someone other than the member it names.
        let impersonated = LeaveRequest(
            vaultID: household.vaultID, accountID: household.reader.accountID, memberSince: 3,
            signature: try household.administrator.keyset.sign(
                LeaveRequest.signedContent(
                    vaultID: household.vaultID, accountID: household.reader.accountID, memberSince: 3),
                domain: .membership))
        #expect(household.ledger.pendingLeaveRequests(among: [impersonated]).isEmpty)
    }

    // MARK: - Two administrators against each other

    /// A4 twice over: two administrators each sign, at the same moment, the record that removes the other, and each
    /// hopes theirs is the one the household keeps.
    @Test("two administrators removing each other at once remove nobody, and the vault stays administrable")
    func mutualRemoval() async throws {
        var household = try await SharingHousehold.make()
        let first = household.administrator
        let second = try SharingParty(seed: 56)
        try await household.add(second, as: .administrator, by: household.owner)
        let before = household.state

        // Their own clients refuse to plan it.
        #expect(throws: MembershipError.ownerOnly) {
            _ = try RotationPlanner.plan(.removal(second.accountID), ledger: household.ledger, signedBy: first.keyset)
        }
        #expect(throws: MembershipError.ownerOnly) {
            _ = try RotationPlanner.plan(.removal(first.accountID), ledger: household.ledger, signedBy: second.keyset)
        }
        // Signed anyway, and published in either order: every device refuses both.
        let records = [
            try household.forgery(.removeMember(second.accountID), signer: first, newKeyID: UUID())
                .signed(by: first.keyset),
            try household.forgery(.removeMember(first.accountID), signer: second, newKeyID: UUID())
                .signed(by: second.keyset),
        ]
        for order in [records, Array(records.reversed())] {
            var ledger = household.ledger
            let report = ledger.ingest(order)
            #expect(report.rejected.map(\.reason) == [.invalid(.ownerOnly), .invalid(.ownerOnly)])
            #expect(ledger.state == before)
        }
        #expect(before.members.filter { $0.role.isAdministrator }.count == 3)

        // The owner settles it, and can still act afterwards.
        try household.rotate(.removal(first.accountID), by: household.owner)
        try household.rotate(.removal(second.accountID), by: household.owner)
        try household.rotate(.routine, by: household.owner)
        #expect(
            household.state.members.filter { $0.role.isAdministrator }.map(\.accountID) == [household.owner.accountID])
    }

    /// A4, an administrator the owner is removing: at the same moment, without having seen the removal, signs a
    /// record of their own at that epoch (one that would remove the owner, and one their role does allow), with its
    /// hash ground below the owner's.
    @Test("the owner removing an administrator wins against that administrator's record at the same epoch")
    func ownerAgainstAdministrator() async throws {
        let household = try await SharingHousehold.make()
        let admin = household.administrator
        var generator = SeededGenerator(seed: 57)
        let removal = try RotationPlanner.plan(
            .removal(admin.accountID), ledger: household.ledger, signedBy: household.owner.keyset, using: &generator)
        let rival = try Self.groundRotation(below: removal.recordHash, on: household.ledger, by: admin, seed: 58)
        let removesOwner = try household.forgery(
            .removeMember(household.owner.accountID), signer: admin, newKeyID: UUID()
        ).signed(by: admin.keyset)
        #expect(rival.recordHash < removal.recordHash)

        let candidates = [removal.record.contents, rival.record.contents, removesOwner]
        var generatorForOrder = SeededGenerator(seed: TestEnvironment.seed(fallback: 59))
        for _ in 0..<TestEnvironment.iterations(standard: 12, long: 200) {
            var ledger = household.ledger
            for record in candidates.shuffled(using: &generatorForOrder) {
                ledger.ingest([record])
            }
            #expect(ledger.state.hash == removal.recordHash)
            #expect(ledger.state.member(admin.accountID) == nil)
            #expect(ledger.state.owner.accountID == household.owner.accountID)
            // Nobody is locked out: the owner signs the next record.
            let next = try RotationPlanner.plan(.routine, ledger: ledger, signedBy: household.owner.keyset)
            #expect(ledger.ingest([next.record.contents]).adopted.count == 1)
        }
    }

    // MARK: - Local state

    /// A8, with write access to the verified-contacts file: plants a pin for an account of its choosing (unsigned,
    /// signed with its own key, or a genuine pin made by a different account), so that a substituted key counts as
    /// verified without the person ever comparing a fingerprint.
    @Test("a pin planted in the contacts store verifies nothing")
    func plantedPins() async throws {
        let me = try SharingParty(seed: 1)
        let target = try SharingParty(seed: 2)
        let attacker = try SharingParty(accountID: target.accountID, seed: 60)
        let other = try SharingParty(seed: 3)
        let store = InMemoryVerifiedContactStore()
        let contacts = VerifiedContacts(store: store, account: me.bundle)

        // A genuine pin for the attacker's bundle, made by someone else's contacts.
        let otherStore = InMemoryVerifiedContactStore()
        let othersContacts = VerifiedContacts(store: otherStore, account: other.bundle)
        _ = try await othersContacts.verify(
            attacker.bundle, evidence: .comparedByEye, signedBy: other.keyset, at: Self.now)
        let foreign = try #require(await otherStore.pin(for: target.accountID))

        // The same pin re-signed by the attacker, claiming to be mine.
        let content = VerifiedContacts.pinContent(
            pinner: me.accountID, method: .safetyNumber, seconds: 1, bundle: attacker.bundle)
        let selfSigned = content + (try attacker.keyset.sign(content, domain: .membership))

        for planted in [foreign, selfSigned, content + [UInt8](repeating: 0, count: 64), [], [1, 2, 3]] {
            await store.savePin(planted, for: target.accountID)
            #expect(try await contacts.pinned(target.accountID) == nil)
            #expect(try await contacts.trust(of: attacker.bundle) == .unverified)
            #expect(try await contacts.trust(of: target.bundle) == .unverified)
        }

        // A genuine pin of mine for one contact, copied under another contact's name.
        let mine = try await contacts.verify(other.bundle, evidence: .comparedByEye, signedBy: me.keyset, at: Self.now)
        #expect(mine.accountID == other.accountID)
        await store.savePin(try #require(await store.pin(for: other.accountID)), for: target.accountID)
        #expect(try await contacts.pinned(target.accountID) == nil)

        // Deleting a pin is all that is left: the contact is unverified again, in front of the person.
        await store.removePin(for: other.accountID)
        #expect(try await contacts.trust(of: other.bundle) == .unverified)
    }

    // MARK: - Round-two findings: forks across calls, late and stale records, names, pins, plans, floods

    /// A well-formed membership object name for contents that are not a record: what anyone who can create objects
    /// can put in the directory.
    static func junkName(vault: UUID, epoch: UInt64, salt: Int, contents: [UInt8]) -> String {
        SharingObjectLocation(
            vaultID: vault,
            kind: .membership(
                epoch: epoch, hash: MembershipHash(unchecked: SharingBytes.sha256([UInt8(truncatingIfNeeded: salt)])),
                digest: SharingBytes.sha256(contents))
        ).name
    }

    /// A5, a former administrator with their key and store write access, helped by a store (A1) that serves the
    /// membership directory a page at a time, or one object at a time, in an order of its choosing: publishes a
    /// record at an epoch before their removal with a hash ground below the accepted one's, hoping a device that
    /// adopts it on one page can no longer connect what the next page holds (review finding S17).
    @Test("a former administrator's rewrite does not stick on a device fed the directory a page at a time")
    func rewriteAcrossPages() async throws {
        var household = try await SharingHousehold.make()
        let former = household.administrator
        let second = try SharingParty(seed: 42)
        try await household.add(second, as: .administrator, by: household.owner)
        let forkPoint = household.ledger
        try household.adopt(
            household.ledger.proposeRoleChange(
                of: household.reader.accountID, to: .readWrite, signedBy: second.keyset
            ).encoded())
        let overwritten = household.state.hash
        try household.rotate(.removal(former.accountID), by: household.owner)
        try household.rotate(.routine, by: second)
        let rewrite = try Self.groundRotation(below: overwritten, on: forkPoint, by: former, seed: 43)
        let genuine = household.ledger.chain.map(\.encoded)

        // First page: everything up to the fork, both records at it. The device cannot know better yet.
        var device = try Self.freshDevice(household, Array(genuine[...5]) + [rewrite.record.contents])
        #expect(device.state.hash == rewrite.recordHash)
        #expect(device.holds(overwritten), "the record that lost is kept")
        // Second page: the owner's removal and what followed. They connect, and the owner's record decides.
        let report = device.ingest(Array(genuine[6...]))
        #expect(report.rejected.isEmpty)
        #expect(device.state == household.state)
        #expect(device.state.member(former.accountID) == nil)
        #expect(device.owedRemovals.isEmpty)

        // One object per call, in orders of the store's choosing, re-offering what did not connect yet.
        let listing = genuine + [rewrite.record.contents]
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 44))
        for _ in 0..<TestEnvironment.iterations(standard: 20, long: 400) {
            var ledger = try Self.freshDevice(household, [genuine[0]])
            var passes = 0
            while ledger.chain.count + ledger.branches.count < listing.count {
                for object in listing.shuffled(using: &generator) {
                    ledger.ingest([object])
                }
                passes += 1
                try #require(passes < 50)
            }
            #expect(ledger.state == household.state)
            #expect(ledger.branches.map(\.state.hash) == [rewrite.recordHash])
        }
    }

    /// A4, a read-only member about to be removed, with nothing but permission to create objects: fills the
    /// membership directory with thousands of objects, some of them shaped like the next record under the owner's
    /// name, so that no device gets through a listing and their removal is never adopted (review finding S17).
    @Test("thousands of junk objects in the membership directory stop nobody from adopting the next record")
    func membershipFlood() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.readWrite, .readOnly])
        var bystander = members[0]
        let flooder = members[1]
        try await bystander.sync(vault)
        let state = try owner.ledger(vault).state
        for index in 0..<4_500 {
            let contents = [UInt8(truncatingIfNeeded: index), UInt8(truncatingIfNeeded: index >> 8), 0x57]
            try await world.store.create(
                Self.junkName(vault: vault, epoch: UInt64(index % 5), salt: index, contents: contents),
                contents: contents, by: flooder.accountID)
        }
        // Records that pass every check that costs nothing, and carry a signature nobody made.
        var unsigned = 0
        for index in 0..<600 {
            var forged = ForgedRecord(
                after: state, signer: owner.accountID, operation: .changeRole(flooder.accountID, to: .administrator))
            forged.vaultKeyID = state.vaultKeyID
            let contents = forged.withSignature(
                [UInt8(truncatingIfNeeded: index), UInt8(truncatingIfNeeded: index >> 8)]
                    + [UInt8](repeating: 0x57, count: 62))
            try await world.store.create(
                SharingObject(try MembershipRecord.parse(contents)).name, contents: contents, by: flooder.accountID)
            unsigned += 1
        }

        #expect(try await owner.remove(flooder.accountID, from: vault) == .complete)
        let report = try await bystander.sync(vault)
        #expect(report.adopted.map(\.operation) == [.removeMember(flooder.accountID)])
        #expect(report.rejected.count == 4_500 + unsigned)
        #expect(report.signatureChecks == unsigned + 1, "one each for what looked like a record, none for the rest")
        #expect(try bystander.ledger(vault).state == owner.ledger(vault).state)
        #expect(try bystander.currentKey(vault).key.keyID == owner.currentKey(vault).key.keyID)

        // The flood is paid for once: what can never be a record is not fetched again.
        #expect(bystander.refusedNames.count == 4_500 + unsigned)
        let again = try await bystander.sync(vault)
        #expect(again.rejected.isEmpty && again.signatureChecks == 0)
    }

    /// A1, serving the store, with two honest administrators: hides the newest head from one administrator's
    /// device, so that its next ordinary action is signed on the stale head, sees from the object names that this
    /// record's hash is the lower one, and releases it after every device has accepted the other administrator's
    /// removal of a member and built on it, to roll the chain back to a state in which that member is listed and
    /// the key they hold is current (review finding S18).
    @Test("a record signed on a stale head and released late displaces nothing that has been built on since")
    func withheldSiblingReleasedLate() async throws {
        var household = try await SharingHousehold.make()
        let second = try SharingParty(seed: 42)
        try await household.add(second, as: .administrator, by: household.owner)
        let fork = household.ledger
        let oldKey = household.state.vaultKeyID
        let target = household.writer.accountID
        let removal = try household.rotate(.removal(target), by: second)
        let afterRemoval = household.ledger
        try household.adopt(
            household.ledger.proposeRoleChange(of: household.reader.accountID, to: .readWrite, signedBy: second.keyset)
                .encoded())
        let stale = try Self.groundRotation(below: removal.recordHash, on: fork, by: household.administrator, seed: 45)
        #expect(stale.recordHash < removal.recordHash)

        // Every device has two records on top of the fork; the stale one is one.
        var device = household.ledger
        var report = device.ingest([stale.record.contents])
        #expect(report.superseded.isEmpty && !report.changedHead)
        #expect(report.outranked == [stale.proposal])
        #expect(device.state == household.state)
        #expect(device.state.member(target) == nil && device.state.vaultKeyID != oldKey)
        #expect(device.status(of: stale.proposal) == .superseded, "its author's device proposes it again")
        #expect(
            try Self.freshDevice(household, household.ledger.chain.map(\.encoded) + [stale.record.contents]).state
                == household.state)

        // The narrowest timing the store has: released when nothing has been built on the removal yet. The two
        // records are then equals and the hash decides, so the removal is undone; but it is not forgotten.
        device = afterRemoval
        report = device.ingest([stale.record.contents])
        #expect(report.superseded == [removal.proposal])
        #expect(device.state.member(target) != nil, "listed again, for now")
        #expect(device.owedRemovals.map(\.accountID) == [target])
        #expect(device.owedRemovals.map(\.reason) == [.removal(target)])
        #expect(device.writePermission(for: target) == .refused(.removalPending), "their writes are still refused")
        #expect(device.writePermission(for: target, atEpoch: device.state.epoch) == .refused(.removalPending))
        let underNewerKey = SealedRecordReference(
            recordID: UUID(), kind: .item, keyID: removal.newKeyID, version: 2)
        #expect(device.recordsToReseal(in: [underNewerKey]).isEmpty, "nothing is sealed back towards a key they hold")
        #expect(
            device.pendingRotation(
                plan: nil, leaveRequests: [], inventory: [underNewerKey], heldKeyIDs: [device.state.vaultKeyID])
                == [.removalOwed(target)])

        // Any administrator's device plans it again; it need not be the one that signed the first.
        let again = try RotationPlanner.plan(
            try #require(device.owedRemovals.first).reason, ledger: device, signedBy: household.administrator.keyset)
        device.ingest([again.record.contents])
        #expect(device.state.member(target) == nil && device.owedRemovals.isEmpty)
        #expect(![oldKey, removal.newKeyID, stale.newKeyID].contains(device.state.vaultKeyID))
        #expect(device.writePermission(for: target) == .refused(.notAMember))
        #expect(device.recordsToReseal(in: [underNewerKey]) == [underNewerKey])
    }

    /// A5, a former administrator with their key and store write access: signs removals of the remaining members on
    /// a branch from before their own removal, so that devices which keep losing records and plan "owed" removals
    /// again would empty the vault on the former administrator's say-so.
    @Test("removals a former administrator signs on a dead branch are owed by nobody")
    func deadBranchRemovalsOweNothing() async throws {
        var household = try await SharingHousehold.make()
        let former = household.administrator
        let fork = household.ledger
        try household.rotate(.removal(former.accountID), by: household.owner)

        var branch = fork
        var attack: [[UInt8]] = []
        for victim in [household.writer, household.reader] {
            let plan = try RotationPlanner.plan(.removal(victim.accountID), ledger: branch, signedBy: former.keyset)
            branch.ingest([plan.record.contents])
            attack.append(plan.record.contents)
        }
        var device = household.ledger
        let report = device.ingest(attack)
        #expect(report.outranked.count == 2 && !report.changedHead)
        #expect(device.owedRemovals.isEmpty)
        #expect(device.writePermission(for: household.writer.accountID) == .allowed)
        #expect(device.state == household.state)
    }

    /// No adversary: an administrator removes a member and then invites them back, on a branch that later loses to a
    /// longer one on which neither happened. Planning the removal again because it "lost" would do the opposite of
    /// what that administrator last decided.
    @Test("a removal its own branch took back by adding the member again is not owed")
    func removalTakenBackIsNotOwed() async throws {
        var household = try await SharingHousehold.make()
        let second = try SharingParty(seed: 42)
        try await household.add(second, as: .administrator, by: household.owner)
        let fork = household.ledger
        let target = household.writer

        var branch = fork
        let removal = try RotationPlanner.plan(.removal(target.accountID), ledger: branch, signedBy: second.keyset)
        branch.ingest([removal.record.contents])
        let readded = try branch.proposeAddition(of: Self.trusted(target), as: .readWrite, signedBy: second.keyset)

        for _ in 0..<3 {
            try household.rotate(.routine, by: household.administrator)
        }
        var device = household.ledger
        device.ingest([removal.record.contents])
        #expect(device.owedRemovals.map(\.accountID) == [target.accountID], "the removal alone is owed")
        device.ingest([readded.encoded()])
        #expect(device.owedRemovals.isEmpty, "with the record that took it back, it is not")
        #expect(device.writePermission(for: target.accountID) == .allowed)
        #expect(device.state == household.state)
        #expect(device.status(of: readded) == .superseded)
    }

    /// No adversary beyond a store that is slow (A1 at its mildest): a second device of the owner's that last synced
    /// several records ago signs an ordinary change on the head it knows, after the owner's other device removed a
    /// member. A rule that favoured the owner's earliest record would silently reinstate that member and make the
    /// key they hold current again (review finding S19).
    @Test("a stale device of the owner's does not undo a removal, and a removal it does displace is carried out again")
    func staleOwnerDevice() async throws {
        var household = try await SharingHousehold.make()
        let tablet = household.ledger
        let target = household.writer.accountID
        let guest = household.outsider
        let oldKey = household.state.vaultKeyID
        try household.adopt(
            household.ledger.proposeRoleChange(
                of: household.reader.accountID, to: .readWrite, signedBy: household.administrator.keyset
            ).encoded())
        let removal = try household.rotate(.removal(target), by: household.owner)

        // One record signed on the old head: the owner has signed once on each path, and the longer path stays.
        let invitation = try tablet.proposeAddition(
            of: Self.trusted(guest), as: .readOnly, signedBy: household.owner.keyset)
        var phone = household.ledger
        var report = phone.ingest([invitation.encoded()])
        #expect(report.superseded.isEmpty && phone.state == household.state)
        #expect(phone.state.member(target) == nil && phone.state.vaultKeyID == removal.newKeyID)
        #expect(phone.status(of: invitation) == .superseded, "the tablet invites the guest again on the new head")
        let again = try phone.proposeAddition(of: Self.trusted(guest), as: .readOnly, signedBy: household.owner.keyset)
        phone.ingest([again.encoded()])
        #expect(phone.state.member(guest.accountID) != nil && phone.state.member(target) == nil)

        // Two records signed on the old head: now the stale path carries more of the owner's signatures and wins.
        var onTablet = tablet
        onTablet.ingest([invitation.encoded()])
        let second = try onTablet.proposeRoleChange(
            of: household.reader.accountID, to: .readWrite, signedBy: household.owner.keyset)
        var device = household.ledger
        report = device.ingest([second.encoded(), invitation.encoded()])
        #expect(report.superseded.map(\.epoch) == [4, 5])
        #expect(device.state.member(target) != nil && device.state.vaultKeyID == oldKey)
        // The removal is owed, on every device that has seen it; the member writes nothing meanwhile, and what was
        // written under the newer key is not sealed again under the old one.
        #expect(device.owedRemovals.map(\.record) == [removal.proposal])
        #expect(device.writePermission(for: target) == .refused(.removalPending))
        let fresh = SealedRecordReference(
            recordID: UUID(), kind: .item, keyID: removal.newKeyID, version: 1)
        #expect(device.recordsToReseal(in: [fresh]).isEmpty)
        #expect(
            try Self.freshDevice(
                household, household.ledger.chain.map(\.encoded) + [invitation.encoded(), second.encoded()]
            ).owedRemovals == device.owedRemovals)
        // An administrator may carry it out as well as the owner: the member is not an administrator.
        let replanned = try RotationPlanner.plan(
            .removal(target), ledger: device, signedBy: household.administrator.keyset)
        device.ingest([replanned.record.contents])
        #expect(device.state.member(target) == nil && device.owedRemovals.isEmpty)
        #expect(device.state.vaultKeyID == replanned.newKeyID)
        #expect(device.recordsToReseal(in: [fresh]) == [fresh])
    }

    /// A4, a read-write member who expects to be made read-only (or an administrator who expects to be demoted, or
    /// anyone who expects the vault to be deleted): every signed byte of that record is predictable, so they create
    /// the object it would be published as first, with a signature nobody made. If a record's name did not cover
    /// its signature, a write-once store would then never take the genuine record (review finding S20).
    @Test("a predictable record cannot be blocked by creating its object first with a signature that does not verify")
    func squattedRecordName() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.readWrite, .readWrite])
        var mallory = members[0]
        var bystander = members[1]
        try await bystander.sync(vault)
        let state = try owner.ledger(vault).state

        // What the owner's record must say, with 64 bytes in place of the signature Mallory cannot make.
        var squats: [[UInt8]] = []
        for operation in [MembershipRecord.Operation.changeRole(mallory.accountID, to: .readOnly), .deleteVault] {
            let predicted = ForgedRecord(after: state, signer: owner.accountID, operation: operation)
                .withSignature([UInt8](repeating: 0, count: 64))
            try await world.store.create(
                SharingObject(try MembershipRecord.parse(predicted)).name, contents: predicted,
                by: mallory.accountID)
            squats.append(predicted)
        }
        let genuine = try owner.ledger(vault).proposeRoleChange(
            of: mallory.accountID, to: .readOnly, signedBy: owner.keyset)
        let squatted = try MembershipRecord.parse(squats[0])
        #expect(squatted.hash == genuine.hash, "the same record, as far as its hash can tell")
        #expect(SharingObject(squatted).name != SharingObject(genuine).name, "and a different object")
        let deletion = try owner.ledger(vault).proposeDeletion(signedBy: owner.keyset)
        #expect(try MembershipRecord.parse(squats[1]).hash == deletion.hash)
        #expect(SharingObject(try MembershipRecord.parse(squats[1])).name != SharingObject(deletion).name)

        try await owner.changeRole(of: mallory.accountID, to: .readOnly, in: vault)
        let report = try await bystander.sync(vault)
        try await mallory.sync(vault)
        #expect(report.adopted.map(\.hash) == [genuine.hash])
        // The squatted deletion is refused. The squatted demotion is refused too if the store lists it ahead of the
        // genuine record, and is otherwise a copy of a record already held; which, depends on the two digests.
        #expect(Set(report.rejected.map(\.reason)) == [.invalid(.signatureInvalid)])
        #expect((1...2).contains(report.rejected.count))
        for member in [owner, bystander, mallory] {
            #expect(try member.ledger(vault).state.member(mallory.accountID)?.role == .readOnly, "\(member.name)")
        }
    }

    /// A4, an administrator (hostile, or handed a substituted bundle by the key directory, A1, and careless with the
    /// comparison): removes a member the owner verified in person and adds the same account ID back with other
    /// keys. The chain's rules allow it. The owner's device must not go on to wrap the next vault key to keys its
    /// person never verified (review finding S21).
    @Test("a member whose keys were swapped in the chain is reported against the pin, and no key is wrapped to them")
    func chainKeyAgainstPin() async throws {
        var household = try await SharingHousehold.make()
        let victim = household.reader
        let impostor = try SharingParty(accountID: victim.accountID, seed: 62)
        let before = try await household.ledger.checkMemberKeys(against: household.contacts)
        #expect(before.substituted.isEmpty && before.unverified.isEmpty, "the owner verified everyone")

        try household.rotate(.removal(victim.accountID), by: household.administrator)
        try household.adopt(
            household.ledger.proposeAddition(
                of: VerifiedContact(bundle: impostor.bundle, method: .comparedByEye, verifiedAt: nil),
                as: .readOnly, signedBy: household.administrator.keyset
            ).encoded())
        let ledger = household.ledger
        #expect(ledger.state.member(victim.accountID)?.bundle.hasSameKeys(as: impostor.bundle) == true)

        let check = try await ledger.checkMemberKeys(against: household.contacts)
        #expect(check.substituted == [victim.accountID] && check.unverified.isEmpty)
        var generator = SeededGenerator(seed: 63)
        for reason in [RotationReason.routine, .removal(household.writer.accountID)] {
            #expect(throws: SharingError.keySubstituted(accountID: victim.accountID)) {
                _ = try RotationPlanner.plan(
                    reason, ledger: ledger, memberKeys: check, signedBy: household.owner.keyset, using: &generator)
            }
        }
        #expect(throws: SharingError.keySubstituted(accountID: victim.accountID)) {
            _ = try ledger.makeGrant(
                of: household.vaultKey, to: victim.accountID, memberKeys: check, from: household.administrator.keyset)
        }
        // A comparison made on an earlier head, or for another vault, does not stand in for one made now.
        #expect(throws: SharingError.memberKeysNotChecked) {
            _ = try RotationPlanner.plan(
                .routine, ledger: ledger, memberKeys: before, signedBy: household.owner.keyset, using: &generator)
        }
        #expect(throws: SharingError.memberKeysNotChecked) {
            _ = try ledger.makeGrant(
                of: household.vaultKey, to: household.writer.accountID, memberKeys: before,
                from: household.administrator.keyset)
        }

        // What the person can do about it: remove the member (no key goes to the swapped keys) ...
        let removal = try RotationPlanner.plan(
            .removal(victim.accountID), ledger: ledger, memberKeys: check, signedBy: household.owner.keyset,
            using: &generator)
        let listed = removal.grants.map { (name: $0.name, contents: $0.contents) }
        var afterwards = ledger
        afterwards.ingest([removal.record.contents])
        #expect(throws: SharingError.self) {
            _ = try afterwards.openGrant(of: removal.newKeyID, from: listed, as: impostor.keyset)
        }
        #expect(try await afterwards.checkMemberKeys(against: household.contacts).substituted.isEmpty)
        // ... or verify the new keys with the member and replace the pin, explicitly.
        _ = try await household.contacts.verify(
            impostor.bundle, evidence: .comparedByEye, signedBy: household.owner.keyset, at: Self.now,
            replacingPin: true)
        let verified = try await ledger.checkMemberKeys(against: household.contacts)
        #expect(verified.substituted.isEmpty)
        _ = try RotationPlanner.plan(
            .routine, ledger: ledger, memberKeys: verified, signedBy: household.owner.keyset, using: &generator)

        // A device with no pins of its own trusts the chain, and says so; its own keys it always knows.
        let writers = VerifiedContacts(store: InMemoryVerifiedContactStore(), account: household.writer.bundle)
        let unpinned = try await ledger.checkMemberKeys(against: writers)
        #expect(unpinned.substituted.isEmpty && unpinned.unverified.count == ledger.state.members.count - 1)
        let impostors = VerifiedContacts(store: InMemoryVerifiedContactStore(), account: victim.bundle)
        #expect(try await ledger.checkMemberKeys(against: impostors).substituted == [victim.accountID])
    }

    /// A5, a former administrator, who keeps a valid signing position at every epoch before their removal: builds
    /// many branches that each introduce the same vault key ID, a deep branch beside them, and at its tip a flood
    /// of copies of a record that names that key ID again, so that asking "has this branch used the key" costs the
    /// number of branches times the depth for every copy, before any signature is looked at (review finding S22).
    @Test("a comb of signed branches reusing one key ID costs a verifier no more than each record's own path")
    func keyReuseComb() async throws {
        let household = try await SharingHousehold.make()
        let former = household.administrator
        let teeth = 30
        let depth = 30
        let copies = 600
        let reused = UUID()
        var records: [[UInt8]] = []
        func extend(_ ledger: inout MembershipLedger, key: UUID) throws {
            let record = try ForgedRecord(
                after: ledger.state, signer: former.accountID, operation: .rotateKey, newKeyID: key
            ).signed(by: former.keyset)
            // A ledger of one path, as in `forkedHistory`: the record is that path's next.
            ledger = try Self.freshDevice(household, ledger.chain.map(\.encoded) + [record])
            records.append(record)
        }
        for _ in 0..<teeth {
            var tooth = household.ledger
            try extend(&tooth, key: UUID())
            try extend(&tooth, key: reused)
        }
        var deep = household.ledger
        for _ in 0..<depth {
            try extend(&deep, key: UUID())
        }
        let tip = ForgedRecord(after: deep.state, signer: former.accountID, operation: .rotateKey, newKeyID: reused)
        let flood = (0..<copies).map { index in
            tip.withSignature(
                [UInt8(truncatingIfNeeded: index), UInt8(truncatingIfNeeded: index >> 8)]
                    + [UInt8](repeating: 0x57, count: 62))
        }
        let genuineTip = try tip.signed(by: former.keyset)

        var ledger = household.ledger
        let report = ledger.ingest(flood + records + [genuineTip])
        #expect(report.rejected.count == copies)
        #expect(report.rejected.allSatisfy { $0.reason == .invalid(.signatureInvalid) })
        #expect(report.signatureChecks == copies + records.count + 1, "one per candidate")
        // Each signed rotation walks the rotations of its own path, and nothing else in the tree.
        #expect(report.keyHistorySteps <= (records.count + 1) * (depth + 2))
        #expect(report.keyHistorySteps < copies * teeth, "far below one walk per copy per branch")
        #expect(ledger.state.epoch == UInt64(household.state.epoch) + UInt64(depth) + 1)
        #expect(ledger.state.vaultKeyID == reused, "valid on that path: no record before it there used the ID")
        // And on a path that did use it, it is refused.
        var tooth = try Self.freshDevice(household, household.ledger.chain.map(\.encoded) + Array(records[0..<2]))
        try extend(&tooth, key: UUID())
        let twice = try ForgedRecord(
            after: tooth.state, signer: former.accountID, operation: .rotateKey, newKeyID: reused
        ).signed(by: former.keyset)
        #expect(tooth.ingest([twice]).rejected.map(\.reason) == [.invalid(.keyReused(reused))])
    }

    /// A8, with write access to this device's files: alters the saved rotation plan so that its first step takes a
    /// different member off the transport's share, or plants a whole plan that another administrator (A4) made, or
    /// one made with keys of its own (review finding S23).
    @Test("a rotation plan altered or planted on disk is refused, and cannot aim a revocation at another member")
    func plantedPlan() async throws {
        let household = try await SharingHousehold.make()
        let me = household.owner
        var generator = SeededGenerator(seed: 64)
        let plan = try RotationPlanner.plan(
            .removal(household.reader.accountID), ledger: household.ledger, signedBy: me.keyset, using: &generator)
        let bytes = plan.encoded()
        #expect(
            try RotationPlan.parse(bytes, account: me.bundle).steps(in: household.ledger).first
                == .revokeTransportAccess(household.reader.accountID))

        // The account that leaves is nowhere but in the signed record; every occurrence of it, replaced.
        let reader = ForgedRecord.bytes(household.reader.accountID)
        let other = ForgedRecord.bytes(household.administrator.accountID)
        var offset = 0
        var found = 0
        while offset + 16 <= bytes.count {
            if Array(bytes[offset..<(offset + 16)]) == reader {
                found += 1
                var altered = bytes
                altered.replaceSubrange(offset..<(offset + 16), with: other)
                #expect(throws: (any Error).self, "at \(offset)") {
                    _ = try RotationPlan.parse(altered, account: me.bundle)
                }
            }
            offset += 1
        }
        #expect(found >= 1)
        for position in bytes.indices {
            var altered = bytes
            altered[position] ^= 0x01
            #expect(throws: (any Error).self, "byte \(position)") {
                _ = try RotationPlan.parse(altered, account: me.bundle)
            }
        }

        // Another administrator's genuine plan, and a stranger's, put in its place.
        let theirs = try RotationPlanner.plan(
            .removal(household.writer.accountID), ledger: household.ledger,
            signedBy: household.administrator.keyset, using: &generator)
        #expect(throws: SharingError.savedPlanInvalid) {
            _ = try RotationPlan.parse(theirs.encoded(), account: me.bundle)
        }
        let strangersKey = VaultKey.generate(vaultID: household.vaultID, using: &generator)
        let strangersVault = try MembershipLedger.create(vaultKey: strangersKey, owner: household.outsider.keyset)
        let strangers = try RotationPlanner.plan(
            .routine, ledger: strangersVault, signedBy: household.outsider.keyset, using: &generator)
        #expect(throws: SharingError.savedPlanInvalid) {
            _ = try RotationPlan.parse(strangers.encoded(), account: me.bundle)
        }
        // The same bytes under a signature of the attacker's own, claiming to be this account's.
        let unsigned = Array(bytes.dropLast(64))
        #expect(throws: SharingError.savedPlanInvalid) {
            _ = try RotationPlan.parse(
                unsigned + household.outsider.keyset.sign(unsigned, domain: .membership), account: me.bundle)
        }
    }

    /// Anyone who can create objects in the store (A4, or A5 on a store that still takes their writes): fills the
    /// leave directory with objects whose names sort before a member's genuine request, and the member's own
    /// subdirectory with requests that say the right things under a signature nobody made, so that no
    /// administrator's device ever rotates the key the departing member holds (review finding S24).
    @Test("a flood in the leave directory does not hide a member's request to leave")
    func leaveRequestFlood() async throws {
        let household = try await SharingHousehold.make()
        let leaver = household.writer
        let request = try LeaveRequest.make(leaving: household.state, as: leaver.keyset)
        var listing: [(name: String, contents: [UInt8])] = []
        for index in 0..<5_000 {
            var account = [UInt8](repeating: 0, count: 16)
            account[14] = UInt8(truncatingIfNeeded: index >> 8)
            account[15] = UInt8(truncatingIfNeeded: index)
            let contents = [UInt8](repeating: UInt8(truncatingIfNeeded: index), count: LeaveRequest.encodedLength)
            listing.append(
                (
                    SharingObjectLocation(
                        vaultID: household.vaultID,
                        kind: .leave(account: UUID(sharingBytes: account), digest: SharingBytes.sha256(contents))
                    ).name, contents
                ))
        }
        for index in 0..<300 {
            let forged = LeaveRequest(
                vaultID: household.vaultID, accountID: leaver.accountID, memberSince: request.memberSince,
                signature: (0..<64).map { UInt8(truncatingIfNeeded: index &+ $0) })
            listing.append((SharingObject(forged).name, forged.encoded()))
        }
        // The owner cannot leave, whatever is filed under their account; and a request misfiled is not one.
        listing.append(
            (
                SharingObjectLocation(
                    vaultID: household.vaultID,
                    kind: .leave(
                        account: household.owner.accountID, digest: SharingBytes.sha256(request.encoded()))
                ).name, request.encoded()
            ))
        #expect(household.ledger.pendingLeaveRequests(among: listing).isEmpty)

        listing.sort { $0.name < $1.name }
        listing.append((SharingObject(request).name, request.encoded()))
        #expect(household.ledger.pendingLeaveRequests(among: listing) == [request])
        #expect(
            household.ledger.pendingRotation(
                plan: nil, leaveRequests: listing, inventory: [], heldKeyIDs: [household.state.vaultKeyID])
                == [.departureRequested(leaver.accountID)])
    }

    /// A1, serving the store, together with a former member X (A5): a member M who was removed is invited back
    /// after X was removed too. The store hides every membership object from M's own removal onwards. M's earlier
    /// membership and the original grant of the old key are a valid prefix of the chain, so an invitation that
    /// built a new ledger from what the store offers would put M's device back to a state older than one it had
    /// itself verified, with X a member and the old key current, and M's next item readable by X (review finding
    /// S26).
    @Test("a member invited back does not rejoin an older state than their own device had accepted")
    func reinvitationRollback() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.readWrite, .readWrite])
        var returning = members[0]
        var former = members[1]
        try await returning.sync(vault)
        try await former.sync(vault)
        let oldKeyID = try owner.ledger(vault).state.vaultKeyID

        try await owner.remove(returning.accountID, from: vault)
        try await returning.sync(vault)
        #expect(try returning.ledger(vault).state.member(returning.accountID) == nil)
        let accepted = try returning.ledger(vault).state
        try await owner.remove(former.accountID, from: vault)
        let invitation = try await owner.invite(
            returning.accountID, to: vault, as: .readWrite, safetyNumber: returning.safetyNumber)

        // The store shows the returning member the directory as it was before their removal.
        let hidden = await world.store.list(
            prefix: SharingObjectLocation.membershipPrefix(vault), viewer: returning.accountID
        ).map(\.name).filter { name in
            guard case .membership(let epoch, _, _)? = SharingObjectLocation(name: name)?.kind else { return false }
            return epoch >= accepted.epoch
        }
        await world.store.hide(hidden, from: returning.accountID)
        await #expect(throws: SharingError.notAMember(returning.accountID)) {
            try await returning.accept(invitation, ownerSafetyNumber: owner.safetyNumber)
        }
        #expect(try returning.ledger(vault).state == accepted, "still where its own device had got to")

        // What accepting without the ledger it holds would have done, and why the ledger must be passed.
        let offered = await world.store.list(
            prefix: SharingObjectLocation.membershipPrefix(vault), viewer: returning.accountID)
        let grants = await world.store.list(
            prefix: SharingObjectLocation.vaultPrefix(vault) + "grant/", viewer: returning.accountID)
        var forgetful = try await IncomingInvitation.begin(
            invitation, knownOwner: owner.accountID, directory: world.directory, contacts: returning.contacts)
        let rolledBack = try forgetful.accept(
            membership: offered.map(\.contents), grants: grants, as: returning.keyset, continuing: nil)
        #expect(rolledBack.ledger.state.epoch < accepted.epoch)
        #expect(rolledBack.ledger.state.member(former.accountID) != nil && rolledBack.vaultKey.key.keyID == oldKeyID)
        // A ledger held for the same vault ID under another owner is not this vault's.
        let othersKey = VaultKey.generate(vaultID: vault, using: &returning.generator)
        let others = try MembershipLedger.create(vaultKey: othersKey, owner: former.keyset)
        var mistaken = try await IncomingInvitation.begin(
            invitation, knownOwner: owner.accountID, directory: world.directory, contacts: returning.contacts)
        #expect(throws: SharingError.vaultOwnerConflict(vaultID: vault)) {
            _ = try mistaken.accept(
                membership: offered.map(\.contents), grants: grants, as: returning.keyset, continuing: others)
        }

        // Shown everything, the invitation goes through, on the newest state and under the newest key.
        await world.store.reveal(to: returning.accountID)
        try await returning.accept(invitation, ownerSafetyNumber: owner.safetyNumber)
        let state = try returning.ledger(vault).state
        #expect(state == (try owner.ledger(vault).state))
        #expect(state.member(former.accountID) == nil && state.vaultKeyID != oldKeyID)
        #expect(state.member(returning.accountID)?.since == state.epoch)
        let secret = UUID()
        try await returning.write("new secret", to: vault, recordID: secret, version: 1)
        try await owner.sync(vault)
        #expect(try await owner.readable(in: vault)[secret] == "new secret")
        #expect(try await former.items(in: vault).allSatisfy { $0.outcome != .read("new secret") })
    }

    /// A1, serving the store, with an honest administrator and the owner acting at once: shows the administrator's
    /// device only its own record until it has adopted it, then the owner's, which wins. A device that looked only
    /// at what a sync reports as superseded, or that forgot what it had proposed, would drop the administrator's
    /// change without a word (review finding S27).
    @Test("a change that loses a fork is proposed again by its author's device, not silently dropped")
    func lostProposalIsProposedAgain() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.administrator, .readWrite, .readOnly])
        var admin = members[0]
        let writer = members[1].accountID
        let reader = members[2].accountID
        try await admin.sync(vault)

        // The owner's record is on the store; the administrator's device is not shown it.
        let owners = try owner.ledger(vault).proposeRoleChange(of: reader, to: .readWrite, signedBy: owner.keyset)
        try await world.store.create(SharingObject(owners).name, contents: owners.encoded(), by: owner.accountID)
        await world.store.hide([SharingObject(owners).name], from: admin.accountID)
        try await admin.changeRole(of: writer, to: .readOnly, in: vault)
        #expect(try admin.ledger(vault).state.member(writer)?.role == .readOnly)
        #expect(admin.proposals[vault]?.isEmpty == true, "adopted, as far as this device could see")

        // Shown both, it reorganises onto the owner's record, and its own change goes out again on the new head.
        await world.store.reveal(to: admin.accountID)
        let report = try await admin.sync(vault)
        #expect(report.superseded.map(\.operation) == [.changeRole(writer, to: .readOnly)])
        try await owner.sync(vault)
        for member in [owner, admin] {
            let state = try member.ledger(vault).state
            #expect(state.epoch == 5, "\(member.name)")
            #expect(state.member(reader)?.role == .readWrite && state.member(writer)?.role == .readOnly)
        }
        #expect(try owner.ledger(vault).state == admin.ledger(vault).state)
    }

    // MARK: - Oversized and malformed input

    /// A1 (and, for a scanned code, anyone who can show the person a QR code): feeds every parser oversized input,
    /// and randomly damaged copies of genuine objects, looking for a crash, a hang, or a damaged object that is
    /// accepted as something other than itself.
    @Test("every sharing parser survives damaged input: it throws, or returns exactly what the bytes say")
    func malformedInput() async throws {
        var household = try await SharingHousehold.make()
        let request = try LeaveRequest.make(leaving: household.state, as: household.writer.keyset)
        let plan = try household.rotate(.departure(request), by: household.owner)
        let record = household.ledger.chain[2].encoded
        let grant = plan.grants[0].contents
        let bundle = KeyBundleCodec.encode(household.owner.bundle)
        let saved = try household.ledger.persisted(signedBy: household.owner.keyset)
        let invitation = Invitation(vaultID: household.vaultID, ownerAccountID: household.owner.accountID).encoded()
        let owner = Self.trusted(household.owner)

        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 61))
        func damaged(_ bytes: [UInt8]) -> [UInt8] {
            var out = bytes
            switch Int.random(in: 0..<4, using: &generator) {
            case 0: out[Int.random(in: out.indices, using: &generator)] = .random(in: .min ... .max, using: &generator)
            case 1: out.removeLast(Int.random(in: 1...min(out.count, 40), using: &generator))
            case 2: out += (0..<Int.random(in: 1...40, using: &generator)).map { _ in 0xFF }
            default:
                let at = Int.random(in: out.indices, using: &generator)
                out.insert(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF], at: at)
            }
            return out
        }
        for _ in 0..<TestEnvironment.iterations(standard: 1_500, long: 100_000) {
            let badRecord = damaged(record)
            if let parsed = try? MembershipRecord.parse(badRecord) { #expect(parsed.encoded() == badRecord) }
            let badGrant = damaged(grant)
            if let parsed = try? KeyGrantCodec.parse(badGrant) { #expect(try KeyGrantCodec.encode(parsed) == badGrant) }
            let badRequest = damaged(request.encoded())
            if let parsed = try? LeaveRequest.parse(badRequest) { #expect(parsed.encoded() == badRequest) }
            let badInvitation = damaged(invitation)
            if let parsed = try? Invitation.parse(badInvitation) { #expect(parsed.encoded() == badInvitation) }
            let badBundle = damaged(bundle)
            if let parsed = try? KeyBundleCodec.parse(badBundle, expecting: household.owner.accountID) {
                #expect(KeyBundleCodec.encode(parsed) == badBundle)
            }
            let badPlan = damaged(plan.encoded())
            if let parsed = try? RotationPlan.parse(badPlan, account: household.owner.bundle) {
                #expect(parsed.encoded() == badPlan)
            }
        }
        for _ in 0..<TestEnvironment.iterations(standard: 60, long: 2_000) {
            let badSaved = damaged(saved)
            let restored = try? MembershipLedger.restore(
                badSaved, vaultID: household.vaultID, owner: owner, account: household.owner.bundle)
            #expect(restored == nil || restored?.state == household.state)
        }

        // Oversized, before anything is parsed.
        let huge = [UInt8](repeating: 0x57, count: 1 << 20)
        #expect(throws: SharingFormatError.tooLarge(huge.count)) { _ = try MembershipRecord.parse(huge) }
        #expect(throws: SharingFormatError.tooLarge(huge.count)) { _ = try KeyGrantCodec.parse(huge) }
        #expect(throws: SharingFormatError.tooLarge(huge.count)) { _ = try LeaveRequest.parse(huge) }
        #expect(throws: SharingFormatError.tooLarge(huge.count)) { _ = try Invitation.parse(huge) }
        #expect(throws: SharingFormatError.tooLarge(huge.count)) {
            _ = try RotationPlan.parse(huge, account: household.owner.bundle)
        }
        #expect(throws: SharingFormatError.tooLarge(huge.count)) {
            _ = try KeyBundleCodec.parse(huge, expecting: household.owner.accountID)
        }
        #expect(throws: SharingFormatError.malformedText) {
            _ = try FingerprintCode(scanned: String(repeating: "W", count: 1 << 20))
        }
        #expect(SharingObjectLocation(name: String(repeating: "sharing/", count: 1 << 16)) == nil)
        #expect(!household.owner.bundle.fingerprint.matches(safetyNumber: String(repeating: "1", count: 1 << 20)))

        // A persisted ledger that declares more records than it could hold.
        var inflated = Array(saved[..<173])
        inflated += [0xFF, 0xFF, 0xFF, 0xFF]
        #expect(throws: SharingFormatError.countTooLarge) {
            _ = try MembershipLedger.restore(
                inflated, vaultID: household.vaultID, owner: owner, account: household.owner.bundle)
        }

        // No number of candidates is one too many: each is examined, and the ledger is where it was.
        var ledger = household.ledger
        let report = ledger.ingest(Array(repeating: [0x57], count: 70_000))
        #expect(report.rejected.count == 70_000 && ledger.state == household.state)
        #expect(throws: LedgerError.noGenesis) {
            _ = try MembershipLedger.join(
                vaultID: household.vaultID, owner: owner, candidates: Array(repeating: [], count: 70_000))
        }
    }

    /// A1, with write access to the store and no key: floods the membership directory with unsigned records that
    /// name a real administrator and a vault key the chain has used before, each of which would make a verifier ask
    /// "was this key used on this branch", to make every sync cost time in proportion to the flood times the chain's
    /// length (review finding S9).
    @Test("a flood of unsigned records naming a reused key costs one signature check each and no walk")
    func reusedKeyFlood() async throws {
        var household = try await SharingHousehold.make()
        let genesisKey = household.state.vaultKeyID
        for _ in 0..<12 {
            try household.rotate(.routine, by: household.owner)
        }
        var ledger = household.ledger
        let flood: [[UInt8]] = (0..<4_096).map { index in
            var forged = household.forgery(.rotateKey, signer: household.administrator, newKeyID: genesisKey)
            forged.entries[0].since = UInt64(index % 3)
            return forged.withSignature([UInt8](repeating: UInt8(truncatingIfNeeded: index), count: 64))
        }
        var report = ledger.ingest(flood)
        #expect(ledger.state == household.state)
        #expect(report.rejected.allSatisfy { $0.reason == .invalid(.signatureInvalid) })
        #expect(report.rejected.count == 256 * 3, "one per distinct candidate; exact copies are not looked at twice")
        #expect(report.signatureChecks == report.rejected.count && report.keyHistorySteps == 0)

        // Signed by an administrator, the reuse is what it is refused for, at the cost of one walk over the
        // chain's rotations.
        report = ledger.ingest([
            try household.forgery(.rotateKey, signer: household.administrator, newKeyID: genesisKey)
                .signed(by: household.administrator.keyset)
        ])
        #expect(report.rejected.map(\.reason) == [.invalid(.keyReused(genesisKey))])
        #expect(report.keyHistorySteps == 13)
    }
}
