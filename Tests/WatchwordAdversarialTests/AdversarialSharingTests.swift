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
                let report = try ledger.ingest([mutated])
                #expect(report.rejected.count == 1, "flip \(mask) at byte \(position)")
                #expect(ledger.state == household.state, "flip \(mask) at byte \(position)")
            }
        }
        #expect(try ledger.ingest([genuine]).adopted.count == 1)
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
        let report = try ledger.ingest([
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
        let report = try ledger.ingest([spoilt, genuine, spoilt])
        #expect(ledger.state.member(household.reader.accountID)?.role == .readWrite)
        #expect(report.rejected.map(\.index) == [0])
        #expect(report.rejected.map(\.reason) == [.invalid(.signatureInvalid)])

        // And once the genuine record is held, the spoilt copy is just a copy.
        #expect(try ledger.ingest([spoilt]).rejected.isEmpty)
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
            let report = try ledger.ingest([forged.withSignature(signature)])
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
        var report = try ledger.ingest([
            household.forgery(.rotateKey, signer: former, newKeyID: UUID()).signed(by: former.keyset)
        ])
        #expect(report.rejected.map(\.reason) == [.invalid(.signerNotAdministrator(former.accountID))])
        #expect(throws: SharingError.notPermitted) {
            _ = try RotationPlanner.plan(.routine, ledger: household.ledger, signedBy: former.keyset)
        }

        try household.rotate(.removal(former.accountID), by: household.owner)
        ledger = household.ledger
        report = try ledger.ingest([
            household.forgery(.rotateKey, signer: former, newKeyID: UUID()).signed(by: former.keyset),
            household.forgery(
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
        _ = try branch.ingest([rewrite.record.contents])
        let further = try RotationPlanner.plan(.routine, ledger: branch, signedBy: former.keyset)
        let attack = [rewrite.record.contents, further.record.contents]

        // A device that has the real chain is not moved.
        var informed = household.ledger
        let report = try informed.ingest(attack)
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
        _ = try misled.ingest(attack)
        #expect(misled.state.member(former.accountID) != nil)
        let correction = try misled.ingest(genuine)
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
        let report = try ledger.ingest(attempts)
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
                grants: [(name: grant.location.name, contents: grant.encoded)], as: guest.keyset)
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
    /// and other recipients, more than a reader examines, so that a newly invited member never reaches their own
    /// grant (review finding S10).
    @Test("a flood of grant objects for other keys and members does not hide a member's own grant")
    func grantFlood() async throws {
        var household = try await SharingHousehold.make()
        let plan = try household.rotate(.routine, by: household.owner)
        let junk = (0...MembershipLimits.maximumCandidates).map { index -> (name: String, contents: [UInt8]) in
            let contents = [UInt8(truncatingIfNeeded: index), UInt8(truncatingIfNeeded: index >> 8)]
            let location = SharingObjectLocation.grant(
                vaultID: household.vaultID, keyID: index.isMultiple(of: 2) ? plan.newKeyID : UUID(),
                recipient: index.isMultiple(of: 2) ? household.outsider.accountID : household.writer.accountID,
                contents: contents)
            return (location.name, contents)
        }
        let listing = junk + plan.grants.map { (name: $0.name, contents: $0.contents) }
        #expect(listing.count > MembershipLimits.maximumCandidates)
        let key = try household.ledger.openGrant(of: plan.newKeyID, from: listing, as: household.writer.keyset)
        #expect(key.key.material.constantTimeEquals(household.vaultKey.key.material))
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
        _ = try theirs.ingest([
            theirs.proposeAddition(of: victimContact, as: .readWrite, signedBy: attacker.keyset).encoded()
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
    @Test("writes by a former member or a read-only member reach the store and are refused by every remaining member")
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
        let signature = try former.keyset.sign(Array(name.utf8) + [0] + envelope, domain: .logSegment)
        await world.store.tamper(name, contents: signature + envelope)

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
            let report = try ledger.ingest(offered)
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
        _ = try stale.ingest(household.ledger.chain.map(\.encoded))
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
        #expect(adminReport.superseded == [adminsRecord])
        for member in [owner, admin, bystander] {
            #expect(try member.ledger(vault).state.hash == ownersRecord.hash, "\(member.name)")
        }
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
            let report = try ledger.ingest([forged.signed(by: signer.keyset)])
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

        #expect(household.ledger.pendingLeaveRequests(among: [request.encoded()]).isEmpty)
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
            try ledger.ingest([forged.signed(by: household.administrator.keyset)]).rejected.map(\.reason)
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
            _ = try third.ingest([record.encoded()])
        }
        #expect(third.state.member(household.reader.accountID)?.since == elsewhere.memberSince)
        #expect(third.pendingLeaveRequests(among: [elsewhere.encoded()]).isEmpty)
        #expect(throws: SharingError.leaveRequestInvalid) {
            _ = try RotationPlanner.plan(.departure(elsewhere), ledger: third, signedBy: household.owner.keyset)
        }
        let relabelled = LeaveRequest(
            vaultID: third.vaultID, accountID: elsewhere.accountID, memberSince: elsewhere.memberSince,
            signature: elsewhere.signature)
        #expect(third.pendingLeaveRequests(among: [relabelled.encoded()]).isEmpty)
        #expect(throws: SharingError.leaveRequestInvalid) { try relabelled.validate(against: third.state) }
        #expect(household.ledger.pendingLeaveRequests(among: [elsewhere.encoded()]) == [elsewhere], "valid at home")

        // A request signed by someone other than the member it names.
        let impersonated = LeaveRequest(
            vaultID: household.vaultID, accountID: household.reader.accountID, memberSince: 3,
            signature: try household.administrator.keyset.sign(
                LeaveRequest.signedContent(
                    vaultID: household.vaultID, accountID: household.reader.accountID, memberSince: 3),
                domain: .membership))
        #expect(household.ledger.pendingLeaveRequests(among: [impersonated.encoded()]).isEmpty)
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
            let report = try ledger.ingest(order)
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
                _ = try ledger.ingest([record])
            }
            #expect(ledger.state.hash == removal.recordHash)
            #expect(ledger.state.member(admin.accountID) == nil)
            #expect(ledger.state.owner.accountID == household.owner.accountID)
            // Nobody is locked out: the owner signs the next record.
            let next = try RotationPlanner.plan(.routine, ledger: ledger, signedBy: household.owner.keyset)
            #expect(try ledger.ingest([next.record.contents]).adopted.count == 1)
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
            if let parsed = try? RotationPlan.parse(badPlan) { #expect(parsed.encoded() == badPlan) }
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
        #expect(throws: SharingFormatError.tooLarge(huge.count)) { _ = try RotationPlan.parse(huge) }
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

        // More candidates than one call examines.
        var ledger = household.ledger
        #expect(throws: LedgerError.tooManyCandidates(MembershipLimits.maximumCandidates + 1)) {
            _ = try ledger.ingest(Array(repeating: record, count: MembershipLimits.maximumCandidates + 1))
        }
        #expect(throws: LedgerError.tooManyCandidates(MembershipLimits.maximumJoinCandidates + 1)) {
            _ = try MembershipLedger.join(
                vaultID: household.vaultID, owner: owner,
                candidates: Array(repeating: [], count: MembershipLimits.maximumJoinCandidates + 1))
        }
    }

    /// A1, with write access to the store: floods the membership directory with unsigned records that name a real
    /// administrator and a vault key the chain has used before, each of which makes the verifier ask "was this key
    /// used on this branch", to make every sync cost time in proportion to the flood times the chain's length.
    @Test("a flood of unsigned records naming a reused key is refused without a signature check each")
    func reusedKeyFlood() async throws {
        var household = try await SharingHousehold.make()
        let genesisKey = household.state.vaultKeyID
        for _ in 0..<12 {
            try household.rotate(.routine, by: household.owner)
        }
        var ledger = household.ledger
        let flood: [[UInt8]] = (0..<MembershipLimits.maximumCandidates).map { index in
            var forged = household.forgery(.rotateKey, signer: household.administrator, newKeyID: genesisKey)
            forged.entries[0].since = UInt64(index % 3)
            return forged.withSignature([UInt8](repeating: UInt8(truncatingIfNeeded: index), count: 64))
        }
        let report = try ledger.ingest(flood)
        #expect(ledger.state == household.state)
        #expect(report.rejected.allSatisfy { $0.reason == .invalid(.keyReused(genesisKey)) })
        #expect(report.rejected.count >= 3)
    }
}
