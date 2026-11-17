import Foundation
import Testing
import WatchwordCrypto
import WatchwordTestSupport

@testable import WatchwordSharing

/// Every state transition of the membership chain and every refusal (docs/02-architecture.md §8.3; PRD F4.1, F4.3,
/// F4.4, F4.5).
@Suite("Membership chain rules")
struct MembershipChainTests {
    @Test("the genesis lists the owner alone, and the household fixture reaches one member of each role")
    func genesisAndRoles() async throws {
        let household = try await SharingHousehold.make()
        let genesis = household.ledger.chain[0].state
        #expect(genesis.epoch == 0)
        #expect(genesis.members.map(\.accountID) == [household.owner.accountID])
        #expect(genesis.owner.role == .owner)
        #expect(genesis.keyEpoch == 0)
        #expect(genesis.vaultKeyID == household.vaultKey.key.keyID)

        let state = household.state
        #expect(state.epoch == 3)
        #expect(state.member(household.owner.accountID)?.role == .owner)
        #expect(state.member(household.administrator.accountID)?.role == .administrator)
        #expect(state.member(household.writer.accountID)?.role == .readWrite)
        #expect(state.member(household.reader.accountID)?.role == .readOnly)
        #expect(state.member(household.outsider.accountID) == nil)
        #expect(state.member(household.writer.accountID)?.since == 2)
        #expect(state.vaultKeyID == genesis.vaultKeyID, "adding members does not change the key")
        #expect(state.keyEpoch == 0)
        #expect(
            state.members.map(\.accountID.uuidString).sorted() == state.members.map(\.accountID.uuidString),
            "members are in account order")
    }

    @Test("an administrator may add and remove ordinary members, change their roles and rotate the key")
    func administratorOperations() async throws {
        var household = try await SharingHousehold.make()
        let admin = household.administrator
        let guest = try SharingParty(seed: 50)

        try await household.add(guest, as: .readOnly, by: admin)
        #expect(household.state.member(guest.accountID)?.role == .readOnly)
        #expect(household.state.member(guest.accountID)?.since == 4)

        try household.adopt(
            household.ledger.proposeRoleChange(of: guest.accountID, to: .readWrite, signedBy: admin.keyset).encoded())
        #expect(household.state.member(guest.accountID)?.role == .readWrite)
        #expect(household.state.member(guest.accountID)?.since == 4, "a role change keeps the stint")

        let before = household.state.vaultKeyID
        try household.rotate(.removal(guest.accountID), by: admin)
        #expect(household.state.member(guest.accountID) == nil)
        #expect(household.state.vaultKeyID != before, "a removal names a new key")
        #expect(household.state.keyEpoch == household.state.epoch)

        let afterRemoval = household.state.vaultKeyID
        try household.rotate(.routine, by: admin)
        #expect(household.state.vaultKeyID != afterRemoval)
        #expect(household.state.members.count == 4)
    }

    @Test("the owner alone grants and revokes the administrator role, removes an administrator and deletes the vault")
    func ownerOnlyOperations() async throws {
        var household = try await SharingHousehold.make()
        let owner = household.owner
        let admin = household.administrator
        let second = try SharingParty(seed: 51)

        // An administrator may not do any of it.
        await #expect(throws: MembershipError.ownerOnly) {
            try await household.add(second, as: .administrator, by: admin)
        }
        #expect(throws: MembershipError.ownerOnly) {
            _ = try household.ledger.proposeRoleChange(
                of: household.writer.accountID, to: .administrator, signedBy: admin.keyset)
        }
        #expect(throws: MembershipError.ownerOnly) {
            _ = try household.ledger.proposeDeletion(signedBy: admin.keyset)
        }

        // The owner may.
        try await household.add(second, as: .administrator, by: owner)
        #expect(throws: MembershipError.ownerOnly, "one administrator cannot demote another") {
            _ = try household.ledger.proposeRoleChange(of: second.accountID, to: .readWrite, signedBy: admin.keyset)
        }
        #expect(throws: MembershipError.ownerOnly, "one administrator cannot remove another") {
            _ = try RotationPlanner.plan(.removal(second.accountID), ledger: household.ledger, signedBy: admin.keyset)
        }
        try household.adopt(
            household.ledger.proposeRoleChange(of: second.accountID, to: .readWrite, signedBy: owner.keyset)
                .encoded())
        try household.rotate(.removal(admin.accountID), by: owner)
        #expect(household.state.member(admin.accountID) == nil)

        try household.adopt(household.ledger.proposeDeletion(signedBy: owner.keyset).encoded())
        #expect(household.state.isDeleted)
        #expect(throws: SharingError.vaultDeleted) {
            _ = try household.ledger.proposeRoleChange(of: second.accountID, to: .readOnly, signedBy: owner.keyset)
        }
        #expect(throws: SharingError.vaultDeleted) {
            _ = try RotationPlanner.plan(.routine, ledger: household.ledger, signedBy: owner.keyset)
        }
    }

    @Test("the owner is fixed: never removed, never re-roled, never joined by a second owner")
    func ownerIsFixed() async throws {
        let household = try await SharingHousehold.make()
        let owner = household.owner
        for signer in [owner, household.administrator] {
            #expect(throws: MembershipError.ownerIsFixed) {
                _ = try RotationPlanner.plan(
                    .removal(owner.accountID), ledger: household.ledger, signedBy: signer.keyset)
            }
            #expect(throws: MembershipError.ownerIsFixed) {
                _ = try household.ledger.proposeRoleChange(
                    of: owner.accountID, to: .administrator, signedBy: signer.keyset)
            }
            #expect(throws: MembershipError.ownerIsFixed) {
                _ = try household.ledger.proposeRoleChange(
                    of: household.writer.accountID, to: .owner, signedBy: signer.keyset)
            }
        }
        await #expect(throws: MembershipError.ownerIsFixed) {
            _ = try household.ledger.proposeAddition(
                of: await household.contact(household.outsider), as: .owner, signedBy: owner.keyset)
        }
        #expect(throws: SharingError.ownerCannotLeave) {
            _ = try LeaveRequest.make(leaving: household.state, as: owner.keyset)
        }
    }

    @Test("members who are not administrators cannot propose anything, and nor can an outsider")
    func nonAdministratorsCannotPropose() async throws {
        let household = try await SharingHousehold.make()
        for party in [household.writer, household.reader, household.outsider] {
            #expect(throws: SharingError.notPermitted) {
                _ = try household.ledger.proposeRoleChange(
                    of: household.reader.accountID, to: .readWrite, signedBy: party.keyset)
            }
            #expect(throws: SharingError.notPermitted) {
                _ = try RotationPlanner.plan(.routine, ledger: household.ledger, signedBy: party.keyset)
            }
        }
    }

    @Test("operations that make no sense are refused with the reason")
    func senselessOperations() async throws {
        var household = try await SharingHousehold.make()
        let owner = household.owner
        await #expect(throws: MembershipError.memberAlreadyPresent(household.writer.accountID)) {
            try await household.add(household.writer, as: .readOnly, by: owner)
        }
        #expect(throws: MembershipError.memberNotFound(household.outsider.accountID)) {
            _ = try household.ledger.proposeRoleChange(
                of: household.outsider.accountID, to: .readOnly, signedBy: owner.keyset)
        }
        #expect(throws: MembershipError.roleUnchanged) {
            _ = try household.ledger.proposeRoleChange(
                of: household.reader.accountID, to: .readOnly, signedBy: owner.keyset)
        }
        #expect(throws: SharingError.nothingToDo, "removing someone who is not there is already done") {
            _ = try RotationPlanner.plan(
                .removal(household.outsider.accountID), ledger: household.ledger, signedBy: owner.keyset)
        }
    }

    /// Records the module would never sign, checked by the verifier that every other device runs.
    @Test("the verifier refuses records that break a rule, whoever signed them")
    func verifierRefusals() async throws {
        var household = try await SharingHousehold.make()
        let owner = household.owner
        let admin = household.administrator
        let writer = household.writer
        let fresh = household.newKeyID()
        let genesisKey = household.ledger.chain[0].state.vaultKeyID
        func refusal(_ forged: ForgedRecord, signedBy party: SharingParty) throws -> MembershipError? {
            var copy = household
            do {
                try copy.adopt(forged.signed(by: party.keyset))
                return nil
            } catch let error as MembershipError {
                return error
            }
        }

        // Position in the chain.
        var skipped = household.forgery(.rotateKey, signer: owner, newKeyID: fresh)
        skipped.epoch += 1
        skipped.keyEpoch += 1
        #expect(try refusal(skipped, signedBy: owner) == .epochNotNext(expected: 4, actual: 5))
        var elsewhere = household.forgery(.rotateKey, signer: owner, newKeyID: fresh)
        elsewhere.previousHash[0] ^= 1
        #expect(try refusal(elsewhere, signedBy: owner) == .previousHashMismatch, "reported as unconnected")
        var otherVault = household.forgery(.rotateKey, signer: owner, newKeyID: fresh)
        otherVault.vaultID = UUID()
        #expect(
            try refusal(otherVault, signedBy: owner)
                == .wrongVault(expected: household.vaultID, actual: otherVault.vaultID))
        #expect(try refusal(household.forgery(.createVault, signer: owner), signedBy: owner) == .malformedGenesis)

        // The signer's standing.
        #expect(
            try refusal(household.forgery(.rotateKey, signer: writer, newKeyID: fresh), signedBy: writer)
                == .signerNotAdministrator(writer.accountID))
        #expect(
            try refusal(
                household.forgery(.rotateKey, signer: household.outsider, newKeyID: fresh),
                signedBy: household.outsider) == .signerNotAMember(household.outsider.accountID))
        #expect(
            try refusal(household.forgery(.rotateKey, signer: owner, newKeyID: fresh), signedBy: admin)
                == .signatureInvalid, "claims the owner signed it; the administrator did")

        // What each role may do.
        #expect(
            try refusal(
                household.forgery(.changeRole(writer.accountID, to: .administrator), signer: admin), signedBy: admin)
                == .ownerOnly)
        #expect(try refusal(household.forgery(.deleteVault, signer: admin), signedBy: admin) == .ownerOnly)
        #expect(
            try refusal(
                household.forgery(.removeMember(owner.accountID), signer: admin, newKeyID: fresh),
                signedBy: admin) == .ownerIsFixed)
        #expect(
            try refusal(
                household.forgery(
                    .addMember(household.outsider.accountID, role: .owner), signer: owner,
                    adding: household.outsider.bundle), signedBy: owner) == .ownerIsFixed)

        // The key rule.
        #expect(
            try refusal(household.forgery(.removeMember(writer.accountID), signer: owner), signedBy: owner)
                == .keyNotRotated, "a removal that keeps the key the removed member holds")
        #expect(
            try refusal(
                household.forgery(.changeRole(writer.accountID, to: .readOnly), signer: owner, newKeyID: fresh),
                signedBy: owner) == .unexpectedKeyChange)
        var zeroKey = household.forgery(.rotateKey, signer: owner, newKeyID: fresh)
        zeroKey.vaultKeyID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        #expect(try refusal(zeroKey, signedBy: owner) == .keyReused(zeroKey.vaultKeyID))
        var wrongKeyEpoch = household.forgery(.rotateKey, signer: owner, newKeyID: fresh)
        wrongKeyEpoch.keyEpoch = 2
        #expect(try refusal(wrongKeyEpoch, signedBy: owner) == .unexpectedKeyChange)
        try household.rotate(.routine, by: owner)
        #expect(
            try refusal(household.forgery(.rotateKey, signer: owner, newKeyID: genesisKey), signedBy: owner)
                == .keyReused(genesisKey), "going back to a key a former member may hold")

        // The resulting member list must be the previous one with the operation applied, and nothing else.
        var keepsRemoved = household.forgery(.removeMember(writer.accountID), signer: owner, newKeyID: fresh)
        keepsRemoved.entries = household.state.members.map(ForgedEntry.init)
        #expect(try refusal(keepsRemoved, signedBy: owner) == .resultingMembersMismatch)
        var smuggled = household.forgery(.rotateKey, signer: admin, newKeyID: fresh)
        smuggled.entries.append(ForgedEntry(bundle: household.outsider.bundle, role: .readWrite, since: 5))
        #expect(try refusal(smuggled, signedBy: admin) == .resultingMembersMismatch, "a member slipped into a rotation")
        var promoted = household.forgery(.rotateKey, signer: admin, newKeyID: fresh)
        for index in promoted.entries.indices where promoted.entries[index].accountID == writer.accountID {
            promoted.entries[index].role = MemberRole.administrator.rawValue
        }
        #expect(try refusal(promoted, signedBy: admin) == .resultingMembersMismatch, "a role changed on the side")
        var swappedKey = household.forgery(.rotateKey, signer: admin, newKeyID: fresh)
        for index in swappedKey.entries.indices where swappedKey.entries[index].accountID == writer.accountID {
            swappedKey.entries[index].agreementKey = household.outsider.bundle.agreementKey
        }
        #expect(try refusal(swappedKey, signedBy: admin) == .resultingMembersMismatch, "a member's key replaced")
        var backdated = household.forgery(
            .addMember(household.outsider.accountID, role: .readOnly), signer: owner,
            adding: household.outsider.bundle)
        backdated.entries[backdated.entries.count - 1].since = 1
        #expect(try refusal(backdated, signedBy: owner) == .resultingMembersMismatch)
        var badBundle = household.forgery(
            .addMember(household.outsider.accountID, role: .readOnly), signer: owner,
            adding: household.outsider.bundle)
        badBundle.entries[badBundle.entries.count - 1].selfSignature[0] ^= 1
        #expect(try refusal(badBundle, signedBy: owner) == .invalidKeyBundle(household.outsider.accountID))
        let forgedLeave = household.forgery(
            .memberLeft(writer.accountID, requestSignature: [UInt8](repeating: 7, count: 64)), signer: owner,
            newKeyID: fresh)
        #expect(try refusal(forgedLeave, signedBy: owner) == .leaveRequestInvalid, "'left' needs the member's word")

        // Nothing follows a deletion.
        try household.adopt(household.ledger.proposeDeletion(signedBy: owner.keyset).encoded())
        #expect(
            try refusal(household.forgery(.rotateKey, signer: owner, newKeyID: fresh), signedBy: owner)
                == .vaultDeleted)
    }

    @Test("a vault holds at most the maximum number of members")
    func memberLimit() async throws {
        var household = try await SharingHousehold.make()
        for index in 0..<(MembershipLimits.maximumMembers - 4) {
            try await household.add(try SharingParty(seed: 10_000 + UInt64(index)), as: .readOnly, by: household.owner)
        }
        #expect(household.state.members.count == MembershipLimits.maximumMembers)
        let onceMore = try SharingParty(seed: 99_999)
        await #expect(throws: MembershipError.tooManyMembers) {
            try await household.add(onceMore, as: .readOnly, by: household.owner)
        }
        #expect(household.ledger.chain.last!.encoded.count <= MembershipRecord.maximumLength)
    }

    @Test("the chain's last epochs are the owner's, so an administrator cannot use it up")
    func epochsReservedForOwner() async throws {
        let household = try await SharingHousehold.make()
        let late = MembershipState(
            vaultID: household.vaultID, epoch: MembershipLimits.maximumAdministratorEpoch,
            hash: household.state.hash, members: household.state.members, vaultKeyID: household.state.vaultKeyID,
            keyEpoch: 0, isDeleted: false)
        func next(by party: SharingParty) throws -> MembershipState {
            let forged = ForgedRecord(after: late, signer: party.accountID, operation: .rotateKey, newKeyID: UUID())
            let record = try MembershipRecord.parse(forged.signed(by: party.keyset))
            return try MembershipRules.nextState(record, hash: record.hash, after: late, keyUsedBefore: { _ in false })
        }
        #expect(throws: MembershipError.epochReservedForOwner) { _ = try next(by: household.administrator) }
        #expect(try next(by: household.owner).epoch == MembershipLimits.maximumAdministratorEpoch + 1)
        #expect(MembershipLimits.maximumAdministratorEpoch < MembershipLimits.maximumEpoch)
    }

    @Test("write permission follows the role, the epoch asked about, and deletion")
    func writePermission() async throws {
        var household = try await SharingHousehold.make()
        let ledger = household.ledger
        #expect(ledger.writePermission(for: household.owner.accountID, atEpoch: 3) == .allowed)
        #expect(ledger.writePermission(for: household.administrator.accountID, atEpoch: 3) == .allowed)
        #expect(ledger.writePermission(for: household.writer.accountID, atEpoch: 3) == .allowed)
        #expect(ledger.writePermission(for: household.reader.accountID, atEpoch: 3) == .refused(.readOnly))
        #expect(ledger.writePermission(for: household.outsider.accountID, atEpoch: 3) == .refused(.notAMember))
        #expect(
            ledger.writePermission(for: household.writer.accountID, atEpoch: 1) == .refused(.notAMember),
            "not yet a member at epoch 1")
        #expect(ledger.writePermission(for: household.writer.accountID, atEpoch: 4) == .refused(.unknownEpoch))
        #expect(WritePermission.allowed.isAllowed)
        #expect(!WritePermission.refused(.readOnly).isAllowed)

        try household.adopt(
            household.ledger.proposeRoleChange(
                of: household.writer.accountID, to: .readOnly, signedBy: household.owner.keyset
            ).encoded())
        #expect(household.ledger.writePermission(for: household.writer.accountID, atEpoch: 4) == .refused(.readOnly))
        #expect(household.ledger.writePermission(for: household.writer.accountID, atEpoch: 3) == .allowed)

        try household.rotate(.removal(household.writer.accountID), by: household.owner)
        #expect(household.state.writePermission(for: household.writer.accountID) == .refused(.notAMember))

        try household.adopt(household.ledger.proposeDeletion(signedBy: household.owner.keyset).encoded())
        #expect(household.state.writePermission(for: household.owner.accountID) == .refused(.vaultDeleted))
    }
}
