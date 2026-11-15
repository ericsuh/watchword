import Foundation
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordTestSupport

@testable import WatchwordSharing

/// Key grants, leave requests and rotation plans (docs/02-architecture.md §8.5, §8.6; PRD F4.3, F4.4, SEC3).
@Suite("Key grants and rotation")
struct KeyGrantAndRotationTests {
    static func objects(_ plan: RotationPlan) -> [(name: String, contents: [UInt8])] {
        plan.grants.map { (name: $0.name, contents: $0.contents) }
    }

    // MARK: - Grants

    @Test("a grant has one fixed encoding and is refused at any other length")
    func grantEncoding() async throws {
        var household = try await SharingHousehold.make()
        let plan = try household.rotate(.routine, by: household.owner)
        let bytes = plan.grants[0].contents
        #expect(bytes.count == KeyGrantCodec.encodedLength)
        let grant = try KeyGrantCodec.parse(bytes)
        #expect(try KeyGrantCodec.encode(grant) == bytes)
        #expect(grant.vaultID == household.vaultID)
        #expect(grant.keyID == plan.newKeyID)
        for length in 0..<bytes.count {
            #expect(throws: SharingFormatError.self) { _ = try KeyGrantCodec.parse(Array(bytes[0..<length])) }
        }
        #expect(throws: SharingFormatError.tooLarge(bytes.count + 1)) { _ = try KeyGrantCodec.parse(bytes + [0]) }
        let short = VaultKeyGrant(
            vaultID: grant.vaultID, keyID: grant.keyID, senderAccountID: grant.senderAccountID,
            recipientAccountID: grant.recipientAccountID, recipientAgreementKey: grant.recipientAgreementKey,
            encapsulatedKey: grant.encapsulatedKey, ciphertext: Array(grant.ciphertext.dropLast()),
            signature: grant.signature)
        #expect(throws: SharingFormatError.badFieldLength) { _ = try KeyGrantCodec.encode(short) }
    }

    @Test("the one account entitled to grant a key is the signer of the record that entitled the recipient to it")
    func grantSender() async throws {
        var household = try await SharingHousehold.make()
        let genesisKey = household.state.vaultKeyID
        let owner = household.owner
        let admin = household.administrator
        #expect(try household.ledger.grantSender(forKey: genesisKey, to: owner.accountID).accountID == owner.accountID)
        #expect(
            try household.ledger.grantSender(forKey: genesisKey, to: household.writer.accountID).accountID
                == owner.accountID, "the owner added the writer")

        let guest = try SharingParty(seed: 70)
        try await household.add(guest, as: .readOnly, by: admin)
        #expect(
            try household.ledger.grantSender(forKey: genesisKey, to: guest.accountID).accountID == admin.accountID,
            "the administrator added the guest")

        let plan = try household.rotate(.removal(household.reader.accountID), by: admin)
        for member in household.state.members {
            #expect(
                try household.ledger.grantSender(forKey: plan.newKeyID, to: member.accountID).accountID
                    == admin.accountID, "whoever rotated grants the new key to everyone who remains")
        }
        #expect(throws: SharingError.notEntitledToKey(household.reader.accountID), "removed before the key existed") {
            _ = try household.ledger.grantSender(forKey: plan.newKeyID, to: household.reader.accountID)
        }
        #expect(
            try household.ledger.grantSender(forKey: genesisKey, to: household.reader.accountID).accountID
                == owner.accountID, "still entitled to the key of their own time")

        let late = try SharingParty(seed: 71)
        try await household.add(late, as: .readWrite, by: owner)
        #expect(throws: SharingError.notEntitledToKey(late.accountID), "never a member while the old key was current") {
            _ = try household.ledger.grantSender(forKey: genesisKey, to: late.accountID)
        }
        #expect(throws: SharingError.notEntitledToKey(household.outsider.accountID)) {
            _ = try household.ledger.grantSender(forKey: plan.newKeyID, to: household.outsider.accountID)
        }
        let unknown = UUID()
        #expect(throws: SharingError.unknownKey(unknown)) {
            _ = try household.ledger.grantSender(forKey: unknown, to: owner.accountID)
        }
        #expect(household.ledger.keyEpoch(of: genesisKey) == 0)
        #expect(household.ledger.keyEpoch(of: plan.newKeyID) == 5)
        #expect(household.ledger.keyEpoch(of: unknown) == nil)
    }

    @Test("every remaining member opens their grant of a rotated key; a grant can be made again if it is lost")
    func openingGrants() async throws {
        var household = try await SharingHousehold.make()
        let plan = try household.rotate(.removal(household.reader.accountID), by: household.owner)
        #expect(plan.grants.count == 3)
        for party in [household.owner, household.administrator, household.writer] {
            let key = try household.ledger.openGrant(of: plan.newKeyID, from: Self.objects(plan), as: party.keyset)
            #expect(key.key.keyID == plan.newKeyID)
            #expect(key.key.material.constantTimeEquals(household.vaultKey.key.material))
        }
        #expect(throws: SharingError.notEntitledToKey(household.reader.accountID)) {
            _ = try household.ledger.openGrant(
                of: plan.newKeyID, from: Self.objects(plan), as: household.reader.keyset)
        }
        #expect(throws: SharingError.grantNotFound) {
            _ = try household.ledger.openGrant(of: plan.newKeyID, from: [], as: household.writer.keyset)
        }

        let again = try household.ledger.makeGrant(
            of: household.vaultKey, to: household.writer.accountID, from: household.owner.keyset)
        let reopened = try household.ledger.openGrant(again.encoded, at: again.location, as: household.writer.keyset)
        #expect(reopened.key.material.constantTimeEquals(household.vaultKey.key.material))
        #expect(throws: SharingError.notPermitted, "only the entitled sender may make it") {
            _ = try household.ledger.makeGrant(
                of: household.vaultKey, to: household.writer.accountID, from: household.administrator.keyset)
        }
    }

    @Test("a grant is opened only where its vault, key and recipient say it belongs")
    func grantLocation() async throws {
        var household = try await SharingHousehold.make()
        let plan = try household.rotate(.routine, by: household.owner)
        let writer = household.writer
        let mine = try #require(
            plan.grants.first {
                if case .grant(_, let recipient, _) = $0.location.kind { return recipient == writer.accountID }
                return false
            })
        _ = try household.ledger.openGrant(mine.contents, at: mine.location, as: writer.keyset)

        let moved: [SharingObjectLocation] = [
            .grant(vaultID: UUID(), keyID: plan.newKeyID, recipient: writer.accountID, contents: mine.contents),
            .grant(
                vaultID: household.vaultID, keyID: plan.newKeyID, recipient: household.reader.accountID,
                contents: mine.contents),
            .grant(
                vaultID: household.vaultID, keyID: plan.newKeyID, recipient: writer.accountID,
                contents: mine.contents + [0]),
            .membership(household.ledger.chain[0].record),
        ]
        for location in moved {
            #expect(throws: SharingError.grantMisfiled) {
                _ = try household.ledger.openGrant(mine.contents, at: location, as: writer.keyset)
            }
        }
        let genesisKey = household.ledger.chain[0].state.vaultKeyID
        #expect(throws: CryptoError.grantMismatch, "filed under another key of the same vault") {
            _ = try household.ledger.openGrant(
                mine.contents,
                at: .grant(
                    vaultID: household.vaultID, keyID: genesisKey, recipient: writer.accountID,
                    contents: mine.contents),
                as: writer.keyset)
        }
    }

    // MARK: - Leave requests

    @Test("a leave request is the member's own, for one vault and one stint of membership")
    func leaveRequest() async throws {
        var household = try await SharingHousehold.make()
        let writer = household.writer
        let request = try LeaveRequest.make(leaving: household.state, as: writer.keyset)
        #expect(request.memberSince == 2)
        let bytes = request.encoded()
        #expect(bytes.count == LeaveRequest.encodedLength)
        #expect(try LeaveRequest.parse(bytes) == request)
        try request.validate(against: household.state)
        for length in 0..<bytes.count {
            #expect(throws: SharingFormatError.self) { _ = try LeaveRequest.parse(Array(bytes[0..<length])) }
        }
        #expect(throws: SharingFormatError.tooLarge(bytes.count + 1)) { _ = try LeaveRequest.parse(bytes + [0]) }

        #expect(throws: SharingError.notAMember(household.outsider.accountID)) {
            _ = try LeaveRequest.make(leaving: household.state, as: household.outsider.keyset)
        }
        let forged = LeaveRequest(
            vaultID: request.vaultID, accountID: household.reader.accountID, memberSince: 3,
            signature: request.signature)
        #expect(throws: SharingError.leaveRequestInvalid, "signed by someone else") {
            try forged.validate(against: household.state)
        }
        let listed = [request, request, forged].map { (name: SharingObject($0).name, contents: $0.encoded()) }
        #expect(
            household.ledger.pendingLeaveRequests(among: listed + [(name: listed[0].name, contents: [1, 2])])
                == [request])
        // Found only where it belongs: under the vault's leave prefix, the member's account and its own digest.
        let elsewhere = SharingObject(forged).name
        let wrongDigest = String(listed[0].name.dropLast(1)) + (listed[0].name.hasSuffix("0") ? "1" : "0")
        for name in [elsewhere, wrongDigest, "leave/\(writer.accountID.uuidString)/x", ""] {
            #expect(household.ledger.pendingLeaveRequests(among: [(name: name, contents: bytes)]).isEmpty)
        }

        try household.rotate(.departure(request), by: household.administrator)
        #expect(household.state.member(writer.accountID) == nil)
        #expect(
            household.ledger.chain.last?.record.operation
                == .memberLeft(writer.accountID, requestSignature: request.signature))
        #expect(household.ledger.pendingLeaveRequests(among: [request]).isEmpty)
        #expect(throws: SharingError.nothingToDo) {
            _ = try RotationPlanner.plan(
                .departure(request), ledger: household.ledger, signedBy: household.owner.keyset)
        }
    }

    @Test("an administrator's departure is carried out by the owner, not by another administrator")
    func administratorLeaves() async throws {
        var household = try await SharingHousehold.make()
        let second = try SharingParty(seed: 72)
        try await household.add(second, as: .administrator, by: household.owner)
        let request = try LeaveRequest.make(leaving: household.state, as: household.administrator.keyset)
        #expect(throws: MembershipError.ownerOnly) {
            _ = try RotationPlanner.plan(.departure(request), ledger: household.ledger, signedBy: second.keyset)
        }
        #expect(throws: MembershipError.ownerOnly, "nor by themselves") {
            _ = try RotationPlanner.plan(
                .departure(request), ledger: household.ledger, signedBy: household.administrator.keyset)
        }
        try household.rotate(.departure(request), by: household.owner)
        #expect(household.state.member(household.administrator.accountID) == nil)
    }

    // MARK: - Plans

    @Test("a plan lists its steps in the order of F4.3: off the share first, grants, the record, then re-sealing")
    func planSteps() async throws {
        let household = try await SharingHousehold.make()
        var generator = SeededGenerator(seed: 9)
        let plan = try RotationPlanner.plan(
            .removal(household.reader.accountID), ledger: household.ledger, signedBy: household.owner.keyset,
            using: &generator)
        #expect(plan.baseEpoch == 3 && plan.baseHash == household.state.hash)
        #expect(plan.grants.count == 3)
        let reader = household.reader.accountID
        #expect(
            plan.steps(in: household.ledger)
                == [.revokeTransportAccess(reader), .mergeOutstandingWrites(reader)]
                + plan.grants.map(RotationStep.publish) + [.publish(plan.record), .resealRecords])
        let record = try MembershipRecord.parse(plan.record.contents)
        #expect(record.operation == .removeMember(household.reader.accountID))
        #expect(record.vaultKeyID == plan.newKeyID && record.hash == plan.recordHash)
        #expect(household.ledger.keyEpoch(of: plan.newKeyID) == nil, "planning changes nothing")

        let routine = try RotationPlanner.plan(
            .routine, ledger: household.ledger, signedBy: household.administrator.keyset, using: &generator)
        #expect(routine.grants.count == 4)
        #expect(
            routine.steps(in: household.ledger).first == .publish(routine.grants[0]), "nobody to take off the share")
        #expect(RotationReason.routine.departingAccount == nil)

        // What is left to do is read from the ledger, so a plan carried out again does only what is still right.
        var after = household
        try after.adopt(plan.record.contents)
        #expect(plan.steps(in: after.ledger) == [.revokeTransportAccess(reader), .resealRecords])
        #expect(routine.steps(in: after.ledger).isEmpty, "superseded: nothing of it is published")
        try await after.add(after.reader, as: .readOnly, by: after.owner)
        #expect(
            plan.steps(in: after.ledger) == [.resealRecords],
            "a member invited back since is not taken off the share by an old plan")
    }

    @Test("a plan survives being written to disk, and a plan altered there is refused")
    func planEncoding() async throws {
        let household = try await SharingHousehold.make()
        var generator = SeededGenerator(seed: 9)
        let request = try LeaveRequest.make(leaving: household.state, as: household.writer.keyset)
        for reason in [RotationReason.removal(household.reader.accountID), .departure(request), .routine] {
            let plan = try RotationPlanner.plan(
                reason, ledger: household.ledger, signedBy: household.owner.keyset, using: &generator)
            let bytes = plan.encoded()
            let me = household.owner.bundle
            #expect(bytes.count <= RotationPlan.maximumLength)
            #expect(try RotationPlan.parse(bytes, account: me) == plan)
            #expect(try RotationPlan.parse(bytes, account: me).reason == reason, "read back from the record")
            for length in stride(from: 0, to: bytes.count, by: 17) {
                #expect(throws: SharingFormatError.self, "length \(length)") {
                    _ = try RotationPlan.parse(Array(bytes[0..<length]), account: me)
                }
            }
            #expect(throws: SharingFormatError.self) { _ = try RotationPlan.parse(bytes + [0], account: me) }
            for offset in [21, 37, 45, 77] {
                var altered = bytes
                altered[offset] ^= 1
                #expect(throws: SharingFormatError.self, "vault, epoch, hash or key at \(offset)") {
                    _ = try RotationPlan.parse(altered, account: me)
                }
            }
            // Signed by the account that made it: nobody else's plan is this account's, and no byte of it changes.
            #expect(throws: SharingError.savedPlanInvalid) {
                _ = try RotationPlan.parse(bytes, account: household.administrator.bundle)
            }
            for offset in stride(from: 0, to: bytes.count, by: 7) {
                var altered = bytes
                altered[offset] ^= 0x40
                #expect(throws: (any Error).self, "byte \(offset)") {
                    _ = try RotationPlan.parse(altered, account: me)
                }
            }
        }
    }

    @Test("a rotation's status is read from what the device can see: unpublished, re-sealing, complete")
    func planStatus() async throws {
        var household = try await SharingHousehold.make()
        let oldKey = household.state.vaultKeyID
        var generator = SeededGenerator(seed: 9)
        let plan = try RotationPlanner.plan(
            .removal(household.reader.accountID), ledger: household.ledger, signedBy: household.owner.keyset,
            using: &generator)
        let author = household.owner.accountID
        let a = SealedRecordReference(recordID: UUID(), kind: .item, keyID: oldKey, version: 4, author: author)
        let b = SealedRecordReference(recordID: UUID(), kind: .item, keyID: oldKey, version: 1, author: author)
        #expect(plan.status(in: household.ledger, inventory: [a, b]) == .awaitingPublication)
        #expect(household.ledger.recordsToReseal(in: [a, b]).isEmpty, "nothing to re-seal before the key changes")

        try household.adopt(plan.record.contents)
        #expect(plan.status(in: household.ledger, inventory: [a, b]) == .resealing(remaining: 2))
        #expect(Set(household.ledger.recordsToReseal(in: [a, b])) == [a, b])
        #expect(
            household.ledger.recordsToReseal(in: [a, b]) == household.ledger.recordsToReseal(in: [b, a]),
            "a stable order, so an interrupted pass resumes")

        let resealed = SealedRecordReference(
            recordID: a.recordID, kind: .item, keyID: plan.newKeyID, version: 5, author: author)
        #expect(plan.status(in: household.ledger, inventory: [resealed, b]) == .resealing(remaining: 1))
        #expect(plan.status(in: household.ledger, inventory: [resealed]) == .complete)
        #expect(plan.status(in: household.ledger, inventory: []) == .complete)
    }

    @Test("records last written by an account that may no longer write are listed for sealing again by one who may")
    func resealAfterLosingWritePermission() async throws {
        var household = try await SharingHousehold.make()
        let key = household.state.vaultKeyID
        func reference(by author: SharingParty, under keyID: UUID) -> SealedRecordReference {
            SealedRecordReference(recordID: UUID(), kind: .item, keyID: keyID, version: 1, author: author.accountID)
        }
        let owners = reference(by: household.owner, under: key)
        let writers = reference(by: household.writer, under: key)
        let admins = reference(by: household.administrator, under: key)
        #expect(household.ledger.recordsToReseal(in: [owners, writers, admins]).isEmpty)

        // Made read-only: nothing rotates, and what the member wrote is published again by someone who may write.
        try household.adopt(
            household.ledger.proposeRoleChange(
                of: household.writer.accountID, to: .readOnly, signedBy: household.administrator.keyset
            ).encoded())
        #expect(household.ledger.recordsToReseal(in: [owners, writers, admins]) == [writers])
        #expect(
            household.ledger.pendingRotation(
                plan: nil, leaveRequests: [], inventory: [owners, writers, admins], heldKeyIDs: [key])
                == [.resealing(remaining: 1)])
        // Read-write again: their own version stands.
        try household.adopt(
            household.ledger.proposeRoleChange(
                of: household.writer.accountID, to: .readWrite, signedBy: household.administrator.keyset
            ).encoded())
        #expect(household.ledger.recordsToReseal(in: [owners, writers, admins]).isEmpty)

        // Removed: everything is under an earlier key anyway; afterwards, a version of theirs under the new key
        // (which they never held, so it is not theirs) and one by a stranger are listed as well.
        let plan = try household.rotate(.removal(household.administrator.accountID), by: household.owner)
        #expect(Set(household.ledger.recordsToReseal(in: [owners, writers, admins])) == [owners, writers, admins])
        let current = reference(by: household.owner, under: plan.newKeyID)
        let claimed = reference(by: household.administrator, under: plan.newKeyID)
        let strangers = reference(by: household.outsider, under: plan.newKeyID)
        #expect(Set(household.ledger.recordsToReseal(in: [current, claimed, strangers])) == [claimed, strangers])

        // A deleted vault takes no writes, so nothing is listed.
        try household.adopt(household.ledger.proposeDeletion(signedBy: household.owner.keyset).encoded())
        #expect(household.ledger.recordsToReseal(in: [owners, claimed]).isEmpty)
    }

    @Test("a plan that lost its place in the chain is superseded, and planning again knows when nothing is left to do")
    func planSuperseded() async throws {
        let household = try await SharingHousehold.make()
        var generator = SeededGenerator(seed: 9)
        let reader = household.reader.accountID
        let admins = try RotationPlanner.plan(
            .removal(reader), ledger: household.ledger, signedBy: household.administrator.keyset, using: &generator)
        let owners = try RotationPlanner.plan(
            .removal(reader), ledger: household.ledger, signedBy: household.owner.keyset, using: &generator)

        var ledger = household.ledger
        ledger.ingest([admins.record.contents])
        #expect(admins.status(in: ledger, inventory: []) == .complete)
        #expect(owners.status(in: ledger, inventory: []) == .superseded, "someone else's record is at that epoch")

        let report = ledger.ingest([owners.record.contents])
        #expect(report.superseded.map(\.hash) == [admins.recordHash], "the owner's record outranks it")
        #expect(admins.status(in: ledger, inventory: []) == .superseded)
        #expect(owners.status(in: ledger, inventory: []) == .complete)
        #expect(throws: SharingError.nothingToDo, "the member is gone either way") {
            _ = try RotationPlanner.plan(
                .removal(reader), ledger: ledger, signedBy: household.administrator.keyset, using: &generator)
        }
        #expect(ledger.state.vaultKeyID == owners.newKeyID)
    }

    @Test("what is pending is visible: a departure asked for, a plan not yet published, a key not yet held, re-sealing")
    func pendingRotation() async throws {
        var household = try await SharingHousehold.make()
        let oldKey = household.state.vaultKeyID
        let author = household.owner.accountID
        let record = SealedRecordReference(recordID: UUID(), kind: .item, keyID: oldKey, version: 1, author: author)
        let listed = { (request: LeaveRequest) in [(name: SharingObject(request).name, contents: request.encoded())] }
        #expect(
            household.ledger.pendingRotation(plan: nil, leaveRequests: [], inventory: [record], heldKeyIDs: [oldKey])
                .isEmpty)

        let request = try LeaveRequest.make(leaving: household.state, as: household.writer.keyset)
        #expect(
            household.ledger.pendingRotation(
                plan: nil, leaveRequests: listed(request), inventory: [record], heldKeyIDs: [oldKey])
                == [.departureRequested(household.writer.accountID)])

        var generator = SeededGenerator(seed: 9)
        let plan = try RotationPlanner.plan(
            .departure(request), ledger: household.ledger, signedBy: household.owner.keyset, using: &generator)
        #expect(
            household.ledger.pendingRotation(
                plan: plan, leaveRequests: listed(request), inventory: [record], heldKeyIDs: [oldKey])
                == [.departureRequested(household.writer.accountID), .awaitingPublication(plan.reason)])

        try household.adopt(plan.record.contents)
        #expect(
            household.ledger.pendingRotation(
                plan: plan, leaveRequests: listed(request), inventory: [record], heldKeyIDs: [oldKey])
                == [.awaitingKey(plan.newKeyID), .resealing(remaining: 1)])
        #expect(
            household.ledger.pendingRotation(
                plan: plan, leaveRequests: [],
                inventory: [
                    SealedRecordReference(
                        recordID: record.recordID, kind: .item, keyID: plan.newKeyID, version: 2, author: author)
                ],
                heldKeyIDs: [oldKey, plan.newKeyID]
            ).isEmpty)
    }
}
