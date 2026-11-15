import Foundation
import Testing
import WatchwordCrypto
import WatchwordTestSupport

@testable import WatchwordSharing

/// Two and three accounts with real keysets going through the whole life of a shared vault over a store that is not
/// trusted (docs/02-architecture.md §8; PRD F4.1 to F4.6; docs/04-test-plan.md scenarios S3 and S4 at the protocol
/// level). The store between them is `HostileSharingStore`: it keeps the transport's contract only when the test
/// lets it.
@Suite("Shared vault simulation")
struct SharingScenarioTests {
    @Test("two people: create, invite, verify both ways, accept, write and read both ways")
    func twoPeople() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.readWrite])
        var partner = members[0]

        #expect(
            try partner.ledger(vault).state.members.map(\.role).sorted { $0.rawValue < $1.rawValue }
                == [.owner, .readWrite])
        #expect(try partner.ledger(vault).state.hash == owner.ledger(vault).state.hash)
        #expect(try await partner.contacts.pinned(owner.accountID)?.method == .safetyNumber)
        #expect(try await owner.contacts.pinned(partner.accountID)?.method == .safetyNumber)

        let wifi = UUID()
        let bank = UUID()
        try await owner.write("wifi password", to: vault, recordID: wifi, version: 1)
        try await partner.write("bank password", to: vault, recordID: bank, version: 1)
        #expect(try await owner.readable(in: vault) == [wifi: "wifi password", bank: "bank password"])
        #expect(try await partner.readable(in: vault) == [wifi: "wifi password", bank: "bank password"])
    }

    @Test("nothing a person would recognise reaches the store: no item text, and membership only as IDs and keys")
    func ciphertextOnly() async throws {
        let world = SharingWorld()
        var (vault, owner, _) = try await world.household(roles: [.readWrite, .readOnly])
        try await owner.write("correct horse battery staple", to: vault, recordID: UUID(), version: 1)
        let key = try owner.currentKey(vault).key.material.unprotectedCopy()
        for (name, contents) in await world.store.allObjects {
            #expect(contents.firstRange(of: Array("correct horse".utf8)) == nil, "\(name)")
            #expect(contents.firstRange(of: key) == nil, "the vault key in the clear in \(name)")
        }
    }

    @Test("three people: a role change, a removal with rotation, and what the removed member can and cannot read")
    func threePeopleRemoval() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.readWrite, .readOnly])
        var partner = members[0]
        var child = members[1]
        try await partner.sync(vault)
        let shared = UUID()
        try await owner.write("before", to: vault, recordID: shared, version: 1)

        // Read-only is kept by the clients: the child's own client refuses, and a write forced past it is ignored.
        await #expect(throws: SharingError.notPermitted) {
            try await child.write("mine", to: vault, recordID: UUID(), version: 1)
        }
        let forced = UUID()
        try await child.write("forced", to: vault, recordID: forced, version: 1, under: child.currentKey(vault))
        #expect(try await owner.readable(in: vault)[forced] == nil)
        #expect(try await partner.items(in: vault).first { $0.recordID == forced }?.outcome == .refused(.readOnly))

        // The owner makes the child read-write; now it counts.
        try await owner.changeRole(of: child.accountID, to: .readWrite, in: vault)
        try await child.sync(vault)
        try await partner.sync(vault)
        try await child.write("allowed now", to: vault, recordID: UUID(), version: 1)
        #expect(try await partner.readable(in: vault).values.contains("allowed now"))
        #expect(try await partner.readable(in: vault)[forced] == "forced", "judged by the membership now known")

        // The owner removes the partner.
        let oldKeyID = try owner.ledger(vault).state.vaultKeyID
        #expect(try await owner.remove(partner.accountID, from: vault) == .complete)
        #expect(await world.store.isRevoked(partner.accountID), "off the transport share first (F4.3a)")
        try await child.sync(vault)
        let newKeyID = try owner.ledger(vault).state.vaultKeyID
        #expect(newKeyID != oldKeyID)
        #expect(child.keys[vault]?[newKeyID] != nil, "the remaining member received the new key")

        try await owner.write("after", to: vault, recordID: shared, version: 9)
        #expect(try await child.readable(in: vault)[shared] == "after")
        #expect(try await owner.inventory(of: vault).allSatisfy { $0.keyID == newKeyID }, "everything was re-sealed")

        // The removed member sees themselves gone, holds no new key, and reads only what they already had.
        try await partner.sync(vault)
        #expect(try partner.ledger(vault).state.member(partner.accountID) == nil)
        #expect(partner.keys[vault]?[newKeyID] == nil)
        let stillVisible = try await partner.items(in: vault)
        #expect(stillVisible.contains { $0.outcome == .read("before") })
        #expect(!stillVisible.contains { $0.outcome == .read("after") })
        #expect(
            stillVisible.filter { $0.keyID == newKeyID }.allSatisfy { $0.outcome == .undecryptable(keyID: newKeyID) })
    }

    @Test("a member leaves: the request waits for an administrator's device, which rotates the key")
    func leaving() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.administrator, .readWrite])
        var admin = members[0]
        let leaver = members[1]
        try await owner.write("shared", to: vault, recordID: UUID(), version: 1)
        let oldKeyID = try owner.ledger(vault).state.vaultKeyID

        try await leaver.requestToLeave(vault)
        let requests = await world.store.list(prefix: SharingObjectLocation.leavePrefix(vault), viewer: owner.accountID)
        #expect(requests.count == 1)
        let pending = try owner.ledger(vault).pendingRotation(
            plan: nil, leaveRequests: requests.map(\.contents), inventory: [], heldKeyIDs: [oldKeyID])
        #expect(pending == [.departureRequested(leaver.accountID)], "visible as pending until someone rotates")

        // The administrator's device comes online and does it; the owner's just follows.
        try await admin.processLeaveRequests(in: vault)
        try await owner.sync(vault)
        #expect(try owner.ledger(vault).state.member(leaver.accountID) == nil)
        #expect(try owner.ledger(vault).state.vaultKeyID != oldKeyID)
        #expect(try owner.currentKey(vault).key.keyID == admin.currentKey(vault).key.keyID)
        if case .memberLeft(let account, _) = try owner.ledger(vault).chain.last!.record.operation {
            #expect(account == leaver.accountID)
        } else {
            Issue.record("the chain should say the member left")
        }
        #expect(
            try owner.ledger(vault).pendingRotation(
                plan: nil, leaveRequests: requests.map(\.contents), inventory: try await owner.inventory(of: vault),
                heldKeyIDs: Set(owner.keys[vault]!.keys)
            ).isEmpty)

        // Processing again does nothing: the request died with the membership it was made for.
        let epoch = try admin.ledger(vault).state.epoch
        try await admin.processLeaveRequests(in: vault)
        #expect(try admin.ledger(vault).state.epoch == epoch)
    }

    @Test("a rotation interrupted at any step resumes from the saved plan and completes")
    func interruptedRotation() async throws {
        for interruptAfter in 0...6 {
            let world = SharingWorld()
            var (vault, owner, members) = try await world.household(roles: [.readWrite, .readOnly], seed: 300)
            var partner = members[0]
            let removed = members[1]
            try await owner.write("one", to: vault, recordID: UUID(), version: 1)
            try await partner.write("two", to: vault, recordID: UUID(), version: 1)

            let plan = try owner.planRotation(.removal(removed.accountID), in: vault)
            #expect(plan.steps.count == 5)
            let status = try await owner.resumeRotation(in: vault, limit: interruptAfter)
            if interruptAfter < 4 {
                #expect(status == .awaitingPublication, "interrupted after \(interruptAfter) steps")
                #expect(try owner.ledger(vault).state.member(removed.accountID) != nil)
            }

            // The device restarts: all it has is the plan it saved and its ledger.
            #expect(try await owner.resumeRotation(in: vault) == .complete, "after \(interruptAfter) steps")
            #expect(owner.savedPlans[vault] == nil)
            try await partner.sync(vault)
            #expect(try partner.ledger(vault).state.member(removed.accountID) == nil)
            #expect(Set(try await partner.readable(in: vault).values) == ["one", "two"])
            let current = try owner.ledger(vault).state.vaultKeyID
            #expect(try await partner.inventory(of: vault).allSatisfy { $0.keyID == current })
        }
    }

    @Test("writes made under the old key while a rotation is in progress are swept up by the next re-sealing pass")
    func lateWritesUnderOldKey() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.readWrite, .readOnly])
        var partner = members[0]
        try owner.planRotation(.removal(members[1].accountID), in: vault)
        #expect(try await owner.resumeRotation(in: vault) == .complete)

        // The partner has not synced yet and still writes under the key they know.
        let late = UUID()
        try await partner.write("late", to: vault, recordID: late, version: 1)
        let current = try owner.ledger(vault).state.vaultKeyID
        let stale = try owner.ledger(vault).recordsToReseal(in: await owner.inventory(of: vault))
        #expect(stale.map(\.recordID) == [late])
        #expect(
            try owner.ledger(vault).pendingRotation(
                plan: nil, leaveRequests: [], inventory: await owner.inventory(of: vault), heldKeyIDs: [current])
                == [.resealing(remaining: 1)])

        // Any writer who holds both keys re-seals; here the partner, once they have caught up.
        try await partner.sync(vault)
        try await partner.write("late", to: vault, recordID: late, version: 2)
        #expect(try owner.ledger(vault).recordsToReseal(in: await owner.inventory(of: vault)).isEmpty)
    }

    @Test(
        "two administrators remove two members at the same moment: one record wins everywhere and the other tries again"
    )
    func concurrentRemovals() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(
            roles: [.administrator, .administrator, .readWrite, .readOnly])
        var first = members[0]
        var second = members[1]
        let writer = members[2]
        let reader = members[3]
        try await owner.write("kept", to: vault, recordID: UUID(), version: 1)
        try await first.sync(vault)
        try await second.sync(vault)

        // Neither sees the other's record before publishing.
        let planOne = try first.planRotation(.removal(writer.accountID), in: vault)
        let planTwo = try second.planRotation(.removal(reader.accountID), in: vault)
        let statusOne = try await first.resumeRotation(in: vault)
        let statusTwo = try await second.resumeRotation(in: vault)
        try await first.sync(vault)
        try await owner.sync(vault)

        let winner = min(planOne.recordHash, planTwo.recordHash)
        #expect(try owner.ledger(vault).state.hash == winner)
        #expect(try first.ledger(vault).state.hash == winner)
        #expect(try second.ledger(vault).state.hash == winner)
        #expect(statusOne == .complete, "it saw only its own record")
        #expect(statusTwo == (winner == planTwo.recordHash ? .complete : .superseded))

        // Whoever lost plans again on the new head; the vault ends with both members gone.
        if winner == planOne.recordHash {
            try await second.remove(reader.accountID, from: vault)
        } else {
            try await first.remove(writer.accountID, from: vault)
        }
        try await owner.sync(vault)
        try await first.sync(vault)
        try await second.sync(vault)
        let state = try owner.ledger(vault).state
        #expect(state.member(writer.accountID) == nil && state.member(reader.accountID) == nil)
        #expect(try first.ledger(vault).state == state)
        #expect(try second.ledger(vault).state == state)
        #expect(state.members.count == 3)
        for member in [owner, first, second] {
            #expect(try member.currentKey(vault).key.keyID == state.vaultKeyID, "\(member.name) holds the final key")
        }
        #expect(Set(try await second.readable(in: vault).values) == ["kept"])
    }

    @Test("a store that withholds, reorders and replays membership objects delays members but never misleads them")
    func hostileStoreBetweenThem() async throws {
        let world = SharingWorld()
        var (vault, owner, members) = try await world.household(roles: [.readWrite, .readOnly])
        var partner = members[0]
        let child = members[1]
        try await partner.sync(vault)
        let before = try partner.ledger(vault).state

        // The store hides the removal from the partner.
        try await owner.remove(child.accountID, from: vault)
        let removal = try owner.ledger(vault).chain.last!
        let name = SharingObjectLocation.membership(removal.record).name
        await world.store.hide([name], from: partner.accountID)
        var report = try await partner.sync(vault)
        #expect(!report.changedHead)
        #expect(try partner.ledger(vault).state == before, "withholding leaves the member where they were")

        // It serves an old record under the hidden record's name instead.
        await world.store.reveal(to: partner.accountID)
        let genuine = await world.store.allObjects[name]
        await world.store.tamper(name, contents: owner.ledgers[vault]!.chain[1].encoded)
        report = try await partner.sync(vault)
        #expect(try partner.ledger(vault).state == before, "a replayed record is one the member already has")

        // And junk beside the real thing.
        await world.store.tamper(name, contents: genuine)
        await world.store.tamper(SharingObjectLocation.membershipPrefix(vault) + "zzz", contents: [1, 2, 3])
        var flipped = genuine!
        flipped[40] ^= 1
        await world.store.tamper(name + "x", contents: flipped)
        report = try await partner.sync(vault)
        #expect(try partner.ledger(vault).state == owner.ledger(vault).state)
        #expect(report.rejected.count == 2)
        #expect(try partner.currentKey(vault).key.keyID == owner.currentKey(vault).key.keyID)
    }

    @Test("the vault's owner deletes it: every member sees it deleted and nobody's writes count any more")
    func deletion() async throws {
        let world = SharingWorld()
        let (vault, owner, members) = try await world.household(roles: [.administrator])
        var admin = members[0]
        let record = try owner.ledger(vault).proposeDeletion(signedBy: owner.keyset)
        try await world.store.create(SharingObject(record).name, contents: record.encoded(), by: owner.accountID)
        try await admin.sync(vault)
        #expect(try admin.ledger(vault).state.isDeleted)
        await #expect(throws: SharingError.notPermitted) {
            try await admin.write("too late", to: vault, recordID: UUID(), version: 1)
        }
        #expect(throws: SharingError.vaultDeleted) {
            _ = try RotationPlanner.plan(.routine, ledger: admin.ledger(vault), signedBy: admin.keyset)
        }
    }
}
