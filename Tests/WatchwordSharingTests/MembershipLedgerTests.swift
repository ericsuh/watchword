import Foundation
import Testing
import WatchwordCrypto
import WatchwordTestSupport

@testable import WatchwordSharing

/// The ledger: what it accepts from a store, how it settles two administrators acting at once, and how it survives
/// being written to disk (docs/02-architecture.md §8.3).
@Suite("Membership ledger")
struct MembershipLedgerTests {
    static func ownerContact(_ household: SharingHousehold) -> VerifiedContact {
        VerifiedContact(bundle: household.owner.bundle, method: .safetyNumber, verifiedAt: nil)
    }

    /// A fresh device's view: joins from whatever records it is offered.
    static func join(_ household: SharingHousehold, _ records: [[UInt8]]) throws -> MembershipLedger {
        try MembershipLedger.join(
            vaultID: household.vaultID, owner: ownerContact(household), candidates: records
        ).ledger
    }

    @Test("records arrive in any order, any number of times, and the same chain results")
    func orderDoesNotMatter() async throws {
        var household = try await SharingHousehold.make()
        try household.rotate(.removal(household.reader.accountID), by: household.administrator)
        try household.rotate(.routine, by: household.owner)
        let records = household.ledger.chain.map(\.encoded)
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 11))
        for _ in 0..<TestEnvironment.iterations(standard: 20, long: 500) {
            let offered = (records + records.shuffled(using: &generator).prefix(3)).shuffled(using: &generator)
            let ledger = try Self.join(household, offered)
            #expect(ledger.state == household.state)
            #expect(ledger.chain.map(\.state.hash) == household.ledger.chain.map(\.state.hash))
        }
    }

    @Test("a chain delivered piecemeal advances as far as it connects and reports the rest")
    func piecemeal() async throws {
        var household = try await SharingHousehold.make()
        try household.rotate(.routine, by: household.owner)
        let records = household.ledger.chain.map(\.encoded)

        var ledger = try Self.join(household, [records[0]])
        #expect(ledger.state.epoch == 0)

        var report = ledger.ingest([records[3], records[4]])
        #expect(ledger.state.epoch == 0, "a gap is not skipped")
        #expect(report.rejected.map(\.reason) == [.unconnected, .unconnected])
        #expect(report.rejected.map(\.index) == [0, 1])
        #expect(!report.changedHead)

        report = ledger.ingest([records[2], records[1], records[4], records[3]])
        #expect(ledger.state == household.state)
        #expect(report.adopted.map(\.epoch) == [1, 2, 3, 4])
        #expect(report.rejected.isEmpty && report.superseded.isEmpty && report.outranked.isEmpty)

        report = ledger.ingest(records)
        #expect(!report.changedHead && report.rejected.isEmpty, "records already held are not news")
    }

    @Test("junk among the candidates is reported and changes nothing")
    func junk() async throws {
        let household = try await SharingHousehold.make()
        var ledger = household.ledger
        let other = try await SharingHousehold.make(seed: 2)
        let report = ledger.ingest([
            [], [1, 2, 3], Array("WWMR".utf8), other.ledger.chain[1].encoded,
            [UInt8](repeating: 0, count: MembershipRecord.maximumLength + 1),
        ])
        #expect(ledger.state == household.state)
        #expect(
            report.rejected.map(\.reason) == [
                .malformed(.truncated), .malformed(.truncated), .malformed(.truncated),
                .invalid(.wrongVault(expected: household.vaultID, actual: other.vaultID)),
                .malformed(.tooLarge(MembershipRecord.maximumLength + 1)),
            ])
        #expect(report.signatureChecks == 0, "none of it reached a signature check")

        // Any number of candidates is examined; nothing is refused for being one too many.
        let many = ledger.ingest(Array(repeating: [], count: 10_000) + [household.ledger.chain[1].encoded])
        #expect(many.rejected.count == 10_000 && ledger.state == household.state)
    }

    @Test("joining needs the owner's genesis: another owner's, or none, is no vault")
    func joinNeedsGenesis() async throws {
        let household = try await SharingHousehold.make()
        let records = household.ledger.chain.map(\.encoded)
        #expect(throws: LedgerError.noGenesis) { _ = try Self.join(household, Array(records.dropFirst())) }
        #expect(throws: LedgerError.noGenesis) { _ = try Self.join(household, []) }

        let impostor = VerifiedContact(bundle: household.outsider.bundle, method: .safetyNumber, verifiedAt: nil)
        #expect(throws: LedgerError.noGenesis, "anchored to someone else, the real chain is nothing") {
            _ = try MembershipLedger.join(vaultID: household.vaultID, owner: impostor, candidates: records)
        }
        #expect(throws: LedgerError.noGenesis, "a chain is for one vault") {
            _ = try MembershipLedger.join(
                vaultID: UUID(), owner: Self.ownerContact(household), candidates: records)
        }
    }

    // MARK: - Two administrators at once

    /// Two administrators each write the next record without seeing the other's.
    static func softFork(_ household: inout SharingHousehold) async throws -> (lower: [UInt8], higher: [UInt8]) {
        let second = try SharingParty(seed: 60)
        try await household.add(second, as: .administrator, by: household.owner)
        let one = try household.ledger.proposeRoleChange(
            of: household.reader.accountID, to: .readWrite, signedBy: household.administrator.keyset)
        let two = try household.ledger.proposeRoleChange(
            of: household.writer.accountID, to: .readOnly, signedBy: second.keyset)
        return one.hash < two.hash ? (one.encoded(), two.encoded()) : (two.encoded(), one.encoded())
    }

    @Test("two administrators acting on the same epoch: every device picks the same record, in any order of arrival")
    func concurrentAdministrators() async throws {
        var household = try await SharingHousehold.make()
        let (lower, higher) = try await Self.softFork(&household)
        let winner = try MembershipRecord.parse(lower)

        var sawBoth = household.ledger
        var report = sawBoth.ingest([higher, lower])
        #expect(sawBoth.state.hash == winner.hash)
        #expect(report.adopted == [winner])
        #expect(report.outranked == [try MembershipRecord.parse(higher)])

        var sawLoserFirst = household.ledger
        report = sawLoserFirst.ingest([higher])
        #expect(sawLoserFirst.state.hash == (try MembershipRecord.parse(higher)).hash)
        report = sawLoserFirst.ingest([lower])
        #expect(sawLoserFirst.state.hash == winner.hash, "reorganised onto the winner")
        #expect(report.superseded == [try MembershipRecord.parse(higher)])
        #expect(report.adopted == [winner])

        var sawWinnerFirst = household.ledger
        sawWinnerFirst.ingest([lower])
        report = sawWinnerFirst.ingest([higher])
        #expect(sawWinnerFirst.state.hash == winner.hash)
        #expect(!report.changedHead)
        #expect(report.outranked == [try MembershipRecord.parse(higher)])
        #expect(sawBoth.state == sawLoserFirst.state && sawBoth.state == sawWinnerFirst.state)
    }

    @Test("between administrators, the branch more has been built on stays, whichever hash is lower at the fork")
    func longerBranchStays() async throws {
        var household = try await SharingHousehold.make()
        let (lower, higher) = try await Self.softFork(&household)
        let fork = household.ledger

        // Devices went on building on the higher-hashed record.
        var built = household
        try built.adopt(higher)
        try built.rotate(.routine, by: built.administrator)
        try built.rotate(.routine, by: built.administrator)
        #expect(built.state.epoch == 7)

        // The other record turns up late: it displaces nothing.
        var ledger = built.ledger
        var report = ledger.ingest([lower])
        #expect(ledger.state == built.state)
        #expect(!report.changedHead && report.superseded.isEmpty)
        #expect(report.outranked == [try MembershipRecord.parse(lower)])
        #expect(ledger.branches.map(\.encoded) == [lower], "it is kept all the same")

        // Only a branch that more was built on would: here, four records against three.
        var other = fork
        other.ingest([lower])
        var longer = [lower]
        for _ in 0..<3 {
            let plan = try RotationPlanner.plan(.routine, ledger: other, signedBy: household.administrator.keyset)
            other.ingest([plan.record.contents])
            longer.append(plan.record.contents)
        }
        report = ledger.ingest(Array(longer.dropFirst().reversed()))
        #expect(ledger.state == other.state)
        #expect(report.superseded.map(\.epoch) == [5, 6, 7] && report.adopted.map(\.epoch) == [5, 6, 7, 8])
        #expect(ledger.branches.map(\.state.epoch) == [5, 6, 7])
        #expect(try Self.join(household, built.ledger.chain.map(\.encoded) + longer).state == other.state)
    }

    @Test("a record that lost a fork is kept, so a record built on it later still connects and can win")
    func losingRecordsAreKept() async throws {
        var household = try await SharingHousehold.make()
        let (lower, higher) = try await Self.softFork(&household)
        var onHigher = household.ledger
        onHigher.ingest([higher])
        let owners = try RotationPlanner.plan(.routine, ledger: onHigher, signedBy: household.owner.keyset)

        // One device hears of the three records one at a time, in the worst order; another all at once.
        var piecemeal = household.ledger
        piecemeal.ingest([lower])
        #expect(piecemeal.ingest([higher]).outranked.count == 1)
        #expect(piecemeal.holds((try MembershipRecord.parse(higher)).hash))
        #expect(!piecemeal.contains((try MembershipRecord.parse(higher)).hash))
        let report = piecemeal.ingest([owners.record.contents])
        #expect(report.rejected.isEmpty, "its predecessor lost, and is still there to connect to")
        #expect(report.superseded == [try MembershipRecord.parse(lower)])

        var atOnce = household.ledger
        atOnce.ingest([owners.record.contents, lower, higher])
        #expect(piecemeal.state.hash == owners.recordHash)
        #expect(piecemeal.chain == atOnce.chain && piecemeal.branches == atOnce.branches)
    }

    @Test("a proposal is awaiting publication, adopted or superseded, read from the ledger")
    func proposalStatus() async throws {
        let household = try await SharingHousehold.make()
        let admins = try household.ledger.proposeRoleChange(
            of: household.writer.accountID, to: .readOnly, signedBy: household.administrator.keyset)
        let removal = try RotationPlanner.plan(
            .removal(household.reader.accountID), ledger: household.ledger, signedBy: household.owner.keyset)
        var device = household.ledger
        #expect(device.status(of: admins) == .awaitingPublication)

        // The administrator's device publishes, then ingests: the owner's record was already on the store.
        let report = device.ingest([removal.record.contents, admins.encoded()])
        #expect(report.superseded.isEmpty && report.outranked == [admins], "the report alone would not say so")
        #expect(device.status(of: admins) == .superseded)
        #expect(device.status(of: removal.proposal) == .adopted)

        // Proposed again on the new head, it is a different record, and is adopted.
        let again = try device.proposeRoleChange(
            of: household.writer.accountID, to: .readOnly, signedBy: household.administrator.keyset)
        #expect(again.hash != admins.hash && device.status(of: again) == .awaitingPublication)
        device.ingest([again.encoded()])
        #expect(device.status(of: again) == .adopted && device.status(of: admins) == .superseded)

        // What has happened by other means is not proposed twice, and another vault's record is nobody's proposal.
        #expect(throws: MembershipError.roleUnchanged) {
            _ = try device.proposeRoleChange(
                of: household.writer.accountID, to: .readOnly, signedBy: household.administrator.keyset)
        }
        let other = try await SharingHousehold.make(seed: 2)
        #expect(device.status(of: other.ledger.chain[1].record) == .superseded)
    }

    @Test("past the limit on records kept from losing branches, the best-ranked stay and the chain is untouched")
    func retentionLimit() async throws {
        var household = try await SharingHousehold.make()
        let fork = household
        // The household goes on; the reader's removal by the administrator then loses to a longer branch.
        let removal = try RotationPlanner.plan(
            .removal(household.reader.accountID), ledger: fork.ledger, signedBy: fork.administrator.keyset)
        try household.rotate(.routine, by: household.administrator)
        try household.rotate(.routine, by: household.administrator)

        let limit = MembershipLimits.maximumRetainedBranchRecords
        let flood = try (0..<(limit + 40)).map { _ in
            try fork.forgery(.rotateKey, signer: fork.administrator, newKeyID: UUID()).signed(
                by: fork.administrator.keyset)
        }
        var ledger = household.ledger
        var report = ledger.ingest(flood + [removal.record.contents])
        #expect(ledger.state == household.state && !report.changedHead)
        #expect(report.rejected.isEmpty && report.outranked.count == limit + 41)
        #expect(ledger.branches.count == limit && report.forgotten == 41)
        #expect(ledger.holds(removal.recordHash), "a removal that is owed is the last thing let go")
        #expect(ledger.owedRemovals.map(\.accountID) == [household.reader.accountID])

        // What is kept is still a tree, and survives a restart.
        let restored = try MembershipLedger.restore(
            ledger.persisted(signedBy: household.owner.keyset), vaultID: household.vaultID,
            owner: Self.ownerContact(household), account: household.owner.bundle)
        #expect(restored.chain == ledger.chain && restored.branches == ledger.branches)
        #expect(restored.owedRemovals == ledger.owedRemovals)

        // Offered everything again, the ledger makes the same choice again.
        report = ledger.ingest(flood)
        #expect(report.forgotten == 41 && ledger.branches == restored.branches)
    }

    @Test("the owner's record wins a fork against an administrator's, whichever hash is lower")
    func ownerOutranksAdministrator() async throws {
        for seed in UInt64(1)...6 {
            var household = try await SharingHousehold.make(seed: seed)
            let owners = try household.ledger.proposeRoleChange(
                of: household.reader.accountID, to: .readWrite, signedBy: household.owner.keyset)
            let admins = try household.ledger.proposeRoleChange(
                of: household.writer.accountID, to: .readOnly, signedBy: household.administrator.keyset)

            var first = household.ledger
            first.ingest([admins.encoded()])
            let report = first.ingest([owners.encoded()])
            #expect(first.state.hash == owners.hash, "seed \(seed)")
            #expect(report.superseded == [admins])

            var second = household.ledger
            second.ingest([owners.encoded()])
            #expect(!second.ingest([admins.encoded()]).changedHead)
            #expect(second.state.hash == owners.hash)

            // And however long the administrator's branch grows.
            try household.adopt(admins.encoded())
            try household.rotate(.routine, by: household.administrator)
            var third = household.ledger
            third.ingest([owners.encoded()])
            #expect(third.state.hash == owners.hash)
        }
    }

    @Test("a branch the owner has since signed on beats a lower-hashed branch the owner has not")
    func ownerEndorsementDecides() async throws {
        var household = try await SharingHousehold.make()
        let (lower, higher) = try await Self.softFork(&household)

        var endorsed = household
        try endorsed.adopt(higher)
        try endorsed.rotate(.routine, by: endorsed.owner)

        var ledger = endorsed.ledger
        let report = ledger.ingest([lower])
        #expect(!report.changedHead)
        #expect(report.outranked == [try MembershipRecord.parse(lower)])
        #expect(ledger.state == endorsed.state)

        // A device meeting everything at once agrees.
        let fresh = try Self.join(household, endorsed.ledger.chain.map(\.encoded) + [lower])
        #expect(fresh.state == endorsed.state)
    }

    @Test("two records the owner signed for the same epoch settle by hash, the same way everywhere")
    func ownerOnTwoDevices() async throws {
        let household = try await SharingHousehold.make()
        let a = try household.ledger.proposeRoleChange(
            of: household.reader.accountID, to: .readWrite, signedBy: household.owner.keyset)
        let b = try household.ledger.proposeRoleChange(
            of: household.writer.accountID, to: .readOnly, signedBy: household.owner.keyset)
        let winner = min(a.hash, b.hash)
        for order in [[a, b], [b, a]] {
            var ledger = household.ledger
            for record in order {
                ledger.ingest([record.encoded()])
            }
            #expect(ledger.state.hash == winner)
        }
    }

    // MARK: - Persistence

    @Test("a ledger written to disk and read back is the same ledger")
    func persistence() async throws {
        var household = try await SharingHousehold.make()
        try household.rotate(.removal(household.reader.accountID), by: household.owner)
        let writer = household.writer
        let ledger = try Self.join(household, household.ledger.chain.map(\.encoded))

        let blob = try ledger.persisted(signedBy: writer.keyset)
        let restored = try MembershipLedger.restore(
            blob, vaultID: household.vaultID, owner: Self.ownerContact(household), account: writer.bundle)
        #expect(restored.state == ledger.state)
        #expect(restored.chain == ledger.chain)
        #expect(restored.owner == household.owner.bundle)

        // Records on losing branches are saved with the rest: a device that restarts still knows what it knew.
        var forked = try await SharingHousehold.make(seed: 3)
        let (lower, higher) = try await Self.softFork(&forked)
        var device = forked.ledger
        device.ingest([lower, higher])
        #expect(device.branches.map(\.encoded) == [higher])
        let again = try MembershipLedger.restore(
            device.persisted(signedBy: forked.writer.keyset), vaultID: forked.vaultID,
            owner: Self.ownerContact(forked), account: forked.writer.bundle)
        #expect(again.chain == device.chain && again.branches == device.branches)

        // A record on a losing branch altered on disk, or one added there, fails the whole blob.
        var altered = try device.persisted(signedBy: forked.writer.keyset)
        altered[altered.count - 70] ^= 1
        #expect(throws: LedgerError.savedRecordInvalid) {
            _ = try MembershipLedger.restore(
                altered, vaultID: forked.vaultID, owner: Self.ownerContact(forked), account: forked.writer.bundle)
        }
        var onHigher = forked.ledger
        onHigher.ingest([higher])
        let longer = try RotationPlanner.plan(.routine, ledger: onHigher, signedBy: forked.administrator.keyset)
        var planted = try device.persisted(signedBy: forked.writer.keyset)
        planted.replaceSubrange(
            (planted.count - higher.count - 6)..<(planted.count - higher.count - 2), with: [2, 0, 0, 0])
        planted += [UInt8(longer.record.contents.count & 0xFF), UInt8(longer.record.contents.count >> 8)]
        planted += longer.record.contents
        #expect(throws: LedgerError.rolledBack(expectedEpoch: device.state.epoch), "it would change the head") {
            _ = try MembershipLedger.restore(
                planted, vaultID: forked.vaultID, owner: Self.ownerContact(forked), account: forked.writer.bundle)
        }
    }

    @Test("a persisted ledger for another account, vault or owner is refused")
    func persistenceIsBound() async throws {
        let household = try await SharingHousehold.make()
        let blob = try household.ledger.persisted(signedBy: household.writer.keyset)
        let owner = Self.ownerContact(household)
        #expect(throws: LedgerError.checkpointInvalid) {
            _ = try MembershipLedger.restore(
                blob, vaultID: household.vaultID, owner: owner, account: household.reader.bundle)
        }
        #expect(throws: LedgerError.checkpointInvalid) {
            _ = try MembershipLedger.restore(blob, vaultID: UUID(), owner: owner, account: household.writer.bundle)
        }
        #expect(throws: LedgerError.checkpointInvalid) {
            _ = try MembershipLedger.restore(
                blob, vaultID: household.vaultID,
                owner: VerifiedContact(bundle: household.outsider.bundle, method: .safetyNumber, verifiedAt: nil),
                account: household.writer.bundle)
        }
    }

    @Test("a persisted ledger cut short at any length is refused")
    func persistenceTruncated() async throws {
        let household = try await SharingHousehold.make()
        let blob = try household.ledger.persisted(signedBy: household.owner.keyset)
        for length in stride(from: 0, to: blob.count, by: 13) {
            #expect(throws: (any Error).self, "length \(length)") {
                _ = try MembershipLedger.restore(
                    Array(blob[0..<length]), vaultID: household.vaultID, owner: Self.ownerContact(household),
                    account: household.owner.bundle)
            }
        }
        #expect(throws: SharingFormatError.trailingBytes) {
            _ = try MembershipLedger.restore(
                blob + [0], vaultID: household.vaultID, owner: Self.ownerContact(household),
                account: household.owner.bundle)
        }
    }

    @Test("key bundles are compared by their keys, so a bundle derived again from the keyset is the same owner")
    func rederivedBundle() async throws {
        let household = try await SharingHousehold.make()
        let again = try household.owner.keyset.publicKeyBundle()
        #expect(again.hasSameKeys(as: household.owner.bundle))
        let owner = VerifiedContact(bundle: again, method: nil, verifiedAt: nil)
        let records = household.ledger.chain.map(\.encoded)
        let ledger = try MembershipLedger.join(vaultID: household.vaultID, owner: owner, candidates: records).ledger
        #expect(ledger.state == household.state)

        let blob = try household.ledger.persisted(signedBy: household.owner.keyset)
        let restored = try MembershipLedger.restore(
            blob, vaultID: household.vaultID, owner: owner, account: again)
        #expect(restored.state == household.state)
        #expect(!household.outsider.bundle.hasSameKeys(as: household.owner.bundle))
    }
}
