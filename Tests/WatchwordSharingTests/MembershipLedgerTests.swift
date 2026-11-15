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
        VerifiedContact(bundle: household.owner.bundle, method: .comparedByEye, verifiedAt: nil)
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

        var report = try ledger.ingest([records[3], records[4]])
        #expect(ledger.state.epoch == 0, "a gap is not skipped")
        #expect(report.rejected.map(\.reason) == [.unconnected, .unconnected])
        #expect(report.rejected.map(\.index) == [0, 1])
        #expect(!report.changedHead)

        report = try ledger.ingest([records[2], records[1], records[4], records[3]])
        #expect(ledger.state == household.state)
        #expect(report.adopted.map(\.epoch) == [1, 2, 3, 4])
        #expect(report.rejected.isEmpty && report.superseded.isEmpty && report.outranked.isEmpty)

        report = try ledger.ingest(records)
        #expect(!report.changedHead && report.rejected.isEmpty, "records already held are not news")
    }

    @Test("junk among the candidates is reported and changes nothing")
    func junk() async throws {
        let household = try await SharingHousehold.make()
        var ledger = household.ledger
        let other = try await SharingHousehold.make(seed: 2)
        let report = try ledger.ingest([
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
        #expect(throws: LedgerError.tooManyCandidates(MembershipLimits.maximumCandidates + 1)) {
            _ = try ledger.ingest(Array(repeating: [], count: MembershipLimits.maximumCandidates + 1))
        }
    }

    @Test("joining needs the owner's genesis: another owner's, or none, is no vault")
    func joinNeedsGenesis() async throws {
        let household = try await SharingHousehold.make()
        let records = household.ledger.chain.map(\.encoded)
        #expect(throws: LedgerError.noGenesis) { _ = try Self.join(household, Array(records.dropFirst())) }
        #expect(throws: LedgerError.noGenesis) { _ = try Self.join(household, []) }

        let impostor = VerifiedContact(bundle: household.outsider.bundle, method: .comparedByEye, verifiedAt: nil)
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
        var report = try sawBoth.ingest([higher, lower])
        #expect(sawBoth.state.hash == winner.hash)
        #expect(report.adopted == [winner])
        #expect(report.outranked == [try MembershipRecord.parse(higher)])

        var sawLoserFirst = household.ledger
        report = try sawLoserFirst.ingest([higher])
        #expect(sawLoserFirst.state.hash == (try MembershipRecord.parse(higher)).hash)
        report = try sawLoserFirst.ingest([lower])
        #expect(sawLoserFirst.state.hash == winner.hash, "reorganised onto the winner")
        #expect(report.superseded == [try MembershipRecord.parse(higher)])
        #expect(report.adopted == [winner])

        var sawWinnerFirst = household.ledger
        _ = try sawWinnerFirst.ingest([lower])
        report = try sawWinnerFirst.ingest([higher])
        #expect(sawWinnerFirst.state.hash == winner.hash)
        #expect(!report.changedHead)
        #expect(report.outranked == [try MembershipRecord.parse(higher)])
        #expect(sawBoth.state == sawLoserFirst.state && sawBoth.state == sawWinnerFirst.state)
    }

    @Test("the decision at a fork does not depend on how much was built on the losing record")
    func forkDecidedAtTheForkPoint() async throws {
        var household = try await SharingHousehold.make()
        let (lower, higher) = try await Self.softFork(&household)

        // A device that saw only the losing record keeps going on it.
        var loserBranch = household
        try loserBranch.adopt(higher)
        try loserBranch.rotate(.routine, by: loserBranch.administrator)
        try loserBranch.rotate(.routine, by: loserBranch.administrator)
        #expect(loserBranch.state.epoch == 7)

        var ledger = loserBranch.ledger
        let report = try ledger.ingest([lower])
        #expect(ledger.state.hash == (try MembershipRecord.parse(lower)).hash)
        #expect(ledger.state.epoch == 5)
        #expect(report.superseded.map(\.epoch) == [5, 6, 7])
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
            _ = try first.ingest([admins.encoded()])
            let report = try first.ingest([owners.encoded()])
            #expect(first.state.hash == owners.hash, "seed \(seed)")
            #expect(report.superseded == [admins])

            var second = household.ledger
            _ = try second.ingest([owners.encoded()])
            #expect(try !second.ingest([admins.encoded()]).changedHead)
            #expect(second.state.hash == owners.hash)

            // And however long the administrator's branch grows.
            try household.adopt(admins.encoded())
            try household.rotate(.routine, by: household.administrator)
            var third = household.ledger
            _ = try third.ingest([owners.encoded()])
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
        let report = try ledger.ingest([lower])
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
                _ = try ledger.ingest([record.encoded()])
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
                owner: VerifiedContact(bundle: household.outsider.bundle, method: .comparedByEye, verifiedAt: nil),
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
