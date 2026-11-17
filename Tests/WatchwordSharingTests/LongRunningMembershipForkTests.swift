import Foundation
import Testing
import WatchwordCrypto
import WatchwordTestSupport

@testable import WatchwordSharing

/// The property the membership ledger's fork rule is built on (docs/02-architecture.md §8.3): the ledger is a
/// grow-only set of valid records, and everything it reports (the accepted chain, the losing branches, the removals
/// owed) is a function of that set. So whatever a store lists, in whatever order and however often, two devices that
/// have seen the same records agree.
///
/// Named `LongRunning…` so the nightly `test:long` run picks it up with `WATCHWORD_LONG_TESTS=1`, which widens the
/// number of histories and deliveries; `WATCHWORD_TEST_SEED` chooses the histories.
@Suite("Membership ledger: convergence over random forked histories")
struct LongRunningMembershipForkTests {
    /// Every valid record of a household whose administrators and owner act on whatever head they happen to know,
    /// stale ones included: a tree with forks at many depths.
    static func forkedHistory(seed: UInt64, records count: Int) async throws -> (SharingHousehold, [[UInt8]]) {
        var household = try await SharingHousehold.make(seed: seed)
        let second = try SharingParty(seed: seed &+ 7_000)
        try await household.add(second, as: .administrator, by: household.owner)
        var generator = SeededGenerator(seed: seed)
        var heads = [household.ledger]
        var records = household.ledger.chain.map(\.encoded)
        var seen = Set(household.ledger.chain.map(\.state.hash))
        let signers = [household.owner, household.administrator, second, household.administrator, second]
        while records.count < count {
            let base = heads[Int.random(in: heads.indices, using: &generator)]
            let signer = signers[Int.random(in: signers.indices, using: &generator)]
            let target = [household.writer, household.reader][Int.random(in: 0..<2, using: &generator)].accountID
            let record: [UInt8]
            do {
                switch Int.random(in: 0..<4, using: &generator) {
                case 0:
                    let role: MemberRole = base.state.member(target)?.role == .readOnly ? .readWrite : .readOnly
                    record = try base.proposeRoleChange(of: target, to: role, signedBy: signer.keyset).encoded()
                case 1:
                    record = try RotationPlanner.plan(
                        .removal(target), ledger: base, signedBy: signer.keyset, using: &generator
                    ).record.contents
                default:
                    record = try RotationPlanner.plan(
                        .routine, ledger: base, signedBy: signer.keyset, using: &generator
                    ).record.contents
                }
            } catch {
                continue
            }
            // The same change by the same signer on the same head is the same record, whatever its signature bytes
            // (they differ from one signing to the next on CryptoKit): one record, not two.
            guard seen.insert(try MembershipRecord.parse(record).hash).inserted else { continue }
            // A ledger that holds one path only: the head someone who had seen nothing else would build on.
            let next = try MembershipLedgerTests.join(household, base.chain.map(\.encoded) + [record])
            heads.append(next)
            records.append(record)
        }
        return (household, records)
    }

    @Test(
        "the accepted chain is a function of the records held: any order, any batches, any repeats, the same ledger")
    func orderAndBatchingDoNotMatter() async throws {
        let first = TestEnvironment.seed(fallback: 0) % 1_000_000 + 1
        for seed in first..<(first + UInt64(TestEnvironment.iterations(standard: 4, long: 40))) {
            let (household, records) = try await Self.forkedHistory(seed: seed, records: 40)
            let reference = try MembershipLedgerTests.join(household, records)
            #expect(reference.branches.count + reference.chain.count == records.count, "every record is valid")
            #expect(!reference.branches.isEmpty, "seed \(seed) forks")

            var generator = SeededGenerator(seed: seed &* 31)
            for _ in 0..<TestEnvironment.iterations(standard: 6, long: 25) {
                var ledger = try MembershipLedgerTests.join(household, [records[0]])
                var rounds = 0
                while ledger.chain.count + ledger.branches.count < records.count {
                    rounds += 1
                    // What a store that withholds at will would list this time.
                    let offered = records.shuffled(using: &generator)
                        .prefix(Int.random(in: 1...records.count, using: &generator))
                    ledger.ingest(Array(offered))
                    // At every step the ledger is what a fresh device would make of the same records.
                    let held = (ledger.chain + ledger.branches).map(\.encoded)
                    let fresh = try MembershipLedgerTests.join(household, held.shuffled(using: &generator))
                    #expect(fresh.chain == ledger.chain && fresh.branches == ledger.branches)
                    #expect(fresh.owedRemovals == ledger.owedRemovals)
                    try #require(rounds < 2_000)
                }
                #expect(ledger.chain == reference.chain, "seed \(seed)")
                #expect(ledger.branches == reference.branches)
                #expect(ledger.owedRemovals == reference.owedRemovals)
            }
        }
    }
}
