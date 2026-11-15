import Foundation
import Testing
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordSync

/// The laws convergence rests on, under random histories (docs/10-sync-correctness.md §7, docs/04-test-plan.md §3).
///
/// Several devices each make stamped edits of every kind on their own copy of one item — field edits, additions,
/// removals, reorders, title, tags, scopes, notes line edits, trash, restore, conflict resolution, permanent deletion
/// — and exchange versions at random (`MergeModel`). At every step the copy written is checked against the
/// specification of a multi-value register, worked out from the true history rather than from the item's metadata;
/// every update is checked to contain the version it was made on; and at the end:
///
/// - for versions `a`, `b`, `c` any device stored, `merge` is commutative, associative and idempotent, and a merge
///   contains its inputs — compared as the whole item that is sealed, not a projection of it;
/// - the same versions delivered in any order, with repeats, give the same item;
/// - once everything has been exchanged, every device holds the same item, and nothing a person typed is gone unless
///   a person discarded it (PRD F7.7).
///
/// Named `LongRunning…` so the nightly `test:long` run widens it (`WATCHWORD_LONG_TESTS`) and varies it
/// (`WATCHWORD_TEST_SEED`); a failure names its seed, run and history.
@Suite("Item merge laws under random histories")
struct LongRunningItemMergeLawTests {
    @Test(
        "random histories keep the specification, the semilattice laws, convergence and everything typed",
        arguments: [1, 2, 3, 4])
    func randomHistories(_ run: UInt64) {
        let seed = TestEnvironment.seed(fallback: 0x17E3_5EED) &+ run
        var generator = SeededGenerator(seed: seed)
        let histories = TestEnvironment.iterations(standard: 40, long: 1_500)
        var conflicts = 0
        var resolutions = 0
        var erased = 0
        var kept = 0
        var merges = 0
        var failures: [String] = []
        for history in 0..<histories where failures.isEmpty {
            let devices = Int.random(in: 2...4, using: &generator)
            var model = MergeModel(devices: devices)
            model.context = "seed \(seed), history \(history)"
            for _ in 0..<Int.random(in: 4...40, using: &generator) {
                let index = Int.random(in: 0..<devices, using: &generator)
                if Int.random(in: 0..<100, using: &generator) < 30 {
                    model.receive(at: index, from: Int.random(in: 0..<devices, using: &generator))
                } else {
                    let operation = Self.operations.randomElement(using: &generator)!
                    model.perform(operation, by: index) { Int.random(in: 0..<$0, using: &generator) }
                }
            }

            let versions = model.versions
            for _ in 0..<12 {
                model.checkLaws(
                    versions.randomElement(using: &generator)!, versions.randomElement(using: &generator)!,
                    versions.randomElement(using: &generator)!)
            }
            // The same set of versions, delivered in different orders and with repeats, to three more devices.
            let delivered = (0..<Int.random(in: 2...6, using: &generator)).map { _ in
                versions.randomElement(using: &generator)!
            }
            let reference = MergeModel.fold(delivered)
            for _ in 0..<3 {
                let repeats = (0..<3).map { _ in delivered.randomElement(using: &generator)! }
                if MergeModel.fold((delivered + repeats).shuffled(using: &generator)) != reference {
                    model.fail("the same versions in another order, with repeats, gave another item")
                }
            }

            if !model.settleAll() { model.fail("devices kept changing after exchanging everything") }
            model.checkConverged()
            failures = model.failures
            conflicts += model.conflictsSeen
            resolutions += model.resolutions
            erased += model.erased
            kept += model.keptAfterDeletion
            merges += model.mergesWritten
        }
        #expect(failures.isEmpty, "\(failures.joined(separator: "\n"))")
        // The histories reached the cases the laws are hardest in.
        #expect(conflicts > 0 && resolutions > 0 && erased > 0 && kept > 0 && merges > 0)
    }

    /// Edits of every kind; the kinds that only matter once something else has happened are drawn more often.
    static let operations: [MergeModel.Operation] =
        MergeModel.Operation.allCases + [.setField, .setField, .setField, .trash, .resolve, .resolve, .delete, .delete]
}
