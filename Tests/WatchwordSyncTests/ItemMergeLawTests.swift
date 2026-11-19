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

    /// The laws a restore's carry rests on (`ItemMerge.reattributed`; docs/10-sync-correctness.md §9; review of round
    /// 13), under the same random histories. The model's last device is the earlier ID; at a random point its copy is
    /// backed up (`a`), with `published` the most of its writes any other copy had seen by then (what its stream can
    /// have carried) and `given` a bound drawn at or below it (a state that says too little). Then the history goes
    /// on, the earlier ID included: old hardware still running, which publishes `a2`, a version that contains `a`.
    ///
    /// `checkReattribution` checks, against every version the other devices stored before the backup: the carry
    /// commutes with merges but for a field order's tie, where only the carry made before the merge gives what every
    /// device holding the pulled version holds (L1 and Z210, the restored ID drawn at random); it is idempotent, keeps
    /// supersession and coverage, and (with `given`) never rewrites a third device's part (M1). Then, for versions `b`
    /// other devices stored after it, `R(a)`, `a2` and `b` merged in every order give one item, holding every value
    /// `a2 ⊔ b` holds (M2's case: nothing old hardware published is lost beside the carry). The field order is the exception, and is left out: it is one register whose latest write
    /// wins, and the carry's renamed copy of the same write can win over `a2`'s with the same field IDs.
    ///
    /// The counts asserted are the cases the laws exist for, so that a change to the model cannot leave them untested:
    /// a backup holding something to carry (`renamed`), a third device's part that had seen the earlier ID above
    /// `given` (`raised`, which the code before M1 rewrote), and old hardware that went on to publish a version
    /// containing the backup (`continued`).
    @Test(
        "a restore's carry is a renaming: it commutes with merges and never rewrites another device",
        arguments: [1, 2, 3, 4])
    func reattribution(_ run: UInt64) {
        let seed = TestEnvironment.seed(fallback: 0x4EA7_7EED) &+ run
        var generator = SeededGenerator(seed: seed)
        let histories = TestEnvironment.iterations(standard: 60, long: 1_000)
        var renamed = 0
        var raised = 0
        var continued = 0
        var tied = 0
        var failures: [String] = []
        for history in 0..<histories where failures.isEmpty {
            let devices = Int.random(in: 2...4, using: &generator)
            let earlier = devices - 1
            var model = MergeModel(devices: devices)
            model.context = "seed \(seed), history \(history)"
            var published: UInt64 = 0
            func step(_ model: inout MergeModel) {
                let index = Int.random(in: 0..<devices, using: &generator)
                if Int.random(in: 0..<100, using: &generator) < 45 {
                    model.receive(at: index, from: Int.random(in: 0..<devices, using: &generator))
                } else {
                    let operation = Self.operations.randomElement(using: &generator)!
                    model.perform(operation, by: index) { Int.random(in: 0..<$0, using: &generator) }
                }
            }
            for _ in 0..<Int.random(in: 6...36, using: &generator) {
                step(&model)
                published = max(published, model.seenByOthers(of: earlier))
            }
            let device = model.replicas[earlier].device
            guard let item = model.replicas[earlier].item, let origin = model.replicas[earlier].origin else { continue }
            let backup = MergeModel.Version(item: item, origin: origin)
            let before = model.versions.filter { $0.origin.device != device }
            // Half the time no state at all (lost with the restore, or one that does not verify, A8): nothing published.
            let given = Bool.random(using: &generator) ? 0 : UInt64.random(in: 0...published, using: &generator)
            let restored = MergeModel.restoredDevice(using: &generator)
            let found = model.checkReattribution(
                backup, of: device, published: published, given: given, others: before, restored: restored)
            if found.renamed { renamed += 1 }
            if found.raised { raised += 1 }
            if found.tied { tied += 1 }

            // Old hardware goes on under the earlier ID, and the others with it.
            let stored = model.versions.count
            for _ in 0..<Int.random(in: 2...20, using: &generator) { step(&model) }
            guard let later = model.replicas[earlier].item, let laterOrigin = model.replicas[earlier].origin else {
                failures = model.failures
                continue
            }
            let a2 = MergeModel.Version(item: later, origin: laterOrigin)
            guard MergeModel.join(a2, backup).item == a2.item else {
                failures = model.failures
                continue
            }
            continued += 1
            let carried = MergeModel.carried(backup, from: device, above: published, to: restored)
            let after = model.versions[stored...].filter { $0.origin.device != device }
            for b in after.shuffled(using: &generator).prefix(4) {
                let orders = [
                    [carried, a2, b], [carried, b, a2], [a2, carried, b], [a2, b, carried], [b, carried, a2],
                    [b, a2, carried],
                ]
                let results = Set(orders.compactMap(MergeModel.fold))
                if results.count != 1 { model.fail("the carry, old hardware's version and another's do not converge") }
                // Every attributed value but the field order's, whose encoding is tagged 2 (`attributedValues`).
                func values(_ item: Item, _ origin: Revision) -> Set<AttributedValue> {
                    Set(
                        ItemMerge.attributedValues(item, origin: origin).filter {
                            $0.bytes.count < 8 || $0.bytes[7] != 2
                        })
                }
                let joined = MergeModel.join(a2, b)
                guard let result = results.first else { continue }
                let lost = values(joined.item, joined.origin).subtracting(
                    values(result, Revision(version: result.version, device: ItemMerge.zeroDevice)))
                if !lost.isEmpty {
                    model.fail("merged with the carry, values old hardware published are gone: \(lost.map(\.revision))")
                }
            }
            failures = model.failures
        }
        #expect(failures.isEmpty, "\(failures.joined(separator: "\n"))")
        // Ties (`tied`) are rare under random histories and not asserted here; the exhaustive exploration meets them.
        #expect(
            renamed > 0 && raised > 0 && continued > 0,
            "renamed \(renamed), raised \(raised), continued \(continued), tied \(tied)")
    }

    /// Edits of every kind; the kinds that only matter once something else has happened are drawn more often.
    static let operations: [MergeModel.Operation] =
        MergeModel.Operation.allCases + [.setField, .setField, .setField, .trash, .resolve, .resolve, .delete, .delete]
}
