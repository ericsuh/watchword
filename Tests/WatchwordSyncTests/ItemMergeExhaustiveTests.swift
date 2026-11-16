import Foundation
import Testing
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordSync

/// Every history of a small configuration (docs/10-sync-correctness.md §7, docs/04-test-plan.md §3): random testing
/// misses corners, so here nothing is sampled. From a starting point, every sequence of up to `depth` steps is
/// explored — each step one device performing one operation of the alphabet, or receiving another device's version —
/// and at every node of that tree:
///
/// - the copy just written matches the specification of a multi-value register, and every update contains the version
///   it was made on (`MergeModel`);
/// - every new version satisfies the semilattice laws with every pair of versions stored so far, which covers every
///   order in which three versions can be merged;
/// - all versions stored so far, merged in several orders, give one item;
/// - from that point, exchanging everything makes every device hold the same item, with nothing a person typed gone
///   unless a person discarded it.
///
/// The number of histories explored is asserted, so the test cannot silently shrink, and so are the counts of the
/// cases it exists for (conflicts, resolutions, deletions that erased, deletions that kept a version).
///
/// Nothing here is random. It is named `LongRunning…` because the nightly `test:long` run takes two of the
/// explorations one step deeper (`WATCHWORD_LONG_TESTS`).
@Suite("Item merge, every small history")
struct LongRunningItemMergeExhaustiveTests {
    struct Totals: Equatable {
        /// Sequences of steps explored, the empty one included.
        var histories = 0
        /// Histories in which a conflict was shown, one was resolved, a deletion erased the item everywhere, and a
        /// deletion left a version in the trash.
        var conflicts = 0
        var resolutions = 0
        var erased = 0
        var kept = 0
        /// Distinct versions stored, and distinct pairs and triples of them the laws were checked on.
        var versions = 0
        var pairs = 0
        var triples = 0
    }

    /// One exploration: every sequence of at most `depth` steps from a starting point. Versions are numbered as they
    /// are first stored, so that a pair or triple of them reached by many histories is checked once.
    struct Exploration {
        let alphabet: [MergeModel.Operation]
        var totals = Totals()
        var failures: [String] = []
        private var numbers: [MergeModel.Version: Int] = [:]
        /// Each version as the merge reads it, read once.
        private var states: [ItemState] = []
        private var joins: [[Int]: ItemState] = [:]
        private var checked: Set<[Int]> = []

        init(alphabet: [MergeModel.Operation]) {
            self.alphabet = alphabet
        }

        private mutating func number(_ version: MergeModel.Version, in model: inout MergeModel) -> Int {
            if let number = numbers[version] { return number }
            numbers[version] = states.count
            let state = ItemState(version.item, origin: version.origin)
            // Reading a stored version and writing it back changes nothing: it is in the one form the merge writes.
            if state.item != version.item { model.fail("a stored version is not in canonical form") }
            states.append(state)
            totals.versions += 1
            return states.count - 1
        }

        /// `x ⊔ y`, with commutativity, idempotence and containment checked the first time the pair is met — and
        /// that the public `ItemMerge.merge` is this join, read back unchanged.
        private mutating func join(_ x: Int, _ y: Int, in model: inout MergeModel) -> ItemState {
            let key = [min(x, y), max(x, y)]
            if let known = joins[key] { return known }
            let joined = states[x].joined(states[y])
            let item = joined.item
            if states[y].joined(states[x]).item != item { model.fail("merge is not commutative") }
            if x == y, item != states[x].item { model.fail("merge is not idempotent") }
            if joined.joined(states[x]).item != item || joined.joined(states[y]).item != item {
                model.fail("a merge does not contain its inputs")
            }
            let origin = Revision(version: item.version, device: ItemMerge.zeroDevice)
            if ItemMerge.canonical(item, origin: origin) != item {
                model.fail("a merge result is not in canonical form")
            }
            joins[key] = joined
            totals.pairs += 1
            return joined
        }

        /// Explores from `model`, whose first `known` versions an ancestor has already checked.
        mutating func explore(_ model: MergeModel, depth: Int, path: String, known: Int) {
            guard failures.isEmpty else { return }
            var model = model
            model.context = path
            totals.histories += 1

            // The laws, for each version this step stored against every pair stored so far: every way of merging
            // three versions gives one item.
            let stored = model.versions
            let versions = stored.map { number($0, in: &model) }
            for new in versions[known...] {
                for (index, x) in versions.enumerated() {
                    for y in versions[index...] {
                        guard checked.insert([x, y, new].sorted()).inserted else { continue }
                        totals.triples += 1
                        let left = join(x, y, in: &model).joined(states[new]).item
                        if left != states[x].joined(join(y, new, in: &model)).item
                            || left != join(x, new, in: &model).joined(states[y]).item
                        {
                            model.fail("merge is not associative")
                        }
                    }
                }
            }
            // Through the public merge, as a device receiving the versions one at a time would: in the order stored,
            // in reverse, and rotated with every version delivered twice.
            if stored.count > 2, known < stored.count {
                let reference = MergeModel.fold(stored)
                if MergeModel.fold(stored.reversed()) != reference
                    || MergeModel.fold(Array(stored[1...]) + stored + [stored[0]]) != reference
                {
                    model.fail("the stored versions merged in another order, with repeats, gave another item")
                }
            }

            // From here, exchanging everything converges and loses nothing.
            var healed = model
            if !healed.settleAll() { healed.fail("devices kept changing after exchanging everything") }
            healed.checkConverged()
            failures = healed.failures
            guard failures.isEmpty else { return }
            totals.conflicts += healed.conflictsSeen > 0 ? 1 : 0
            totals.resolutions += model.resolutions > 0 ? 1 : 0
            totals.erased += model.erased > 0 && healed.replicas.allSatisfy { $0.item == nil } ? 1 : 0
            totals.kept += healed.keptAfterDeletion > 0 ? 1 : 0
            guard depth > 0 else { return }

            for device in model.replicas.indices {
                for operation in alphabet {
                    var next = model
                    // Where an operation has a choice it takes the first: the others are other histories' firsts.
                    // A step that does nothing (resolving where nothing conflicts, deleting what is not in the trash)
                    // is not a history of its own.
                    guard next.perform(operation, by: device, pick: { _ in 0 }) else { continue }
                    explore(next, depth: depth - 1, path: path + " \(device):\(operation)", known: stored.count)
                }
                for source in model.replicas.indices where source != device {
                    var next = model
                    guard next.receive(at: device, from: source) else { continue }
                    explore(next, depth: depth - 1, path: path + " \(device)<\(source)", known: stored.count)
                }
            }
        }
    }

    /// Explores and compares with the totals recorded when the test was written. A change to the merge that alters
    /// what small histories reach shows up here as a different count, to be understood before the number is changed.
    ///
    /// Review finding Y33 changed three standard totals: the lines an edit inserts now carry a nonce, drawn here from
    /// a generator seeded by the step so that counts repeat, so two histories that insert the same line at the same
    /// revision by different paths store two versions where they stored one. Drawing a constant nonce gives the old
    /// totals exactly.
    static func check(
        _ start: MergeModel, alphabet: [MergeModel.Operation], depth: Int, expecting expected: Totals,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        var exploration = Exploration(alphabet: alphabet)
        exploration.explore(start, depth: depth, path: "", known: 0)
        #expect(
            exploration.failures.isEmpty, "\(exploration.failures.joined(separator: "\n"))",
            sourceLocation: sourceLocation)
        #expect(exploration.totals == expected, sourceLocation: sourceLocation)
    }

    /// Edits of a field, its removal, a reorder, an attribute, a notes line, trash and restore, conflict resolution
    /// and permanent deletion.
    static let alphabet: [MergeModel.Operation] = [
        .setField, .removeField, .reorder, .setTitle, .replaceLine, .trash, .restore, .resolve, .delete,
    ]

    /// One more step in the nightly run (`WATCHWORD_LONG_TESTS`), where a history can hold a conflict, its
    /// resolution, and something concurrent with both.
    static var depth: Int {
        TestEnvironment.isLongRun ? 4 : 3
    }

    @Test("two devices, every history from a fresh item")
    func twoDevices() {
        Self.check(
            MergeModel(devices: 2), alphabet: Self.alphabet, depth: Self.depth,
            expecting: TestEnvironment.isLongRun
                ? Totals(
                    histories: 32083, conflicts: 7324, resolutions: 20, erased: 376, kept: 1148, versions: 9077,
                    pairs: 65141, triples: 230823)
                : Totals(
                    histories: 2321, conflicts: 324, resolutions: 0, erased: 30, kept: 36, versions: 885, pairs: 4643,
                    triples: 13145))
    }

    @Test("two devices that already disagree about one field, every history from there")
    func twoDevicesInConflict() {
        var start = MergeModel(devices: 2)
        start.perform(.setField, by: 0) { _ in 1 }
        start.perform(.setField, by: 1) { _ in 1 }
        Self.check(
            start, alphabet: Self.alphabet, depth: Self.depth,
            expecting: TestEnvironment.isLongRun
                ? Totals(
                    histories: 43593, conflicts: 42449, resolutions: 2134, erased: 208, kept: 1644, versions: 13277,
                    pairs: 121045, triples: 564263)
                : Totals(
                    histories: 3037, conflicts: 2979, resolutions: 80, erased: 6, kept: 68, versions: 1283, pairs: 9244,
                    triples: 36086))
    }

    @Test("two devices, one of which has trashed the item, every history from there")
    func twoDevicesWithTrash() {
        var start = MergeModel(devices: 2)
        start.perform(.trash, by: 0) { _ in 0 }
        Self.check(
            start, alphabet: Self.alphabet, depth: 3,
            expecting: Totals(
                histories: 3514, conflicts: 968, resolutions: 2, erased: 95, kept: 322, versions: 1238, pairs: 7692,
                triples: 25867))
    }

    /// The start `resolutionDiscardsEverywhere` needs: both devices edited a field while it held a conflict, so each
    /// retains a value and the field is in conflict again.
    @Test("two devices holding retained values and a fresh conflict, every history from there")
    func twoDevicesWithRetainedValues() {
        var start = MergeModel(devices: 2)
        start.perform(.setField, by: 0) { _ in 1 }
        start.perform(.setField, by: 1) { _ in 1 }
        start.receive(at: 0, from: 1)
        start.receive(at: 1, from: 0)
        start.perform(.setField, by: 0) { _ in 1 }
        start.perform(.setField, by: 1) { _ in 1 }
        Self.check(
            start, alphabet: [.setField, .removeField, .setTitle, .resolve], depth: 3,
            expecting: Totals(
                histories: 585, conflicts: 585, resolutions: 44, erased: 0, kept: 0, versions: 302, pairs: 2905,
                triples: 15316))
    }

    @Test("three devices, two of which hold the item in the trash, every history of edits, removals and deletion")
    func threeDevices() {
        var start = MergeModel(devices: 3)
        start.perform(.trash, by: 0) { _ in 0 }
        start.receive(at: 1, from: 0)
        Self.check(
            start, alphabet: [.setField, .removeField, .restore, .resolve, .delete], depth: 3,
            expecting: Totals(
                histories: 1891, conflicts: 572, resolutions: 0, erased: 142, kept: 448, versions: 332, pairs: 1993,
                triples: 6622))
    }
}
