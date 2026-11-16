import Foundation
import Testing
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordSync

/// The write cut, at the level of the merge (docs/10-sync-correctness.md §9, review findings S28, S32 and S43). Four
/// devices of a shared vault edit one item and exchange versions at random: three honest ones and a fourth whose
/// account is removed part-way, after which everything it writes is late — edits through `ItemMerge.stamped`, and
/// writes of a modified client that stamps nothing: a line marked removed, retained values discarded, a history entry
/// planted, none naming a writer. A version is held aside when its own revision is late or any value it holds is
/// attributed to a late revision (`ItemMerge.attributedValues`): the judge of a shared vault, with the stream index
/// and segment bytes left out (the session's adversarial suite covers those).
///
/// Device 0 learns of the removal at once and holds late versions aside as they arrive; devices 1 and 2 learn of it
/// only at the end, merge everything until then, and then rebuild from the versions that count, as a replay does.
/// Checked, after every version has reached everyone:
///
/// - device 0's copy and every rebuilt copy are the same item, the join of the versions that count;
/// - nothing in it is late: every removed line was removed by an honest edit, every retained value missing was
///   discarded by an honest resolution, every history entry was recorded by an honest edit (ground truth kept apart
///   from the item's metadata);
/// - a version written by a device that had merged nothing late is never held aside, so no honest removal, discard or
///   entry is voided by mistake.
///
/// Named `LongRunning…` so the nightly `test:long` run widens it (`WATCHWORD_LONG_TESTS`) and varies it
/// (`WATCHWORD_TEST_SEED`); a failure names its seed and history.
@Suite("Late writes held aside, under random histories")
struct LongRunningLateWriteSimulationTests {
    struct Device {
        let id: UUID
        var copy: Item
        var origin: Revision
        var highest: UInt64
        /// The edits this copy contains (ground truth, not read from the item).
        var knows: Set<Revision>
    }

    struct Version {
        var item: Item
        var origin: Revision
        /// The edits it contains.
        var knows: Set<Revision>
    }

    static let devices = [SyncFixtures.deviceA, SyncFixtures.deviceB, SyncFixtures.deviceC, UUID()]
    static let late = 3

    struct History {
        var devices: [Device]
        var versions: [Version] = []
        var lateRevisions: Set<Revision> = []
        /// The highest version the late device had written when its permission ended: an edit of its above this is
        /// outside the cut.
        var cutVersion: UInt64 = .max
        var isLate = false {
            didSet { cutVersion = devices[LongRunningLateWriteSimulationTests.late].highest }
        }
        var tick = 0.0
        // Ground truth.
        var honestlyRemoved: Set<NoteLine.ID> = []
        var honestDiscards: [VersionVector] = []
        var honestEntries: Set<ItemHistoryEntry> = []
        var lateEffects = 0

        init(start: Item) {
            let origin = Revision(version: start.version, device: LongRunningLateWriteSimulationTests.devices[0])
            devices = LongRunningLateWriteSimulationTests.devices.map {
                Device(id: $0, copy: start, origin: origin, highest: start.version, knows: [origin])
            }
            versions = [Version(item: start, origin: origin, knows: [origin])]
            honestEntries = Set(start.history.map(ItemState.content(of:)))
        }

        /// The judge: the version's own revision, every value it holds, and every edit its clock says it contains
        /// (S44), must count.
        func held(_ item: Item, origin: Revision) -> Bool {
            let lateDevice = LongRunningLateWriteSimulationTests.devices[LongRunningLateWriteSimulationTests.late]
            return lateRevisions.contains(origin)
                || ItemMerge.attributedValues(item, origin: origin).contains { lateRevisions.contains($0.revision) }
                || (ItemMerge.effectiveClock(item, origin: origin).entries[lateDevice] ?? 0) > cutVersion
        }

        mutating func nextRevision(_ index: Int, above other: UInt64 = 0) -> Revision {
            let version = max(devices[index].highest, devices[index].copy.version, other) + 1
            devices[index].highest = version
            let revision = Revision(version: version, device: devices[index].id)
            if isLate, index == LongRunningLateWriteSimulationTests.late { lateRevisions.insert(revision) }
            return revision
        }

        mutating func store(_ index: Int, _ item: Item, origin: Revision, edit: Bool) {
            devices[index].copy = item
            devices[index].origin = origin
            if edit { devices[index].knows.insert(origin) }
            versions.append(Version(item: item, origin: origin, knows: devices[index].knows))
            // A device that had merged nothing late never writes a version that is held aside.
            if !lateRevisions.contains(origin), devices[index].knows.isDisjoint(with: lateRevisions),
                held(item, origin: origin)
            {
                Issue.record("an honest version is held aside: \(origin)")
            }
        }

        var honest: Bool { !isLate }

        mutating func edit(_ index: Int, using generator: inout SeededGenerator) {
            tick += 1
            let device = devices[index]
            var draft = device.copy
            draft.modifiedAt = Date(timeIntervalSince1970: 1_800_000_000 + tick)
            let honestWrite = index != LongRunningLateWriteSimulationTests.late || !isLate
            switch Int.random(in: 0..<5, using: &generator) {
            case 0:
                draft.fields[1].value = "password-\(Int(tick))"
            case 1:
                draft.title = ["Bank", "Bank (joint)", "First Bank"].randomElement(using: &generator)!
            case 2:
                var lines = NoteText.lines(of: draft.notes)
                if lines.count > 1, Bool.random(using: &generator) {
                    lines.remove(at: Int.random(in: 0..<lines.count, using: &generator))
                } else {
                    lines.insert("line \(Int(tick))", at: Int.random(in: 0...lines.count, using: &generator))
                }
                draft.notes = lines.joined(separator: "\n")
            case 3:
                let values = ItemMerge.conflicts(of: draft)[.title] ?? []
                guard let chosen = values.randomElement(using: &generator) else { return }
                let revision = nextRevision(index)
                var resolved = ItemMerge.resolve(
                    draft, group: .title, choosing: chosen.value, origin: device.origin, revision: revision)
                resolved.modifiedAt = max(resolved.modifiedAt, draft.modifiedAt)
                if honestWrite { honestDiscards.append(ItemMerge.effectiveClock(device.copy, origin: device.origin)) }
                store(index, resolved, origin: revision, edit: true)
                return
            default:
                guard !honestWrite else { return }
                modifiedClient(index, using: &generator)
                return
            }
            if draft.fields != device.copy.fields {
                let entry = ItemHistoryEntry(
                    replacedAt: draft.modifiedAt, version: device.copy.version, fields: device.copy.fields)
                draft.history.insert(entry, at: 0)
                if honestWrite { honestEntries.insert(entry) }
            }
            let revision = nextRevision(index)
            draft.version = revision.version
            let saved = ItemMerge.stamped(
                draft, previous: device.copy, previousOrigin: device.origin, revision: revision, using: &generator)
            if honestWrite {
                let before = Set(device.copy.noteLines.filter(\.removed).map(\.id))
                honestlyRemoved.formUnion(saved.noteLines.filter { $0.removed && !before.contains($0.id) }.map(\.id))
            }
            store(index, saved, origin: revision, edit: true)
        }

        /// What a modified client of the late account writes: one change, stamped by nothing.
        mutating func modifiedClient(_ index: Int, using generator: inout SeededGenerator) {
            var item = devices[index].copy
            switch Int.random(in: 0..<3, using: &generator) {
            case 0:
                guard
                    let line = item.noteLines.indices.filter({ !item.noteLines[$0].removed }).randomElement(
                        using: &generator)
                else { return }
                item.noteLines[line].removed = true
                item.noteLines[line].text = ""
                item.notes = NoteText.text(item.noteLines)
            case 1:
                guard !item.retainedValues.isEmpty else { return }
                item.discards[.title, default: []].append(ItemDiscard(revision: nil, seen: item.clock))
                item.retainedValues = []
            default:
                let planted = Field(kind: .password, label: "Password", value: "planted-\(Int(tick))")
                item.history.insert(ItemHistoryEntry(replacedAt: item.modifiedAt, version: 1, fields: [planted]), at: 0)
            }
            let revision = nextRevision(index)
            item.version = revision.version
            store(index, item, origin: revision, edit: true)
        }

        mutating func receive(at index: Int, _ version: Version) {
            let device = devices[index]
            // Device 0 knows of the removal, and holds late versions aside as they arrive.
            if index == 0, held(version.item, origin: version.origin) { return }
            let merged = ItemMerge.merge(device.copy, origin: device.origin, version.item, origin: version.origin)
            devices[index].knows.formUnion(version.knows)
            guard !ItemMerge.sameState(merged, device.copy) else { return }
            let revision = nextRevision(index, above: max(device.copy.version, version.item.version))
            store(index, ItemMerge.written(merged, as: revision), origin: revision, edit: false)
        }

        /// The join of every version that counts: what a replay rebuilds, on any device holding all of them.
        func rebuilt() -> Item? {
            var result: (item: Item, origin: Revision)?
            for version in versions where !held(version.item, origin: version.origin) {
                guard let current = result else {
                    result = (version.item, version.origin)
                    continue
                }
                let merged = ItemMerge.merge(current.item, origin: current.origin, version.item, origin: version.origin)
                result = (merged, Revision(version: merged.version, device: ItemMerge.zeroDevice))
            }
            return result?.item
        }
    }

    @Test("a device that learnt of the removal first and one that learnt last hold the same item, with nothing late")
    func lateWritesUnderRandomHistories() {
        let seed = TestEnvironment.seed(fallback: 0x5432_43A7)
        var generator = SeededGenerator(seed: seed)
        let histories = TestEnvironment.iterations(standard: 150, long: 3_000)
        var withLateEffects = 0
        var heldAside = 0
        for history in 0..<histories {
            var start = MergeFixtures.base(notes: "one\ntwo\nthree\nfour")
            start.title = "Bank"
            var run = History(start: start)
            let steps = Int.random(in: 10...50, using: &generator)
            let cut = Int.random(in: 0..<steps, using: &generator)
            for step in 0..<steps {
                if step == cut { run.isLate = true }
                let index = Int.random(in: 0..<Self.devices.count, using: &generator)
                if Int.random(in: 0..<100, using: &generator) < 45 {
                    let source = Int.random(in: 0..<Self.devices.count, using: &generator)
                    let version = Version(
                        item: run.devices[source].copy, origin: run.devices[source].origin,
                        knows: run.devices[source].knows)
                    run.receive(at: index, version)
                } else {
                    run.edit(index, using: &generator)
                }
            }
            // A device that merged late work shows its effect until it learns of the removal.
            let unaware = run.devices[1].copy
            // Everything reaches everyone, in random order, until nobody writes anything new.
            var delivered = 0
            while delivered < run.versions.count {
                delivered = run.versions.count
                for index in 0..<3 {
                    for version in run.versions.shuffled(using: &generator) { run.receive(at: index, version) }
                }
            }
            guard let rebuilt = run.rebuilt() else {
                Issue.record("seed \(seed), history \(history): nothing counts")
                continue
            }
            heldAside += run.versions.filter { run.held($0.item, origin: $0.origin) }.count
            if !ItemMerge.sameState(unaware, rebuilt) && run.held(unaware, origin: run.devices[1].origin) {
                withLateEffects += 1
            }

            let context = "seed \(seed), history \(history)"
            #expect(ItemMerge.sameState(run.devices[0].copy, rebuilt), "\(context): the aware device differs")
            // Every version that counts is in it.
            let origin = Revision(version: rebuilt.version, device: ItemMerge.zeroDevice)
            for version in run.versions where !run.held(version.item, origin: version.origin) {
                let again = ItemMerge.merge(rebuilt, origin: origin, version.item, origin: version.origin)
                #expect(ItemMerge.sameState(again, rebuilt), "\(context): a version that counts is missing")
            }
            for line in rebuilt.noteLines where line.removed {
                #expect(run.honestlyRemoved.contains(line.id), "\(context): a line removed by a late write")
            }
            let retained = Set(rebuilt.retainedValues)
            for version in run.versions where !run.held(version.item, origin: version.origin) {
                for value in version.item.retainedValues where !retained.contains(value) {
                    #expect(
                        run.honestDiscards.contains { $0.contains(value.stamp.revision) },
                        "\(context): a retained value discarded by a late write")
                }
            }
            for entry in rebuilt.history {
                #expect(
                    run.honestEntries.contains(ItemState.content(of: entry)), "\(context): a late history entry")
            }
        }
        // Not vacuous: late work was merged by the unaware device and undone by the rebuild, often.
        #expect(withLateEffects > histories / 10)
        #expect(heldAside > histories)
    }
}
