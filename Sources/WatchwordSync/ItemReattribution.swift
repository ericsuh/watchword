import Foundation
import WatchwordModel

extension ItemMerge {
    /// `item`, read from a row written as `origin`, with every part `device` wrote above version `published` of the
    /// record written again as `writer`'s: what a store restored onto other hardware carries over from its earlier
    /// device ID (`device`, which published that version and nothing after it) to its new one (`writer`), so that the
    /// work reaches the vault's members (review of round 12, M1 and Z191; docs/10-sync-correctness.md §9).
    ///
    /// Each revision `(k, device)` with `k` above the bound is renamed `(k, writer)`, wherever it is named: a group's
    /// values, conflicts and retained values, the field order, note lines (their IDs, anchors and removals), discards
    /// and the writers of history entries. The version vectors of `device`'s and `writer`'s own parts, and the clock,
    /// keep `device`'s count up to the bound and give the rest of it to `writer`, so that whatever superseded or
    /// covered one of those revisions still does, under its new name. Nothing else changes, and no part is dropped.
    ///
    /// The bound is `published`, raised to what the item itself shows another device saw of `device` (review of
    /// round 13, M1): the highest count of `device` in any stamp or discard of a third device, the highest of its
    /// lines that a third device's line is anchored after, and the highest a third device removed. Whatever another
    /// device saw was published, so a `published` read from a lost or rolled-back state (A8), or one saved before a
    /// later publish, renames none of it; and so no part of a third device is ever rewritten: its stamps, its `seen`
    /// vectors, its discards and its lines stay byte for byte as its own stream carried them, as every member's judge
    /// checks them (docs/10 §9, clause 2). `writer`'s own parts are renamed with `device`'s: they are this
    /// installation's, and no judge counts a version of it that names `device`'s unpublished work.
    ///
    /// Sound only where nobody but this installation holds `device`'s work above the bound: what it wrote and never
    /// published. The renamed revisions are distinct from each other and from any `writer` wrote, which never wrote
    /// those versions of the record, so the renaming is one to one, and a merge with any version another device holds
    /// (each contains nothing above the bound of `device`, and nothing of `writer`'s renamed work) gives what it gave
    /// before, renamed.
    public static func reattributed(
        _ item: Item, origin: Revision, from device: UUID, above published: UInt64, to writer: UUID
    ) -> Item {
        var state = ItemState(item, origin: origin)
        guard device != writer else { return state.item }
        let bound = max(published, seenByOthers(state, of: device, besides: writer))
        func ours(_ owner: UUID) -> Bool { owner == device || owner == writer }
        func revision(_ revision: Revision) -> Revision {
            guard revision.device == device, revision.version > bound else { return revision }
            return Revision(version: revision.version, device: writer)
        }
        func vector(_ vector: VersionVector) -> VersionVector {
            guard let count = vector.entries[device], count > bound else { return vector }
            var entries = vector.entries
            entries[device] = bound
            entries[writer] = max(entries[writer] ?? 0, count)
            return VersionVector(entries)
        }
        func stamp(_ stamp: GroupStamp) -> GroupStamp {
            guard ours(stamp.revision.device) else { return stamp }
            return GroupStamp(revision: revision(stamp.revision), seen: vector(stamp.seen))
        }
        func value(_ value: ConflictingValue) -> ConflictingValue {
            ConflictingValue(stamp: stamp(value.stamp), value: value.value)
        }
        func id(_ id: NoteLine.ID) -> NoteLine.ID {
            NoteLine.ID(revision: revision(id.revision), index: id.index, nonce: id.nonce)
        }
        state.registers = state.registers.mapValues { $0.map(value) }
        state.order.stamp = stamp(state.order.stamp)
        state.clock = vector(state.clock)
        state.lines = NoteText.ordered(
            state.lines.map { line in
                var line = line
                line.id = id(line.id)
                line.after = line.after.map(id)
                line.removedBy = line.removedBy.map(revision)
                return line
            })
        state.history = state.history.mapValues { Set($0.map(revision)) }
        state.retained = Set(state.retained.map(value))
        state.discards = state.discards.mapValues { discards in
            Set(
                discards.map { discard in
                    guard let owner = discard.revision?.device, ours(owner) else { return discard }
                    return ItemDiscard(revision: discard.revision.map(revision), seen: vector(discard.seen))
                })
        }
        return state.item
    }

    /// The most of `device`'s work on the record that `state` shows a third device (neither `device` nor `besides`)
    /// had seen: its count in each such device's stamps and discards, each line of `device`'s that such a device's
    /// line is anchored after, and each line of `device`'s that such a device removed. All of it was published.
    static func seenByOthers(_ state: ItemState, of device: UUID, besides writer: UUID) -> UInt64 {
        func third(_ owner: UUID) -> Bool { owner != device && owner != writer }
        var seen: UInt64 = 0
        func note(_ stamp: GroupStamp) {
            if third(stamp.revision.device) { seen = max(seen, stamp.seen.entries[device] ?? 0) }
        }
        for value in state.registers.values.joined() { note(value.stamp) }
        for value in state.retained { note(value.stamp) }
        note(state.order.stamp)
        for discards in state.discards.values {
            for discard in discards {
                guard let owner = discard.revision?.device, third(owner) else { continue }
                seen = max(seen, discard.seen.entries[device] ?? 0)
            }
        }
        for line in state.lines {
            if third(line.id.revision.device), let after = line.after, after.revision.device == device {
                seen = max(seen, after.revision.version)
            }
            if line.id.revision.device == device, line.removedBy.contains(where: { third($0.device) }) {
                seen = max(seen, line.id.revision.version)
            }
        }
        return seen
    }
}
