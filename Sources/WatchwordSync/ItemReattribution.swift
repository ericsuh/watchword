import Foundation
import WatchwordModel

extension ItemMerge {
    /// `item`, read from a row written as `origin`, with every part `device` wrote above version `published` of the
    /// record written again as `writer`'s: what a store restored onto other hardware carries over from its earlier
    /// device ID (`device`, which published that version and nothing after it) to its new one (`writer`), so that the
    /// work reaches the vault's members (review of round 12, M1 and Z191; docs/10-sync-correctness.md §9).
    ///
    /// Each revision `(k, device)` with `k` above `published` becomes `(k, writer)`, wherever it is named: a group's
    /// values, conflicts and retained values, the field order, note lines (their IDs, anchors and removals), discards
    /// and the writers of history entries. Every version vector (each stamp's `seen`, each discard's, the clock) keeps
    /// `device`'s count up to `published` and gives the rest of it to `writer`, so that whatever superseded or covered
    /// one of those revisions still does, under its new name. Nothing else changes, and no part is dropped: the result
    /// holds what `item` held, attributed so that each value of `device` it still names was in a version that ID
    /// published, and its clock claims no edit of `device` that ID did not publish.
    ///
    /// Sound only where nobody but this installation holds `device`'s work above `published`: what it wrote and never
    /// published. The renamed revisions are distinct from each other and from any `writer` wrote, which never wrote
    /// the record before, so the renaming is one to one, and a merge with any version another device holds (each
    /// contains nothing above `published` of `device`) gives what it gave before, renamed.
    public static func reattributed(
        _ item: Item, origin: Revision, from device: UUID, above published: UInt64, to writer: UUID
    ) -> Item {
        var state = ItemState(item, origin: origin)
        guard device != writer else { return state.item }
        func revision(_ revision: Revision) -> Revision {
            guard revision.device == device, revision.version > published else { return revision }
            return Revision(version: revision.version, device: writer)
        }
        func vector(_ vector: VersionVector) -> VersionVector {
            guard let count = vector.entries[device], count > published else { return vector }
            var entries = vector.entries
            entries[device] = published
            entries[writer] = max(entries[writer] ?? 0, count)
            return VersionVector(entries)
        }
        func stamp(_ stamp: GroupStamp) -> GroupStamp {
            GroupStamp(revision: revision(stamp.revision), seen: vector(stamp.seen))
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
            Set(discards.map { ItemDiscard(revision: $0.revision.map(revision), seen: vector($0.seen)) })
        }
        return state.item
    }
}
