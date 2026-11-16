import Foundation
import WatchwordModel

/// One value of an item together with the write it claims to come from: the revision in its stamp, and an injective,
/// platform-independent encoding of the value *and its whole stamp* (`CanonicalWriter`).
///
/// A shared vault's judge (docs/02-architecture.md §8.8, review finding S28) cannot take a value's revision on its
/// writer's word: the writer chose the stamp, so a former member can label a late value with a revision a remaining
/// member really wrote. It attributes the encoding instead, to the segment of the claimed device's own stream that
/// carried those exact bytes; a value whose bytes that stream never carried is not that device's work, whatever its
/// stamp says. The session digests `bytes`; this module stays free of CryptoKit.
public struct AttributedValue: Hashable, Sendable {
    public let revision: Revision
    public let bytes: [UInt8]
}

extension ItemMerge {
    /// Every attributable value `item` holds, read from a row written as `origin` (through `ItemState.init`, so with
    /// the bounds every merge applies): each group's values, conflicts and retained values, the field order, each
    /// note line — once with its text, and once as the bare line ID, which is what a removed copy of the line still
    /// shows — each removal of a line (review finding S32), each resolution's discard, and each history entry once
    /// for every write that recorded it (S43). A group value with no stamp is attributed to version 0 of an all-zero
    /// device, which no stream carries; a removal, discard or history entry that names no writer is read as the
    /// work of `origin`, the row that carries it (`ItemState.init`).
    ///
    /// Nothing the merge keeps is left out, and none of these parts is ever dropped by a merge (removals, discards and
    /// history only grow): so a version that holds anything a write made, or the effect of one, holds a value
    /// attributed to that write, and is judged by it (docs/10-sync-correctness.md §9).
    public static func attributedValues(_ item: Item, origin: Revision) -> [AttributedValue] {
        let state = ItemState(item, origin: origin)
        var values: [AttributedValue] = []
        for (group, register) in state.registers {
            for value in register { values.append(attributed(value, in: group)) }
        }
        for value in state.retained {
            guard let group = group(of: value.value) else { continue }
            values.append(attributed(value, in: group))
        }
        var order = CanonicalWriter()
        order.append(UInt64(2))
        order.append(UInt64(state.order.ids.count))
        for id in state.order.ids { order.append(id) }
        order.append(state.order.stamp)
        values.append(AttributedValue(revision: state.order.stamp.revision, bytes: order.bytes))
        for line in state.lines {
            var bare = CanonicalWriter()
            bare.append(UInt64(5))
            bare.append(line.id)
            values.append(AttributedValue(revision: line.id.revision, bytes: bare.bytes))
            for removal in line.removedBy {
                var removed = CanonicalWriter()
                removed.append(UInt64(7))
                removed.append(line.id)
                removed.append(removal.version)
                removed.append(removal.device)
                values.append(AttributedValue(revision: removal, bytes: removed.bytes))
            }
            guard !line.removed else { continue }
            var text = CanonicalWriter()
            text.append(UInt64(4))
            text.append(line.id)
            text.append(line.text)
            values.append(AttributedValue(revision: line.id.revision, bytes: text.bytes))
        }
        for (group, discards) in state.discards {
            for discard in discards {
                guard let revision = discard.revision else { continue }
                var writer = CanonicalWriter()
                writer.append(UInt64(8))
                writer.append(group.rawValue)
                writer.append(revision.version)
                writer.append(revision.device)
                writer.append(discard.seen)
                values.append(AttributedValue(revision: revision, bytes: writer.bytes))
            }
        }
        for (entry, writers) in state.history {
            var content = CanonicalWriter()
            content.append(entry.replacedAt)
            content.append(entry.version)
            content.append(UInt64(entry.fields.count))
            for field in entry.fields { content.append(field) }
            for revision in writers {
                var writer = CanonicalWriter()
                writer.append(UInt64(9))
                writer.append(revision.version)
                writer.append(revision.device)
                writer.append(UInt64(content.bytes.count))
                values.append(AttributedValue(revision: revision, bytes: writer.bytes + content.bytes))
            }
        }
        return values
    }

    /// The values a permanent deletion writes into a version it does not cover (`settle`): for each deletion the
    /// tombstone's summary names, the trash and "kept after a deletion" at the deletion's own revision. They are the
    /// same on every device that applies the deletion, so they are attributed to the segment carrying the tombstone.
    /// Every deletion the summary names, believed at this tombstone's stamp or not: a later tombstone of the record
    /// raises the stamp the engine believes summaries at, and what settling then writes must still be attributable.
    public static func attributedSettlement(ofErasureSummary summary: [UInt8]) -> [AttributedValue] {
        var values: [AttributedValue] = []
        for erasure in ItemErasures(summary: summary).elements where erasure != .void {
            var seen = erasure.seen
            seen.record(erasure.revision)
            let stamp = GroupStamp(revision: erasure.revision, seen: seen)
            let writes: [ItemGroupValue] = [
                .trashedAt(erasure.date ?? ItemErasure.undatedTrash), .keptAfterDeletion(true),
            ]
            for value in writes {
                guard let group = group(of: value) else { continue }
                values.append(attributed(ConflictingValue(stamp: stamp, value: value), in: group))
            }
        }
        return values
    }

    /// A group's value: the same encoding whether it is shown, a conflict or retained, since one write's value moves
    /// between the three as others edit the group.
    private static func attributed(_ value: ConflictingValue, in group: ItemGroup) -> AttributedValue {
        var writer = CanonicalWriter()
        writer.append(UInt64(1))
        writer.append(group.rawValue)
        writer.append(value.value)
        writer.append(value.stamp)
        return AttributedValue(revision: value.stamp.revision, bytes: writer.bytes)
    }
}

extension CanonicalWriter {
    mutating func append(_ stamp: GroupStamp) {
        append(stamp.revision.version)
        append(stamp.revision.device)
        append(stamp.seen)
    }

    mutating func append(_ id: NoteLine.ID) {
        append(id.revision.version)
        append(id.revision.device)
        append(UInt64(id.index))
        append(id.nonce)
    }
}
