import Foundation
import WatchwordModel

/// Notes as a line-level sequence CRDT (an RGA over lines; PRD F7.6, docs/02-architecture.md §7.5,
/// docs/10-sync-correctness.md §3.4).
///
/// Every line has a unique ID (the revision that inserted it, its index in that edit, and a nonce drawn for the edit
/// so that no other writer can name the line before seeing it) and names the line it was inserted after. Lines are
/// never changed in place: an edit removes the old line and inserts the new text, and the removal names the edit that
/// made it (`NoteLine.removedBy`, review finding S32). The replicated state is the set of lines by ID; merging is the
/// union, joined line by line (`join`: removal wins, and every removal is kept), and the document order is a function
/// of that set alone — children of a line, newest first, depth first — so devices that have seen the same edits show
/// the same notes, and concurrent edits to different lines all survive. Two devices that change the same line
/// concurrently both keep their version, one after the other; nothing either of them typed is lost.
///
/// The merge is a join for *any* two sets of lines, not only honest ones: `join` is one, entry by entry, and `ordered`
/// is total (dangling anchors, cycles and repeated IDs all have a defined place), so a crafted line cannot make two
/// devices disagree, loop, or drop a line another device wrote.
///
/// Text is compared byte for byte throughout (docs/10-sync-correctness.md §2): a line respelt in another Unicode
/// normalisation form is another line.
public enum NoteText {
    /// The lines of `text`; empty notes have none. Every U+000A ends a line, including the one in a CR-LF pair, so no
    /// line holds a line break.
    public static func lines(of text: String) -> [String] {
        guard !text.isEmpty else { return [] }
        return text.utf8.split(separator: lineBreak, omittingEmptySubsequences: false).map {
            String(decoding: $0, as: UTF8.self)
        }
    }

    /// The visible text of `lines`, in document order.
    public static func text(_ lines: [NoteLine]) -> String {
        ordered(lines).filter { !$0.removed }.map(\.text).joined(separator: "\n")
    }

    /// `text` written from scratch by `revision`.
    public static func initial(_ text: String, revision: Revision) -> [NoteLine] {
        edit([], to: text, revision: revision)
    }

    /// One line per ID, in document order: depth first from the start, each line's children newest first. Lines given
    /// more than once under one ID are joined (`join`). A line whose anchor is not among the lines is placed as if
    /// inserted at the start, and lines that sit in a cycle follow everything else, each cycle from its least ID
    /// (only a hostile writer produces either): none is dropped.
    ///
    /// Linear in the size of the lines, up to sorting: copies of one ID are gathered and joined together, not folded
    /// in one at a time, which for thousands of copies with different texts re-split and re-sorted the text so far at
    /// every step (review finding Y32).
    public static func ordered(_ lines: [NoteLine]) -> [NoteLine] {
        var byID: [NoteLine.ID: NoteLine] = [:]
        byID.reserveCapacity(lines.count)
        var copies: [NoteLine.ID: [NoteLine]] = [:]
        for line in lines {
            if byID[line.id] == nil {
                byID[line.id] = line.removed || !line.removedBy.isEmpty ? removed(line, by: nil) : line
            } else {
                copies[line.id, default: []].append(line)
            }
        }
        for (id, others) in copies {
            guard let first = byID[id] else { continue }
            byID[id] = join([first] + others)
        }
        var children: [NoteLine.ID?: [NoteLine]] = [:]
        for line in byID.values {
            let parent = line.after.flatMap { byID[$0] == nil ? nil : $0 }
            children[parent, default: []].append(line)
        }
        for key in children.keys { children[key]!.sort { $0.id > $1.id } }
        var result: [NoteLine] = []
        result.reserveCapacity(byID.count)
        var visited: Set<NoteLine.ID> = []
        // Iterative, so a long chain of lines cannot exhaust the stack.
        func place(_ roots: [NoteLine]) {
            var stack: [NoteLine] = roots.reversed()
            while let line = stack.popLast() {
                guard visited.insert(line.id).inserted else { continue }
                result.append(line)
                stack.append(contentsOf: (children[line.id] ?? []).reversed())
            }
        }
        place(children[nil] ?? [])
        if result.count < byID.count {
            // What no path from the start reaches sits in a cycle of anchors, or hangs off one. Each such group is
            // laid out as the rest is, depth first, from its least ID — so a line inserted after one of them still
            // follows it, and an edit of such notes saves what the person typed, in the order they typed it.
            for root in byID.values.filter({ !visited.contains($0.id) }).sorted(by: { $0.id < $1.id }) {
                place([root])
            }
        }
        return result
    }

    /// The union of two versions' lines, in document order. A line removed in either is removed.
    public static func merge(_ a: [NoteLine], _ b: [NoteLine]) -> [NoteLine] {
        ordered(a + b)
    }

    /// `lines` as read from a record written at version `limit`: no line may claim a newer revision than the record
    /// that carries it, so IDs, anchors and removals above it are lowered to it (docs/10-sync-correctness.md §6). This
    /// bounds what a record can claim; the nonce in every ID is what keeps a writer from naming lines it has not seen
    /// (`NoteLine.ID`).
    public static func clamped(_ lines: [NoteLine], to limit: UInt64) -> [NoteLine] {
        guard
            lines.contains(where: {
                $0.id.revision.version > limit || ($0.after?.revision.version ?? 0) > limit
                    || $0.removedBy.contains { $0.version > limit }
            })
        else { return lines }
        return lines.map { line in
            var line = line
            line.id.revision = line.id.revision.clamped(to: limit)
            // Only the revision is lowered: the anchor keeps its index and nonce, so it still names the line.
            if var after = line.after {
                after.revision = after.revision.clamped(to: limit)
                line.after = after
            }
            line.removedBy = line.removedBy.map { $0.clamped(to: limit) }
            return line
        }
    }

    /// `lines` as read from a record written as `origin` (`ItemState.init`): clamped to its version, and every
    /// removal that names no writer — a record from before removals did, or one whose writer left it out — read as
    /// the record's own write (review finding S32). So every removal the merge holds names a writer, and one a record
    /// carries without naming it is the work of whoever wrote that record.
    public static func read(_ lines: [NoteLine], origin: Revision) -> [NoteLine] {
        clamped(lines, to: origin.version).map { line in
            guard line.removed, line.removedBy.isEmpty else { return line }
            var line = line
            line.removedBy = [origin]
            return line
        }
    }

    /// The lines after changing the visible text to `text`: unchanged lines keep their IDs, removed ones are marked,
    /// new ones are inserted by `revision` after the line that precedes them, each carrying `nonce` in its ID. Nothing
    /// is dropped, so the result contains `lines` (`merge(result, lines) == result`).
    ///
    /// `nonce` is a number no other writer can predict, drawn once for the edit (`ItemMerge.stamped` draws it). The
    /// default, zero, is for the lines of a new item and for tests; see `NoteLine.ID`.
    public static func edit(_ lines: [NoteLine], to text: String, revision: Revision, nonce: UInt64 = 0)
        -> [NoteLine]
    {
        let document = ordered(lines)
        let visible = document.filter { !$0.removed }
        // Unchanged notes are no edit, even where a line holds a line break (two texts joined under one ID).
        if visible.map(\.text).joined(separator: "\n").utf8.elementsEqual(text.utf8) { return document }
        let old = visible.map { Array($0.text.utf8) }
        let new = Self.lines(of: text)
        let matches = commonLines(old, new.map { Array($0.utf8) })

        var removedIDs: Set<NoteLine.ID> = []
        let matchedOld = Set(matches.map(\.0))
        for (index, line) in visible.enumerated() where !matchedOld.contains(index) {
            removedIDs.insert(line.id)
        }
        var oldForNew: [Int: Int] = [:]
        for (oldIndex, newIndex) in matches { oldForNew[newIndex] = oldIndex }

        // A fresh revision has no lines yet. One that does (a caller reusing a revision, or lines another writer
        // filed under it) continues after them, so a new line never lands on an existing ID.
        var nextIndex: UInt32 = 0
        for line in document where line.id.revision == revision && line.id.index >= nextIndex {
            nextIndex = line.id.index == .max ? .max : line.id.index + 1
        }
        var inserted: [NoteLine] = []
        var previous: NoteLine.ID?
        for (newIndex, content) in new.enumerated() {
            if let oldIndex = oldForNew[newIndex] {
                previous = visible[oldIndex].id
            } else {
                let id = NoteLine.ID(revision: revision, index: nextIndex, nonce: nonce)
                if nextIndex < .max { nextIndex += 1 }
                inserted.append(NoteLine(id: id, after: previous, text: content))
                previous = id
            }
        }
        let kept = document.map { removedIDs.contains($0.id) ? removed($0, by: revision) : $0 }
        return ordered(kept + inserted)
    }

    /// The join of two copies of one line (same ID). Between honest devices the copies differ only in `removed` and
    /// `removedBy`: removal wins, and the removals are the union of both, so each keeps naming its writer. Where a
    /// writer reused an ID with another anchor or text, the anchor is the greater of the two and the text keeps *both*
    /// texts, one per line, so whichever copy an honest device wrote is still there. Each part is a join in its own
    /// right (a maximum, an "or", set unions), so this is commutative, associative and idempotent.
    static func join(_ x: NoteLine, _ y: NoteLine) -> NoteLine {
        join([x, y])
    }

    /// The join of any number of copies of one line, in one pass: what folding `join(_:_:)` over them gives, in any
    /// order. The text is the one text if they all agree, otherwise every distinct line of any of them in byte order.
    static func join(_ copies: [NoteLine]) -> NoteLine {
        guard var line = copies.first else { preconditionFailure("joining no lines") }
        var isRemoved = false
        var differ = false
        var removals: Set<Revision> = []
        for copy in copies {
            line.after = later(line.after, copy.after)
            isRemoved = isRemoved || copy.removed || !copy.removedBy.isEmpty
            removals.formUnion(copy.removedBy)
            differ = differ || !copy.text.utf8.elementsEqual(line.text.utf8)
        }
        line.removed = isRemoved
        line.removedBy = removals.sorted()
        if isRemoved {
            line.text = ""
        } else if differ {
            var pieces: Set<[UInt8]> = []
            for copy in copies {
                for piece in copy.text.utf8.split(separator: lineBreak, omittingEmptySubsequences: false) {
                    pieces.insert(Array(piece))
                }
            }
            line.text = pieces.sorted { $0.lexicographicallyPrecedes($1) }
                .map { String(decoding: $0, as: UTF8.self) }.joined(separator: "\n")
        }
        return line
    }

    /// The line removed, by `revision` as well as whoever had removed it already; the removals in a fixed order.
    static func removed(_ line: NoteLine, by revision: Revision?) -> NoteLine {
        var line = line
        line.removed = true
        line.text = ""
        var removals = Set(line.removedBy)
        if let revision { removals.insert(revision) }
        line.removedBy = removals.sorted()
        return line
    }

    private static let lineBreak = UInt8(ascii: "\n")

    private static func later(_ x: NoteLine.ID?, _ y: NoteLine.ID?) -> NoteLine.ID? {
        guard let x else { return y }
        guard let y else { return x }
        return max(x, y)
    }

    /// Pairs of (old index, new index) of lines kept, in order: common prefix and suffix, then a longest common
    /// subsequence of the middle when it is small enough to compute, otherwise none (the middle is replaced — still
    /// correct, only coarser when merged).
    ///
    /// Lines are given as their UTF-8, so that a line respelt in another normalisation form counts as changed.
    static func commonLines(_ old: [[UInt8]], _ new: [[UInt8]]) -> [(Int, Int)] {
        var prefix = 0
        while prefix < old.count, prefix < new.count, old[prefix] == new[prefix] { prefix += 1 }
        var suffix = 0
        while suffix < old.count - prefix, suffix < new.count - prefix,
            old[old.count - 1 - suffix] == new[new.count - 1 - suffix]
        {
            suffix += 1
        }
        var pairs = (0..<prefix).map { ($0, $0) }
        let oldMiddle = Array(old[prefix..<(old.count - suffix)])
        let newMiddle = Array(new[prefix..<(new.count - suffix)])
        if !oldMiddle.isEmpty, !newMiddle.isEmpty, oldMiddle.count * newMiddle.count <= 4_000_000 {
            pairs += longestCommonSubsequence(oldMiddle, newMiddle).map { ($0.0 + prefix, $0.1 + prefix) }
        }
        pairs += (0..<suffix).map { (old.count - suffix + $0, new.count - suffix + $0) }
        return pairs
    }

    static func longestCommonSubsequence(_ a: [[UInt8]], _ b: [[UInt8]]) -> [(Int, Int)] {
        let width = b.count + 1
        var table = [Int32](repeating: 0, count: (a.count + 1) * width)
        for i in stride(from: a.count - 1, through: 0, by: -1) {
            for j in stride(from: b.count - 1, through: 0, by: -1) {
                table[i * width + j] =
                    a[i] == b[j]
                    ? table[(i + 1) * width + j + 1] + 1 : max(table[(i + 1) * width + j], table[i * width + j + 1])
            }
        }
        var pairs: [(Int, Int)] = []
        var i = 0
        var j = 0
        while i < a.count, j < b.count {
            if a[i] == b[j] {
                pairs.append((i, j))
                i += 1
                j += 1
            } else if table[(i + 1) * width + j] >= table[i * width + j + 1] {
                i += 1
            } else {
                j += 1
            }
        }
        return pairs
    }
}
