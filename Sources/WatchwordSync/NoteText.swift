import Foundation
import WatchwordModel

/// Notes as a line-level sequence CRDT (an RGA over lines; PRD F7.6, docs/02-architecture.md §7.5).
///
/// Every line has a unique ID (the revision that inserted it and its index in that edit) and names the line it was
/// inserted after. Lines are never changed in place: an edit removes the old line and inserts the new text. Merging is
/// the union of lines (removal wins), and the document order is a function of that union alone — children of a line,
/// newest first, depth first — so devices that have seen the same edits show the same notes, and concurrent edits to
/// different lines all survive. Two devices that change the same line concurrently both keep their version, one after
/// the other; nothing either of them typed is lost.
public enum NoteText {
    /// The lines of `text`; empty notes have none.
    public static func lines(of text: String) -> [String] {
        text.isEmpty ? [] : text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    }

    /// The visible text of `lines`, in document order.
    public static func text(_ lines: [NoteLine]) -> String {
        ordered(lines).filter { !$0.removed }.map(\.text).joined(separator: "\n")
    }

    /// `text` written from scratch by `revision`.
    public static func initial(_ text: String, revision: Revision) -> [NoteLine] {
        edit([], to: text, revision: revision)
    }

    /// Document order: depth first from the start, each line's children newest first. Lines whose anchor is unknown
    /// or that sit in a cycle (only a hostile writer produces either) are not dropped: they follow, by ID.
    public static func ordered(_ lines: [NoteLine]) -> [NoteLine] {
        let byID = Dictionary(lines.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        var children: [NoteLine.ID?: [NoteLine]] = [:]
        for line in byID.values {
            let parent = line.after.flatMap { byID[$0] == nil ? nil : $0 }
            children[parent, default: []].append(line)
        }
        for key in children.keys { children[key]!.sort { $0.id > $1.id } }
        var result: [NoteLine] = []
        var visited: Set<NoteLine.ID> = []
        // Iterative, so a long chain of lines cannot exhaust the stack.
        var stack: [NoteLine] = (children[nil] ?? []).reversed()
        while let line = stack.popLast() {
            guard visited.insert(line.id).inserted else { continue }
            result.append(line)
            stack.append(contentsOf: (children[line.id] ?? []).reversed())
        }
        if result.count < byID.count {
            result += byID.values.filter { !visited.contains($0.id) }.sorted { $0.id < $1.id }
        }
        return result
    }

    /// The union of two versions' lines, in document order. A line removed in either is removed.
    public static func merge(_ a: [NoteLine], _ b: [NoteLine]) -> [NoteLine] {
        var byID: [NoteLine.ID: NoteLine] = [:]
        for line in a + b {
            guard var existing = byID[line.id] else {
                byID[line.id] = line.removed ? removed(line) : line
                continue
            }
            if existing.removed || line.removed {
                existing = removed(existing)
            } else if Array(existing.text.utf8).lexicographicallyPrecedes(Array(line.text.utf8)) {
                existing.text = line.text  // Only a writer reusing an ID gets here; any fixed choice converges.
            }
            byID[line.id] = existing
        }
        return ordered(Array(byID.values))
    }

    /// The lines after changing the visible text to `text`: unchanged lines keep their IDs, removed ones are marked,
    /// new ones are inserted by `revision` after the line that precedes them.
    public static func edit(_ lines: [NoteLine], to text: String, revision: Revision) -> [NoteLine] {
        let document = ordered(lines)
        let visible = document.filter { !$0.removed }
        let old = visible.map(\.text)
        let new = Self.lines(of: text)
        let matches = commonLines(old, new)

        var removedIDs: Set<NoteLine.ID> = []
        let matchedOld = Set(matches.map(\.0))
        for (index, line) in visible.enumerated() where !matchedOld.contains(index) {
            removedIDs.insert(line.id)
        }
        var oldForNew: [Int: Int] = [:]
        for (oldIndex, newIndex) in matches { oldForNew[newIndex] = oldIndex }

        var inserted: [NoteLine] = []
        var previous: NoteLine.ID?
        var nextIndex: UInt32 = 0
        for (newIndex, content) in new.enumerated() {
            if let oldIndex = oldForNew[newIndex] {
                previous = visible[oldIndex].id
            } else {
                let id = NoteLine.ID(revision: revision, index: nextIndex)
                nextIndex += 1
                inserted.append(NoteLine(id: id, after: previous, text: content))
                previous = id
            }
        }
        let kept = document.map { removedIDs.contains($0.id) ? removed($0) : $0 }
        return ordered(kept + inserted)
    }

    static func removed(_ line: NoteLine) -> NoteLine {
        var line = line
        line.removed = true
        line.text = ""
        return line
    }

    /// Pairs of (old index, new index) of lines kept, in order: common prefix and suffix, then a longest common
    /// subsequence of the middle when it is small enough to compute, otherwise none (the middle is replaced — still
    /// correct, only coarser when merged).
    static func commonLines(_ old: [String], _ new: [String]) -> [(Int, Int)] {
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

    static func longestCommonSubsequence(_ a: [String], _ b: [String]) -> [(Int, Int)] {
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
