import Foundation
import WatchwordModel

/// How an imported item relates to one already in the vault.
public enum DuplicateKind: String, Hashable, Sendable {
    /// Same title, scopes, tags, notes and field values: importing it adds nothing.
    case identical
    /// The same account by the look of it: a scope and a login name in common, or, for items with no scope, the same
    /// title and login names. The fields may differ (a changed password, an added code).
    case sameAccount
}

public struct DuplicateMatch: Hashable, Sendable {
    public var importedID: UUID
    public var existingID: UUID
    public var kind: DuplicateKind

    public init(importedID: UUID, existingID: UUID, kind: DuplicateKind) {
        self.importedID = importedID
        self.existingID = existingID
        self.kind = kind
    }
}

/// What the person chose to do about a duplicate.
public enum DuplicateResolution: String, Hashable, Sendable, CaseIterable {
    /// Leave the existing item alone and do not import this one.
    case skip
    /// Import it as a separate item.
    case keepBoth
    /// Add what the imported item has and the existing one lacks to the existing item.
    case merge
}

/// Finds imported items that duplicate ones already in the vault (PRD F8.1–F8.3).
///
/// Detection only. Nothing here decides anything: `matches` reports, the UI offers skip, keep both or merge, and
/// `resolve` computes what the person's choice means. An import never drops or merges an item on its own.
public enum DuplicateDetector {
    /// The most existing items one imported item is compared with. An import file is hostile, and fifty thousand
    /// entries that each resemble every item in the vault must not become a quadratic amount of work or of results.
    public static let maximumMatchesPerItem = 16

    /// Every pairing of an imported item with an existing item it duplicates, in the order of `imported`. An
    /// imported item can match several existing items, up to `maximumMatchesPerItem`; `identical` matches are
    /// listed before `sameAccount` ones. Trashed existing items are not candidates. Linear in the two lists.
    public static func matches(imported: [Item], existing: [Item]) -> [DuplicateMatch] {
        var byKey: [String: [Int]] = [:]
        let candidates = existing.filter { !$0.isTrashed }
        for (index, item) in candidates.enumerated() {
            for key in accountKeys(of: item) {
                byKey[key, default: []].append(index)
            }
        }
        var contents: [Int: Content] = [:]
        var matches: [DuplicateMatch] = []
        for item in imported {
            let itemContent = content(of: item)
            var seen = Set<Int>()
            var found: [DuplicateMatch] = []
            search: for key in accountKeys(of: item).sorted() {
                for index in byKey[key] ?? [] where seen.insert(index).inserted {
                    guard found.count < maximumMatchesPerItem else { break search }
                    let other = candidates[index]
                    let otherContent = contents[index] ?? content(of: other)
                    contents[index] = otherContent
                    let kind: DuplicateKind = itemContent == otherContent ? .identical : .sameAccount
                    found.append(DuplicateMatch(importedID: item.id, existingID: other.id, kind: kind))
                }
            }
            matches += found.filter { $0.kind == .identical } + found.filter { $0.kind == .sameAccount }
        }
        return matches
    }

    /// What to save for one imported item under the person's `resolution`: nothing, the imported item as it is, or
    /// the existing item with the imported item's additions.
    public static func resolve(_ resolution: DuplicateResolution, imported: Item, existing: Item) -> Item? {
        switch resolution {
        case .skip: return nil
        case .keepBoth: return imported
        case .merge: return merged(imported, into: existing)
        }
    }

    /// `existing` plus whatever `imported` has that it lacks: scopes, tags, fields whose kind and value it does not
    /// already hold, and notes it does not already contain. Nothing of `existing` is removed or replaced, so a
    /// differing password arrives as a second password field for the person to choose between. The result keeps
    /// `existing`'s identity and goes through `VaultSession.save` like any edit.
    public static func merged(_ imported: Item, into existing: Item) -> Item {
        var result = existing
        for scope in imported.scopes where !result.scopes.contains(where: { $0.host == scope.host }) {
            result.scopes.append(scope)
        }
        for field in imported.fields
        where !result.fields.contains(where: { $0.kind == field.kind && $0.value == field.value }) {
            result.fields.append(field)
        }
        result.tags.formUnion(imported.tags)
        if !imported.notes.isEmpty, !result.notes.contains(imported.notes) {
            result.notes += (result.notes.isEmpty ? "" : "\n\n") + imported.notes
        }
        return result
    }

    /// The keys two items must share one of to be the same account: `host|login name` for every scope and login
    /// name, or `|title|login name` for an item with no scope. Compared without regard to case: a match here only
    /// puts a question to the person.
    private static func accountKeys(of item: Item) -> Set<String> {
        // The first few of each: an item from a file may carry a thousand, and their product is the work done.
        var names = Set(item.loginNames.prefix(4).map { $0.lowercased() })
        if names.isEmpty { names = [""] }
        var keys = Set<String>()
        if item.scopes.isEmpty {
            let title = item.title.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard !title.isEmpty else { return [] }
            for name in names {
                keys.insert("\u{0}\(title)\u{0}\(name)")
            }
        } else {
            for scope in item.scopes.prefix(8) {
                for name in names {
                    keys.insert("\(scope.host)\u{0}\(name)")
                }
            }
        }
        return keys
    }

    /// What an item says, without its identifiers, timestamps and sync metadata.
    private struct Content: Hashable {
        var title: String
        var scopes: Set<ServiceScope>
        var fields: [String]
        var tags: Set<String>
        var notes: String
    }

    private static func content(of item: Item) -> Content {
        Content(
            title: item.title, scopes: Set(item.scopes),
            fields: item.fields.map { "\($0.kind.rawValue)\u{0}\($0.label)\u{0}\($0.value)" }.sorted(),
            tags: item.tags, notes: item.notes)
    }
}
