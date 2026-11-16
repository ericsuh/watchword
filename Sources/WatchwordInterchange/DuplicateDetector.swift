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
    /// Hosts the imported item is scoped to and the existing item is not, in the imported item's order. A merge adds
    /// none of them unless the person accepts it by name (`MergeChoices.hosts`): each is one more site on which
    /// AutoFill would offer the existing item's secrets, and the import file chose it (PRD SEC6, F11.2). Show them.
    public var newHosts: [String]
    /// Whether the imported item holds a user name, email address, password, one-time password or passkey the
    /// existing item lacks. A merge adds none of those either without the person's choice (`MergeChoices.fieldIDs`).
    public var hasNewSignInFields: Bool

    public init(
        importedID: UUID, existingID: UUID, kind: DuplicateKind, newHosts: [String] = [],
        hasNewSignInFields: Bool = false
    ) {
        self.importedID = importedID
        self.existingID = existingID
        self.kind = kind
        self.newHosts = newHosts
        self.hasNewSignInFields = hasNewSignInFields
    }
}

/// What the person chose to do about a duplicate.
public enum DuplicateResolution: String, Hashable, Sendable, CaseIterable {
    /// Leave the existing item alone and do not import this one.
    case skip
    /// Import it as a separate item.
    case keepBoth
    /// Add what the imported item has and the existing one lacks to the existing item, except what would change
    /// where or with what the existing item signs in: that needs `MergeChoices`.
    case merge
}

/// What an imported item has that an existing one lacks: what a merge would add, for the person to see first.
public struct MergeAdditions: Hashable, Sendable {
    /// Scopes for hosts the existing item is not scoped to. **Never added by default**: with one of these the
    /// existing item's password is offered on a host the import file named.
    public var scopes: [ServiceScope]
    /// User names, email addresses, passwords, one-time passwords and passkeys the existing item does not hold.
    /// Never added by default: they are what AutoFill offers, and a file must not choose that for an existing item.
    public var signInFields: [Field]
    /// Every other field the existing item does not hold. Added by a merge.
    public var otherFields: [Field]
    /// Added by a merge.
    public var tags: Set<String>
    /// The imported notes, where the existing notes do not already hold every line of them. Appended by a merge.
    public var notes: String

    /// Whether a merge leaves something out unless the person chooses it.
    public var needsChoice: Bool { !scopes.isEmpty || !signInFields.isEmpty }
    public var isEmpty: Bool {
        scopes.isEmpty && signInFields.isEmpty && otherFields.isEmpty && tags.isEmpty && notes.isEmpty
    }
}

/// The additions a person accepted one by one. Empty by default, and there is no "all": a choice names its host.
public struct MergeChoices: Hashable, Sendable {
    /// Hosts from `MergeAdditions.scopes` to add to the existing item's scopes.
    public var hosts: Set<String>
    /// Fields from `MergeAdditions.signInFields` to add to the existing item.
    public var fieldIDs: Set<UUID>

    public init(hosts: Set<String> = [], fieldIDs: Set<UUID> = []) {
        self.hosts = hosts
        self.fieldIDs = fieldIDs
    }

    public static let none = MergeChoices()
}

/// Finds imported items that duplicate ones already in the vault (PRD F8.1–F8.3).
///
/// Detection only. Nothing here decides anything: `matches` reports, the UI offers skip, keep both or merge, and
/// `resolve` computes what the person's choice means. An import never drops or merges an item on its own.
///
/// A match is made on one shared host and login name, and the file controls everything else about the imported
/// item, so "merge" is where a hostile file (adversary A7) would reach an existing secret. The rule that stops it: a
/// merge never changes where the existing item is offered or what it signs in with. New scopes and new sign-in
/// fields are reported (`DuplicateMatch.newHosts`, `additions`) and added only when the person accepts each one.
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
        var held: [Int: Holdings] = [:]
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
                    let holdings = held[index] ?? Holdings(other)
                    held[index] = holdings
                    var newHosts: [String] = []
                    var listed = Set<String>()
                    for scope in item.scopes where !holdings.hosts.contains(scope.host) {
                        if listed.insert(scope.host).inserted { newHosts.append(scope.host) }
                    }
                    let newSignIn = item.fields.contains { isSignInKind($0.kind) && !holdings.holds($0) }
                    found.append(
                        DuplicateMatch(
                            importedID: item.id, existingID: other.id, kind: kind, newHosts: newHosts,
                            hasNewSignInFields: newSignIn))
                }
            }
            matches += found.filter { $0.kind == .identical } + found.filter { $0.kind == .sameAccount }
        }
        return matches
    }

    /// What to save for one imported item under the person's `resolution`: nothing, the imported item as it is, or
    /// the existing item with the imported item's additions. `choices` matters to a merge only.
    public static func resolve(
        _ resolution: DuplicateResolution, imported: Item, existing: Item, accepting choices: MergeChoices = .none
    ) -> Item? {
        switch resolution {
        case .skip: return nil
        case .keepBoth: return imported
        case .merge: return merged(imported, into: existing, accepting: choices)
        }
    }

    /// The kinds AutoFill offers: adding one to an item changes what the item signs in with.
    static func isSignInKind(_ kind: FieldKind) -> Bool {
        switch kind {
        case .username, .email, .password, .totp, .passkey: return true
        default: return false
        }
    }

    /// What `imported` has that `existing` lacks. Linear in the two items.
    public static func additions(of imported: Item, to existing: Item) -> MergeAdditions {
        var holdings = Holdings(existing)
        var additions = MergeAdditions(scopes: [], signInFields: [], otherFields: [], tags: [], notes: "")
        for scope in imported.scopes where holdings.hosts.insert(scope.host).inserted {
            additions.scopes.append(scope)
        }
        for field in imported.fields where holdings.insert(field) {
            if isSignInKind(field.kind) {
                additions.signInFields.append(field)
            } else {
                additions.otherFields.append(field)
            }
        }
        additions.tags = imported.tags.subtracting(existing.tags)
        if !imported.notes.isEmpty, !holdsEveryLine(of: imported.notes, in: existing.notes) {
            additions.notes = imported.notes
        }
        return additions
    }

    /// `existing` plus what `imported` has that it lacks: tags, notes whose lines it does not already hold, and
    /// fields whose kind and value it does not already hold, other than sign-in fields. Nothing of `existing` is
    /// removed or replaced.
    ///
    /// **Its scopes are never widened and its sign-in fields never added to, except by `choices`**: the hosts and
    /// fields the person accepted one by one from `additions(of:to:)`. Without them, AutoFill offers the result
    /// exactly where, and with exactly what, it offered `existing` (PRD SEC6, F11.2). The result keeps `existing`'s
    /// identity and goes through `VaultSession.save` like any edit, which checks every scope against the policy.
    public static func merged(_ imported: Item, into existing: Item, accepting choices: MergeChoices = .none) -> Item {
        let additions = additions(of: imported, to: existing)
        var result = existing
        result.scopes += additions.scopes.filter { choices.hosts.contains($0.host) }
        result.fields += additions.signInFields.filter { choices.fieldIDs.contains($0.id) }
        result.fields += additions.otherFields
        result.tags.formUnion(additions.tags)
        if !additions.notes.isEmpty {
            result.notes += (result.notes.isEmpty ? "" : "\n\n") + additions.notes
        }
        return result
    }

    /// Whether every line of `notes` is a line of `existing`, compared on bytes. One pass over each text and a set
    /// of lines: a string search here is quadratic on Linux, and both texts may be as long as a field can be.
    static func holdsEveryLine(of notes: String, in existing: String) -> Bool {
        func lines(_ text: String) -> [ArraySlice<UInt8>] {
            Array(text.utf8).split(separator: 0x0A, omittingEmptySubsequences: true).map { line in
                line.last == 0x0D ? line.dropLast() : line
            }
        }
        let held = Set(lines(existing))
        return lines(notes).allSatisfy { $0.isEmpty || held.contains($0) }
    }

    /// The hosts and field values an item holds, for set lookups.
    private struct Holdings {
        var hosts: Set<String>
        private var fields: Set<FieldKey>

        /// A value is its bytes: two passwords that are equal as strings and differ in normalisation are two
        /// passwords.
        private struct FieldKey: Hashable {
            var kind: FieldKind
            var value: [UInt8]

            init(_ field: Field) {
                kind = field.kind
                value = Array(field.value.utf8)
            }
        }

        init(_ item: Item) {
            hosts = Set(item.scopes.map(\.host))
            fields = Set(item.fields.map(FieldKey.init))
        }

        func holds(_ field: Field) -> Bool {
            fields.contains(FieldKey(field))
        }

        /// Records `field`; false if a field of its kind and value was already held.
        mutating func insert(_ field: Field) -> Bool {
            fields.insert(FieldKey(field)).inserted
        }
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
            let title = UTF8Text.trimmed(item.title).lowercased()
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
        var fields: [[UInt8]]
        var tags: Set<String>
        var notes: String
    }

    private static func content(of item: Item) -> Content {
        Content(
            title: item.title, scopes: Set(item.scopes),
            fields: item.fields.map { Array("\($0.kind.rawValue)\u{0}\($0.label)\u{0}\($0.value)".utf8) }
                .sorted { $0.lexicographicallyPrecedes($1) },
            tags: item.tags, notes: item.notes)
    }
}
