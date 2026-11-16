import Foundation

/// Equality of everything an item holds is equality of its bytes (docs/10-sync-correctness.md §2, review finding
/// Y31).
///
/// Swift compares `String`s by Unicode canonical equivalence: "é" as one scalar (C3 A9 in UTF-8) equals "e" followed
/// by a combining accent (65 CC 81). For a password manager those are two values. A site hashes the bytes it is sent,
/// so the two spellings are two passwords; and a merge that takes them for one value keeps whichever a device already
/// held, so two devices can hold different bytes for good while every comparison reports them equal. So the types an
/// item is made of compare text byte for byte: a value respelt in another normalisation form is another value — an
/// edit to save and stamp, a conflict to keep and show, a history entry to record.
///
/// Only `==` is replaced. The synthesised `hash(into:)` stays correct, because values equal byte for byte are equal
/// as `String`s too and so hash alike. Every stored property must appear in its type's `==` below; the model's tests
/// count the properties so that one added later cannot be left out unnoticed.
///
/// A `Set<String>` or a dictionary keyed by `String` still cannot hold two spellings of one member. Comparing two of
/// them here compares the spelling each holds.
enum ExactText {
    static func equal(_ lhs: String, _ rhs: String) -> Bool {
        lhs.utf8.count == rhs.utf8.count && lhs.utf8.elementsEqual(rhs.utf8)
    }

    static func equal(_ lhs: Set<String>, _ rhs: Set<String>) -> Bool {
        guard lhs.count == rhs.count else { return false }
        // The members of a set differ pairwise, so matching each of `lhs` to its equivalent in `rhs` pairs them all.
        for member in lhs {
            guard let index = rhs.firstIndex(of: member), equal(rhs[index], member) else { return false }
        }
        return true
    }

    static func equal(_ lhs: [String: String], _ rhs: [String: String]) -> Bool {
        guard lhs.count == rhs.count else { return false }
        for (key, value) in lhs {
            guard let index = rhs.index(forKey: key), equal(rhs[index].key, key), equal(rhs[index].value, value)
            else { return false }
        }
        return true
    }
}

extension Field {
    public static func == (lhs: Field, rhs: Field) -> Bool {
        lhs.id == rhs.id && lhs.kind == rhs.kind && ExactText.equal(lhs.label, rhs.label)
            && ExactText.equal(lhs.value, rhs.value) && ExactText.equal(lhs.meta, rhs.meta)
    }
}

extension ServiceScope {
    public static func == (lhs: ServiceScope, rhs: ServiceScope) -> Bool {
        lhs.includeSubdomains == rhs.includeSubdomains && ExactText.equal(lhs.host, rhs.host)
            && ExactText.equal(lhs.excludedHosts, rhs.excludedHosts)
    }
}

extension NoteLine {
    public static func == (lhs: NoteLine, rhs: NoteLine) -> Bool {
        lhs.id == rhs.id && lhs.after == rhs.after && lhs.removed == rhs.removed && ExactText.equal(lhs.text, rhs.text)
    }
}

extension ItemGroupValue {
    public static func == (lhs: ItemGroupValue, rhs: ItemGroupValue) -> Bool {
        // Switched on one side so that a case added later does not compile until it is compared here.
        switch lhs {
        case .title(let title):
            if case .title(let other) = rhs { return ExactText.equal(title, other) }
        case .scopes(let scopes):
            if case .scopes(let other) = rhs { return scopes == other }
        case .tags(let tags):
            if case .tags(let other) = rhs { return ExactText.equal(tags, other) }
        case .archived(let archived):
            if case .archived(let other) = rhs { return archived == other }
        case .trashedAt(let date):
            if case .trashedAt(let other) = rhs { return date == other }
        case .keptAfterDeletion(let kept):
            if case .keptAfterDeletion(let other) = rhs { return kept == other }
        case .excludedFromSuggestions(let excluded):
            if case .excludedFromSuggestions(let other) = rhs { return excluded == other }
        case .fieldOrder(let ids):
            if case .fieldOrder(let other) = rhs { return ids == other }
        case .field(let field):
            if case .field(let other) = rhs { return field == other }
        }
        return false
    }
}

extension Item {
    public static func == (lhs: Item, rhs: Item) -> Bool {
        lhs.id == rhs.id && lhs.vaultID == rhs.vaultID && lhs.version == rhs.version
            && ExactText.equal(lhs.title, rhs.title) && ExactText.equal(lhs.notes, rhs.notes)
            && ExactText.equal(lhs.tags, rhs.tags) && lhs.scopes == rhs.scopes && lhs.fields == rhs.fields
            && lhs.createdAt == rhs.createdAt && lhs.modifiedAt == rhs.modifiedAt && lhs.archived == rhs.archived
            && lhs.trashedAt == rhs.trashedAt && lhs.keptAfterDeletion == rhs.keptAfterDeletion
            && lhs.excludedFromSuggestions == rhs.excludedFromSuggestions && lhs.clock == rhs.clock
            && lhs.fieldOrder == rhs.fieldOrder && lhs.revisions == rhs.revisions && lhs.discards == rhs.discards
            && lhs.history == rhs.history && lhs.conflicts == rhs.conflicts
            && lhs.retainedValues == rhs.retainedValues && lhs.noteLines == rhs.noteLines
    }
}
