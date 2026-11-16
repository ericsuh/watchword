import Foundation
import WatchwordStore

/// What a write requires of the row it replaces, checked against the row it read and committed conditionally on that
/// row (`StoreChange.expectations`), so the check and the write are one compare-and-swap.
enum WriteExpectation: Sendable, Hashable {
    /// No item under the ID yet.
    case absent
    /// The item exists at exactly this version.
    case version(UInt64)
    /// If the item exists, it is at this version: what `save` asks of a draft (Y29). A draft of an item that is no
    /// longer stored replaces nothing, and is saved as it always was.
    case versionIfPresent(UInt64)

    func check(_ row: StoredRecord?, id: UUID) throws {
        switch (self, row) {
        case (.absent, nil), (.versionIfPresent, nil): return
        case (.absent, .some): throw VaultError.versionConflict(id)
        case (.version, nil): throw VaultError.versionConflict(id)
        case (.version(let expected), .some(let row)), (.versionIfPresent(let expected), .some(let row)):
            guard row.version == expected else { throw VaultError.versionConflict(id) }
        }
    }
}
