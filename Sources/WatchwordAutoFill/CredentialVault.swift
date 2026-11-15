import Foundation
import WatchwordMatching
import WatchwordModel

/// Why the vault did not answer. The model turns `locked` into a state it reports and everything else into a refusal;
/// it never retries around either.
public enum CredentialVaultError: Error, Equatable, Sendable {
    /// No keys in memory. Also the answer when the vault locks while a request is in flight.
    case locked
    case noAccount
    case itemNotFound(UUID)
    /// The stored item is not at the version the caller read: someone else wrote in between.
    case versionConflict(UUID)
    /// A scope the scope policy refuses (PRD F11.2). The vault checks whatever the caller sends.
    case scopeRejected(ScopeValidationError)
    /// Anything else, described for a log. Not interpreted.
    case failed(String)
}

/// The vault as the AutoFill core sees it: read the unlocked items, write one back (docs/02-architecture.md §9.1).
///
/// This is the whole surface between `WatchwordAutoFill` and the vault, so that the request model can be tested with
/// `FakeCredentialVault` on any platform and holds no key, no store and no session of its own. `VaultSession` is the
/// production conformer. Every method throws `CredentialVaultError`, and `locked` whenever the vault is not
/// unlocked at the moment of the call.
public protocol CredentialVault: Sendable {
    /// Every readable item of every unlocked vault, the archived and the trashed included: the model filters, and
    /// needs archived items to rank against.
    func credentialItems() async throws -> [Item]

    /// The vault a new item is created in (the Personal vault).
    func defaultVaultID() async throws -> UUID

    /// Whether items stored here also reach the sync store, so a passkey created now is backed up (WebAuthn's BS
    /// flag, which must be true to the facts).
    func isBackedUp() async throws -> Bool

    /// Creates or replaces an item, as a compare-and-swap.
    ///
    /// With `replacingVersion == nil` the item must not exist yet. Otherwise the stored item's `version` must equal
    /// `replacingVersion`, or the call throws `versionConflict` and writes nothing. The vault owns `version`,
    /// `createdAt`, `modifiedAt`, `history`, the trash state and all sync metadata, whatever the caller put there,
    /// and it runs every scope through `ScopePolicy`. Returns the item as stored.
    @discardableResult
    func saveCredentialItem(_ item: Item, replacingVersion: UInt64?) async throws -> Item
}

/// The wall clock, for one-time codes and timestamps. Same shape as `WatchwordKit.WallClock`, which this module
/// cannot name; one clock type can conform to both.
public protocol AutoFillClock: Sendable {
    func now() async -> Date
}

public struct SystemAutoFillClock: AutoFillClock {
    public init() {}

    public func now() -> Date {
        Date()
    }
}

/// Marks a relying party's report leaves on a field (PRD F6.7). They live in `Field.meta`, inside the item's
/// ciphertext, and are all a report can ever write besides a passkey's user name: a remote party flags, it never
/// deletes.
extension Field {
    static let reportedUnusedKey = "autofill.reportedUnused"
    static let reportedUnknownKey = "autofill.reportedUnknown"
    static let lastReportKey = "autofill.lastReport"

    /// When the site said this password is no longer used to sign in (it has been replaced by a passkey, say).
    public var reportedUnusedAt: Date? {
        timestamp(Field.reportedUnusedKey)
    }

    /// When the relying party said it does not know this passkey. The passkey stays in the item and can still be
    /// chosen in the extension; it is no longer published for QuickType.
    public var reportedUnknownAt: Date? {
        timestamp(Field.reportedUnknownKey)
    }

    /// When a report last changed this field: the rate limit's memory.
    var lastReportAt: Date? {
        timestamp(Field.lastReportKey)
    }

    private func timestamp(_ key: String) -> Date? {
        guard let text = meta[key], let seconds = Int64(text), seconds >= 0 else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(seconds))
    }

    mutating func setTimestamp(_ date: Date?, for key: String) {
        guard let seconds = date?.timeIntervalSince1970, seconds.isFinite, seconds >= 0, seconds < 1e12 else {
            meta[key] = nil
            return
        }
        meta[key] = String(Int64(seconds.rounded(.down)))
    }

    /// Clears a report's flag by the person's own action (they chose to keep using the credential). Not rate
    /// limited: it is not a remote party's write.
    public mutating func clearReportFlags() {
        meta[Field.reportedUnusedKey] = nil
        meta[Field.reportedUnknownKey] = nil
    }
}
