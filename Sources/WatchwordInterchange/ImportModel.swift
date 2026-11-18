import Foundation
import WatchwordMatching
import WatchwordModel

/// The formats this module reads and writes (PRD F8.1–F8.4).
public enum InterchangeFormat: String, Hashable, Sendable, CaseIterable {
    /// 1Password 8 CSV: `Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes`.
    case onePassword8CSV
    /// 1Password 7 CSV, whose columns the person chose; recognised by `URL` without Apple's exact header.
    case onePassword7CSV
    /// Apple Passwords CSV: `Title,URL,Username,Password,Notes,OTPAuth`.
    case applePasswordsCSV
    /// 1Password Unencrypted Export: a ZIP archive whose `export.data` member is JSON.
    case onePUX
    /// FIDO Credential Exchange Format 1.0 JSON.
    case credentialExchange
    /// The encrypted Watchword archive (docs/02-architecture.md §14.1). Read and written by the session, which holds
    /// the keys; this module turns the items an archive held into drafts (`ArchivedItems`).
    case watchwordArchive
}

/// What an imported entry is, for the report's counts. Watchword items have no category of their own: the kind
/// records what the source called the entry and decides how its fields are mapped.
public enum ImportedKind: String, Hashable, Sendable, CaseIterable {
    case login
    case password
    case secureNote
    case apiCredential
    case bankAccount
    case membership
    case passkey
    case oneTimePassword
    /// Every other source category: imported as an item of custom fields.
    case other
}

/// What the source said about an entry's place in its vault.
public enum ImportedState: String, Hashable, Sendable {
    case active
    case archived
    /// In the source's trash. Skipped unless `ImportOptions.includesTrashed`; when included, the draft is not itself
    /// trashed, because only the vault may move an item to the trash (`VaultSession.trash`): the caller does that
    /// after saving.
    case trashed
}

/// Where in the file an entry came from, for messages a person can act on. Holds titles, which are private: a
/// report is as sensitive as the vault's metadata and is never logged.
public struct ImportEntryReference: Hashable, Sendable {
    /// The entry's position in the file, counting from one, over every entry seen (skipped ones included).
    public var index: Int
    /// The line a CSV record started on.
    public var line: Int?
    public var title: String
    /// The source's own identifier for the entry, when it has one.
    public var sourceID: String?
    /// The vault or account the source filed the entry under.
    public var container: String?

    public init(index: Int, line: Int? = nil, title: String = "", sourceID: String? = nil, container: String? = nil) {
        self.index = index
        self.line = line
        self.title = title
        self.sourceID = sourceID
        self.container = container
    }
}

/// Why a URL did not become a scope (PRD F11.2).
public enum ScopeRefusal: Error, Equatable, Sendable {
    /// Not unambiguously a web host: `HostNormalizer` refused it.
    case notAHost(HostNormalizationError)
    /// A host, but one a scope may not name: `ScopePolicy` refused it.
    case policy(ScopeValidationError)
}

/// Something about an imported entry the person should know. The entry was imported.
public enum ImportWarning: Equatable, Sendable {
    /// The URL was kept as a `url` field; AutoFill will not offer the item for it.
    case scopeRefused(url: String, reason: ScopeRefusal)
    /// The value was kept as a concealed custom field, not as a working one-time-password field.
    case unusableOneTimePassword(label: String, reason: OTPAuthError)
    /// The passkey could not be stored and was left out; `reason` names what was out of bounds.
    case passkeyRefused(reason: String)
    /// Part of a passkey that has no place in a Watchword passkey was left out (a second PRF secret, a credential
    /// blob, a large blob that would not decode).
    case passkeyDetailDropped(String)
    /// A credential type this importer has no mapping for; its text fields were kept as custom fields.
    case unsupportedCredentialType(String)
    /// A field type with no mapping, or a value that is not of its field's type. The value was kept as a field of
    /// text when it had text (a string, a number, a boolean), and dropped otherwise.
    case unsupportedFieldType(label: String, type: String)
    /// A file attachment, which this importer does not carry.
    case attachmentNotImported(name: String)
    /// A link to another item, which does not survive the move.
    case linkedItemNotImported(label: String)
    /// A state this importer does not know; the entry was imported as active.
    case unknownState(String)
    /// A timestamp outside any plausible range was ignored. For a date field, the number was kept as a text field.
    case implausibleDate(label: String)
    /// The entry, or the import as a whole, listed more URLs than an import considers as scopes
    /// (`InterchangeLimits.maximumURLsPerItem`, `maximumScopeDerivations`). `count` of them were kept as `url`
    /// fields; AutoFill will not offer the item for them.
    case urlsNotConsidered(count: Int)
    /// The entry was scoped to Android apps, which have no place in a Watchword item; `count` were left out.
    case androidAppsNotImported(count: Int)
    /// The entry carried no title; one was derived from its first URL or login name.
    case titleDerived
    /// The entry's URL named `wwwHost`, and `apex` was added as a further scope beside it, with the same subdomain
    /// setting, so the item is offered on both (`ImportOptions.matchApexOfWWWHosts`). A merge into an existing item
    /// adds it only if the person accepts that host, like any other (`MergeChoices`).
    case apexScopeAdded(wwwHost: String, apex: String)
    /// Values sync was keeping for the person to choose between (`Item.conflicts`, `Item.retainedValues`) were kept
    /// as `count` concealed fields labelled "(unresolved value)": an import starts the item afresh, with no sync
    /// history to hold them as alternatives.
    case unresolvedValuesKept(count: Int)
    /// `count` unresolved values that have no text form were left out: a passkey, or, from an encrypted Watchword
    /// archive (which keeps other titles, hosts and tags as fields), a flag such as the archived mark, which settles to
    /// the value shown.
    case unresolvedValuesOmitted(count: Int)
    /// The encrypted Watchword archive had the item in the trash because sync left it there, not because a person
    /// moved it (kept after a permanent deletion that had not seen it, trashed without seeing every edit, or over a
    /// concurrent restore: `Item.isTrashedByPerson` is false). It is imported as a live item, not skipped as the
    /// source's trash and not trashed again, where the 30-day purge would remove it as the person's (PRD F1.5, F7.7).
    case restoredFromSyncTrash
    /// `count` entries the AutoFill extension had recorded on the item's fields about a site's reports (when it last
    /// reported, what it flagged) were not restored from the archive: they describe the vault the archive came from,
    /// and are earned again as the item is used (review §Z, Z85).
    case autoFillStateNotRestored(count: Int)
    /// A date the file gave (created, modified, or when an earlier version was replaced) was later than this device's
    /// clock and was set to now: sync keeps an item's modification time from going backwards, so one date in the
    /// future would stick on every device (review §Z, Z85).
    case futureDateBounded
}

/// Why an entry was not imported.
public enum ImportSkipReason: Hashable, Sendable {
    /// The entry is larger than one item may be.
    case tooLarge(InterchangeLimits.Kind, limit: Int)
    /// An earlier entry in the same file has this identifier, which the format requires to be unique.
    case duplicateIdentifier(String)
    /// The entry was in the source's trash and `ImportOptions.includesTrashed` is off.
    case trashedAtSource
    /// Nothing in the entry could be imported: no title, no field, no note, no URL.
    case empty
    /// A CSV record with a different number of cells from the header.
    case columnCountMismatch(expected: Int, found: Int)
    /// The entry is not shaped like an entry of its format; `path` names the offending value.
    case malformed(path: String)
    /// Every credential in the entry was of a kind that could not be imported.
    case nothingImportable
}

public struct ImportWarningRecord: Equatable, Sendable {
    public var entry: ImportEntryReference
    public var warning: ImportWarning

    public init(entry: ImportEntryReference, warning: ImportWarning) {
        self.entry = entry
        self.warning = warning
    }
}

public struct ImportSkipRecord: Hashable, Sendable {
    public var entry: ImportEntryReference
    public var reason: ImportSkipReason

    public init(entry: ImportEntryReference, reason: ImportSkipReason) {
        self.entry = entry
        self.reason = reason
    }
}

/// What an import did, in full: nothing is dropped, changed or refused without a line here (PRD F8.1–F8.3).
public struct ImportReport: Equatable, Sendable {
    public var format: InterchangeFormat
    /// Entries imported, by what the source called them.
    public var countsByKind: [ImportedKind: Int]
    /// At most `maximumWarnings`; `omittedWarningCount` says how many more there were.
    public var warnings: [ImportWarningRecord]
    /// One record for every entry not imported: at most the item limit, since the file stops being read there.
    public var skipped: [ImportSkipRecord]
    /// Warnings beyond `maximumWarnings`, counted and not kept.
    public var omittedWarningCount: Int

    /// The most warnings a report lists. A hostile file can earn one with a few bytes (a URL of one character is
    /// refused as a scope), so an unbounded list would turn a 100 MB file into gigabytes of report (SEC7).
    public static let maximumWarnings = 10_000

    public init(
        format: InterchangeFormat, countsByKind: [ImportedKind: Int] = [:], warnings: [ImportWarningRecord] = [],
        skipped: [ImportSkipRecord] = [], omittedWarningCount: Int = 0
    ) {
        self.format = format
        self.countsByKind = countsByKind
        self.warnings = warnings
        self.skipped = skipped
        self.omittedWarningCount = omittedWarningCount
    }

    public var importedCount: Int { countsByKind.values.reduce(0, +) }
}

/// One imported entry: an item draft for the vault to save, and what the source said about it.
public struct ImportedEntry: Hashable, Sendable {
    /// A draft: a fresh `id` from the injected generator, the caller's `vaultID`, scopes that passed `ScopePolicy`.
    /// `createdAt`, `modifiedAt` and `history` carry the source's values where it had them, for an import path that
    /// keeps them; `VaultSession.save` replaces all three with its own. They are the file's word and nothing more:
    /// this module has no clock, so it bounds them to a plausible range only, and a path that keeps them must
    /// refuse any later than its own clock's now (sync keeps `modifiedAt` monotonic, so one date in the year 9000
    /// would stick).
    public var item: Item
    public var kind: ImportedKind
    public var state: ImportedState
    public var reference: ImportEntryReference

    public init(item: Item, kind: ImportedKind, state: ImportedState, reference: ImportEntryReference) {
        self.item = item
        self.kind = kind
        self.state = state
        self.reference = reference
    }
}

public struct ImportResult: Equatable, Sendable {
    public var entries: [ImportedEntry]
    public var report: ImportReport

    public init(entries: [ImportedEntry], report: ImportReport) {
        self.entries = entries
        self.report = report
    }

    /// The result with every date a draft keeps from the file (created, modified, each history entry's replacement
    /// time) no later than `now`, each entry that had one later reported once (`futureDateBounded`). The obligation
    /// `ImportedEntry` states for a path that keeps the file's dates; the session calls it with its clock's now
    /// before a preview is shown (review §Z, Z85). This module has no clock, so `now` is the caller's.
    public func boundingDates(notAfter now: Date) -> ImportResult {
        var bounded = self
        for index in bounded.entries.indices {
            var item = bounded.entries[index].item
            var changed = false
            func bound(_ date: inout Date) {
                if date > now {
                    date = now
                    changed = true
                }
            }
            bound(&item.createdAt)
            bound(&item.modifiedAt)
            for entry in item.history.indices { bound(&item.history[entry].replacedAt) }
            guard changed else { continue }
            if item.createdAt > item.modifiedAt { item.createdAt = item.modifiedAt }
            bounded.entries[index].item = item
            if bounded.report.warnings.count < ImportReport.maximumWarnings {
                bounded.report.warnings.append(
                    ImportWarningRecord(entry: bounded.entries[index].reference, warning: .futureDateBounded))
            } else {
                bounded.report.omittedWarningCount += 1
            }
        }
        return bounded
    }
}

/// The choices an import leaves to its caller. None of them can widen what a file is able to do.
public struct ImportOptions: Hashable, Sendable {
    /// Import entries from the source's trash, marked `ImportedState.trashed`. Off by default: they are skipped and
    /// listed.
    public var includesTrashed: Bool
    /// The tag given to entries the source marked as favourites, or `nil` to drop the mark.
    public var favoriteTag: String?
    /// Give an entry whose URL names `www.<apex>` a further scope for `<apex>`, with the same subdomain setting, beside
    /// the `www` one, which is kept (owner decision, 2026-11-16). On by default: a login saved on `www.example.com` is
    /// then offered on `example.com` too, as the person almost always means. The apex must pass `ScopePolicy` (never
    /// a public suffix: `www.co.uk` adds nothing), only one leading `www` label is removed
    /// (`ScopeDerivation.apexScope(beside:)`), and each addition is listed in the report (`apexScopeAdded`) so the
    /// preview can show it. Off, a scope matches exactly the host the source recorded and its subdomains.
    public var matchApexOfWWWHosts: Bool

    public init(includesTrashed: Bool = false, favoriteTag: String? = "Favorite", matchApexOfWWWHosts: Bool = true) {
        self.includesTrashed = includesTrashed
        self.favoriteTag = favoriteTag
        self.matchApexOfWWWHosts = matchApexOfWWWHosts
    }
}

/// Keys this module writes into `Field.meta`, so that what one format knew about a field survives to an export.
/// Hints only: an export validates them like any other input and works without them.
public enum InterchangeMeta {
    /// The title of the section the field sat in (1PUX), or of the custom-fields group (CXF).
    public static let section = "section"
    /// The source's own type name for the value (`concealed`, `monthYear`, `creditCardNumber`, …).
    public static let sourceType = "sourceType"
    /// The `sourceType` of a `url` field holding one of the entry's own website URLs as text: one that could not
    /// become a scope (PRD F11.2), or one that said more than the scope it became. An export writes it back where
    /// the format keeps an entry's URLs, unless it names a host the item is not scoped to (`ExportSupport.websites`).
    public static let websiteType = "website"
    /// The source's own identifier for the field (`accountNo`, `membership_no`, …).
    public static let sourceID = "sourceID"
    /// The category the source filed the entry under (1PUX's `categoryUuid`), on each of the entry's fields, for the
    /// categories with a shape of their own. An item has no category; an export prefers this to guessing one.
    public static let category = "category"
    /// The `sourceType` of a text field holding an entry's subtitle (CXF), where it said something the entry's
    /// title and fields did not.
    public static let subtitleType = "subtitle"

    /// Every key this module writes.
    static let all: Set<String> = [section, sourceType, sourceID, category]
}
