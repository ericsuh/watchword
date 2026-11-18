import Foundation
import WatchwordMatching
import WatchwordModel

/// One entry of an encrypted Watchword archive, as the session read it: an item it decrypted and decoded, or a
/// record that would not decode. The archive's cryptography is the session's (docs/02-architecture.md §14.1); this
/// module sees only what came out of it.
public struct ArchivedEntry: Sendable {
    public enum Content: Sendable {
        case item(Item)
        /// Authenticated but not an item this version can read; listed in the report, never dropped in silence.
        case unreadable
    }

    public var content: Content
    /// The name of the vault the item was archived from.
    public var container: String?

    public init(_ content: Content, container: String? = nil) {
        self.content = content
        self.container = container
    }
}

/// Turns the items of an encrypted Watchword archive into drafts for `vaultID`, through the same assembler as every
/// other format (PRD F8.4, F11.2).
///
/// An archive opened with the right passphrase and Secret Key was written by someone who held both, which is the
/// person, or someone the person was persuaded to take an archive and its Emergency Kit from. Its contents are
/// treated like any import file's (A7): fresh item and field IDs from the injected generator, the caller's vault,
/// every scope checked again (`ScopeDerivation.validated`) and kept only as narrow as it was, one-time passwords
/// through `OTPParameters`, passkeys through `PasskeyCredential`, the import's budgets and the stored-size bound,
/// and no sync metadata: what sync was holding for the person to choose between is kept as concealed fields and
/// reported. Unlike the other formats it keeps everything a Watchword item holds: every field's kind, label and
/// metadata, the whole history (each earlier version's fields), the creation and modification times, the archived
/// mark and the exclusion from suggestions.
public enum ArchivedItems {
    public static func importEntries(
        _ entries: [ArchivedEntry], into vaultID: UUID, limits: InterchangeLimits = .archive,
        options: ImportOptions = ImportOptions(), using generator: inout some RandomNumberGenerator
    ) throws -> ImportResult {
        var assembler = ImportAssembler(format: .watchwordArchive, vaultID: vaultID, limits: limits, options: options)
        for entry in entries {
            let index = try assembler.beginEntry()
            let reference = ImportEntryReference(index: index, container: entry.container)
            switch entry.content {
            case .unreadable:
                assembler.skip(reference, .malformed(path: "entry \(index)"))
            case .item(let item):
                try assembler.addArchived(item, reference: reference, using: &generator)
            }
        }
        return assembler.result
    }

    /// What a restore of an archive holding `items` would not bring back, worked out when the archive is made, so the
    /// person learns of it before relying on the file (review §Z, Z82). The same assembler and limits as the restore,
    /// with the trash included (whether to restore it is the person's choice then, not a loss). The drafts are thrown
    /// away; `generator` only fills their IDs.
    public static func restoreCheck(
        _ items: [Item], limits: InterchangeLimits = .archive, using generator: inout some RandomNumberGenerator
    ) -> ArchiveRestoreCheck {
        do {
            let result = try importEntries(
                items.map { ArchivedEntry(.item($0)) }, into: UUID(), limits: limits,
                options: ImportOptions(includesTrashed: true), using: &generator)
            let skipped = result.report.skipped.compactMap { record -> ArchiveRestoreCheck.Skipped? in
                guard let id = record.entry.sourceID.flatMap(UUID.init(uuidString:)) else { return nil }
                return ArchiveRestoreCheck.Skipped(itemID: id, reason: record.reason)
            }
            return ArchiveRestoreCheck(skipped: skipped, limitReached: nil)
        } catch InterchangeError.limitExceeded(let kind, _) {
            return ArchiveRestoreCheck(skipped: [], limitReached: kind)
        } catch {
            return ArchiveRestoreCheck(skipped: [], limitReached: nil, failed: true)
        }
    }
}

/// What restoring an archive would not bring back (`ArchivedItems.restoreCheck`). Empty when everything restores.
public struct ArchiveRestoreCheck: Hashable, Sendable {
    public struct Skipped: Hashable, Sendable {
        public var itemID: UUID
        public var reason: ImportSkipReason
    }

    /// Items a restore would leave out, each with why.
    public var skipped: [Skipped]
    /// A budget that would fail the whole restore, if one would.
    public var limitReached: InterchangeLimits.Kind?
    /// The check itself failed for another reason: whether the archive restores is unknown.
    public var failed: Bool

    public init(skipped: [Skipped] = [], limitReached: InterchangeLimits.Kind? = nil, failed: Bool = false) {
        self.skipped = skipped
        self.limitReached = limitReached
        self.failed = failed
    }

    /// Everything in the archive would come back.
    public var restoresEverything: Bool { skipped.isEmpty && limitReached == nil && !failed }
}

extension ImportAssembler {
    /// A timestamp from an archive, if it is one a person could mean.
    static func plausible(_ date: Date) -> Date? {
        let seconds = date.timeIntervalSince1970
        guard seconds.isFinite, seconds >= 0, seconds <= Double(latestPlausibleTimestamp) else { return nil }
        return date
    }

    /// The prefix of the `Field.meta` keys the AutoFill extension writes (`autofill.lastReport` and the rest).
    static let autoFillMetaPrefix = "autofill."

    /// A field's metadata as an archive restores it: everything but the AutoFill extension's state (Z85).
    static func restoredMeta(_ meta: [String: String], dropped: inout Int) -> [String: String] {
        guard meta.keys.contains(where: { $0.hasPrefix(autoFillMetaPrefix) }) else { return meta }
        var kept = meta
        for key in meta.keys where key.hasPrefix(autoFillMetaPrefix) {
            kept[key] = nil
            dropped += 1
        }
        return kept
    }

    /// The archive's counterpart of `add`: the same rules, applied to an item rather than to a format's record.
    mutating func addArchived(
        _ archived: Item, reference: ImportEntryReference, using generator: inout some RandomNumberGenerator
    ) throws {
        var reference = reference
        reference.title = archived.title.utf8.count <= limits.maximumFieldBytes ? archived.title : ""
        let identifier = archived.id.uuidString
        reference.sourceID = identifier
        guard seenIdentifiers.insert(identifier).inserted else {
            skip(reference, .duplicateIdentifier(identifier))
            return
        }
        // Only the person's own trash is trash here. Sync also leaves items in the trash that nobody chose to discard
        // (kept after a deletion that had not seen them, trashed without seeing every edit, or over a concurrent
        // restore); restored as trash, the 30-day purge would remove them as the person's (PRD F1.5, F7.7), and
        // skipped, the report would call them the person's. They come back live, and the report says why.
        let trashedBySync = archived.isTrashed && !archived.isTrashedByPerson
        let state: ImportedState =
            archived.isTrashedByPerson ? .trashed : archived.archived ? .archived : .active
        if state == .trashed, !options.includesTrashed {
            skip(reference, .trashedAtSource)
            return
        }
        let unresolved = ImportAssembler.unresolvedAlternatives(of: archived)
        let exclusions = archived.scopes.reduce(0) { $0 + $1.excludedHosts.count }
        let parts =
            archived.fields.count + archived.scopes.count + exclusions + archived.tags.count
            + unresolved.fields.count
        guard parts <= limits.maximumFieldsPerItem else {
            skip(reference, .tooLarge(.fieldsPerItem, limit: limits.maximumFieldsPerItem))
            return
        }
        let historyFields = archived.history.reduce(0) { $0 + $1.fields.count }
        // Before any field is built, as in `add`: what this entry adds against what the whole import may hold.
        let kept = parts + historyFields
        guard kept <= limits.maximumTotalFields - totalFields else { throw limits.exceeded(.totalFields) }

        var warnings: [ImportWarning] = trashedBySync ? [.restoredFromSyncTrash] : []
        var scopes: [ServiceScope] = []
        var fields: [Field] = []
        var hosts = Set<String>()
        var considered = 0
        var unconsidered = 0
        for scope in archived.scopes {
            guard considered < limits.maximumURLsPerItem, scopeDerivations < limits.maximumScopeDerivations else {
                fields.append(website(scope.host, using: &generator))
                unconsidered += 1
                continue
            }
            considered += 1
            scopeDerivations += 1
            switch ScopeDerivation.validated(scope) {
            case .success(let checked):
                if hosts.insert(checked.host).inserted { scopes.append(checked) }
            case .failure(let reason):
                fields.append(website(scope.host, using: &generator))
                warnings.append(.scopeRefused(url: scope.host, reason: reason))
            }
        }
        if unconsidered > 0 { warnings.append(.urlsNotConsidered(count: unconsidered)) }

        // Field IDs are the file's: drawn afresh, the same old ID mapping to the same new one across the history, so
        // an earlier version's field is still recognisably the same field. A repeated ID among the current fields
        // gets one of its own.
        var renamed: [UUID: UUID] = [:]
        // Keys the AutoFill extension keeps about a relying party's reports (rate limits, flags) are this vault's
        // state, not the item's: a person cannot type them, and a far-future `autofill.lastReport` from a crafted
        // archive would silence that field's reports for good (Z85). They are not restored.
        var deviceState = 0
        for field in archived.fields {
            let id = RandomUUID.make(using: &generator)
            if renamed[field.id] == nil { renamed[field.id] = id }
            switch field.kind {
            case .totp:
                do {
                    let uri = try ImportAssembler.canonicalOneTimePasswordURI(field.value)
                    fields.append(
                        Field(
                            id: id, kind: .totp, label: field.label, value: uri,
                            meta: Self.restoredMeta(field.meta, dropped: &deviceState)))
                } catch {
                    let reason = (error as? OTPAuthError) ?? .notAnOTPAuthURI
                    var meta = Self.restoredMeta(field.meta, dropped: &deviceState)
                    meta[InterchangeMeta.sourceType] = "totp"
                    let label = field.label.isEmpty ? "One-time password" : field.label
                    fields.append(Field(id: id, kind: .custom, label: label, value: field.value, meta: meta))
                    warnings.append(.unusableOneTimePassword(label: field.label, reason: reason))
                }
            case .passkey:
                if let credential = try? field.passkeyCredential(),
                    let checked = try? Field.passkey(credential, id: id, label: field.label)
                {
                    fields.append(checked)
                } else {
                    warnings.append(.passkeyRefused(reason: "encoding"))
                }
            default:
                fields.append(
                    Field(
                        id: id, kind: field.kind, label: field.label, value: field.value,
                        meta: Self.restoredMeta(field.meta, dropped: &deviceState)))
            }
        }
        for value in unresolved.fields {
            fields.append(
                Field(id: RandomUUID.make(using: &generator), kind: value.kind, label: value.label, value: value.value))
        }
        if !unresolved.fields.isEmpty { warnings.append(.unresolvedValuesKept(count: unresolved.fields.count)) }
        if unresolved.omitted > 0 { warnings.append(.unresolvedValuesOmitted(count: unresolved.omitted)) }

        var implausible = false
        var history: [ItemHistoryEntry] = []
        for entry in archived.history {
            var entryFields: [Field] = []
            for field in entry.fields {
                let id = renamed[field.id] ?? RandomUUID.make(using: &generator)
                renamed[field.id] = id
                entryFields.append(
                    Field(
                        id: id, kind: field.kind, label: field.label, value: field.value,
                        meta: Self.restoredMeta(field.meta, dropped: &deviceState)))
            }
            let replacedAt = ImportAssembler.plausible(entry.replacedAt)
            if replacedAt == nil { implausible = true }
            history.append(
                ItemHistoryEntry(
                    replacedAt: replacedAt ?? Date(timeIntervalSince1970: 0), version: entry.version,
                    fields: entryFields))
        }

        if deviceState > 0 { warnings.append(.autoFillStateNotRestored(count: deviceState)) }
        let tags = Set(archived.tags.map { UTF8Text.trimmed($0) }.filter { !$0.isEmpty })
        var title = UTF8Text.trimmed(archived.title)
        guard !(title.isEmpty && fields.isEmpty && scopes.isEmpty && archived.notes.isEmpty) else {
            skip(reference, .empty)
            return
        }
        if title.isEmpty {
            title = scopes.first?.host ?? fields.first { $0.kind == .username || $0.kind == .email }?.value ?? ""
            if !title.isEmpty { warnings.append(.titleDerived) }
        }
        reference.title = title

        let created = ImportAssembler.plausible(archived.createdAt)
        let modified = ImportAssembler.plausible(archived.modifiedAt)
        if created == nil || modified == nil { implausible = true }
        if implausible { warnings.append(.implausibleDate(label: "")) }
        let createdAt = created ?? modified ?? Date(timeIntervalSince1970: 0)
        // A clean item: no version, no trash, and none of the archive's sync metadata (the vault stamps its own).
        let item = Item(
            id: RandomUUID.make(using: &generator), vaultID: vaultID, title: title, scopes: scopes, fields: fields,
            tags: tags, notes: archived.notes, createdAt: createdAt, modifiedAt: modified ?? createdAt,
            archived: archived.archived, history: history, excludedFromSuggestions: archived.excludedFromSuggestions)
        guard try countStored(item) else {
            skip(reference, .tooLarge(.storedItemBytes, limit: limits.maximumStoredItemBytes))
            return
        }
        totalFields += kept
        let kind = ImportAssembler.archivedKind(of: item)
        entries.append(ImportedEntry(item: item, kind: kind, state: state, reference: reference))
        report.countsByKind[kind, default: 0] += 1
        for warning in warnings {
            guard report.warnings.count < ImportReport.maximumWarnings else {
                report.omittedWarningCount += 1
                continue
            }
            report.warnings.append(ImportWarningRecord(entry: reference, warning: warning))
        }
    }

    /// What sync was holding beside the values `item` shows, as fields the person can see and choose from: a field's
    /// other text (`ExportSupport.unresolvedValues`), another title, the hosts of another set of scopes, and other
    /// tags. A restore starts the item afresh, with no sync metadata to hold them as alternatives, and the archive is
    /// the backup whose purpose is to keep everything (PRD F7.7). A host becomes a `url` field with no
    /// `InterchangeMeta.websiteType`, so it is text the person reads and never a scope or an exported website: an
    /// alternative widens nothing. Only flags (the archived mark, the trash, the exclusion from suggestions, the field
    /// order) and passkeys are left out, counted in `omitted`: a flag settles to the value shown and the person can
    /// set it again, and a passkey has no text form.
    static func unresolvedAlternatives(of item: Item) -> (
        fields: [(kind: FieldKind, label: String, value: String)], omitted: Int
    ) {
        let text = ExportSupport.unresolvedValues(of: item)
        var fields = text.fields.map { (kind: FieldKind.custom, label: $0.label, value: $0.value) }
        // `ExportSupport` counts every kept value that is not a field's text as omitted; those kept here are taken
        // back out of that count.
        var omitted = text.omitted
        var listed = Set<[UInt8]>()
        func add(_ kind: FieldKind, _ label: String, _ value: String) {
            guard listed.insert(Array(label.utf8) + [0] + Array(value.utf8)).inserted else { return }
            fields.append((kind, label, value))
        }
        let shownHosts = Set(item.scopes.map(\.host))
        let conflicting = item.conflicts.keys.sorted().flatMap { item.conflicts[$0] ?? [] }
        for kept in conflicting + item.retainedValues {
            switch kept.value {
            case .title(let title):
                omitted -= 1
                let title = UTF8Text.trimmed(title)
                if !title.isEmpty, title != UTF8Text.trimmed(item.title) {
                    add(.custom, "Title (unresolved value)", title)
                }
            case .scopes(let scopes):
                omitted -= 1
                for host in scopes.map(\.host) where !host.isEmpty && !shownHosts.contains(host) {
                    add(.url, "Website (unresolved value)", host)
                }
            case .tags(let tags):
                omitted -= 1
                let other = tags.map { UTF8Text.trimmed($0) }.filter { !$0.isEmpty && !item.tags.contains($0) }
                if !other.isEmpty {
                    add(.custom, "Tags (unresolved value)", Set(other).sorted().joined(separator: ", "))
                }
            default:
                continue
            }
        }
        return (fields, omitted)
    }

    /// A refused or unconsidered scope, kept as the website it named. No scope comes from it.
    private func website(_ host: String, using generator: inout some RandomNumberGenerator) -> Field {
        Field(
            id: RandomUUID.make(using: &generator), kind: .url, label: "Website", value: host,
            meta: [InterchangeMeta.sourceType: InterchangeMeta.websiteType])
    }

    /// What an archived item is, for the report's counts: Watchword items have no category, so it is read off them.
    static func archivedKind(of item: Item) -> ImportedKind {
        let kinds = Set(item.fields.map(\.kind))
        if kinds.contains(.password) || kinds.contains(.username) || kinds.contains(.email) || !item.scopes.isEmpty {
            return .login
        }
        if kinds.contains(.passkey) { return .passkey }
        if kinds.contains(.totp) { return .oneTimePassword }
        if kinds.contains(.apiKey) { return .apiCredential }
        if item.fields.isEmpty, !item.notes.isEmpty { return .secureNote }
        return .other
    }
}
