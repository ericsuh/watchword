import Foundation
import WatchwordMatching
import WatchwordModel

/// Turns a URL from an import file into a scope, or says why not (PRD F11.2, SEC8).
///
/// The one route by which an imported URL can come to govern AutoFill: `HostNormalizer` first, so anything that is
/// not unambiguously a web host is refused, then `ScopePolicy`, so a host that spans unrelated owners (`com`,
/// `co.uk`, `github.io`) is refused. Nothing is repaired on the way: a refused URL stays a URL field.
public enum ScopeDerivation {
    public static func scope(forURL text: String, stripsLeadingWWW: Bool = false) -> Result<ServiceScope, ScopeRefusal>
    {
        // A scheme makes it a URL; anything else must be a bare host, and a path or port then refuses it.
        let kind: ServiceIdentifierKind = text.contains("://") ? .url : .domain
        let host: NormalizedHost
        do {
            host = try HostNormalizer.normalize(ServiceIdentifier(text, kind: kind))
        } catch let error as HostNormalizationError {
            return .failure(.notAHost(error))
        } catch {
            return .failure(.notAHost(.invalidHost(text)))
        }
        // Stricter than the policy on purpose: letters, digits, hyphens, underscores and dots only (non-ASCII
        // letters are an internationalised name). `*.example.com` is a host to the matcher, not a pattern, and a
        // file must not be able to plant a scope that reads as a wildcard.
        let isPlainName = host.value.unicodeScalars.allSatisfy { scalar in
            !scalar.isASCII || scalar.properties.isAlphabetic || scalar.properties.numericType != nil
                || scalar == "-" || scalar == "_" || scalar == "."
        }
        guard isPlainName else { return .failure(.notAHost(.invalidHost(host.value))) }
        var candidates = [host.value]
        if stripsLeadingWWW, host.value.hasPrefix("www.") {
            candidates.insert(String(host.value.dropFirst(4)), at: 0)
        }
        var refusal = ScopeValidationError.empty
        for candidate in candidates {
            // A dotted-decimal address has no subdomains to include.
            let isAddress = candidate.allSatisfy { $0.isASCII && ($0.isNumber || $0 == ".") }
            let scope = ServiceScope(host: candidate, includeSubdomains: !isAddress)
            do {
                try ScopePolicy.validate(scope)
                return .success(scope)
            } catch let error as ScopeValidationError {
                refusal = error
            } catch {
                refusal = .notAHostname(candidate)
            }
        }
        return .failure(.policy(refusal))
    }
}

/// A value as a format's parser read it, before the vault's rules are applied.
struct SourceField {
    enum Kind {
        /// Stored as it is.
        case plain(FieldKind)
        /// An `otpauth://` URI or a bare Base32 secret, to be validated through `OTPParameters`.
        case oneTimePassword
        /// A one-time-password value the parser already knows is unusable.
        case unusableOneTimePassword(OTPAuthError)
        case passkey(PasskeyCredential)
    }

    var kind: Kind
    var label: String
    var value: String
    var meta: [String: String] = [:]
}

struct SourcePassword {
    var value: String
    var replacedAt: Date?
}

/// An entry as a format's parser read it. Everything in it is still hostile.
struct SourceRecord {
    var reference: ImportEntryReference
    var kind: ImportedKind
    var title: String
    var urls: [String] = []
    var fields: [SourceField] = []
    var tags: [String] = []
    var notes: String = ""
    var state: ImportedState = .active
    var favorite = false
    var createdAt: Date?
    var modifiedAt: Date?
    var pastPasswords: [SourcePassword] = []
    var warnings: [ImportWarning] = []
    /// Set when the source had something for this entry and none of it could be mapped.
    var hadUnimportableContent = false
}

/// The one place import entries become item drafts (PRD F8.1–F8.3, F11.2): every format's parser hands its
/// `SourceRecord`s here, so the size caps, the scope policy and the one-time-password validation cannot be skipped
/// by a format that forgot them.
struct ImportAssembler {
    /// Seconds since 1970 for 9999-12-31T23:59:59Z: beyond it a timestamp is noise.
    static let latestPlausibleTimestamp: Int64 = 253_402_300_799

    let vaultID: UUID
    let limits: InterchangeLimits
    let options: ImportOptions
    private(set) var entries: [ImportedEntry] = []
    private(set) var report: ImportReport
    private var seenIdentifiers = Set<String>()
    /// Every entry and container visited, imported or not: the bound on the work one file can ask for.
    private var visited = 0
    private(set) var entryIndex = 0

    init(format: InterchangeFormat, vaultID: UUID, limits: InterchangeLimits, options: ImportOptions) {
        self.vaultID = vaultID
        self.limits = limits
        self.options = options
        self.report = ImportReport(format: format)
    }

    var result: ImportResult { ImportResult(entries: entries, report: report) }

    /// Counts one more array element against the item limit, before anything is done with it.
    mutating func visit() throws {
        visited += 1
        guard visited <= limits.maximumItems else { throw limits.exceeded(.items) }
    }

    /// Counts an entry and returns its position in the file.
    mutating func beginEntry() throws -> Int {
        try visit()
        entryIndex += 1
        return entryIndex
    }

    mutating func skip(_ reference: ImportEntryReference, _ reason: ImportSkipReason) {
        report.skipped.append(ImportSkipRecord(entry: reference, reason: reason))
    }

    /// A position in the results, so that a container's name can be applied once it is known.
    struct Mark {
        var entries: Int
        var warnings: Int
        var skipped: Int
    }

    var mark: Mark { Mark(entries: entries.count, warnings: report.warnings.count, skipped: report.skipped.count) }

    /// Records `container` on everything added since `mark`. A JSON object's members come in any order, so a
    /// vault's name may be read after its items.
    mutating func setContainer(_ container: String, since mark: Mark) {
        for index in mark.entries..<entries.count {
            entries[index].reference.container = container
        }
        for index in mark.warnings..<report.warnings.count {
            report.warnings[index].entry.container = container
        }
        for index in mark.skipped..<report.skipped.count {
            report.skipped[index].entry.container = container
        }
    }

    /// Adds tags to the entries added since `mark`, by the source's identifier for each. Like a container's name,
    /// a collection may be read after the items it lists. A tag larger than a field may be is left off.
    mutating func addTags(_ tags: [String: [String]], since mark: Mark) {
        guard !tags.isEmpty else { return }
        for index in mark.entries..<entries.count {
            guard let identifier = entries[index].reference.sourceID, let names = tags[identifier] else { continue }
            for name in names where name.utf8.count <= limits.maximumFieldBytes {
                let trimmed = UTF8Text.trimmed(name)
                if !trimmed.isEmpty { entries[index].item.tags.insert(trimmed) }
            }
        }
    }

    /// A timestamp from a file, if it is one a person could mean.
    static func date(seconds: Int64?) -> Date? {
        guard let seconds, (0...latestPlausibleTimestamp).contains(seconds) else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(seconds))
    }

    /// Applies the vault's rules to `record` and adds the resulting draft, or records why it was skipped.
    mutating func add(_ record: SourceRecord, using generator: inout some RandomNumberGenerator) {
        var reference = record.reference
        if let identifier = reference.sourceID {
            guard seenIdentifiers.insert(identifier).inserted else {
                skip(reference, .duplicateIdentifier(identifier))
                return
            }
        }
        if record.state == .trashed, !options.includesTrashed {
            skip(reference, .trashedAtSource)
            return
        }
        if let reason = oversize(record) {
            skip(reference, reason)
            return
        }

        var warnings = record.warnings
        var fields: [Field] = []
        var scopes: [ServiceScope] = []
        // Sets, not searches of the arrays: an entry may list a thousand URLs, and a file fifty thousand entries.
        var scopeHosts = Set<String>()
        var refusedURLs = Set<String>()
        for url in record.urls {
            let trimmed = UTF8Text.trimmed(url)
            guard !trimmed.isEmpty else { continue }
            switch ScopeDerivation.scope(forURL: trimmed, stripsLeadingWWW: options.stripsLeadingWWW) {
            case .success(let scope):
                if scopeHosts.insert(scope.host).inserted { scopes.append(scope) }
            case .failure(let reason):
                guard refusedURLs.insert(trimmed).inserted else { continue }
                fields.append(
                    Field(
                        id: RandomUUID.make(using: &generator), kind: .url, label: "Website", value: trimmed,
                        meta: [InterchangeMeta.sourceType: InterchangeMeta.websiteType]))
                warnings.append(.scopeRefused(url: trimmed, reason: reason))
            }
        }
        for source in record.fields where !source.value.isEmpty {
            let id = RandomUUID.make(using: &generator)
            switch source.kind {
            case .plain(let kind):
                fields.append(Field(id: id, kind: kind, label: source.label, value: source.value, meta: source.meta))
            case .oneTimePassword:
                do {
                    let uri = try ImportAssembler.canonicalOneTimePasswordURI(source.value)
                    fields.append(Field(id: id, kind: .totp, label: source.label, value: uri, meta: source.meta))
                } catch {
                    let reason = (error as? OTPAuthError) ?? .notAnOTPAuthURI
                    fields.append(ImportAssembler.unusableOneTimePassword(source, id: id))
                    warnings.append(.unusableOneTimePassword(label: source.label, reason: reason))
                }
            case .unusableOneTimePassword(let reason):
                fields.append(ImportAssembler.unusableOneTimePassword(source, id: id))
                warnings.append(.unusableOneTimePassword(label: source.label, reason: reason))
            case .passkey(let credential):
                do {
                    fields.append(try Field.passkey(credential, id: id, label: source.label))
                } catch {
                    warnings.append(.passkeyRefused(reason: "encoding"))
                }
            }
        }

        var tags = Set(record.tags.map { UTF8Text.trimmed($0) }.filter { !$0.isEmpty })
        if record.favorite, let favoriteTag = options.favoriteTag, !favoriteTag.isEmpty {
            tags.insert(favoriteTag)
        }

        var title = UTF8Text.trimmed(record.title)
        guard !(title.isEmpty && fields.isEmpty && scopes.isEmpty && record.notes.isEmpty) else {
            skip(reference, record.hadUnimportableContent ? .nothingImportable : .empty)
            return
        }
        if title.isEmpty {
            title =
                scopes.first?.host ?? fields.first { $0.kind == .username || $0.kind == .email }?.value ?? ""
            if !title.isEmpty { warnings.append(.titleDerived) }
        }
        reference.title = title

        // Newest first, as `Item.history` is kept; an undated one is older than any dated one.
        let history = record.pastPasswords.filter { !$0.value.isEmpty }
            .sorted { ($0.replacedAt ?? .distantPast) > ($1.replacedAt ?? .distantPast) }
            .map { past in
                ItemHistoryEntry(
                    replacedAt: past.replacedAt ?? Date(timeIntervalSince1970: 0), version: 0,
                    fields: [
                        Field(
                            id: RandomUUID.make(using: &generator), kind: .password, label: "Password",
                            value: past.value)
                    ])
            }

        let created = record.createdAt ?? record.modifiedAt ?? Date(timeIntervalSince1970: 0)
        let item = Item(
            id: RandomUUID.make(using: &generator), vaultID: vaultID, title: title, scopes: scopes, fields: fields,
            tags: tags, notes: record.notes, createdAt: created, modifiedAt: record.modifiedAt ?? created,
            archived: record.state == .archived, history: history)
        entries.append(ImportedEntry(item: item, kind: record.kind, state: record.state, reference: reference))
        report.countsByKind[record.kind, default: 0] += 1
        for warning in warnings {
            guard report.warnings.count < ImportReport.maximumWarnings else {
                report.omittedWarningCount += 1
                continue
            }
            report.warnings.append(ImportWarningRecord(entry: reference, warning: warning))
        }
    }

    /// The reason `record` is too large to be an item, if it is. Checked before any of it is copied into a draft.
    private func oversize(_ record: SourceRecord) -> ImportSkipReason? {
        let parts = record.fields.count + record.urls.count + record.tags.count + record.pastPasswords.count
        guard parts <= limits.maximumFieldsPerItem else {
            return .tooLarge(.fieldsPerItem, limit: limits.maximumFieldsPerItem)
        }
        var total = 0
        var largest = 0
        func count(_ text: String) {
            let size = text.utf8.count
            total += size
            largest = max(largest, size)
        }
        count(record.title)
        count(record.notes)
        for text in record.urls + record.tags {
            count(text)
        }
        for field in record.fields {
            count(field.label)
            count(field.value)
            for (key, value) in field.meta {
                count(key)
                count(value)
            }
        }
        for past in record.pastPasswords {
            count(past.value)
        }
        guard largest <= limits.maximumFieldBytes else {
            return .tooLarge(.fieldBytes, limit: limits.maximumFieldBytes)
        }
        guard total <= limits.maximumEntryBytes else { return .tooLarge(.entryBytes, limit: limits.maximumEntryBytes) }
        return nil
    }

    /// The canonical `otpauth://totp/` URI for a one-time-password value from a file: either a URI, validated through
    /// `OTPParameters`, or a bare Base32 secret with the default parameters. Throws `OTPAuthError` for anything a
    /// code could not be computed from.
    static func canonicalOneTimePasswordURI(_ value: String) throws -> String {
        let trimmed = UTF8Text.trimmed(value)
        let parameters: OTPParameters
        let isURI = trimmed.lowercased().hasPrefix("otpauth:")
        if isURI {
            parameters = try OTPParameters(uri: trimmed)
        } else {
            guard trimmed.utf8.count <= OTPParameters.maximumURILength else { throw OTPAuthError.tooLong }
            let compact = trimmed.filter { $0 != " " && $0 != "-" }
            guard !compact.isEmpty else { throw OTPAuthError.missingSecret }
            guard let secret = Base32.decode(compact) else { throw OTPAuthError.malformedSecret }
            parameters = try OTPParameters(secret: secret)
        }
        // Stored in canonical form when that reads back as the same parameters; otherwise as it was written, which
        // has just been shown to parse.
        let canonical = parameters.uri
        if (try? OTPParameters(uri: canonical)) == parameters { return canonical }
        guard isURI else { throw OTPAuthError.malformedSecret }
        return trimmed
    }

    /// Kept, concealed, so the person still has the value; not a `totp` field, so nothing tries to compute a code.
    private static func unusableOneTimePassword(_ source: SourceField, id: UUID) -> Field {
        var meta = source.meta
        meta[InterchangeMeta.sourceType] = "totp"
        let label = source.label.isEmpty ? "One-time password" : source.label
        return Field(id: id, kind: .custom, label: label, value: source.value, meta: meta)
    }
}
