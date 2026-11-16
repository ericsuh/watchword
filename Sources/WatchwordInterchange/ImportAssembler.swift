import Foundation
import WatchwordMatching
import WatchwordModel

/// Turns a URL from an import file into a scope, or says why not (PRD F11.2, SEC8).
///
/// The one route by which an imported URL can come to govern AutoFill: `HostNormalizer` first, so anything that is
/// not unambiguously a web host is refused, then `ScopePolicy`, so a host that spans unrelated owners (`com`,
/// `co.uk`, `github.io`) is refused. Nothing is repaired on the way: a refused URL stays a URL field.
public enum ScopeDerivation {
    public static func scope(forURL text: String) -> Result<ServiceScope, ScopeRefusal> {
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
        // A dotted-decimal address has no subdomains to include.
        let scope = ServiceScope(host: host.value, includeSubdomains: !isAddress(host.value))
        do {
            try ScopePolicy.validate(scope)
            return .success(scope)
        } catch let error as ScopeValidationError {
            return .failure(.policy(error))
        } catch {
            return .failure(.policy(.notAHostname(host.value)))
        }
    }

    /// The scope an import adds beside one for `www.<apex>` (`ImportOptions.matchApexOfWWWHosts`, owner decision
    /// 2026-11-16): `<apex>`, with the same subdomain setting, so that an entry saved on a site's `www` host is offered
    /// on the site itself too. Exactly one leading `www` label is removed, never more: `www.www.example.com` gives
    /// `www.example.com`, and that is not stripped again. `nil` when the scope is not on a `www` host, when what
    /// remains is a dotted-decimal address, and when the scope policy refuses it (`www.co.uk` gives nothing: `co.uk`
    /// is a public suffix).
    public static func apexScope(beside scope: ServiceScope) -> ServiceScope? {
        let www = Array("www.".utf8)
        let host = Array(scope.host.utf8)
        guard host.count > www.count, host.starts(with: www) else { return nil }
        let apex = String(decoding: host.dropFirst(www.count), as: UTF8.self)
        guard !isAddress(apex) else { return nil }
        let candidate = ServiceScope(host: apex, includeSubdomains: scope.includeSubdomains)
        guard candidate.host == apex, ScopePolicy.isAcceptable(candidate) else { return nil }
        return candidate
    }

    /// A scope read from an encrypted Watchword archive, checked as an imported URL's would be: its host must be what
    /// `scope(forURL:)` derives from it, unchanged, so the normaliser, the plain-name rule and `ScopePolicy` all
    /// apply. What it says beyond its host can only narrow it: subdomains stay included only where the derived scope
    /// includes them, and exclusions are kept (PRD F11.2).
    static func validated(_ scope: ServiceScope) -> Result<ServiceScope, ScopeRefusal> {
        switch self.scope(forURL: scope.host) {
        case .failure(let refusal):
            return .failure(refusal)
        case .success(let derived):
            guard Array(derived.host.utf8) == Array(scope.host.utf8) else {
                return .failure(.notAHost(.invalidHost(scope.host)))
            }
            return .success(
                ServiceScope(
                    host: derived.host, includeSubdomains: derived.includeSubdomains && scope.includeSubdomains,
                    excludedHosts: scope.excludedHosts))
        }
    }

    /// Whether `host` is a dotted-decimal address: digits and dots only.
    static func isAddress(_ host: String) -> Bool {
        host.utf8.allSatisfy { (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) || $0 == UInt8(ascii: ".") }
    }

    /// The hosts a URL kept as text can stand for among an item's scopes: the host derived from it, and that host
    /// without a leading `www.` (the apex scope an import adds beside a `www` one stands for the same URL, and an
    /// older import derived the apex alone). `nil` for a URL no scope can come from.
    /// Derived from the text every time it is asked, with the rules an import applies, never read from a hint.
    static func websiteHosts(of text: String) -> [String]? {
        guard case .success(let scope) = scope(forURL: text) else { return nil }
        var hosts = [scope.host]
        if scope.host.hasPrefix("www.") { hosts.append(String(scope.host.dropFirst(4))) }
        return hosts
    }

    /// The URL an export writes for a scope that has no URL of its own on record.
    static func canonicalURL(for scope: ServiceScope) -> String {
        "https://\(scope.host)/"
    }

    /// Whether `text` says nothing beyond `scope`: the host alone, or `https://` and the host with at most a bare
    /// slash. Anything else (another scheme, a port, a path, a query) is information the scope does not hold, and the
    /// import keeps the text. Compared on bytes, ASCII letters without regard to case.
    static func isCanonical(_ text: String, for scope: ServiceScope) -> Bool {
        func folded(_ text: String) -> [UInt8] {
            text.utf8.map { (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains($0) ? $0 + 0x20 : $0 }
        }
        let written = folded(text)
        let host = Array(scope.host.utf8)
        let prefixed = Array("https://".utf8) + host
        return written == host || written == prefixed || written == prefixed + [UInt8(ascii: "/")]
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
    // Internal rather than private so the archive path (`ArchivedItems.swift`) counts against the same budgets.
    var entries: [ImportedEntry] = []
    var report: ImportReport
    var seenIdentifiers = Set<String>()
    /// Every entry and container visited, imported or not: the bound on the work one file can ask for.
    private var visited = 0
    /// Fields, URLs, tags and history entries in the drafts so far, against `maximumTotalFields`.
    var totalFields = 0
    /// URLs (and, from an archive, scopes) handed to `ScopeDerivation` so far, against `maximumScopeDerivations`.
    var scopeDerivations = 0
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
    /// a collection may be read after the items it lists. A tag larger than a field may be is left off. The tags
    /// count against `maximumTotalFields` like any others.
    mutating func addTags(_ tags: [String: [String]], since mark: Mark) throws {
        guard !tags.isEmpty else { return }
        for index in mark.entries..<entries.count {
            guard let identifier = entries[index].reference.sourceID, let names = tags[identifier] else { continue }
            for name in names where name.utf8.count <= limits.maximumFieldBytes {
                let trimmed = UTF8Text.trimmed(name)
                guard !trimmed.isEmpty, entries[index].item.tags.insert(trimmed).inserted else { continue }
                totalFields += 1
                guard totalFields <= limits.maximumTotalFields else { throw limits.exceeded(.totalFields) }
            }
        }
    }

    /// A timestamp from a file, if it is one a person could mean.
    static func date(seconds: Int64?) -> Date? {
        guard let seconds, (0...latestPlausibleTimestamp).contains(seconds) else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(seconds))
    }

    /// Seconds since 1970 for 0001-01-01T00:00:00Z: the first day a `yyyy-MM-dd` date can name.
    static let earliestCalendarDate: Int64 = -62_135_596_800

    /// `yyyy-MM-dd` for a date field from a file. Unlike a timestamp, a date may lie before 1970 (a date of birth
    /// does): any day of the years 1 to 9999 is one a person could mean.
    static func calendarDate(seconds: Int64) -> String? {
        guard (earliestCalendarDate...latestPlausibleTimestamp).contains(seconds) else { return nil }
        return CivilDate.string(seconds: seconds)
    }

    /// Applies the vault's rules to `record` and adds the resulting draft, or records why it was skipped. Throws only
    /// when the import as a whole has reached `maximumTotalFields`.
    mutating func add(_ record: SourceRecord, using generator: inout some RandomNumberGenerator) throws {
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
        // Keyed by bytes: two spellings that are equal as strings and differ as bytes are both kept.
        var scopeHosts = Set<String>()
        var seenURLs = Set<[UInt8]>()
        var considered = 0
        var unconsidered = 0
        // Each URL kept as text, in the file's order. One that says nothing beyond its scope is kept only if another
        // URL of the same host is, so that an export then writes both and not the longer one alone.
        var websites: [(text: String, canonicalFor: String?)] = []
        var hostsWithText = Set<String>()
        // Apex scopes to add beside `www` ones, once every URL of the entry has been seen: a host the entry lists for
        // itself is the file's own scope, not an addition.
        var apexes: [(www: String, apex: ServiceScope)] = []
        for url in record.urls {
            let trimmed = UTF8Text.trimmed(url)
            // A repeat is dropped before it is parsed: parsing a URL is the expensive part.
            guard !trimmed.isEmpty, seenURLs.insert(Array(trimmed.utf8)).inserted else { continue }
            guard considered < limits.maximumURLsPerItem, scopeDerivations < limits.maximumScopeDerivations else {
                websites.append((trimmed, nil))
                unconsidered += 1
                continue
            }
            considered += 1
            scopeDerivations += 1
            switch ScopeDerivation.scope(forURL: trimmed) {
            case .success(let scope):
                if scopeHosts.insert(scope.host).inserted {
                    scopes.append(scope)
                    if options.matchApexOfWWWHosts, let apex = ScopeDerivation.apexScope(beside: scope) {
                        apexes.append((www: scope.host, apex: apex))
                    }
                }
                // A scope is a host. Whatever else the URL said (a scheme, a port, the sign-in page) is kept beside
                // it, so that nothing is lost and an export writes the URL back as it was (PRD F8.1).
                if ScopeDerivation.isCanonical(trimmed, for: scope) {
                    websites.append((trimmed, scope.host))
                } else {
                    websites.append((trimmed, nil))
                    hostsWithText.insert(scope.host)
                }
            case .failure(let reason):
                websites.append((trimmed, nil))
                warnings.append(.scopeRefused(url: trimmed, reason: reason))
            }
        }
        for (www, apex) in apexes where scopeHosts.insert(apex.host).inserted {
            scopes.append(apex)
            warnings.append(.apexScopeAdded(wwwHost: www, apex: apex.host))
        }
        // Before any field is built: what this entry adds to the drafts, against what the whole import may hold. A
        // URL counts once however often the entry repeats it.
        let kept =
            record.fields.count(where: { !$0.value.isEmpty }) + websites.count + record.tags.count
            + record.pastPasswords.count + (record.favorite ? 1 : 0)
        guard kept <= limits.maximumTotalFields - totalFields else { throw limits.exceeded(.totalFields) }
        for (text, canonicalFor) in websites where canonicalFor.map({ hostsWithText.contains($0) }) ?? true {
            fields.append(
                Field(
                    id: RandomUUID.make(using: &generator), kind: .url, label: "Website", value: text,
                    meta: [InterchangeMeta.sourceType: InterchangeMeta.websiteType]))
        }
        if unconsidered > 0 { warnings.append(.urlsNotConsidered(count: unconsidered)) }
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
        // Measured as the vault will store it, not as the file wrote it: a draft listed as imported must be one
        // the vault accepts.
        guard StoredItemSize.estimate(item) <= limits.maximumStoredItemBytes else {
            skip(reference, .tooLarge(.storedItemBytes, limit: limits.maximumStoredItemBytes))
            return
        }
        totalFields += kept
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
