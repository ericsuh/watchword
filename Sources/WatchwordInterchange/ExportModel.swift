import Foundation
import WatchwordModel

/// Something an export could not carry as it was. Exports never fail over one item: what a format cannot hold is
/// left out or moved, and listed here so the person is told before they rely on the file (PRD F8.4, F8.5).
public enum ExportWarning: Hashable, Sendable {
    /// The format has no place for a passkey (CSV, 1PUX); the item was exported without it.
    case passkeyOmitted(itemID: UUID)
    /// A stored passkey field did not decode, so it could not be written.
    case passkeyUnreadable(itemID: UUID)
    /// Fields the format has no column for were written into the notes as `label: value` lines.
    case fieldsMovedToNotes(itemID: UUID, count: Int)
    /// A cell began with a character a spreadsheet would run as a formula, and was prefixed with an apostrophe
    /// (PRD SEC7). An importer will see the apostrophe as part of the value.
    case cellNeutralised(itemID: UUID, column: String)
    /// The item is in the trash and was left out.
    case trashedItemOmitted(itemID: UUID)
    /// A one-time-password field that is not a usable `otpauth://totp/` URI was written as a concealed field.
    case oneTimePasswordUnusable(itemID: UUID)
    /// The item holds field values that sync is keeping until the person chooses between them (`Item.conflicts`,
    /// `Item.retainedValues`; PRD F7.6, F7.7). `count` of them were written as extra concealed fields labelled
    /// "(unresolved value)" (as lines of the notes in CSV), so the export leaves none behind.
    case unresolvedValuesAdded(itemID: UUID, count: Int)
    /// `count` unresolved values of something other than a field's text (a title, the scopes, the tags, the
    /// archived mark, a passkey) were left out: only the value shown was written.
    case unresolvedValuesOmitted(itemID: UUID, count: Int)
    /// `entries` earlier versions of the item's fields (`Item.history`) were left out, or written without all of
    /// their fields: CXF and CSV have no place for history, and 1PUX keeps earlier passwords only.
    case historyOmitted(itemID: UUID, entries: Int)
    /// The scope for `host` did not include subdomains, or excluded hosts. No format here can say so: the file names
    /// the host only, and whatever imports it (this app included) will offer the item on its subdomains too.
    case scopeRestrictionOmitted(itemID: UUID, host: String)
    /// `count` URLs the item holds as its websites were written as ordinary fields (lines of the notes in CSV), not
    /// among its sign-in URLs: each names a host the item is not scoped to, or came after the first
    /// `InterchangeLimits.maximumURLsPerItem`. Whatever imports the file would otherwise offer the item there.
    case websiteNotScoped(itemID: UUID, count: Int)
    /// The item is archived and the format has no archived mark (CXF, CSV): it was written as an active item.
    case archivedStateOmitted(itemID: UUID)
    /// The format has no place for tags (CSV); the item was written without them.
    case tagsOmitted(itemID: UUID)
    /// Something the field records beside its value was left out: which recovery codes are spent, for one.
    case fieldDetailOmitted(itemID: UUID, label: String)
}

public struct ExportReport: Hashable, Sendable {
    /// Items written.
    public var exportedCount: Int
    public var warnings: [ExportWarning]

    public init(exportedCount: Int = 0, warnings: [ExportWarning] = []) {
        self.exportedCount = exportedCount
        self.warnings = warnings
    }
}

/// An export: the file's bytes, which are **plaintext**, and what could not be carried.
///
/// Nothing in this module writes a file or asks for the account password. The caller does both: re-entry of the
/// password before the bytes exist, the strongest file-protection class when they are written, and the standing
/// warning while they exist (PRD F8.4).
public struct ExportResult: Hashable, Sendable {
    public var bytes: [UInt8]
    public var report: ExportReport

    public init(bytes: [UInt8], report: ExportReport) {
        self.bytes = bytes
        self.report = report
    }
}

/// What every exporter does the same way: the URLs it writes for an item, the values sync is keeping, and the
/// warnings for what no format here can carry. Kept in one place so that no format forgets a line of the report.
enum ExportSupport {
    static let unresolvedLabel = "Unresolved values"

    /// The URLs to write where a format keeps an entry's sign-in URLs, and the `url` fields they came from.
    ///
    /// A scope is a host, so the URL for one is `https://host/`, unless the item still holds the URL it was imported
    /// with (`ImportAssembler` keeps any that said more than its host, as a `url` field of type
    /// `InterchangeMeta.websiteType`): then that text is written in its place, and the sign-in page, port or scheme
    /// survives. Which field stands for which scope is decided here, by deriving each field's host again, never
    /// from a hint. Website fields no scope can come from (URLs the scope policy refused on import) follow.
    ///
    /// **Nothing here names a host the item is not scoped to.** Whatever reads the file offers the item's secrets on
    /// every URL written here, so a website field whose URL derives to a host that is not one of the item's scopes
    /// is not written: the item is not offered there in this app (the person removed the scope, or the field came
    /// from somewhere that never checked), and an export must not widen that (PRD SEC6, F11.2). Such a field is
    /// left to the caller to write like any other field, and reported. So is one beyond the number of URLs an
    /// import considers for one entry, which is not parsed at all.
    static func websites(of item: Item, report: inout ExportReport) -> (urls: [String], fieldIDs: Set<UUID>) {
        let scoped = Set(item.scopes.map(\.host))
        var websiteFields: [Field] = []
        var byHost: [String: [Int]] = [:]
        var unscoped = 0
        // As many are parsed as an import would have parsed for one entry; an item is not trusted to be small (it
        // may come from another member of a shared vault), and parsing a URL is the costly step.
        var parsed = 0
        for field in item.fields
        where field.kind == .url && field.meta[InterchangeMeta.sourceType] == InterchangeMeta.websiteType {
            guard parsed < InterchangeLimits.standard.maximumURLsPerItem else {
                unscoped += 1
                continue
            }
            parsed += 1
            if let hosts = ScopeDerivation.websiteHosts(of: field.value) {
                let own = hosts.filter(scoped.contains)
                guard !own.isEmpty else {
                    unscoped += 1
                    continue
                }
                for host in own {
                    byHost[host, default: []].append(websiteFields.count)
                }
            }
            websiteFields.append(field)
        }
        var urls: [String] = []
        var written = Set<Int>()
        for scope in item.scopes {
            let own = (byHost[scope.host] ?? []).filter { written.insert($0).inserted }
            if own.isEmpty {
                urls.append(ScopeDerivation.canonicalURL(for: scope))
            } else {
                urls += own.map { websiteFields[$0].value }
            }
        }
        for (index, field) in websiteFields.enumerated() where !written.contains(index) {
            urls.append(field.value)
        }
        if unscoped > 0 { report.warnings.append(.websiteNotScoped(itemID: item.id, count: unscoped)) }
        return (urls, Set(websiteFields.map(\.id)))
    }

    /// The field values sync is keeping beside the ones `item` shows, each labelled for the person, and the number of
    /// kept values that are not a field's text. In a fixed order, so an export is deterministic.
    static func unresolvedValues(of item: Item) -> (fields: [(label: String, value: String)], omitted: Int) {
        var shown: [UUID: [UInt8]] = [:]
        for field in item.fields {
            shown[field.id] = Array(field.value.utf8)
        }
        var fields: [(label: String, value: String)] = []
        var listed = Set<[UInt8]>()
        var omitted = 0
        let conflicting = item.conflicts.keys.sorted().flatMap { item.conflicts[$0] ?? [] }
        for kept in conflicting + item.retainedValues {
            guard case .field(let field) = kept.value else {
                omitted += 1
                continue
            }
            // A removal holds no value; an empty value, or the one already shown, has nothing to add.
            guard let field, !field.value.isEmpty else { continue }
            let value = Array(field.value.utf8)
            guard shown[field.id] != value else { continue }
            guard field.kind != .passkey else {
                omitted += 1
                continue
            }
            let name = field.label.isEmpty ? field.kind.rawValue : field.label
            guard listed.insert(Array(name.utf8) + [0] + value).inserted else { continue }
            fields.append(("\(name) (unresolved value)", field.value))
        }
        return (fields, omitted)
    }

    /// The warnings for what no format here carries: restricted scopes and what fields record beside their value.
    static func commonWarnings(for item: Item, into report: inout ExportReport) {
        for scope in item.scopes {
            let restricted = !scope.includeSubdomains && !ScopeDerivation.isAddress(scope.host)
            if restricted || !scope.excludedHosts.isEmpty {
                report.warnings.append(.scopeRestrictionOmitted(itemID: item.id, host: scope.host))
            }
        }
        for field in item.fields where field.meta.keys.contains(where: { !InterchangeMeta.all.contains($0) }) {
            report.warnings.append(.fieldDetailOmitted(itemID: item.id, label: field.label))
        }
    }
}

/// Calendar arithmetic on the proleptic Gregorian calendar in UTC, so date fields mean the same on every platform
/// and no formatter or locale is involved.
enum CivilDate {
    /// `yyyy-MM-dd` for a number of seconds since 1970.
    static func string(seconds: Int64) -> String {
        let (year, month, day) = civil(days: Int(floorDivide(seconds, 86_400)))
        return "\(pad(year, 4))-\(pad(month, 2))-\(pad(day, 2))"
    }

    /// Seconds since 1970 at noon UTC on a `yyyy-MM-dd` date, or `nil` if `text` is not one.
    static func seconds(fromDate text: String) -> Int64? {
        let parts = text.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0].count == 4, parts[1].count == 2, parts[2].count == 2,
            let year = number(parts[0]), let month = number(parts[1]), let day = number(parts[2]),
            (1...12).contains(month), (1...31).contains(day)
        else { return nil }
        let days = daysFromCivil(year: year, month: month, day: day)
        // Only a real date: 31 February does not round-trip.
        guard civil(days: days) == (year, month, day) else { return nil }
        return Int64(days) * 86_400 + 43_200
    }

    /// `yyyy-MM` for 1Password's `monthYear` integer (`YYYYMM`), or `nil` if it is not one.
    static func string(monthYear: Int64) -> String? {
        let year = monthYear / 100
        let month = monthYear % 100
        guard (1...9999).contains(year), (1...12).contains(month) else { return nil }
        return "\(pad(Int(year), 4))-\(pad(Int(month), 2))"
    }

    /// The `YYYYMM` integer for a `yyyy-MM` string.
    static func monthYear(from text: String) -> Int64? {
        let parts = text.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 2, parts[0].count == 4, parts[1].count == 2, let year = number(parts[0]),
            let month = number(parts[1]), (1...9999).contains(year), (1...12).contains(month)
        else { return nil }
        return Int64(year * 100 + month)
    }

    private static func number(_ text: Substring) -> Int? {
        guard text.utf8.allSatisfy({ (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) }) else { return nil }
        return Int(text)
    }

    private static func pad(_ value: Int, _ width: Int) -> String {
        let digits = String(value)
        return String(repeating: "0", count: max(0, width - digits.count)) + digits
    }

    private static func floorDivide(_ value: Int64, _ divisor: Int64) -> Int64 {
        let quotient = value / divisor
        return value % divisor < 0 ? quotient - 1 : quotient
    }

    /// Days since 1970-01-01 to a civil date (Howard Hinnant's `civil_from_days`).
    private static func civil(days: Int) -> (Int, Int, Int) {
        let shifted = days + 719_468
        let era = (shifted >= 0 ? shifted : shifted - 146_096) / 146_097
        let dayOfEra = shifted - era * 146_097
        let yearOfEra = (dayOfEra - dayOfEra / 1_460 + dayOfEra / 36_524 - dayOfEra / 146_096) / 365
        let dayOfYear = dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100)
        let monthIndex = (5 * dayOfYear + 2) / 153
        let day = dayOfYear - (153 * monthIndex + 2) / 5 + 1
        let month = monthIndex < 10 ? monthIndex + 3 : monthIndex - 9
        let year = yearOfEra + era * 400 + (month <= 2 ? 1 : 0)
        return (year, month, day)
    }

    private static func daysFromCivil(year: Int, month: Int, day: Int) -> Int {
        let adjusted = month <= 2 ? year - 1 : year
        let era = (adjusted >= 0 ? adjusted : adjusted - 399) / 400
        let yearOfEra = adjusted - era * 400
        let dayOfYear = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1
        let dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear
        return era * 146_097 + dayOfEra - 719_468
    }
}
