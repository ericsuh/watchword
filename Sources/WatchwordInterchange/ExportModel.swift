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
