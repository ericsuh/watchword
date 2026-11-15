import Foundation
import WatchwordModel

/// CSV exports of 1Password and Apple Passwords, in and out (PRD F8.1, F8.2, F8.4).
///
/// The header row decides everything. Known columns are matched by name, without regard to case; any other column
/// is kept, as a concealed custom field labelled with its header, so a column this importer has never heard of
/// costs nothing. A file whose first row names fewer than two known columns is not guessed at.
public enum PasswordCSV {
    /// The columns this importer understands.
    enum Column: Hashable {
        case title, url, username, password, oneTimePassword, favorite, archived, tags, notes
        case custom(String)

        init(header: String) {
            switch UTF8Text.trimmed(header).lowercased() {
            case "title": self = .title
            case "url", "website": self = .url
            case "username": self = .username
            case "password": self = .password
            case "otpauth", "one-time password": self = .oneTimePassword
            case "favorite": self = .favorite
            case "archived": self = .archived
            case "tags": self = .tags
            case "notes": self = .notes
            default: self = .custom(header)
            }
        }

        var isKnown: Bool {
            if case .custom = self { return false }
            return true
        }
    }

    /// Apple Passwords' header, exactly (docs/00-research.md §1.3).
    public static let applePasswordsHeader = ["Title", "URL", "Username", "Password", "Notes", "OTPAuth"]

    /// Which exporter wrote a header row. Throws `unrecognisedCSVHeader` for a row naming fewer than two known
    /// columns, and `malformedCSV(.duplicateColumn)` when two columns claim the same meaning.
    public static func detectFormat(header: [String]) throws -> InterchangeFormat {
        try columns(of: CSVRecord(line: 1, fields: header)).format
    }

    private static func columns(of header: CSVRecord) throws -> (format: InterchangeFormat, columns: [Column]) {
        let columns = header.fields.map(Column.init(header:))
        let known = columns.filter(\.isKnown)
        guard Set(known).count == known.count else {
            throw InterchangeError.malformedCSV(.duplicateColumn, line: header.line)
        }
        guard known.count >= 2 else { throw InterchangeError.unrecognisedCSVHeader }
        let format: InterchangeFormat
        if header.fields == applePasswordsHeader {
            format = .applePasswordsCSV
        } else if header.fields.contains("Url")
            || known.contains(where: { [.favorite, .archived, .tags].contains($0) })
        {
            format = .onePassword8CSV
        } else {
            format = .onePassword7CSV
        }
        return (format, columns)
    }

    /// Imports a 1Password or Apple Passwords CSV file as item drafts for `vaultID`.
    public static func importFile(
        _ bytes: [UInt8], into vaultID: UUID, limits: InterchangeLimits = .standard,
        options: ImportOptions = ImportOptions(), using generator: inout some RandomNumberGenerator
    ) throws -> ImportResult {
        let records = try CSVReader.parse(bytes, limits: limits)
        guard let header = records.first else { throw InterchangeError.malformedCSV(.empty, line: 1) }
        let (format, columns) = try columns(of: header)
        var assembler = ImportAssembler(format: format, vaultID: vaultID, limits: limits, options: options)

        for row in records.dropFirst() {
            let index = try assembler.beginEntry()
            var record = SourceRecord(
                reference: ImportEntryReference(index: index, line: row.line), kind: .login, title: "")
            guard row.fields.count == columns.count else {
                if let title = columns.firstIndex(of: .title), title < row.fields.count {
                    record.reference.title = row.fields[title]
                }
                assembler.skip(
                    record.reference, .columnCountMismatch(expected: columns.count, found: row.fields.count))
                continue
            }
            for (position, cell) in row.fields.enumerated() {
                if isNeutralisedFormula(cell) {
                    record.warnings.append(.possiblyNeutralisedFormula(column: header.fields[position]))
                }
                switch columns[position] {
                case .title:
                    record.title = cell
                    record.reference.title = cell
                case .url:
                    record.urls.append(cell)
                case .username:
                    record.fields.append(SourceField(kind: .plain(.username), label: "Username", value: cell))
                case .password:
                    record.fields.append(SourceField(kind: .plain(.password), label: "Password", value: cell))
                case .oneTimePassword:
                    record.fields.append(
                        SourceField(kind: .oneTimePassword, label: "One-time password", value: cell))
                case .favorite:
                    record.favorite = isTrue(cell)
                case .archived:
                    if isTrue(cell) { record.state = .archived }
                case .tags:
                    record.tags = cell.split(whereSeparator: { $0 == ";" || $0 == "," }).map(String.init)
                case .notes:
                    record.notes = cell
                case .custom(let name):
                    record.fields.append(SourceField(kind: .plain(.custom), label: name, value: cell))
                }
            }
            record.kind = kind(of: record)
            assembler.add(record, using: &generator)
        }
        return assembler.result
    }

    private static func kind(of record: SourceRecord) -> ImportedKind {
        func has(_ kind: FieldKind) -> Bool {
            record.fields.contains { field in
                if case .plain(kind) = field.kind { return !field.value.isEmpty }
                return false
            }
        }
        let hasURL = record.urls.contains { !$0.isEmpty }
        if has(.password), !has(.username), !hasURL { return .password }
        if !has(.password), !has(.username), !hasURL, !record.notes.isEmpty { return .secureNote }
        return .login
    }

    private static func isTrue(_ cell: String) -> Bool {
        ["true", "1", "yes"].contains(UTF8Text.trimmed(cell).lowercased())
    }

    /// Whether a cell looks like the output of `CSVWriter.neutralised`: an apostrophe, then a formula character.
    private static func isNeutralisedFormula(_ cell: String) -> Bool {
        guard cell.hasPrefix("'") else { return false }
        return CSVWriter.isFormulaLike(String(cell.dropFirst()))
    }

    /// Exports `items` as an Apple Passwords CSV file (PRD F8.4): one row per scope, since Apple Passwords keeps one
    /// entry per website.
    ///
    /// The format has six columns. What does not fit is not lost quietly: a passkey is left out and reported
    /// (passkeys do not survive CSV, docs/00-research.md §1.3), and every other field without a column is written
    /// into the notes as a `label: value` line and reported. Cells a spreadsheet would run are made inert under
    /// `formulaPolicy`, and each one changed is reported.
    public static func exportApplePasswords(
        _ items: [Item], formulaPolicy: CSVWriter.FormulaPolicy = .neutralise
    ) -> ExportResult {
        var report = ExportReport()
        var rows = [applePasswordsHeader]
        for item in items {
            guard !item.isTrashed else {
                report.warnings.append(.trashedItemOmitted(itemID: item.id))
                continue
            }
            let username = item.fields.first { $0.kind == .username } ?? item.fields.first { $0.kind == .email }
            let password = item.field(.password)
            let oneTimePassword = item.fields.first { $0.kind == .totp && (try? $0.otpParameters()) != nil }
            var urls = item.scopes.map { "https://\($0.host)/" }
            let urlField = urls.isEmpty ? item.fields.first { $0.kind == .url } : nil
            if let urlField { urls = [urlField.value] }

            var notes = item.notes
            var moved = 0
            for field in item.fields {
                if field.kind == .passkey {
                    report.warnings.append(.passkeyOmitted(itemID: item.id))
                    continue
                }
                let hasColumn = [username?.id, password?.id, oneTimePassword?.id, urlField?.id].contains(field.id)
                guard !hasColumn, !field.value.isEmpty else { continue }
                if !notes.isEmpty { notes += "\n" }
                notes += "\(field.label.isEmpty ? field.kind.rawValue : field.label): \(field.value)"
                moved += 1
            }
            if moved > 0 { report.warnings.append(.fieldsMovedToNotes(itemID: item.id, count: moved)) }

            for url in urls.isEmpty ? [""] : urls {
                let cells = [
                    item.title, url, username?.value ?? "", password?.value ?? "", notes, oneTimePassword?.value ?? "",
                ]
                var row: [String] = []
                for (column, cell) in zip(applePasswordsHeader, cells) {
                    let written = CSVWriter.neutralised(cell, policy: formulaPolicy)
                    if written != cell { report.warnings.append(.cellNeutralised(itemID: item.id, column: column)) }
                    row.append(written)
                }
                rows.append(row)
            }
            report.exportedCount += 1
        }
        return ExportResult(bytes: Array(CSVWriter.encode(rows).utf8), report: report)
    }
}
