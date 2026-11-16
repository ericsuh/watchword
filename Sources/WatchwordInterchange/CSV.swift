import Foundation

/// One record of a CSV file, with the line it started on (for the import report).
public struct CSVRecord: Hashable, Sendable {
    public var line: Int
    public var fields: [String]

    public init(line: Int, fields: [String]) {
        self.line = line
        self.fields = fields
    }
}

/// An RFC 4180 reader for password-manager exports (PRD F8.1, F8.2, SEC7).
///
/// What it accepts beyond the RFC, deliberately: LF as well as CRLF between records, a UTF-8 byte-order mark, a
/// missing line break after the last record, and blank lines (skipped). What it refuses, where a lenient reader
/// would guess: invalid UTF-8 (`InterchangeError.invalidUTF8`: a replacement character inside a password is a
/// different password), UTF-16, a NUL, a quote inside an unquoted field, text after a closing quote, a carriage
/// return on its own outside quotes, and a quoted field that never closes. Cell text is otherwise data and is
/// returned exactly as written: nothing is trimmed, and a cell beginning with `=` is not a formula here.
///
/// Size limits are enforced as bytes are consumed, so an unterminated quote cannot swallow more than one entry's
/// worth of memory before it is refused, and a row is refused at its hundred-and-first cell.
public enum CSVReader {
    private static let quote = UInt8(ascii: "\"")
    private static let comma = UInt8(ascii: ",")
    private static let lineFeed = UInt8(ascii: "\n")
    private static let carriageReturn = UInt8(ascii: "\r")

    /// Every record of the file, held at once. The cells are counted against `maximumTotalFields` as they are kept,
    /// because rows of two-byte cells are otherwise the cheapest way to turn a file into memory.
    public static func parse(_ bytes: [UInt8], limits: InterchangeLimits = .standard) throws -> [CSVRecord] {
        var records: [CSVRecord] = []
        var cells = 0
        try forEachRecord(bytes, limits: limits) { record in
            cells += record.fields.count
            guard cells <= limits.maximumTotalFields else { throw limits.exceeded(.totalFields) }
            records.append(record)
        }
        return records
    }

    /// Hands each record to `body` as it is read, holding one record at a time: what an import uses, so that the
    /// file's rows are never in memory beside the drafts made from them. A record with more than
    /// `maximumCSVColumns` cells, or one more record than `maximumItems` and a header, ends the read.
    public static func forEachRecord(
        _ bytes: [UInt8], limits: InterchangeLimits = .standard, _ body: (CSVRecord) throws -> Void
    ) throws {
        try limits.checkInput(bytes.count)
        let range = try UTF8Text.validatedRange(of: bytes)

        var count = 0
        var fields: [String] = []
        var field: [UInt8] = []
        var line = 1
        var recordLine = 1
        var rowBytes = 0
        var inQuotes = false
        var afterQuote = false
        var rowHasContent = false

        func endField() throws {
            fields.append(UTF8Text.string(field))
            guard fields.count <= limits.maximumCSVColumns else { throw limits.exceeded(.csvColumns) }
            field.removeAll(keepingCapacity: true)
            afterQuote = false
        }
        func endRecord() throws {
            if rowHasContent {
                try endField()
                count += 1
                // One more than the item limit: the header row is not an item.
                guard count <= limits.maximumItems + 1 else { throw limits.exceeded(.items) }
                try body(CSVRecord(line: recordLine, fields: fields))
                fields.removeAll(keepingCapacity: true)
            }
            rowHasContent = false
            rowBytes = 0
            line += 1
            recordLine = line
        }
        func append(_ byte: UInt8) throws {
            guard byte != 0 else { throw InterchangeError.malformedCSV(.nulCharacter, line: line) }
            field.append(byte)
            guard field.count <= limits.maximumFieldBytes else { throw limits.exceeded(.fieldBytes) }
        }

        var index = range.lowerBound
        while index < range.upperBound {
            let byte = bytes[index]
            index += 1
            rowBytes += 1
            guard rowBytes <= limits.maximumEntryBytes else { throw limits.exceeded(.entryBytes) }
            if inQuotes {
                if byte == quote {
                    if index < range.upperBound, bytes[index] == quote {
                        try append(quote)
                        index += 1
                        rowBytes += 1
                    } else {
                        inQuotes = false
                        afterQuote = true
                    }
                } else {
                    if byte == lineFeed { line += 1 }
                    try append(byte)
                }
                continue
            }
            switch byte {
            case comma:
                try endField()
                rowHasContent = true
            case lineFeed:
                try endRecord()
            case carriageReturn:
                guard index < range.upperBound, bytes[index] == lineFeed else {
                    throw InterchangeError.malformedCSV(.strayCarriageReturn, line: line)
                }
                index += 1
                try endRecord()
            case quote:
                guard !afterQuote else { throw InterchangeError.malformedCSV(.textAfterClosingQuote, line: line) }
                guard field.isEmpty else { throw InterchangeError.malformedCSV(.quoteInUnquotedField, line: line) }
                inQuotes = true
                rowHasContent = true
            default:
                guard !afterQuote else { throw InterchangeError.malformedCSV(.textAfterClosingQuote, line: line) }
                try append(byte)
                rowHasContent = true
            }
        }
        guard !inQuotes else { throw InterchangeError.malformedCSV(.unterminatedQuote, line: recordLine) }
        try endRecord()
    }
}

/// An RFC 4180 writer, with the formula-injection defence plaintext exports need (PRD SEC7).
public enum CSVWriter {
    /// What to do with a cell a spreadsheet would run as a formula.
    public enum FormulaPolicy: Hashable, Sendable {
        /// Prefix it with an apostrophe, which spreadsheets show as text. The default, and what SEC7 requires of an
        /// export: the file is plaintext a person may well open in a spreadsheet to look at.
        case neutralise
        /// Write it as it is. For a file that goes straight into another password manager's importer and is then
        /// deleted: an apostrophe in front of a password that begins with `-` is a different password there.
        case preserve
    }

    /// Whether a spreadsheet would treat `cell` as a formula or a command: it begins with `=`, `+`, `-`, `@`, a tab
    /// or a carriage return (OWASP, "CSV Injection").
    public static func isFormulaLike(_ cell: String) -> Bool {
        guard let first = cell.unicodeScalars.first else { return false }
        return first == "=" || first == "+" || first == "-" || first == "@" || first == "\t" || first == "\r"
    }

    /// `cell`, made inert under `policy`.
    public static func neutralised(_ cell: String, policy: FormulaPolicy = .neutralise) -> String {
        policy == .neutralise && isFormulaLike(cell) ? "'" + cell : cell
    }

    /// The rows as CSV text: CRLF after every record, and a field quoted when it contains a comma, a quote, a line
    /// break, or leading or trailing white space, or begins with U+FEFF (unquoted at the start of the file it would
    /// be read as a byte-order mark and lost; the fuzzer found that). Cells are written as given; neutralise them
    /// first.
    public static func encode(_ rows: [[String]]) -> String {
        var output = ""
        for row in rows {
            output += row.map(encodeField).joined(separator: ",")
            output += "\r\n"
        }
        return output
    }

    private static func encodeField(_ field: String) -> String {
        let scalars = field.unicodeScalars
        let needsQuotes =
            scalars.contains { $0 == "," || $0 == "\"" || $0 == "\r" || $0 == "\n" }
            || scalars.first.map { $0 == " " || $0 == "\t" || $0 == "\u{FEFF}" } == true
            || scalars.last.map { $0 == " " || $0 == "\t" } == true
        guard needsQuotes else { return field }
        // Scalar by scalar, not with a string search: a search by characters does not see the quote in a quote
        // followed by a combining mark, and an undoubled quote ends the cell for whatever reads the file next.
        var quoted = String.UnicodeScalarView()
        quoted.append("\"")
        for scalar in scalars {
            if scalar == "\"" { quoted.append("\"") }
            quoted.append(scalar)
        }
        quoted.append("\"")
        return String(quoted)
    }
}
