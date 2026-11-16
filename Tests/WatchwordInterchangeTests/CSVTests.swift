import Foundation
import Testing
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordInterchange

@Suite("CSV reader and writer (RFC 4180)")
struct CSVTests {
    private func rows(_ text: String) throws -> [[String]] {
        try CSVReader.parse(Array(text.utf8)).map(\.fields)
    }

    @Test("Quoted fields hold commas, quotes and line breaks")
    func quoting() throws {
        let text = "a,\"b,c\",\"d \"\"quoted\"\"\",\"line one\r\nline two\"\r\n\"\",x\r\n"
        #expect(try rows(text) == [["a", "b,c", "d \"quoted\"", "line one\r\nline two"], ["", "x"]])
    }

    @Test("LF and CRLF both end a record, with or without a final line break")
    func lineEndings() throws {
        #expect(try rows("a,b\nc,d\n") == [["a", "b"], ["c", "d"]])
        #expect(try rows("a,b\r\nc,d\r\n") == [["a", "b"], ["c", "d"]])
        #expect(try rows("a,b\r\nc,d") == [["a", "b"], ["c", "d"]])
        #expect(try rows("a,b\nc,d\r\n\r\n\n") == [["a", "b"], ["c", "d"]])
    }

    @Test("Records carry the line they start on")
    func lineNumbers() throws {
        let records = try CSVReader.parse(Array("h\n\"two\nlines\"\n\nlast\n".utf8))
        #expect(records.map(\.line) == [1, 2, 5])
        #expect(records.map(\.fields) == [["h"], ["two\nlines"], ["last"]])
    }

    @Test("Cells are data: nothing is trimmed, and empty cells are kept")
    func cellsAreData() throws {
        #expect(try rows(" a , b\t,,\n") == [[" a ", " b\t", "", ""]])
        #expect(try rows(",\n") == [["", ""]])
        #expect(try rows("=1+1,+2,-3,@x\n") == [["=1+1", "+2", "-3", "@x"]])
    }

    @Test("A UTF-8 byte-order mark is skipped, and text is read as UTF-8")
    func byteOrderMark() throws {
        let bytes = [0xEF, 0xBB, 0xBF] + Array("Título,Größe\npässwörd,日本語\n".utf8)
        #expect(try CSVReader.parse(bytes).map(\.fields) == [["Título", "Größe"], ["pässwörd", "日本語"]])
        #expect(try CSVReader.parse([0xEF, 0xBB, 0xBF]).isEmpty)
    }

    @Test("Records can be read one at a time, and reading stops where the caller stops it")
    func streaming() throws {
        struct Stop: Error {}
        var seen: [CSVRecord] = []
        try CSVReader.forEachRecord(Array("a,b\n\n\"c\nd\",e\nf,g".utf8)) { seen.append($0) }
        #expect(
            seen == [
                CSVRecord(line: 1, fields: ["a", "b"]), CSVRecord(line: 3, fields: ["c\nd", "e"]),
                CSVRecord(line: 5, fields: ["f", "g"]),
            ])
        #expect(try CSVReader.parse(Array("a,b\n\n\"c\nd\",e\nf,g".utf8)) == seen)
        var count = 0
        #expect(throws: Stop.self) {
            // The third record is malformed, and is never reached.
            try CSVReader.forEachRecord(Array("a\nb\nc\"d\n".utf8)) { _ in
                count += 1
                if count == 2 { throw Stop() }
            }
        }
        #expect(count == 2)
    }

    @Test("Columns, rows and cells stop at their limits, as they are read")
    func limits() throws {
        let wide = Array((Array(repeating: "a", count: 101).joined(separator: ",") + "\n").utf8)
        #expect(throws: InterchangeError.limitExceeded(.csvColumns, limit: 100)) { try CSVReader.parse(wide) }
        #expect(try CSVReader.parse(Array(wide.dropFirst(2))).first?.fields.count == 100)

        let tight = InterchangeLimits(maximumItems: 3, maximumTotalFields: 7)
        // Four rows and a header are one row too many.
        var rows = 0
        #expect(throws: InterchangeError.limitExceeded(.items, limit: 3)) {
            try CSVReader.forEachRecord(Array("h\n1\n2\n3\n4\n".utf8), limits: tight) { _ in rows += 1 }
        }
        #expect(rows == 4)
        // Read whole, the cells are counted as they are kept.
        #expect(try CSVReader.parse(Array("a,b\nc,d\ne,f\ng\n".utf8), limits: tight).count == 4)
        #expect(throws: InterchangeError.limitExceeded(.totalFields, limit: 7)) {
            try CSVReader.parse(Array("a,b\nc,d\ne,f\ng,h\n".utf8), limits: tight)
        }
    }

    @Test("An empty file has no records")
    func empty() throws {
        #expect(try rows("").isEmpty)
        #expect(try rows("\n\r\n").isEmpty)
    }

    @Test(
        "Malformed quoting is refused, with the line",
        arguments: [
            ("a\n\"never closed\nmore", InterchangeError.malformedCSV(.unterminatedQuote, line: 2)),
            ("a\"b\n", .malformedCSV(.quoteInUnquotedField, line: 1)),
            ("x\n\"a\"b\n", .malformedCSV(.textAfterClosingQuote, line: 2)),
            ("x\n\"a\" \"b\"\n", .malformedCSV(.textAfterClosingQuote, line: 2)),
            ("a\rb\n", .malformedCSV(.strayCarriageReturn, line: 1)),
            ("a\r", .malformedCSV(.strayCarriageReturn, line: 1)),
            ("ok\na\u{0}b\n", .malformedCSV(.nulCharacter, line: 2)),
        ])
    func malformed(_ text: String, _ expected: InterchangeError) {
        #expect(throws: expected) { try CSVReader.parse(Array(text.utf8)) }
    }

    @Test("The writer quotes only what needs it and ends records with CRLF")
    func writer() {
        let rows = [["plain", "with,comma", "with \"quote\"", "two\nlines", " padded ", ""], ["x"]]
        #expect(
            CSVWriter.encode(rows)
                == "plain,\"with,comma\",\"with \"\"quote\"\"\",\"two\nlines\",\" padded \",\r\nx\r\n")
    }

    /// Found by the `csv` fuzz target: a first cell beginning with U+FEFF was written bare, and read back as a
    /// byte-order mark, which is to say not at all.
    @Test("A first cell that begins with U+FEFF survives a round trip")
    func leadingByteOrderMarkCell() throws {
        let rows = [["\u{FEFF}", "A0c,", " `"], ["\u{FEFF}x"]]
        let encoded = CSVWriter.encode(rows)
        #expect(encoded.hasPrefix("\"\u{FEFF}\","))
        #expect(try self.rows(encoded) == rows)
    }

    /// A quote followed by a combining mark is one character that is not a quote, so a search by characters leaves
    /// it undoubled, and the cell then ends early for a reader that works on bytes, as spreadsheets do.
    @Test("A quote is doubled even when a combining mark follows it")
    func quoteBeforeCombiningMark() throws {
        let cell = "x\"\u{301},=cmd|' /C calc'!A0"
        let encoded = CSVWriter.encode([[cell, "y"]])
        #expect(Array(encoded.utf8) == Array("\"x\"\"\u{301},=cmd|' /C calc'!A0\",y\r\n".utf8))
        #expect(try rows(encoded) == [[cell, "y"]])
    }

    @Test("Whatever the writer writes, the reader reads back")
    func roundTrip() throws {
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 0xC5F))
        // Scalars, joined freely, so that combining marks land after quotes, commas and line breaks.
        let alphabet = "ab,\"\r\n '=+-@\t;é日\u{FEFF}\u{301}".unicodeScalars.map { String($0) }
        for _ in 0..<TestEnvironment.iterations(standard: 200, long: 20_000) {
            let rows = (0..<Int.random(in: 1...4, using: &generator)).map { _ in
                (0..<Int.random(in: 1...4, using: &generator)).map { _ in
                    (0..<Int.random(in: 0...6, using: &generator)).map { _ in
                        alphabet.randomElement(using: &generator)!
                    }.joined()
                }
            }
            // A record of one empty cell is a blank line, which the reader skips by design.
            let expected = rows.filter { $0 != [""] }
            let parsed = try CSVReader.parse(Array(CSVWriter.encode(rows).utf8)).map(\.fields)
            // Scalar for scalar: string equality would forgive a difference in normalisation.
            #expect(
                parsed.map { $0.map { Array($0.unicodeScalars) } }
                    == expected.map { $0.map { Array($0.unicodeScalars) } })
        }
    }

    /// Owner decision, 2026-11-16: the CSV is for another password manager's importer, never a spreadsheet, so
    /// exported values are exact. A cell that begins with a formula character, a tab or a carriage return is written
    /// as it is, with RFC 4180 quoting only, and reads back byte for byte.
    @Test(
        "Formula-like cells are written exactly, with RFC 4180 quoting only",
        arguments: zip(
            ["=cmd|' /C calc'!A0", "+1", "-1", "@x", "\tcmd", "\rcmd", "'already", "a=b"],
            ["=cmd|' /C calc'!A0", "+1", "-1", "@x", "\"\tcmd\"", "\"\rcmd\"", "'already", "a=b"]))
    func formulaCellsAreExact(_ cell: String, _ written: String) throws {
        let encoded = CSVWriter.encode([[cell, "y"]])
        #expect(Array(encoded.utf8) == Array("\(written),y\r\n".utf8))
        let parsed = try CSVReader.parse(Array(encoded.utf8)).map { $0.fields.map { Array($0.utf8) } }
        #expect(parsed == [[Array(cell.utf8), Array("y".utf8)]])
    }
}

@Suite("Password CSV import and export")
struct PasswordCSVTests {
    private func importCSV(_ text: String, options: ImportOptions = ImportOptions()) throws -> ImportResult {
        var generator = SeededGenerator(seed: 2)
        return try PasswordCSV.importFile(Array(text.utf8), into: Fixtures.vaultID, options: options, using: &generator)
    }

    @Test("Detects the exporter from the header row")
    func detection() throws {
        #expect(try PasswordCSV.detectFormat(header: PasswordCSV.applePasswordsHeader) == .applePasswordsCSV)
        #expect(
            try PasswordCSV.detectFormat(
                header: ["Title", "Url", "Username", "Password", "OTPAuth", "Favorite", "Archived", "Tags", "Notes"])
                == .onePassword8CSV)
        #expect(try PasswordCSV.detectFormat(header: ["Title", "URL", "Username", "Password"]) == .onePassword7CSV)
        #expect(try PasswordCSV.detectFormat(header: ["title", "website", "USERNAME", "password"]) == .onePassword7CSV)
        #expect(throws: InterchangeError.unrecognisedCSVHeader) {
            try PasswordCSV.detectFormat(header: ["wendy", "hunter2", "https://example.com"])
        }
        #expect(throws: InterchangeError.unrecognisedCSVHeader) {
            try PasswordCSV.detectFormat(header: ["Password", "Colour"])
        }
        #expect(throws: InterchangeError.malformedCSV(.duplicateColumn, line: 1)) {
            try PasswordCSV.detectFormat(header: ["Title", "Password", "password"])
        }
        #expect(throws: InterchangeError.malformedCSV(.duplicateColumn, line: 1)) {
            try PasswordCSV.detectFormat(header: ["Title", "Url", "Website", "Password"])
        }
    }

    @Test("Imports Apple Passwords CSV")
    func applePasswords() throws {
        let result = try importCSV(Fixtures.applePasswordsCSV)
        #expect(result.report.format == .applePasswordsCSV)
        #expect(result.report.countsByKind == [.login: 3])
        #expect(result.report.skipped.isEmpty)

        let example = try result.entry(titled: "Example").item
        #expect(example.scopes == [ServiceScope(host: "example.com")])
        #expect(example.values(.username) == ["wendy"])
        #expect(example.values(.password) == ["p,ass\"word"])
        #expect(example.notes == "two\nlines")
        #expect(try example.field(.totp)?.otpParameters().issuer == "Example")
        #expect(result.entries.first?.reference.line == 2)

        // A formula-shaped password is a password: imported exactly, never evaluated or altered.
        let router = try result.entry(titled: "Router").item
        #expect(router.values(.password) == ["=cmd|' /C calc'!A0"])
        #expect(router.scopes == [ServiceScope(host: "192.168.1.1", includeSubdomains: false)])
        #expect(result.entries[1].reference.line == 4)

        let www = try result.entry(titled: "Example (www)").item
        #expect(www.scopes.map(\.host) == ["www.example.com", "example.com"])
        #expect(www.values(.password) == ["-leading-dash"])
        #expect(
            result.report.warnings.map(\.warning) == [.apexScopeAdded(wwwHost: "www.example.com", apex: "example.com")])
        #expect(result.report.warnings.first?.entry.title == "Example (www)")
    }

    @Test("Imports 1Password 8 CSV: favourites, archive, tags and bare one-time-password secrets")
    func onePassword8() throws {
        let result = try importCSV(Fixtures.onePassword8CSV)
        #expect(result.report.format == .onePassword8CSV)
        #expect(result.report.countsByKind == [.login: 2, .password: 1])

        let example = try result.entry(titled: "Example")
        #expect(example.item.scopes.map(\.host) == ["example.com"])
        #expect(example.item.tags == ["work", "family", "Favorite"])
        #expect(example.item.notes == "First note")
        #expect(try example.item.field(.totp)?.otpParameters().secret == Data("12345678901234567890".utf8))

        let old = try result.entry(titled: "Old thing")
        #expect(old.state == .archived)
        #expect(old.item.archived)
        #expect(old.item.tags.isEmpty)

        let password = try result.entry(titled: "Just a password")
        #expect(password.kind == .password)
        #expect(password.item.fields.map(\.kind) == [.password])
    }

    @Test("Imports 1Password 7 CSV, keeping unknown columns as custom fields")
    func onePassword7() throws {
        let result = try importCSV(Fixtures.onePassword7CSV)
        #expect(result.report.format == .onePassword7CSV)
        let item = try result.entry(titled: "Example").item
        #expect(item.scopes.map(\.host) == ["example.com"])
        #expect(item.notes == "note")
        let custom = item.fields.filter { $0.kind == .custom }
        #expect(custom.map(\.label) == ["Type", "Security answer"])
        #expect(custom.map(\.value) == ["Login", "Fluffy"])
    }

    @Test("The favourite tag is the caller's choice")
    func favoriteTag() throws {
        let result = try importCSV(Fixtures.onePassword8CSV, options: ImportOptions(favoriteTag: nil))
        #expect(try result.entry(titled: "Example").item.tags == ["work", "family"])
    }

    @Test("Rows that do not fit the header, and empty rows, are skipped and listed")
    func skippedRows() throws {
        let csv =
            "Title,URL,Username,Password\nShort,https://a.example\nLong,https://b.example,u,p,extra\n,,,\nGood,https://c.example,u,p\n"
        let result = try importCSV(csv)
        #expect(result.entries.map(\.item.title) == ["Good"])
        #expect(
            result.report.skipped.map(\.reason) == [
                .columnCountMismatch(expected: 4, found: 2), .columnCountMismatch(expected: 4, found: 5), .empty,
            ])
        #expect(result.report.skipped.map(\.entry.line) == [2, 3, 4])
        #expect(result.report.skipped.map(\.entry.title) == ["Short", "Long", ""])
    }

    @Test("A file with no header, or nothing at all, is refused")
    func noHeader() {
        #expect(throws: InterchangeError.malformedCSV(.empty, line: 1)) { try importCSV("") }
        #expect(throws: InterchangeError.unrecognisedCSVHeader) {
            try importCSV("Example,https://example.com,wendy,hunter2\n")
        }
    }

    @Test("A title is derived, and said to be, when the file has none")
    func derivedTitle() throws {
        let result = try importCSV("Title,URL,Username,Password\n,https://example.com,wendy,p\n,,wendy,p\n")
        #expect(result.entries.map(\.item.title) == ["example.com", "wendy"])
        #expect(result.report.warnings.map(\.warning) == [.titleDerived, .titleDerived])
    }

    @Test("Exports Apple Passwords CSV that reads back")
    func exportRoundTrip() throws {
        // Without the apex scope a www host gains on import: an item with two scopes is two Apple Passwords entries,
        // one per website, and would read back as two items.
        let exact = ImportOptions(matchApexOfWWWHosts: false)
        let imported = try importCSV(Fixtures.applePasswordsCSV, options: exact)
        let exported = PasswordCSV.exportApplePasswords(imported.entries.map(\.item))
        #expect(exported.report.exportedCount == 3)
        #expect(exported.report.warnings.isEmpty)
        let text = String(decoding: exported.bytes, as: UTF8.self)
        #expect(text.hasPrefix("Title,URL,Username,Password,Notes,OTPAuth\r\n"))
        let again = try importCSV(text, options: exact)
        #expect(again.entries.map { ItemShape($0.item) } == imported.entries.map { ItemShape($0.item) })
    }

    @Test("Export moves what has no column into the notes, leaves passkeys out, and says so")
    func exportReport() throws {
        let passkey = try PasskeyCredential(
            credentialID: Data(repeating: 1, count: 32), relyingPartyID: "example.com",
            userHandle: Data(repeating: 2, count: 16), userName: "wendy",
            privateKeyPKCS8: Data(repeating: 3, count: 64),
            createdAt: Date(timeIntervalSince1970: 1_700_000_000))
        let item = Item(
            vaultID: Fixtures.vaultID, title: "Bank",
            scopes: [ServiceScope(host: "bank.example"), ServiceScope(host: "cards.bank.example")],
            fields: [
                Field(kind: .username, label: "Username", value: "wendy"),
                Field(kind: .password, label: "Password", value: "-starts-with-dash"),
                Field(kind: .securityQuestion, label: "First pet?", value: "Fluffy"),
                Field(kind: .pin, label: "PIN", value: "0420"),
                try Field.passkey(passkey),
            ], notes: "=HYPERLINK(\"http://evil.example\")")
        let trashed = Item(
            vaultID: Fixtures.vaultID, title: "Gone", scopes: [], fields: [],
            trashedAt: Date(timeIntervalSince1970: 1))
        let exported = PasswordCSV.exportApplePasswords([item, trashed])
        let rows = try CSVReader.parse(exported.bytes).map(\.fields)
        #expect(rows.count == 3)
        #expect(rows[1][0...3] == ["Bank", "https://bank.example/", "wendy", "-starts-with-dash"])
        #expect(rows[2][1] == "https://cards.bank.example/")
        #expect(rows[1][4] == "=HYPERLINK(\"http://evil.example\")\nFirst pet?: Fluffy\nPIN: 0420")
        #expect(!String(decoding: exported.bytes, as: UTF8.self).contains("privateKey"))
        #expect(exported.report.exportedCount == 1)
        #expect(
            Set(exported.report.warnings) == [
                .passkeyOmitted(itemID: item.id), .fieldsMovedToNotes(itemID: item.id, count: 2),
                .trashedItemOmitted(itemID: trashed.id),
            ])
        // The file reads back as exactly the values stored, and an import takes a cell exactly as written.
        var generator = SeededGenerator(seed: 3)
        let again = try PasswordCSV.importFile(exported.bytes, into: Fixtures.vaultID, using: &generator)
        #expect(again.entries.first?.item.values(.password) == ["-starts-with-dash"])
        #expect(again.entries.first?.item.notes.hasPrefix("=HYPERLINK(") == true)
        #expect(again.report.warnings.isEmpty)
    }
}
