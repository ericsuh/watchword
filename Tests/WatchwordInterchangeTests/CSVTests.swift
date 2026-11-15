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

    @Test("Whatever the writer writes, the reader reads back")
    func roundTrip() throws {
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 0xC5F))
        let alphabet = Array("ab,\"\r\n '=+-@\t;é日\u{FEFF}")
        for _ in 0..<TestEnvironment.iterations(standard: 200, long: 20_000) {
            let rows = (0..<Int.random(in: 1...4, using: &generator)).map { _ in
                (0..<Int.random(in: 1...4, using: &generator)).map { _ in
                    String(
                        (0..<Int.random(in: 0...6, using: &generator)).map { _ in
                            alphabet.randomElement(using: &generator)!
                        })
                }
            }
            // A record of one empty cell is a blank line, which the reader skips by design.
            let expected = rows.filter { $0 != [""] }
            let parsed = try CSVReader.parse(Array(CSVWriter.encode(rows).utf8)).map(\.fields)
            #expect(parsed == expected)
        }
    }

    @Test(
        "Formula-like cells are made inert on export",
        arguments: zip(
            ["=1+1", "+1", "-1", "@SUM(A1)", "\tcmd", "\rcmd", "safe", "", "'already", "a=b"],
            ["'=1+1", "'+1", "'-1", "'@SUM(A1)", "'\tcmd", "'\rcmd", "safe", "", "'already", "a=b"]))
    func neutralisation(_ cell: String, _ expected: String) {
        #expect(CSVWriter.neutralised(cell) == expected)
        #expect(CSVWriter.neutralised(cell, policy: .preserve) == cell)
        #expect(CSVWriter.isFormulaLike(cell) == (cell != expected))
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
        #expect(www.scopes.map(\.host) == ["www.example.com"])
        #expect(www.values(.password) == ["-leading-dash"])
        #expect(result.report.warnings.isEmpty)
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
        let imported = try importCSV(Fixtures.applePasswordsCSV)
        let exported = PasswordCSV.exportApplePasswords(imported.entries.map(\.item), formulaPolicy: .preserve)
        #expect(exported.report.exportedCount == 3)
        #expect(exported.report.warnings.isEmpty)
        let text = String(decoding: exported.bytes, as: UTF8.self)
        #expect(text.hasPrefix("Title,URL,Username,Password,Notes,OTPAuth\r\n"))
        let again = try importCSV(text)
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
        #expect(rows[1][0...3] == ["Bank", "https://bank.example/", "wendy", "'-starts-with-dash"])
        #expect(rows[2][1] == "https://cards.bank.example/")
        #expect(rows[1][4] == "'=HYPERLINK(\"http://evil.example\")\nFirst pet?: Fluffy\nPIN: 0420")
        #expect(!String(decoding: exported.bytes, as: UTF8.self).contains("privateKey"))
        #expect(exported.report.exportedCount == 1)
        #expect(
            Set(exported.report.warnings) == [
                .passkeyOmitted(itemID: item.id), .fieldsMovedToNotes(itemID: item.id, count: 2),
                .cellNeutralised(itemID: item.id, column: "Password"),
                .cellNeutralised(itemID: item.id, column: "Notes"),
                .trashedItemOmitted(itemID: trashed.id),
            ])
        // Importing the neutralised file keeps the apostrophe, as data, and says what it probably is.
        var generator = SeededGenerator(seed: 3)
        let again = try PasswordCSV.importFile(exported.bytes, into: Fixtures.vaultID, using: &generator)
        #expect(again.entries.first?.item.values(.password) == ["'-starts-with-dash"])
        #expect(again.report.warnings.map(\.warning).contains(.possiblyNeutralisedFormula(column: "Password")))
    }
}
