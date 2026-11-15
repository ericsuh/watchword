import Foundation
import Testing
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordInterchange

@Suite("1PUX import and export")
struct OnePUXTests {
    private func importFixture(options: ImportOptions = ImportOptions()) throws -> ImportResult {
        var generator = SeededGenerator(seed: 1)
        return try OnePUX.importDocument(
            Fixtures.onePUXBytes, into: Fixtures.vaultID, options: options, using: &generator)
    }

    private var exportOptions: OnePUX.ExportOptions {
        OnePUX.ExportOptions(
            accountID: UUID(uuidString: "AAAAAAAA-0000-4000-8000-000000000001")!,
            vaultID: UUID(uuidString: "AAAAAAAA-0000-4000-8000-000000000002")!,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000))
    }

    @Test("Imports every category and reports what it did")
    func importsFixture() throws {
        let result = try importFixture()
        #expect(result.report.format == .onePUX)
        #expect(
            result.report.countsByKind == [
                .login: 1, .password: 1, .secureNote: 1, .apiCredential: 1, .bankAccount: 1, .membership: 1,
                .other: 1,
            ])
        #expect(result.report.importedCount == 7)
        #expect(result.report.skipped.map(\.reason) == [.trashedAtSource])
        #expect(result.report.skipped.first?.entry.title == "Closed account")
        #expect(result.entries.allSatisfy { $0.item.vaultID == Fixtures.vaultID })
        #expect(result.entries.allSatisfy { $0.reference.container == "Personal" })
        #expect(Set(result.entries.map(\.item.id)).count == 7)
        // Identifiers come from the injected generator, never from the file.
        var generator = SeededGenerator(seed: 1)
        let again = try OnePUX.importDocument(Fixtures.onePUXBytes, into: Fixtures.vaultID, using: &generator)
        #expect(again == result)
    }

    @Test("A Login keeps its fields, sections, history, tags and dates")
    func login() throws {
        let result = try importFixture()
        let entry = try result.entry(titled: "Example")
        let item = entry.item
        #expect(entry.kind == .login)
        #expect(entry.state == .active)
        #expect(entry.reference.sourceID == "fkruyzrldvizuqlnavfj3gltfe")
        #expect(item.scopes.map(\.host) == ["www.example.com", "accounts.example.co.uk"])
        #expect(item.scopes.allSatisfy { $0.includeSubdomains })
        #expect(item.values(.username) == ["wendy@example.com"])
        #expect(item.values(.password) == ["correct horse battery staple"])
        #expect(item.notes == "Line one\nLine two")
        #expect(item.tags == ["work", "shared/finance", "Favorite"])
        #expect(item.createdAt == Date(timeIntervalSince1970: 1_614_298_956))
        #expect(item.modifiedAt == Date(timeIntervalSince1970: 1_635_346_445))
        #expect(!item.archived)

        // The public suffix is kept as a URL, not as a scope (F11.2).
        let website = try #require(item.field(labelled: "Website"))
        #expect(website.kind == .url)
        #expect(website.value == "https://github.io")
        #expect(
            result.warnings(for: "Example") == [
                .scopeRefused(url: "https://github.io", reason: .policy(.publicSuffix("github.io")))
            ])

        // A saved web-form text field is kept; a checkbox is page state and is not.
        #expect(item.field(labelled: "locale")?.value == "EN-GB")
        #expect(item.field(labelled: "remember") == nil)

        let pin = try #require(item.field(labelled: "PIN"))
        #expect(pin.kind == .custom)
        #expect(pin.value == "12345")
        #expect(pin.meta[InterchangeMeta.section] == "Security")
        #expect(pin.meta[InterchangeMeta.sourceID] == "CCEF647B399604E8F6Q6C8C3W31AFD407")
        #expect(pin.meta[InterchangeMeta.sourceType] == "concealed")

        let code = try #require(item.field(.totp))
        let parameters = try code.otpParameters()
        #expect(Base32.encode(parameters.secret) == Fixtures.totpSecret)
        #expect(parameters.issuer == "Example")
        #expect(parameters.account == "wendy")

        #expect(item.values(.email) == ["backup@example.org"])
        #expect(item.values(.date) == ["2020-02-16"])
        #expect(item.field(labelled: "empty") == nil)

        #expect(item.history.map { $0.fields.map(\.value) } == [["old password"], ["older password"]])
        #expect(item.history.map(\.replacedAt.timeIntervalSince1970) == [1_558_322_355, 1_458_322_355])
        #expect(item.history.allSatisfy { $0.fields.allSatisfy { $0.kind == .password } })
    }

    @Test("Password, Secure Note, API Credential, Bank Account and Membership keep their shape")
    func categories() throws {
        let result = try importFixture()

        let password = try result.entry(titled: "Garage door")
        #expect(password.kind == .password)
        #expect(password.item.fields.map(\.kind) == [.password])
        #expect(password.item.values(.password) == ["hunter2hunter2"])

        let note = try result.entry(titled: "Safe")
        #expect(note.kind == .secureNote)
        #expect(note.item.fields.isEmpty)
        #expect(note.item.notes == "The safe is behind the painting.")

        let api = try result.entry(titled: "Deploy token")
        #expect(api.kind == .apiCredential)
        #expect(api.item.values(.username) == ["deploy-bot"])
        #expect(api.item.values(.apiKey) == ["sk_live_abc123"])
        #expect(api.item.values(.date) == ["2030-01-01"])
        #expect(api.item.values(.text) == ["bearer", "api.example.com"])

        let bank = try result.entry(titled: "Savings")
        #expect(bank.kind == .bankAccount)
        #expect(bank.item.values(.accountNumber) == ["021000021", "9876543210", "GB33BUKB20201555555555"])
        #expect(bank.item.values(.pin) == ["4321"])
        #expect(bank.item.values(.phoneNumber) == ["+44 20 7946 0000"])
        #expect(bank.item.field(labelled: "phone")?.meta[InterchangeMeta.section] == "Branch Information")
        #expect(bank.item.notes == "Joint account")

        let membership = try result.entry(titled: "Library card")
        #expect(membership.kind == .membership)
        #expect(membership.state == .archived)
        #expect(membership.item.archived)
        #expect(membership.item.values(.accountNumber) == ["L-000123"])
        #expect(membership.item.values(.pin) == ["0420"])
        #expect(membership.item.values(.date) == ["2030-12"])
        // A URL inside a section is a field. Only the entry's own URLs become scopes.
        #expect(membership.item.values(.url) == ["https://library.example.org/account"])
        #expect(membership.item.scopes.isEmpty)
    }

    @Test("Other categories become custom-field items, and what cannot be carried is reported")
    func otherCategory() throws {
        let result = try importFixture()
        let card = try result.entry(titled: "Visa")
        #expect(card.kind == .other)
        let number = try #require(card.item.field(labelled: "number"))
        #expect(number.kind == .custom)
        #expect(number.kind.isSecret)
        #expect(number.meta[InterchangeMeta.sourceType] == "creditCardNumber")
        #expect(card.item.field(labelled: "verification number")?.kind == .custom)
        #expect(card.item.field(labelled: "billing address")?.value == "1 Infinite Loop\nCupertino\nCA\n95014\nus")
        #expect(card.item.values(.date) == ["2029-12"])
        // An unknown value type is kept, concealed.
        #expect(card.item.field(labelled: "hologram")?.kind == .custom)
        #expect(card.item.field(labelled: "hologram")?.value == "sparkly")
        #expect(
            result.warnings(for: "Visa") == [
                .attachmentNotImported(name: "statement.pdf"),
                .linkedItemNotImported(label: "linked login"),
                .unsupportedFieldType(label: "hologram", type: "futureType"),
            ])
    }

    @Test("Trashed entries are imported only on request, and marked")
    func trashed() throws {
        let result = try importFixture(options: ImportOptions(includesTrashed: true))
        let entry = try result.entry(titled: "Closed account")
        #expect(entry.state == .trashed)
        #expect(entry.item.trashedAt == nil)
        #expect(result.report.skipped.isEmpty)
        #expect(result.report.countsByKind[.login] == 2)
    }

    @Test("Reads the archive, and only its export.data member")
    func archive() throws {
        var generator = SeededGenerator(seed: 1)
        let result = try OnePUX.importArchive(Fixtures.onePUXArchive(), into: Fixtures.vaultID, using: &generator)
        let expected = try importFixture()
        #expect(result == expected)
    }

    /// `zipfile.ZipFile(..., "w", zipfile.ZIP_DEFLATED)` in Python 3 over `export.attributes`, `export.data` (a
    /// one-item document) and a `files/` directory: an archive from a writer that is not ours.
    @Test("Reads an archive written by Python's zipfile")
    func pythonArchive() throws {
        let archive = Array(Data(base64Encoded: PythonArchives.deflated)!)
        var generator = SeededGenerator(seed: 1)
        let result = try OnePUX.importArchive(archive, into: Fixtures.vaultID, using: &generator)
        #expect(result.entries.map(\.item.title) == ["Python fixture"])
        #expect(result.entries.first?.item.values(.password) == ["zipfile-made"])
        #expect(result.entries.first?.item.scopes.map(\.host) == ["python.example.org"])
    }

    /// The same archive written to an unseekable stream, so every member has a data descriptor and a local header
    /// with zeroed sizes.
    @Test("Reads an archive with data descriptors")
    func streamedArchive() throws {
        let archive = Array(Data(base64Encoded: PythonArchives.streamed)!)
        var generator = SeededGenerator(seed: 1)
        let result = try OnePUX.importArchive(archive, into: Fixtures.vaultID, using: &generator)
        #expect(result.entries.map(\.item.title) == ["Python fixture"])
    }

    /// A member opened with `force_zip64=True`: ZIP64 is refused by name, not misread.
    @Test("Refuses a ZIP64 archive written by Python's zipfile")
    func zip64Archive() {
        let archive = Array(Data(base64Encoded: PythonArchives.zip64)!)
        var generator = SeededGenerator(seed: 1)
        #expect(throws: InterchangeError.unsupportedArchive(.zip64)) {
            try OnePUX.importArchive(archive, into: Fixtures.vaultID, using: &generator)
        }
    }

    @Test("An export reads back as the same items")
    func roundTrip() throws {
        let first = try importFixture()
        let exported = try OnePUX.exportArchive(first.entries.map(\.item), options: exportOptions)
        #expect(exported.report.exportedCount == 7)
        #expect(exported.report.warnings.isEmpty)
        var generator = SeededGenerator(seed: 99)
        let second = try OnePUX.importArchive(exported.bytes, into: Fixtures.vaultID, using: &generator)
        #expect(second.report.skipped.isEmpty)
        #expect(second.entries.count == 7)
        // The credit card's address, attachment and unknown type have no 1PUX form to return to; everything else
        // must survive exactly.
        for entry in first.entries where entry.item.title != "Visa" {
            let other = try second.entry(titled: entry.item.title)
            #expect(ItemShape(other.item) == ItemShape(entry.item), "\(entry.item.title)")
            #expect(other.kind == entry.kind, "\(entry.item.title)")
            #expect(other.state == entry.state, "\(entry.item.title)")
        }
        let card = try second.entry(titled: "Visa")
        let original = try first.entry(titled: "Visa")
        #expect(card.item.fields.map(\.value) == original.item.fields.map(\.value))
        #expect(card.item.fields.map(\.kind.isSecret) == original.item.fields.map(\.kind.isSecret))

        // And a second export of the re-imported items is byte-for-byte stable in what it says.
        let third = OnePUX.exportDocument(second.entries.map(\.item), options: exportOptions)
        var again = SeededGenerator(seed: 7)
        let reread = try OnePUX.importDocument(third.document, into: Fixtures.vaultID, using: &again)
        #expect(reread.entries.map { ItemShape($0.item) } == second.entries.map { ItemShape($0.item) })
    }

    @Test("The exported archive has the two members 1Password expects, stored")
    func exportedArchiveLayout() throws {
        let items = try importFixture().entries.map(\.item)
        let exported = try OnePUX.exportArchive(items, options: exportOptions)
        let archive = try ZIPArchive(exported.bytes)
        #expect(archive.entries.map(\.name) == ["export.attributes", "export.data"])
        let attributes = String(decoding: try archive.contents(of: "export.attributes"), as: UTF8.self)
        #expect(
            attributes == #"{"version":3,"description":"1Password Unencrypted Export","createdAt":1700000000}"#)
        // Deterministic: the same items and options give the same bytes.
        #expect(try OnePUX.exportArchive(items, options: exportOptions).bytes == exported.bytes)
    }

    @Test("Items made in Watchword export under the category their fields imply")
    func exportCategories() throws {
        func item(_ title: String, scopes: [String] = [], _ fields: [(FieldKind, String)], notes: String = "") -> Item {
            Item(
                vaultID: Fixtures.vaultID, title: title, scopes: scopes.map { ServiceScope(host: $0) },
                fields: fields.map { Field(kind: $0.0, label: $0.0.rawValue, value: $0.1) }, notes: notes)
        }
        #expect(
            OnePUX.category(for: item("login", scopes: ["example.com"], [(.username, "u"), (.password, "p")])) == "001")
        #expect(OnePUX.category(for: item("password", [(.password, "p")])) == "005")
        #expect(OnePUX.category(for: item("note", [], notes: "text")) == "003")
        #expect(OnePUX.category(for: item("token", [(.apiKey, "k"), (.username, "bot")])) == "112")
        #expect(OnePUX.category(for: item("card", [(.accountNumber, "L-1"), (.pin, "1")])) == "105")
        #expect(OnePUX.category(for: item("unscoped login", [(.username, "u"), (.password, "p")])) == "001")
    }

    @Test("What 1PUX cannot hold is left out and reported")
    func exportReport() throws {
        let passkey = try PasskeyCredential(
            credentialID: Data(repeating: 1, count: 32), relyingPartyID: "example.com",
            userHandle: Data(repeating: 2, count: 16), userName: "wendy",
            privateKeyPKCS8: Data(repeating: 3, count: 64),
            createdAt: Date(timeIntervalSince1970: 1_700_000_000))
        let withPasskey = Item(
            vaultID: Fixtures.vaultID, title: "Passkey", scopes: [ServiceScope(host: "example.com")],
            fields: [try Field.passkey(passkey), Field(kind: .totp, label: "Code", value: "not a uri")])
        let trashed = Item(
            vaultID: Fixtures.vaultID, title: "Gone", scopes: [], fields: [],
            trashedAt: Date(timeIntervalSince1970: 1_700_000_000))
        let exported = OnePUX.exportDocument([withPasskey, trashed], options: exportOptions)
        #expect(exported.report.exportedCount == 1)
        #expect(
            exported.report.warnings == [
                .passkeyOmitted(itemID: withPasskey.id), .oneTimePasswordUnusable(itemID: withPasskey.id),
                .trashedItemOmitted(itemID: trashed.id),
            ])
        let text = String(decoding: exported.document, as: UTF8.self)
        #expect(!text.contains("credentialID"))
        #expect(text.contains(#"{"concealed":"not a uri"}"#))
    }

    @Test("A document that is not shaped like 1PUX is refused, by name")
    func structure() {
        func error(_ json: String) -> InterchangeError? {
            var generator = SeededGenerator(seed: 1)
            do {
                _ = try OnePUX.importDocument(Array(json.utf8), into: Fixtures.vaultID, using: &generator)
                return nil
            } catch {
                return error as? InterchangeError
            }
        }
        #expect(error("[]") == .unexpectedStructure(path: "$"))
        #expect(error("{}") == .unexpectedStructure(path: "accounts"))
        #expect(error(#"{"accounts": {}}"#) == .unexpectedStructure(path: "accounts"))
        #expect(error(#"{"accounts": [7]}"#) == .unexpectedStructure(path: "accounts[]"))
        #expect(error(#"{"accounts": [{"vaults": [[]]}]}"#) == .unexpectedStructure(path: "accounts[].vaults[]"))
        #expect(
            error(#"{"accounts": [{"vaults": [{"items": 3}]}]}"#)
                == .unexpectedStructure(path: "accounts[].vaults[].items"))
        #expect(error(#"{"accounts": []} x"#) == .malformedJSON(.trailingData, byteOffset: 17))
        #expect(error(#"{"accounts": [], "accounts": []}"#) == .malformedJSON(.duplicateKey, byteOffset: 17))
    }

    @Test("Entries that are not items, repeat an identifier or hold nothing are skipped and listed")
    func skippedEntries() throws {
        let json = #"""
            {"accounts": [{"vaults": [{"items": [
              "not an item",
              {"uuid": "a", "categoryUuid": "003", "overview": {"title": "First"}, "details": {"notesPlain": "one"}},
              {"uuid": "a", "categoryUuid": "003", "overview": {"title": "Second"}, "details": {"notesPlain": "two"}},
              {"uuid": "b", "categoryUuid": "001", "overview": {"title": ""}, "details": {}},
              {"uuid": "c", "categoryUuid": "006", "overview": {"title": ""}, "details": {"documentAttributes": {"fileName": "will.pdf"}}}
            ], "attrs": {"name": "Named afterwards"}}]}]}
            """#
        var generator = SeededGenerator(seed: 1)
        let result = try OnePUX.importDocument(Array(json.utf8), into: Fixtures.vaultID, using: &generator)
        #expect(result.entries.map(\.item.title) == ["First"])
        #expect(result.entries.first?.reference.container == "Named afterwards")
        #expect(
            result.report.skipped.map(\.reason) == [
                .malformed(path: "items[]"), .duplicateIdentifier("a"), .empty, .nothingImportable,
            ])
        #expect(result.report.skipped.map(\.entry.index) == [1, 3, 4, 5])
        #expect(result.report.skipped.allSatisfy { $0.entry.container == "Named afterwards" })
    }

    @Test("Unknown states and impossible dates are reported, not guessed at")
    func oddValues() throws {
        let json = #"""
            {"accounts": [{"vaults": [{"items": [
              {"uuid": "a", "state": "quarantined", "createdAt": -5, "updatedAt": 99999999999999,
               "categoryUuid": "001", "overview": {"title": "Odd"},
               "details": {"sections": [{"title": "", "fields": [
                 {"title": "when", "id": "x", "value": {"date": 99999999999999}},
                 {"title": "month", "id": "y", "value": {"monthYear": 202613}},
                 {"title": "code", "id": "z", "value": {"totp": "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=1"}},
                 {"title": "bare", "id": "w", "value": {"totp": "GEZD GNBV GY3T QOJQ"}}
               ]}]}}
            ]}]}]}
            """#
        var generator = SeededGenerator(seed: 1)
        let result = try OnePUX.importDocument(Array(json.utf8), into: Fixtures.vaultID, using: &generator)
        let entry = try result.entry(titled: "Odd")
        #expect(entry.state == .active)
        #expect(entry.item.createdAt == Date(timeIntervalSince1970: 0))
        #expect(
            result.warnings(for: "Odd") == [
                .unknownState("quarantined"), .implausibleDate(label: "createdAt"),
                .implausibleDate(label: "updatedAt"), .implausibleDate(label: "when"),
                .implausibleDate(label: "month"),
                .unusableOneTimePassword(label: "code", reason: .unsupportedType("hotp")),
            ])
        // The unusable value is kept, concealed, and is not a working code field.
        let kept = try #require(entry.item.field(labelled: "code"))
        #expect(kept.kind == .custom)
        #expect(kept.value == "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=1")
        // A bare Base32 secret becomes a canonical URI with the default parameters.
        let bare = try #require(entry.item.field(labelled: "bare"))
        #expect(bare.kind == .totp)
        #expect(bare.value == "otpauth://totp/?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&period=30")
    }
}

/// Archives written by Python 3's `zipfile` over a one-item 1PUX document:
///
/// ```python
/// DATA = json.dumps({"accounts": [{"attrs": {"name": "Py"}, "vaults": [{"attrs": {"name": "V"}, "items": [{
///     "uuid": "pyfixture", "categoryUuid": "001", "state": "active",
///     "overview": {"title": "Python fixture", "url": "https://python.example.org/"},
///     "details": {"loginFields": [
///         {"value": "py", "designation": "username", "fieldType": "T", "name": "u", "id": ""},
///         {"value": "zipfile-made", "designation": "password", "fieldType": "P", "name": "p", "id": ""}]}}]}]}]})
/// ```
///
/// `deflated` is `ZipFile(buffer, "w", ZIP_DEFLATED)` with `export.attributes`, `export.data` and a `files/`
/// directory; `streamed` is the same written to an object without `seek`, so `zipfile` emits data descriptors.
enum PythonArchives {
    static let deflated =
        "UEsDBBQAAAAIAIMYIlhwZJ5vSwAAAFYAAAARAAAAZXhwb3J0LmF0dHJpYnV0ZXOrVipLLSrOzM9TslIw1lFQSkktTi7KLCiBiCgZ"
        + "BiQWF5fnF6UohOal5iUXVRaUpKYouFYU5BeVKAGVJxelJgJFHEuAig3NDaCgFgBQSwMEFAAAAAgAgxgiWG3zqo3kAAAAvAEAAAsA"
        + "AABleHBvcnQuZGF0YXVPMW7DMAz8iqG5jdM1D+icIe1SdCAs2iEgS4JEyXGN/L2i7AIGmkAayLvj8bgo6DqXLEd1ar4WBcxBykVZ"
        + "GLEU6jyr+0ujMiTzXPRZNcQ4bpKUSAvh555unAKqwnfAOLgwf2zk8fgmcOSCSw8dU65KlzFkwqkuYWKzReGrs83OMQUjxJXZx1Pb"
        + "+io44A1Gb/DgwtDWYBoZyKyRjRvIvhMavUXNYBKuWVXVRhosMDkrYIoY6pWF6mXqMvuqvgjyd3+SZj1KFu5Mf8j3ZPB1BI0P7D3E"
        + "OLmg/9mf9/Z+b/99L1/eL1BLAwQUAAAAAACDGCJYAAAAAAAAAAAAAAAABgAAAGZpbGVzL1BLAQIUAxQAAAAIAIMYIlhwZJ5vSwAA"
        + "AFYAAAARAAAAAAAAAAAAAACAAQAAAABleHBvcnQuYXR0cmlidXRlc1BLAQIUAxQAAAAIAIMYIlht86qN5AAAALwBAAALAAAAAAAA"
        + "AAAAAACAAXoAAABleHBvcnQuZGF0YVBLAQIUAxQAAAAAAIMYIlgAAAAAAAAAAAAAAAAGAAAAAAAAAAAAAACAAYcBAABmaWxlcy9Q"
        + "SwUGAAAAAAMAAwCsAAAAqwEAAAAA"
    static let streamed =
        "UEsDBBQACAAIAIMYIlgAAAAAAAAAAAAAAAARAAAAZXhwb3J0LmF0dHJpYnV0ZXOrVipLLSrOzM9TslIw1lFQSkktTi7KLCiBiCgZ"
        + "BiQWF5fnF6UohOal5iUXVRaUpKYouFYU5BeVKAGVJxelJgJFHEuAig3NDaCgFgBQSwcIcGSeb0sAAABWAAAAUEsDBBQACAAIAIMY"
        + "IlgAAAAAAAAAAAAAAAALAAAAZXhwb3J0LmRhdGF1TzFuwzAM/IqhuY3TNQ/onCHtUnQgLNohIEuCRMlxjfy9ouwCBppAGsi74/G4"
        + "KOg6lyxHdWq+FgXMQcpFWRixFOo8q/tLozIk81z0WTXEOG6SlEgL4eeebpwCqsJ3wDi4MH9s5PH4JnDkgksPHVOuSpcxZMKpLmFi"
        + "s0Xhq7PNzjEFI8SV2cdT2/oqOOANRm/w4MLQ1mAaGciskY0byL4TGr1FzWASrllV1UYaLDA5K2CKGOqVhepl6jL7qr4I8nd/kmY9"
        + "ShbuTH/I92TwdQSND+w9xDi5oP/Zn/f2fm//fS9f3i9QSwcIbfOqjeQAAAC8AQAAUEsDBBQACAAAAIMYIlgAAAAAAAAAAAAAAAAG"
        + "AAAAZmlsZXMvUEsHCAAAAAAAAAAAAAAAAFBLAQIUAxQACAAIAIMYIlhwZJ5vSwAAAFYAAAARAAAAAAAAAAAAAACAAQAAAABleHBv"
        + "cnQuYXR0cmlidXRlc1BLAQIUAxQACAAIAIMYIlht86qN5AAAALwBAAALAAAAAAAAAAAAAACAAYoAAABleHBvcnQuZGF0YVBLAQIU"
        + "AxQACAAAAIMYIlgAAAAAAAAAAAAAAAAGAAAAAAAAAAAAAACAAacBAABmaWxlcy9QSwUGAAAAAAMAAwCsAAAA2wEAAAAA"
    /// A single `export.data` member opened with `force_zip64=True`.
    static let zip64 =
        "UEsDBC0AAAAAAIMYIlht86qN//////////8LABQAZXhwb3J0LmRhdGEBABAAvAEAAAAAAAC8AQAAAAAAAHsiYWNjb3VudHMiOiBb"
        + "eyJhdHRycyI6IHsibmFtZSI6ICJQeSJ9LCAidmF1bHRzIjogW3siYXR0cnMiOiB7Im5hbWUiOiAiViJ9LCAiaXRlbXMiOiBbeyJ1"
        + "dWlkIjogInB5Zml4dHVyZSIsICJjYXRlZ29yeVV1aWQiOiAiMDAxIiwgInN0YXRlIjogImFjdGl2ZSIsICJvdmVydmlldyI6IHsi"
        + "dGl0bGUiOiAiUHl0aG9uIGZpeHR1cmUiLCAidXJsIjogImh0dHBzOi8vcHl0aG9uLmV4YW1wbGUub3JnLyJ9LCAiZGV0YWlscyI6"
        + "IHsibG9naW5GaWVsZHMiOiBbeyJ2YWx1ZSI6ICJweSIsICJkZXNpZ25hdGlvbiI6ICJ1c2VybmFtZSIsICJmaWVsZFR5cGUiOiAi"
        + "VCIsICJuYW1lIjogInUiLCAiaWQiOiAiIn0sIHsidmFsdWUiOiAiemlwZmlsZS1tYWRlIiwgImRlc2lnbmF0aW9uIjogInBhc3N3"
        + "b3JkIiwgImZpZWxkVHlwZSI6ICJQIiwgIm5hbWUiOiAicCIsICJpZCI6ICIifV19fV19XX1dfVBLAQItAy0AAAAAAIMYIlht86qN"
        + "vAEAALwBAAALAAAAAAAAAAAAAACAAQAAAABleHBvcnQuZGF0YVBLBQYAAAAAAQABADkAAAD5AQAAAAA="
}
