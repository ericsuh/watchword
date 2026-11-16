import Foundation
import Testing
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordInterchange

@Suite("Credential Exchange Format import and export")
struct CredentialExchangeTests {
    private func importCXF(_ bytes: [UInt8] = Fixtures.cxfBytes, seed: UInt64 = 4) throws -> ImportResult {
        var generator = SeededGenerator(seed: seed)
        return try CredentialExchange.importDocument(bytes, into: Fixtures.vaultID, using: &generator)
    }

    private var exportOptions: CredentialExchange.ExportOptions {
        CredentialExchange.ExportOptions(
            exporterRelyingPartyID: "watchword.example",
            accountID: UUID(uuidString: "AAAAAAAA-0000-4000-8000-000000000001")!,
            timestamp: Date(timeIntervalSince1970: 1_700_000_000))
    }

    @Test("Imports each credential type it knows")
    func importsFixture() throws {
        let result = try importCXF()
        #expect(result.report.format == .credentialExchange)
        #expect(result.report.countsByKind == [.login: 1, .apiCredential: 1, .other: 1, .secureNote: 1])
        #expect(result.report.skipped.isEmpty)
        #expect(result.entries.allSatisfy { $0.reference.container == "wendy" })

        let entry = try result.entry(titled: "Example")
        let item = entry.item
        #expect(entry.reference.sourceID == "aXRlbS0x")
        #expect(item.scopes == [ServiceScope(host: "example.com")])
        #expect(item.values(.username) == ["wendy"])
        #expect(item.values(.password) == ["correct horse battery staple"])
        #expect(item.tags == ["work", "Favorite"])
        #expect(item.notes == "Remember the dog's name.")
        #expect(item.createdAt == Date(timeIntervalSince1970: 1_614_298_956))

        let parameters = try #require(try item.field(.totp)?.otpParameters())
        #expect(Base32.encode(parameters.secret) == Fixtures.totpSecret)
        #expect(parameters.issuer == "Example")
        #expect(parameters.account == "wendy")
        #expect(parameters.digits == 6)
        #expect(parameters.period == 30)

        let passkey = try #require(try item.field(.passkey)?.passkeyCredential())
        #expect(passkey.relyingPartyID == "example.com")
        #expect(passkey.credentialID == Data(0..<32))
        #expect(passkey.userHandle == Data("user-handle-0001".utf8))
        #expect(passkey.userName == "wendy")
        #expect(passkey.userDisplayName == "Wendy Appleseed")
        #expect(passkey.privateKeyPKCS8 == Base64URL.decode(Fixtures.privateKey))
        #expect(passkey.prfSecret == Data(32..<64))
        #expect(passkey.createdAt == Date(timeIntervalSince1970: 1_614_298_956))

        let pet = try #require(item.field(labelled: "First pet?"))
        #expect(pet.kind == .custom)
        #expect(pet.value == "Fluffy")
        #expect(pet.meta[InterchangeMeta.section] == "Security questions")
        #expect(item.field(labelled: "Town of birth?")?.kind == .text)

        // `co.uk` is a URL the item keeps, not a scope it gains (F11.2); the sign-in page is kept beside its scope.
        #expect(item.values(.url) == ["https://example.com/login", "https://co.uk"])
        #expect(
            result.warnings(for: "Example") == [
                .scopeRefused(url: "https://co.uk", reason: .policy(.publicSuffix("co.uk")))
            ])
    }

    @Test("API keys and notes map to their own fields")
    func apiKeyAndNote() throws {
        let result = try importCXF()
        let token = try result.entry(titled: "Deploy token")
        #expect(token.kind == .apiCredential)
        #expect(token.item.values(.apiKey) == ["sk_live_abc123"])
        #expect(token.item.values(.username) == ["deploy-bot"])
        #expect(token.item.values(.text) == ["bearer"])
        #expect(token.item.values(.url) == ["https://api.example.com"])
        #expect(token.item.values(.date) == ["2030-01-01"])
        // An API key's URL is a field; scopes come only from the item's own scope.
        #expect(token.item.scopes.isEmpty)

        let note = try result.entry(titled: "Just a note")
        #expect(note.kind == .secureNote)
        #expect(note.item.notes == "Nothing else.")
        #expect(note.item.fields.isEmpty)
    }

    @Test("An unknown credential type is kept as concealed custom fields and reported")
    func unknownType() throws {
        let result = try importCXF()
        let wifi = try result.entry(titled: "Home network")
        #expect(wifi.kind == .other)
        #expect(wifi.item.fields.allSatisfy { $0.kind == .custom })
        #expect(
            wifi.item.fields.map(\.label) == [
                "wifi: ssid", "wifi: networkSecurityType", "wifi: passphrase", "wifi: hidden",
            ])
        #expect(wifi.item.fields.map(\.value) == ["Appleseed", "wpa3-personal", "open sesame", "false"])
        #expect(result.warnings(for: "Home network") == [.unsupportedCredentialType("wifi")])
    }

    @Test("An export reads back as the same items")
    func roundTrip() throws {
        let first = try importCXF()
        let exported = CredentialExchange.exportDocument(first.entries.map(\.item), options: exportOptions)
        #expect(exported.report.exportedCount == 4)
        #expect(exported.report.warnings.isEmpty)
        let second = try importCXF(exported.bytes, seed: 77)
        #expect(second.report.skipped.isEmpty)
        for entry in first.entries where entry.item.title != "Home network" {
            let other = try second.entry(titled: entry.item.title)
            #expect(ItemShape(other.item) == ItemShape(entry.item), "\(entry.item.title)")
            #expect(other.kind == entry.kind)
        }
        // The Wi-Fi item's fields come back as an ordinary custom-fields group.
        let wifi = try second.entry(titled: "Home network")
        #expect(wifi.item.fields.map(\.value) == ["Appleseed", "wpa3-personal", "open sesame", "false"])
        #expect(wifi.item.fields.allSatisfy { $0.kind == .custom })

        // Stable from then on.
        let third = CredentialExchange.exportDocument(second.entries.map(\.item), options: exportOptions)
        let reread = try importCXF(third.bytes, seed: 78)
        #expect(reread.entries.map { ItemShape($0.item) } == second.entries.map { ItemShape($0.item) })
    }

    @Test("Security questions, PINs and recovery codes export as custom-fields")
    func exportsCustomFields() throws {
        let passkey = try PasskeyCredential(
            credentialID: Data(repeating: 1, count: 32), relyingPartyID: "example.com",
            userHandle: Data(repeating: 2, count: 16), userName: "wendy",
            privateKeyPKCS8: Data(repeating: 3, count: 64),
            createdAt: Date(timeIntervalSince1970: 1_700_000_000), prfSecret: Data(repeating: 4, count: 32),
            largeBlob: Data("large blob contents".utf8))
        let item = Item(
            id: UUID(uuidString: "00010203-0405-4607-8809-0A0B0C0D0E0F")!, vaultID: Fixtures.vaultID,
            title: "Everything", scopes: [ServiceScope(host: "example.com")],
            fields: [
                Field(kind: .email, label: "Email", value: "wendy@example.com"),
                Field(kind: .password, label: "Password", value: "pw"),
                Field(kind: .securityQuestion, label: "First pet?", value: "Fluffy"),
                Field(kind: .pin, label: "PIN", value: "0420"),
                Field(kind: .recoveryCodes, label: "Recovery codes", value: "aaaa\nbbbb"),
                Field(kind: .text, label: "Plan", value: "family"),
                Field(kind: .totp, label: "Code", value: "garbage"),
                try Field.passkey(passkey),
            ], tags: ["Favorite"], createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_100))
        let exported = CredentialExchange.exportDocument([item], options: exportOptions)
        #expect(exported.report.warnings == [.oneTimePasswordUnusable(itemID: item.id)])
        let text = String(decoding: exported.bytes, as: UTF8.self)
        #expect(text.hasPrefix(#"{"version":{"major":1,"minor":0},"exporterRpId":"watchword.example","#))
        #expect(text.contains(#""id":"AAECAwQFRgeICQoLDA0ODw""#))
        #expect(text.contains(#""favorite":true"#))
        #expect(text.contains(#""scope":{"urls":["https://example.com/"],"androidApps":[]}"#))
        #expect(
            text.contains(
                #"{"type":"basic-auth","username":{"fieldType":"email","value":"wendy@example.com"},"#
                    + #""password":{"fieldType":"concealed-string","value":"pw"}}"#))
        #expect(
            text.contains(
                #"{"type":"custom-fields","fields":[{"fieldType":"concealed-string","value":"Fluffy","label":"First pet?"},"#
                    + #"{"fieldType":"concealed-string","value":"0420","label":"PIN"},"#
                    + #"{"fieldType":"concealed-string","value":"aaaa\nbbbb","label":"Recovery codes"},"#
                    + #"{"fieldType":"string","value":"family","label":"Plan"},"#
                    + #"{"fieldType":"concealed-string","value":"garbage","label":"Code"}]}"#))

        // The passkey survives whole, PRF secret and large blob included.
        let again = try importCXF(exported.bytes)
        let restored = try #require(try again.entries.first?.item.field(.passkey)?.passkeyCredential())
        #expect(restored == passkey)
        // The unusable code was written as a concealed field, so nothing is left to warn about.
        #expect(again.report.warnings.isEmpty)
        #expect(again.entries.first?.item.field(labelled: "Code")?.kind == .custom)
    }

    private func importItems(_ items: String) throws -> ImportResult {
        let json =
            #"{"version":{"major":1,"minor":0},"exporterRpId":"x.example","exporterDisplayName":"X","timestamp":1,"#
            + #""accounts":[{"id":"YQ","username":"","email":"","collections":[],"items":["# + items + "]}]}"
        return try importCXF(Array(json.utf8))
    }

    @Test("Numbers and booleans are kept as text; subtitles and Android apps are not passed over in silence")
    func nothingDroppedSilently() throws {
        let result = try importItems(
            #"""
            {"id": "aQ", "title": "Typed", "subtitle": "the blue one",
             "scope": {"urls": ["https://example.com"], "androidApps": [{"bundleId": "com.example"}, {"bundleId": "b"}]},
             "credentials": [
               {"type": "basic-auth", "username": {"fieldType": "string", "value": "wendy"},
                "password": {"fieldType": "concealed-string", "value": ["not", "text"]}},
               {"type": "custom-fields", "fields": [
                 {"fieldType": "number", "value": 42, "label": "Floor"},
                 {"fieldType": "boolean", "value": true, "label": "Parking"},
                 {"fieldType": "number", "value": 2.5, "label": "Rate"},
                 {"fieldType": "string", "value": {"deep": 1}, "label": "Odd"},
                 {"fieldType": "string", "value": null, "label": "Nothing"},
                 "not a field"]}]},
            {"id": "bQ", "title": "Plain", "subtitle": "wendy", "credentials": [
               {"type": "basic-auth", "username": {"fieldType": "string", "value": "wendy"}}]},
            {"id": "cQ", "title": "Same", "subtitle": "Same", "credentials": [
               {"type": "note", "content": {"fieldType": "string", "value": "n"}}]}
            """#)
        let typed = try result.entry(titled: "Typed").item
        #expect(
            typed.fields.map { "\($0.label)=\($0.value) [\($0.kind.rawValue)]" } == [
                "Username=wendy [username]", "Floor=42 [text]", "Parking=true [text]", "Rate=2.5 [text]",
                "Subtitle=the blue one [text]",
            ])
        #expect(
            result.warnings(for: "Typed") == [
                .androidAppsNotImported(count: 2),
                .unsupportedFieldType(label: "Password", type: "concealed-string"),
                .unsupportedFieldType(label: "Odd", type: "string"),
                .unsupportedFieldType(label: "Field", type: "unknown"),
            ])
        // A subtitle that repeats the title or a field says nothing new, and adds no field.
        #expect(try result.entry(titled: "Plain").item.fields.map(\.value) == ["wendy"])
        #expect(try result.entry(titled: "Same").item.fields.isEmpty)
        #expect(result.warnings(for: "Plain").isEmpty)

        // The subtitle goes back out as a subtitle.
        let exported = CredentialExchange.exportDocument([typed], options: exportOptions)
        let text = String(decoding: exported.bytes, as: UTF8.self)
        #expect(text.contains(#""title":"Typed","subtitle":"the blue one","#))
        #expect(!text.contains(#""label":"Subtitle""#))
        let again = try importCXF(exported.bytes, seed: 9)
        #expect(try ItemShape(again.entry(titled: "Typed").item) == ItemShape(typed))
    }

    @Test("Passkeys outside their bounds are refused alone, and the rest of the item is imported")
    func refusedPasskeys() throws {
        func item(_ passkey: String) -> [UInt8] {
            Array(
                """
                {"version": {"major": 1, "minor": 0}, "accounts": [{"items": [{"id": "a", "title": "Site",
                  "credentials": [{"type": "basic-auth", "username": {"fieldType": "string", "value": "u"}}, \(passkey)]}]}]}
                """.utf8)
        }
        func passkey(_ changes: [String: String]) -> String {
            var members = [
                "credentialId": "\"\(Fixtures.credentialID)\"", "rpId": "\"example.com\"", "username": "\"u\"",
                "userDisplayName": "\"U\"", "userHandle": "\"\(Fixtures.userHandle)\"",
                "key": "\"\(Fixtures.privateKey)\"",
            ]
            members.merge(changes) { $1 }
            return "{\"type\": \"passkey\", "
                + members.sorted { $0.key < $1.key }.map { "\"\($0.key)\": \($0.value)" }
                .joined(separator: ", ") + "}"
        }
        let oversizedKey = "\"" + Base64URL.encode([UInt8](repeating: 7, count: 513)) + "\""
        let hugeBlob = "\"" + String(repeating: "A", count: 200_000) + "\""
        let cases: [(String, String)] = [
            (passkey(["credentialId": "\"AAEC\""]), "credentialID"),
            (passkey(["credentialId": "\"not base64url!\""]), "credentialId"),
            (passkey(["credentialId": "\"\(Fixtures.credentialID)==\""]), "credentialId"),
            (passkey(["userHandle": "\"\""]), "userHandle"),
            (passkey(["key": oversizedKey]), "privateKey"),
            (passkey(["key": hugeBlob]), "privateKey"),
            (passkey(["rpId": "\"Example.com\""]), "rpId"),
            (passkey(["rpId": "7"]), "rpId"),
        ]
        for (json, reason) in cases {
            let result = try importCXF(item(json))
            let entry = try result.entry(titled: "Site")
            #expect(entry.item.field(.passkey) == nil, "\(reason)")
            #expect(entry.item.values(.username) == ["u"])
            #expect(result.report.warnings.map(\.warning) == [.passkeyRefused(reason: reason)], "\(reason)")
        }
        // With nothing else in the item, the item itself is skipped, and listed.
        let alone = Array(
            """
            {"version": {"major": 1, "minor": 0}, "accounts": [{"items": [{"id": "a", "title": "",
              "credentials": [\(passkey(["key": oversizedKey]))]}]}]}
            """.utf8)
        let result = try importCXF(alone)
        #expect(result.entries.isEmpty)
        #expect(result.report.skipped.map(\.reason) == [.nothingImportable])
    }

    @Test("Passkey extensions with no place in a Watchword passkey are dropped by name")
    func passkeyExtensions() throws {
        let json = """
            {"version": {"major": 1, "minor": 0}, "accounts": [{"items": [{"id": "a", "title": "Site", "credentials": [
              {"type": "passkey", "credentialId": "\(Fixtures.credentialID)", "rpId": "example.com", "username": "u",
               "userDisplayName": "U", "userHandle": "\(Fixtures.userHandle)", "key": "\(Fixtures.privateKey)",
               "fido2Extensions": {
                 "hmacCredentials": {"algorithm": "hmac-sha256", "credWithUV": "\(Fixtures.prfSecret)", "credWithoutUV": "\(Fixtures.credentialID)"},
                 "credBlob": "AAEC",
                 "largeBlob": {"uncompressedSize": 99999999, "data": "AAEC"}}}]}]}]}
            """
        let result = try importCXF(Array(json.utf8))
        let passkey = try #require(try result.entries.first?.item.field(.passkey)?.passkeyCredential())
        #expect(passkey.prfSecret == Data(32..<64))
        #expect(passkey.largeBlob == nil)
        #expect(
            result.report.warnings.map(\.warning) == [
                .passkeyDetailDropped("hmacCredentials.credWithoutUV"), .passkeyDetailDropped("largeBlob"),
                .passkeyDetailDropped("credBlob"),
            ])
    }

    @Test("One-time passwords that cannot work are kept, concealed, with the reason")
    func unusableOneTimePasswords() throws {
        func document(_ totp: String) -> [UInt8] {
            Array(
                #"{"version": {"major": 1, "minor": 0}, "accounts": [{"items": [{"id": "a", "title": "Site", "credentials": ["#
                    .utf8) + Array(totp.utf8) + Array("]}]}]}".utf8)
        }
        let cases: [(String, OTPAuthError)] = [
            (
                #"{"type": "totp", "secret": "not base32 at all!", "period": 30, "digits": 6, "algorithm": "sha1"}"#,
                .malformedSecret
            ),
            (
                #"{"type": "totp", "secret": "GEZDGNBVGY3TQOJQ", "period": 0, "digits": 6, "algorithm": "sha1"}"#,
                .periodOutOfRange("0")
            ),
            (
                #"{"type": "totp", "secret": "GEZDGNBVGY3TQOJQ", "period": 30, "digits": 40, "algorithm": "sha1"}"#,
                .digitsOutOfRange("40")
            ),
            (
                #"{"type": "totp", "secret": "GEZDGNBVGY3TQOJQ", "period": 30, "digits": 6, "algorithm": "md5"}"#,
                .unsupportedAlgorithm("md5")
            ),
            (
                #"{"type": "totp", "secret": "GEZDGNBV", "period": 30, "digits": 6, "algorithm": "sha1"}"#,
                .secretLength(5)
            ),
            (
                #"{"type": "totp", "secret": "GEZDGNBVGY3TQOJQ", "period": "soon", "digits": 6, "algorithm": "sha1"}"#,
                .periodOutOfRange("")
            ),
        ]
        for (totp, reason) in cases {
            let result = try importCXF(document(totp))
            let item = try result.entry(titled: "Site").item
            #expect(item.field(.totp) == nil)
            let kept = try #require(item.field(labelled: "One-time password"))
            #expect(kept.kind == .custom)
            #expect(
                result.report.warnings.map(\.warning) == [
                    .unusableOneTimePassword(label: "One-time password", reason: reason)
                ])
        }
    }

    @Test("Collections become tags on the items they list, wherever they sit in the account")
    func collections() throws {
        let json = #"""
            {"version": {"major": 1, "minor": 0}, "accounts": [{
              "items": [
                {"id": "a", "title": "A", "tags": ["own"], "credentials": [{"type": "note", "content": {"fieldType": "string", "value": "a"}}]},
                {"id": "b", "title": "B", "credentials": [{"type": "note", "content": {"fieldType": "string", "value": "b"}}]}
              ],
              "collections": [
                {"id": "c1", "title": "Work", "items": [{"item": "a"}, {"item": "missing"}],
                 "subCollections": [{"id": "c2", "title": "Servers", "items": [{"item": "b"}, {"item": "a"}]}]},
                {"id": "c3", "title": "", "items": [{"item": "b"}]},
                "not a collection"
              ]}]}
            """#
        let result = try importCXF(Array(json.utf8))
        #expect(try result.entry(titled: "A").item.tags == ["own", "Work", "Work/Servers"])
        #expect(try result.entry(titled: "B").item.tags == ["Work/Servers"])
    }

    @Test("Versions other than 1.x, and documents without one, are refused")
    func versions() {
        func error(_ json: String) -> InterchangeError? {
            do {
                _ = try importCXF(Array(json.utf8))
                return nil
            } catch {
                return error as? InterchangeError
            }
        }
        #expect(error(#"{"version": {"major": 2, "minor": 0}, "accounts": []}"#) == .unsupportedVersion("2.0"))
        #expect(error(#"{"accounts": [], "version": {"major": 0, "minor": 9}}"#) == .unsupportedVersion("0.9"))
        #expect(error(#"{"version": {"major": 1, "minor": 3}, "accounts": []}"#) == nil)
        #expect(error(#"{"accounts": []}"#) == .unexpectedStructure(path: "version"))
        #expect(error(#"{"version": "1.0", "accounts": []}"#) == .unexpectedStructure(path: "version"))
        #expect(error(#"{"version": {"major": 1, "minor": 0}}"#) == .unexpectedStructure(path: "accounts"))
        #expect(
            error(#"{"version": {"major": 1, "minor": 0}, "accounts": [{"items": {}}]}"#)
                == .unexpectedStructure(path: "accounts[].items"))
    }

    @Test("Items without credentials, or repeating an identifier, are skipped and listed")
    func skippedItems() throws {
        let json = #"""
            {"version": {"major": 1, "minor": 0}, "accounts": [{"items": [
              {"id": "a", "title": "First", "credentials": [{"type": "note", "content": {"fieldType": "string", "value": "one"}}]},
              {"id": "a", "title": "Again", "credentials": [{"type": "note", "content": {"fieldType": "string", "value": "two"}}]},
              {"id": "b", "title": "No credentials"},
              {"id": "c", "title": "", "credentials": []},
              17
            ]}]}
            """#
        let result = try importCXF(Array(json.utf8))
        #expect(result.entries.map(\.item.title) == ["First"])
        #expect(
            result.report.skipped.map(\.reason) == [
                .duplicateIdentifier("a"), .malformed(path: "items[].credentials"), .empty,
                .malformed(path: "items[]"),
            ])
        #expect(result.report.skipped.map(\.entry.title) == ["Again", "No credentials", "", ""])
    }
}
