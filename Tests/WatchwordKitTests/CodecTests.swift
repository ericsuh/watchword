import Foundation
import Testing
import WatchwordKit
import WatchwordModel

@Suite("Item payload codec")
struct ItemCodecTests {
    static let item = Item(
        vaultID: UUID(),
        title: "Bank — “Première” 🏦",
        scopes: [ServiceScope(host: "firstbank.co.uk", excludedHosts: ["mortgages.firstbank.co.uk"])],
        fields: [
            Field(kind: .password, label: "Password", value: "p@ss\u{0}word\n"),
            Field(kind: .securityQuestion, label: "Q1", value: "Rex", meta: ["question": "First pet?"]),
        ],
        tags: ["finance"],
        notes: "e\u{301}",
        createdAt: Date(timeIntervalSince1970: 1_800_000_000.25),
        modifiedAt: Date(timeIntervalSince1970: 1_800_000_001),
        version: 9,
        archived: true,
        trashedAt: Date(timeIntervalSince1970: 1_800_000_002),
        history: [ItemHistoryEntry(replacedAt: Date(timeIntervalSince1970: 1), version: 8, fields: [])],
        excludedFromSuggestions: true
    )

    @Test("every property survives encode and decode")
    func roundTrip() throws {
        #expect(try ItemCodec.decode(ItemCodec.encode(Self.item)) == Self.item)
    }

    @Test("oversized payloads are refused before decoding")
    func sizeCap() {
        let huge = [UInt8](repeating: 0x20, count: ItemCodec.maximumPayloadLength + 1)
        #expect(throws: ItemCodecError.payloadTooLarge(huge.count)) { try ItemCodec.decode(huge) }
        var big = Self.item
        big.notes = String(repeating: "x", count: ItemCodec.maximumPayloadLength)
        #expect(throws: ItemCodecError.self) { try ItemCodec.encode(big) }
    }

    @Test("malformed payloads surface as one error", arguments: ["", "{}", "[]", "{\"id\":1}", "\u{FEFF}{"])
    func malformed(_ text: String) {
        #expect(throws: ItemCodecError.malformedPayload) { try ItemCodec.decode(Array(text.utf8)) }
    }
}

@Suite("Emergency Kit")
struct EmergencyKitTests {
    @Test("the setup code round-trips and is not a URL")
    func setupCode() {
        let kit = EmergencyKit(
            accountID: UUID(), secretKey: "WW-ABCDEF-GHJKM-NPQRS-TUVWX-YZ234-56", createdAt: Date())
        #expect(kit.setupCode.hasPrefix("WWKIT1:"))
        #expect(URL(string: kit.setupCode)?.host == nil)
        let parsed = EmergencyKit.parseSetupCode(kit.setupCode)
        #expect(parsed?.accountID == kit.accountID)
        #expect(parsed?.secretKey == kit.secretKey)
    }

    @Test(
        "anything else is not a setup code",
        arguments: ["", "WWKIT1", "WWKIT2:\(UUID().uuidString):x", "WWKIT1:not-a-uuid:x", "WWKIT1:\(UUID()):x:y"])
    func rejects(_ text: String) {
        #expect(EmergencyKit.parseSetupCode(text) == nil)
    }
}

@Suite("Recovery codes")
struct RecoveryCodeTests {
    @Test("codes can be marked used and unused; out-of-range indices are ignored")
    func marking() {
        var field = Field(kind: .recoveryCodes, label: "Backup codes", value: "1111 2222\n3333 4444\n5555 6666")
        #expect(field.recoveryCodes == ["1111 2222", "3333 4444", "5555 6666"])
        field.markRecoveryCode(at: 1, used: true)
        field.markRecoveryCode(at: 2, used: true)
        field.markRecoveryCode(at: 7, used: true)
        #expect(field.usedRecoveryCodeIndices == [1, 2])
        field.markRecoveryCode(at: 2, used: false)
        #expect(field.usedRecoveryCodeIndices == [1])
        var password = Field(kind: .password, label: "Password", value: "x")
        password.markRecoveryCode(at: 0, used: true)
        #expect(password.meta.isEmpty)
    }
}
