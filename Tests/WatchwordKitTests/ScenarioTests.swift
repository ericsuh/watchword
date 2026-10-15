#if canImport(CryptoKit) && canImport(CommonCrypto)
    import Foundation
    import Testing
    import WatchwordMatching
    import WatchwordModel
    import WatchwordTestSupport

    @testable import WatchwordKit

    /// PRD scenarios S1–S4 against `VaultSession` with in-memory ports (docs/03-implementation-plan.md, milestone 2
    /// exit criteria; docs/04-test-plan.md §4). The vault stores and returns what each scenario needs and the matching
    /// layer decides over what came back from the store. The sharing halves of S3 and S4 (a second member, revocation,
    /// read-only) need the membership chain and arrive with milestone 4.
    @Suite("Scenarios S1–S4 against the vault")
    struct VaultScenarioTests {
        static func vault() async throws -> (TestVault, UUID) {
            let vault = TestVault()
            try await vault.createAccount()
            return (vault, try #require(await vault.session.personalVaultID))
        }

        @Test("S1: the AWS console gets only the AWS credential, Amazon retail only the retail one, each with its TOTP")
        func s1() async throws {
            let (vault, vaultID) = try await Self.vault()
            let retail = try await vault.session.save(
                Item(
                    vaultID: vaultID, title: "Amazon", scopes: [ServiceScope(host: "amazon.com")],
                    fields: [
                        Field(kind: .email, label: "Email", value: "pat@example.com"),
                        Field(kind: .password, label: "Password", value: "retail-pw"),
                        Field(kind: .totp, label: "OTP", value: "otpauth://totp/Amazon?secret=RETAIL"),
                    ]))
            let aws = try await vault.session.save(
                Item(
                    vaultID: vaultID, title: "AWS root",
                    scopes: [
                        ServiceScope(host: "signin.aws.amazon.com"), ServiceScope(host: "console.aws.amazon.com"),
                    ],
                    fields: [
                        Field(kind: .email, label: "Email", value: "pat@example.com"),
                        Field(kind: .password, label: "Password", value: "aws-pw"),
                        Field(kind: .totp, label: "OTP", value: "otpauth://totp/AWS?secret=AWSROOT"),
                    ]))
            let stored = try await vault.session.items().items

            let console = AutoFillGate.decide(
                for: ServiceIdentifier("https://signin.aws.amazon.com/signin", kind: .url), among: stored)
            guard case .fill(let consoleMatch) = console else {
                Issue.record("expected a fill on the AWS console, got \(console)")
                return
            }
            #expect(consoleMatch.item.id == aws.id)
            #expect(consoleMatch.item.field(.totp)?.value.contains("AWSROOT") == true)
            let shopping = AutoFillGate.decide(
                for: ServiceIdentifier("https://www.amazon.com/ap/signin", kind: .url), among: stored)
            guard case .fill(let shoppingMatch) = shopping else {
                Issue.record("expected a fill on amazon.com, got \(shopping)")
                return
            }
            #expect(shoppingMatch.item.id == retail.id)
            #expect(shoppingMatch.item.field(.totp)?.value.contains("RETAIL") == true)
            let explicitRetailOnConsole = AutoFillGate.authorize(
                retail, for: ServiceIdentifier("https://signin.aws.amazon.com/signin", kind: .url), among: stored)
            #expect(throws: FillRefusal.self) { try explicitRetailOnConsole.get() }
        }

        @Test("S2: passkey and recovery codes live in one item; marking a code used is a new version with history")
        func s2() async throws {
            let (vault, vaultID) = try await Self.vault()
            let codesField = Field(
                kind: .recoveryCodes, label: "Backup codes", value: "1111-2222\n3333-4444\n5555-6666")
            let google = try await vault.session.save(
                Item(
                    vaultID: vaultID, title: "Google", scopes: [ServiceScope(host: "google.com")],
                    fields: [
                        Field(kind: .email, label: "Email", value: "pat@example.com"),
                        Field(
                            kind: .passkey, label: "Passkey", value: "base64-private-key",
                            meta: ["rpID": "google.com", "credentialID": "abc", "prf": "true"]),
                        codesField,
                    ]))
            try await vault.session.markRecoveryCode(itemID: google.id, fieldID: codesField.id, index: 1, used: true)
            let after = try await vault.session.item(id: google.id)
            #expect(after.version == google.version + 1)
            let codes = try #require(after.fields.first { $0.id == codesField.id })
            #expect(codes.usedRecoveryCodeIndices == [1])
            #expect(after.history.first?.fields.first { $0.id == codesField.id }?.usedRecoveryCodeIndices == [])
            #expect(after.field(.passkey)?.meta["rpID"] == "google.com")
        }

        @Test("S3: a bank item with phone, password, TOTP and three security questions round-trips intact")
        func s3() async throws {
            let (vault, vaultID) = try await Self.vault()
            let questions = (1...3).map {
                Field(
                    kind: .securityQuestion, label: "Question \($0)", value: "answer \($0)",
                    meta: ["question": "Question text \($0)?"])
            }
            let bank = try await vault.session.save(
                Item(
                    vaultID: vaultID, title: "First Bank", scopes: [ServiceScope(host: "firstbank.co.uk")],
                    fields: [
                        Field(kind: .phoneNumber, label: "Phone", value: "+44 20 7946 0000"),
                        Field(kind: .password, label: "Password", value: "bank-pw"),
                        Field(kind: .totp, label: "OTP", value: "otpauth://totp/Bank?secret=BANK"),
                    ] + questions))
            let stored = try await vault.session.item(id: bank.id)
            #expect(
                stored.fields.filter { $0.kind == .securityQuestion }.map(\.value) == [
                    "answer 1", "answer 2", "answer 3",
                ])
            #expect(stored.fields.filter { $0.kind.isSecret }.count == 5)
        }

        @Test("S4: a library card keeps its PIN and card number as insertable fields")
        func s4() async throws {
            let (vault, vaultID) = try await Self.vault()
            let library = try await vault.session.save(
                Item(
                    vaultID: vaultID, title: "City Library", scopes: [ServiceScope(host: "catalogue.citylibrary.org")],
                    fields: [
                        Field(kind: .accountNumber, label: "Card number", value: "2 1234 56789 0123"),
                        Field(kind: .username, label: "Username", value: "pat"),
                        Field(kind: .password, label: "Password", value: "library-pw"),
                        Field(kind: .pin, label: "PIN", value: "4321"),
                    ]))
            let stored = try await vault.session.item(id: library.id)
            #expect(stored.field(.pin)?.value == "4321")
            #expect(stored.field(.accountNumber)?.value == "2 1234 56789 0123")
            #expect(stored.field(.pin)?.kind.isSecret == true)
        }
    }
#endif
