import Foundation
import Testing
import WatchwordAutoFill
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

@Suite("Request model: one-time codes and text to insert")
struct OneTimeCodeAndTextRequestTests {
    typealias Fixtures = AutoFillFixtures

    static let console = Fixtures.url("https://signin.aws.amazon.com/signin")
    static let shop = Fixtures.url("https://www.amazon.com/ap/signin")
    static let bankSite = Fixtures.url("https://www.firstbank.co.uk/login")
    static let librarySite = Fixtures.domain("library.example.org")

    static func expectedCode(_ secret: String, at date: Date = Fixtures.now) throws -> String {
        try TOTP.code(for: try OTPParameters(secret: Data(secret.utf8)), at: date).code
    }

    // MARK: One-time codes (F6.3, F11.4)

    @Test("the list holds the code fields of the items the gate would fill")
    func codeList() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        guard case .list(let entries) = await harness.model.oneTimeCodeList(for: [Self.console]) else {
            Issue.record("no list")
            return
        }
        #expect(entries.map(\.title) == ["AWS root"])
        #expect(entries.first?.fieldID == Fixtures.id(203))
        #expect(entries.first?.userName == Fixtures.email)
        #expect(await harness.model.oneTimeCodeList(for: [Fixtures.domain("news.example.net")]) == .list([]))
        #expect(await harness.model.oneTimeCodeList(for: []) == .refused(.noServiceIdentifier))
        await harness.vault.lock()
        #expect(await harness.model.oneTimeCodeList(for: [Self.console]) == .vaultLocked)
    }

    @Test("each site gets its own account's code, and the code follows the clock")
    func codeForHost() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let aws = try await harness.model.oneTimeCode(
            for: FieldChoice(itemID: Fixtures.awsRoot.id, fieldID: Fixtures.id(203)), identifiers: [Self.console]
        ).value
        let retail = try await harness.model.oneTimeCode(
            for: FieldChoice(itemID: Fixtures.amazonRetail.id, fieldID: Fixtures.id(103)), identifiers: [Self.shop]
        ).value
        #expect(aws.code == (try Self.expectedCode(Fixtures.awsSecret)))
        #expect(retail.code == (try Self.expectedCode(Fixtures.retailSecret)))
        #expect(aws.code != retail.code)
        #expect(aws.secondsRemaining == 30)
        #expect(!String(describing: aws).contains(aws.code))

        await harness.clock.advance(by: 31)
        let later = try await harness.model.oneTimeCode(
            for: FieldChoice(itemID: Fixtures.awsRoot.id, fieldID: Fixtures.id(203)), identifiers: [Self.console]
        ).value
        #expect(later.code == (try Self.expectedCode(Fixtures.awsSecret, at: Fixtures.now.addingTimeInterval(31))))
        #expect(later.secondsRemaining == 29)
    }

    @Test("a code is withheld on any host its item is not the match for, with no way to ask again")
    func codeWithheld() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        let choice = FieldChoice(itemID: Fixtures.amazonRetail.id, fieldID: Fixtures.id(103))
        for identifier in [Self.console, Fixtures.domain("arnazon.com"), Fixtures.domain("news.example.net")] {
            let outcome = await harness.model.oneTimeCode(for: choice, identifiers: [identifier])
            #expect(outcome.refusal?.isGateRefusal == true, "\(identifier.identifier): \(outcome)")
        }
        #expect(await harness.model.oneTimeCode(for: choice, identifiers: []) == .refused(.noServiceIdentifier))
        guard case .warning = await harness.model.oneTimeCodeList(for: [Fixtures.domain("arnazon.com")]) else {
            Issue.record("no warning on a look-alike")
            return
        }
    }

    @Test("a field that is not a code, or does not parse as one, yields no code")
    func codeFieldErrors() async {
        var broken = Fixtures.library
        broken.fields.append(
            Field(id: Fixtures.id(590), kind: .totp, label: "HOTP", value: "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ"))
        let harness = AutoFillHarness(items: [broken])
        #expect(
            await harness.model.oneTimeCode(
                for: FieldChoice(itemID: broken.id, fieldID: Fixtures.id(590)), identifiers: [Self.librarySite])
                == .refused(.oneTimeCode(.unsupportedType("hotp"))))
        #expect(
            await harness.model.oneTimeCode(
                for: FieldChoice(itemID: broken.id, fieldID: Fixtures.id(503)), identifiers: [Self.librarySite])
                == .refused(.unknownRecord))
        // And it is not listed.
        #expect(await harness.model.oneTimeCodeList(for: [Self.librarySite]) == .list([]))
    }

    @Test("a clock that reads nonsense yields no code")
    func codeClockOutOfRange() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        await harness.clock.set(Date(timeIntervalSince1970: -5))
        #expect(
            await harness.model.oneTimeCode(
                for: FieldChoice(itemID: Fixtures.awsRoot.id, fieldID: Fixtures.id(203)), identifiers: [Self.console])
                == .refused(.clock(.timeOutOfRange)))
    }

    @Test("a published code identity is answered without UI only when its item is the sole fill")
    func silentCode() async throws {
        var second = Fixtures.bank
        second.id = Fixtures.id(92)
        let harness = AutoFillHarness(items: Fixtures.all)
        func request(_ item: Item, _ field: Int, on identifier: ServiceIdentifier) -> OneTimeCodeIdentityRequest {
            OneTimeCodeIdentityRequest(
                serviceIdentifier: identifier,
                recordIdentifier: RecordIdentifier(itemID: item.id, fieldID: Fixtures.id(field)).text)
        }
        let code = try await harness.model.oneTimeCodeWithoutInteraction(
            for: request(Fixtures.awsRoot, 203, on: Self.console)
        ).value
        #expect(code.code == (try Self.expectedCode(Fixtures.awsSecret)))

        // The retail code asked for on the console, a record naming no field, and a field that is gone.
        #expect(
            await harness.model.oneTimeCodeWithoutInteraction(
                for: request(Fixtures.amazonRetail, 103, on: Self.console)
            ).refusal?.isGateRefusal == true)
        #expect(
            await harness.model.oneTimeCodeWithoutInteraction(
                for: OneTimeCodeIdentityRequest(
                    serviceIdentifier: Self.console,
                    recordIdentifier: RecordIdentifier(itemID: Fixtures.awsRoot.id).text))
                == .refused(.unknownRecord))
        #expect(
            await harness.model.oneTimeCodeWithoutInteraction(
                for: request(Fixtures.awsRoot, 999, on: Self.console)) == .requiresInteraction(.staleIdentity))

        let tied = AutoFillHarness(items: [Fixtures.bank, second])
        #expect(
            await tied.model.oneTimeCodeWithoutInteraction(
                for: request(Fixtures.bank, 404, on: Self.bankSite)) == .requiresInteraction(.ambiguousMatch))
        await tied.vault.lock()
        #expect(
            await tied.model.oneTimeCodeWithoutInteraction(
                for: request(Fixtures.bank, 404, on: Self.bankSite)) == .requiresInteraction(.vaultLocked))
    }

    // MARK: Text to insert (F6.4)

    static func list(_ outcome: TextInsertionListOutcome) throws -> TextInsertionList {
        guard case .list(let list) = outcome else { throw UnexpectedOutcome(description: "\(outcome)") }
        return list
    }

    @Test("for a named host the list is that host's items, every field but the passkey, with no secret in it")
    func textListForHost() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let bank = try Self.list(await harness.model.textInsertionList(for: [Self.bankSite]))
        #expect(bank.hostVerified)
        #expect(bank.items.map(\.title) == ["First Bank"])
        let fields = try #require(bank.items.first?.fields)
        #expect(
            fields.map(\.kind) == [
                .username, .phoneNumber, .password, .totp, .securityQuestion, .securityQuestion, .securityQuestion,
            ])
        #expect(
            fields.filter { $0.kind == .securityQuestion }.map(\.question) == [
                "First pet?", "First street?", "First teacher?",
            ])
        #expect(fields.first { $0.kind == .phoneNumber }?.preview == "+44 20 7946 0000")
        #expect(fields.filter(\.kind.isSecret).allSatisfy { $0.preview == nil })
        let dump = String(describing: bank)
        for secret in ["bank-password", "Rex", "Elm Street", "Ms Okafor", "otpauth"] {
            #expect(!dump.contains(secret))
        }

        let google = try Self.list(await harness.model.textInsertionList(for: [Fixtures.domain("google.com")]))
        #expect(google.items.first?.fields.map(\.kind) == [.email, .recoveryCodes])
        #expect(google.items.first?.fields.last?.recoveryCodeCount == 3)
    }

    @Test("the fields of scenarios S3 and S4 insert as text on their own sites")
    func textForHost() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        func text(_ item: Item, _ field: Int, _ part: TextPart = .whole, on identifier: ServiceIdentifier) async
            -> Outcome<TextToInsert>
        {
            await harness.model.textToInsert(
                for: TextChoice(itemID: item.id, fieldID: Fixtures.id(field), part: part), identifiers: [identifier])
        }
        #expect(await text(Fixtures.library, 504, on: Self.librarySite) == .success("4821"))
        #expect(await text(Fixtures.library, 501, on: Self.librarySite) == .success("2 1234 56789 0"))
        #expect(await text(Fixtures.bank, 405, on: Self.bankSite) == .success("Rex"))
        #expect(await text(Fixtures.bank, 407, on: Self.bankSite) == .success("Ms Okafor"))
        #expect(await text(Fixtures.bank, 403, on: Self.bankSite) == .success("bank-password"))
        #expect(
            await text(Fixtures.google, 303, .recoveryCode(index: 1), on: Fixtures.domain("google.com"))
                == .success("3333-4444"))
        // A code field inserts the current code, never its secret.
        #expect(
            await text(Fixtures.bank, 404, on: Self.bankSite)
                == .success(TextToInsert(try Self.expectedCode("bank-totp-secret-000")))
        )
    }

    @Test("text is gated like any release: wrong site, look-alike and other accounts are refused")
    func textGated() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        for (item, field, identifier) in [
            (Fixtures.library, 504, Self.bankSite),
            (Fixtures.bank, 405, Fixtures.domain("firstbamk.co.uk")),
            (Fixtures.amazonRetail, 102, Self.console),
            (Fixtures.bank, 404, Fixtures.domain("firstbank.co.uk.evil.example")),
        ] {
            let outcome = await harness.model.textToInsert(
                for: TextChoice(itemID: item.id, fieldID: Fixtures.id(field)), identifiers: [identifier])
            #expect(outcome.refusal?.isGateRefusal == true, "\(item.title) on \(identifier.identifier): \(outcome)")
        }
        guard
            case .warning(let warning) = await harness.model.textInsertionList(
                for: [Fixtures.domain("firstbamk.co.uk")])
        else {
            Issue.record("no warning")
            return
        }
        #expect(warning.impersonating == ["firstbank.co.uk"])
    }

    @Test("a passkey is never text, and a recovery-code field only gives one code at a time")
    func textParts() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        let google = [Fixtures.domain("google.com")]
        #expect(
            await harness.model.textToInsert(
                for: TextChoice(itemID: Fixtures.google.id, fieldID: Fixtures.id(302)), identifiers: google)
                == .refused(.fieldWithheld(.passkey)))
        #expect(
            await harness.model.textToInsert(
                for: TextChoice(itemID: Fixtures.google.id, fieldID: Fixtures.id(303)), identifiers: google)
                == .refused(.nothingToRelease))
        #expect(
            await harness.model.textToInsert(
                for: TextChoice(itemID: Fixtures.google.id, fieldID: Fixtures.id(303), part: .recoveryCode(index: 3)),
                identifiers: google) == .refused(.nothingToRelease))
        #expect(
            await harness.model.textToInsert(
                for: TextChoice(itemID: Fixtures.google.id, fieldID: Fixtures.id(301), part: .recoveryCode(index: 0)),
                identifiers: google) == .refused(.nothingToRelease))
        #expect(
            await harness.model.textToInsert(
                for: TextChoice(itemID: Fixtures.google.id, fieldID: Fixtures.id(999)), identifiers: google)
                == .refused(.unknownRecord))
    }

    @Test("when the system names no site, the list is hand-picked items without passwords, codes or passkeys")
    func textListWithoutHost() async throws {
        var archived = Fixtures.library
        archived.id = Fixtures.id(93)
        archived.title = "Old library"
        archived.archived = true
        let harness = AutoFillHarness(items: Fixtures.all + [archived])
        let list = try Self.list(await harness.model.textInsertionList(for: []))
        #expect(!list.hostVerified)
        #expect(list.items.map(\.title) == ["AWS root", "Amazon", "First Bank", "Google", "Library"])
        let kinds = Set(list.items.flatMap(\.fields).map(\.kind))
        #expect(kinds.isDisjoint(with: [.password, .totp, .passkey]))
        #expect(kinds.isSuperset(of: [.pin, .securityQuestion, .recoveryCodes, .accountNumber, .email]))
    }

    @Test("with no site named, the insertable kinds insert and the host-bound kinds are withheld")
    func textWithoutHost() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        func text(_ item: Item, _ field: Int, _ part: TextPart = .whole) async -> Outcome<TextToInsert> {
            await harness.model.textToInsert(
                for: TextChoice(itemID: item.id, fieldID: Fixtures.id(field), part: part), identifiers: [])
        }
        #expect(await text(Fixtures.library, 504) == .success("4821"))
        #expect(await text(Fixtures.library, 501) == .success("2 1234 56789 0"))
        #expect(await text(Fixtures.bank, 406) == .success("Elm Street"))
        #expect(await text(Fixtures.google, 303, .recoveryCode(index: 0)) == .success("1111-2222"))
        #expect(await text(Fixtures.library, 503) == .refused(.fieldWithheld(.password)))
        #expect(await text(Fixtures.bank, 404) == .refused(.fieldWithheld(.totp)))
        #expect(await text(Fixtures.google, 302) == .refused(.fieldWithheld(.passkey)))
        #expect(await text(Fixtures.google, 999) == .refused(.unknownRecord))
        await harness.vault.lock()
        #expect(await text(Fixtures.library, 504) == .vaultLocked)
        #expect(await harness.model.textInsertionList(for: []) == .vaultLocked)
    }

    @Test("marking a recovery code used is a new version that keeps the old one in history (S2)")
    func markRecoveryCode() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let choice = FieldChoice(itemID: Fixtures.google.id, fieldID: Fixtures.id(303))
        #expect(await harness.model.markRecoveryCode(choice, index: 1) == .success(true))
        let item = try #require(await harness.vault.item(Fixtures.google.id))
        #expect(item.version == 2)
        #expect(item.fields.first { $0.id == Fixtures.id(303) }?.usedRecoveryCodeIndices == [1])
        #expect(item.history.first?.fields.first { $0.id == Fixtures.id(303) }?.usedRecoveryCodeIndices == [])
        // Again changes nothing; out of range and other fields are refused.
        #expect(await harness.model.markRecoveryCode(choice, index: 1) == .success(false))
        #expect(await harness.model.markRecoveryCode(choice, index: 9) == .refused(.unknownRecord))
        #expect(
            await harness.model.markRecoveryCode(
                FieldChoice(itemID: Fixtures.google.id, fieldID: Fixtures.id(301)), index: 0)
                == .refused(.unknownRecord))
        #expect(await harness.vault.saves.count == 1)
        let list = try Self.list(await harness.model.textInsertionList(for: [Fixtures.domain("google.com")]))
        #expect(list.items.first?.fields.last?.usedRecoveryCodes == [1])
    }
}
