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
        // A lock that lands while the request waits on the clock wins.
        await harness.vault.lockAfterReads(1)
        #expect(
            await harness.model.oneTimeCode(
                for: FieldChoice(itemID: Fixtures.awsRoot.id, fieldID: Fixtures.id(203)), identifiers: [Self.console])
                == .vaultLocked)
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

    @Test("a published code identity, handed back as stored, is answered without UI; any other needs the person")
    func silentCode() async throws {
        // The bank is for all of its site and nothing else is; the Amazon accounts are not published at all
        // (scenario S1: the system may offer `amazon.com` on the AWS console, and does not say which page it is).
        let harness = AutoFillHarness(items: Fixtures.all)
        let published = try await harness.publishedCodes()
        #expect(published.map(\.host) == ["firstbank.co.uk"])
        let code = try await harness.model.oneTimeCodeWithoutInteraction(for: published[0].handedBack).value
        #expect(code.code == (try Self.expectedCode("bank-totp-secret-000")))

        func identity(_ item: Item, _ field: Int, host: String) -> OneTimeCodeIdentityRequest {
            OneTimeCodeIdentity(
                host: host, label: item.loginNames[0],
                recordIdentifier: RecordIdentifier(itemID: item.id, fieldID: Fixtures.id(field))
            ).handedBack
        }
        #expect(
            await harness.model.oneTimeCodeWithoutInteraction(
                for: identity(Fixtures.amazonRetail, 103, host: "amazon.com")) == .requiresInteraction(.ambiguousMatch))
        #expect(
            await harness.model.oneTimeCodeWithoutInteraction(
                for: identity(Fixtures.awsRoot, 203, host: "signin.aws.amazon.com"))
                == .requiresInteraction(.staleIdentity))
        // A record naming no field, a field that is gone, a field that is not a code, and a page's URL where the
        // identity's own identifier belongs.
        #expect(
            await harness.model.oneTimeCodeWithoutInteraction(
                for: OneTimeCodeIdentityRequest(
                    serviceIdentifier: Fixtures.domain("firstbank.co.uk"), label: "40012345",
                    recordIdentifier: RecordIdentifier(itemID: Fixtures.bank.id).text))
                == .refused(.unknownRecord))
        // The name the suggestion showed is no longer the item's.
        #expect(
            await harness.model.oneTimeCodeWithoutInteraction(
                for: OneTimeCodeIdentity(
                    host: "firstbank.co.uk", label: "an-old-name",
                    recordIdentifier: RecordIdentifier(itemID: Fixtures.bank.id, fieldID: Fixtures.id(404))
                ).handedBack) == .requiresInteraction(.staleIdentity))
        for field in [999, 403] {
            #expect(
                await harness.model.oneTimeCodeWithoutInteraction(
                    for: identity(Fixtures.bank, field, host: "firstbank.co.uk"))
                    == .requiresInteraction(.staleIdentity))
        }
        #expect(
            await harness.model.oneTimeCodeWithoutInteraction(
                for: OneTimeCodeIdentityRequest(
                    serviceIdentifier: Self.bankSite, label: "40012345",
                    recordIdentifier: RecordIdentifier(itemID: Fixtures.bank.id, fieldID: Fixtures.id(404)).text))
                == .requiresInteraction(.staleIdentity))

        // Two accounts that would be suggested under one name: neither code is published.
        var second = Fixtures.bank
        second.id = Fixtures.id(92)
        let tied = AutoFillHarness(items: [Fixtures.bank, second])
        #expect(try await tied.publishedCodes().isEmpty)
        #expect(
            await tied.model.oneTimeCodeWithoutInteraction(for: identity(Fixtures.bank, 404, host: "firstbank.co.uk"))
                == .requiresInteraction(.ambiguousMatch))
        await tied.vault.lock()
        #expect(
            await tied.model.oneTimeCodeWithoutInteraction(for: identity(Fixtures.bank, 404, host: "firstbank.co.uk"))
                == .requiresInteraction(.vaultLocked))

        // A lock that lands while the request waits on the clock wins.
        let locking = AutoFillHarness(items: [Fixtures.bank])
        await locking.vault.lockAfterReads(1)
        #expect(
            await locking.model.oneTimeCodeWithoutInteraction(
                for: identity(Fixtures.bank, 404, host: "firstbank.co.uk")) == .requiresInteraction(.vaultLocked))
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

    @Test("when the system names no site, the list is hand-picked items with their fields that are not secrets")
    func textListWithoutHost() async throws {
        var archived = Fixtures.library
        archived.id = Fixtures.id(93)
        archived.title = "Old library"
        archived.archived = true
        var excluded = Fixtures.library
        excluded.id = Fixtures.id(94)
        excluded.title = "Private library"
        excluded.excludedFromSuggestions = true
        var keys = Fixtures.library
        keys.id = Fixtures.id(95)
        keys.title = "Keys"
        keys.fields = [
            Field(kind: .apiKey, label: "Token", value: "sk-live"), Field(kind: .custom, label: "X", value: "y"),
        ]
        let harness = AutoFillHarness(items: Fixtures.all + [archived, excluded, keys])
        let list = try Self.list(await harness.model.textInsertionListWithoutHost())
        #expect(!list.hostVerified)
        // "Keys" holds nothing but secrets, so it has nothing to offer.
        #expect(list.items.map(\.title) == ["AWS root", "Amazon", "First Bank", "Google", "Library"])
        let kinds = Set(list.items.flatMap(\.fields).map(\.kind))
        #expect(kinds == [.email, .username, .phoneNumber, .accountNumber])
        #expect(kinds.allSatisfy { !$0.isSecret })
        #expect(list.items.flatMap(\.fields).allSatisfy { $0.preview != nil })
    }

    @Test("with no site named, fields that are not secrets insert and every secret is withheld")
    func textWithoutHost() async {
        var library = Fixtures.library
        library.fields.append(Field(id: Fixtures.id(505), kind: .apiKey, label: "API key", value: "sk-live"))
        library.fields.append(Field(id: Fixtures.id(506), kind: .custom, label: "Custom", value: "custom-secret"))
        let harness = AutoFillHarness(items: [library, Fixtures.bank, Fixtures.google])
        func text(_ item: Item, _ field: Int, _ part: TextPart = .whole) async -> Outcome<TextToInsert> {
            await harness.model.textToInsertWithoutHost(
                for: TextChoice(itemID: item.id, fieldID: Fixtures.id(field), part: part))
        }
        #expect(await text(library, 501) == .success("2 1234 56789 0"))
        #expect(await text(library, 502) == .success("pat"))
        #expect(await text(Fixtures.bank, 402) == .success("+44 20 7946 0000"))
        // Everything that signs someone in somewhere stays behind (F11.4): there is no host to check it against.
        #expect(await text(library, 503) == .refused(.fieldWithheld(.password)))
        #expect(await text(library, 504) == .refused(.fieldWithheld(.pin)))
        #expect(await text(library, 505) == .refused(.fieldWithheld(.apiKey)))
        #expect(await text(library, 506) == .refused(.fieldWithheld(.custom)))
        #expect(await text(Fixtures.bank, 404) == .refused(.fieldWithheld(.totp)))
        #expect(await text(Fixtures.bank, 406) == .refused(.fieldWithheld(.securityQuestion)))
        #expect(await text(Fixtures.google, 302) == .refused(.fieldWithheld(.passkey)))
        #expect(await text(Fixtures.google, 303, .recoveryCode(index: 0)) == .refused(.fieldWithheld(.recoveryCodes)))
        #expect(await text(Fixtures.google, 999) == .refused(.unknownRecord))
        await harness.vault.lock()
        #expect(await text(library, 501) == .vaultLocked)
        #expect(await harness.model.textInsertionListWithoutHost() == .vaultLocked)
    }

    @Test("the host-checked text request with no identifier is refused: it is not the hand-picked one")
    func textNeedsAnIdentifier() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        #expect(await harness.model.textInsertionList(for: []) == .refused(.noServiceIdentifier))
        for field in [501, 503, 504] {
            #expect(
                await harness.model.textToInsert(
                    for: TextChoice(itemID: Fixtures.library.id, fieldID: Fixtures.id(field)), identifiers: [])
                    == .refused(.noServiceIdentifier))
        }
        // A lock that lands after the items were read wins here too.
        await harness.vault.lockAfterReads(1)
        #expect(
            await harness.model.textToInsert(
                for: TextChoice(itemID: Fixtures.library.id, fieldID: Fixtures.id(504)),
                identifiers: [Self.librarySite]) == .vaultLocked)
        await harness.vault.unlock()
        await harness.vault.lockAfterReads(1)
        #expect(
            await harness.model.textToInsertWithoutHost(
                for: TextChoice(itemID: Fixtures.library.id, fieldID: Fixtures.id(501))) == .vaultLocked)
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
