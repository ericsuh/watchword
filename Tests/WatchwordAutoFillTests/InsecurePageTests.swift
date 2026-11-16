import Foundation
import Testing
import WatchwordAutoFill
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

/// PRD F6.9 (owner decision, 2026-11-16): nothing that puts a secret into a page is done for a page loaded over plain
/// `http`. Domain identifiers, which name an app's associated domain and carry no scheme, are unchanged.
@Suite("Request model: pages loaded over plain http")
struct InsecurePageTests {
    typealias Fixtures = AutoFillFixtures

    static let plainShop = Fixtures.url("http://www.amazon.com/ap/signin")
    static let secureShop = Fixtures.url("https://www.amazon.com/ap/signin")
    static let plainBank = Fixtures.url("HTTP://www.firstbank.co.uk/login")
    static let library = Fixtures.url("http://library.example.org/")

    static func isInsecurePage(_ refusal: ProviderRefusal?, _ host: String) -> Bool {
        guard case .gate(.insecurePage(let page)) = refusal else { return false }
        return page.value == host
    }

    @Test("the gate reads the scheme: http pages are insecure, https pages and domains are not")
    func gateReadsTheScheme() {
        #expect(HostNormalizer.isPlainHTTPPage(Self.plainShop))
        #expect(HostNormalizer.isPlainHTTPPage(Self.plainBank))
        #expect(HostNormalizer.isPlainHTTPPage(Fixtures.url("  http://amazon.com  ")))
        #expect(!HostNormalizer.isPlainHTTPPage(Self.secureShop))
        #expect(!HostNormalizer.isPlainHTTPPage(Fixtures.domain("amazon.com")))
        #expect(!HostNormalizer.isPlainHTTPPage(Fixtures.domain("http.example")))
        guard case .refuse(.insecurePage(let host)) = AutoFillGate.decide(for: Self.plainShop, among: Fixtures.all)
        else {
            Issue.record("http page was not refused")
            return
        }
        #expect(host.value == "www.amazon.com")
        #expect(AutoFillGate.decide(for: Self.secureShop, among: Fixtures.all).isFill)
        #expect(AutoFillGate.decide(for: Fixtures.domain("www.amazon.com"), among: Fixtures.all).isFill)
        // An identifier the gate cannot read is still that refusal, not this one.
        guard
            case .refuse(.unusableIdentifier) = AutoFillGate.decide(
                for: Fixtures.url("http://amazon.com@evil.example/"), among: Fixtures.all)
        else {
            Issue.record("user-info was not refused as unusable")
            return
        }
    }

    @Test("a credential list for an http page lists nothing and says why")
    func credentialList() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        let outcome = await harness.model.credentialList(for: [Self.plainShop])
        guard case .refused(let refusal) = outcome, Self.isInsecurePage(refusal, "www.amazon.com") else {
            Issue.record("\(outcome)")
            return
        }
        guard case .list(let list) = await harness.model.credentialList(for: [Self.secureShop]) else {
            Issue.record("https page was not listed")
            return
        }
        #expect(list.passwords.map(\.itemID) == [Fixtures.amazonRetail.id])
        // Beside an https page, the http identifier contributes nothing.
        guard case .list(let mixed) = await harness.model.credentialList(for: [Self.plainBank, Self.secureShop]) else {
            Issue.record("mixed request was not listed")
            return
        }
        #expect(mixed.hosts == ["www.amazon.com"])
        #expect(mixed.passwords.map(\.itemID) == [Fixtures.amazonRetail.id])
    }

    @Test("a password, a one-time code and text are refused for an http page, even when chosen")
    func releases() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let password = await harness.model.password(
            for: PasswordChoice(itemID: Fixtures.amazonRetail.id, userName: Fixtures.email),
            identifiers: [Self.plainShop])
        #expect(Self.isInsecurePage(password.refusal, "www.amazon.com"))
        let code = await harness.model.oneTimeCode(
            for: FieldChoice(itemID: Fixtures.amazonRetail.id, fieldID: Fixtures.id(103)),
            identifiers: [Self.plainShop])
        #expect(Self.isInsecurePage(code.refusal, "www.amazon.com"))
        let text = await harness.model.textToInsert(
            for: TextChoice(itemID: Fixtures.library.id, fieldID: Fixtures.id(501)), identifiers: [Self.library])
        #expect(Self.isInsecurePage(text.refusal, "library.example.org"))
        let pin = await harness.model.textToInsert(
            for: TextChoice(itemID: Fixtures.library.id, fieldID: Fixtures.id(504)), identifiers: [Self.library])
        #expect(Self.isInsecurePage(pin.refusal, "library.example.org"))

        // The same requests on the https page, and from the app's domain, release as before.
        #expect(
            try await harness.model.password(
                for: PasswordChoice(itemID: Fixtures.amazonRetail.id, userName: Fixtures.email),
                identifiers: [Self.secureShop]
            ).value.password == "retail-password")
        #expect(
            try await harness.model.textToInsert(
                for: TextChoice(itemID: Fixtures.library.id, fieldID: Fixtures.id(501)),
                identifiers: [Fixtures.domain("library.example.org")]
            ).value == TextToInsert("2 1234 56789 0"))
    }

    @Test("one-time code and text lists for an http page are refused")
    func lists() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        let codes = await harness.model.oneTimeCodeList(for: [Self.plainShop])
        guard case .refused(let codeRefusal) = codes, Self.isInsecurePage(codeRefusal, "www.amazon.com") else {
            Issue.record("\(codes)")
            return
        }
        let text = await harness.model.textInsertionList(for: [Self.library])
        guard case .refused(let textRefusal) = text, Self.isInsecurePage(textRefusal, "library.example.org") else {
            Issue.record("\(text)")
            return
        }
    }

    @Test("a login typed into an http page is not saved, asked or unasked, and no password is generated for one")
    func saveAndGenerate() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        let request = SavePasswordRequest(
            serviceIdentifier: Fixtures.url("http://shop.example.net/login"), userName: "pat", password: "pw")
        #expect(Self.isInsecurePage(await harness.model.savePasswordPlan(for: request).refusal, "shop.example.net"))
        #expect(
            Self.isInsecurePage(
                await harness.model.savePassword(request, to: .newItem).refusal, "shop.example.net"))
        #expect(
            Self.isInsecurePage(
                await harness.model.savePassword(request, to: .existingItem(Fixtures.amazonRetail.id)).refusal,
                "shop.example.net"))
        #expect(
            Self.isInsecurePage(
                await harness.model.savePasswordWithoutInteraction(request).refusal, "shop.example.net"))
        #expect(await harness.vault.saves.isEmpty)

        let generated = await harness.model.generatePassword(
            for: GeneratePasswordRequest(serviceIdentifier: Fixtures.url("http://shop.example.net/signup")))
        #expect(Self.isInsecurePage(generated.refusal, "shop.example.net"))
        #expect(
            (try? await harness.model.generatePassword(
                for: GeneratePasswordRequest(serviceIdentifier: Fixtures.url("https://shop.example.net/signup"))
            ).value) != nil)
        #expect((try? await harness.model.generatePassword().value) != nil)
    }

    /// A QuickType identity is a domain, so it is unaffected; one handed back as an `http` URL is refused.
    @Test("published identities are unaffected, and an http URL in an identity's place is refused")
    func identities() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let passwords = try await harness.publishedPasswords()
        let bank = try #require(passwords.first { $0.recordIdentifier.itemID == Fixtures.bank.id })
        #expect(try await harness.model.passwordWithoutInteraction(for: bank.handedBack).value.password != "")
        var asURL = bank.handedBack
        asURL.serviceIdentifier = Fixtures.url("http://\(bank.host)/")
        #expect(Self.isInsecurePage(await harness.model.passwordWithoutInteraction(for: asURL).refusal, bank.host))
    }
}
