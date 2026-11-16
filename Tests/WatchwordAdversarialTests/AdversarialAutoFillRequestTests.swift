import Foundation
import Testing
import WatchwordAutoFill
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

/// Cross-site release attempts through every request the credential provider answers (PRD SEC6, F11.1, F11.4, F11.7;
/// docs/04-test-plan.md §6.3 and §6.7). `AdversarialMatchingTests` and `AdversarialPhishingTests` attack the gate;
/// these attack what is built on it, so a request type that forgot to ask the gate fails here.
@Suite("Adversarial: AutoFill request model", .tags(.adversarial))
struct AdversarialAutoFillRequestTests {
    typealias Fixtures = AutoFillFixtures

    // MARK: - The sweep

    /// Relying party IDs a page behind `identifier` could be asking as: the identifier itself and, for a web URL,
    /// its host. The system only lets a page name a relying party its own origin is entitled to, and the model
    /// relies on that for the pairing of page and relying party (an assertion is bound to its relying party by the
    /// signature in any case), so a host buried in a `javascript:` or `data:` identifier is not an origin and is
    /// not tried.
    static func relyingParties(for identifier: ServiceIdentifier) -> [String] {
        var candidates = [identifier.identifier]
        if let components = URLComponents(string: identifier.identifier), let host = components.host,
            ["http", "https"].contains(components.scheme?.lowercased() ?? "")
        {
            candidates.append(host)
        }
        return candidates
    }

    /// Asks for everything `item` holds, through every request type that releases a secret, as a page behind
    /// `identifiers` could cause it to be asked. Returns a description of each release that succeeded.
    ///
    /// The requests made without the person carry an identity the system hands back, not the page. The sweep puts
    /// the page's identifier in the identity's place all the same: that is what an adapter that confused the two
    /// would send, and it must release nothing a look-alike or another site could use. What the system really hands
    /// back is covered by `quickTypeIdentityIsRightEverywhere`.
    static func releases(
        of item: Item, to identifiers: [ServiceIdentifier], model: CredentialProviderModel
    ) async -> [String] {
        var released: [String] = []
        let names = Set(item.loginNames + ["", "admin"])
        for name in names {
            if case .success = await model.password(
                for: PasswordChoice(itemID: item.id, userName: name), identifiers: identifiers)
            {
                released.append("password by choice (\(item.title))")
            }
            for identifier in identifiers {
                let request = PasswordIdentityRequest(
                    serviceIdentifier: identifier, user: name, recordIdentifier: RecordIdentifier(itemID: item.id).text)
                if case .success = await model.passwordWithoutInteraction(for: request) {
                    released.append("password without interaction (\(item.title))")
                }
            }
        }
        for field in item.fields {
            let choice = FieldChoice(itemID: item.id, fieldID: field.id)
            let record = RecordIdentifier(itemID: item.id, fieldID: field.id).text
            if case .success = await model.oneTimeCode(for: choice, identifiers: identifiers) {
                released.append("one-time code by choice (\(item.title))")
            }
            for part in [TextPart.whole, .recoveryCode(index: 0)] {
                if case .success = await model.textToInsert(
                    for: TextChoice(itemID: item.id, fieldID: field.id, part: part), identifiers: identifiers)
                {
                    released.append("text of \(field.kind.rawValue) (\(item.title))")
                }
            }
            for identifier in identifiers {
                for label in Set(item.loginNames + ["", "Watchword"]) {
                    if case .success = await model.oneTimeCodeWithoutInteraction(
                        for: OneTimeCodeIdentityRequest(
                            serviceIdentifier: identifier, label: label, recordIdentifier: record))
                    {
                        released.append("one-time code without interaction (\(item.title))")
                    }
                }
                guard field.kind == .passkey, let credential = try? field.passkeyCredential() else { continue }
                for relyingParty in relyingParties(for: identifier) {
                    for allowed in [[], [credential.credentialID]] {
                        let request = PasskeyAssertionRequest(
                            relyingPartyID: relyingParty, clientDataHash: Fixtures.clientDataHash(),
                            allowedCredentialIDs: allowed)
                        if case .success = await model.passkeyAssertion(
                            for: choice, request: request, presence: .verified)
                        {
                            released.append("passkey assertion by choice (\(item.title))")
                        }
                        if case .success = await model.passkeyAssertionWithoutInteraction(
                            request: request,
                            identity: PasskeyIdentityRequest(
                                recordIdentifier: record, credentialID: credential.credentialID),
                            presence: .verified)
                        {
                            released.append("passkey assertion without interaction (\(item.title))")
                        }
                    }
                }
            }
        }
        return released
    }

    // MARK: - A hostile page

    static let hostileIdentifiers: [ServiceIdentifier] = [
        // Look-alikes of saved sites (docs/05-anti-phishing.md).
        Fixtures.domain("arnazon.com"), Fixtures.domain("amaz0n.com"), Fixtures.domain("\u{0430}mazon.com"),
        Fixtures.domain("amazon.com.evil.example"), Fixtures.domain("secure-amazon.example"),
        Fixtures.domain("amazom.com"), Fixtures.domain("xn--mazon-1nf.com"),
        Fixtures.domain("firstbank.co.uk.evil.example"), Fixtures.domain("firstbamk.co.uk"),
        Fixtures.domain("g00gle.com"), Fixtures.domain("google.com.evil.example"),
        Fixtures.domain("signin.aws.amazon.com.evil.example"), Fixtures.domain("library.example.org.evil.example"),
        // Identifiers that are not what they seem.
        Fixtures.url("https://amazon.com@evil.example/"), Fixtures.url("https://www.amazon.com:pw@evil.example/"),
        Fixtures.url("https://x.amazon%2Ecom/"), Fixtures.url("https://evil.example/?q=amazon.com"),
        Fixtures.url("https://evil.example/amazon.com"), Fixtures.url("https://evil.example#google.com"),
        Fixtures.url("file:///amazon.com"), Fixtures.url("javascript://google.com/%0aalert(1)"),
        Fixtures.url("data:text/html,google.com"), Fixtures.domain("amazon.com\u{200B}"),
        Fixtures.domain("amazon.com/"), Fixtures.domain("google.com:443"), Fixtures.domain(""),
        Fixtures.domain("com"), Fixtures.domain("co.uk"), Fixtures.domain("example.org"),
        // An unrelated site with nothing saved.
        Fixtures.url("https://evil.example/login"),
    ]

    /// A6, a malicious page or app: it controls the service identifier and relying party ID the system reports, and
    /// can cause any request type to be made, including for items and fields it names itself. Nothing may be
    /// released to it, whichever request it rides and whichever item is asked for.
    @Test("no request type releases anything to a hostile or look-alike identifier", arguments: hostileIdentifiers)
    func hostileIdentifier(_ identifier: ServiceIdentifier) async {
        let harness = AutoFillHarness(items: Fixtures.all)
        for item in Fixtures.all {
            let released = await Self.releases(of: item, to: [identifier], model: harness.model)
            #expect(released.isEmpty, "\(identifier.identifier): \(released)")
        }
        // And the lists that precede a choice offer nothing to choose.
        if case .list(let list) = await harness.model.credentialList(for: [identifier]) {
            #expect(list.passwords.isEmpty && list.passkeys.isEmpty)
            #expect(list.suggested == nil)
        }
        if case .list(let codes) = await harness.model.oneTimeCodeList(for: [identifier]) {
            #expect(codes.isEmpty)
        }
        if case .list(let text) = await harness.model.textInsertionList(for: [identifier]) {
            #expect(text.items.isEmpty)
        }
        #expect(await harness.vault.saves.isEmpty)
    }

    /// A2, an attacker on the network path (a café's Wi-Fi, a hostile router), serves or rewrites a page of a site the
    /// person really has an account on, loaded over plain `http`: whatever is filled there, the attacker reads, and the
    /// page's scripts and form are the attacker's. The host is right, so the scope check alone would fill. The owner's
    /// rule (PRD F6.9, 2026-11-16): nothing that puts a secret into the page is done for it, the person's explicit
    /// choice included, and no login is saved from it. The same requests over `https` release, which keeps the sweep
    /// honest.
    @Test("a page at http://bank.example gets nothing of an item scoped bank.example, even when it is chosen")
    func plainHTTPPage() async throws {
        let item = Item(
            id: Fixtures.id(9), vaultID: Fixtures.vaultID, title: "Bank", scopes: [ServiceScope(host: "bank.example")],
            fields: [
                Field(id: Fixtures.id(901), kind: .username, label: "Username", value: "pat"),
                Field(id: Fixtures.id(902), kind: .password, label: "Password", value: "bank-password"),
                Fixtures.totp("bank-example-totp-01", id: Fixtures.id(903)),
                Field(id: Fixtures.id(904), kind: .accountNumber, label: "Account", value: "12345678"),
            ], version: 1)
        let harness = AutoFillHarness(items: [item])
        for page in ["http://bank.example/login", "HTTP://BANK.example/", "http://www.bank.example/"] {
            let identifier = Fixtures.url(page)
            let released = await Self.releases(of: item, to: [identifier], model: harness.model)
            #expect(released.isEmpty, "\(page): \(released)")
            let list = await harness.model.credentialList(for: [identifier])
            let codes = await harness.model.oneTimeCodeList(for: [identifier])
            let text = await harness.model.textInsertionList(for: [identifier])
            #expect(list == .refused(.gate(.insecurePage(try HostNormalizer.normalize(identifier)))), "\(page)")
            #expect(codes == .refused(.gate(.insecurePage(try HostNormalizer.normalize(identifier)))), "\(page)")
            #expect(text == .refused(.gate(.insecurePage(try HostNormalizer.normalize(identifier)))), "\(page)")
            let save = SavePasswordRequest(serviceIdentifier: identifier, userName: "pat", password: "typed")
            #expect(await harness.model.savePassword(save, to: .existingItem(item.id)).refusal?.isGateRefusal == true)
            #expect(await harness.model.savePasswordWithoutInteraction(save).refusal?.isGateRefusal == true)
        }
        #expect(await harness.vault.saves.isEmpty)
        let secure = await Self.releases(
            of: item, to: [Fixtures.url("https://bank.example/login")], model: harness.model)
        #expect(!secure.isEmpty)
    }

    struct Site: Sendable, CustomTestStringConvertible {
        var identifier: ServiceIdentifier
        var legitimate: UUID

        var testDescription: String { identifier.identifier }
    }

    static let sites = [
        Site(identifier: Fixtures.url("https://www.amazon.com/ap/signin"), legitimate: Fixtures.amazonRetail.id),
        Site(identifier: Fixtures.url("https://signin.aws.amazon.com/signin"), legitimate: Fixtures.awsRoot.id),
        Site(identifier: Fixtures.domain("google.com"), legitimate: Fixtures.google.id),
        Site(identifier: Fixtures.url("https://www.firstbank.co.uk/login"), legitimate: Fixtures.bank.id),
        Site(identifier: Fixtures.domain("library.example.org"), legitimate: Fixtures.library.id),
    ]

    /// A6 again, as a legitimate site the person does have an account on: Amazon's page must not be able to obtain
    /// the bank's password, AWS's one-time code or Google's passkey assertion, by any request type, even when the
    /// request names the other item explicitly (a buggy or tampered list). The last expectation keeps the sweep
    /// honest: the same requests do release the site's own item.
    @Test("a real site receives its own item and nothing of any other item", arguments: sites)
    func crossSite(_ site: Site) async {
        let harness = AutoFillHarness(items: Fixtures.all)
        for item in Fixtures.all where item.id != site.legitimate {
            let released = await Self.releases(of: item, to: [site.identifier], model: harness.model)
            #expect(released.isEmpty, "\(item.title) on \(site.identifier.identifier): \(released)")
        }
        let own = Fixtures.all.first { $0.id == site.legitimate }!
        #expect(!(await Self.releases(of: own, to: [site.identifier], model: harness.model)).isEmpty)
    }

    /// A6: a hostile app that declares a real site among its associated domains only widens what it can ask for by
    /// that real site; adding hostile identifiers to the request must never unlock an item of a third site.
    @Test("extra identifiers in a request never widen what an item is released for")
    func identifierStuffing() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        let stuffed =
            [Fixtures.domain("library.example.org")] + Self.hostileIdentifiers
            + (0..<200).map { Fixtures.domain("filler\($0).example") }
        for item in Fixtures.all where item.id != Fixtures.library.id {
            let released = await Self.releases(of: item, to: stuffed, model: harness.model)
            #expect(released.isEmpty, "\(item.title): \(released)")
        }
    }

    /// A6 on a look-alike host, with the person present and trying to help: the extension is asked for the host's
    /// list and gets a warning with nothing to choose; there is no request, flag or presence level that turns the
    /// refusal into a release (F11.4, F11.7), and with no host named the password and code stay withheld.
    @Test("a refusal cannot be overridden: no presence level, repeated request or missing identifier releases it")
    func noOverride() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        let lookAlike = [Fixtures.domain("arnazon.com")]
        guard case .warning(let warning) = await harness.model.credentialList(for: lookAlike) else {
            Issue.record("a look-alike host was not warned about")
            return
        }
        #expect(warning.impersonating == ["amazon.com"])
        let choice = PasswordChoice(itemID: Fixtures.amazonRetail.id, userName: Fixtures.email)
        for _ in 0..<3 {
            #expect(await harness.model.password(for: choice, identifiers: lookAlike).refusal?.isGateRefusal == true)
        }
        #expect(await harness.model.password(for: choice, identifiers: []) == .refused(.noServiceIdentifier))
        #expect(
            await harness.model.oneTimeCode(
                for: FieldChoice(itemID: Fixtures.amazonRetail.id, fieldID: Fixtures.id(103)), identifiers: [])
                == .refused(.noServiceIdentifier))
        // The text-insertion request, which the system makes with no host, is not a way round either.
        #expect(
            await harness.model.textToInsertWithoutHost(
                for: TextChoice(itemID: Fixtures.amazonRetail.id, fieldID: Fixtures.id(102)))
                == .refused(.fieldWithheld(.password)))
        #expect(
            await harness.model.textToInsertWithoutHost(
                for: TextChoice(itemID: Fixtures.amazonRetail.id, fieldID: Fixtures.id(103)))
                == .refused(.fieldWithheld(.totp)))
        #expect(
            await harness.model.textToInsertWithoutHost(
                for: TextChoice(itemID: Fixtures.google.id, fieldID: Fixtures.id(302)))
                == .refused(.fieldWithheld(.passkey)))
    }

    /// A6 on a look-alike host that has already phished the password by hand entry and now asks for "a backup
    /// code", "your security answer" or "your PIN". The person invokes the system's text insertion, which names no
    /// site, so there is no host to check and no warning to show. Nothing that signs anyone in may leave that way
    /// (F11.4's reasoning, for every replayable secret), and an adapter that dropped the identifiers of a
    /// host-checked request must get a refusal, not the hand-picked answer.
    @Test("with no host named, no secret of any kind can be inserted as text")
    func hostlessTextReleasesNoSecret() async throws {
        var everything = Fixtures.library
        everything.id = Fixtures.id(70)
        everything.fields = FieldKind.allCases.enumerated().map { index, kind in
            switch kind {
            case .totp: return Fixtures.totp("everything-secret-00", id: Fixtures.id(700 + index))
            case .passkey:
                return Fixtures.passkey(relyingParty: "library.example.org", seed: 70, id: Fixtures.id(700 + index))
            case .recoveryCodes:
                return Field(
                    id: Fixtures.id(700 + index), kind: kind, label: kind.rawValue, value: "aaaa-1111\nbbbb-2222")
            default:
                return Field(
                    id: Fixtures.id(700 + index), kind: kind, label: kind.rawValue, value: "value-\(kind.rawValue)")
            }
        }
        let harness = AutoFillHarness(items: Fixtures.all + [everything])
        guard case .list(let list) = await harness.model.textInsertionListWithoutHost() else {
            Issue.record("no list")
            return
        }
        #expect(!list.hostVerified)
        #expect(list.items.flatMap(\.fields).allSatisfy { !$0.kind.isSecret })
        for item in Fixtures.all + [everything] {
            for field in item.fields {
                for part in [TextPart.whole, .recoveryCode(index: 0)] {
                    let choice = TextChoice(itemID: item.id, fieldID: field.id, part: part)
                    let outcome = await harness.model.textToInsertWithoutHost(for: choice)
                    if field.kind.isSecret {
                        #expect(outcome == .refused(.fieldWithheld(field.kind)), "\(item.title) \(field.kind)")
                    }
                    // The host-checked request with its identifiers lost is refused outright, secret or not.
                    #expect(
                        await harness.model.textToInsert(for: choice, identifiers: [])
                            == .refused(.noServiceIdentifier))
                }
            }
        }
        #expect(await harness.model.textInsertionList(for: []) == .refused(.noServiceIdentifier))
        // The same code, asked for where the page is known to be a look-alike, is refused by the gate with the
        // assessment; asked for on Google itself, it is released.
        let code = TextChoice(itemID: Fixtures.google.id, fieldID: Fixtures.id(303), part: .recoveryCode(index: 0))
        #expect(
            await harness.model.textToInsert(for: code, identifiers: [Fixtures.domain("g00gle.com")])
                .refusal?.isGateRefusal == true)
        #expect(
            await harness.model.textToInsert(for: code, identifiers: [Fixtures.domain("google.com")])
                == .success("1111-2222"))
    }

    // MARK: - QuickType: the request that names no page

    /// The hosts the property test builds scopes from and probes with: three sites, a country-code one, and two
    /// tenants of a shared host.
    static let quickTypeHosts = [
        "shop.example", "www.shop.example", "pay.shop.example", "admin.pay.shop.example", "other.example",
        "firstbank.co.uk", "www.firstbank.co.uk", "acme.zendesk.com", "evil.zendesk.com", "zendesk.com",
    ]

    /// A6, as any page that shares a site with an account of the person's: another service of the same company
    /// (scenario S1), a tenant of the same shared host, a forgotten subdomain taken over. It is helped by the
    /// operating system, not by a bug: which pages a stored identity is suggested on is the system's own matching,
    /// as wide as the registrable domain, and a tap hands the identity back without saying which page it came from.
    /// So an identity must be answered only if its item is the right answer on *every* page of its site. The oracle
    /// is the gate itself, asked page by page: for each identity the model publishes or answers, on each probe host
    /// of the identity's site, the item must be released by choice there and be the only account offered under
    /// that name. And publishing must agree with answering: nothing unpublished is answered when handed back.
    @Test("a QuickType identity is answered only if its item is the right answer on every page of its site")
    func quickTypeIdentityIsRightEverywhere() async throws {
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 2026))
        let users = ["pat@example.com", "work@example.com"]
        var answered = 0
        for round in 0..<TestEnvironment.iterations(standard: 120, long: 4_000) {
            var items: [Item] = []
            for index in 0..<Int.random(in: 1...5, using: &generator) {
                var scopes: [ServiceScope] = []
                for _ in 0..<Int.random(in: 1...2, using: &generator) {
                    var excluded: Set<String> = []
                    if Int.random(in: 0..<5, using: &generator) == 0 {
                        excluded.insert(Self.quickTypeHosts.randomElement(using: &generator)!)
                    }
                    scopes.append(
                        ServiceScope(
                            host: Self.quickTypeHosts.randomElement(using: &generator)!,
                            includeSubdomains: Int.random(in: 0..<4, using: &generator) != 0, excludedHosts: excluded))
                }
                var item = Item(
                    id: Fixtures.id(1_000 + index), vaultID: Fixtures.vaultID, title: "Item \(index)", scopes: scopes,
                    fields: [
                        Field(kind: .email, label: "Email", value: users.randomElement(using: &generator)!),
                        Field(kind: .password, label: "Password", value: "password-\(round)-\(index)"),
                        Fixtures.totp("totp-secret-item-\(index)-0", id: Fixtures.id(2_000 + index)),
                    ], version: 1)
                switch Int.random(in: 0..<12, using: &generator) {
                case 0: item.archived = true
                case 1: item.excludedFromSuggestions = true
                case 2: item.trashedAt = Fixtures.now
                default: break
                }
                items.append(item)
            }
            let harness = AutoFillHarness(items: [])
            for item in items { await harness.vault.plant(item) }
            let published = try await harness.publishedIdentities()

            // Every candidate identity an old store could hold: each item, each of its scope hosts, each user.
            for item in items {
                for host in Set(item.scopes.map(\.host)) {
                    let user = item.loginNames[0]
                    let password = PasswordIdentity(
                        host: host, user: user, recordIdentifier: RecordIdentifier(itemID: item.id), rank: 0)
                    let code = OneTimeCodeIdentity(
                        host: host, label: user,
                        recordIdentifier: RecordIdentifier(itemID: item.id, fieldID: item.fields[2].id))
                    let passwordOutcome = await harness.model.passwordWithoutInteraction(for: password.handedBack)
                    let codeOutcome = await harness.model.oneTimeCodeWithoutInteraction(for: code.handedBack)
                    let isPublished = published.contains {
                        if case .password(let identity) = $0 {
                            return identity.host == host && identity.user == user
                                && identity.recordIdentifier == password.recordIdentifier
                        }
                        return false
                    }
                    let codeIsPublished = published.contains { $0 == .oneTimeCode(code) }
                    var passwordAnswered = false
                    if case .success = passwordOutcome { passwordAnswered = true }
                    var codeAnswered = false
                    if case .success = codeOutcome { codeAnswered = true }
                    #expect(passwordAnswered == isPublished, "round \(round): \(item.title) at \(host)")
                    #expect(codeAnswered == codeIsPublished, "round \(round): \(item.title) code at \(host)")
                    guard passwordAnswered || codeAnswered else { continue }
                    answered += 1

                    // The pages the system could have offered it on: every host of the identity's site, taken
                    // as widely as the system might (the last two labels, three under `co.uk`), parents and
                    // siblings of the identity's own host included.
                    let labels = host.split(separator: ".")
                    let site = labels.suffix(host.hasSuffix(".co.uk") ? 3 : 2).joined(separator: ".")
                    let probes = (Self.quickTypeHosts + Self.quickTypeHosts.map { "zz." + $0 } + ["zz.\(host)"])
                        .filter { $0 == site || $0.hasSuffix("." + site) }
                    for probe in probes {
                        let page = [Fixtures.domain(probe)]
                        let byChoice = await harness.model.password(
                            for: PasswordChoice(itemID: item.id, userName: user), identifiers: page)
                        guard case .success = byChoice else {
                            Issue.record("round \(round): \(item.title) answered for \(host), refused on \(probe)")
                            continue
                        }
                        guard case .list(let list) = await harness.model.credentialList(for: page) else {
                            Issue.record("round \(round): no list on \(probe)")
                            continue
                        }
                        #expect(
                            list.passwords.filter { $0.userName == user }.map(\.itemID) == [item.id],
                            "round \(round): \(user) is not one account on \(probe)")
                        #expect(!list.otherAccounts.contains { $0.itemID == item.id })
                    }
                }
            }
        }
        // The generator does produce vaults in which something is answered; the test is not vacuous.
        #expect(answered > 0)
    }

    /// A6 on the AWS console sign-in page (scenario S1), with a credential identity store that is out of date: the
    /// retail identity was published for `amazon.com` before the AWS item reached this device by sync, or before
    /// the person excluded a host or narrowed the scope on another device. The system offers the stale suggestion
    /// under the same email as the AWS account; the person taps it. The request is exactly what was stored, and it
    /// must release neither the retail password nor the retail one-time code.
    @Test("S1 with a stale identity store: the retail identity, handed back as it was stored, releases nothing")
    func staleQuickTypeIdentity() async throws {
        var excluding = Fixtures.amazonRetail
        excluding.scopes = [ServiceScope(host: "amazon.com", excludedHosts: ["aws.amazon.com"])]
        var exact = Fixtures.amazonRetail
        exact.scopes = [ServiceScope(host: "amazon.com", includeSubdomains: false)]
        var excluded = Fixtures.amazonRetail
        excluded.excludedFromSuggestions = true
        var archived = Fixtures.amazonRetail
        archived.archived = true
        var renamed = Fixtures.amazonRetail
        renamed.fields[0].value = "pat@new.example"

        let changes: [(String, [Item])] = [
            ("the AWS item arrives", [Fixtures.amazonRetail, Fixtures.awsRoot]),
            ("a host is excluded", [excluding]), ("the scope loses its subdomains", [exact]),
            ("the item is excluded from AutoFill", [excluded]), ("the item is archived", [archived]),
            ("the user name changes", [renamed]),
        ]
        for (what, after) in changes {
            let harness = AutoFillHarness(items: [Fixtures.amazonRetail])
            let stored = try await harness.publishedIdentities()
            #expect(stored.count == 2)
            // The vault changes underneath the store (sync, or the app on another device); nothing republishes.
            for item in after { await harness.vault.plant(item) }
            for identity in stored {
                switch identity {
                case .password(let password):
                    if case .success = await harness.model.passwordWithoutInteraction(for: password.handedBack) {
                        Issue.record("the retail password was released after \(what)")
                    }
                case .oneTimeCode(let code):
                    if case .success = await harness.model.oneTimeCodeWithoutInteraction(for: code.handedBack) {
                        Issue.record("the retail code was released after \(what)")
                    }
                case .passkey:
                    Issue.record("unexpected passkey identity")
                }
            }
            // And the next publication takes them out of the store.
            #expect(Set(stored).isDisjoint(with: try await harness.publishedIdentities()), "\(what)")
        }
    }

    // MARK: - Passkeys

    /// A6: a page asks for an assertion as a relying party spelled to collide with a saved one after some
    /// normalisation the authenticator might have done: other case, a trailing dot, whitespace, a homograph, a
    /// public suffix, an IP address. Each is refused before the vault is read, so nothing is hashed or signed for it.
    @Test(
        "a relying party ID in any spelling but the canonical one is refused before the vault is read",
        arguments: [
            "Google.com", "GOOGLE.COM", "google.com.", " google.com", "google.com ", "g\u{043E}\u{043E}gle.com",
            "google.com\u{200B}", "https://google.com", "google.com/", "google.com:443", "com", "co.uk", "",
            "142.250.0.1", "[::1]", "google.com%00", "goo\u{00AD}gle.com",
        ])
    func relyingPartySpelling(_ relyingParty: String) async {
        let harness = AutoFillHarness(items: Fixtures.all)
        let credentialID = (try? Fixtures.google.fields[1].passkeyCredential().credentialID) ?? Data()
        let request = PasskeyAssertionRequest(relyingPartyID: relyingParty, clientDataHash: Fixtures.clientDataHash())
        let choice = FieldChoice(itemID: Fixtures.google.id, fieldID: Fixtures.id(302))
        guard
            case .refused(.passkey(.relyingPartyRejected)) = await harness.model.passkeyAssertion(
                for: choice, request: request, presence: .verified)
        else {
            Issue.record("\(relyingParty) was not rejected")
            return
        }
        guard
            case .refused(.passkey(.relyingPartyRejected)) = await harness.model.passkeyAssertionWithoutInteraction(
                request: request,
                identity: PasskeyIdentityRequest(
                    recordIdentifier: RecordIdentifier(itemID: Fixtures.google.id, fieldID: Fixtures.id(302)).text,
                    credentialID: credentialID), presence: .verified)
        else {
            Issue.record("\(relyingParty) was not rejected without interaction")
            return
        }
        let registration = PasskeyRegistrationRequest(
            relyingPartyID: relyingParty, user: PasskeyUser(handle: Data("h".utf8), name: "pat"),
            clientDataHash: Fixtures.clientDataHash())
        #expect(
            await harness.model.registerPasskey(registration, destination: .newItem, presence: .verified).refusal != nil
        )
        #expect(await harness.vault.readCount == 0)
        #expect(await harness.vault.saves.isEmpty)
    }

    /// A6: a page that controls every field of a conditional (silent) registration request must not be able to use
    /// it to plant items or credentials in the vault. The only thing such a request can do is add a passkey to the
    /// one password login already saved for that very relying party and user.
    @Test("a silent registration request cannot plant an item, whatever it claims")
    func conditionalRegistrationCannotPlant() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        for relyingParty in ["evil.example", "amazon.com.evil.example", "arnazon.com", "amazon.co.uk", "example.org"] {
            for name in [Fixtures.email, "", "admin", "pat"] {
                let request = PasskeyRegistrationRequest(
                    relyingPartyID: relyingParty, user: PasskeyUser(handle: Data("h".utf8), name: name),
                    clientDataHash: Fixtures.clientDataHash())
                let outcome = await harness.model.registerPasskeyWithoutInteraction(request)
                #expect(outcome == .refused(.noItemToUpgrade), "\(relyingParty) \(name): \(outcome)")
            }
        }
        #expect(await harness.vault.saves.isEmpty)
        #expect(await harness.vault.allItems == Fixtures.all)
    }

    /// A6, against availability: a page under the item's relying party (the site after an XSS, or any same-site
    /// subdomain) issues conditional-create requests in a loop. Every field of the request is the page's: a fresh
    /// user handle each time, any relying party ID its origin may claim. Each accepted request would add a passkey
    /// field and a history entry holding all the fields before it, in a history that is never pruned (F1.4), until
    /// the item passes its payload limit and refuses every later edit, on every device. Nobody is asked, so the
    /// bound has to be in the model: one upgrade per item, ever.
    @Test("a loop of silent registrations adds one passkey to an item, whatever each request claims")
    func conditionalRegistrationCannotGrowAnItem() async throws {
        var shop = Fixtures.library
        shop.scopes = [ServiceScope(host: "shop.example")]
        let harness = AutoFillHarness(items: [shop])
        var accepted = 0
        for round in 0..<300 {
            let relyingParty = ["shop.example", "www.shop.example", "t\(round).shop.example"][round % 3]
            let request = PasskeyRegistrationRequest(
                relyingPartyID: relyingParty, user: PasskeyUser(handle: Data("handle-\(round)".utf8), name: "pat"),
                clientDataHash: Fixtures.clientDataHash(UInt8(truncatingIfNeeded: round)))
            switch await harness.model.registerPasskeyWithoutInteraction(request) {
            case .success: accepted += 1
            case .refused(.noItemToUpgrade): break
            case let other: Issue.record("round \(round): \(other)")
            }
        }
        #expect(accepted == 1)
        let item = try #require(await harness.vault.item(shop.id))
        #expect(item.fields.filter { $0.kind == .passkey }.count == 1)
        #expect(item.history.count == 1)
        #expect(await harness.vault.saves.count == 1)
        #expect(await harness.vault.allItems.count == 1)
        // A passkey field that does not even decode counts: the item has had its upgrade.
        var planted = Fixtures.bank
        planted.fields.append(Field(kind: .passkey, label: "Broken", value: "{}"))
        let other = AutoFillHarness(items: [planted])
        #expect(
            await other.model.registerPasskeyWithoutInteraction(
                PasskeyRegistrationRequest(
                    relyingPartyID: "firstbank.co.uk", user: PasskeyUser(handle: Data("h".utf8), name: "40012345"),
                    clientDataHash: Fixtures.clientDataHash())) == .refused(.noItemToUpgrade))
    }

    /// A6, with the person's help: a page that may claim the registrable domain as its relying party asks for a
    /// passkey and proposes the person's existing login as the place to keep it. That login is scoped to one exact
    /// host; adding the passkey so that it worked would mean giving the item the relying party as a scope, from the
    /// extension, on a page's request, after which its *password* would be offered wherever that scope reaches. A
    /// scope is added in the app and nowhere else (F11.7): no registration, silent or confirmed, changes one.
    @Test("no passkey registration, silent or confirmed, changes the scopes of an existing item")
    func registrationNeverAddsAScope() async throws {
        var login = Fixtures.library
        login.id = Fixtures.id(62)
        login.scopes = [ServiceScope(host: "www.shop.example", includeSubdomains: false)]
        let harness = AutoFillHarness(items: Fixtures.all + [login])
        let before = await harness.vault.allItems
        let relyingParties = ["shop.example", "www.shop.example", "amazon.com", "aws.amazon.com", "google.com"]
        for relyingParty in relyingParties {
            for name in ["pat", Fixtures.email] {
                let request = PasskeyRegistrationRequest(
                    relyingPartyID: relyingParty, user: PasskeyUser(handle: Data("h-\(relyingParty)".utf8), name: name),
                    clientDataHash: Fixtures.clientDataHash())
                _ = await harness.model.registerPasskeyWithoutInteraction(request)
                for item in before {
                    _ = await harness.model.registerPasskey(
                        request, destination: .existingItem(item.id), presence: .verified)
                }
                _ = await harness.model.registerPasskey(
                    request, destination: .newItemBesideExisting, presence: .verified)
                _ = await harness.model.registerPasskey(request, destination: .newItem, presence: .verified)
            }
        }
        for original in before {
            #expect(await harness.vault.item(original.id)?.scopes == original.scopes, "\(original.title)")
        }
        // The exact-host login took a passkey only as its own relying party.
        let stored = try #require(await harness.vault.item(login.id))
        for field in stored.fields where field.kind == .passkey {
            #expect(try field.passkeyCredential().relyingPartyID == "www.shop.example")
        }
        // And every item created is scoped to a relying party that asked, or exactly as an item the person scoped.
        let allowed = Set(before.flatMap(\.scopes)).union(relyingParties.map { ServiceScope(host: $0) })
        let created = await harness.vault.allItems.filter { item in !before.contains { $0.id == item.id } }
        #expect(!created.isEmpty)
        for item in created {
            #expect(item.scopes.count == 1)
            #expect(allowed.contains(item.scopes[0]), "\(item.scopes)")
        }
    }

    // MARK: - Records no honest client wrote

    /// A vault that returns what it is given, duplicates included: `FakeCredentialVault` keys its items by ID, as
    /// the stores do today, and so cannot hold the state this adversary creates.
    struct LooseVault: CredentialVault {
        let items: [Item]
        func credentialItems() async throws -> [Item] { items }
        func confirmUnlocked() async throws {}
        func defaultVaultID() async throws -> UUID { AutoFillFixtures.vaultID }
        func isBackedUp() async throws -> Bool { true }
        func saveCredentialItem(_ item: Item, replacingVersion: UInt64?) async throws -> Item {
            throw CredentialVaultError.failed("read-only")
        }
    }

    /// A4, a malicious member of a shared vault, who chooses the record ID of an item they write: they plant an
    /// item whose ID equals the victim's bank item and whose scope is their own site. Every request names an item
    /// by its ID alone, so the gate could be satisfied by the planted twin ("an item with this ID matches
    /// `evil.example`") while the secret is read from the victim's item. An ID two readable items share must name
    /// neither: nothing is listed, released, written or published for it, on the attacker's site or the bank's.
    /// And a twin must not unseat the item it copies from the ranking, or planting one for the AWS item would put
    /// the retail login back on the console.
    @Test("an item ID that two readable items share releases nothing, and still ranks")
    func duplicatedItemID() async throws {
        var twin = Fixtures.library
        twin.id = Fixtures.bank.id
        twin.title = "Planted"
        twin.scopes = [ServiceScope(host: "evil.example")]
        var awsTwin = Fixtures.library
        awsTwin.id = Fixtures.awsRoot.id
        awsTwin.scopes = [ServiceScope(host: "evil.example")]
        let evil = Fixtures.url("https://evil.example/login")
        let bankSite = Fixtures.url("https://www.firstbank.co.uk/login")
        let console = Fixtures.url("https://signin.aws.amazon.com/signin")

        for order in [[Fixtures.bank, twin], [twin, Fixtures.bank]] {
            let items = order + [Fixtures.amazonRetail, Fixtures.awsRoot, awsTwin]
            let model = CredentialProviderModel(
                vault: LooseVault(items: items), clock: FakeClock(Fixtures.now),
                random: SeededGenerator(seed: 5))
            for site in [evil, bankSite, console] {
                for item in [Fixtures.bank, twin, Fixtures.awsRoot] {
                    let released = await Self.releases(of: item, to: [site], model: model)
                    #expect(released.isEmpty, "\(item.title) on \(site.identifier): \(released)")
                }
                if case .list(let list) = await model.credentialList(for: [site]) {
                    #expect(list.passwords.isEmpty, "\(site.identifier)")
                }
                #expect(await model.oneTimeCodeList(for: [site]) == .list([]))
            }
            #expect(
                await model.password(
                    for: PasswordChoice(itemID: Fixtures.bank.id, userName: "40012345"), identifiers: [evil])
                    == .refused(.duplicateRecord))
            #expect(
                await model.passwordWithoutInteraction(
                    for: PasswordIdentity(
                        host: "firstbank.co.uk", user: "40012345",
                        recordIdentifier: RecordIdentifier(itemID: Fixtures.bank.id), rank: 7
                    ).handedBack) == .refused(.duplicateRecord))
            #expect(
                await model.textToInsertWithoutHost(
                    for: TextChoice(itemID: Fixtures.bank.id, fieldID: Fixtures.id(402)))
                    == .refused(.duplicateRecord))
            #expect(
                await model.markRecoveryCode(FieldChoice(itemID: Fixtures.bank.id, fieldID: Fixtures.id(405)), index: 0)
                    == .refused(.duplicateRecord))
            #expect(
                await model.savePassword(
                    SavePasswordRequest(serviceIdentifier: evil, userName: "40012345", password: "x"),
                    to: .existingItem(Fixtures.bank.id)) == .refused(.duplicateRecord))
            #expect(
                try await model.handle(.unusedPassword(domain: "firstbank.co.uk", userName: "40012345")).value.changes
                    .isEmpty)
            // The twinned AWS item still keeps the retail login off the console.
            #expect(
                await model.password(
                    for: PasswordChoice(itemID: Fixtures.amazonRetail.id, userName: Fixtures.email),
                    identifiers: [console]
                ).refusal?.isGateRefusal == true)
            let published = CredentialIdentityPlanner.identities(for: items)
            #expect(
                !published.contains { [Fixtures.bank.id, Fixtures.awsRoot.id].contains($0.recordIdentifier.itemID) })
            // The item that shares no ID is untouched by all this.
            #expect(
                try await model.password(
                    for: PasswordChoice(itemID: Fixtures.amazonRetail.id, userName: Fixtures.email),
                    identifiers: [Fixtures.url("https://www.amazon.com/")]
                ).value.password == "retail-password")
        }
    }

    /// A2 or A3 at the keyboard of a device whose identity store is out of date: the person marked the bank item
    /// "exclude from AutoFill suggestions" on another device (PRD F6.8: reachable only by opening the app), the
    /// item has synced, the store has not been rewritten. The suggestion is still in the QuickType bar, and the
    /// extension's own list is one tap away. Neither may give the item up.
    @Test("an item excluded from AutoFill is not released for a stale identity, nor listed, nor chosen")
    func excludedItemIsUnreachable() async throws {
        let harness = AutoFillHarness(items: [Fixtures.bank, Fixtures.google])
        let stored = try await harness.publishedIdentities()
        #expect(stored.count == 3)
        var bank = Fixtures.bank
        bank.excludedFromSuggestions = true
        var google = Fixtures.google
        google.excludedFromSuggestions = true
        await harness.vault.plant(bank)
        await harness.vault.plant(google)

        for identity in stored {
            switch identity {
            case .password(let password):
                #expect(
                    await harness.model.passwordWithoutInteraction(for: password.handedBack)
                        == .refused(.itemNotInUse))
            case .oneTimeCode(let code):
                #expect(
                    await harness.model.oneTimeCodeWithoutInteraction(for: code.handedBack) == .refused(.itemNotInUse))
            case .passkey(let passkey):
                #expect(
                    await harness.model.passkeyAssertionWithoutInteraction(
                        request: PasskeyAssertionRequest(
                            relyingPartyID: passkey.relyingPartyID, clientDataHash: Fixtures.clientDataHash()),
                        identity: passkey.handedBack, presence: .verified) == .refused(.itemNotInUse))
            }
        }
        for (item, site) in [
            (bank, Fixtures.url("https://www.firstbank.co.uk/login")), (google, Fixtures.domain("google.com")),
        ] {
            #expect(await Self.releases(of: item, to: [site], model: harness.model).isEmpty)
            if case .list(let list) = await harness.model.credentialList(
                for: [site],
                passkey: PasskeyAssertionRequest(
                    relyingPartyID: "google.com", clientDataHash: Fixtures.clientDataHash()))
            {
                #expect(list.isEmpty)
            }
            if case .list(let text) = await harness.model.textInsertionList(for: [site]) {
                #expect(text.items.isEmpty)
            }
        }
        guard case .list(let handPicked) = await harness.model.textInsertionListWithoutHost() else {
            Issue.record("no list")
            return
        }
        #expect(handPicked.items.isEmpty)
        #expect(try await harness.publishedIdentities().isEmpty)
    }

    /// A4, a malicious member of a shared vault (or A7, a crafted import): they can write any item into a vault the
    /// victim can read. An item with a scope spanning unrelated owners must not make its credential appear on
    /// every site under that suffix; the scope policy holds at use as well as at entry (F11.2).
    @Test("an over-broad scope planted in a stored item matches nothing")
    func plantedBroadScope() async throws {
        var planted = Fixtures.library
        planted.id = Fixtures.id(80)
        planted.title = "Planted"
        planted.scopes = [ServiceScope(host: "com"), ServiceScope(host: "co.uk"), ServiceScope(host: "github.io")]
        var half = Fixtures.library
        half.id = Fixtures.id(81)
        half.title = "Half"
        half.scopes = [ServiceScope(host: "org"), ServiceScope(host: "half.example.org")]
        let harness = AutoFillHarness(items: [])
        await harness.vault.plant(planted)
        await harness.vault.plant(half)

        for host in ["victim.com", "evil.com", "bank.co.uk", "tenant.github.io", "com", "other.example.org"] {
            let identifier = Fixtures.domain(host)
            for item in [planted, half] {
                let released = await Self.releases(of: item, to: [identifier], model: harness.model)
                #expect(released.isEmpty, "\(item.title) on \(host): \(released)")
            }
            if case .list(let list) = await harness.model.credentialList(for: [identifier]) {
                #expect(list.isEmpty, "\(host)")
            }
            #expect(
                try await harness.model.handle(.unusedPassword(domain: host, userName: "pat")).value.changes.isEmpty)
        }
        // The item's sound scope still works, and nothing rewrote the stored record.
        #expect(
            try await harness.model.password(
                for: PasswordChoice(itemID: half.id, userName: "pat"),
                identifiers: [Fixtures.domain("half.example.org")]
            ).value.password == "library-password")
        #expect(await harness.vault.item(half.id) == half)
        #expect(CredentialIdentityPlanner.identities(for: [planted, half]).isEmpty)
    }

    /// A4 or A7: a passkey for one relying party stored in an item scoped to another. Whichever party asks, the
    /// credential is not used: its own relying party is not what the item is for, and the item's host is not the
    /// credential's relying party.
    @Test("a passkey planted in another site's item is not asserted for either party")
    func plantedPasskey() async throws {
        var planted = Fixtures.amazonRetail
        planted.scopes = [ServiceScope(host: "evil.example")]
        planted.fields.append(Fixtures.google.fields[1])
        let harness = AutoFillHarness(items: [planted])
        let choice = FieldChoice(itemID: planted.id, fieldID: Fixtures.id(302))
        #expect(
            await harness.model.passkeyAssertion(
                for: choice,
                request: PasskeyAssertionRequest(
                    relyingPartyID: "evil.example", clientDataHash: Fixtures.clientDataHash()),
                presence: .verified) == .refused(.passkey(.relyingPartyMismatch)))
        #expect(
            await harness.model.passkeyAssertion(
                for: choice,
                request: PasskeyAssertionRequest(
                    relyingPartyID: "google.com", clientDataHash: Fixtures.clientDataHash()),
                presence: .verified
            ).refusal?.isGateRefusal == true)
        guard
            case .list(let list) = await harness.model.credentialList(
                for: [Fixtures.domain("evil.example")],
                passkey: PasskeyAssertionRequest(
                    relyingPartyID: "evil.example", clientDataHash: Fixtures.clientDataHash()))
        else {
            Issue.record("no list")
            return
        }
        #expect(list.passkeys.isEmpty)
    }

    static let malformedFields: [Field] = [
        Field(kind: .passkey, label: "empty", value: ""),
        Field(kind: .passkey, label: "not JSON", value: "base64-private-key"),
        Field(kind: .passkey, label: "huge", value: String(repeating: "A", count: 200_000)),
        Field(
            kind: .passkey, label: "bad key",
            value:
                #"{"createdAt":1,"credentialID":"AAAAAAAAAAAAAAAAAAAAAA","privateKey":"AAAA","rpID":"evil.example","#
                + #""userDisplayName":"","userHandle":"AA","userName":"x"}"#),
        Field(kind: .totp, label: "zero period", value: "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&period=0"),
        Field(kind: .totp, label: "forty digits", value: "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&digits=40"),
        Field(kind: .totp, label: "no secret", value: "otpauth://totp/x?secret="),
        Field(kind: .totp, label: "counter", value: "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=1"),
        Field(kind: .totp, label: "not a URI", value: String(repeating: "%", count: 5_000)),
        Field(kind: .recoveryCodes, label: "no codes", value: "", meta: ["used": "0,1,999999999999999999999"]),
        Field(kind: .password, label: "empty", value: ""),
    ]

    /// A4 or A7: field values no honest client wrote, in an item the victim's site legitimately matches. The site's
    /// request must end in a refusal for that field, not a crash, a hang, or a secret derived from garbage, and the
    /// item's sound fields must still be usable.
    @Test(
        "malformed stored fields are refused field by field, without taking the item down", arguments: malformedFields)
    func malformedStoredField(_ field: Field) async throws {
        var item = Fixtures.library
        item.scopes = [ServiceScope(host: "evil.example")]
        item.fields.append(field)
        let harness = AutoFillHarness(items: [item])
        let site = [Fixtures.domain("evil.example")]

        let choice = FieldChoice(itemID: item.id, fieldID: field.id)
        if case .success = await harness.model.oneTimeCode(for: choice, identifiers: site) {
            Issue.record("a code was computed from \(field.label)")
        }
        if case .success = await harness.model.passkeyAssertion(
            for: choice,
            request: PasskeyAssertionRequest(relyingPartyID: "evil.example", clientDataHash: Fixtures.clientDataHash()),
            presence: .verified)
        {
            Issue.record("an assertion was made from \(field.label)")
        }
        if field.kind != .password, field.kind != .recoveryCodes,
            case .success = await harness.model.textToInsert(
                for: TextChoice(itemID: item.id, fieldID: field.id), identifiers: site)
        {
            Issue.record("text was produced from \(field.label)")
        }
        _ = await harness.model.textToInsert(
            for: TextChoice(itemID: item.id, fieldID: field.id, part: .recoveryCode(index: 0)), identifiers: site)
        _ = await harness.model.credentialList(
            for: site,
            passkey: PasskeyAssertionRequest(relyingPartyID: "evil.example", clientDataHash: Fixtures.clientDataHash()))
        _ = await harness.model.oneTimeCodeList(for: site)
        _ = await harness.model.textInsertionList(for: site)
        _ = await harness.model.textInsertionListWithoutHost()
        _ = await harness.model.textToInsertWithoutHost(for: TextChoice(itemID: item.id, fieldID: field.id))
        _ = CredentialIdentityPlanner.identities(for: [item])
        // The PIN beside it is unaffected.
        #expect(
            await harness.model.textToInsert(
                for: TextChoice(itemID: item.id, fieldID: Fixtures.id(504)), identifiers: site) == .success("4821"))
    }

    // MARK: - Reports and saves from a remote party

    /// A6, as a relying party or a page: it can send any credential-update report and any save-password request the
    /// system will relay, for any domain, user and credential ID it likes. Whatever it sends, nothing is deleted:
    /// every item, every field and every secret value present before is present afterwards, no item is trashed,
    /// archived or re-scoped, and existing items change only by the flags and the passkey account name a report is
    /// allowed to set.
    @Test("no report or silent save, from any party, deletes, trashes, re-scopes or overwrites anything")
    func remotePartiesNeverDelete() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let google = try Fixtures.google.fields[1].passkeyCredential()
        let parties = [
            "amazon.com", "signin.aws.amazon.com", "google.com", "firstbank.co.uk", "library.example.org",
            "evil.example", "arnazon.com", "com", "",
        ]
        let users = [Fixtures.email, "pat", "40012345", "", "admin"]
        let handles = [google.userHandle, Data("other".utf8), Data()]
        let credentialIDs = [google.credentialID, Data(repeating: 1, count: 32), Data()]
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 99))
        for round in 0..<TestEnvironment.iterations(standard: 300, long: 5_000) {
            let party = parties.randomElement(using: &generator)!
            let user = users.randomElement(using: &generator)!
            let handle = handles.randomElement(using: &generator)!
            let credentialID = credentialIDs.randomElement(using: &generator)!
            switch Int.random(in: 0..<6, using: &generator) {
            case 0: _ = await harness.model.handle(.unusedPassword(domain: party, userName: user))
            case 1:
                _ = await harness.model.handle(
                    .passkeyRenamed(relyingPartyID: party, userHandle: handle, newName: "renamed-\(round)"))
            case 2: _ = await harness.model.handle(.unknownPasskey(relyingPartyID: party, credentialID: credentialID))
            case 3:
                _ = await harness.model.handle(
                    .acceptedPasskeys(
                        relyingPartyID: party, userHandle: handle,
                        acceptedCredentialIDs: Bool.random(using: &generator) ? [] : [credentialID]))
            case 4:
                _ = await harness.model.savePasswordWithoutInteraction(
                    SavePasswordRequest(
                        serviceIdentifier: Fixtures.domain(party), userName: user, password: "attacker-\(round)"))
            default:
                _ = await harness.model.registerPasskeyWithoutInteraction(
                    PasskeyRegistrationRequest(
                        relyingPartyID: party, user: PasskeyUser(handle: Data("h\(round)".utf8), name: user),
                        clientDataHash: Fixtures.clientDataHash()))
            }
            // A new day now and then, so the rate limit is not what is being tested.
            if round.isMultiple(of: 7) { await harness.clock.advance(by: CredentialProviderModel.reportInterval) }
        }

        for original in Fixtures.all {
            let now = try #require(await harness.vault.item(original.id))
            #expect(now.scopes == original.scopes)
            #expect(now.title == original.title)
            #expect(!now.isTrashed && !now.archived && !now.excludedFromSuggestions)
            for field in original.fields {
                let kept = try #require(now.fields.first { $0.id == field.id }, "\(original.title) lost \(field.label)")
                #expect(kept.kind == field.kind)
                if field.kind == .passkey {
                    // A rename is the one permitted edit; the key material and binding are untouched.
                    var before = try field.passkeyCredential()
                    let after = try kept.passkeyCredential()
                    before.userName = after.userName
                    #expect(before == after)
                } else {
                    #expect(kept.value == field.value, "\(original.title) \(field.label) changed")
                }
            }
            // History only ever grows, one entry per stored version.
            #expect(UInt64(now.history.count) == now.version - original.version)
        }
        // Anything new is a login for the exact host that asked, never a wider scope and never on a public suffix.
        for item in await harness.vault.allItems where !Fixtures.all.contains(where: { $0.id == item.id }) {
            #expect(item.scopes.count == 1)
            #expect(item.scopes.allSatisfy { !$0.includeSubdomains && ScopePolicy.isAcceptable($0) })
            #expect(parties.contains(item.scopes[0].host))
        }
    }

    /// A6, a hostile relying party, against availability rather than confidentiality: every report-made change is a
    /// new version in a history that is never pruned (PRD F1.4), and an item past its payload limit refuses edits.
    /// A site that reports a new account name on every page load must not be able to fill an item that way.
    @Test("a relying party cannot grow an item's history faster than one version per field per day")
    func reportFlood() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let credential = try Fixtures.google.fields[1].passkeyCredential()
        for round in 0..<2_000 {
            _ = await harness.model.handle(
                .passkeyRenamed(
                    relyingPartyID: "google.com", userHandle: credential.userHandle, newName: "name-\(round)"))
            _ = await harness.model.handle(
                .acceptedPasskeys(
                    relyingPartyID: "google.com", userHandle: credential.userHandle,
                    acceptedCredentialIDs: round.isMultiple(of: 2) ? [] : [credential.credentialID]))
        }
        #expect(await harness.vault.saves.count == 1)
        #expect(await harness.vault.item(Fixtures.google.id)?.history.count == 1)
    }

    /// A6: a page that triggers save-password requests. It may add a login for its own exact host. It must not be
    /// able to choose a wider scope, a title, or an existing item to overwrite, and a look-alike host is not saved
    /// without the person seeing the warning.
    @Test("a save request cannot widen a scope, pick its title, or reach another site's item")
    func hostileSave() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let page = Fixtures.url("https://login.evil.example/phish")
        let request = SavePasswordRequest(serviceIdentifier: page, userName: Fixtures.email, password: "phished")
        for item in Fixtures.all {
            let outcome = await harness.model.savePassword(request, to: .existingItem(item.id))
            #expect(outcome.refusal?.isGateRefusal == true, "\(item.title): \(outcome)")
        }
        #expect(await harness.vault.allItems == Fixtures.all)

        let saved = try await harness.model.savePassword(request, to: .newItem).value
        let item = try #require(await harness.vault.item(saved.itemID))
        #expect(item.scopes == [ServiceScope(host: "login.evil.example", includeSubdomains: false)])
        #expect(item.title == "login.evil.example")
        for host in ["evil.example", "www.login.evil.example", "amazon.com"] {
            #expect(
                await harness.model.password(
                    for: PasswordChoice(itemID: item.id, userName: Fixtures.email), identifiers: [Fixtures.domain(host)]
                ).refusal?.isGateRefusal == true)
        }
        #expect(
            await harness.model.savePasswordWithoutInteraction(
                SavePasswordRequest(
                    serviceIdentifier: Fixtures.domain("arnazon.com"), userName: Fixtures.email, password: "x"))
                == .requiresInteraction(.confirmation))
    }

    /// A6: the `passwordrules` string is written by the page. A hostile one aims at availability (a parser or
    /// generator that never returns) or at weakening the password outside what the generator allows. Random and
    /// hand-made hostile strings must each end, quickly, in a refusal or in a password of 4 to 128 printable ASCII
    /// characters that obeys the rules as parsed.
    @Test("hostile password rules end in a refusal or a bounded, conforming password")
    func hostilePasswordRules() async throws {
        let harness = AutoFillHarness()
        var samples = [
            "minlength: 99999999999999999999999", "minlength: 4294967296", "maxlength: 0", "max-consecutive: 0",
            String(repeating: "required: [a];", count: 5_000), String(repeating: "[", count: 2_000),
            "allowed: [" + String(repeating: "a", count: 2_000) + "]", "required: [a]; required: [b]; maxlength: 4",
            "required: [\u{0}]", "allowed: unicode; minlength: 128; maxlength: 128", "required: lower; allowed: []",
            "required: " + String(repeating: "lower,", count: 300) + "upper", ";;;;;;;;", "minlength: 0x20",
            "required: [ab]; max-consecutive: 1; minlength: 128",
        ]
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 4))
        let pieces = [
            "required", "allowed", "minlength", "maxlength", "max-consecutive", ":", ";", ",", " ", "[", "]", "upper",
            "lower", "digit", "special", "ascii-printable", "unicode", "0", "1", "4", "12", "128", "129", "-", "a",
            "Z", "\u{00E9}", "\\",
        ]
        for _ in 0..<TestEnvironment.iterations(standard: 400, long: 20_000) {
            samples.append(
                (0..<Int.random(in: 1...12, using: &generator)).map { _ in pieces.randomElement(using: &generator)! }
                    .joined())
        }
        for rules in samples {
            switch await harness.model.generatePassword(for: GeneratePasswordRequest(passwordRules: rules)) {
            case .success(let generated):
                #expect((4...128).contains(generated.password.count), "\(rules)")
                #expect(generated.password.unicodeScalars.allSatisfy { (0x21...0x7E).contains($0.value) }, "\(rules)")
                #expect(try PasswordRules(parsing: rules).isSatisfied(by: generated.password), "\(rules)")
            case .refused(.passwordRules):
                break
            default:
                Issue.record("unexpected outcome for \(rules)")
            }
        }
    }

    // MARK: - Locked

    /// A3, a thief with the device unlocked and the app locked: they can invoke AutoFill anywhere, including on the
    /// real sites, and tap every suggestion. With no keys in memory no request type may return a secret or write
    /// anything; each reports the lock and nothing else.
    @Test("with the vault locked, every request type reports the lock and releases nothing")
    func lockedVault() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        await harness.vault.lock()
        for site in Self.sites {
            for item in Fixtures.all {
                #expect(await Self.releases(of: item, to: [site.identifier], model: harness.model).isEmpty)
            }
            #expect(await harness.model.credentialList(for: [site.identifier]) == .vaultLocked)
            #expect(await harness.model.oneTimeCodeList(for: [site.identifier]) == .vaultLocked)
            #expect(await harness.model.textInsertionList(for: [site.identifier]) == .vaultLocked)
        }
        #expect(await harness.model.textInsertionListWithoutHost() == .vaultLocked)
        #expect(
            await harness.model.textToInsertWithoutHost(
                for: TextChoice(itemID: Fixtures.library.id, fieldID: Fixtures.id(501))) == .vaultLocked)
        let registration = PasskeyRegistrationRequest(
            relyingPartyID: "amazon.com", user: PasskeyUser(handle: Data("h".utf8), name: Fixtures.email),
            clientDataHash: Fixtures.clientDataHash())
        #expect(
            await harness.model.registerPasskey(registration, destination: .newItem, presence: .verified)
                == .vaultLocked)
        #expect(
            await harness.model.registerPasskeyWithoutInteraction(registration) == .requiresInteraction(.vaultLocked))
        #expect(await harness.model.passkeyRegistrationOptions(for: registration) == .vaultLocked)
        let save = SavePasswordRequest(
            serviceIdentifier: Fixtures.domain("new.example.net"), userName: "pat", password: "pw")
        #expect(await harness.model.savePassword(save, to: .newItem) == .vaultLocked)
        #expect(await harness.model.savePasswordWithoutInteraction(save) == .requiresInteraction(.vaultLocked))
        #expect(
            await harness.model.handle(.unusedPassword(domain: "amazon.com", userName: Fixtures.email)) == .vaultLocked)
        #expect(
            await harness.model.markRecoveryCode(
                FieldChoice(itemID: Fixtures.google.id, fieldID: Fixtures.id(303)), index: 0) == .vaultLocked)
        #expect(await harness.model.publishAllIdentities() == .vaultLocked)
        #expect(await harness.vault.saves.isEmpty)
        #expect(await harness.publisher.published.isEmpty)
    }

    /// A3 again, with timing: the auto-lock fires while a request is in flight, after the items were read and before
    /// the write. The lock wins: a registration stores nothing and returns no credential, and a largeBlob write that
    /// cannot land yields no assertion.
    @Test("a lock that lands in the middle of a request wins")
    func lockMidRequest() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let registration = PasskeyRegistrationRequest(
            relyingPartyID: "shop.example", user: PasskeyUser(handle: Data("h".utf8), name: "pat"),
            clientDataHash: Fixtures.clientDataHash())
        await harness.vault.lockAfterReads(1)
        #expect(
            await harness.model.registerPasskey(registration, destination: .newItem, presence: .verified)
                == .vaultLocked)
        #expect(await harness.vault.allItems == Fixtures.all)

        await harness.vault.unlock()
        await harness.vault.lockAfterReads(1)
        let blob = PasskeyAssertionRequest(
            relyingPartyID: "google.com", clientDataHash: Fixtures.clientDataHash(),
            extensions: PasskeyAssertionExtensions(largeBlob: .write(Data("blob".utf8))))
        #expect(
            await harness.model.passkeyAssertion(
                for: FieldChoice(itemID: Fixtures.google.id, fieldID: Fixtures.id(302)), request: blob,
                presence: .verified) == .vaultLocked)

        await harness.vault.unlock()
        await harness.vault.lockAfterReads(1)
        #expect(
            await harness.model.savePassword(
                SavePasswordRequest(
                    serviceIdentifier: Fixtures.domain("new.example.net"), userName: "pat", password: "pw"),
                to: .newItem) == .vaultLocked)
        #expect(await harness.vault.saves.isEmpty)
    }

    /// A3 once more: the lock lands after a request has read the items and before it answers, while it waits on
    /// the clock or for its turn on the actor. The plaintext is already in the request's hands; the lock must still
    /// win. Every request type that hands a secret back is run with the vault locking as its one read returns, on
    /// the site the item belongs to, where nothing else would refuse it.
    @Test("a lock that lands after the items were read stops every kind of release")
    func lockBeforeRelease() async throws {
        let bankSite = [Fixtures.url("https://www.firstbank.co.uk/login")]
        let google = [Fixtures.domain("google.com")]
        let assertion = PasskeyAssertionRequest(relyingPartyID: "google.com", clientDataHash: Fixtures.clientDataHash())
        let passkey = RecordIdentifier(itemID: Fixtures.google.id, fieldID: Fixtures.id(302))
        let credentialID = try Fixtures.google.fields[1].passkeyCredential().credentialID
        let bankPassword = PasswordIdentity(
            host: "firstbank.co.uk", user: "40012345", recordIdentifier: RecordIdentifier(itemID: Fixtures.bank.id),
            rank: 7)
        let bankCode = OneTimeCodeIdentity(
            host: "firstbank.co.uk", label: "40012345",
            recordIdentifier: RecordIdentifier(itemID: Fixtures.bank.id, fieldID: Fixtures.id(404)))

        /// Runs `request` twice on a fresh vault: unlocked throughout, where it must release (so the locked run
        /// proves something), and locking as the items are read.
        func check(_ name: String, _ request: (CredentialProviderModel) async -> (released: Bool, locked: Bool)) async {
            let open = AutoFillHarness(items: Fixtures.all)
            #expect(await request(open.model).released, "\(name) does not release when unlocked")
            let locking = AutoFillHarness(items: Fixtures.all)
            await locking.vault.lockAfterReads(1)
            let outcome = await request(locking.model)
            #expect(!outcome.released, "\(name) released after the lock")
            #expect(outcome.locked, "\(name) did not report the lock")
            #expect(await locking.vault.readCount == 1)
        }
        func result<Value>(_ outcome: Outcome<Value>) -> (released: Bool, locked: Bool) {
            switch outcome {
            case .success: return (true, false)
            case .vaultLocked: return (false, true)
            case .refused: return (false, false)
            }
        }
        func result<Value>(_ outcome: SilentOutcome<Value>) -> (released: Bool, locked: Bool) {
            switch outcome {
            case .success: return (true, false)
            case .requiresInteraction(.vaultLocked): return (false, true)
            case .requiresInteraction, .refused: return (false, false)
            }
        }

        await check("password by choice") {
            result(
                await $0.password(
                    for: PasswordChoice(itemID: Fixtures.bank.id, userName: "40012345"), identifiers: bankSite))
        }
        await check("password without interaction") {
            result(await $0.passwordWithoutInteraction(for: bankPassword.handedBack))
        }
        await check("one-time code by choice") {
            result(
                await $0.oneTimeCode(
                    for: FieldChoice(itemID: Fixtures.bank.id, fieldID: Fixtures.id(404)), identifiers: bankSite))
        }
        await check("one-time code without interaction") {
            result(await $0.oneTimeCodeWithoutInteraction(for: bankCode.handedBack))
        }
        await check("security answer as text") {
            result(
                await $0.textToInsert(
                    for: TextChoice(itemID: Fixtures.bank.id, fieldID: Fixtures.id(405)), identifiers: bankSite))
        }
        await check("one-time code as text") {
            result(
                await $0.textToInsert(
                    for: TextChoice(itemID: Fixtures.bank.id, fieldID: Fixtures.id(404)), identifiers: bankSite))
        }
        await check("recovery code as text") {
            result(
                await $0.textToInsert(
                    for: TextChoice(
                        itemID: Fixtures.google.id, fieldID: Fixtures.id(303), part: .recoveryCode(index: 0)),
                    identifiers: google))
        }
        await check("hand-picked text") {
            result(
                await $0.textToInsertWithoutHost(for: TextChoice(itemID: Fixtures.bank.id, fieldID: Fixtures.id(402))))
        }
        await check("passkey assertion by choice") {
            result(
                await $0.passkeyAssertion(
                    for: FieldChoice(itemID: Fixtures.google.id, fieldID: Fixtures.id(302)), request: assertion,
                    presence: .verified))
        }
        await check("passkey assertion without interaction") {
            result(
                await $0.passkeyAssertionWithoutInteraction(
                    request: assertion,
                    identity: PasskeyIdentityRequest(recordIdentifier: passkey.text, credentialID: credentialID),
                    presence: .verified))
        }
    }

    // MARK: - What the system stores

    /// A2 or A3, reading the operating system's credential identity store, which is plaintext outside the app
    /// (docs/02-architecture.md §2, "Also disclosed by design"): they learn hosts and user names of published items
    /// and nothing else. No title, note, tag, secret, field label or private key, and nothing at all about an item
    /// the person excluded, archived or trashed.
    @Test("the identity store learns hosts, user names and opaque IDs only, and nothing of excluded items")
    func identityDisclosure() async throws {
        var excluded = Fixtures.bank
        excluded.excludedFromSuggestions = true
        var archived = Fixtures.library
        archived.scopes = [ServiceScope(host: "library.example")]
        archived.archived = true
        var noted = Fixtures.amazonRetail
        noted.notes = "NOTE-SECRET"
        noted.tags = ["TAG-SECRET"]
        let harness = AutoFillHarness(items: [noted, Fixtures.google, excluded, archived])
        _ = try await harness.model.publishAllIdentities().value
        let published = await harness.publisher.published
        #expect(published.count == 3)
        var text = ""
        for identity in published {
            switch identity {
            case .password(let value):
                text += [value.host, value.user, value.recordIdentifier.text].joined(separator: "|")
            case .passkey(let value):
                text += [
                    value.relyingPartyID, value.userName, value.recordIdentifier.text,
                    Base64URL.encode(value.credentialID), Base64URL.encode(value.userHandle),
                ].joined(separator: "|")
            case .oneTimeCode(let value):
                text += [value.host, value.label, value.recordIdentifier.text].joined(separator: "|")
            }
            #expect(identity.recordIdentifier.itemID != excluded.id)
            #expect(identity.recordIdentifier.itemID != archived.id)
        }
        let credential = try Fixtures.google.fields[1].passkeyCredential()
        for secret in [
            "retail-password", "aws-password", "bank-password", "library-password", "NOTE-SECRET", "TAG-SECRET",
            "Amazon", "AWS root", "Google", "First Bank", "firstbank", "library", "1111-2222", "otpauth",
            Base32.encode(Array(Fixtures.retailSecret.utf8)), Base64URL.encode(credential.privateKeyPKCS8),
            Base64URL.encode(credential.prfSecret ?? Data()), "Backup codes", "One-time code",
        ] {
            #expect(!text.contains(secret), "\(secret) is in the identity store")
        }
    }
}
