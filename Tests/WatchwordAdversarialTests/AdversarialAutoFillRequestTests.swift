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
                if case .success = await model.oneTimeCodeWithoutInteraction(
                    for: OneTimeCodeIdentityRequest(serviceIdentifier: identifier, recordIdentifier: record))
                {
                    released.append("one-time code without interaction (\(item.title))")
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
            await harness.model.textToInsert(
                for: TextChoice(itemID: Fixtures.amazonRetail.id, fieldID: Fixtures.id(102)), identifiers: [])
                == .refused(.fieldWithheld(.password)))
        #expect(
            await harness.model.textToInsert(
                for: TextChoice(itemID: Fixtures.amazonRetail.id, fieldID: Fixtures.id(103)), identifiers: [])
                == .refused(.fieldWithheld(.totp)))
        #expect(
            await harness.model.textToInsert(
                for: TextChoice(itemID: Fixtures.google.id, fieldID: Fixtures.id(302)), identifiers: [])
                == .refused(.fieldWithheld(.passkey)))
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

    // MARK: - Records no honest client wrote

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
        #expect(CredentialIdentityPlanner.identities(for: planted).isEmpty)
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
        _ = await harness.model.textInsertionList(for: [])
        _ = CredentialIdentityPlanner.identities(for: item)
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
        archived.archived = true
        var noted = Fixtures.amazonRetail
        noted.notes = "NOTE-SECRET"
        noted.tags = ["TAG-SECRET"]
        let harness = AutoFillHarness(items: [noted, Fixtures.awsRoot, Fixtures.google, excluded, archived])
        _ = try await harness.model.publishAllIdentities().value
        let published = await harness.publisher.published
        #expect(!published.isEmpty)
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
