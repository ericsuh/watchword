import Foundation
import Testing
import WatchwordAutoFill
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

@Suite("Request model: credential list and passwords")
struct CredentialListTests {
    typealias Fixtures = AutoFillFixtures

    static let console = Fixtures.url("https://signin.aws.amazon.com/signin")
    static let shop = Fixtures.url("https://www.amazon.com/ap/signin")

    static func list(_ outcome: CredentialListOutcome) throws -> CredentialList {
        guard case .list(let list) = outcome else { throw UnexpectedOutcome(description: "\(outcome)") }
        return list
    }

    // MARK: List

    @Test("the list holds the most specific matches only, not the accounts they shadow, and suggests a sole match")
    func listForOneHost() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let console = try Self.list(await harness.model.credentialList(for: [Self.console]))
        #expect(console.passwords.map(\.title) == ["AWS root"])
        #expect(console.passwords.first?.userName == Fixtures.email)
        #expect(console.passwords.first?.matchedHost == "signin.aws.amazon.com")
        #expect(console.passwords.first?.hasOneTimeCode == true)
        // Retail matches the console less specifically: shadowed, so neither listed nor released (F6.6).
        #expect(!console.passwords.contains { $0.itemID == Fixtures.amazonRetail.id })
        #expect(console.suggested?.itemID == Fixtures.awsRoot.id)
        #expect(console.hosts == ["signin.aws.amazon.com"])
        #expect(console.passkeys.isEmpty)

        let shop = try Self.list(await harness.model.credentialList(for: [Self.shop]))
        #expect(shop.passwords.map(\.title) == ["Amazon"])
        #expect(shop.suggested?.itemID == Fixtures.amazonRetail.id)
    }

    @Test("accounts that tie are both listed and none is suggested (F11.5)")
    func tie() async throws {
        var second = Fixtures.amazonRetail
        second.id = Fixtures.id(90)
        second.title = "Amazon (work)"
        second.fields[0].value = "work@example.com"
        let harness = AutoFillHarness(items: [Fixtures.amazonRetail, second])
        let list = try Self.list(await harness.model.credentialList(for: [Self.shop]))
        #expect(list.passwords.map(\.title) == ["Amazon", "Amazon (work)"])
        #expect(list.suggested == nil)
    }

    @Test("an item with several login names is listed once per name")
    func severalLoginNames() async throws {
        var item = Fixtures.library
        item.fields.insert(Field(kind: .email, label: "Email", value: Fixtures.email), at: 0)
        let harness = AutoFillHarness(items: [item])
        let list = try Self.list(
            await harness.model.credentialList(for: [Fixtures.domain("library.example.org")]))
        #expect(list.passwords.map(\.userName) == [Fixtures.email, "pat"])
        #expect(list.suggested?.userName == Fixtures.email)
    }

    @Test("an item with no password is not a password entry, and one with no login name has an empty one")
    func passwordlessAndNameless() async throws {
        var nameless = Fixtures.library
        nameless.fields.removeAll { $0.kind == .username }
        let harness = AutoFillHarness(items: [Fixtures.google, nameless])
        #expect(
            try Self.list(await harness.model.credentialList(for: [Fixtures.domain("google.com")])).passwords.isEmpty)
        let list = try Self.list(await harness.model.credentialList(for: [Fixtures.domain("library.example.org")]))
        #expect(list.passwords.map(\.userName) == [""])
    }

    @Test("a locked vault is reported, not worked around")
    func locked() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        await harness.vault.lock()
        #expect(await harness.model.credentialList(for: [Self.shop]) == .vaultLocked)
        #expect(
            await harness.model.password(
                for: PasswordChoice(itemID: Fixtures.amazonRetail.id, userName: Fixtures.email),
                identifiers: [Self.shop])
                == .vaultLocked)
        await harness.vault.unlock()
        #expect(await harness.model.credentialList(for: [Self.shop]) != .vaultLocked)
    }

    @Test("with no service identifier there is nothing to authorise a password for")
    func noIdentifier() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        #expect(await harness.model.credentialList(for: []) == .refused(.noServiceIdentifier))
        #expect(
            await harness.model.password(
                for: PasswordChoice(itemID: Fixtures.amazonRetail.id, userName: Fixtures.email), identifiers: [])
                == .refused(.noServiceIdentifier))
    }

    @Test(
        "an identifier that is not a usable hostname is refused",
        arguments: ["https://amazon.com@evil.example/", "file:///etc/passwd", "javascript:alert(1)", "https:///"])
    func unusableIdentifier(_ url: String) async {
        let harness = AutoFillHarness(items: Fixtures.all)
        let outcome = await harness.model.credentialList(for: [Fixtures.url(url)])
        guard case .refused(.gate(.unusableIdentifier)) = outcome else {
            Issue.record("\(url) gave \(outcome)")
            return
        }
    }

    @Test("a site with nothing saved gets an empty list and no alarm")
    func newSite() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let list = try Self.list(await harness.model.credentialList(for: [Fixtures.url("https://news.example.net/")]))
        #expect(list.isEmpty)
        #expect(list.suggested == nil)
        #expect(list.hosts == ["news.example.net"])
    }

    @Test(
        "a look-alike host gets the warning instead of an empty list (F11.3)",
        arguments: ["arnazon.com", "amaz0n.com", "amazon.com.evil.example", "firstbamk.co.uk"])
    func lookAlike(_ host: String) async {
        let harness = AutoFillHarness(items: Fixtures.all)
        guard case .warning(let warning) = await harness.model.credentialList(for: [Fixtures.domain(host)]) else {
            Issue.record("\(host) was not warned about")
            return
        }
        #expect(warning.host == host)
        #expect(!warning.signals.isEmpty)
        #expect(!warning.impersonating.isEmpty)
    }

    @Test("an archived account is not offered, yet still keeps a less specific one off its host")
    func archivedItem() async throws {
        var archived = Fixtures.awsRoot
        archived.archived = true
        let harness = AutoFillHarness(items: [Fixtures.amazonRetail, archived])
        let list = try Self.list(await harness.model.credentialList(for: [Self.console]))
        #expect(list.passwords.isEmpty)
        #expect(list.suggested == nil)
        #expect(list.isEmpty)
        let outcome = await harness.model.password(
            for: PasswordChoice(itemID: Fixtures.amazonRetail.id, userName: Fixtures.email), identifiers: [Self.console]
        )
        #expect(outcome.refusal?.isGateRefusal == true)
        #expect(
            await harness.model.password(
                for: PasswordChoice(itemID: archived.id, userName: Fixtures.email), identifiers: [Self.console])
                == .refused(.itemNotInUse))
    }

    @Test("an item in the trash is neither offered nor ranked")
    func trashedItem() async throws {
        var trashed = Fixtures.awsRoot
        trashed.trashedAt = Fixtures.now
        let harness = AutoFillHarness(items: [Fixtures.amazonRetail, trashed])
        let list = try Self.list(await harness.model.credentialList(for: [Self.console]))
        #expect(list.passwords.map(\.title) == ["Amazon"])
        #expect(
            await harness.model.password(
                for: PasswordChoice(itemID: trashed.id, userName: Fixtures.email), identifiers: [Self.console])
                == .refused(.itemNotInUse))
    }

    @Test("an app's several associated domains are each matched, and a sole match is still suggested")
    func severalIdentifiers() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let both = try Self.list(
            await harness.model.credentialList(
                for: [Fixtures.domain("news.example.net"), Fixtures.domain("library.example.org"), Fixtures.domain("")])
        )
        #expect(both.passwords.map(\.title) == ["Library"])
        #expect(both.hosts == ["news.example.net", "library.example.org"])
        #expect(both.suggested?.itemID == Fixtures.library.id)

        let two = try Self.list(
            await harness.model.credentialList(
                for: [Fixtures.domain("firstbank.co.uk"), Fixtures.domain("library.example.org")]))
        #expect(Set(two.passwords.map(\.title)) == ["First Bank", "Library"])
        #expect(two.suggested == nil)
    }

    @Test("a flagged password says so in its entry")
    func reportedUnused() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        _ = try await harness.model.handle(.unusedPassword(domain: "amazon.com", userName: Fixtures.email)).value
        let list = try Self.list(await harness.model.credentialList(for: [Self.shop]))
        #expect(list.passwords.first?.reportedUnused == true)
    }

    // MARK: Password after a choice

    @Test("the chosen login's password is released for its own host")
    func chosenPassword() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let credential = try await harness.model.password(
            for: PasswordChoice(itemID: Fixtures.awsRoot.id, userName: Fixtures.email), identifiers: [Self.console]
        ).value
        #expect(credential.user == Fixtures.email)
        #expect(credential.password == "aws-password")
        #expect(!String(describing: credential).contains("aws-password"))
        #expect(!String(reflecting: Outcome.success(credential)).contains("aws-password"))
    }

    @Test("an explicit choice is authorised again: shadowed accounts and other sites' items are refused (SEC6)")
    func choiceIsReauthorized() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        for (itemID, identifier) in [
            (Fixtures.amazonRetail.id, Self.console),  // shadowed there: neither listed nor released
            (Fixtures.awsRoot.id, Self.shop),
            (Fixtures.bank.id, Self.shop),
            (Fixtures.amazonRetail.id, Fixtures.domain("arnazon.com")),
        ] {
            let outcome = await harness.model.password(
                for: PasswordChoice(itemID: itemID, userName: Fixtures.email), identifiers: [identifier])
            #expect(outcome.refusal?.isGateRefusal == true, "\(itemID) on \(identifier.identifier): \(outcome)")
        }
    }

    @Test("a choice that names nothing the item holds is refused")
    func unknownChoices() async {
        var bare = Fixtures.library
        bare.id = Fixtures.id(91)
        bare.scopes = [ServiceScope(host: "bare.example.org")]
        bare.fields.removeAll { $0.kind == .password }
        let harness = AutoFillHarness(items: Fixtures.all + [bare])
        #expect(
            await harness.model.password(
                for: PasswordChoice(itemID: Fixtures.id(999), userName: Fixtures.email), identifiers: [Self.shop])
                == .refused(.unknownRecord))
        #expect(
            await harness.model.password(
                for: PasswordChoice(itemID: Fixtures.amazonRetail.id, userName: "someone@else.example"),
                identifiers: [Self.shop]) == .refused(.unknownRecord))
        #expect(
            await harness.model.password(
                for: PasswordChoice(itemID: Fixtures.amazonRetail.id, userName: ""), identifiers: [Self.shop])
                == .refused(.unknownRecord))
        #expect(
            await harness.model.password(
                for: PasswordChoice(itemID: bare.id, userName: "pat"),
                identifiers: [Fixtures.domain("bare.example.org")])
                == .refused(.nothingToRelease))
    }

    // MARK: Password without interaction

    // The system hands back the identity Watchword published and never the page, so every request below is built
    // from a published identity (`handedBack`), or says in what way it differs from one.

    static func identity(_ item: Item, host: String, user: String = Fixtures.email) -> PasswordIdentityRequest {
        PasswordIdentity(host: host, user: user, recordIdentifier: RecordIdentifier(itemID: item.id), rank: 0)
            .handedBack
    }

    @Test("a published identity, handed back as stored, fills without UI")
    func silentFill() async throws {
        let harness = AutoFillHarness(items: [Fixtures.amazonRetail, Fixtures.bank])
        let published = try await harness.publishedPasswords()
        #expect(Set(published.map(\.host)) == ["amazon.com", "firstbank.co.uk"])
        for identity in published {
            let credential = try await harness.model.passwordWithoutInteraction(for: identity.handedBack).value
            #expect(credential.user == identity.user)
            #expect(
                credential.password
                    == (identity.recordIdentifier.itemID == Fixtures.bank.id ? "bank-password" : "retail-password"))
        }
    }

    /// The review finding this replaced a wrong test for: the retail identity is stored for `amazon.com`, the
    /// system may offer it on the AWS console, and nothing in the request says which page it is.
    @Test("S1: with an AWS item in the vault, neither Amazon account is published or answered without UI")
    func silentS1() async throws {
        var retail = Fixtures.amazonRetail
        retail.scopes = [ServiceScope(host: "amazon.com", excludedHosts: ["aws.amazon.com"])]
        for items in [[Fixtures.amazonRetail, Fixtures.awsRoot], [retail, Fixtures.awsRoot]] {
            let harness = AutoFillHarness(items: items)
            #expect(try await harness.publishedPasswords().isEmpty)
            #expect(try await harness.publishedCodes().isEmpty)
            // A stale store may still hold what was published before the AWS item existed.
            #expect(
                await harness.model.passwordWithoutInteraction(
                    for: Self.identity(items[0], host: "amazon.com"))
                    == .requiresInteraction(
                        items[0] == retail ? .staleIdentity : .ambiguousMatch))
            for host in ["signin.aws.amazon.com", "console.aws.amazon.com", "aws.amazon.com"] {
                #expect(
                    await harness.model.passwordWithoutInteraction(for: Self.identity(Fixtures.awsRoot, host: host))
                        == .requiresInteraction(.staleIdentity), "\(host)")
            }
        }
    }

    @Test("an item that is not for every page of its site is not answered without UI")
    func silentNeedsWholeSite() async throws {
        var excluding = Fixtures.amazonRetail
        excluding.scopes = [ServiceScope(host: "amazon.com", excludedHosts: ["pay.amazon.com"])]
        var exact = Fixtures.amazonRetail
        exact.scopes = [ServiceScope(host: "amazon.com", includeSubdomains: false)]
        var subdomain = Fixtures.amazonRetail
        subdomain.scopes = [ServiceScope(host: "www.amazon.com")]
        var tenant = Fixtures.amazonRetail
        tenant.scopes = [ServiceScope(host: "acme.zendesk.com")]
        for (item, host) in [
            (excluding, "amazon.com"), (exact, "amazon.com"), (subdomain, "www.amazon.com"),
            (tenant, "acme.zendesk.com"), (Fixtures.library, "library.example.org"),
        ] {
            let harness = AutoFillHarness(items: [item])
            #expect(try await harness.publishedPasswords().isEmpty, "\(host)")
            let user = item.loginNames[0]
            #expect(
                await harness.model.passwordWithoutInteraction(for: Self.identity(item, host: host, user: user))
                    == .requiresInteraction(.staleIdentity), "\(host)")
            // The list, which is told the page, still offers it.
            let list = try Self.list(await harness.model.credentialList(for: [Fixtures.domain(host)]))
            #expect(list.passwords.map(\.itemID) == [item.id], "\(host)")
        }
    }

    @Test("accounts that tie are told apart by the user name tapped, and need the person when they share it")
    func silentTie() async throws {
        var work = Fixtures.amazonRetail
        work.id = Fixtures.id(90)
        work.fields[0].value = "work@example.com"
        work.fields[1].value = "work-password"
        let harness = AutoFillHarness(items: [Fixtures.amazonRetail, work])
        let published = try await harness.publishedPasswords()
        #expect(published.map(\.user) == [Fixtures.email, "work@example.com"])
        #expect(
            try await harness.model.passwordWithoutInteraction(for: published[1].handedBack).value.password
                == "work-password")
        #expect(
            try await harness.model.passwordWithoutInteraction(for: published[0].handedBack).value.password
                == "retail-password")

        var twin = Fixtures.amazonRetail
        twin.id = Fixtures.id(91)
        let tied = AutoFillHarness(items: [Fixtures.amazonRetail, twin])
        #expect(try await tied.publishedPasswords().isEmpty)
        for item in [Fixtures.amazonRetail, twin] {
            #expect(
                await tied.model.passwordWithoutInteraction(for: Self.identity(item, host: "amazon.com"))
                    == .requiresInteraction(.ambiguousMatch))
        }
    }

    @Test("a stale user name and a locked vault each need the person")
    func silentNeedsInteraction() async {
        let harness = AutoFillHarness(items: [Fixtures.amazonRetail])
        #expect(
            await harness.model.passwordWithoutInteraction(
                for: Self.identity(Fixtures.amazonRetail, host: "amazon.com", user: "old-name"))
                == .requiresInteraction(.staleIdentity))
        await harness.vault.lock()
        #expect(
            await harness.model.passwordWithoutInteraction(
                for: Self.identity(Fixtures.amazonRetail, host: "amazon.com"))
                == .requiresInteraction(.vaultLocked))
    }

    @Test("an identity's identifier is a lookup key: a page's URL in its place, or a look-alike, releases nothing")
    func silentIdentifierIsNotThePage() async {
        let harness = AutoFillHarness(items: [Fixtures.amazonRetail])
        for identifier in [
            Self.shop, Self.console, Fixtures.domain("www.amazon.com"), Fixtures.domain("amazon.com.evil.example"),
            Fixtures.domain("arnazon.com"),
        ] {
            let outcome = await harness.model.passwordWithoutInteraction(
                for: PasswordIdentityRequest(
                    serviceIdentifier: identifier, user: Fixtures.email,
                    recordIdentifier: RecordIdentifier(itemID: Fixtures.amazonRetail.id).text))
            #expect(outcome == .requiresInteraction(.staleIdentity), "\(identifier.identifier): \(outcome)")
        }
        let unusable = await harness.model.passwordWithoutInteraction(
            for: PasswordIdentityRequest(
                serviceIdentifier: Fixtures.url("https://amazon.com@evil.example/"), user: Fixtures.email,
                recordIdentifier: RecordIdentifier(itemID: Fixtures.amazonRetail.id).text))
        #expect(unusable.refusal?.isGateRefusal == true)
        for record in [
            "", "garbage", RecordIdentifier(itemID: Fixtures.id(999)).text,
            RecordIdentifier(itemID: Fixtures.amazonRetail.id, fieldID: Fixtures.id(102)).text,
            Fixtures.amazonRetail.id.uuidString + " ", "/" + Fixtures.amazonRetail.id.uuidString,
        ] {
            let outcome = await harness.model.passwordWithoutInteraction(
                for: PasswordIdentityRequest(
                    serviceIdentifier: Fixtures.domain("amazon.com"), user: Fixtures.email, recordIdentifier: record))
            #expect(outcome == .refused(.unknownRecord), "\(record): \(outcome)")
        }
    }

    // MARK: Excluded from AutoFill (F6.8)

    @Test("an item excluded from AutoFill is not listed or released by the extension, and still ranks")
    func excludedItem() async throws {
        var excluded = Fixtures.awsRoot
        excluded.excludedFromSuggestions = true
        var sensitive = Fixtures.bank
        sensitive.excludedFromSuggestions = true
        let harness = AutoFillHarness(items: [Fixtures.amazonRetail, excluded, sensitive])
        let bankSite = Fixtures.url("https://www.firstbank.co.uk/login")

        #expect(try Self.list(await harness.model.credentialList(for: [bankSite])).isEmpty)
        #expect(await harness.model.oneTimeCodeList(for: [bankSite]) == .list([]))
        #expect(
            await harness.model.password(
                for: PasswordChoice(itemID: sensitive.id, userName: "40012345"), identifiers: [bankSite])
                == .refused(.itemNotInUse))
        #expect(
            await harness.model.oneTimeCode(
                for: FieldChoice(itemID: sensitive.id, fieldID: Fixtures.id(404)), identifiers: [bankSite])
                == .refused(.itemNotInUse))
        #expect(
            await harness.model.textToInsert(
                for: TextChoice(itemID: sensitive.id, fieldID: Fixtures.id(405)), identifiers: [bankSite])
                == .refused(.itemNotInUse))
        // An identity the store still holds from before the exclusion (made on another device, say).
        #expect(
            await harness.model.passwordWithoutInteraction(
                for: Self.identity(sensitive, host: "firstbank.co.uk", user: "40012345")) == .refused(.itemNotInUse))
        #expect(
            await harness.model.oneTimeCodeWithoutInteraction(
                for: OneTimeCodeIdentity(
                    host: "firstbank.co.uk", label: "40012345",
                    recordIdentifier: RecordIdentifier(itemID: sensitive.id, fieldID: Fixtures.id(404))
                ).handedBack) == .refused(.itemNotInUse))
        #expect(
            await harness.model.markRecoveryCode(FieldChoice(itemID: sensitive.id, fieldID: Fixtures.id(405)), index: 0)
                == .refused(.itemNotInUse))
        #expect(try await harness.publishedIdentities().isEmpty)

        // The excluded AWS item still keeps the retail login off the console.
        let console = try Self.list(await harness.model.credentialList(for: [Self.console]))
        #expect(console.passwords.isEmpty)
        #expect(console.isEmpty)
        #expect(
            await harness.model.password(
                for: PasswordChoice(itemID: Fixtures.amazonRetail.id, userName: Fixtures.email),
                identifiers: [Self.console]
            ).refusal?.isGateRefusal == true)
    }

    // MARK: Vault failures

    @Test("a vault that fails is a refusal, and one that locks mid-request yields nothing")
    func vaultFailures() async {
        struct Broken: CredentialVault {
            func credentialItems() async throws -> [Item] { throw CredentialVaultError.noAccount }
            func defaultVaultID() async throws -> UUID { throw CredentialVaultError.noAccount }
            func confirmUnlocked() async throws { throw CredentialVaultError.noAccount }
            func isBackedUp() async throws -> Bool { throw CredentialVaultError.noAccount }
            func saveCredentialItem(_ item: Item, replacingVersion: UInt64?) async throws -> Item {
                throw CredentialVaultError.noAccount
            }
        }
        let broken = CredentialProviderModel(vault: Broken())
        #expect(await broken.credentialList(for: [Self.shop]) == .refused(.vault(.noAccount)))
        #expect(
            await broken.passwordWithoutInteraction(for: Self.identity(Fixtures.amazonRetail, host: "amazon.com"))
                == .refused(.vault(.noAccount)))

        // A lock that lands after the items were read, before the answer: the password read goes nowhere.
        let harness = AutoFillHarness(items: Fixtures.all)
        await harness.vault.lockAfterReads(1)
        #expect(
            await harness.model.password(
                for: PasswordChoice(itemID: Fixtures.awsRoot.id, userName: Fixtures.email), identifiers: [Self.console])
                == .vaultLocked)
        let alone = AutoFillHarness(items: [Fixtures.amazonRetail])
        await alone.vault.lockAfterReads(1)
        #expect(
            await alone.model.passwordWithoutInteraction(for: Self.identity(Fixtures.amazonRetail, host: "amazon.com"))
                == .requiresInteraction(.vaultLocked))
    }

    @Test("identities are republished from the unlocked items on request")
    func publishAll() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let count = try await harness.model.publishAllIdentities().value
        #expect(count == CredentialIdentityPlanner.identities(for: Fixtures.all).count)
        #expect(await harness.publisher.published == CredentialIdentityPlanner.identities(for: Fixtures.all))
        await harness.vault.lock()
        #expect(await harness.model.publishAllIdentities() == .vaultLocked)
    }
}
