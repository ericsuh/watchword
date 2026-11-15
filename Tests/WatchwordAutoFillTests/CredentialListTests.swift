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

    @Test("the list holds the most specific matches, keeps other accounts apart and suggests a sole match")
    func listForOneHost() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let console = try Self.list(await harness.model.credentialList(for: [Self.console]))
        #expect(console.passwords.map(\.title) == ["AWS root"])
        #expect(console.passwords.first?.userName == Fixtures.email)
        #expect(console.passwords.first?.matchedHost == "signin.aws.amazon.com")
        #expect(console.passwords.first?.hasOneTimeCode == true)
        #expect(console.otherAccounts.map(\.title) == ["Amazon"])
        #expect(console.otherAccounts.first?.matchedHost == "amazon.com")
        #expect(console.suggested?.itemID == Fixtures.awsRoot.id)
        #expect(console.hosts == ["signin.aws.amazon.com"])
        #expect(console.passkeys.isEmpty)

        let shop = try Self.list(await harness.model.credentialList(for: [Self.shop]))
        #expect(shop.passwords.map(\.title) == ["Amazon"])
        #expect(shop.otherAccounts.isEmpty)
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
        #expect(list.otherAccounts.isEmpty)
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
        #expect(list.otherAccounts.map(\.title) == ["Amazon"])
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

    @Test("an explicit choice is authorised again: other accounts and other sites' items are refused (SEC6)")
    func choiceIsReauthorized() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        for (itemID, identifier) in [
            (Fixtures.amazonRetail.id, Self.console),  // shown under "other accounts", never released there
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

    static func identity(
        _ item: Item, on identifier: ServiceIdentifier, user: String = Fixtures.email
    ) -> PasswordIdentityRequest {
        PasswordIdentityRequest(
            serviceIdentifier: identifier, user: user, recordIdentifier: RecordIdentifier(itemID: item.id).text)
    }

    @Test("a QuickType suggestion fills without UI when its item is the only fill for the host")
    func silentFill() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let aws = try await harness.model.passwordWithoutInteraction(
            for: Self.identity(Fixtures.awsRoot, on: Self.console)
        ).value
        #expect(aws.password == "aws-password")
        let retail = try await harness.model.passwordWithoutInteraction(
            for: Self.identity(Fixtures.amazonRetail, on: Fixtures.domain("amazon.com"))
        ).value
        #expect(retail.password == "retail-password")
    }

    @Test("a tie, a locked vault and a stale user name each need the person")
    func silentNeedsInteraction() async {
        var second = Fixtures.amazonRetail
        second.id = Fixtures.id(90)
        let harness = AutoFillHarness(items: [Fixtures.amazonRetail, second, Fixtures.library])
        #expect(
            await harness.model.passwordWithoutInteraction(for: Self.identity(Fixtures.amazonRetail, on: Self.shop))
                == .requiresInteraction(.ambiguousMatch))
        #expect(
            await harness.model.passwordWithoutInteraction(
                for: Self.identity(Fixtures.library, on: Fixtures.domain("library.example.org"), user: "old-name"))
                == .requiresInteraction(.staleIdentity))
        await harness.vault.lock()
        #expect(
            await harness.model.passwordWithoutInteraction(for: Self.identity(Fixtures.amazonRetail, on: Self.shop))
                == .requiresInteraction(.vaultLocked))
    }

    @Test("a published identity is only a lookup key: the gate still decides")
    func silentRefusals() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        // The retail identity replayed for the console, and for a look-alike.
        for identifier in [Self.console, Fixtures.domain("amazon.com.evil.example")] {
            let outcome = await harness.model.passwordWithoutInteraction(
                for: Self.identity(Fixtures.amazonRetail, on: identifier))
            #expect(outcome.refusal?.isGateRefusal == true, "\(identifier.identifier): \(outcome)")
        }
        for record in [
            "", "garbage", RecordIdentifier(itemID: Fixtures.id(999)).text,
            RecordIdentifier(itemID: Fixtures.amazonRetail.id, fieldID: Fixtures.id(102)).text,
            Fixtures.amazonRetail.id.uuidString + " ", "/" + Fixtures.amazonRetail.id.uuidString,
        ] {
            let outcome = await harness.model.passwordWithoutInteraction(
                for: PasswordIdentityRequest(
                    serviceIdentifier: Self.shop, user: Fixtures.email, recordIdentifier: record))
            #expect(outcome == .refused(.unknownRecord), "\(record): \(outcome)")
        }
    }

    // MARK: Vault failures

    @Test("a vault that fails is a refusal, and one that locks mid-request yields nothing")
    func vaultFailures() async {
        struct Broken: CredentialVault {
            func credentialItems() async throws -> [Item] { throw CredentialVaultError.noAccount }
            func credentialItem(id: UUID) async throws -> Item { throw CredentialVaultError.noAccount }
            func defaultVaultID() async throws -> UUID { throw CredentialVaultError.noAccount }
            func isBackedUp() async throws -> Bool { throw CredentialVaultError.noAccount }
            func saveCredentialItem(_ item: Item, replacingVersion: UInt64?) async throws -> Item {
                throw CredentialVaultError.noAccount
            }
        }
        let broken = CredentialProviderModel(vault: Broken())
        #expect(await broken.credentialList(for: [Self.shop]) == .refused(.vault(.noAccount)))
        #expect(
            await broken.passwordWithoutInteraction(for: Self.identity(Fixtures.amazonRetail, on: Self.shop))
                == .refused(.vault(.noAccount)))
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
