import Foundation
import Testing
import WatchwordAutoFill
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

// Review finding Z60 (docs/06-adversarial-review.md): the vault is a trust domain in the AutoFill core. The adversary
// throughout is A4 of docs/02-architecture.md §2: a current member of a shared vault whose role may write. They can
// put any item the scope policy accepts into that vault, with any title, user name and scope, and they read
// everything saved there. They cannot write the victim's own vaults.
extension AdversarialAutoFillRequestTests {
    static let household = [Fixtures.sharedVaultID: Fixtures.sharedVaultName]

    /// A login with fixed IDs: `number` names the item, and its fields are `number * 100 + 1` and `+ 2`.
    static func login(
        _ number: Int, vault: UUID, title: String, scope: ServiceScope, userName: String?, password: String?
    ) -> Item {
        var fields: [Field] = []
        if let userName {
            fields.append(Field(id: Fixtures.id(number * 100 + 1), kind: .username, label: "Username", value: userName))
        }
        if let password {
            fields.append(Field(id: Fixtures.id(number * 100 + 2), kind: .password, label: "Password", value: password))
        }
        return Item(id: Fixtures.id(number), vaultID: vault, title: title, scopes: [scope], fields: fields, version: 1)
    }

    static func conditionalRequest(_ relyingParty: String, userName: String) -> PasskeyRegistrationRequest {
        PasskeyRegistrationRequest(
            relyingPartyID: relyingParty, user: PasskeyUser(handle: Data("handle".utf8), name: userName),
            clientDataHash: Fixtures.clientDataHash())
    }

    /// Threat: A4 wants the victim's next passkey. The victim keeps `alice@x` for the shop in their own vault, saved
    /// by the extension and so scoped to the exact host `www.shop.example`. A4 puts an item scoped `shop.example`
    /// with that user name and any password into the shared vault: for the relying party `shop.example` it is the
    /// only match. The site signs the victim in and asks for a conditional passkey; with no UI the private key was
    /// appended to A4's item and sealed under the shared vault's key. Now nothing is written to an item of a shared
    /// vault without the person, the sheet that does ask names the vault and does not pre-select such an item, and
    /// the same item in a vault of the person's own is still upgraded (it is the vault that decides).
    @Test("a conditional registration never puts a passkey into an item of a shared vault")
    func conditionalRegistrationSkipsSharedVaults() async throws {
        let own = Self.login(
            61, vault: Fixtures.vaultID, title: "www.shop.example",
            scope: ServiceScope(host: "www.shop.example", includeSubdomains: false), userName: "alice@x",
            password: "own")
        let planted = Self.login(
            62, vault: Fixtures.sharedVaultID, title: "Shop", scope: ServiceScope(host: "shop.example"),
            userName: "alice@x", password: "any")
        let request = Self.conditionalRequest("shop.example", userName: "alice@x")

        let harness = AutoFillHarness(items: [own, planted], sharedVaults: Self.household)
        for presence in [PersonPresence.absent, .present, .verified] {
            #expect(
                await harness.model.registerPasskeyWithoutInteraction(request, presence: presence)
                    == .refused(.noItemToUpgrade))
        }
        #expect(await harness.vault.saves.isEmpty)

        let options = try await harness.model.passkeyRegistrationOptions(for: request).value
        #expect(options.existingItems.map(\.itemID) == [planted.id])
        #expect(options.existingItems.first?.vault == Fixtures.sharedVault)
        #expect(options.existingItems.first?.vault.everyMemberSeesWhatIsSaved == true)
        #expect(options.suggested == .newItem, "an item of a shared vault is chosen by the person, not for them")
        #expect(options.relatedLogins.map(\.itemID) == [own.id])
        #expect(options.relatedLogins.first?.vault == Fixtures.personalVault)
        #expect(options.newItem.vault == Fixtures.personalVault)
        // The person can still choose it, knowingly.
        let chosen = try await harness.model.registerPasskey(
            request, destination: .existingItem(planted.id), presence: .verified
        ).value
        #expect(chosen.itemID == planted.id)

        // The same two items where nobody else writes the second vault: the one login for the relying party is
        // upgraded, as before.
        let alone = AutoFillHarness(items: [own, planted])
        #expect(try await alone.model.registerPasskeyWithoutInteraction(request).value.itemID == planted.id)

        // A vault the session did not describe is taken to be shared.
        let undescribed = CredentialProviderModel(
            vault: UndescribedVault(items: [own, planted]), clock: FakeClock(Fixtures.now),
            random: SeededGenerator(seed: 6))
        #expect(await undescribed.registerPasskeyWithoutInteraction(request) == .refused(.noItemToUpgrade))
    }

    /// A vault that describes none of its vaults: what a conformer that forgot would return.
    struct UndescribedVault: CredentialVault {
        let items: [Item]
        func credentialSnapshot() async throws -> CredentialSnapshot {
            CredentialSnapshot(items: items, vaults: [], defaultVaultID: AutoFillFixtures.vaultID)
        }
        func confirmUnlocked() async throws {}
        func isBackedUp() async throws -> Bool { true }
        func saveCredentialItem(_ item: Item, replacingVersion: UInt64?) async throws -> Item { item }
    }

    /// Threat: A4 wants the victim's password for the bank, or just wants the victim's login gone from AutoFill
    /// there. The victim's own login covers `bank.example` and its subdomains. A4 puts an item scoped to the exact
    /// login host into the shared vault: more specific, so it shadowed the victim's login, which the extension then
    /// neither listed nor released; with no password in it nothing was listed at all, and the next save offered A4's
    /// item as the only one to update. Archived, it hid the login without ever being visible. Now an item of a
    /// shared vault shadows nothing outside its vault: the victim's login stays listed and released, the two are a
    /// choice (nothing suggested, nothing done silently), and each entry and candidate says which vault it is in.
    @Test(
        "an item of a shared vault never shadows the person's own login, whatever its scope",
        arguments: [false, true])
    func sharedVaultItemNeverShadows(plantedIsArchived: Bool) async throws {
        let own = Self.login(
            63, vault: Fixtures.vaultID, title: "Bank", scope: ServiceScope(host: "bank.example"),
            userName: "alice@x", password: "real")
        var planted = Self.login(
            64, vault: Fixtures.sharedVaultID, title: "Bank",
            scope: ServiceScope(host: "www.bank.example", includeSubdomains: false), userName: nil, password: nil)
        planted.archived = plantedIsArchived
        let harness = AutoFillHarness(items: [own, planted], sharedVaults: Self.household)
        let page = Fixtures.url("https://www.bank.example/login")

        let list = try #require(await harness.model.credentialList(for: [page]).list)
        #expect(list.passwords.map(\.itemID) == [own.id])
        #expect(list.passwords.first?.vault == Fixtures.personalVault)
        #expect(list.suggested == nil, "two vaults meet on this host: the person chooses")
        #expect(
            try await harness.model.password(
                for: PasswordChoice(itemID: own.id, userName: "alice@x"), identifiers: [page]
            )
            .value.password == "real")

        let request = SavePasswordRequest(serviceIdentifier: page, userName: "alice@x", password: "changed")
        guard
            case .offerUpdate(let candidates, let newItem) = try await harness.model.savePasswordPlan(for: request)
                .value
        else {
            Issue.record("the person's own login is not offered for update")
            return
        }
        #expect(candidates.first?.itemID == own.id)
        #expect(candidates.first?.vault == Fixtures.personalVault)
        #expect(newItem.vault == Fixtures.personalVault)
        if plantedIsArchived {
            #expect(candidates.count == 1)
        } else {
            #expect(candidates.map(\.itemID) == [own.id, planted.id])
            #expect(candidates.last?.vault == Fixtures.sharedVault)
            #expect(candidates.last?.vault.everyMemberSeesWhatIsSaved == true)
        }
        // Nothing is written anywhere without the person.
        #expect(await harness.model.savePasswordWithoutInteraction(request) == .requiresInteraction(.confirmation))
        #expect(await harness.vault.saves.isEmpty)

        // In the person's own vault the same item does shadow: that is their statement, and unchanged.
        let alone = AutoFillHarness(items: [own, planted])
        #expect(try #require(await alone.model.credentialList(for: [page]).list).passwords.isEmpty)
    }

    /// Threat: A4 makes their item indistinguishable from the victim's: the same title, user name and scope. The two
    /// tie, as they always did, and the update sheet listed two rows alike in every field shown; the one tapped
    /// decided whether the new password went to A4. Now every entry and candidate carries its vault and whether it
    /// is shared, which A4 cannot choose (the vault's name they can), and the person's own comes first.
    @Test("two logins alike in everything a member can choose are told apart by their vaults")
    func identicalRowsDifferByVault() async throws {
        let own = Self.login(
            65, vault: Fixtures.vaultID, title: "Bank", scope: ServiceScope(host: "bank.example"),
            userName: "alice@x", password: "real")
        let planted = Self.login(
            66, vault: Fixtures.sharedVaultID, title: "Bank", scope: ServiceScope(host: "bank.example"),
            userName: "alice@x", password: "guess")
        // The member names the shared vault after the victim's own.
        let harness = AutoFillHarness(items: [planted, own], sharedVaults: [Fixtures.sharedVaultID: "Personal"])
        let page = Fixtures.url("https://bank.example/login")

        let list = try #require(await harness.model.credentialList(for: [page]).list)
        #expect(list.suggested == nil)
        #expect(Set(list.passwords.map(\.vault.isShared)) == [false, true])
        for entry in list.passwords {
            #expect(entry.vault.isShared == (entry.itemID == planted.id))
            #expect(entry.vault.name == "Personal")
        }
        guard
            case .offerUpdate(let candidates, _) = try await harness.model.savePasswordPlan(
                for: SavePasswordRequest(serviceIdentifier: page, userName: "alice@x", password: "changed")
            ).value
        else {
            Issue.record("no update offered")
            return
        }
        #expect(candidates.map(\.itemID) == [own.id, planted.id])
        #expect(candidates.map(\.vault.isShared) == [false, true])
        #expect(candidates.map(\.title) == ["Bank", "Bank"])
    }

    /// Threat: A4 working with A6, or an honest member who was phished into adding a host. The victim's own vault
    /// holds `amazon.com`. A scope for a look-alike host in the shared vault made that host "recognised": the
    /// look-alike warning went away and the extension offered the shared item there, vouching for the page, after
    /// which the victim types their real password by hand. A scope is evidence about a host only in its own vault:
    /// the host is still compared with what the other vaults hold, the warning names the real site, and nothing is
    /// listed, released, published or silently saved there, until the person scopes an item of their own to the host.
    @Test(
        "a member's scope does not vouch for a look-alike of a site the person saved themselves",
        arguments: ["amaz0n.com", "arnazon.com", "amazon.com.evil.example"])
    func memberScopeDoesNotVouchForALookAlike(lookAlike: String) async throws {
        var planted = Self.login(
            67, vault: Fixtures.sharedVaultID, title: "Amazon", scope: ServiceScope(host: lookAlike),
            userName: Fixtures.email, password: "member-password")
        planted.fields.append(Fixtures.totp("planted-totp-secret-1", id: Fixtures.id(6703)))
        let harness = AutoFillHarness(items: [Fixtures.amazonRetail, planted], sharedVaults: Self.household)
        let page = Fixtures.url("https://\(lookAlike)/signin")

        guard case .warning(let warning) = await harness.model.credentialList(for: [page]) else {
            Issue.record("no warning on \(lookAlike)")
            return
        }
        #expect(warning.impersonating == ["amazon.com"])
        #expect(await harness.model.oneTimeCodeList(for: [page]) == .warning(warning))
        #expect(await harness.model.textInsertionList(for: [page]) == .warning(warning))
        #expect(await Self.releases(of: planted, to: [page, Fixtures.domain(lookAlike)], model: harness.model).isEmpty)
        let refusal = await harness.model.password(
            for: PasswordChoice(itemID: planted.id, userName: Fixtures.email), identifiers: [page]
        ).refusal
        guard case .gate(.resemblesSavedSite(let assessment)) = refusal else {
            Issue.record("\(String(describing: refusal))")
            return
        }
        #expect(assessment.impersonatesSavedSite)
        #expect(try await harness.publishedIdentities().allSatisfy { $0.recordIdentifier.itemID != planted.id })

        // Saving there shows the warning and is never done silently.
        let request = SavePasswordRequest(serviceIdentifier: page, userName: Fixtures.email, password: "typed")
        guard case .createItem(let proposal) = try await harness.model.savePasswordPlan(for: request).value else {
            Issue.record("the member's item is offered for update on a look-alike")
            return
        }
        #expect(proposal.warning?.impersonating == ["amazon.com"])
        #expect(await harness.model.savePasswordWithoutInteraction(request) == .requiresInteraction(.confirmation))

        // The person's own word for the host ends it: with an item of theirs scoped there, both are offered.
        let vouched = Self.login(
            68, vault: Fixtures.vaultID, title: "Mine", scope: ServiceScope(host: lookAlike), userName: "me",
            password: "mine")
        let after = AutoFillHarness(items: [Fixtures.amazonRetail, planted, vouched], sharedVaults: Self.household)
        let list = try #require(await after.model.credentialList(for: [page]).list)
        #expect(Set(list.passwords.map(\.itemID)) == [planted.id, vouched.id])

        // And a shared vault's item for a host that resembles nothing is offered as it always was.
        let plain = Self.login(
            69, vault: Fixtures.sharedVaultID, title: "Streaming", scope: ServiceScope(host: "streaming.example"),
            userName: "family", password: "shared")
        let ordinary = AutoFillHarness(items: [Fixtures.amazonRetail, plain], sharedVaults: Self.household)
        let offered = try #require(
            await ordinary.model.credentialList(for: [Fixtures.url("https://streaming.example/")]).list)
        #expect(offered.suggested?.itemID == plain.id)
        #expect(offered.suggested?.vault == Fixtures.sharedVault)
    }

    /// Threat: A4 against the keyboard's suggestions, which are answered without the page being named. The victim's
    /// own login covers the whole of `bank.example` and is published for QuickType. A4 saves an item below it. The
    /// item does not shadow the victim's on any page, but on its own host the two are a choice, and a tap that names
    /// no page cannot be one: the victim's identity is withdrawn and a tap on a stale one asks for the person. So a
    /// member can take a suggestion away, and can never direct one: nothing of either vault is released silently
    /// for the site, and A4's own item is not published where the victim's login is scoped below it.
    @Test("across vaults a keyboard suggestion is withdrawn, never redirected")
    func quickTypeAcrossVaults() async throws {
        let own = Self.login(
            70, vault: Fixtures.vaultID, title: "Bank", scope: ServiceScope(host: "bank.example"),
            userName: "alice@x", password: "real")
        let before = AutoFillHarness(items: [own])
        let identity = try #require(try await before.publishedPasswords().first)
        #expect(try await before.model.passwordWithoutInteraction(for: identity.handedBack).value.password == "real")

        let below = Self.login(
            71, vault: Fixtures.sharedVaultID, title: "Bank",
            scope: ServiceScope(host: "login.bank.example", includeSubdomains: false), userName: "alice@x",
            password: "guess")
        let harness = AutoFillHarness(items: [own, below], sharedVaults: Self.household)
        #expect(try await harness.publishedPasswords().isEmpty)
        #expect(
            await harness.model.passwordWithoutInteraction(for: identity.handedBack)
                == .requiresInteraction(.ambiguousMatch))

        // The other way round: the member's item covers the site, the person's own is below it.
        let wide = Self.login(
            72, vault: Fixtures.sharedVaultID, title: "Shop", scope: ServiceScope(host: "shop.example"),
            userName: "alice@x", password: "guess")
        let narrow = Self.login(
            73, vault: Fixtures.vaultID, title: "Shop",
            scope: ServiceScope(host: "www.shop.example", includeSubdomains: false), userName: "alice@x",
            password: "real")
        let other = AutoFillHarness(items: [wide, narrow], sharedVaults: Self.household)
        #expect(try await other.publishedPasswords().isEmpty)
        // On the page, the person's own login shadows the member's less specific one, as their own items always do.
        let list = try #require(
            await other.model.credentialList(for: [Fixtures.url("https://www.shop.example/")]).list)
        #expect(list.passwords.map(\.itemID) == [narrow.id])
        #expect(list.suggested?.itemID == narrow.id)
    }

    /// Threat: A4 widening an item the victim creates. The save sheet offers "beside the accounts already here" with
    /// those accounts' scope, which was described as "one the person gave an item"; a member's item made it one A4
    /// chose, copied into a new item in the victim's own vault. Now only the person's own items lend their scope:
    /// the member's item is counted among what a new exact-host item would hide, and no scope of it is offered.
    @Test("a new item never takes its scope from an item of a shared vault")
    func newItemNeverCopiesAMembersScope() async throws {
        let planted = Self.login(
            74, vault: Fixtures.sharedVaultID, title: "Shop", scope: ServiceScope(host: "shop.example"),
            userName: "someone", password: "x")
        let harness = AutoFillHarness(items: [planted], sharedVaults: Self.household)
        let request = SavePasswordRequest(
            serviceIdentifier: Fixtures.url("https://www.shop.example/login"), userName: "alice@x", password: "new")
        guard case .createItem(let proposal) = try await harness.model.savePasswordPlan(for: request).value else {
            Issue.record("another account's item is offered for update")
            return
        }
        #expect(proposal.hiddenAccounts == 1)
        #expect(proposal.besideExisting == nil)
        #expect(proposal.vault == Fixtures.personalVault)
        let saved = try await harness.model.savePassword(request, to: .newItemBesideExisting).value
        let item = try #require(await harness.vault.item(saved.itemID))
        #expect(item.scopes == [ServiceScope(host: "www.shop.example", includeSubdomains: false)])
        #expect(item.vaultID == Fixtures.vaultID)

        // With an item of the person's own covering the host too, its scope is the one offered.
        let own = Self.login(
            75, vault: Fixtures.vaultID, title: "Shop", scope: ServiceScope(host: "shop.example"),
            userName: "pat", password: "y")
        let both = AutoFillHarness(items: [planted, own], sharedVaults: Self.household)
        guard case .createItem(let second) = try await both.model.savePasswordPlan(for: request).value else {
            Issue.record("no proposal")
            return
        }
        #expect(second.hiddenAccounts == 2)
        #expect(
            second.besideExisting
                == SharedScopeProposal(scopeHost: "shop.example", includesSubdomains: true, accounts: 1))
    }
}

extension CredentialListOutcome {
    /// The list, or `nil` for any other outcome.
    var list: CredentialList? {
        if case .list(let list) = self { return list }
        return nil
    }
}
