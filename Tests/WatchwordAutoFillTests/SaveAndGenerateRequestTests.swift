import Foundation
import Testing
import WatchwordAutoFill
import WatchwordGenerator
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

@Suite("Request model: saving and generating passwords")
struct SaveAndGenerateRequestTests {
    typealias Fixtures = AutoFillFixtures

    static func request(
        _ url: String, user: String = "pat@example.com", password: String = "new-password"
    ) -> SavePasswordRequest {
        SavePasswordRequest(serviceIdentifier: Fixtures.url(url), userName: user, password: password)
    }

    // MARK: Saving (F6.5)

    @Test("a login on a new site becomes a new item scoped to exactly that host")
    func createItem() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let request = Self.request("https://Shop.Example.net/account/login")
        let plan = try await harness.model.savePasswordPlan(for: request).value
        #expect(
            plan
                == .createItem(
                    NewItemProposal(
                        title: "shop.example.net", scopeHost: "shop.example.net", userName: "pat@example.com",
                        warning: nil)))
        #expect(await harness.vault.saves.isEmpty)

        let saved = try await harness.model.savePassword(request, to: .newItem).value
        #expect(saved.createdItem)
        let item = try #require(await harness.vault.item(saved.itemID))
        #expect(item.title == "shop.example.net")
        #expect(item.scopes == [ServiceScope(host: "shop.example.net", includeSubdomains: false)])
        #expect(item.fields.map(\.kind) == [.username, .password])
        #expect(item.fields.map(\.value) == ["pat@example.com", "new-password"])
        #expect(item.vaultID == Fixtures.vaultID)

        // It fills on that host and not on a sibling or a subdomain, and its identity is published.
        let credential = try await harness.model.password(
            for: PasswordChoice(itemID: item.id, userName: "pat@example.com"),
            identifiers: [Fixtures.domain("shop.example.net")]
        ).value
        #expect(credential.password == "new-password")
        #expect(
            await harness.model.password(
                for: PasswordChoice(itemID: item.id, userName: "pat@example.com"),
                identifiers: [Fixtures.domain("evil.shop.example.net")]
            ).refusal?.isGateRefusal == true)
        #expect(
            await harness.publisher.published.contains(
                .password(
                    PasswordIdentity(
                        host: "shop.example.net", user: "pat@example.com",
                        recordIdentifier: RecordIdentifier(itemID: item.id),
                        rank: 7))))
    }

    @Test("a changed password is offered as an update of the matching account, and the old one stays in history")
    func updateItem() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let request = Self.request("https://www.amazon.com/ap/signin", password: "changed-password")
        let plan = try await harness.model.savePasswordPlan(for: request).value
        guard case .offerUpdate(let candidates, let newItem) = plan else {
            Issue.record("expected an update offer, got \(plan)")
            return
        }
        #expect(candidates.map(\.itemID) == [Fixtures.amazonRetail.id])
        #expect(candidates.first?.passwordDiffers == true)
        #expect(candidates.first?.matchedHost == "amazon.com")
        #expect(newItem.scopeHost == "www.amazon.com")

        let saved = try await harness.model.savePassword(request, to: .existingItem(Fixtures.amazonRetail.id)).value
        #expect(!saved.createdItem)
        let item = try #require(await harness.vault.item(Fixtures.amazonRetail.id))
        #expect(item.field(.password)?.value == "changed-password")
        #expect(item.history.first?.fields.first { $0.kind == .password }?.value == "retail-password")
        // Nothing else moved: same scopes, title, other fields, and no new item.
        #expect(item.scopes == Fixtures.amazonRetail.scopes)
        #expect(item.title == "Amazon")
        #expect(
            item.fields.filter { $0.kind != .password } == Fixtures.amazonRetail.fields.filter { $0.kind != .password })
        #expect(await harness.vault.allItems.count == Fixtures.all.count)
    }

    @Test("a login already saved needs nothing, with or without UI")
    func alreadySaved() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let request = Self.request("https://www.amazon.com/", password: "retail-password")
        #expect(
            try await harness.model.savePasswordPlan(for: request).value
                == .alreadySaved(itemID: Fixtures.amazonRetail.id))
        #expect(
            try await harness.model.savePasswordWithoutInteraction(request).value
                == SavedPassword(itemID: Fixtures.amazonRetail.id, createdItem: false))
        #expect(
            try await harness.model.savePassword(request, to: .existingItem(Fixtures.amazonRetail.id)).value
                == SavedPassword(itemID: Fixtures.amazonRetail.id, createdItem: false))
        #expect(await harness.vault.saves.isEmpty)
    }

    @Test("a second account on a site is a new item, and existing accounts with other names are not candidates")
    func secondAccount() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let request = Self.request("https://www.amazon.com/", user: "work@example.com")
        guard case .createItem(let proposal) = try await harness.model.savePasswordPlan(for: request).value else {
            Issue.record("expected a new item")
            return
        }
        #expect(proposal.scopeHost == "www.amazon.com")
        #expect(proposal.warning == nil)
        // Forcing the update onto the other account is refused.
        #expect(
            await harness.model.savePassword(request, to: .existingItem(Fixtures.amazonRetail.id))
                == .refused(.unknownRecord))
        #expect(await harness.vault.saves.isEmpty)
    }

    @Test("an item with no user name can take the one from the login it is updated with")
    func addsUserName() async throws {
        var nameless = Fixtures.library
        nameless.fields.removeAll { $0.kind == .username }
        let harness = AutoFillHarness(items: [nameless])
        let request = SavePasswordRequest(
            serviceIdentifier: Fixtures.domain("library.example.org"), userName: "pat", password: "library-password")
        guard case .offerUpdate(let candidates, _) = try await harness.model.savePasswordPlan(for: request).value else {
            Issue.record("expected an update offer")
            return
        }
        #expect(candidates.first?.passwordDiffers == false)
        _ = try await harness.model.savePassword(request, to: .existingItem(nameless.id)).value
        let item = try #require(await harness.vault.item(nameless.id))
        #expect(item.loginNames == ["pat"])
        #expect(item.field(.password)?.value == "library-password")
        #expect(item.scopes == nameless.scopes)
    }

    @Test("only an item the gate would fill here can be updated: not another site's, not a less specific one")
    func updateIsGated() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        let console = Self.request("https://signin.aws.amazon.com/signin")
        for itemID in [Fixtures.amazonRetail.id, Fixtures.bank.id, Fixtures.id(999)] {
            let outcome = await harness.model.savePassword(console, to: .existingItem(itemID))
            #expect(outcome.refusal != nil, "\(itemID): \(outcome)")
        }
        #expect(await harness.vault.saves.isEmpty)
        #expect(await harness.vault.item(Fixtures.amazonRetail.id) == Fixtures.amazonRetail)
    }

    @Test("without UI a new login is saved, but nothing existing is changed and nobody chooses for the person")
    func silentSave() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let created = try await harness.model.savePasswordWithoutInteraction(Self.request("https://new.example.net/"))
            .value
        #expect(created.createdItem)
        #expect(
            await harness.vault.item(created.itemID)?.scopes == [
                ServiceScope(host: "new.example.net", includeSubdomains: false)
            ])
        // Asked again, it is already there.
        #expect(
            try await harness.model.savePasswordWithoutInteraction(Self.request("https://new.example.net/")).value
                == SavedPassword(itemID: created.itemID, createdItem: false))

        #expect(
            await harness.model.savePasswordWithoutInteraction(
                Self.request("https://www.amazon.com/", password: "changed"))
                == .requiresInteraction(.confirmation))
        #expect(await harness.vault.item(Fixtures.amazonRetail.id) == Fixtures.amazonRetail)
        await harness.vault.lock()
        #expect(
            await harness.model.savePasswordWithoutInteraction(Self.request("https://other.example.net/"))
                == .requiresInteraction(.vaultLocked))
        #expect(await harness.model.savePasswordPlan(for: Self.request("https://other.example.net/")) == .vaultLocked)
    }

    @Test("a login on a look-alike host carries the warning, and is never saved unasked")
    func lookAlikeHost() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let request = Self.request("https://arnazon.com/signin")
        guard case .createItem(let proposal) = try await harness.model.savePasswordPlan(for: request).value else {
            Issue.record("expected a proposal")
            return
        }
        #expect(proposal.warning?.impersonating == ["amazon.com"])
        #expect(await harness.model.savePasswordWithoutInteraction(request) == .requiresInteraction(.confirmation))
        #expect(await harness.vault.saves.isEmpty)
    }

    @Test(
        "a host the scope policy refuses is never saved as a scope (F11.2)",
        arguments: ["https://localhost/login", "https://github.io/", "https://co.uk/", "http://intranet/"])
    func scopePolicy(_ url: String) async {
        let harness = AutoFillHarness(items: Fixtures.all)
        for refusal in [
            await harness.model.savePasswordPlan(for: Self.request(url)).refusal,
            await harness.model.savePassword(Self.request(url), to: .newItem).refusal,
            await harness.model.savePasswordWithoutInteraction(Self.request(url)).refusal,
        ] {
            guard case .scopeRejected = refusal else {
                Issue.record("\(url): \(String(describing: refusal))")
                continue
            }
        }
        #expect(await harness.vault.saves.isEmpty)
    }

    @Test("an unusable identifier or malformed login is refused")
    func malformedRequests() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        let unusable = await harness.model.savePasswordPlan(for: Self.request("https://amazon.com@evil.example/"))
        guard case .refused(.gate(.unusableIdentifier(.containsUserInfo))) = unusable else {
            Issue.record("\(unusable)")
            return
        }
        for password in ["", String(repeating: "p", count: 4097), "line\nbreak", "nul\u{0}"] {
            #expect(
                await harness.model.savePassword(
                    Self.request("https://new.example.net/", password: password), to: .newItem)
                    == .refused(.invalidRequest("password")))
        }
        for user in [String(repeating: "u", count: 1025), "pat\u{202E}", "pat\n"] {
            #expect(
                await harness.model.savePassword(Self.request("https://new.example.net/", user: user), to: .newItem)
                    == .refused(.invalidRequest("userName")))
        }
        #expect(await harness.vault.saves.isEmpty)
    }

    @Test("updating a password clears a report that the old one was unused")
    func updateClearsUnusedFlag() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        _ = try await harness.model.handle(.unusedPassword(domain: "amazon.com", userName: Fixtures.email)).value
        #expect(await harness.vault.item(Fixtures.amazonRetail.id)?.field(.password)?.reportedUnusedAt != nil)
        _ = try await harness.model.savePassword(
            Self.request("https://www.amazon.com/", password: "fresh"), to: .existingItem(Fixtures.amazonRetail.id)
        ).value
        #expect(await harness.vault.item(Fixtures.amazonRetail.id)?.field(.password)?.reportedUnusedAt == nil)
    }

    @Test("a save that loses to a concurrent write is reported, not forced")
    func conflict() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        await harness.vault.failNextSave(with: .versionConflict(Fixtures.amazonRetail.id))
        #expect(
            await harness.model.savePassword(
                Self.request("https://www.amazon.com/", password: "changed"),
                to: .existingItem(Fixtures.amazonRetail.id))
                == .refused(.vault(.versionConflict(Fixtures.amazonRetail.id))))
        #expect(await harness.vault.item(Fixtures.amazonRetail.id) == Fixtures.amazonRetail)
    }

    // MARK: Generating (F3.1, F6.5)

    @Test("with no rules the password is the default policy's: twenty characters, every class")
    func generateDefault() async throws {
        let harness = AutoFillHarness()
        let generated = try await harness.model.generatePassword().value
        #expect(generated.password.count == 20)
        #expect(generated.policy.classes == .all)
        #expect(generated.entropyBits > Entropy.warningThresholdBits)
        #expect(generated.password.contains { $0.isLowercase })
        #expect(generated.password.contains { $0.isUppercase })
        #expect(generated.password.contains { $0.isNumber })
        #expect(!String(describing: generated).contains(generated.password))
        // Needs no vault.
        await harness.vault.lock()
        #expect(try await harness.model.generatePassword().value.password != generated.password)
        #expect(await harness.vault.readCount == 0)
    }

    @Test("generation is reproducible under a seed and advances the generator")
    func generateDeterministic() async throws {
        let first = AutoFillHarness(seed: 9)
        let second = AutoFillHarness(seed: 9)
        let a = try await first.model.generatePassword().value.password
        #expect(try await second.model.generatePassword().value.password == a)
        #expect(try await first.model.generatePassword().value.password != a)
    }

    @Test("site rules shape the password, and weak rules show in the entropy")
    func generateWithRules() async throws {
        let harness = AutoFillHarness()
        let pin = try await harness.model.generatePassword(
            for: GeneratePasswordRequest(passwordRules: "allowed: digit; minlength: 6; maxlength: 6")
        ).value
        #expect(pin.password.count == 6)
        #expect(pin.password.allSatisfy { $0.isNumber })
        #expect(pin.entropyBits < Entropy.warningThresholdBits)

        let long = try await harness.model.generatePassword(
            for: GeneratePasswordRequest(passwordRules: "minlength: 64; required: lower; required: [-]")
        ).value
        #expect(long.password.count == 64)
        #expect(long.password.contains("-"))
        #expect(long.password.allSatisfy { $0 == "-" || $0.isLowercase })
    }

    @Test(
        "rules that cannot be parsed or met yield no password",
        arguments: ["minlength: 500", "maxlength: 2", "gibberish", "required: emoji", "minlength: 30; maxlength: 8"])
    func generateRefusals(_ rules: String) async {
        let harness = AutoFillHarness()
        let outcome = await harness.model.generatePassword(for: GeneratePasswordRequest(passwordRules: rules))
        guard case .refused(.passwordRules) = outcome else {
            Issue.record("\(rules): \(outcome)")
            return
        }
    }
}
