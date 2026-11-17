import Foundation
import Testing
import WatchwordAutoFill
import WatchwordKit
import WatchwordMatching
import WatchwordModel
import WatchwordPresentation
import WatchwordTestSupport

// Review finding Z61 (docs/06-adversarial-review.md): the hand-edit route to a look-alike scope.
extension AdversarialAccountScreenTests {
    static func amazon(in vaultID: UUID) -> Item {
        Item(
            vaultID: vaultID, title: "Amazon", scopes: [ServiceScope(host: "amazon.com")],
            fields: [
                Field(kind: .username, label: "Username", value: "pat"),
                Field(kind: .password, label: "Password", value: "retail-password"),
            ])
    }

    /// Threat: A6, a phishing page on a look-alike host, with the person doing what docs/05-anti-phishing.md §1
    /// predicts when AutoFill stays silent: they open the app, edit the Amazon item and add the address from the
    /// browser to Websites. The save used to succeed with no assessment, after which the gate filled the Amazon
    /// password on the look-alike and every host below it, and reported the host as recognised. Now the session
    /// refuses the save until the host is confirmed by name (PRD F11.7), whatever screen asks; the editor's model
    /// turns the refusal into a question that names the site, in ASCII, what it resembles, and the item; nothing
    /// is written until the person says yes; and a full URL, pasted whole, was never a host at all.
    @Test(
        "adding a look-alike host to an item by hand needs a confirmation that names the site and the item",
        arguments: ["amaz0n.com", "arnazon.com", "amazon.com.evil.example", "\u{0430}mazon.com"])
    func handEditedLookAlike(lookAlike: String) async throws {
        let vault = TestVault()
        try await vault.createAccount()
        let personal = try #require(await vault.session.personalVaultID)
        let saved = try await vault.session.save(Self.amazon(in: personal))
        let provider = CredentialProviderModel(vault: vault.session, clock: FakeClock(AutoFillFixtures.now))
        let page = ServiceIdentifier("https://\(lookAlike)/ap/signin", kind: .url)

        var draft = saved
        draft.scopes = ItemEditorModel.scopes(from: "amazon.com, \(lookAlike)", keeping: saved.scopes)
        #expect(draft.scopes.count == 2)
        let added = try #require(draft.scopes.last)

        // Below the view: the session refuses, and says which host.
        let refusal = await #expect(throws: VaultError.self) { try await vault.session.save(draft) }
        guard case .hostsNeedConfirmation(let needed) = refusal else {
            Issue.record("\(String(describing: refusal))")
            return
        }
        #expect(needed.map(\.host) == [added.host])
        #expect(needed.first?.resembles == ["amazon.com"])
        // Confirming some other host confirms nothing.
        await #expect(throws: VaultError.hostsNeedConfirmation(needed)) {
            try await vault.session.save(draft, confirmingHosts: ["amazon.com", "other.example"])
        }

        // The editor: a question, and nothing written.
        let editor = ItemEditorModel(context: Self.context(vault.session))
        #expect(await editor.save(draft) == nil)
        let prompt = try #require(editor.prompts.first)
        #expect(editor.prompts.count == 1 && editor.errorMessage == nil)
        #expect(prompt.title == "Add \(HostText.ascii(lookAlike)) to “Amazon”?")
        #expect(prompt.message.contains("amazon.com") && prompt.message.contains("“Amazon”"))
        #expect(prompt.message.contains("and its subdomains"))
        #expect(prompt.host.ascii.allSatisfy { $0.isASCII })
        #expect(try await vault.session.item(id: saved.id).scopes == saved.scopes)
        if case .list(let list) = await provider.credentialList(for: [page]) {
            Issue.record("offered on the look-alike before any confirmation: \(list.passwords.map(\.title))")
        }

        // Declined: still nothing written, and the question is gone.
        editor.cancelConfirmation()
        #expect(await editor.confirmAndSave() == nil)
        #expect(try await vault.session.item(id: saved.id).scopes == saved.scopes)

        // Confirmed by name: the person's decision, recorded as a scope like any other.
        #expect(await editor.save(draft) == nil)
        let stored = try #require(await editor.confirmAndSave())
        #expect(stored.scopes.map(\.host) == ["amazon.com", added.host])
        #expect(!editor.isAwaitingConfirmation)
        // Saving the item again adds nothing, so asks nothing.
        var renamed = stored
        renamed.title = "Amazon (retail)"
        #expect(try await vault.session.save(renamed).title == "Amazon (retail)")
    }

    /// Threat: the same, by the other routes into an item's scopes: a new item made with the real site and its
    /// look-alike together, and a look-alike of a site that only another of the person's items holds. And the
    /// bounds of the control: a host that resembles nothing is added without a question, a subdomain the item
    /// already covers is its own, and a pasted URL is refused by the scope policy as it always was.
    @Test("the confirmation covers new items and other items' sites, and asks nothing for an ordinary host")
    func handEditBounds() async throws {
        let vault = TestVault()
        try await vault.createAccount()
        let personal = try #require(await vault.session.personalVaultID)

        // A new item holding the site and its look-alike: the pair is judged against itself.
        var pair = Self.amazon(in: personal)
        pair.scopes = [ServiceScope(host: "amazon.com"), ServiceScope(host: "amaz0n.com")]
        let needed = try await vault.session.hostsNeedingConfirmation(in: pair)
        #expect(needed.map(\.host).sorted() == ["amaz0n.com", "amazon.com"], "each resembles the other")
        await #expect(throws: VaultError.self) { try await vault.session.save(pair) }

        let amazon = try await vault.session.save(Self.amazon(in: personal))
        // Another item of the person's, given a look-alike of Amazon.
        var other = Item(vaultID: personal, title: "Shop", scopes: [ServiceScope(host: "amazom.com")], fields: [])
        #expect(try await vault.session.hostsNeedingConfirmation(in: other).first?.resembles == ["amazon.com"])
        other.scopes = [ServiceScope(host: "bookshop.example")]
        #expect(try await vault.session.save(other).scopes.map(\.host) == ["bookshop.example"])

        // The item's own subdomain, and an unrelated host.
        var widened = amazon
        widened.scopes = ItemEditorModel.scopes(
            from: "amazon.com, smile.amazon.com, payments.example", keeping: amazon.scopes)
        #expect(try await vault.session.hostsNeedingConfirmation(in: widened).isEmpty)
        #expect(try await vault.session.save(widened).scopes.count == 3)

        // A host outside ASCII resembles nothing saved and still cannot be read by eye.
        var idn = Item(vaultID: personal, title: "Bücher", scopes: [ServiceScope(host: "bücher.example")], fields: [])
        idn.scopes = ItemEditorModel.scopes(from: "bücher.example", keeping: [])
        let unreadable = try await vault.session.hostsNeedingConfirmation(in: idn)
        #expect(unreadable.count == 1 && unreadable[0].resembles.isEmpty)
        let prompt = HostConfirmationPrompt(unreadable[0], scope: idn.scopes[0], itemTitle: idn.title)
        #expect(prompt.title.contains("xn--bcher-kva.example"))

        // A URL pasted whole is not a host.
        var pasted = amazon
        pasted.version = try await vault.session.item(id: amazon.id).version
        pasted.scopes = ItemEditorModel.scopes(from: "amazon.com, https://amaz0n.com/ap/signin", keeping: amazon.scopes)
        await #expect(throws: VaultError.self) { try await vault.session.save(pasted, confirmingHosts: ["amaz0n.com"]) }
    }
}
