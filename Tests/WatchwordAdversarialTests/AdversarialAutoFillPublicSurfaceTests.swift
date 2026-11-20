import Foundation
import Testing
import WatchwordAutoFill
import WatchwordKit
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

// Review finding Z78 (docs/06-adversarial-review.md): public entry points that skipped a check the rest enforce.
extension AdversarialAutoFillRequestTests {
    /// Threat: A6, a look-alike page, through any caller of the session's `CredentialVault` conformance that is not
    /// the model (an adapter written later, a second extension). `saveCredentialItem` saved with
    /// `.confirmedByCaller`, so a new item scoped to `amaz0n.com` beside a saved `amazon.com` went in with nobody
    /// asked, and then filled on the look-alike. The look-alike check of PRD F11.7 (Z61) is now made there too: a host
    /// that needs a confirmation is refused unless the call names it, as the model does for the one it warned about.
    @Test("the session's credential-vault save cannot add a look-alike host unnamed")
    func credentialVaultSaveChecksLookAlikes() async throws {
        let vault = TestVault(clock: FakeClock(AutoFillFixtures.now))
        try await vault.createAccount()
        let personal = try #require(await vault.session.personalVaultID)
        _ = try await vault.session.save(
            Item(vaultID: personal, title: "Amazon", scopes: [ServiceScope(host: "amazon.com")], fields: []))
        let planted = Item(
            vaultID: personal, title: "amaz0n.com",
            scopes: [ServiceScope(host: "amaz0n.com", includeSubdomains: false)],
            fields: [Field(kind: .password, label: "Password", value: "typed")])
        let session: any CredentialVault = vault.session
        await #expect(throws: CredentialVaultError.self) {
            try await session.saveCredentialItem(planted, replacingVersion: nil)
        }
        #expect(try await vault.session.items(in: personal).items.count == 1)

        // The model names the host whose warning its sheet showed, and only then: the person who chose a new item on
        // the save sheet's warning saves it; nothing is saved there unasked.
        let model = CredentialProviderModel(vault: vault.session, clock: FakeClock(AutoFillFixtures.now))
        let request = SavePasswordRequest(
            serviceIdentifier: AutoFillFixtures.url("https://amaz0n.com/signin"), userName: "pat", password: "typed")
        #expect(await model.savePasswordWithoutInteraction(request) == .requiresInteraction(.confirmation))
        guard case .createItem(let proposal) = try await model.savePasswordPlan(for: request).value else {
            Issue.record("no proposal")
            return
        }
        #expect(proposal.warning?.impersonating == ["amazon.com"])
        let saved = try await model.savePassword(request, to: .newItem).value
        #expect(try await vault.session.item(id: saved.itemID).scopes.map(\.host) == ["amaz0n.com"])
    }
}
