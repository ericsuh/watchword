import Foundation
import Testing
import WatchwordAutoFill
import WatchwordKit
import WatchwordMatching
import WatchwordModel
import WatchwordSharing
import WatchwordTestSupport

// Review finding Z60 (docs/06-adversarial-review.md), end to end: real sessions, a real shared vault, and the AutoFill
// model over the victim's session as the extension will run it.
extension AdversarialSharedVaultTests {
    /// Threat: A4, a member of a shared vault who may write, against another member's passkey. The victim keeps the
    /// shop's login in their Personal vault, saved by the extension for `www.shop.example`. The member saves an item
    /// in the shared vault scoped `shop.example` with the victim's user name. The shop signs the victim in and asks
    /// for a conditional passkey for `shop.example`: the member's item was the one match, the private key was added
    /// to it with nobody asked, sealed under the vault key the member holds, and synced to them. Now the session
    /// tells the model which vaults are shared (its own answer, `isMarkedShared`), the request is refused, nothing
    /// reaches the member, and the sheet that does ask names the vault and that everyone in it would hold the key.
    @Test("a member's planted login never receives another member's passkey without them choosing it")
    func plantedLoginDoesNotCaptureAPasskey() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], name: "Household", seed: 1210)
        let (victim, member) = (home.owner, home.members[0])
        let model = CredentialProviderModel(
            vault: victim.session, clock: FakeClock(AutoFillFixtures.now), random: SeededGenerator(seed: 1211))

        let saved = try await model.savePasswordWithoutInteraction(
            SavePasswordRequest(
                serviceIdentifier: AutoFillFixtures.url("https://www.shop.example/login"), userName: "alice@x",
                password: "victims-password")
        ).value
        let personal = try await victim.session.defaultVaultID()
        #expect(try await victim.session.item(id: saved.itemID).vaultID == personal)
        // A second vault of the victim's own, never shared, is theirs alone.
        let private2 = try await victim.session.createVault(name: "Work").id

        let planted = try await member.session.save(
            Item(
                vaultID: home.vaultID, title: "Shop", scopes: [ServiceScope(host: "shop.example")],
                fields: [
                    Field(kind: .username, label: "Username", value: "alice@x"),
                    Field(kind: .password, label: "Password", value: "anything"),
                ]))
        try await Self.syncAll([member, victim])
        #expect(try await victim.session.item(id: planted.id).title == "Shop")

        // What the session tells the model of each vault.
        let snapshot = try await victim.session.credentialSnapshot()
        #expect(snapshot.defaultVaultID == personal)
        #expect(snapshot.vaults.first { $0.id == home.vaultID }?.isShared == true)
        #expect(snapshot.vaults.first { $0.id == home.vaultID }?.name == "Household")
        #expect(snapshot.vaults.first { $0.id == personal }?.isShared == false)
        #expect(snapshot.vaults.first { $0.id == private2 }?.isShared == false)
        // The member's own device says the same of the vault it writes.
        #expect(
            try await member.session.credentialSnapshot().vaults.first { $0.id == home.vaultID }?.isShared == true)

        let request = PasskeyRegistrationRequest(
            relyingPartyID: "shop.example", user: PasskeyUser(handle: Data("handle".utf8), name: "alice@x"),
            clientDataHash: AutoFillFixtures.clientDataHash())
        #expect(await model.registerPasskeyWithoutInteraction(request) == .refused(.noItemToUpgrade))
        try await Self.syncAll([victim, member])
        #expect(try await !member.session.item(id: planted.id).fields.contains { $0.kind == .passkey })
        #expect(
            try await !member.session.items(in: home.vaultID).items.contains { item in
                item.fields.contains { $0.kind == .passkey }
            })

        let options = try await model.passkeyRegistrationOptions(for: request).value
        #expect(
            options.existingItems.map(\.vault)
                == [EntryVault(id: home.vaultID, name: "Household", isShared: true)])
        #expect(options.suggested == .newItem)
        #expect(options.newItem.vault == EntryVault(id: personal, name: VaultInfo.defaultPersonalName, isShared: false))
        #expect(options.relatedLogins.map(\.itemID) == [saved.itemID])

        // The passkey the suggestion makes stays in the Personal vault, where the member reads nothing.
        let result = try await model.registerPasskey(request, destination: options.suggested, presence: .verified).value
        #expect(try await victim.session.item(id: result.itemID).vaultID == personal)
        try await Self.syncAll([victim, member])
        #expect(
            try await !member.session.items().items.contains { item in
                item.fields.contains { $0.kind == .passkey }
            })
    }

    /// Threat: the same member against the victim's password. The planted item is scoped to the exact login host,
    /// below the victim's own login for the domain, and holds no password: it used to shadow the victim's login out
    /// of the extension and stand as the only item to update. Over real sessions: the victim's login is still listed
    /// and released, the update sheet offers it first and names both vaults, and nothing is saved silently.
    @Test("a member's more specific item neither hides another member's own login nor takes its next password")
    func plantedLoginDoesNotHideOrCapture() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], name: "Household", seed: 1230)
        let (victim, member) = (home.owner, home.members[0])
        let model = CredentialProviderModel(
            vault: victim.session, clock: FakeClock(AutoFillFixtures.now), random: SeededGenerator(seed: 1231))
        let personal = try await victim.session.defaultVaultID()
        let own = try await victim.session.save(
            Item(
                vaultID: personal, title: "Bank", scopes: [ServiceScope(host: "bank.example")],
                fields: [
                    Field(kind: .username, label: "Username", value: "alice@x"),
                    Field(kind: .password, label: "Password", value: "real-password"),
                ]))
        let planted = try await member.session.save(
            Item(
                vaultID: home.vaultID, title: "Bank",
                scopes: [ServiceScope(host: "www.bank.example", includeSubdomains: false)],
                fields: [Field(kind: .username, label: "Username", value: "alice@x")]))
        try await Self.syncAll([member, victim])

        let page = AutoFillFixtures.url("https://www.bank.example/login")
        guard case .list(let list) = await model.credentialList(for: [page]) else {
            Issue.record("no list")
            return
        }
        #expect(list.passwords.map(\.itemID) == [own.id])
        #expect(list.passwords.first?.vault.isShared == false)
        #expect(
            try await model.password(for: PasswordChoice(itemID: own.id, userName: "alice@x"), identifiers: [page])
                .value.password == "real-password")

        let request = SavePasswordRequest(serviceIdentifier: page, userName: "alice@x", password: "new-password")
        #expect(await model.savePasswordWithoutInteraction(request) == .requiresInteraction(.confirmation))
        guard case .offerUpdate(let candidates, _) = try await model.savePasswordPlan(for: request).value else {
            Issue.record("no update offered")
            return
        }
        #expect(candidates.map(\.itemID) == [own.id, planted.id])
        #expect(candidates.map(\.vault.isShared) == [false, true])
        #expect(candidates.last?.vault.name == "Household")
        _ = try await model.savePassword(request, to: .existingItem(own.id)).value
        try await Self.syncAll([victim, member])
        #expect(try await member.session.item(id: planted.id).field(.password) == nil)
    }
}
