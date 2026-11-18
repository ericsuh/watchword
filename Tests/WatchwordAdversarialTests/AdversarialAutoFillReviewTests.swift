import Foundation
import Testing
import WatchwordAutoFill
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

// Findings of the review of the Z60 to Z69 fixes (docs/06-adversarial-review.md, rows Z70 onwards). The adversaries
// are those of docs/02-architecture.md §2: A4, a current member of a shared vault who may write, and A6, a page or a
// relying party.
extension AdversarialAutoFillRequestTests {
    /// Threat (Z70): A4 directs a keyboard suggestion without a page being named. The victim's own login covers the
    /// whole of `shop.example`, user `alice@x`, and is published for QuickType. A4 puts an item into the shared vault,
    /// also scoped to the whole site, with a user name that differs by bytes and not to the eye (a Cyrillic а, a
    /// trailing space). The names differ, so the "a name another item at the host shares" rule passed both, the
    /// shared one passed the gate because the victim's own item makes the host recognised, and QuickType showed two
    /// rows that look identical and name no vault. A tap on A4's row released A4's password with no UI; the victim
    /// signed in to an account A4 controls. The same for one-time-code identities. Now where an item of another trust
    /// class is scoped to the same host, neither item has a suggestion there: the person chooses in the list, which
    /// names the vault.
    @Test(
        "a member cannot steer a keyboard suggestion with a look-alike user name at the person's own site",
        arguments: ["\u{0430}lice@x", "alice@x ", "alice@x"])
    func lookAlikeUserNameAtTheSameHost(plantedName: String) async throws {
        var own = Self.login(
            80, vault: Fixtures.vaultID, title: "Shop", scope: ServiceScope(host: "shop.example"),
            userName: "alice@x", password: "real")
        own.fields.append(Fixtures.totp("own-totp-secret-001", id: Fixtures.id(8003)))
        var planted = Self.login(
            81, vault: Fixtures.sharedVaultID, title: "Shop", scope: ServiceScope(host: "shop.example"),
            userName: plantedName, password: "attacker")
        planted.fields.append(Fixtures.totp("planted-totp-secret", id: Fixtures.id(8103)))

        let harness = AutoFillHarness(items: [own, planted], sharedVaults: Self.household)
        let published = try await harness.publishedIdentities()
        #expect(published.isEmpty, "\(published)")

        // A stale identity of either, handed back, needs the person.
        for (item, name) in [(own, "alice@x"), (planted, plantedName)] {
            let password = PasswordIdentity(
                host: "shop.example", user: name, recordIdentifier: RecordIdentifier(itemID: item.id), rank: 5)
            #expect(
                await harness.model.passwordWithoutInteraction(for: password.handedBack)
                    == .requiresInteraction(.ambiguousMatch))
            let code = OneTimeCodeIdentity(
                host: "shop.example", label: name,
                recordIdentifier: RecordIdentifier(itemID: item.id, fieldID: item.fields[2].id))
            #expect(
                await harness.model.oneTimeCodeWithoutInteraction(for: code.handedBack)
                    == .requiresInteraction(.ambiguousMatch))
        }

        // On the page both are listed, each with its vault, and nothing is suggested.
        let list = try #require(
            await harness.model.credentialList(for: [Fixtures.url("https://www.shop.example/")]).list)
        #expect(Set(list.passwords.map(\.itemID)) == [own.id, planted.id])
        #expect(list.suggested == nil)

        // Two of the person's own vaults are one trust class: each item keeps its suggestion (names that differ).
        let otherOwnVault = UUID(uuidString: "00000000-0000-4000-8000-0000000000CC")!
        var second = planted
        second.vaultID = otherOwnVault
        let alone = AutoFillHarness(items: [own, second])
        let ownPublished = try await alone.publishedPasswords()
        if plantedName == "alice@x" {
            #expect(ownPublished.isEmpty, "two of the person's own accounts tie under one name")
        } else {
            #expect(Set(ownPublished.map(\.recordIdentifier.itemID)) == [own.id, second.id])
        }
    }

    /// Threat (Z70, passkeys): the same member saves a passkey for the shop in the shared vault under a user name
    /// that looks like the victim's. Every passkey the gate would release was published, and for a relying party
    /// where the two classes meet the gate answers `chooseAmong` with both: the system's passkey sheet showed two rows
    /// alike, and a tap on A4's signed the victim in to A4's account. Now a shared vault's passkey is not published
    /// where the relying party's matches include an item of another vault, and a stale identity of it handed back
    /// needs the person.
    @Test("a member's passkey is not suggested where the person's own account for the relying party is")
    func memberPasskeyBesideTheOwnAccount() async throws {
        let ownField = Fixtures.passkey(
            relyingParty: "shop.example", userName: "alice@x", seed: 82, id: Fixtures.id(8203))
        var own = Self.login(
            82, vault: Fixtures.vaultID, title: "Shop", scope: ServiceScope(host: "shop.example"),
            userName: "alice@x", password: nil)
        own.fields.append(ownField)
        let plantedField = Fixtures.passkey(
            relyingParty: "shop.example", userName: "\u{0430}lice@x", seed: 83, id: Fixtures.id(8303))
        var planted = Self.login(
            83, vault: Fixtures.sharedVaultID, title: "Shop", scope: ServiceScope(host: "shop.example"),
            userName: "\u{0430}lice@x", password: nil)
        planted.fields.append(plantedField)

        let harness = AutoFillHarness(items: [own, planted], sharedVaults: Self.household)
        let published = try await harness.publishedIdentities()
        #expect(published.map(\.recordIdentifier) == [RecordIdentifier(itemID: own.id, fieldID: ownField.id)])

        let credential = try plantedField.passkeyCredential()
        let stale = PasskeyIdentity(
            relyingPartyID: "shop.example", userName: credential.userName, credentialID: credential.credentialID,
            userHandle: credential.userHandle,
            recordIdentifier: RecordIdentifier(itemID: planted.id, fieldID: plantedField.id),
            rank: 5)
        let request = PasskeyAssertionRequest(relyingPartyID: "shop.example", clientDataHash: Fixtures.clientDataHash())
        #expect(
            await harness.model.passkeyAssertionWithoutInteraction(
                request: request, identity: stale.handedBack, presence: .verified)
                == .requiresInteraction(.ambiguousMatch))
        // The person can still choose it in the extension's list, which names the vault.
        _ = try await harness.model.passkeyAssertion(
            for: FieldChoice(itemID: planted.id, fieldID: plantedField.id), request: request, presence: .verified
        ).value

        // Alone in the shared vault, the member's passkey is suggested as before.
        let household = AutoFillHarness(items: [planted], sharedVaults: Self.household)
        #expect(try await household.publishedIdentities().count == 1)
        _ = try await household.model.passkeyAssertionWithoutInteraction(
            request: request, identity: stale.handedBack, presence: .verified
        ).value
    }
}

extension AdversarialAutoFillRequestTests {
    /// Threat (Z76): A4 puts `аmazon.com` (Cyrillic а) into the household vault, which is where the family's only
    /// Amazon login is. A host a shared vault matches was compared only with what is outside the vaults that recognise
    /// it, and that held for the host being added to an item as well as for a page: when the victim added
    /// `аmazon.com` to an item of their own, or to the household's Amazon item, the editor asked nothing, the host
    /// reading as recognised, and the victim's own item then filled there. Now a host being added to an item is
    /// recognised only by the person's own vaults or the item's own vault, and is compared with every saved scope that
    /// does not itself match it. The gate's judgement of a page is unchanged (within one shared vault a member could
    /// as well edit the item the look-alike resembles; `AdversarialPhishingTests` holds that), and a host that cannot
    /// be read is refused there whatever.
    @Test("a member's look-alike in a shared vault vouches for no item the person adds it to")
    func sharedVaultLookAlikeOfItsOwnSite() async throws {
        let lookAlike = "\u{0430}mazon.com"
        let real = Self.login(
            90, vault: Fixtures.sharedVaultID, title: "Amazon", scope: ServiceScope(host: "amazon.com"),
            userName: "family", password: "family-password")
        let planted = Self.login(
            91, vault: Fixtures.sharedVaultID, title: "Amazon", scope: ServiceScope(host: lookAlike),
            userName: "family", password: "member-password")
        let harness = AutoFillHarness(items: [real, planted], sharedVaults: Self.household)
        let page = Fixtures.url("https://\(lookAlike)/signin")
        guard case .warning = await harness.model.credentialList(for: [page]) else {
            Issue.record("a host that mixes scripts is offered without a warning")
            return
        }

        // The editor's question, for an item of the person's own vault and for one of the household's.
        let sites = SavedSites(stored: [real, planted], ownVaults: [Fixtures.vaultID]).prepared()
        #expect(
            sites.standing(ofNewHost: lookAlike, inVault: Fixtures.vaultID)
                == .needsConfirmation(resembles: ["amazon.com"]))
        #expect(
            sites.standing(ofNewHost: lookAlike, inSharedVault: true, inVault: Fixtures.sharedVaultID)
                == .needsConfirmation(resembles: ["amazon.com"]))
        // A plain host a member saved is still recognised for that vault's items, and for no other vault's.
        let plain = Self.login(
            92, vault: Fixtures.sharedVaultID, title: "Club", scope: ServiceScope(host: "gardenclub.example"),
            userName: "family", password: "club")
        let more = SavedSites(stored: [real, plain], ownVaults: [Fixtures.vaultID]).prepared()
        #expect(
            more.standing(ofNewHost: "gardenclub.example", inSharedVault: true, inVault: Fixtures.sharedVaultID)
                == .ordinary)
        #expect(more.standing(ofNewHost: "gardenclub.example", inVault: Fixtures.vaultID) == .ordinary)
        // A look-alike that only a shared vault holds a scope for, and that resembles nothing saved, still reads as
        // nothing in particular for another vault's item: neither recognised nor a look-alike.
        let lone = Self.login(
            93, vault: Fixtures.sharedVaultID, title: "Lone", scope: ServiceScope(host: "lone-site.example"),
            userName: "family", password: "lone")
        let single = SavedSites(stored: [lone], ownVaults: [Fixtures.vaultID]).prepared()
        #expect(single.standing(ofNewHost: "lone-site.example", inVault: Fixtures.vaultID) == .ordinary)
    }
}
