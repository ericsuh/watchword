import Foundation
import Testing
import WatchwordAutoFill
import WatchwordInterchange
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordKit

// Review finding Z62 (docs/06-adversarial-review.md): what a new entry of an import file can do to AutoFill. The
// adversary is A7 of docs/02-architecture.md §2: whoever hands the person the file. They control every byte of it
// and nothing else.
extension AdversarialSessionInterchangeTests {
    static func cxf(items: String) -> [UInt8] {
        Array(
            #"""
            {"version": {"major": 1, "minor": 0}, "exporterRpId": "exporter.example", "exporterDisplayName": "Exporter",
             "timestamp": 1755129600,
             "accounts": [{"id": "YWNjb3VudC0x", "username": "wendy", "email": "wendy@example.com", "collections": [],
               "items": [\#(items)]}]}
            """#.utf8)
    }

    static func cxfLogin(title: String, urls: [String], username: String, password: String) -> String {
        let list = urls.map { "\"\($0)\"" }.joined(separator: ", ")
        return #"""
            {"id": "aXRlbS0x", "creationAt": 1614298956, "modifiedAt": 1635346445, "title": "\#(title)",
             "scope": {"urls": [\#(list)], "androidApps": []},
             "credentials": [{"type": "basic-auth", "username": {"fieldType": "string", "value": "\#(username)"},
               "password": {"fieldType": "concealed-string", "value": "\#(password)"}}]}
            """#
    }

    static let loginPage = ServiceIdentifier("https://login.bank.example/", kind: .url)

    static func provider(_ vault: TestVault) -> CredentialProviderModel {
        CredentialProviderModel(vault: vault.session, clock: FakeClock(AutoFillFixtures.now))
    }

    /// Threat: A7's file holds an entry titled like the victim's bank login, with two URLs: the bank's own login
    /// host, and a host of the attacker's. It duplicates nothing (another host, so no match), and used to be
    /// imported with no question as one item scoped to both. One label below the victim's login for `bank.example`,
    /// it outranked it: the extension stopped offering the real login on the bank's sign-in page, filled the bogus
    /// password, and offered the imported item as the one to update when the victim typed the real password, which
    /// was then offered on the attacker's host. Now the preview says, by the gate's own ranking, which saved account
    /// the entry would hide and on which host; the commit refuses without a decision for it; and skipped, it changes
    /// nothing.
    @Test("an imported entry that would outrank a saved login needs a decision, and names what it would hide")
    func importedEntryCannotTakeOverUnasked() async throws {
        let (vault, personal) = try await Self.vault()
        let bank = try await vault.session.save(Self.bank(personal))
        let file = Self.cxf(
            items: Self.cxfLogin(
                title: "Bank", urls: ["https://login.bank.example/", "https://portal.evil.example/"],
                username: "wendy", password: "bogus"))
        let preview = try await vault.session.previewImport(file, format: .credentialExchange, into: personal)
        #expect(preview.matches.isEmpty, "another host: not a duplicate")
        let entry = try #require(preview.entries.first)
        let concern = try #require(preview.concerns.first)
        #expect(preview.concerns.count == 1 && concern.importedID == entry.id)
        #expect(
            concern.hidden == [
                AffectedAccount(itemID: bank.id, vaultID: personal, title: "Bank", host: "login.bank.example")
            ])
        #expect(concern.beside.isEmpty && concern.lookAlikeHosts.isEmpty && !concern.isArchived)
        #expect(Set(entry.scopes.map(\.host)) == ["login.bank.example", "portal.evil.example"])

        await #expect(throws: InterchangeSessionError.decisionRequired(importedID: entry.id)) {
            try await vault.session.commitImport(preview.id, decisions: [:])
        }
        // The refusal consumed nothing and wrote nothing.
        #expect(try await vault.session.items().items.map(\.id) == [bank.id])
        let skipped = try await vault.session.commitImport(preview.id, decisions: [entry.id: .skip])
        #expect(skipped.skipped == [entry.id] && skipped.created.isEmpty)
        let list = try #require(await Self.provider(vault).credentialList(for: [Self.loginPage]).list)
        #expect(list.passwords.map(\.itemID) == [bank.id])

        // Imported all the same, it is the person's decision, made on what the preview showed.
        let again = try await vault.session.previewImport(file, format: .credentialExchange, into: personal)
        let chosen = try #require(again.concerns.first).importedID
        #expect(try await vault.session.commitImport(again.id, decisions: [chosen: .keepBoth]).created.count == 1)
    }

    /// Threat: the same file, with the entry marked archived. An archived item ranks and is never listed or
    /// released, so it hid the saved login on the bank's sign-in page while offering nothing in its place: AutoFill
    /// went silent there, with nothing on any screen to say why, and the person typed the password by hand. The
    /// import review could not show it: the entry's state was dropped. Now it is a concern like any other entry that
    /// outranks, and says that the entry is archived.
    @Test("an archived entry that would hide a saved login is not imported without a decision")
    func archivedEntryCannotHideUnasked() async throws {
        let (vault, personal) = try await Self.vault()
        let bank = try await vault.session.save(Self.bank(personal))
        let file = Array(
            """
            Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes
            Old bank,https://login.bank.example/,,,,false,true,,
            """.utf8)
        let preview = try await vault.session.previewImport(file, format: .passwordCSV, into: personal)
        let concern = try #require(preview.concerns.first)
        #expect(concern.isArchived)
        #expect(concern.hidden.map(\.itemID) == [bank.id])
        #expect(preview.entries.first?.state == .archived)
        await #expect(throws: InterchangeSessionError.decisionRequired(importedID: concern.importedID)) {
            try await vault.session.commitImport(preview.id, decisions: [:])
        }
    }

    /// Threat: duplicates were looked for in the target vault only, and AutoFill ranks across every vault. An entry
    /// with the host and login name of an item the victim keeps in another vault raised no question and then tied
    /// with it: two rows on every fill, and either offered for the next saved password. The concern names the saved
    /// account and its vault whichever vault it is in.
    @Test("an entry that would stand beside a login saved in another vault needs a decision")
    func entryBesideAnotherVaultsLogin() async throws {
        let (vault, personal) = try await Self.vault()
        let work = try await vault.session.createVault(name: "Work").id
        let bank = try await vault.session.save(Self.bank(work))
        let file = Array(
            """
            Title,URL,Username,Password,Notes,OTPAuth
            Bank,https://bank.example/,wendy,other,,
            """.utf8)
        let preview = try await vault.session.previewImport(file, format: .passwordCSV, into: personal)
        #expect(preview.matches.isEmpty)
        let concern = try #require(preview.concerns.first)
        #expect(concern.hidden.isEmpty)
        #expect(
            concern.beside == [AffectedAccount(itemID: bank.id, vaultID: work, title: "Bank", host: "bank.example")])
    }

    /// Threat: A7 with A6. An entry for a look-alike of a saved site, imported as a new item of the person's own,
    /// made the look-alike a host the vault recognises: no warning there any more, and the extension offering the
    /// file's login on the phishing page. A host enters an item's scopes only with the confirmation PRD F11.7
    /// requires, from a file as from the editor.
    @Test("an entry scoped to a look-alike of a saved site needs a decision that names the site")
    func lookAlikeEntryNeedsADecision() async throws {
        let (vault, personal) = try await Self.vault()
        try await vault.session.save(
            Item(vaultID: personal, title: "Amazon", scopes: [ServiceScope(host: "amazon.com")], fields: []))
        let file = Array(
            """
            Title,URL,Username,Password,Notes,OTPAuth
            Amazon,https://amaz0n.com/ap/signin,wendy,file-password,,
            Garden club,https://gardenclub.org/,wendy,garden-password,,
            """.utf8)
        let preview = try await vault.session.previewImport(file, format: .passwordCSV, into: personal)
        #expect(preview.concerns.count == 1, "the ordinary entry raises none")
        let concern = try #require(preview.concerns.first)
        #expect(concern.lookAlikeHosts == [HostConfirmation(host: "amaz0n.com", resembles: ["amazon.com"])])
        await #expect(throws: InterchangeSessionError.decisionRequired(importedID: concern.importedID)) {
            try await vault.session.commitImport(preview.id, decisions: [:])
        }
        let outcome = try await vault.session.commitImport(preview.id, decisions: [concern.importedID: .skip])
        #expect(outcome.created.count == 1 && outcome.skipped == [concern.importedID])
        if case .list(let list) = await Self.provider(vault).credentialList(
            for: [ServiceIdentifier("https://amaz0n.com/ap/signin", kind: .url)])
        {
            Issue.record("offered on the look-alike: \(list.passwords.map(\.title))")
        }
    }

    /// Threat: A7 chooses the file's size, and the review compares every host in it with every saved scope. The
    /// comparison is bounded: what a budget does not cover is reported as unchecked, which needs the decision, and
    /// never passes as ordinary.
    @Test("hosts past the review's budget are reported as unchecked, never passed")
    func reviewBudget() {
        let vault = UUID()
        let saved = (0..<10).map {
            Item(
                vaultID: vault, title: "Saved \($0)", scopes: [ServiceScope(host: "saved\($0).example.org")], fields: []
            )
        }
        let sites = SavedSites(stored: saved, ownVaults: [vault])
        let perHost = sites.prepared().comparisonsPerHost
        #expect(perHost == 10)
        // The budget is a parameter so that the test need not make twenty million comparisons to pass it.
        let budget = 5 * perHost
        let drafts = [
            DraftScopes(id: UUID(), scopes: (0..<3).map { ServiceScope(host: "host\($0).test") }, state: .active),
            DraftScopes(id: UUID(), scopes: (3..<6).map { ServiceScope(host: "host\($0).test") }, state: .active),
        ]
        let concerns = VaultSession.importConcerns(
            drafts, among: sites, vaultID: vault, isOwnVault: true, budget: budget)
        #expect(concerns.count == 1, "the first entry fits the budget and is ordinary")
        #expect(concerns.first?.importedID == drafts[1].id)
        #expect(concerns.first?.uncheckedHosts == ["host5.test"])
        #expect(VaultSession.maximumImportHostComparisons >= 1_000_000)
    }
}
