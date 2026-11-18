import Foundation
import Testing
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordAutoFill

@Suite("Credential identity publishing")
struct CredentialIdentityTests {
    typealias Fixtures = AutoFillFixtures

    static func passwords(_ identities: [CredentialIdentity]) -> [PasswordIdentity] {
        identities.compactMap {
            if case .password(let identity) = $0 { return identity }
            return nil
        }
    }

    static func passkeys(_ identities: [CredentialIdentity]) -> [PasskeyIdentity] {
        identities.compactMap {
            if case .passkey(let identity) = $0 { return identity }
            return nil
        }
    }

    static func codes(_ identities: [CredentialIdentity]) -> [OneTimeCodeIdentity] {
        identities.compactMap {
            if case .oneTimeCode(let identity) = $0 { return identity }
            return nil
        }
    }

    static func plan(_ items: Item...) -> [CredentialIdentity] {
        CredentialIdentityPlanner.identities(for: items)
    }

    // MARK: Planner

    @Test("one password identity per whole-site scope host and user, ranked by the host's specificity")
    func wholeSiteLogin() {
        let retail = Self.passwords(Self.plan(Fixtures.amazonRetail))
        #expect(retail.map(\.host) == ["amazon.com"])
        #expect(retail.map(\.user) == [Fixtures.email])
        #expect(retail[0].rank == 5)
        #expect(retail[0].recordIdentifier == RecordIdentifier(itemID: Fixtures.amazonRetail.id))
        let bank = Self.passwords(Self.plan(Fixtures.bank))
        #expect(bank.map(\.host) == ["firstbank.co.uk"])
        #expect(bank.map(\.user) == ["40012345"])
        #expect(bank[0].rank == 7)
    }

    /// The system hands a tapped identity back without the page and chooses itself where to offer it, so an
    /// identity is published only where the item is right on every page of its site.
    @Test("S1: once the AWS item exists, neither Amazon account has a password or code identity")
    func scenarioS1() {
        #expect(Self.plan(Fixtures.amazonRetail).count == 2)
        // Scoped to hosts below the site's root: the system could offer these on `www.amazon.com`.
        #expect(Self.plan(Fixtures.awsRoot).isEmpty)
        #expect(Self.plan(Fixtures.amazonRetail, Fixtures.awsRoot).isEmpty)
        // An archived AWS item still ranks on the console, so it still counts; one in the trash does not.
        var archived = Fixtures.awsRoot
        archived.archived = true
        #expect(Self.plan(Fixtures.amazonRetail, archived).isEmpty)
        var excluded = Fixtures.awsRoot
        excluded.excludedFromSuggestions = true
        #expect(Self.plan(Fixtures.amazonRetail, excluded).isEmpty)
        var trashed = Fixtures.awsRoot
        trashed.trashedAt = Fixtures.now
        #expect(Self.plan(Fixtures.amazonRetail, trashed).count == 2)
        // A scope the policy refuses matches nothing, so it hides nothing either.
        var broad = Fixtures.library
        broad.scopes = [ServiceScope(host: "com")]
        #expect(Self.plan(Fixtures.amazonRetail, broad).count == 2)
    }

    @Test(
        "a scope that is not the whole site publishes no password or code identity",
        arguments: [
            ServiceScope(host: "amazon.com", includeSubdomains: false),
            ServiceScope(host: "amazon.com", excludedHosts: ["aws.amazon.com"]),
            ServiceScope(host: "www.amazon.com"), ServiceScope(host: "www.amazon.com", includeSubdomains: false),
            ServiceScope(host: "signin.aws.amazon.com", includeSubdomains: false),
            // A tenant of a shared host: whether the system treats `zendesk.com` as a suffix is not ours to know.
            ServiceScope(host: "acme.zendesk.com"), ServiceScope(host: "alice.github.io"),
            // Under a country-code suffix the list does not carry, the last two labels are taken for the site.
            ServiceScope(host: "bank.com.fj"), ServiceScope(host: "www.firstbank.co.uk"),
            ServiceScope(host: "192.168.1.10"),
        ])
    func partialScopes(_ scope: ServiceScope) {
        var item = Fixtures.amazonRetail
        item.scopes = [scope]
        #expect(Self.plan(item).isEmpty)
        // Beside a whole-site scope it adds nothing and takes nothing away.
        item.scopes = [scope, ServiceScope(host: "example.net")]
        #expect(Self.passwords(Self.plan(item)).map(\.host) == ["example.net"])
    }

    @Test("accounts on one site are published when their names differ, and not when a name is shared")
    func tiedAccounts() {
        var work = Fixtures.amazonRetail
        work.id = Fixtures.id(90)
        work.fields[0].value = "work@example.com"
        let both = Self.plan(Fixtures.amazonRetail, work)
        #expect(Self.passwords(both).map(\.user) == [Fixtures.email, "work@example.com"])
        #expect(Self.codes(both).map(\.label) == [Fixtures.email, "work@example.com"])

        // The second account also knows the first one's email: that name no longer tells them apart.
        work.fields.append(Field(kind: .username, label: "Old", value: Fixtures.email))
        let shared = Self.plan(Fixtures.amazonRetail, work)
        #expect(Self.passwords(shared).map(\.user) == ["work@example.com"])
        #expect(Self.codes(shared).map(\.label) == ["work@example.com"])

        // An account scoped to the root alone ties on that one host, which is enough.
        var rootOnly = Fixtures.amazonRetail
        rootOnly.id = Fixtures.id(91)
        rootOnly.scopes = [ServiceScope(host: "amazon.com", includeSubdomains: false)]
        #expect(Self.plan(Fixtures.amazonRetail, rootOnly).isEmpty)
    }

    @Test("one identity per passkey the gate would release, and one for an item's single code field")
    func passkeysAndCodes() throws {
        let identities = Self.plan(Fixtures.google)
        let passkey = try #require(Self.passkeys(identities).first)
        let credential = try #require(try Fixtures.google.field(.passkey)?.passkeyCredential())
        #expect(Self.passkeys(identities).count == 1)
        #expect(passkey.relyingPartyID == "google.com")
        #expect(passkey.credentialID == credential.credentialID)
        #expect(passkey.userHandle == credential.userHandle)
        #expect(passkey.userName == Fixtures.email)
        #expect(passkey.recordIdentifier == RecordIdentifier(itemID: Fixtures.google.id, fieldID: Fixtures.id(302)))
        // Google holds no password, so there is no password identity to publish.
        #expect(Self.passwords(identities).isEmpty)

        let codes = Self.codes(Self.plan(Fixtures.bank))
        #expect(codes.map(\.host) == ["firstbank.co.uk"])
        #expect(codes.map(\.label) == ["40012345"])
        #expect(codes.map(\.recordIdentifier.fieldID) == [Fixtures.id(404)])

        // Two code fields would be two suggestions under one name.
        var twoCodes = Fixtures.bank
        twoCodes.fields.append(Fixtures.totp("second-totp-secret-0"))
        #expect(Self.codes(Self.plan(twoCodes)).isEmpty)
        #expect(Self.passwords(Self.plan(twoCodes)).count == 1)
    }

    /// A passkey request names its relying party, so the gate is asked, and the identity follows the gate.
    @Test("a passkey is published exactly when the gate would release it for its relying party")
    func passkeyFollowsTheGate() {
        var login = Fixtures.amazonRetail
        login.scopes = [ServiceScope(host: "login.example.com")]
        login.fields.append(Fixtures.passkey(relyingParty: "login.example.com", seed: 11))
        var broad = Fixtures.library
        broad.scopes = [ServiceScope(host: "example.com")]
        broad.fields.append(Fixtures.passkey(relyingParty: "login.example.com", seed: 12))
        #expect(Self.passkeys(Self.plan(broad)).count == 1)
        // Beside a more specific item, the broad one is an "other account" for that relying party.
        let both = Self.passkeys(Self.plan(broad, login))
        #expect(both.map(\.recordIdentifier.itemID) == [login.id])

        var outside = Fixtures.google
        outside.scopes = [ServiceScope(host: "accounts.example.net")]
        #expect(Self.passkeys(Self.plan(outside)).isEmpty)
    }

    @Test("every login name gets its own identity, once")
    func multipleUsers() {
        var item = Fixtures.amazonRetail
        item.fields.append(Field(kind: .username, label: "Username", value: "pat"))
        item.fields.append(Field(kind: .username, label: "Again", value: "pat"))
        item.fields.append(Field(kind: .username, label: "Blank", value: ""))
        item.scopes.append(ServiceScope(host: "amazon.com"))
        #expect(Self.passwords(Self.plan(item)).map(\.user) == [Fixtures.email, "pat"])
    }

    @Test("nothing is published for an excluded, archived or trashed item (F6.8)")
    func excludedItems() {
        var excluded = Fixtures.amazonRetail
        excluded.excludedFromSuggestions = true
        var archived = Fixtures.google
        archived.archived = true
        var trashed = Fixtures.bank
        trashed.trashedAt = Fixtures.now
        #expect(CredentialIdentityPlanner.identities(for: [excluded, archived, trashed]).isEmpty)
        #expect(!CredentialIdentityPlanner.identities(for: Fixtures.all).isEmpty)
    }

    @Test("nothing is published for an ID two items share")
    func duplicatedIDs() {
        var twin = Fixtures.library
        twin.id = Fixtures.bank.id
        #expect(CredentialIdentityPlanner.identities(for: [Fixtures.bank, twin]).isEmpty)
        #expect(!CredentialIdentityPlanner.identities(for: [Fixtures.bank]).isEmpty)
    }

    /// The identity store is plaintext outside the app (docs/02-architecture.md §2, "Also disclosed by design").
    @Test("an identity carries hosts, user names and opaque IDs, and nothing else from the item")
    func minimalDisclosure() {
        var items = [Fixtures.amazonRetail, Fixtures.google, Fixtures.bank]
        items[0].notes = "NOTE-MARKER"
        items[0].tags = ["TAG-MARKER"]
        let identities = CredentialIdentityPlanner.identities(for: items)
        #expect(identities.count == 5)
        let dump = String(describing: identities)
        for secret in [
            "retail-password", "bank-password", "Rex", "1111-2222", "otpauth", "NOTE-MARKER", "TAG-MARKER",
            "First Bank", "Amazon", "Google", "+44", "One-time code", "Backup codes",
        ] {
            #expect(!dump.contains(secret), "\(secret) would be published")
        }
        let credential = try? Fixtures.google.field(.passkey)?.passkeyCredential()
        #expect(credential != nil)
        if let credential {
            #expect(!dump.contains(Base64URL.encode(credential.privateKeyPKCS8)))
        }
    }

    @Test("a password login with no user name, or an empty password, is not published")
    func noUserName() {
        var empty = Fixtures.amazonRetail
        empty.fields[1].value = ""
        #expect(Self.passwords(Self.plan(empty)).isEmpty)
        var item = Fixtures.amazonRetail
        item.fields.removeAll { $0.kind == .email }
        let identities = Self.plan(item)
        #expect(Self.passwords(identities).isEmpty)
        // Its one-time code falls back to the otpauth label's account.
        #expect(Self.codes(identities).map(\.label) == ["Watchword"])
    }

    @Test("scopes the policy refuses, and fields that do not decode, publish nothing")
    func hostileRecords() {
        var item = Fixtures.amazonRetail
        item.scopes = [
            ServiceScope(host: "com"), ServiceScope(host: "co.uk"), ServiceScope(host: "exa mple.com"),
            ServiceScope(host: ""),
        ]
        item.fields.append(Field(kind: .totp, label: "Broken", value: "otpauth://hotp/x?secret=AAAA"))
        item.fields.append(Field(kind: .passkey, label: "Broken", value: "{}"))
        #expect(Self.plan(item).isEmpty)
    }

    @Test("one item cannot flood the identity store")
    func boundedPerItem() {
        var item = Fixtures.amazonRetail
        item.scopes = (0..<200).map { ServiceScope(host: "host\($0).example") }
        item.fields += (0..<50).map { Field(kind: .username, label: "User", value: "user\($0)") }
        #expect(Self.plan(item).count == CredentialIdentityPlanner.maximumIdentitiesPerItem)
    }

    // MARK: Record identifiers

    @Test("a record identifier round-trips and is strict about its spelling")
    func recordIdentifier() throws {
        let item = Fixtures.id(7)
        let field = Fixtures.id(8)
        #expect(RecordIdentifier(RecordIdentifier(itemID: item).text) == RecordIdentifier(itemID: item))
        #expect(
            RecordIdentifier(RecordIdentifier(itemID: item, fieldID: field).text)
                == RecordIdentifier(itemID: item, fieldID: field))
        let text = RecordIdentifier(itemID: item).text
        #expect(text == "00000000-0000-4000-8000-000000000007")
        for bad in [
            "", text.uppercased().replacingOccurrences(of: "0007", with: "000A"), text + "/", "/" + text,
            text + "/" + text + "/" + text, text + " ", String(text.dropLast()), "not-a-uuid",
            text.replacingOccurrences(of: "-", with: ""), "../" + text,
        ] {
            #expect(RecordIdentifier(bad) == nil, "\(bad)")
        }
    }

    // MARK: Differences

    @Test("a new item adds its identities, a deleted one removes them, an unchanged one does nothing")
    func differenceForCreationAndDeletion() {
        let all = Self.plan(Fixtures.bank)
        let created = CredentialIdentityPlanner.difference(
            from: [Fixtures.google], to: [Fixtures.google, Fixtures.bank])
        #expect(created.additions == all)
        #expect(created.removals.isEmpty)
        let deleted = CredentialIdentityPlanner.difference(
            from: [Fixtures.google, Fixtures.bank], to: [Fixtures.google])
        #expect(deleted.removals == all)
        #expect(deleted.additions.isEmpty)
        #expect(CredentialIdentityPlanner.difference(from: Fixtures.all, to: Fixtures.all).isEmpty)
    }

    @Test("an edit changes only the identities it touches")
    func differenceForEdits() {
        var renamed = Fixtures.bank
        renamed.title = "First Bank (joint)"
        renamed.notes = "moved"
        renamed.fields[2].value = "new-password"
        #expect(CredentialIdentityPlanner.difference(from: [Fixtures.bank], to: [renamed]).isEmpty)

        var rescoped = Fixtures.bank
        rescoped.scopes.append(ServiceScope(host: "firstbank.example"))
        let widened = CredentialIdentityPlanner.difference(from: [Fixtures.bank], to: [rescoped])
        #expect(widened.removals.isEmpty)
        #expect(Self.passwords(widened.additions).map(\.host) == ["firstbank.example"])
        #expect(Self.codes(widened.additions).map(\.host) == ["firstbank.example"])

        var reuser = Fixtures.amazonRetail
        reuser.fields[0].value = "pat@new.example"
        let changed = CredentialIdentityPlanner.difference(from: [Fixtures.amazonRetail], to: [reuser])
        #expect(Self.passwords(changed.removals).map(\.user) == [Fixtures.email])
        #expect(Self.passwords(changed.additions).map(\.user) == ["pat@new.example"])
        #expect(Set(changed.removals).isDisjoint(with: changed.additions))
    }

    @Test("one item's change can remove or restore another item's identities")
    func differenceAcrossItems() {
        let retail = Self.plan(Fixtures.amazonRetail)
        let added = CredentialIdentityPlanner.difference(
            from: [Fixtures.amazonRetail], to: [Fixtures.amazonRetail, Fixtures.awsRoot])
        #expect(added.removals == retail)
        #expect(added.additions.isEmpty)
        var trashed = Fixtures.awsRoot
        trashed.trashedAt = Fixtures.now
        let removed = CredentialIdentityPlanner.difference(
            from: [Fixtures.amazonRetail, Fixtures.awsRoot], to: [Fixtures.amazonRetail, trashed])
        #expect(removed.additions == retail)
        #expect(removed.removals.isEmpty)
    }

    @Test("excluding, archiving or trashing an item removes everything it had published")
    func differenceForExclusion() {
        let all = Self.plan(Fixtures.google)
        var excluded = Fixtures.google
        excluded.excludedFromSuggestions = true
        #expect(CredentialIdentityPlanner.difference(from: [Fixtures.google], to: [excluded]).removals == all)
        #expect(CredentialIdentityPlanner.difference(from: [excluded], to: [Fixtures.google]).additions == all)
    }

    // MARK: Publisher

    @Test("publishAll replaces the store with exactly the planned identities")
    func publishAll() async throws {
        let publisher = FakeCredentialIdentityPublisher()
        try await publisher.replaceAll(with: CredentialIdentityPlanner.identities(for: [Fixtures.amazonRetail]))
        let published = try await CredentialIdentityPublishing.publishAll(
            [Fixtures.google, Fixtures.bank], to: publisher)
        #expect(await publisher.published == published)
        #expect(published == CredentialIdentityPlanner.identities(for: [Fixtures.google, Fixtures.bank]))
        #expect(published.count == 3)
    }

    @Test("nothing is published while the provider is not enabled")
    func disabledStore() async throws {
        let publisher = FakeCredentialIdentityPublisher(isEnabled: false)
        #expect(try await CredentialIdentityPublishing.publishAll(Fixtures.all, to: publisher).isEmpty)
        try await CredentialIdentityPublishing.publishChange(
            from: nil, to: Fixtures.google, all: { Fixtures.all }, to: publisher)
        #expect(await publisher.published.isEmpty)
        #expect(await publisher.replaceAllCalls == 0)
        #expect(await publisher.incrementalCalls == 0)
    }

    @Test("a change is applied incrementally where the store allows, and as a full replacement where it does not")
    func publishChange() async throws {
        var edited = Fixtures.bank
        edited.excludedFromSuggestions = true
        let excluded = edited
        let expected = CredentialIdentityPlanner.identities(for: [Fixtures.google])

        let incremental = FakeCredentialIdentityPublisher()
        try await CredentialIdentityPublishing.publishAll([Fixtures.google, Fixtures.bank], to: incremental)
        try await CredentialIdentityPublishing.publishChange(
            from: Fixtures.bank, to: excluded, all: { [Fixtures.google, excluded] }, to: incremental)
        #expect(await incremental.published == expected)
        #expect(await incremental.incrementalCalls == 1)
        #expect(await incremental.replaceAllCalls == 1)

        let whole = FakeCredentialIdentityPublisher(supportsIncrementalUpdates: false)
        try await CredentialIdentityPublishing.publishAll([Fixtures.google, Fixtures.bank], to: whole)
        try await CredentialIdentityPublishing.publishChange(
            from: Fixtures.bank, to: excluded, all: { [Fixtures.google, excluded] }, to: whole)
        #expect(await whole.published == expected)
        #expect(await whole.incrementalCalls == 0)
        #expect(await whole.replaceAllCalls == 2)
    }

    @Test("a created or deleted item's effect on the other items' identities reaches the store")
    func publishChangeAcrossItems() async throws {
        let publisher = FakeCredentialIdentityPublisher()
        try await CredentialIdentityPublishing.publishAll([Fixtures.amazonRetail], to: publisher)
        #expect(await publisher.published.count == 2)
        // The AWS item is created: the retail identities go.
        try await CredentialIdentityPublishing.publishChange(
            from: nil, to: Fixtures.awsRoot, all: { [Fixtures.amazonRetail, Fixtures.awsRoot] }, to: publisher)
        #expect(await publisher.published.isEmpty)
        // And deleted: they come back.
        try await CredentialIdentityPublishing.publishChange(
            from: Fixtures.awsRoot, to: nil, all: { [Fixtures.amazonRetail] }, to: publisher)
        #expect(await publisher.published == CredentialIdentityPlanner.identities(for: [Fixtures.amazonRetail]))
    }
}
