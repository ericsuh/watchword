import Foundation
import Testing
import WatchwordAutoFill
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

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

    // MARK: Planner

    @Test("S1: one password identity per scope host and user, ranked by how specific the host is")
    func scenarioS1() {
        let retail = Self.passwords(CredentialIdentityPlanner.identities(for: Fixtures.amazonRetail))
        let aws = Self.passwords(CredentialIdentityPlanner.identities(for: Fixtures.awsRoot))
        #expect(retail.map(\.host) == ["amazon.com"])
        #expect(aws.map(\.host) == ["signin.aws.amazon.com", "console.aws.amazon.com"])
        #expect(retail.allSatisfy { $0.user == Fixtures.email })
        #expect(aws.allSatisfy { $0.user == Fixtures.email })
        // Distinct ranks: the console's hosts outrank the retail domain (PRD F6.6, E2E-S1).
        #expect(retail[0].rank == 5)
        #expect(aws.map(\.rank) == [9, 9])
        #expect(aws.allSatisfy { $0.rank > retail[0].rank })
        #expect(retail[0].recordIdentifier == RecordIdentifier(itemID: Fixtures.amazonRetail.id))
    }

    @Test("an identity's rank is the specificity the matcher gives an exact match on its host")
    func rankIsSpecificity() throws {
        for identity in Self.passwords(CredentialIdentityPlanner.identities(for: Fixtures.all)) {
            let host = try HostNormalizer.normalize(ServiceIdentifier(identity.host, kind: .domain))
            let match = try #require(ScopeMatcher.match(ServiceScope(host: identity.host), host: host))
            #expect(identity.rank == match.specificity)
        }
    }

    @Test("one identity per passkey and per one-time code field")
    func passkeysAndCodes() throws {
        let identities = CredentialIdentityPlanner.identities(for: Fixtures.google)
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

        let codes = Self.codes(CredentialIdentityPlanner.identities(for: Fixtures.awsRoot))
        #expect(codes.map(\.host) == ["signin.aws.amazon.com", "console.aws.amazon.com"])
        #expect(codes.allSatisfy { $0.label == Fixtures.email })
        #expect(codes.allSatisfy { $0.recordIdentifier.fieldID == Fixtures.id(203) })
    }

    @Test("every login name gets its own identity, once")
    func multipleUsers() {
        var item = Fixtures.amazonRetail
        item.fields.append(Field(kind: .username, label: "Username", value: "pat"))
        item.fields.append(Field(kind: .username, label: "Again", value: "pat"))
        item.fields.append(Field(kind: .username, label: "Blank", value: ""))
        item.scopes.append(ServiceScope(host: "amazon.com"))
        #expect(Self.passwords(CredentialIdentityPlanner.identities(for: item)).map(\.user) == [Fixtures.email, "pat"])
    }

    @Test("nothing is published for an excluded, archived or trashed item (F6.8)")
    func excludedItems() {
        var excluded = Fixtures.amazonRetail
        excluded.excludedFromSuggestions = true
        var archived = Fixtures.google
        archived.archived = true
        var trashed = Fixtures.awsRoot
        trashed.trashedAt = Fixtures.now
        #expect(CredentialIdentityPlanner.identities(for: [excluded, archived, trashed]).isEmpty)
        #expect(!CredentialIdentityPlanner.identities(for: Fixtures.all).isEmpty)
    }

    /// The identity store is plaintext outside the app (docs/02-architecture.md §2, "Also disclosed by design").
    @Test("an identity carries hosts, user names and opaque IDs, and nothing else from the item")
    func minimalDisclosure() {
        var items = Fixtures.all
        items[0].notes = "NOTE-MARKER"
        items[0].tags = ["TAG-MARKER"]
        let dump = String(describing: CredentialIdentityPlanner.identities(for: items))
        for secret in [
            "retail-password", "aws-password", "bank-password", "library-password", "4821", "Rex", "1111-2222",
            "otpauth", "NOTE-MARKER", "TAG-MARKER", "First Bank", "AWS root", "+44", "2 1234",
        ] {
            #expect(!dump.contains(secret), "\(secret) would be published")
        }
        let credential = try? Fixtures.google.field(.passkey)?.passkeyCredential()
        #expect(credential != nil)
        if let credential {
            #expect(!dump.contains(Base64URL.encode(credential.privateKeyPKCS8)))
        }
    }

    @Test("a password login with no user name is not published")
    func noUserName() {
        var item = Fixtures.amazonRetail
        item.fields.removeAll { $0.kind == .email }
        let identities = CredentialIdentityPlanner.identities(for: item)
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
        #expect(CredentialIdentityPlanner.identities(for: item).isEmpty)
    }

    @Test("a passkey its own item is not scoped to is not published")
    func passkeyOutsideScope() {
        var item = Fixtures.google
        item.scopes = [ServiceScope(host: "accounts.example.net")]
        #expect(Self.passkeys(CredentialIdentityPlanner.identities(for: item)).isEmpty)
    }

    @Test("one item cannot flood the identity store")
    func boundedPerItem() {
        var item = Fixtures.amazonRetail
        item.scopes = (0..<200).map { ServiceScope(host: "host\($0).example.com") }
        item.fields += (0..<50).map { Field(kind: .username, label: "User", value: "user\($0)") }
        #expect(
            CredentialIdentityPlanner.identities(for: item).count == CredentialIdentityPlanner.maximumIdentitiesPerItem)
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
        let all = CredentialIdentityPlanner.identities(for: Fixtures.awsRoot)
        let created = CredentialIdentityPlanner.difference(from: nil, to: Fixtures.awsRoot)
        #expect(created.additions == all)
        #expect(created.removals.isEmpty)
        let deleted = CredentialIdentityPlanner.difference(from: Fixtures.awsRoot, to: nil)
        #expect(deleted.removals == all)
        #expect(deleted.additions.isEmpty)
        #expect(CredentialIdentityPlanner.difference(from: Fixtures.awsRoot, to: Fixtures.awsRoot).isEmpty)
    }

    @Test("an edit changes only the identities it touches")
    func differenceForEdits() {
        var renamed = Fixtures.awsRoot
        renamed.title = "AWS (root)"
        renamed.notes = "moved"
        renamed.fields[1].value = "new-password"
        #expect(CredentialIdentityPlanner.difference(from: Fixtures.awsRoot, to: renamed).isEmpty)

        var rescoped = Fixtures.awsRoot
        rescoped.scopes.removeLast()
        let narrowed = CredentialIdentityPlanner.difference(from: Fixtures.awsRoot, to: rescoped)
        #expect(narrowed.additions.isEmpty)
        #expect(narrowed.removals.count == 2)
        #expect(Self.passwords(narrowed.removals).map(\.host) == ["console.aws.amazon.com"])
        #expect(Self.codes(narrowed.removals).map(\.host) == ["console.aws.amazon.com"])

        var reuser = Fixtures.amazonRetail
        reuser.fields[0].value = "pat@new.example"
        let changed = CredentialIdentityPlanner.difference(from: Fixtures.amazonRetail, to: reuser)
        #expect(Self.passwords(changed.removals).map(\.user) == [Fixtures.email])
        #expect(Self.passwords(changed.additions).map(\.user) == ["pat@new.example"])
        #expect(Set(changed.removals).isDisjoint(with: changed.additions))
    }

    @Test("excluding, archiving or trashing an item removes everything it had published")
    func differenceForExclusion() {
        let all = CredentialIdentityPlanner.identities(for: Fixtures.google)
        var excluded = Fixtures.google
        excluded.excludedFromSuggestions = true
        #expect(CredentialIdentityPlanner.difference(from: Fixtures.google, to: excluded).removals == all)
        #expect(CredentialIdentityPlanner.difference(from: excluded, to: Fixtures.google).additions == all)
    }

    // MARK: Publisher

    @Test("publishAll replaces the store with exactly the planned identities")
    func publishAll() async throws {
        let publisher = FakeCredentialIdentityPublisher()
        try await publisher.replaceAll(
            with: CredentialIdentityPlanner.identities(for: [Fixtures.library]))
        let published = try await CredentialIdentityPublishing.publishAll(
            [Fixtures.amazonRetail, Fixtures.awsRoot], to: publisher)
        #expect(await publisher.published == published)
        #expect(published == CredentialIdentityPlanner.identities(for: [Fixtures.amazonRetail, Fixtures.awsRoot]))
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
        var edited = Fixtures.awsRoot
        edited.excludedFromSuggestions = true
        let excluded = edited
        let expected = CredentialIdentityPlanner.identities(for: [Fixtures.amazonRetail])

        let incremental = FakeCredentialIdentityPublisher()
        try await CredentialIdentityPublishing.publishAll([Fixtures.amazonRetail, Fixtures.awsRoot], to: incremental)
        try await CredentialIdentityPublishing.publishChange(
            from: Fixtures.awsRoot, to: excluded, all: { [Fixtures.amazonRetail, excluded] }, to: incremental)
        #expect(await incremental.published == expected)
        #expect(await incremental.incrementalCalls == 1)
        #expect(await incremental.replaceAllCalls == 1)

        let whole = FakeCredentialIdentityPublisher(supportsIncrementalUpdates: false)
        try await CredentialIdentityPublishing.publishAll([Fixtures.amazonRetail, Fixtures.awsRoot], to: whole)
        try await CredentialIdentityPublishing.publishChange(
            from: Fixtures.awsRoot, to: excluded, all: { [Fixtures.amazonRetail, excluded] }, to: whole)
        #expect(await whole.published == expected)
        #expect(await whole.incrementalCalls == 0)
        #expect(await whole.replaceAllCalls == 2)
    }
}
