import Foundation
import Testing
import WatchwordAutoFill
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

@Suite("Request model: credential-update reports")
struct CredentialReportTests {
    typealias Fixtures = AutoFillFixtures

    static let handle = Data("user-handle".utf8)

    static func credential(_ item: Item?, field: Int = 302) throws -> PasskeyCredential {
        try #require(try item?.fields.first { $0.id == Fixtures.id(field) }?.passkeyCredential())
    }

    // MARK: Unused password

    @Test("an unused-password report flags the login's password and changes nothing else")
    func unusedPassword() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let result = try await harness.model.handle(
            .unusedPassword(domain: "amazon.com", userName: Fixtures.email)
        ).value
        #expect(
            result.changes == [
                ReportChange(itemID: Fixtures.amazonRetail.id, fieldID: Fixtures.id(102), kind: .flaggedUnusedPassword)
            ])
        let item = try #require(await harness.vault.item(Fixtures.amazonRetail.id))
        #expect(item.field(.password)?.reportedUnusedAt == Fixtures.now)
        #expect(item.field(.password)?.value == "retail-password")
        #expect(item.fields.count == Fixtures.amazonRetail.fields.count)
        #expect(item.scopes == Fixtures.amazonRetail.scopes)
        #expect(!item.isTrashed && !item.archived)
        // The AWS account, same email, is another site's and is untouched.
        #expect(await harness.vault.item(Fixtures.awsRoot.id) == Fixtures.awsRoot)

        // Reported again: nothing to do, and no new version.
        let again = try await harness.model.handle(.unusedPassword(domain: "amazon.com", userName: Fixtures.email))
            .value
        #expect(again == ReportResult(changes: [], rateLimited: 0, conflicts: 0))
        #expect(await harness.vault.saves.count == 1)
    }

    @Test("a report reaches only what its sender could be given: other users, other sites and look-alikes get nothing")
    func unusedPasswordIsGated() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        for (domain, user) in [
            ("amazon.com", "someone@else.example"), ("signin.aws.amazon.com.evil.example", Fixtures.email),
            ("arnazon.com", Fixtures.email), ("example.net", Fixtures.email), ("google.com", Fixtures.email),
        ] {
            let result = try await harness.model.handle(.unusedPassword(domain: domain, userName: user)).value
            #expect(result.changes.isEmpty, "\(domain) \(user)")
        }
        #expect(await harness.vault.saves.isEmpty)
        #expect(
            await harness.model.handle(.unusedPassword(domain: "https://amazon.com/", userName: Fixtures.email))
                .refusal?.isGateRefusal == true)
        #expect(
            await harness.model.handle(.unusedPassword(domain: "amazon.com", userName: ""))
                == .refused(.invalidRequest("userName")))
    }

    // MARK: Passkeys

    @Test("a rename updates the passkey's account name and keeps the old one in history")
    func passkeyRenamed() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let before = try Self.credential(Fixtures.google)
        let result = try await harness.model.handle(
            .passkeyRenamed(relyingPartyID: "google.com", userHandle: Self.handle, newName: "pat.new@example.com")
        ).value
        #expect(result.changes.map(\.kind) == [.renamedPasskey])
        let item = try #require(await harness.vault.item(Fixtures.google.id))
        let after = try Self.credential(item)
        #expect(after.userName == "pat.new@example.com")
        // Only the name moved: same key, same ID, same relying party, same secret.
        var expected = before
        expected.userName = "pat.new@example.com"
        #expect(after == expected)
        #expect(
            try Self.credential(Item(vaultID: item.vaultID, title: "", scopes: [], fields: item.history[0].fields))
                .userName
                == Fixtures.email)
        // The published identity follows.
        #expect(
            await harness.publisher.published.contains {
                if case .passkey(let identity) = $0 { return identity.userName == "pat.new@example.com" }
                return false
            })

        // The same name again is nothing to do.
        let again = try await harness.model.handle(
            .passkeyRenamed(relyingPartyID: "google.com", userHandle: Self.handle, newName: "pat.new@example.com")
        ).value
        #expect(again.changes.isEmpty && again.rateLimited == 0)
    }

    @Test("an unknown-credential report flags the passkey and withdraws its identity, and the passkey stays")
    func unknownPasskey() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        _ = try await harness.model.publishAllIdentities().value
        let credential = try Self.credential(Fixtures.google)
        let result = try await harness.model.handle(
            .unknownPasskey(relyingPartyID: "google.com", credentialID: credential.credentialID)
        ).value
        #expect(result.changes.map(\.kind) == [.flaggedUnknownPasskey])
        let item = try #require(await harness.vault.item(Fixtures.google.id))
        #expect(item.fields.first { $0.id == Fixtures.id(302) }?.reportedUnknownAt == Fixtures.now)
        #expect(try Self.credential(item) == credential)
        #expect(
            await harness.publisher.published.allSatisfy {
                if case .passkey = $0 { return false }
                return true
            })
        // Still in the extension's list, marked, and still usable if the person insists.
        guard
            case .list(let list) = await harness.model.credentialList(
                for: [],
                passkey: PasskeyAssertionRequest(
                    relyingPartyID: "google.com", clientDataHash: Fixtures.clientDataHash()))
        else {
            Issue.record("no list")
            return
        }
        #expect(list.passkeys.map(\.reportedUnknown) == [true])
    }

    @Test("an accepted-credentials report flags what is missing from it and clears what is back in it")
    func acceptedPasskeys() async throws {
        var item = Fixtures.google
        item.fields.append(Fixtures.passkey(relyingParty: "google.com", seed: 61, id: Fixtures.id(361)))
        item.fields.append(
            Fixtures.passkey(relyingParty: "google.com", userHandle: "other-user", seed: 62, id: Fixtures.id(362)))
        let harness = AutoFillHarness(items: [item])
        let first = try Self.credential(item, field: 302)
        let second = try Self.credential(item, field: 361)

        let flagged = try await harness.model.handle(
            .acceptedPasskeys(
                relyingPartyID: "google.com", userHandle: Self.handle, acceptedCredentialIDs: [first.credentialID])
        ).value
        #expect(
            flagged.changes == [
                ReportChange(itemID: item.id, fieldID: Fixtures.id(361), kind: .flaggedUnknownPasskey)
            ])
        var stored = try #require(await harness.vault.item(item.id))
        #expect(stored.fields.first { $0.id == Fixtures.id(302) }?.reportedUnknownAt == nil)
        #expect(stored.fields.first { $0.id == Fixtures.id(361) }?.reportedUnknownAt != nil)
        // Another user's passkey at the same party is not this report's business.
        #expect(stored.fields.first { $0.id == Fixtures.id(362) }?.reportedUnknownAt == nil)

        // A day later the credential is accepted again.
        await harness.clock.advance(by: CredentialProviderModel.reportInterval)
        let cleared = try await harness.model.handle(
            .acceptedPasskeys(
                relyingPartyID: "google.com", userHandle: Self.handle,
                acceptedCredentialIDs: [first.credentialID, second.credentialID])
        ).value
        #expect(cleared.changes.map(\.kind) == [.clearedUnknownPasskey])
        stored = try #require(await harness.vault.item(item.id))
        #expect(stored.fields.first { $0.id == Fixtures.id(361) }?.reportedUnknownAt == nil)
        #expect(stored.fields.count == item.fields.count)
    }

    @Test("passkey reports are honoured only from the credential's own relying party")
    func passkeyReportsAreGated() async throws {
        var planted = Fixtures.amazonRetail
        planted.fields.append(Fixtures.google.fields[1])
        let harness = AutoFillHarness(items: [Fixtures.google, planted])
        let credential = try Self.credential(Fixtures.google)
        for report in [
            CredentialUpdateReport.unknownPasskey(relyingPartyID: "amazon.com", credentialID: credential.credentialID),
            .unknownPasskey(relyingPartyID: "evil.example", credentialID: credential.credentialID),
            .passkeyRenamed(relyingPartyID: "amazon.com", userHandle: Self.handle, newName: "attacker"),
            .acceptedPasskeys(relyingPartyID: "evil.example", userHandle: Self.handle, acceptedCredentialIDs: []),
            .acceptedPasskeys(relyingPartyID: "amazon.com", userHandle: Self.handle, acceptedCredentialIDs: []),
            .unknownPasskey(relyingPartyID: "google.com", credentialID: Data(repeating: 1, count: 32)),
            .passkeyRenamed(relyingPartyID: "google.com", userHandle: Data("someone-else".utf8), newName: "x"),
        ] {
            #expect(try await harness.model.handle(report).value.changes.isEmpty, "\(report)")
        }
        #expect(await harness.vault.saves.isEmpty)
    }

    @Test("malformed reports are refused")
    func malformedReports() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        func refusal(_ report: CredentialUpdateReport) async -> ProviderRefusal? {
            await harness.model.handle(report).refusal
        }
        #expect(
            await refusal(.passkeyRenamed(relyingPartyID: "google.com", userHandle: Self.handle, newName: ""))
                == .invalidRequest("newName"))
        #expect(
            await refusal(.passkeyRenamed(relyingPartyID: "google.com", userHandle: Self.handle, newName: "a\u{202E}b"))
                == .invalidRequest("newName"))
        #expect(
            await refusal(
                .passkeyRenamed(
                    relyingPartyID: "google.com", userHandle: Self.handle, newName: String(repeating: "n", count: 2000))
            )
                == .invalidRequest("newName"))
        #expect(
            await refusal(.passkeyRenamed(relyingPartyID: "google.com", userHandle: Data(), newName: "n"))
                == .invalidRequest("userHandle"))
        #expect(
            await refusal(
                .acceptedPasskeys(
                    relyingPartyID: "google.com", userHandle: Self.handle,
                    acceptedCredentialIDs: Array(repeating: Data(count: 32), count: 300)))
                == .passkey(.listTooLong))
        #expect(
            await refusal(.unknownPasskey(relyingPartyID: "google.com", credentialID: Data(count: 2000)))
                == .passkey(.listTooLong))
        guard
            case .passkey(.relyingPartyRejected) = await refusal(
                .unknownPasskey(relyingPartyID: "com", credentialID: Data(count: 32)))
        else {
            Issue.record("public-suffix relying party accepted")
            return
        }
        #expect(await harness.vault.saves.isEmpty)
    }

    // MARK: Limits

    @Test("a report changes one field at most once a day, so a site cannot grow an item without bound")
    func rateLimit() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        func rename(_ name: String) async throws -> ReportResult {
            try await harness.model.handle(
                .passkeyRenamed(relyingPartyID: "google.com", userHandle: Self.handle, newName: name)
            ).value
        }
        #expect(try await rename("name-0").changes.count == 1)
        for index in 1...50 {
            let result = try await rename("name-\(index)")
            #expect(result.changes.isEmpty)
            #expect(result.rateLimited == 1)
        }
        let credential = try Self.credential(Fixtures.google)
        #expect(
            try await harness.model.handle(
                .unknownPasskey(relyingPartyID: "google.com", credentialID: credential.credentialID)
            ).value.rateLimited == 1)
        #expect(await harness.vault.saves.count == 1)
        #expect(try Self.credential(await harness.vault.item(Fixtures.google.id)).userName == "name-0")

        await harness.clock.advance(by: CredentialProviderModel.reportInterval - 1)
        #expect(try await rename("still-early").rateLimited == 1)
        await harness.clock.advance(by: 1)
        #expect(try await rename("next-day").changes.count == 1)
        #expect(await harness.vault.item(Fixtures.google.id)?.history.count == 2)
    }

    @Test("reports wait for an unlocked vault, skip archived and trashed items, and survive a lost race")
    func availability() async throws {
        var archived = Fixtures.amazonRetail
        archived.archived = true
        var trashed = Fixtures.library
        trashed.trashedAt = Fixtures.now
        let harness = AutoFillHarness(items: [archived, trashed, Fixtures.google])
        #expect(
            try await harness.model.handle(.unusedPassword(domain: "amazon.com", userName: Fixtures.email)).value
                .changes.isEmpty)
        #expect(
            try await harness.model.handle(.unusedPassword(domain: "library.example.org", userName: "pat")).value
                .changes.isEmpty)

        await harness.vault.failNextSave(with: .versionConflict(Fixtures.google.id))
        let credential = try Self.credential(Fixtures.google)
        let lost = try await harness.model.handle(
            .unknownPasskey(relyingPartyID: "google.com", credentialID: credential.credentialID)
        ).value
        #expect(lost == ReportResult(changes: [], rateLimited: 0, conflicts: 1))

        await harness.vault.lock()
        #expect(
            await harness.model.handle(
                .unknownPasskey(relyingPartyID: "google.com", credentialID: credential.credentialID)) == .vaultLocked)
        #expect(await harness.vault.saves.isEmpty)
    }
}
