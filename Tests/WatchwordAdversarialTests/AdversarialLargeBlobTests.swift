import Foundation
import Testing
import WatchwordAutoFill
import WatchwordKit
import WatchwordModel
import WatchwordTestSupport

// Review finding Z66 (docs/06-adversarial-review.md): the largeBlob extension, written by a relying party.
extension AdversarialAutoFillRequestTests {
    /// Threat: A6 as the relying party of a passkey the person holds (or script injected into its pages). Each
    /// sign-in may carry `largeBlob: write(...)` with up to 16 KiB of fresh bytes; each write replaced the passkey
    /// field, and the vault keeps every earlier field set in the item's history, which is never pruned (F1.4). About
    /// forty-five sign-ins filled the item's 1 MiB payload, after which every edit of it failed: a password change,
    /// a report flag, an edit in the app. Now a write is refused (and reported as not written, the assertion still
    /// good) once it would leave the item past half its payload limit, and a field takes at most one write per day.
    @Test("a relying party's largeBlob writes cannot fill an item until it no longer saves")
    func largeBlobCannotFreezeAnItem() async throws {
        let clock = FakeClock(AutoFillFixtures.now)
        let vault = TestVault(clock: clock)
        try await vault.createAccount()
        let personal = try #require(await vault.session.personalVaultID)
        let google = AutoFillFixtures.google
        try await vault.session.save(
            Item(id: google.id, vaultID: personal, title: google.title, scopes: google.scopes, fields: google.fields))
        let model = CredentialProviderModel(
            vault: vault.session, clock: clock, random: SeededGenerator(seed: TestEnvironment.seed(fallback: 66)))
        let choice = FieldChoice(itemID: google.id, fieldID: AutoFillFixtures.id(302))
        var generator = SeededGenerator(seed: 66)
        func write() async throws -> Bool {
            let blob = Data(
                (0..<PasskeyCredential.maximumLargeBlobLength).map { _ in UInt8.random(in: 0...255, using: &generator) }
            )
            let request = PasskeyAssertionRequest(
                relyingPartyID: "google.com", clientDataHash: AutoFillFixtures.clientDataHash(),
                allowedCredentialIDs: [], userVerification: .preferred,
                extensions: PasskeyAssertionExtensions(largeBlob: .write(blob)))
            let result = try await model.passkeyAssertion(for: choice, request: request, presence: .verified).value
            return result.largeBlob == .write(didWrite: true)
        }

        // A second write within the day is refused; the assertion is still made.
        #expect(try await write())
        #expect(try await !write(), "a second write the same day")

        var written = 1
        for _ in 0..<100 {
            await clock.advance(by: CredentialProviderModel.largeBlobInterval)
            guard try await write() else { break }
            written += 1
        }
        #expect(written < 100, "writes never stopped")
        // The item still takes the person's edits: well inside its payload limit.
        var edited = try await vault.session.item(id: google.id)
        edited.title = "Google!"
        edited.fields.append(Field(kind: .text, label: "Recovery", value: String(repeating: "r", count: 100_000)))
        let saved = try await vault.session.save(edited)
        #expect(saved.title == "Google!")
    }
}

// Review finding Z71: the review of the Z66 fix. Every write the model makes for a remote party has the budget.
extension AdversarialAutoFillRequestTests {
    /// Threat: A6 as the relying party again, finishing what Z66's bound stopped. It writes largeBlobs until the
    /// item reaches the largeBlob budget, then sends one `passkeyRenamed` report a day with alternating names (or
    /// toggles the unknown flag with `acceptedPasskeys`): each report changes only the passkey's name or meta, and
    /// each keeps a history entry holding every field, the 16 KiB blob included. Nothing checked the budget there,
    /// and about three weeks later the item passed its 1 MiB payload, after which every edit of it failed, a password
    /// change included. Now a report that would take the item past the budget is not applied (and counted), and the
    /// item still takes the person's edits after two months of reports.
    @Test("a relying party's reports cannot fill an item until it no longer saves")
    func reportsCannotFreezeAnItem() async throws {
        let clock = FakeClock(AutoFillFixtures.now)
        let vault = TestVault(clock: clock)
        try await vault.createAccount()
        let personal = try #require(await vault.session.personalVaultID)
        let google = AutoFillFixtures.google
        try await vault.session.save(
            Item(id: google.id, vaultID: personal, title: google.title, scopes: google.scopes, fields: google.fields))
        let model = CredentialProviderModel(
            vault: vault.session, clock: clock, random: SeededGenerator(seed: TestEnvironment.seed(fallback: 71)))
        let choice = FieldChoice(itemID: google.id, fieldID: AutoFillFixtures.id(302))
        let handle = try google.fields[1].passkeyCredential().userHandle
        var generator = SeededGenerator(seed: 71)
        // The largeBlob writes Z66 allows, up to its budget.
        for _ in 0..<100 {
            let blob = Data(
                (0..<PasskeyCredential.maximumLargeBlobLength).map { _ in UInt8.random(in: 0...255, using: &generator) }
            )
            let request = PasskeyAssertionRequest(
                relyingPartyID: "google.com", clientDataHash: AutoFillFixtures.clientDataHash(),
                allowedCredentialIDs: [], userVerification: .preferred,
                extensions: PasskeyAssertionExtensions(largeBlob: .write(blob)))
            let result = try await model.passkeyAssertion(for: choice, request: request, presence: .verified).value
            await clock.advance(by: CredentialProviderModel.largeBlobInterval)
            guard result.largeBlob == .write(didWrite: true) else { break }
        }

        var applied = 0
        var refused = 0
        for day in 0..<60 {
            await clock.advance(by: CredentialProviderModel.reportInterval)
            let report: CredentialUpdateReport =
                day.isMultiple(of: 3)
                ? .acceptedPasskeys(
                    relyingPartyID: "google.com", userHandle: handle,
                    acceptedCredentialIDs: day.isMultiple(of: 2)
                        ? [] : [try google.fields[1].passkeyCredential().credentialID])
                : .passkeyRenamed(
                    relyingPartyID: "google.com", userHandle: handle, newName: day.isMultiple(of: 2) ? "pat" : "Pat")
            if case .success(let result) = await model.handle(report) {
                applied += result.changes.count
                refused += result.overBudget
            }
        }
        #expect(refused > 0, "reports went on growing the item (\(applied) applied)")
        // The item still takes the person's edits: well inside its payload limit.
        var edited = try await vault.session.item(id: google.id)
        edited.title = "Google!"
        edited.fields.append(Field(kind: .text, label: "Recovery", value: String(repeating: "r", count: 100_000)))
        let saved = try await vault.session.save(edited)
        #expect(saved.title == "Google!")
    }
}
