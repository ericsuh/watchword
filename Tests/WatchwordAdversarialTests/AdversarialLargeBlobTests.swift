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
