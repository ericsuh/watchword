import Crypto
import Foundation
import Testing
import WatchwordAutoFill
import WatchwordKit
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

/// Scenarios S1 and S2 once more, with the request model over a real `VaultSession` as its `CredentialVault`: AES-GCM
/// records, the vault's own versions and history, its compare-and-swap and its lock (docs/04-test-plan.md §4,
/// "written once against `VaultSession`").
@Suite("Request model over a real vault session")
struct VaultSessionBridgeTests {
    typealias Fixtures = AutoFillFixtures

    static func unlockedVault() async throws -> (TestVault, CredentialProviderModel, UUID) {
        let vault = TestVault(clock: FakeClock(Fixtures.now))
        try await vault.createAccount()
        let vaultID = try #require(await vault.session.personalVaultID)
        let model = CredentialProviderModel(
            vault: vault.session, clock: vault.clock,
            random: SeededGenerator(seed: TestEnvironment.seed(fallback: 21)))
        return (vault, model, vaultID)
    }

    /// The fixture as a new item of `vaultID`: the vault assigns the version and timestamps.
    static func fresh(_ item: Item, in vaultID: UUID) -> Item {
        Item(id: item.id, vaultID: vaultID, title: item.title, scopes: item.scopes, fields: item.fields)
    }

    @Test("S1 over a real session: each Amazon account fills on its own site, and a locked session releases nothing")
    func s1() async throws {
        let (vault, model, vaultID) = try await Self.unlockedVault()
        try await vault.session.save(Self.fresh(Fixtures.amazonRetail, in: vaultID))
        try await vault.session.save(Self.fresh(Fixtures.awsRoot, in: vaultID))
        let console = Fixtures.url("https://signin.aws.amazon.com/signin")
        let shop = Fixtures.url("https://www.amazon.com/ap/signin")

        guard case .list(let list) = await model.credentialList(for: [console]) else {
            Issue.record("no list")
            return
        }
        #expect(list.passwords.map(\.itemID) == [Fixtures.awsRoot.id])
        #expect(list.otherAccounts.map(\.itemID) == [Fixtures.amazonRetail.id])
        #expect(
            try await model.password(
                for: PasswordChoice(itemID: Fixtures.awsRoot.id, userName: Fixtures.email), identifiers: [console]
            ).value.password == "aws-password")
        #expect(
            try await model.password(
                for: PasswordChoice(itemID: Fixtures.amazonRetail.id, userName: Fixtures.email), identifiers: [shop]
            ).value.password == "retail-password")
        #expect(
            await model.password(
                for: PasswordChoice(itemID: Fixtures.amazonRetail.id, userName: Fixtures.email), identifiers: [console]
            ).refusal?.isGateRefusal == true)
        // QuickType: with both accounts in the vault the retail identity is not answered (the system does not say
        // which Amazon page the tap came from); the bank's, alone on its site, is.
        let retailIdentity = PasswordIdentity(
            host: "amazon.com", user: Fixtures.email,
            recordIdentifier: RecordIdentifier(itemID: Fixtures.amazonRetail.id),
            rank: 5)
        #expect(
            await model.passwordWithoutInteraction(for: retailIdentity.handedBack)
                == .requiresInteraction(.ambiguousMatch))
        try await vault.session.save(Self.fresh(Fixtures.bank, in: vaultID))
        let bankIdentity = PasswordIdentity(
            host: "firstbank.co.uk", user: "40012345", recordIdentifier: RecordIdentifier(itemID: Fixtures.bank.id),
            rank: 7)
        #expect(
            try await model.passwordWithoutInteraction(for: bankIdentity.handedBack).value.password == "bank-password")
        let code = try await model.oneTimeCode(
            for: FieldChoice(itemID: Fixtures.awsRoot.id, fieldID: Fixtures.id(203)), identifiers: [console]
        ).value
        #expect(
            code.code
                == (try TOTP.code(for: try OTPParameters(secret: Data(Fixtures.awsSecret.utf8)), at: Fixtures.now).code)
        )

        // The vault refuses an over-broad scope whatever the model sends, and the model reports it as such.
        #expect(
            await model.savePassword(
                SavePasswordRequest(
                    serviceIdentifier: Fixtures.url("https://localhost/"), userName: "x", password: "y"),
                to: .newItem
            ).refusal == .scopeRejected(.publicSuffix("localhost")))

        await vault.session.lock()
        #expect(await model.credentialList(for: [console]) == .vaultLocked)
        #expect(
            await model.password(
                for: PasswordChoice(itemID: Fixtures.awsRoot.id, userName: Fixtures.email), identifiers: [console])
                == .vaultLocked)
        #expect(
            await model.passwordWithoutInteraction(for: bankIdentity.handedBack) == .requiresInteraction(.vaultLocked))
    }

    @Test(
        "S2 over a real session: a registered passkey is sealed in the item, signs after a relaunch, and codes are marked"
    )
    func s2() async throws {
        let (vault, model, vaultID) = try await Self.unlockedVault()
        var google = Self.fresh(Fixtures.google, in: vaultID)
        google.fields.removeAll { $0.kind == .passkey }
        let saved = try await vault.session.save(google)

        let registration = PasskeyRegistrationRequest(
            relyingPartyID: "google.com", user: PasskeyUser(handle: Data("g-user-1".utf8), name: Fixtures.email),
            clientDataHash: Fixtures.clientDataHash(7))
        let registered = try await model.registerPasskey(
            registration, destination: .existingItem(google.id), presence: .verified
        ).value
        // Not synced: backup-eligible, not backed up.
        #expect(registered.attestationObject[30 + 32] == 0x4D)
        let stored = try await vault.session.item(id: google.id)
        #expect(stored.version == saved.version + 1)
        #expect(stored.history.first?.fields == saved.fields)
        let credential = try #require(try stored.fields.last?.passkeyCredential())
        #expect(credential.credentialID == registered.credentialID)

        // A new session over the same store (the extension's process) unlocks and signs with the stored key.
        let relaunched = vault.relaunched()
        try await relaunched.session.unlock(password: TestVault.password)
        let extensionModel = CredentialProviderModel(
            vault: relaunched.session, clock: vault.clock)
        let prfInput = PRFInputValues(first: Data("vault key".utf8))
        let request = PasskeyAssertionRequest(
            relyingPartyID: "google.com", clientDataHash: Fixtures.clientDataHash(8),
            extensions: PasskeyAssertionExtensions(prf: PRFAssertionInput(inputValues: prfInput)))
        let result = try await extensionModel.passkeyAssertion(
            for: FieldChoice(itemID: google.id, fieldID: registered.fieldID), request: request, presence: .verified
        ).value
        let publicKey = try P256.Signing.PrivateKey(derRepresentation: credential.privateKeyPKCS8).publicKey
        #expect(
            publicKey.isValidSignature(
                try P256.Signing.ECDSASignature(derRepresentation: result.assertion.signature),
                for: result.assertion.authenticatorData + result.assertion.clientDataHash))
        #expect(result.prf == (try PasskeyPRF.evaluate(secret: try #require(credential.prfSecret), inputs: prfInput)))

        // A used backup code is marked through the model: a new version, the old one in the vault's history.
        let codes = try #require(stored.fields.first { $0.kind == .recoveryCodes })
        #expect(
            await extensionModel.markRecoveryCode(FieldChoice(itemID: google.id, fieldID: codes.id), index: 2)
                == .success(true))
        let after = try await relaunched.session.item(id: google.id)
        #expect(after.version == stored.version + 1)
        #expect(after.fields.first { $0.id == codes.id }?.usedRecoveryCodeIndices == [2])
        #expect(after.history.count == 2)

        // A write prepared against a version that has since moved is refused, not merged over.
        await #expect(throws: CredentialVaultError.versionConflict(google.id)) {
            try await relaunched.session.saveCredentialItem(stored, replacingVersion: stored.version)
        }
        #expect(try await relaunched.session.item(id: google.id) == after)
    }
}
