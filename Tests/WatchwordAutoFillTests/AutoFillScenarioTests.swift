import Crypto
import Foundation
import Testing
import WatchwordAutoFill
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

/// PRD scenarios S1 and S2 driven through the request model, as the extension will drive it
/// (docs/04-test-plan.md §4, E2E-S1 and E2E-S2; docs/03-implementation-plan.md, milestone 5 exit criteria).
@Suite("Scenarios S1 and S2 through the request model")
struct AutoFillScenarioTests {
    typealias Fixtures = AutoFillFixtures

    static let console = Fixtures.url("https://signin.aws.amazon.com/signin")
    static let shop = Fixtures.url("https://www.amazon.com/ap/signin")

    @Test("S1: the AWS console is offered only the AWS account, amazon.com only the retail one, each with its own code")
    func s1() async throws {
        let harness = AutoFillHarness(items: [Fixtures.amazonRetail, Fixtures.awsRoot])

        // The console: AWS is the list, and only AWS can be released. Retail is shadowed there: neither listed nor
        // released, by choice included (PRD F6.6; owner decision 2026-11-16).
        guard case .list(let consoleList) = await harness.model.credentialList(for: [Self.console]) else {
            Issue.record("no list for the console")
            return
        }
        #expect(consoleList.passwords.map(\.itemID) == [Fixtures.awsRoot.id])
        #expect(!consoleList.passwords.contains { $0.itemID == Fixtures.amazonRetail.id })
        #expect(
            await harness.model.password(
                for: PasswordChoice(itemID: Fixtures.amazonRetail.id, userName: Fixtures.email),
                identifiers: [Self.console]
            ).refusal?.isGateRefusal == true)
        #expect(
            await harness.model.oneTimeCode(
                for: FieldChoice(itemID: Fixtures.amazonRetail.id, fieldID: Fixtures.id(103)),
                identifiers: [Self.console]
            ).refusal?.isGateRefusal == true)
        #expect(consoleList.suggested?.itemID == Fixtures.awsRoot.id)
        let awsPassword = try await harness.model.password(
            for: PasswordChoice(itemID: Fixtures.awsRoot.id, userName: Fixtures.email), identifiers: [Self.console]
        ).value
        #expect(awsPassword == PasswordCredential(user: Fixtures.email, password: "aws-password"))
        let awsCode = try await harness.model.oneTimeCode(
            for: FieldChoice(itemID: Fixtures.awsRoot.id, fieldID: Fixtures.id(203)), identifiers: [Self.console]
        ).value
        #expect(
            awsCode.code
                == (try TOTP.code(
                    for: try OTPParameters(secret: Data(Fixtures.awsSecret.utf8)), at: Fixtures.now
                ).code))

        // amazon.com: only retail matches at all.
        guard case .list(let shopList) = await harness.model.credentialList(for: [Self.shop]) else {
            Issue.record("no list for the shop")
            return
        }
        #expect(shopList.passwords.map(\.itemID) == [Fixtures.amazonRetail.id])
        let retailCode = try await harness.model.oneTimeCode(
            for: FieldChoice(itemID: Fixtures.amazonRetail.id, fieldID: Fixtures.id(103)), identifiers: [Self.shop]
        ).value
        #expect(
            retailCode.code
                == (try TOTP.code(
                    for: try OTPParameters(secret: Data(Fixtures.retailSecret.utf8)), at: Fixtures.now
                ).code))
        #expect(retailCode.code != awsCode.code)

        // Neither is ever handed to the other's site: by choice, as a code, or as text.
        let retailChoice = PasswordChoice(itemID: Fixtures.amazonRetail.id, userName: Fixtures.email)
        let awsChoice = PasswordChoice(itemID: Fixtures.awsRoot.id, userName: Fixtures.email)
        #expect(
            await harness.model.password(for: retailChoice, identifiers: [Self.console]).refusal?.isGateRefusal == true)
        #expect(await harness.model.password(for: awsChoice, identifiers: [Self.shop]).refusal?.isGateRefusal == true)
        #expect(
            await harness.model.oneTimeCode(
                for: FieldChoice(itemID: Fixtures.amazonRetail.id, fieldID: Fixtures.id(103)),
                identifiers: [Self.console]
            )
            .refusal?.isGateRefusal == true)
        #expect(
            await harness.model.textToInsert(
                for: TextChoice(itemID: Fixtures.awsRoot.id, fieldID: Fixtures.id(202)), identifiers: [Self.shop]
            )
            .refusal?.isGateRefusal == true)

        // QuickType. A tap hands back the stored identity and not the page, and the system decides where an
        // `amazon.com` identity is offered: quite possibly on the console too. So with both accounts in the vault
        // neither has a password or code identity, and what an out-of-date store still holds is not answered. The
        // keyboard's own list (above), which is told the page, is where these two accounts are chosen.
        #expect(try await harness.publishedIdentities().isEmpty)
        let before = AutoFillHarness(items: [Fixtures.amazonRetail])
        for identity in try await before.publishedPasswords() {
            #expect(identity.host == "amazon.com")
            #expect(
                try await before.model.passwordWithoutInteraction(for: identity.handedBack).value
                    == .init(
                        user: Fixtures.email, password: "retail-password"))
            #expect(
                await harness.model.passwordWithoutInteraction(for: identity.handedBack)
                    == .requiresInteraction(.ambiguousMatch))
        }
        for identity in try await before.publishedCodes() {
            #expect(
                await harness.model.oneTimeCodeWithoutInteraction(for: identity.handedBack)
                    == .requiresInteraction(.ambiguousMatch))
        }
        #expect(try await before.publishedPasswords().count == 1)
        #expect(try await before.publishedCodes().count == 1)

        // And saving the AWS item takes the retail identities out of the store.
        let growing = AutoFillHarness(items: [Fixtures.amazonRetail])
        #expect(try await growing.publishedIdentities().count == 2)
        _ = try await growing.model.savePassword(
            SavePasswordRequest(serviceIdentifier: Self.console, userName: Fixtures.email, password: "aws-password"),
            to: .newItem
        ).value
        #expect(await growing.publisher.published.isEmpty)
    }

    @Test("S2: a passkey registered for Google signs in, its prf output is stable, and a used backup code is marked")
    func s2() async throws {
        // The person has a Google item with an email and backup codes, and no passkey yet.
        var google = Fixtures.google
        google.fields.removeAll { $0.kind == .passkey }
        let harness = AutoFillHarness(items: [google, Fixtures.amazonRetail])

        // Registration through the request handler: the sheet suggests the Google item, and the passkey joins it.
        let registration = PasskeyRegistrationRequest(
            relyingPartyID: "google.com", user: PasskeyUser(handle: Data("g-user-1".utf8), name: Fixtures.email),
            clientDataHash: Fixtures.clientDataHash(7), userVerification: .required,
            extensions: PasskeyRegistrationExtensions(prf: .checkForSupport))
        let options = try await harness.model.passkeyRegistrationOptions(for: registration).value
        #expect(options.suggested == .existingItem(google.id))
        let registered = try await harness.model.registerPasskey(
            registration, destination: options.suggested, presence: .verified
        ).value
        #expect(registered.itemID == google.id)
        #expect(registered.prf?.isSupported == true)
        let stored = try #require(await harness.vault.item(google.id))
        #expect(stored.fields.map(\.kind) == [.email, .recoveryCodes, .passkey])
        let credential = try #require(try stored.fields.last?.passkeyCredential())
        let publicKey = try P256.Signing.PrivateKey(derRepresentation: credential.privateKeyPKCS8).publicKey

        // AutoFill offers the passkey on Google's sign-in page.
        let prfInput = PRFInputValues(first: Data("vault key".utf8))
        let request = PasskeyAssertionRequest(
            relyingPartyID: "google.com", clientDataHash: Fixtures.clientDataHash(8), userVerification: .required,
            extensions: PasskeyAssertionExtensions(prf: PRFAssertionInput(inputValues: prfInput)))
        guard
            case .list(let list) = await harness.model.credentialList(
                for: [Fixtures.url("https://accounts.google.com/v3/signin")], passkey: request)
        else {
            Issue.record("no list on Google's sign-in page")
            return
        }
        #expect(list.passkeys.map(\.credentialID) == [registered.credentialID])
        let entry = try #require(list.passkeys.first)

        // On assertion the signature verifies with the stored public key, twice, and the prf output is stable.
        var outputs: [PRFOutputValues?] = []
        for _ in 0..<2 {
            let result = try await harness.model.passkeyAssertion(
                for: FieldChoice(itemID: entry.itemID, fieldID: entry.fieldID), request: request, presence: .verified
            ).value
            #expect(
                publicKey.isValidSignature(
                    try P256.Signing.ECDSASignature(derRepresentation: result.assertion.signature),
                    for: result.assertion.authenticatorData + result.assertion.clientDataHash))
            #expect(result.assertion.userHandle == Data("g-user-1".utf8))
            outputs.append(result.prf)
        }
        #expect(outputs[0] != nil)
        #expect(outputs[0] == outputs[1])

        // The backup codes are in the same item, insert as text on request, and a used one is marked as spent:
        // a new item version, with the old one in history.
        let codes = try #require(stored.fields.first { $0.kind == .recoveryCodes })
        let google2 = [Fixtures.domain("google.com")]
        #expect(
            await harness.model.textToInsert(
                for: TextChoice(itemID: google.id, fieldID: codes.id, part: .recoveryCode(index: 0)),
                identifiers: google2)
                == .success("1111-2222"))
        let before = try #require(await harness.vault.item(google.id))
        #expect(
            await harness.model.markRecoveryCode(FieldChoice(itemID: google.id, fieldID: codes.id), index: 0)
                == .success(true))
        let after = try #require(await harness.vault.item(google.id))
        #expect(after.version == before.version + 1)
        #expect(after.fields.first { $0.id == codes.id }?.usedRecoveryCodeIndices == [0])
        #expect(after.history.first?.version == before.version)
        #expect(after.history.first?.fields.first { $0.id == codes.id }?.usedRecoveryCodeIndices == [])
        // The passkey is untouched by that edit and still signs.
        #expect(try after.fields.last?.passkeyCredential() == credential)

        // Neither the passkey nor the codes leave for another party.
        #expect(
            await harness.model.passkeyAssertion(
                for: FieldChoice(itemID: entry.itemID, fieldID: entry.fieldID),
                request: PasskeyAssertionRequest(
                    relyingPartyID: "amazon.com", clientDataHash: Fixtures.clientDataHash(8)),
                presence: .verified
            ).refusal?.isGateRefusal == true)
        #expect(
            await harness.model.textToInsert(
                for: TextChoice(itemID: google.id, fieldID: codes.id, part: .recoveryCode(index: 1)),
                identifiers: [Fixtures.domain("g00gle.com")]
            ).refusal?.isGateRefusal == true)
    }
}
