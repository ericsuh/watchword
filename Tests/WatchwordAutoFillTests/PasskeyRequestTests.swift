import Crypto
import Foundation
import Testing
import WatchwordAutoFill
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

@Suite("Request model: passkeys")
struct PasskeyRequestTests {
    typealias Fixtures = AutoFillFixtures

    static let googleChoice = FieldChoice(itemID: Fixtures.google.id, fieldID: Fixtures.id(302))

    static func assertionRequest(
        _ relyingParty: String = "google.com", allowed: [Data] = [],
        verification: UserVerificationPreference = .preferred,
        extensions: PasskeyAssertionExtensions = PasskeyAssertionExtensions()
    ) -> PasskeyAssertionRequest {
        PasskeyAssertionRequest(
            relyingPartyID: relyingParty, clientDataHash: Fixtures.clientDataHash(), allowedCredentialIDs: allowed,
            userVerification: verification, extensions: extensions)
    }

    static func registrationRequest(
        _ relyingParty: String = "shop.example", userName: String = "pat@example.com", handle: String = "handle-1",
        algorithms: [Int] = [-7, -257], verification: UserVerificationPreference = .preferred,
        excluded: [Data] = [], extensions: PasskeyRegistrationExtensions = PasskeyRegistrationExtensions()
    ) -> PasskeyRegistrationRequest {
        PasskeyRegistrationRequest(
            relyingPartyID: relyingParty, user: PasskeyUser(handle: Data(handle.utf8), name: userName),
            clientDataHash: Fixtures.clientDataHash(2), supportedAlgorithms: algorithms, userVerification: verification,
            excludedCredentialIDs: excluded, extensions: extensions)
    }

    static func storedCredential(_ item: Item, field: UUID? = nil) throws -> PasskeyCredential {
        let found = item.fields.first { $0.kind == .passkey && (field == nil || $0.id == field) }
        return try #require(try found?.passkeyCredential())
    }

    /// Verifies an assertion the way a relying party would: the public key of the stored credential, over
    /// `authenticatorData ‖ clientDataHash`.
    static func verify(_ assertion: PasskeyAssertion, with credential: PasskeyCredential) throws -> Bool {
        let key = try P256.Signing.PrivateKey(derRepresentation: credential.privateKeyPKCS8).publicKey
        return key.isValidSignature(
            try P256.Signing.ECDSASignature(derRepresentation: assertion.signature),
            for: assertion.authenticatorData + assertion.clientDataHash)
    }

    // MARK: Assertion

    @Test("the credential list offers the relying party's passkeys alongside the page's passwords")
    func passkeyList() async throws {
        var withPassword = Fixtures.google
        withPassword.fields.append(Field(kind: .password, label: "Password", value: "google-password"))
        let harness = AutoFillHarness(items: [withPassword, Fixtures.amazonRetail])
        let credential = try Self.storedCredential(Fixtures.google)
        guard
            case .list(let list) = await harness.model.credentialList(
                for: [Fixtures.url("https://accounts.google.com/signin")], passkey: Self.assertionRequest())
        else {
            Issue.record("no list")
            return
        }
        #expect(list.passkeys.map(\.credentialID) == [credential.credentialID])
        #expect(list.passkeys.first?.userName == Fixtures.email)
        #expect(list.passkeys.first?.relyingPartyID == "google.com")
        #expect(list.passkeys.first?.fieldID == Fixtures.id(302))
        #expect(list.passwords.map(\.title) == ["Google"])
        #expect(list.passkeyRefusal == nil)

        // A passkey-only request, with no page identifier at all, still lists passkeys.
        guard case .list(let only) = await harness.model.credentialList(for: [], passkey: Self.assertionRequest())
        else {
            Issue.record("no passkey-only list")
            return
        }
        #expect(only.passkeys.count == 1)
        #expect(only.passwords.isEmpty)
    }

    @Test("an allow-list narrows the passkeys offered, and an empty one means any")
    func allowList() async throws {
        var item = Fixtures.google
        item.fields.append(
            Fixtures.passkey(relyingParty: "google.com", userName: "second@example.com", seed: 77, id: Fixtures.id(399))
        )
        let harness = AutoFillHarness(items: [item])
        let first = try Self.storedCredential(item, field: Fixtures.id(302))
        let second = try Self.storedCredential(item, field: Fixtures.id(399))
        func listed(_ allowed: [Data]) async -> [Data] {
            guard
                case .list(let list) = await harness.model.credentialList(
                    for: [], passkey: Self.assertionRequest(allowed: allowed))
            else { return [] }
            return list.passkeys.map(\.credentialID)
        }
        #expect(await listed([]) == [first.credentialID, second.credentialID])
        #expect(await listed([second.credentialID]) == [second.credentialID])
        #expect(await listed([Data(repeating: 9, count: 32)]) == [])

        // Choosing a passkey outside the allow-list is refused even though the item holds it.
        #expect(
            await harness.model.passkeyAssertion(
                for: Self.googleChoice, request: Self.assertionRequest(allowed: [second.credentialID]),
                presence: .verified)
                == .refused(.unknownRecord))
    }

    @Test("an assertion verifies under the stored key and carries truthful flags and a zero counter")
    func assertion() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let credential = try Self.storedCredential(Fixtures.google)
        let result = try await harness.model.passkeyAssertion(
            for: Self.googleChoice, request: Self.assertionRequest(), presence: .verified
        ).value
        let assertion = result.assertion
        #expect(try Self.verify(assertion, with: credential))
        #expect(assertion.credentialID == credential.credentialID)
        #expect(assertion.userHandle == Data("user-handle".utf8))
        #expect(assertion.relyingPartyID == "google.com")
        #expect(assertion.clientDataHash == Fixtures.clientDataHash())
        #expect(assertion.authenticatorData.prefix(32) == Data(SHA256.hash(data: Data("google.com".utf8))))
        #expect(assertion.authenticatorData[32] == 0x1D)
        #expect(assertion.authenticatorData.suffix(4) == Data([0, 0, 0, 0]))
        #expect(result.prf == nil)
        #expect(result.largeBlob == nil)
        #expect(await harness.vault.saves.isEmpty)
    }

    @Test(
        "flags follow what happened: verification only when verified, backup state only when synced",
        arguments: [(PersonPresence.verified, true, UInt8(0x1D)), (.present, true, 0x19), (.verified, false, 0x0D)])
    func assertionFlags(_ presence: PersonPresence, _ backedUp: Bool, _ flags: UInt8) async throws {
        let harness = AutoFillHarness(items: Fixtures.all, backedUp: backedUp)
        let result = try await harness.model.passkeyAssertion(
            for: Self.googleChoice, request: Self.assertionRequest(), presence: presence
        ).value
        #expect(result.assertion.authenticatorData[32] == flags)
    }

    @Test("verification the relying party requires is never claimed without having happened")
    func userVerification() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        let required = Self.assertionRequest(verification: .required)
        #expect(
            await harness.model.passkeyAssertion(for: Self.googleChoice, request: required, presence: .present)
                == .refused(.passkey(.userVerificationRequired)))
        #expect(
            await harness.model.passkeyAssertion(for: Self.googleChoice, request: required, presence: .absent)
                == .refused(.passkey(.userPresenceRequired)))
        #expect(
            await harness.model.passkeyAssertion(
                for: Self.googleChoice, request: Self.assertionRequest(), presence: .absent)
                == .refused(.passkey(.userPresenceRequired)))
    }

    @Test("a passkey is asserted only for its own relying party, and only from an item scoped to it (F11.1)")
    func relyingPartyBinding() async {
        var moved = Fixtures.google
        moved.id = Fixtures.id(94)
        moved.title = "Moved"
        moved.scopes = [ServiceScope(host: "accounts.example.net")]
        let harness = AutoFillHarness(items: [Fixtures.google, Fixtures.amazonRetail, moved])

        // Another party asks for Google's passkey: the item is not for that host.
        for other in ["amazon.com", "evil.example", "g00gle.com", "google.com.evil.example"] {
            let outcome = await harness.model.passkeyAssertion(
                for: Self.googleChoice, request: Self.assertionRequest(other), presence: .verified)
            #expect(outcome.refusal?.isGateRefusal == true, "\(other): \(outcome)")
        }
        // An item scoped to the asking party that holds some other party's passkey: the stored ID decides.
        var planted = Fixtures.amazonRetail
        planted.fields.append(Fixtures.google.fields[1])
        let plantedHarness = AutoFillHarness(items: [planted])
        #expect(
            await plantedHarness.model.passkeyAssertion(
                for: FieldChoice(itemID: planted.id, fieldID: Fixtures.id(302)),
                request: Self.assertionRequest("amazon.com"),
                presence: .verified) == .refused(.passkey(.relyingPartyMismatch)))
        // The right party, but the item holding the passkey is no longer scoped to it.
        let outcome = await harness.model.passkeyAssertion(
            for: FieldChoice(itemID: moved.id, fieldID: Fixtures.id(302)), request: Self.assertionRequest(),
            presence: .verified)
        #expect(outcome.refusal?.isGateRefusal == true)
    }

    @Test(
        "a relying party ID that is not a canonical registrable host is refused before anything is read",
        arguments: ["com", "co.uk", "Google.com", "google.com.", "https://google.com", "127.0.0.1", "", "goo gle.com"])
    func relyingPartyRejected(_ relyingParty: String) async {
        let harness = AutoFillHarness(items: Fixtures.all)
        let outcome = await harness.model.passkeyAssertion(
            for: Self.googleChoice, request: Self.assertionRequest(relyingParty), presence: .verified)
        guard case .refused(.passkey(.relyingPartyRejected)) = outcome else {
            Issue.record("\(relyingParty): \(outcome)")
            return
        }
        #expect(await harness.vault.readCount == 0)
    }

    @Test("malformed requests are refused: hash length, list sizes, blob size")
    func malformedAssertionRequests() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        var short = Self.assertionRequest()
        short.clientDataHash = Data(repeating: 1, count: 31)
        #expect(
            await harness.model.passkeyAssertion(for: Self.googleChoice, request: short, presence: .verified)
                == .refused(.passkey(.clientDataHashLength(31))))
        let many = Self.assertionRequest(allowed: Array(repeating: Data(repeating: 1, count: 32), count: 257))
        #expect(
            await harness.model.passkeyAssertion(for: Self.googleChoice, request: many, presence: .verified)
                == .refused(.passkey(.listTooLong)))
        let long = Self.assertionRequest(allowed: [Data(repeating: 1, count: 1024)])
        #expect(
            await harness.model.passkeyAssertion(for: Self.googleChoice, request: long, presence: .verified)
                == .refused(.passkey(.listTooLong)))
        let blob = Self.assertionRequest(
            extensions: PasskeyAssertionExtensions(
                largeBlob: .write(Data(count: PasskeyCredential.maximumLargeBlobLength + 1))))
        #expect(
            await harness.model.passkeyAssertion(for: Self.googleChoice, request: blob, presence: .verified)
                == .refused(.passkey(.largeBlobTooLong)))
        #expect(await harness.vault.readCount == 0)
    }

    @Test("a locked vault yields no assertion")
    func lockedAssertion() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        await harness.vault.lock()
        #expect(
            await harness.model.passkeyAssertion(
                for: Self.googleChoice, request: Self.assertionRequest(), presence: .verified) == .vaultLocked)
    }

    // MARK: prf and largeBlob

    @Test("prf output is stable across assertions and equals the evaluation over the stored secret")
    func prf() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let credential = try Self.storedCredential(Fixtures.google)
        let inputs = PRFInputValues(first: Data("first".utf8), second: Data("second".utf8))
        let request = Self.assertionRequest(
            extensions: PasskeyAssertionExtensions(prf: PRFAssertionInput(inputValues: inputs)))
        let first = try await harness.model.passkeyAssertion(
            for: Self.googleChoice, request: request, presence: .verified
        ).value
        let second = try await harness.model.passkeyAssertion(
            for: Self.googleChoice, request: request, presence: .verified
        ).value
        let expected = try PasskeyPRF.evaluate(secret: try #require(credential.prfSecret), inputs: inputs)
        #expect(first.prf == expected)
        #expect(second.prf == expected)
        #expect(first.prf?.second != nil)
        // The signatures differ (ECDSA is randomised); the derived keys do not.
        #expect(try Self.verify(second.assertion, with: credential))
    }

    @Test("inputs given for the chosen credential win over the general ones")
    func prfPerCredential() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let credential = try Self.storedCredential(Fixtures.google)
        let general = PRFInputValues(first: Data("general".utf8))
        let specific = PRFInputValues(first: Data("specific".utf8))
        let request = Self.assertionRequest(
            extensions: PasskeyAssertionExtensions(
                prf: PRFAssertionInput(
                    inputValues: general,
                    perCredential: [credential.credentialID: specific, Data(repeating: 5, count: 32): general])))
        let result = try await harness.model.passkeyAssertion(
            for: Self.googleChoice, request: request, presence: .verified
        ).value
        #expect(result.prf == (try PasskeyPRF.evaluate(secret: try #require(credential.prfSecret), inputs: specific)))

        let none = Self.assertionRequest(extensions: PasskeyAssertionExtensions(prf: PRFAssertionInput()))
        #expect(
            try await harness.model.passkeyAssertion(
                for: Self.googleChoice, request: none, presence: .verified
            ).value.prf == nil)
    }

    @Test("prf is not evaluated for a person who was present but not verified")
    func prfNeedsVerification() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let inputs = PRFInputValues(first: Data("first".utf8))
        let request = Self.assertionRequest(
            extensions: PasskeyAssertionExtensions(prf: PRFAssertionInput(inputValues: inputs)))
        let present = try await harness.model.passkeyAssertion(
            for: Self.googleChoice, request: request, presence: .present
        ).value
        #expect(present.prf == nil)
        #expect(present.assertion.authenticatorData[32] == 0x19)
        #expect(
            try await harness.model.passkeyAssertion(for: Self.googleChoice, request: request, presence: .verified)
                .value.prf != nil)

        let registered = try await harness.model.registerPasskey(
            Self.registrationRequest(extensions: PasskeyRegistrationExtensions(prf: .evaluate(inputs))),
            destination: .newItem, presence: .present
        ).value
        #expect(registered.prf == PRFRegistrationOutput(isSupported: true, values: nil))
    }

    @Test("a credential whose key cannot sign writes no largeBlob either")
    func unusableKeyWritesNothing() async throws {
        var credential = try Self.storedCredential(Fixtures.google)
        credential.privateKeyPKCS8 = Data("not a key".utf8)
        var broken = Fixtures.google
        broken.fields[1] = try Field.passkey(credential, id: Fixtures.id(302))
        let harness = AutoFillHarness(items: [broken])
        let request = Self.assertionRequest(
            extensions: PasskeyAssertionExtensions(largeBlob: .write(Data("blob".utf8))))
        #expect(
            await harness.model.passkeyAssertion(for: Self.googleChoice, request: request, presence: .verified)
                == .refused(.passkey(.unusablePrivateKey)))
        #expect(await harness.vault.saves.isEmpty)
    }

    @Test("a largeBlob is written into the item, read back, and survives in history when replaced")
    func largeBlob() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        func assert(_ input: LargeBlobAssertionInput) async throws -> PasskeyAssertionResult {
            try await harness.model.passkeyAssertion(
                for: Self.googleChoice,
                request: Self.assertionRequest(extensions: PasskeyAssertionExtensions(largeBlob: input)),
                presence: .verified
            ).value
        }
        #expect(try await assert(.read).largeBlob == .read(nil))
        let blob = Data("certificate bytes".utf8)
        let written = try await assert(.write(blob))
        #expect(written.largeBlob == .write(didWrite: true))
        let stored = try #require(await harness.vault.item(Fixtures.google.id))
        #expect(try Self.storedCredential(stored).largeBlob == blob)
        #expect(stored.version == 2)
        #expect(stored.scopes == Fixtures.google.scopes)
        // The key did not change, so the assertion made alongside the write verifies under the same credential.
        #expect(try Self.verify(written.assertion, with: try Self.storedCredential(Fixtures.google)))
        #expect(try await assert(.read).largeBlob == .read(blob))

        // Writing the same bytes again is not a new version.
        #expect(try await assert(.write(blob)).largeBlob == .write(didWrite: true))
        #expect(await harness.vault.saves.count == 1)

        // Another write the same day is not made (Z66): reported as not written, the assertion still good.
        #expect(try await assert(.write(Data("same day".utf8))).largeBlob == .write(didWrite: false))
        #expect(await harness.vault.saves.count == 1)

        // A write that loses to a concurrent change is reported as not written; the assertion still stands.
        await harness.clock.advance(by: CredentialProviderModel.largeBlobInterval)
        await harness.vault.failNextSave(with: .versionConflict(Fixtures.google.id))
        let lost = try await assert(.write(Data("other".utf8)))
        #expect(lost.largeBlob == .write(didWrite: false))
        #expect(try await assert(.read).largeBlob == .read(blob))
    }

    // MARK: Without interaction

    static func identity(_ item: Item, field: Int, credential: PasskeyCredential) -> PasskeyIdentityRequest {
        PasskeyIdentityRequest(
            recordIdentifier: RecordIdentifier(itemID: item.id, fieldID: Fixtures.id(field)).text,
            credentialID: credential.credentialID)
    }

    @Test("a passkey chosen in the system sheet is asserted without UI, even between tied accounts")
    func silentAssertion() async throws {
        var second = Fixtures.google
        second.id = Fixtures.id(95)
        second.title = "Google (work)"
        second.fields[1] = Fixtures.passkey(
            relyingParty: "google.com", userName: "work@example.com", seed: 55, id: Fixtures.id(395))
        let harness = AutoFillHarness(items: [Fixtures.google, second])
        let credential = try Self.storedCredential(second)
        let result = try await harness.model.passkeyAssertionWithoutInteraction(
            request: Self.assertionRequest(), identity: Self.identity(second, field: 395, credential: credential),
            presence: .verified
        ).value
        #expect(try Self.verify(result.assertion, with: credential))
        #expect(result.assertion.credentialID == credential.credentialID)
    }

    @Test("without UI, a locked vault, missing verification or presence each ask for the person")
    func silentNeedsInteraction() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let credential = try Self.storedCredential(Fixtures.google)
        let identity = Self.identity(Fixtures.google, field: 302, credential: credential)
        #expect(
            await harness.model.passkeyAssertionWithoutInteraction(
                request: Self.assertionRequest(verification: .required), identity: identity, presence: .present)
                == .requiresInteraction(.userVerification))
        #expect(
            await harness.model.passkeyAssertionWithoutInteraction(
                request: Self.assertionRequest(), identity: identity, presence: .absent)
                == .requiresInteraction(.userPresence))
        await harness.vault.lock()
        #expect(
            await harness.model.passkeyAssertionWithoutInteraction(
                request: Self.assertionRequest(), identity: identity, presence: .verified)
                == .requiresInteraction(.vaultLocked))
    }

    @Test("an identity that does not match what is stored is refused")
    func silentRefusals() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let credential = try Self.storedCredential(Fixtures.google)
        var wrongID = Self.identity(Fixtures.google, field: 302, credential: credential)
        wrongID.credentialID = Data(repeating: 3, count: 32)
        #expect(
            await harness.model.passkeyAssertionWithoutInteraction(
                request: Self.assertionRequest(), identity: wrongID, presence: .verified) == .refused(.unknownRecord))
        for record in [
            "", "x", RecordIdentifier(itemID: Fixtures.google.id).text,
            RecordIdentifier(itemID: Fixtures.google.id, fieldID: Fixtures.id(301)).text,
            RecordIdentifier(itemID: Fixtures.id(999), fieldID: Fixtures.id(302)).text,
        ] {
            #expect(
                await harness.model.passkeyAssertionWithoutInteraction(
                    request: Self.assertionRequest(),
                    identity: PasskeyIdentityRequest(recordIdentifier: record, credentialID: credential.credentialID),
                    presence: .verified) == .refused(.unknownRecord), "\(record)")
        }
        let elsewhere = await harness.model.passkeyAssertionWithoutInteraction(
            request: Self.assertionRequest("amazon.com"),
            identity: Self.identity(Fixtures.google, field: 302, credential: credential), presence: .verified)
        #expect(elsewhere.refusal?.isGateRefusal == true)
    }

    // MARK: Registration

    @Test("a relying party that resembles a saved site carries the look-alike warning in its new-item proposal")
    func registerOnLookAlikeRelyingParty() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let options = try await harness.model.passkeyRegistrationOptions(for: Self.registrationRequest("amaz0n.com"))
            .value
        #expect(options.existingItems.isEmpty)
        #expect(options.newItem.warning?.impersonating == ["amazon.com"])
        // A relying party of a saved site carries none.
        let genuine = try await harness.model.passkeyRegistrationOptions(for: Self.registrationRequest("amazon.com"))
            .value
        #expect(genuine.newItem.warning == nil)
    }

    @Test("registering for a new site creates an item titled and scoped by the relying party")
    func registerNewItem() async throws {
        // Without the library card: its host `library.example.org` has "example" as its name, which the reserved
        // suffix of `shop.example` would be taken to imitate.
        let harness = AutoFillHarness(items: Fixtures.all.filter { $0.id != Fixtures.library.id })
        let request = Self.registrationRequest(
            extensions: PasskeyRegistrationExtensions(prf: .checkForSupport, largeBlobRequested: true))
        let options = try await harness.model.passkeyRegistrationOptions(for: request).value
        #expect(options.existingItems.isEmpty)
        #expect(options.relatedLogins.isEmpty)
        #expect(options.suggested == .newItem)
        #expect(options.relyingPartyID == "shop.example")
        #expect(
            options.newItem
                == NewItemProposal(
                    vault: Fixtures.personalVault, title: "shop.example", scopeHost: "shop.example",
                    includesSubdomains: true,
                    userName: "pat@example.com", warning: nil, hiddenAccounts: 0, besideExisting: nil))

        let result = try await harness.model.registerPasskey(request, destination: .newItem, presence: .verified).value
        let item = try #require(await harness.vault.item(result.itemID))
        #expect(result.createdItem)
        #expect(item.title == "shop.example")
        #expect(item.scopes == [ServiceScope(host: "shop.example", includeSubdomains: true)])
        #expect(item.vaultID == Fixtures.vaultID)
        #expect(item.fields.map(\.kind) == [.username, .passkey])
        #expect(item.fields.first?.value == "pat@example.com")
        let credential = try Self.storedCredential(item, field: result.fieldID)
        #expect(credential.credentialID == result.credentialID)
        #expect(credential.relyingPartyID == "shop.example")
        #expect(credential.userHandle == Data("handle-1".utf8))
        #expect(credential.createdAt == Fixtures.now)
        #expect(credential.prfSecret?.count == 32)
        #expect(result.clientDataHash == Fixtures.clientDataHash(2))
        #expect(result.prf == PRFRegistrationOutput(isSupported: true, values: nil))
        #expect(result.largeBlobSupported == true)

        // The attestation object is `none` over authenticator data that names this credential and its public key.
        let attestation = [UInt8](result.attestationObject)
        #expect(
            Array(attestation.prefix(30))
                == [UInt8](hex: "a363666d74646e6f6e656761747453746d74a068617574684461746158a4"))
        let authenticatorData = Data(attestation.dropFirst(30))
        #expect(authenticatorData.prefix(32) == Data(SHA256.hash(data: Data("shop.example".utf8))))
        #expect(authenticatorData[32] == 0x5D)
        #expect(authenticatorData[55..<87] == credential.credentialID)
        let publicKey = try P256.Signing.PrivateKey(derRepresentation: credential.privateKeyPKCS8).publicKey
        #expect(authenticatorData[97..<129] == publicKey.x963Representation[1..<33])
        #expect(authenticatorData[132..<164] == publicKey.x963Representation[33..<65])

        // The new passkey is offered, published and usable straight away.
        #expect(
            await harness.publisher.published.contains {
                if case .passkey(let identity) = $0 { return identity.credentialID == credential.credentialID }
                return false
            })
        let assertion = try await harness.model.passkeyAssertion(
            for: FieldChoice(itemID: item.id, fieldID: result.fieldID), request: Self.assertionRequest("shop.example"),
            presence: .verified
        ).value
        #expect(try Self.verify(assertion.assertion, with: credential))
    }

    @Test("a passkey can join the item the site's password is in, whose scopes stay as they were")
    func registerIntoExistingItem() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let request = Self.registrationRequest("amazon.com", userName: Fixtures.email)
        let options = try await harness.model.passkeyRegistrationOptions(for: request).value
        #expect(options.existingItems.map(\.title) == ["Amazon"])
        #expect(options.existingItems.first?.matchesUserName == true)
        #expect(options.suggested == .existingItem(Fixtures.amazonRetail.id))

        let result = try await harness.model.registerPasskey(
            request, destination: .existingItem(Fixtures.amazonRetail.id), presence: .verified
        ).value
        #expect(!result.createdItem)
        #expect(result.itemID == Fixtures.amazonRetail.id)
        let item = try #require(await harness.vault.item(Fixtures.amazonRetail.id))
        #expect(item.scopes == Fixtures.amazonRetail.scopes)
        #expect(item.title == "Amazon")
        #expect(item.fields.dropLast() == Fixtures.amazonRetail.fields[...])
        #expect(item.fields.last?.kind == .passkey)
        #expect(await harness.vault.allItems.count == Fixtures.all.count)
    }

    /// The review finding: the second account's new item was scoped to the relying party exactly, outranked the
    /// item holding the first account's passkey, and the gate then refused that passkey for good.
    @Test("a second account's passkey, registered beside the first, leaves the first assertable")
    func secondAccountBesideTheFirst() async throws {
        var example = Fixtures.library
        example.title = "Example"
        example.scopes = [ServiceScope(host: "example.com")]
        example.fields[1].value = "alice"
        let harness = AutoFillHarness(items: [example])
        let alice = try await harness.model.registerPasskey(
            Self.registrationRequest("login.example.com", userName: "alice", handle: "alice-handle"),
            destination: .existingItem(example.id), presence: .verified
        ).value
        let aliceChoice = FieldChoice(itemID: example.id, fieldID: alice.fieldID)
        let assertion = Self.assertionRequest("login.example.com")
        #expect(
            try await harness.model.passkeyAssertion(for: aliceChoice, request: assertion, presence: .verified).value
                .assertion.userHandle == Data("alice-handle".utf8))

        // Bob registers. No item holds his name, so the suggestion is a new item, and one that hides nobody.
        let bobRequest = Self.registrationRequest("login.example.com", userName: "bob", handle: "bob-handle")
        let options = try await harness.model.passkeyRegistrationOptions(for: bobRequest).value
        #expect(options.existingItems.map(\.itemID) == [example.id])
        #expect(options.newItem.scopeHost == "login.example.com")
        #expect(options.newItem.hiddenAccounts == 1)
        #expect(
            options.newItem.besideExisting
                == SharedScopeProposal(scopeHost: "example.com", includesSubdomains: true, accounts: 1))
        #expect(options.suggested == .newItemBesideExisting)
        let bob = try await harness.model.registerPasskey(
            bobRequest, destination: options.suggested, presence: .verified
        )
        .value
        #expect(bob.createdItem)
        #expect(await harness.vault.item(bob.itemID)?.scopes == [ServiceScope(host: "example.com")])
        #expect(await harness.vault.item(example.id)?.scopes == [ServiceScope(host: "example.com")])

        // Both passkeys are offered, published and assertable, by choice and from the system's sheet.
        guard
            case .list(let list) = await harness.model.credentialList(
                for: [Fixtures.domain("login.example.com")], passkey: assertion)
        else {
            Issue.record("no list")
            return
        }
        #expect(Set(list.passkeys.map(\.userName)) == ["alice", "bob"])
        let published = await harness.publisher.published.compactMap { identity -> PasskeyIdentity? in
            if case .passkey(let passkey) = identity { return passkey }
            return nil
        }
        #expect(Set(published.map(\.userName)) == ["alice", "bob"])
        for identity in published {
            #expect(
                try await harness.model.passkeyAssertionWithoutInteraction(
                    request: assertion, identity: identity.handedBack, presence: .verified
                ).value.assertion.userHandle == identity.userHandle)
        }
        #expect(
            try await harness.model.passkeyAssertion(for: aliceChoice, request: assertion, presence: .verified).value
                .assertion.userHandle == Data("alice-handle".utf8))

        // The other destination, which the sheet said would hide one account: it does, and the hidden passkey's
        // identity leaves the system's sheet instead of being offered and then refused.
        let apart = AutoFillHarness(items: [try #require(await harness.vault.item(example.id))], seed: 43)
        _ = try await apart.publishedIdentities()
        _ = try await apart.model.registerPasskey(bobRequest, destination: .newItem, presence: .verified).value
        #expect(
            await apart.model.passkeyAssertion(for: aliceChoice, request: assertion, presence: .verified)
                .refusal?.isGateRefusal == true)
        let left = await apart.publisher.published.compactMap { identity -> String? in
            if case .passkey(let passkey) = identity { return passkey.userName }
            return nil
        }
        #expect(left == ["bob"])
    }

    /// The review finding: a login the save flow scoped to `www.shop.example` is not for the relying party
    /// `shop.example`, so the passkey cannot join it. That stays so, because joining it would mean adding a scope
    /// from the extension (PRD F11.7); what changed is that the sheet now names the login.
    @Test("a login scoped under the relying party is named, never re-scoped, and the passkey goes to its own item")
    func loginScopedBelowTheRelyingParty() async throws {
        let harness = AutoFillHarness(items: [])
        let saved = try await harness.model.savePasswordWithoutInteraction(
            SavePasswordRequest(
                serviceIdentifier: Fixtures.url("https://www.shop.example/login"), userName: "pat@example.com",
                password: "pw")
        ).value
        let login = try #require(await harness.vault.item(saved.itemID))
        #expect(login.scopes == [ServiceScope(host: "www.shop.example", includeSubdomains: false)])

        let request = Self.registrationRequest("shop.example")
        #expect(await harness.model.registerPasskeyWithoutInteraction(request) == .refused(.noItemToUpgrade))
        let options = try await harness.model.passkeyRegistrationOptions(for: request).value
        #expect(options.existingItems.isEmpty)
        #expect(options.relatedLogins.map(\.itemID) == [login.id])
        #expect(options.relatedLogins.first?.title == "www.shop.example")
        #expect(options.suggested == .newItem)
        #expect(options.newItem.hiddenAccounts == 0)
        // Naming it as the destination anyway is refused by the gate, and nothing is written.
        #expect(
            await harness.model.registerPasskey(request, destination: .existingItem(login.id), presence: .verified)
                .refusal?.isGateRefusal == true)
        #expect(await harness.vault.item(login.id) == login)

        let registered = try await harness.model.registerPasskey(request, destination: .newItem, presence: .verified)
            .value
        #expect(registered.createdItem)
        #expect(await harness.vault.item(login.id) == login)
        // Each half works where it belongs: the password on www, the passkey for the relying party.
        #expect(
            try await harness.model.password(
                for: PasswordChoice(itemID: login.id, userName: "pat@example.com"),
                identifiers: [Fixtures.url("https://www.shop.example/login")]
            ).value.password == "pw")
        #expect(
            try await harness.model.passkeyAssertion(
                for: FieldChoice(itemID: registered.itemID, fieldID: registered.fieldID),
                request: Self.assertionRequest("shop.example"), presence: .verified
            ).value.assertion.userHandle == Data("handle-1".utf8))

        // A login for another account, or one scoped elsewhere, is not "related".
        var other = login
        other.id = Fixtures.id(60)
        other.scopes = [ServiceScope(host: "www.shop.example.net")]
        var otherUser = login
        otherUser.id = Fixtures.id(61)
        otherUser.fields[0].value = "someone@else.example"
        let unrelated = AutoFillHarness(items: [other, otherUser])
        #expect(try await unrelated.model.passkeyRegistrationOptions(for: request).value.relatedLogins.isEmpty)
    }

    @Test("one item holds a bounded number of passkeys")
    func passkeysPerItemAreBounded() async throws {
        let harness = AutoFillHarness(items: [Fixtures.amazonRetail])
        for round in 0..<CredentialProviderModel.maximumPasskeysPerItem {
            _ = try await harness.model.registerPasskey(
                Self.registrationRequest("amazon.com", userName: Fixtures.email, handle: "handle-\(round)"),
                destination: .existingItem(Fixtures.amazonRetail.id), presence: .verified
            ).value
        }
        let full = Self.registrationRequest("amazon.com", userName: Fixtures.email, handle: "one-too-many")
        #expect(
            await harness.model.registerPasskey(
                full, destination: .existingItem(Fixtures.amazonRetail.id), presence: .verified)
                == .refused(.passkey(.tooManyCredentials)))
        let options = try await harness.model.passkeyRegistrationOptions(for: full).value
        #expect(options.existingItems.isEmpty)
        #expect(options.suggested == .newItemBesideExisting || options.suggested == .newItem)
        #expect(
            await harness.vault.item(Fixtures.amazonRetail.id)?.fields.filter { $0.kind == .passkey }.count
                == CredentialProviderModel.maximumPasskeysPerItem)
    }

    @Test("a passkey cannot be added to an item that is not for the relying party")
    func registerIntoForeignItem() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        for itemID in [Fixtures.awsRoot.id, Fixtures.bank.id, Fixtures.id(999)] {
            let outcome = await harness.model.registerPasskey(
                Self.registrationRequest("amazon.com"), destination: .existingItem(itemID), presence: .verified)
            #expect(outcome.refusal != nil && outcome.refusal != .noServiceIdentifier, "\(outcome)")
        }
        #expect(await harness.vault.saves.isEmpty)
    }

    @Test(
        "a relying party ID the scope policy refuses is never stored (F11.2)",
        arguments: ["com", "co.uk", "github.io", "localhost", "Shop.example", "shop.example.", "10.0.0.1"])
    func registerRejectedRelyingParty(_ relyingParty: String) async {
        let harness = AutoFillHarness(items: Fixtures.all)
        let request = Self.registrationRequest(relyingParty)
        for outcome in [
            await harness.model.registerPasskey(request, destination: .newItem, presence: .verified).refusal,
            await harness.model.passkeyRegistrationOptions(for: request).refusal,
            await harness.model.registerPasskeyWithoutInteraction(request).refusal,
        ] {
            guard case .passkey(.relyingPartyRejected) = outcome else {
                Issue.record("\(relyingParty): \(String(describing: outcome))")
                continue
            }
        }
        #expect(await harness.vault.saves.isEmpty)
    }

    @Test("malformed registration requests are refused")
    func malformedRegistrationRequests() async {
        let harness = AutoFillHarness(items: Fixtures.all)
        func refusal(_ request: PasskeyRegistrationRequest, presence: PersonPresence = .verified) async
            -> ProviderRefusal?
        {
            await harness.model.registerPasskey(request, destination: .newItem, presence: presence).refusal
        }
        #expect(await refusal(Self.registrationRequest(algorithms: [-257, -8])) == .passkey(.noSupportedAlgorithm))
        #expect(await refusal(Self.registrationRequest(algorithms: [])) == .passkey(.noSupportedAlgorithm))
        #expect(await refusal(Self.registrationRequest(handle: "")) == .passkey(.invalidUser("userHandle")))
        #expect(
            await refusal(Self.registrationRequest(handle: String(repeating: "h", count: 65)))
                == .passkey(.invalidUser("userHandle")))
        #expect(
            await refusal(Self.registrationRequest(userName: "pat\u{202E}moc.elpmaxe"))
                == .passkey(.invalidUser("userName")))
        #expect(
            await refusal(Self.registrationRequest(userName: String(repeating: "n", count: 1025)))
                == .passkey(.invalidUser("userName")))
        var badHash = Self.registrationRequest()
        badHash.clientDataHash = Data()
        #expect(await refusal(badHash) == .passkey(.clientDataHashLength(0)))
        #expect(
            await refusal(Self.registrationRequest(verification: .required), presence: .present)
                == .passkey(.userVerificationRequired))
        #expect(await refusal(Self.registrationRequest(), presence: .absent) == .passkey(.userPresenceRequired))
        let longPRF = Self.registrationRequest(
            extensions: PasskeyRegistrationExtensions(prf: .evaluate(PRFInputValues(first: Data(count: 5000)))))
        #expect(await refusal(longPRF) == .passkey(.prfInputTooLong))
        #expect(await harness.vault.saves.isEmpty)
    }

    @Test("a credential the relying party excludes blocks a second registration")
    func excludedCredential() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let existing = try Self.storedCredential(Fixtures.google)
        let request = Self.registrationRequest(
            "google.com", excluded: [Data(repeating: 1, count: 32), existing.credentialID])
        #expect(
            await harness.model.registerPasskey(request, destination: .newItem, presence: .verified)
                == .refused(.passkey(.credentialExcluded)))
        #expect(await harness.model.passkeyRegistrationOptions(for: request) == .refused(.passkey(.credentialExcluded)))
        // The same ID excluded by another relying party means nothing.
        let other = Self.registrationRequest("shop.example", excluded: [existing.credentialID])
        #expect(
            try await harness.model.registerPasskey(other, destination: .newItem, presence: .verified).value.createdItem
        )
    }

    @Test("prf can be evaluated at registration, and matches a later assertion")
    func registrationPRF() async throws {
        let harness = AutoFillHarness(items: [])
        let inputs = PRFInputValues(first: Data("enrol".utf8))
        let result = try await harness.model.registerPasskey(
            Self.registrationRequest(extensions: PasskeyRegistrationExtensions(prf: .evaluate(inputs))),
            destination: .newItem, presence: .verified
        ).value
        #expect(result.largeBlobSupported == nil)
        let atRegistration = try #require(result.prf?.values)
        let later = try await harness.model.passkeyAssertion(
            for: FieldChoice(itemID: result.itemID, fieldID: result.fieldID),
            request: Self.assertionRequest(
                "shop.example", extensions: PasskeyAssertionExtensions(prf: PRFAssertionInput(inputValues: inputs))),
            presence: .verified
        ).value
        #expect(later.prf == atRegistration)
    }

    @Test("a random source that repeats itself cannot mint the same credential twice")
    func repeatingGenerator() async throws {
        let vault = FakeCredentialVault(vaultID: Fixtures.vaultID)
        let model = CredentialProviderModel(
            vault: vault, clock: FakeClock(Fixtures.now), random: RepeatingGenerator(words: [0x0123_4567_89AB_CDEF]))
        _ = try await model.registerPasskey(Self.registrationRequest(), destination: .newItem, presence: .verified)
            .value
        #expect(
            await model.registerPasskey(
                Self.registrationRequest("other.example"), destination: .newItem, presence: .verified)
                == .refused(.passkey(.credentialIDCollision)))
        #expect(await vault.allItems.count == 1)

        let dead = CredentialProviderModel(
            vault: vault, clock: FakeClock(Fixtures.now), random: RepeatingGenerator(words: [0]))
        #expect(
            await dead.registerPasskey(
                Self.registrationRequest("third.example"), destination: .newItem, presence: .verified)
                == .refused(.passkey(.keyGenerationFailed)))
    }

    @Test("a vault that is not synced yields a credential that says it is not backed up")
    func notBackedUp() async throws {
        let harness = AutoFillHarness(items: [], backedUp: false)
        let result = try await harness.model.registerPasskey(
            Self.registrationRequest(), destination: .newItem, presence: .verified
        ).value
        // BE without BS: eligible, not yet backed up.
        #expect(result.attestationObject[30 + 32] == 0x4D)
    }

    // MARK: Conditional registration (F6.2, F11.8)

    @Test("a conditional request upgrades the one password login the site has, without asking")
    func conditionalUpgrade() async throws {
        let harness = AutoFillHarness(items: Fixtures.all)
        let request = Self.registrationRequest("amazon.com", userName: Fixtures.email)
        let result = try await harness.model.registerPasskeyWithoutInteraction(request).value
        #expect(result.itemID == Fixtures.amazonRetail.id)
        #expect(!result.createdItem)
        // Nobody was asked: neither UP nor UV, and the credential is backed up.
        #expect(result.attestationObject[30 + 32] == 0x58)
        let item = try #require(await harness.vault.item(Fixtures.amazonRetail.id))
        #expect(item.fields.map(\.kind) == [.email, .password, .totp, .passkey])
        #expect(item.scopes == Fixtures.amazonRetail.scopes)
        #expect(await harness.vault.allItems.count == Fixtures.all.count)

        // Asking again adds nothing: not for the same account, not under another user handle, and not as another
        // relying party the same page could name. An upgrade happens once.
        #expect(await harness.model.registerPasskeyWithoutInteraction(request) == .refused(.noItemToUpgrade))
        for again in [
            Self.registrationRequest("amazon.com", userName: Fixtures.email, handle: "another-handle"),
            Self.registrationRequest("www.amazon.com", userName: Fixtures.email, handle: "third-handle"),
        ] {
            #expect(await harness.model.registerPasskeyWithoutInteraction(again) == .refused(.noItemToUpgrade))
        }
        #expect(await harness.vault.saves.count == 1)
    }

    /// Review finding Z71: a conditional upgrade is the relying party's write, so it has the budget every such
    /// write has. An item whose history already holds about the budget is not upgraded without the person.
    @Test("a conditional request does not upgrade an item it would take past the remote-write budget")
    func conditionalUpgradeHasTheBudget() async throws {
        var item = Fixtures.amazonRetail
        let note = Field(kind: .text, label: "Note", value: String(repeating: "n", count: 16 * 1024))
        item.history = (0..<32).map {
            ItemHistoryEntry(replacedAt: Fixtures.now, version: UInt64($0 + 1), fields: item.fields + [note])
        }
        let harness = AutoFillHarness(items: [item])
        let request = Self.registrationRequest("amazon.com", userName: Fixtures.email)
        #expect(await harness.model.registerPasskeyWithoutInteraction(request) == .refused(.noItemToUpgrade))
        #expect(await harness.vault.saves.isEmpty)
        // With the person, on the registration sheet, it is theirs to do.
        let chosen = try await harness.model.registerPasskey(
            request, destination: .existingItem(item.id), presence: .verified
        ).value
        #expect(chosen.itemID == item.id)
    }

    @Test("a conditional request never creates an item or guesses between accounts")
    func conditionalRefusals() async {
        var second = Fixtures.amazonRetail
        second.id = Fixtures.id(96)
        var passwordless = Fixtures.library
        passwordless.fields.removeAll { $0.kind == .password }
        var archived = Fixtures.bank
        archived.archived = true
        var excluded = Fixtures.library
        excluded.id = Fixtures.id(97)
        excluded.scopes = [ServiceScope(host: "private.example")]
        excluded.excludedFromSuggestions = true
        let harness = AutoFillHarness(
            items: [Fixtures.amazonRetail, second, passwordless, archived, excluded, Fixtures.google])
        for request in [
            Self.registrationRequest("new-site.example"),  // nothing saved for the site
            Self.registrationRequest("amazon.com", userName: Fixtures.email),  // two accounts tie
            Self.registrationRequest("library.example.org", userName: "pat"),  // no password to upgrade
            Self.registrationRequest("firstbank.co.uk", userName: "40012345"),  // archived
            Self.registrationRequest("private.example", userName: "pat"),  // excluded from AutoFill
            Self.registrationRequest("google.com", userName: "someone@else.example"),  // another account's name
            Self.registrationRequest("google.com", userName: ""),
        ] {
            #expect(
                await harness.model.registerPasskeyWithoutInteraction(request) == .refused(.noItemToUpgrade),
                "\(request.relyingPartyID)")
        }
        #expect(await harness.vault.saves.isEmpty)
        #expect(
            await harness.model.registerPasskeyWithoutInteraction(
                Self.registrationRequest("amazon.com", verification: .required))
                == .requiresInteraction(.userVerification))
        await harness.vault.lock()
        #expect(
            await harness.model.registerPasskeyWithoutInteraction(Self.registrationRequest("amazon.com"))
                == .requiresInteraction(.vaultLocked))
    }
}
