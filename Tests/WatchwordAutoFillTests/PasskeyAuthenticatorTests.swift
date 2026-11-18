import Crypto
import Foundation
import Testing
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordAutoFill

/// Known answers from an independent implementation: Python 3 with `cryptography`, `hashlib` and `hmac`.
///
/// The script reproduces `SeededGenerator` (SplitMix64) and the order in which `PasskeyAuthenticator.register` draws
/// from it (private scalar, credential ID, `prf` secret: 32 bytes each, as little-endian 64-bit words), derives the
/// public key with `cryptography`, and builds the COSE key, authenticator data and attestation object byte by byte
/// with no CBOR library. Nothing below was produced by the code under test, except `recordedSignature`, which that
/// script's verification step accepted.
///
/// ```python
/// import hashlib, hmac, struct
/// from cryptography.hazmat.primitives.asymmetric import ec
/// from cryptography.hazmat.primitives import hashes, serialization
/// M = (1 << 64) - 1
/// def splitmix(state):
///     while True:
///         state = (state + 0x9E3779B97F4A7C15) & M
///         z = state
///         z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M
///         z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M
///         yield z ^ (z >> 31)
/// def take(gen, count):
///     return b"".join(struct.pack("<Q", next(gen)) for _ in range((count + 7) // 8))[:count]
/// gen = splitmix(2024)
/// scalar, cred_id, prf_secret = take(gen, 32), take(gen, 32), take(gen, 32)
/// key = ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())
/// n = key.public_key().public_numbers()
/// x, y = n.x.to_bytes(32, "big"), n.y.to_bytes(32, "big")
/// aaguid = bytes.fromhex("5B0C7A3E9D414F6CA2B83E1F7C0D9A54")
/// cose = bytes.fromhex("a5010203262001215820") + x + bytes.fromhex("225820") + y
/// def auth_data(flags, attested):
///     data = hashlib.sha256(b"example.com").digest() + bytes([flags]) + bytes(4)
///     return data + (aaguid + struct.pack(">H", 32) + cred_id + cose if attested else b"")
/// reg = auth_data(0x5D, True)
/// att = b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x58" + bytes([len(reg)]) + reg
/// prf = lambda s, v: hmac.new(s, hashlib.sha256(b"WebAuthn PRF\x00" + v).digest(), hashlib.sha256).hexdigest()
/// own = ec.derive_private_key(
///     int.from_bytes(hashlib.sha256(b"watchword passkey vector").digest(), "big"), ec.SECP256R1())
/// pkcs8 = own.private_bytes(
///     serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
/// # Verifying what the authenticator signed (raises InvalidSignature otherwise):
/// own.public_key().verify(
///     recorded_signature, auth_data(0x1D, False) + hashlib.sha256(b"client data").digest(),
///     ec.ECDSA(hashes.SHA256()))
/// ```
enum PasskeyVectors {
    static let seed: UInt64 = 2024
    static let relyingParty = "example.com"
    static let credentialID = "7a43766465c1a0d4eb5a45696d7b6b8d973260e3ca49022392a7c4993e03aa98"
    static let prfSecret = "30e5a95be0e8392b310336dc847b466d39a3215dbf8728761bcda59699a344d6"
    static let publicKeyX963 =
        "04f073985dfe21efa1ee09890f8813919dd5be6ff5626b1b5b2fe84122c1080a51"
        + "d2bfbcfa987c80d5ccb9f23317e49c12d6cc8ed60839172fbbf46733ffc0bfca"
    static let coseKey =
        "a5010203262001215820f073985dfe21efa1ee09890f8813919dd5be6ff5626b1b5b2fe84122c1080a51"
        + "225820d2bfbcfa987c80d5ccb9f23317e49c12d6cc8ed60839172fbbf46733ffc0bfca"
    static let rpIDHash = "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947"
    /// Flags 0x5D: UP, UV, BE, BS, AT.
    static let registrationAuthenticatorData =
        rpIDHash + "5d00000000" + "5b0c7a3e9d414f6ca2b83e1f7c0d9a54" + "0020" + credentialID + coseKey
    static let attestationObject =
        "a363666d74646e6f6e656761747453746d74a068617574684461746158a4" + registrationAuthenticatorData
    static let prfFirst = "04c59834bb3f0db7bfe0f06911653df5b263f147c49dc3926fade9cd204b84a2"
    static let prfSecond = "b5952f695e1b4df7e1b51bafbfeda8271067ac9f866247a646e7070132d60ff1"
    /// `prf(bytes(range(32)), bytes(32))`.
    static let prfFixed = "2468e7275b6817e2349d84793d2d4651a2e1ead9b347339450e8ed7ca91e1740"

    /// A key the Python script generated, as PKCS#8 DER, and its public point.
    static let ownPKCS8 =
        "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101042035704852ffb20bf832c6a9ce6ac1d6f9"
        + "db60daf300c5b8194f166fe0c6cd233ea144034200044530f125ff31221e58126df75189087c439510c92d58d0df1ae1d86d8a"
        + "58637c5b2be7f8d917651c780ca3f8f38ea8a4b0df24c4235db3d0a6ca0b50938f6e71"
    static let ownPublicKeyX963 =
        "044530f125ff31221e58126df75189087c439510c92d58d0df1ae1d86d8a58637c"
        + "5b2be7f8d917651c780ca3f8f38ea8a4b0df24c4235db3d0a6ca0b50938f6e71"
    /// SHA-256 of `client data`.
    static let clientDataHash = "108a9107a11167c1d1090f07d6fd7dbf37f8cd8ad88a90fc1b3bc067c120fd23"

    /// One signature `PasskeyAuthenticator.assertion` produced with `ownPKCS8` over
    /// `authenticatorData(flags 0x1D) ‖ clientDataHash`, which `cryptography` verified (the last lines of the script).
    static let recordedSignature =
        "3046022100819b3bacccea4d075f1c436a126e02415cbf9006597dd1603b0b743470892fb7"
        + "0221008ba912f4f169d7f62e47db7bb2f082554f2ba2472fa8b6fdb075174912be6099"

    static func data(_ hex: String) -> Data {
        Data([UInt8](hex: hex))
    }

    static func ownCredential() throws -> PasskeyCredential {
        try PasskeyCredential(
            credentialID: data(credentialID), relyingPartyID: relyingParty, userHandle: Data("user-1".utf8),
            userName: "pat@example.com", privateKeyPKCS8: data(ownPKCS8),
            createdAt: Date(timeIntervalSince1970: 1_800_000_000), prfSecret: data(prfSecret))
    }
}

@Suite("Passkey authenticator")
struct PasskeyAuthenticatorTests {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)
    static let user = PasskeyUser(handle: Data("user-1".utf8), name: "pat@example.com", displayName: "Pat")

    static func register(
        seed: UInt64 = PasskeyVectors.seed, presence: PersonPresence = .verified, backedUp: Bool = true
    ) throws -> PasskeyRegistration {
        var generator = SeededGenerator(seed: seed)
        return try PasskeyAuthenticator.register(
            relyingParty: try RelyingPartyID(PasskeyVectors.relyingParty), user: user, presence: presence,
            backedUp: backedUp, now: now, using: &generator)
    }

    // MARK: Registration

    @Test("registration matches the independently built credential, authenticator data and attestation object")
    func registrationKnownAnswer() throws {
        let registration = try Self.register()
        let credential = registration.credential
        #expect(credential.credentialID == PasskeyVectors.data(PasskeyVectors.credentialID))
        #expect(credential.prfSecret == PasskeyVectors.data(PasskeyVectors.prfSecret))
        #expect(credential.relyingPartyID == "example.com")
        #expect(credential.userHandle == Self.user.handle)
        #expect(credential.userName == "pat@example.com")
        #expect(credential.userDisplayName == "Pat")
        #expect(credential.createdAt == Self.now)
        #expect(credential.largeBlob == nil)

        let key = try P256.Signing.PrivateKey(derRepresentation: credential.privateKeyPKCS8)
        #expect(key.publicKey.x963Representation == PasskeyVectors.data(PasskeyVectors.publicKeyX963))
        #expect(registration.authenticatorData == PasskeyVectors.data(PasskeyVectors.registrationAuthenticatorData))
        #expect(registration.attestationObject == PasskeyVectors.data(PasskeyVectors.attestationObject))
    }

    /// The stored form is PKCS#8 (`PasskeyCredential.privateKeyPKCS8`), which is what the Credential Exchange Format
    /// carries. The prefix is that of the key `cryptography` serialised as PKCS#8: version 0, then the algorithm
    /// identifier `id-ecPublicKey` with the curve `prime256v1`.
    @Test("a new credential's private key is stored as PKCS#8")
    func privateKeyEncoding() throws {
        let key = [UInt8](try Self.register().credential.privateKeyPKCS8)
        let prefix = [UInt8](hex: "308187020100301306072a8648ce3d020106082a8648ce3d030107")
        #expect(Array(key.prefix(prefix.count)) == prefix)
        #expect(Array([UInt8](hex: PasskeyVectors.ownPKCS8).prefix(prefix.count)) == prefix)
        #expect(key.count == 138)
    }

    @Test("the COSE key is the canonical ES256 encoding of the public point")
    func coseKey() {
        let encoded = WebAuthnEncoding.coseES256Key(x963: PasskeyVectors.data(PasskeyVectors.publicKeyX963))
        #expect(encoded == [UInt8](hex: PasskeyVectors.coseKey))
        #expect(encoded.count == 77)
    }

    @Test("a new credential survives its field and still signs")
    func fieldRoundTrip() throws {
        let registration = try Self.register()
        let field = try Field.passkey(registration.credential)
        let restored = try field.passkeyCredential()
        #expect(restored == registration.credential)
        let assertion = try PasskeyAuthenticator.assertion(
            with: restored, for: try RelyingPartyID("example.com"),
            clientDataHash: PasskeyVectors.data(PasskeyVectors.clientDataHash), presence: .verified, backedUp: true)
        let publicKey = try P256.Signing.PublicKey(
            x963Representation: PasskeyVectors.data(PasskeyVectors.publicKeyX963))
        #expect(
            publicKey.isValidSignature(
                try P256.Signing.ECDSASignature(derRepresentation: assertion.signature),
                for: assertion.authenticatorData + assertion.clientDataHash))
    }

    @Test(
        "registration flags say who took part and whether the credential is backed up",
        arguments: zip(
            [PersonPresence.verified, .present, .absent, .verified],
            [true, true, true, false]))
    func registrationFlags(_ presence: PersonPresence, _ backedUp: Bool) throws {
        let flags = AuthenticatorFlags(
            rawValue: try Self.register(presence: presence, backedUp: backedUp).authenticatorData[32])
        #expect(flags.contains(.attestedCredentialData))
        #expect(flags.contains(.backupEligible))
        #expect(!flags.contains(.extensionData))
        #expect(flags.contains(.backedUp) == backedUp)
        #expect(flags.contains(.userPresent) == (presence != .absent))
        #expect(flags.contains(.userVerified) == (presence == .verified))
    }

    @Test("different seeds give different keys, credential IDs and prf secrets")
    func distinctCredentials() throws {
        let first = try Self.register(seed: 1).credential
        let second = try Self.register(seed: 2).credential
        #expect(first.credentialID != second.credentialID)
        #expect(first.privateKeyPKCS8 != second.privateKeyPKCS8)
        #expect(first.prfSecret != second.prfSecret)
        #expect(first.prfSecret?.count == 32)
        #expect(first.credentialID.count == 32)
    }

    @Test("a user handle outside WebAuthn's bounds is refused", arguments: [0, 65])
    func userHandleBounds(_ length: Int) throws {
        var generator = SeededGenerator(seed: 1)
        #expect(throws: PasskeyError.invalidUser("userHandle")) {
            try PasskeyAuthenticator.register(
                relyingParty: try RelyingPartyID("example.com"),
                user: PasskeyUser(handle: Data(repeating: 1, count: length), name: "pat"), presence: .verified,
                backedUp: true, now: Self.now, using: &generator)
        }
    }

    // MARK: Assertion

    @Test(
        "assertion authenticator data is the hash, truthful flags and a zero counter",
        arguments: [(PersonPresence.verified, true, "1d"), (.present, true, "19"), (.verified, false, "0d")])
    func assertionAuthenticatorData(_ presence: PersonPresence, _ backedUp: Bool, _ flags: String) throws {
        let assertion = try PasskeyAuthenticator.assertion(
            with: try PasskeyVectors.ownCredential(), for: try RelyingPartyID("example.com"),
            clientDataHash: PasskeyVectors.data(PasskeyVectors.clientDataHash), presence: presence, backedUp: backedUp)
        #expect(assertion.authenticatorData == PasskeyVectors.data(PasskeyVectors.rpIDHash + flags + "00000000"))
        #expect(assertion.authenticatorData.count == 37)
        #expect(assertion.userHandle == Data("user-1".utf8))
        #expect(assertion.credentialID == PasskeyVectors.data(PasskeyVectors.credentialID))
        #expect(assertion.relyingPartyID == "example.com")
    }

    @Test("a signature made with a key from another implementation verifies under that key's public point")
    func signsWithForeignKey() throws {
        let assertion = try PasskeyAuthenticator.assertion(
            with: try PasskeyVectors.ownCredential(), for: try RelyingPartyID("example.com"),
            clientDataHash: PasskeyVectors.data(PasskeyVectors.clientDataHash), presence: .verified, backedUp: true)
        let publicKey = try P256.Signing.PublicKey(
            x963Representation: PasskeyVectors.data(PasskeyVectors.ownPublicKeyX963))
        let signature = try P256.Signing.ECDSASignature(derRepresentation: assertion.signature)
        let signed = PasskeyVectors.data(PasskeyVectors.rpIDHash + "1d00000000" + PasskeyVectors.clientDataHash)
        #expect(publicKey.isValidSignature(signature, for: signed))
        // DER: a SEQUENCE of two INTEGERs, at most 72 bytes.
        #expect(assertion.signature.first == 0x30)
        #expect(assertion.signature.count <= 72)
        // And not over anything else.
        #expect(!publicKey.isValidSignature(signature, for: signed + [0]))
    }

    @Test("the recorded signature, which Python verified, still verifies")
    func recordedSignature() throws {
        let publicKey = try P256.Signing.PublicKey(
            x963Representation: PasskeyVectors.data(PasskeyVectors.ownPublicKeyX963))
        let signature = try P256.Signing.ECDSASignature(
            derRepresentation: PasskeyVectors.data(PasskeyVectors.recordedSignature))
        #expect(
            publicKey.isValidSignature(
                signature,
                for: PasskeyVectors.data(PasskeyVectors.rpIDHash + "1d00000000" + PasskeyVectors.clientDataHash)))
    }

    @Test("a credential signs for its own relying party and no other")
    func relyingPartyBinding() throws {
        let credential = try PasskeyVectors.ownCredential()
        for other in ["example.org", "www.example.com", "evil-example.com", "example.com.evil.example"] {
            #expect(throws: PasskeyError.relyingPartyMismatch) {
                try PasskeyAuthenticator.assertion(
                    with: credential, for: try RelyingPartyID(other),
                    clientDataHash: PasskeyVectors.data(PasskeyVectors.clientDataHash), presence: .verified,
                    backedUp: true)
            }
        }
    }

    @Test("an assertion nobody was present for is refused")
    func presenceRequired() throws {
        #expect(throws: PasskeyError.userPresenceRequired) {
            try PasskeyAuthenticator.assertion(
                with: try PasskeyVectors.ownCredential(), for: try RelyingPartyID("example.com"),
                clientDataHash: PasskeyVectors.data(PasskeyVectors.clientDataHash), presence: .absent, backedUp: true)
        }
    }

    @Test("a client data hash that is not 32 bytes is refused", arguments: [0, 31, 33, 64])
    func clientDataHashLength(_ length: Int) throws {
        #expect(throws: PasskeyError.clientDataHashLength(length)) {
            try PasskeyAuthenticator.assertion(
                with: try PasskeyVectors.ownCredential(), for: try RelyingPartyID("example.com"),
                clientDataHash: Data(repeating: 7, count: length), presence: .verified, backedUp: true)
        }
    }

    @Test("a stored key that is not a P-256 private key is refused, not used")
    func unusableKey() throws {
        var credential = try PasskeyVectors.ownCredential()
        for bytes in [Data([0x30, 0x00]), Data(repeating: 0xFF, count: 138), Data("not a key".utf8)] {
            credential.privateKeyPKCS8 = bytes
            #expect(throws: PasskeyError.unusablePrivateKey) {
                try PasskeyAuthenticator.assertion(
                    with: credential, for: try RelyingPartyID("example.com"),
                    clientDataHash: PasskeyVectors.data(PasskeyVectors.clientDataHash), presence: .verified,
                    backedUp: true)
            }
        }
    }

    // MARK: prf

    @Test("prf outputs match HMAC-SHA-256 over the prefixed hash of each input")
    func prfKnownAnswer() throws {
        let outputs = try PasskeyPRF.evaluate(
            secret: PasskeyVectors.data(PasskeyVectors.prfSecret),
            inputs: PRFInputValues(first: Data("first salt".utf8), second: Data("second salt".utf8)))
        #expect(outputs.first == PasskeyVectors.data(PasskeyVectors.prfFirst))
        #expect(outputs.second == PasskeyVectors.data(PasskeyVectors.prfSecond))

        let fixed = try PasskeyPRF.evaluate(
            secret: Data(0..<32), inputs: PRFInputValues(first: Data(repeating: 0, count: 32)))
        #expect(fixed.first == PasskeyVectors.data(PasskeyVectors.prfFixed))
        #expect(fixed.second == nil)
    }

    @Test("prf is stable for one credential and input, and differs across either")
    func prfSeparation() throws {
        let secret = PasskeyVectors.data(PasskeyVectors.prfSecret)
        let a = try PasskeyPRF.evaluate(secret: secret, inputs: PRFInputValues(first: Data("a".utf8)))
        #expect(try PasskeyPRF.evaluate(secret: secret, inputs: PRFInputValues(first: Data("a".utf8))) == a)
        #expect(try PasskeyPRF.evaluate(secret: secret, inputs: PRFInputValues(first: Data("b".utf8))) != a)
        #expect(try PasskeyPRF.evaluate(secret: Data(0..<32), inputs: PRFInputValues(first: Data("a".utf8))) != a)
        #expect(a.first.count == 32)
    }

    @Test("prf refuses an over-long input and a secret of the wrong length")
    func prfBounds() {
        let secret = PasskeyVectors.data(PasskeyVectors.prfSecret)
        #expect(throws: PasskeyError.prfInputTooLong) {
            try PasskeyPRF.evaluate(
                secret: secret, inputs: PRFInputValues(first: Data(count: PasskeyPRF.maximumInputLength + 1)))
        }
        #expect(throws: PasskeyError.prfInputTooLong) {
            try PasskeyPRF.evaluate(
                secret: secret,
                inputs: PRFInputValues(first: Data(), second: Data(count: PasskeyPRF.maximumInputLength + 1)))
        }
        #expect(throws: PasskeyError.malformedCredential(.invalid("prfSecret"))) {
            try PasskeyPRF.evaluate(secret: Data(count: 16), inputs: PRFInputValues(first: Data()))
        }
    }

    // MARK: Relying party IDs

    @Test(
        "ordinary relying party IDs are accepted",
        arguments: [
            "example.com", "accounts.google.com", "firstbank.co.uk", "xn--bcher-kva.example", "tenant.github.io",
        ])
    func relyingPartyAccepted(_ value: String) throws {
        let relyingParty = try RelyingPartyID(value)
        #expect(relyingParty.value == value)
        #expect(relyingParty.hash == Data(SHA256.hash(data: Data(value.utf8))))
        let normalized = try HostNormalizer.normalize(ServiceIdentifier(value, kind: .domain))
        #expect(relyingParty.host == normalized)
        #expect(relyingParty.scope.host == normalized.value)
        #expect(relyingParty.scope.includeSubdomains)
        // The scope a new passkey item gets must match the requests for its own relying party, A-labels or not.
        #expect(ScopeMatcher.match(relyingParty.scope, host: normalized)?.isExact == true)
    }

    @Test(
        "a relying party ID that is not one canonical registrable hostname is refused",
        arguments: [
            "", "com", "co.uk", "github.io", "localhost", "Example.com", "example.com.", " example.com",
            "https://example.com", "example.com/path", "example.com:443", "user@example.com", "127.0.0.1", "::1",
            "[::1]", "b\u{00FC}cher.example", "\u{0430}mazon.com", "exa mple.com", "example..com", "example.com%2e",
        ])
    func relyingPartyRefused(_ value: String) {
        #expect(throws: RelyingPartyIDError.self) { try RelyingPartyID(value) }
    }

    // MARK: Encoding

    @Test("CBOR heads use the shortest form")
    func cborHeads() {
        func encoded(_ body: (inout CBORWriter) -> Void) -> [UInt8] {
            var writer = CBORWriter()
            body(&writer)
            return writer.bytes
        }
        #expect(encoded { $0.unsigned(0) } == [0x00])
        #expect(encoded { $0.unsigned(23) } == [0x17])
        #expect(encoded { $0.unsigned(24) } == [0x18, 0x18])
        #expect(encoded { $0.unsigned(256) } == [0x19, 0x01, 0x00])
        #expect(encoded { $0.unsigned(65536) } == [0x1A, 0x00, 0x01, 0x00, 0x00])
        #expect(encoded { $0.negative(0) } == [0x20])
        #expect(encoded { $0.negative(6) } == [0x26])
        #expect(encoded { $0.text("fmt") } == [0x63, 0x66, 0x6D, 0x74])
        #expect(encoded { $0.byteString([1, 2]) } == [0x42, 0x01, 0x02])
        #expect(encoded { $0.byteString([UInt8](repeating: 0, count: 300)) }.prefix(3) == [0x59, 0x01, 0x2C])
        #expect(encoded { $0.mapHeader(count: 3) } == [0xA3])
    }

    /// A relying party at a shared-hosting suffix (Z63): a passkey for `wordpress.com` is WordPress's own, and is
    /// stored for that host alone, so a tenant's subdomain is never the relying party's.
    @Test("a relying party at a shared-hosting suffix is accepted, with a scope for its host alone")
    func sharedHostingRelyingParty() throws {
        let relyingParty = try RelyingPartyID("wordpress.com")
        #expect(relyingParty.scope == ServiceScope(host: "wordpress.com", includeSubdomains: false))
        #expect(try RelyingPartyID("example.com").scope.includeSubdomains)
        #expect(throws: RelyingPartyIDError.self) { try RelyingPartyID("co.uk") }
        #expect(throws: RelyingPartyIDError.self) { try RelyingPartyID("github.io") }
    }

}
