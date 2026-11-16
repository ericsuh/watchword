import Crypto
import Foundation
import SecureMemory
import WatchwordModel

public enum PasskeyError: Error, Equatable, Sendable {
    /// The request names a relying party other than the one the credential is bound to.
    case relyingPartyMismatch
    case relyingPartyRejected(RelyingPartyIDError)
    /// The client data hash is not a SHA-256 digest.
    case clientDataHashLength(Int)
    /// The relying party accepts no algorithm this authenticator has (ES256 only).
    case noSupportedAlgorithm
    /// The stored private key is not a usable P-256 key.
    case unusablePrivateKey
    /// An assertion always needs the person to have taken part.
    case userPresenceRequired
    /// The relying party requires verification and the person was not verified for this request.
    case userVerificationRequired
    /// A user handle or name outside WebAuthn's bounds, named.
    case invalidUser(String)
    /// The generator did not produce a usable key or credential ID.
    case keyGenerationFailed
    /// The new credential's ID is already in the vault: the random source is repeating itself.
    case credentialIDCollision
    /// The vault already holds a credential the relying party listed in `excludeCredentials`.
    case credentialExcluded
    /// The item already holds as many passkeys as one item may.
    case tooManyCredentials
    /// More entries in an allow or exclude list, or more bytes in one, than the authenticator will look at.
    case listTooLong
    case prfInputTooLong
    case largeBlobTooLong
    /// The stored `.passkey` field does not decode.
    case malformedCredential(PasskeyCodingError)
}

/// How much the person took part in one request, reported by the extension and written into the flags as it is
/// (WebAuthn UP and UV).
public enum PersonPresence: Hashable, Sendable {
    /// Nobody was asked anything: a conditional (automatic) passkey registration.
    case absent
    /// The person acted (chose the credential in the system's or the extension's UI) but was not verified.
    case present
    /// The person was verified for this request: they unlocked the vault with the password or biometry.
    case verified

    var flags: AuthenticatorFlags {
        switch self {
        case .absent: return []
        case .present: return [.userPresent]
        case .verified: return [.userPresent, .userVerified]
        }
    }
}

/// The account a passkey is created for, as the relying party describes it.
public struct PasskeyUser: Hashable, Sendable {
    public var handle: Data
    public var name: String
    public var displayName: String

    public init(handle: Data, name: String, displayName: String = "") {
        self.handle = handle
        self.name = name
        self.displayName = displayName
    }
}

/// A new credential and the bytes the relying party is sent for it.
public struct PasskeyRegistration: Hashable, Sendable {
    /// What goes into the item's `.passkey` field.
    public let credential: PasskeyCredential
    public let authenticatorData: Data
    /// CBOR, attestation format `none`.
    public let attestationObject: Data
}

/// One signed assertion.
public struct PasskeyAssertion: Hashable, Sendable {
    public let relyingPartyID: String
    public let credentialID: Data
    public let userHandle: Data
    public let authenticatorData: Data
    /// ECDSA P-256 with SHA-256 over `authenticatorData ‖ clientDataHash`, ASN.1 DER.
    public let signature: Data
    public let clientDataHash: Data
}

/// A software WebAuthn authenticator for synced passkeys (PRD F6.2; docs/02-architecture.md §9.1).
///
/// Pure functions over a `PasskeyCredential`: no vault, no clock, no global state. Who may call them, and for which
/// item, is `CredentialProviderModel`'s business; what they refuse on their own is a relying party other than the
/// credential's, an assertion nobody was present for, and malformed inputs.
public enum PasskeyAuthenticator {
    /// COSE algorithm identifier for ECDSA P-256 with SHA-256, the one algorithm implemented.
    public static let es256: Int = -7

    /// Identifies Watchword as the authenticator model in attested credential data, so a relying party can label
    /// which provider holds a passkey. The same for every installation: not a secret, not per user, and it says
    /// nothing about the person. With "none" attestation the platform may replace it with zeros. Not registered in
    /// the community list of authenticator AAGUIDs as of 2026-11-16 (README.md, "Passkey AAGUID").
    public static let aaguid = UUID(uuidString: "5B0C7A3E-9D41-4F6C-A2B8-3E1F7C0D9A54")!

    static var aaguidBytes: [UInt8] {
        let u = aaguid.uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }

    public static let credentialIDLength = 32
    public static let clientDataHashLength = 32

    /// Creates a credential: a P-256 key, a random credential ID and a random `prf` secret, in that order, each drawn
    /// from `generator` as little-endian 64-bit words (`SecureBytes(randomCount:using:)`).
    ///
    /// Every credential gets a `prf` secret whether or not this registration asked for the extension, so a relying
    /// party that starts using `prf` later finds it available; the secret is independent of the private key.
    ///
    /// Flags: BE is always set (a Watchword passkey lives in an item, and items sync), BS only when `backedUp`, UP
    /// and UV as `presence` says. A conditional registration, which nobody is asked about, has neither.
    public static func register(
        relyingParty: RelyingPartyID, user: PasskeyUser, presence: PersonPresence, backedUp: Bool, now: Date,
        using generator: inout some RandomNumberGenerator
    ) throws -> PasskeyRegistration {
        guard PasskeyCredential.userHandleLengthRange.contains(user.handle.count) else {
            throw PasskeyError.invalidUser("userHandle")
        }
        let privateKey = try generateKey(using: &generator)
        let credentialID = Data(SecureBytes(randomCount: credentialIDLength, using: &generator).unprotectedCopy())
        let prfSecret = SecureBytes(randomCount: PasskeyCredential.prfSecretLength, using: &generator)
        defer { prfSecret.zeroise() }
        // An all-zero ID or secret is what a dead generator produces; neither is ever a legitimate draw.
        guard credentialID.contains(where: { $0 != 0 }), prfSecret.contains(where: { $0 != 0 }) else {
            throw PasskeyError.keyGenerationFailed
        }

        let credential: PasskeyCredential
        do {
            credential = try PasskeyCredential(
                credentialID: credentialID, relyingPartyID: relyingParty.value, userHandle: user.handle,
                userName: user.name, userDisplayName: user.displayName, privateKeyPKCS8: privateKey.derRepresentation,
                createdAt: now, prfSecret: Data(prfSecret.unprotectedCopy()))
        } catch let error as PasskeyCodingError {
            if case .invalid(let name) = error { throw PasskeyError.invalidUser(name) }
            throw PasskeyError.malformedCredential(error)
        }

        var flags: AuthenticatorFlags = [.attestedCredentialData, .backupEligible]
        flags.formUnion(presence.flags)
        if backedUp { flags.insert(.backedUp) }
        let authenticatorData = WebAuthnEncoding.authenticatorData(
            relyingParty: relyingParty, flags: flags,
            attested: (credentialID, WebAuthnEncoding.coseES256Key(x963: privateKey.publicKey.x963Representation)))
        return PasskeyRegistration(
            credential: credential, authenticatorData: authenticatorData,
            attestationObject: WebAuthnEncoding.attestationObject(authenticatorData: authenticatorData))
    }

    /// Signs an assertion with `credential`, for `relyingParty` only.
    ///
    /// The relying party is compared with the one stored in the credential, byte for byte, before the key is even
    /// decoded: a credential is never used for a party it was not created for, whatever the caller selected
    /// (docs/05-anti-phishing.md, L1).
    public static func assertion(
        with credential: PasskeyCredential, for relyingParty: RelyingPartyID, clientDataHash: Data,
        presence: PersonPresence, backedUp: Bool
    ) throws -> PasskeyAssertion {
        guard credential.relyingPartyID == relyingParty.value else { throw PasskeyError.relyingPartyMismatch }
        guard clientDataHash.count == clientDataHashLength else {
            throw PasskeyError.clientDataHashLength(clientDataHash.count)
        }
        guard presence != .absent else { throw PasskeyError.userPresenceRequired }
        let privateKey: P256.Signing.PrivateKey
        do {
            privateKey = try P256.Signing.PrivateKey(derRepresentation: credential.privateKeyPKCS8)
        } catch {
            throw PasskeyError.unusablePrivateKey
        }

        var flags: AuthenticatorFlags = [.backupEligible]
        flags.formUnion(presence.flags)
        if backedUp { flags.insert(.backedUp) }
        let authenticatorData = WebAuthnEncoding.authenticatorData(relyingParty: relyingParty, flags: flags)
        let signature: P256.Signing.ECDSASignature
        do {
            signature = try privateKey.signature(for: authenticatorData + clientDataHash)
        } catch {
            throw PasskeyError.unusablePrivateKey
        }
        return PasskeyAssertion(
            relyingPartyID: relyingParty.value, credentialID: credential.credentialID,
            userHandle: credential.userHandle, authenticatorData: authenticatorData,
            signature: signature.derRepresentation, clientDataHash: clientDataHash)
    }

    /// A P-256 private key whose scalar is 32 bytes from `generator`, redrawn in the one-in-2³² case that they are
    /// not below the group order. Bounded, so a generator stuck on an unusable value fails instead of spinning.
    static func generateKey(using generator: inout some RandomNumberGenerator) throws -> P256.Signing.PrivateKey {
        for _ in 0..<8 {
            let scalar = SecureBytes(randomCount: 32, using: &generator)
            defer { scalar.zeroise() }
            if let key = try? P256.Signing.PrivateKey(rawRepresentation: scalar) {
                return key
            }
        }
        throw PasskeyError.keyGenerationFailed
    }
}

/// The two inputs of one `prf` evaluation, as the relying party passed them to `eval` (not yet hashed).
public struct PRFInputValues: Hashable, Sendable {
    public var first: Data
    public var second: Data?

    public init(first: Data, second: Data? = nil) {
        self.first = first
        self.second = second
    }
}

/// The results of one `prf` evaluation: 32 bytes each. Secrets derived from the credential's `prf` secret.
public struct PRFOutputValues: Hashable, Sendable {
    public let first: Data
    public let second: Data?
}

/// The WebAuthn `prf` extension, evaluated as CTAP's `hmac-secret` does (docs/02-architecture.md §9.1).
///
/// `output = HMAC-SHA-256(prfSecret, SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input))`. The prefix hash is WebAuthn's: it keeps
/// a web page from choosing the raw salt, so the same credential's `hmac-secret` outputs for non-web uses stay out of
/// its reach. The secret is the credential's own 32 random bytes, never the signing key.
public enum PasskeyPRF {
    /// A page chooses these inputs; this bounds the hashing it can ask for.
    public static let maximumInputLength = 4096

    static let prefix = Array("WebAuthn PRF".utf8) + [0x00]

    static func salt(for input: Data) -> Data {
        var hasher = SHA256()
        hasher.update(data: prefix)
        hasher.update(data: input)
        return Data(hasher.finalize())
    }

    public static func evaluate(secret: Data, inputs: PRFInputValues) throws -> PRFOutputValues {
        guard secret.count == PasskeyCredential.prfSecretLength else {
            throw PasskeyError.malformedCredential(.invalid("prfSecret"))
        }
        guard inputs.first.count <= maximumInputLength, (inputs.second?.count ?? 0) <= maximumInputLength else {
            throw PasskeyError.prfInputTooLong
        }
        let key = SymmetricKey(data: secret)
        func output(_ input: Data) -> Data {
            Data(HMAC<SHA256>.authenticationCode(for: salt(for: input), using: key))
        }
        return PRFOutputValues(first: output(inputs.first), second: inputs.second.map(output))
    }
}
