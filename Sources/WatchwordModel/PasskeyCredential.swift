import Foundation

public enum PasskeyCodingError: Error, Equatable, Sendable {
    case notAPasskeyField
    case tooLong
    case malformed
    /// A value outside its bounds, named so a test (and an import report) can say which.
    case invalid(String)
}

/// A passkey as stored in a `.passkey` field's `value` (PRD F1.2, docs/02-architecture.md §9): a WebAuthn
/// discoverable credential whose private key lives in the item, inside the item's ciphertext.
///
/// The field value is JSON with sorted keys; binary values are base64url without padding. The private key is PKCS#8
/// DER, which is what the Credential Exchange Format carries and what `P256.Signing.PrivateKey(derRepresentation:)`
/// reads, so this module needs no cryptography: `WatchwordAutoFill` signs with it, `WatchwordInterchange` moves it.
///
/// The value may have been written by another member of a shared vault or by an import file, so decoding is bounded
/// (SEC9) and every length is checked: nothing here is trusted because it decrypted.
public struct PasskeyCredential: Hashable, Sendable {
    public static let maximumFieldLength = 64 * 1024
    /// WebAuthn limits: credential IDs are at most 1023 bytes, user handles at most 64.
    public static let credentialIDLengthRange = 16...1023
    public static let userHandleLengthRange = 1...64
    public static let maximumRelyingPartyIDLength = 253
    public static let maximumNameLength = 1024
    public static let maximumPrivateKeyLength = 512
    public static let prfSecretLength = 32
    public static let maximumLargeBlobLength = 16 * 1024

    public var credentialID: Data
    /// The relying party ID the credential is bound to, lower-case (`google.com`). An assertion is only ever made for
    /// this ID.
    public var relyingPartyID: String
    public var userHandle: Data
    public var userName: String
    public var userDisplayName: String
    /// The ES256 (P-256) private key, PKCS#8 DER. Not validated as a key here; the signer does that.
    public var privateKeyPKCS8: Data
    public var createdAt: Date
    /// The credential's secret for the WebAuthn `prf` extension (CTAP `hmac-secret`), when the credential was created
    /// with it. Random, per credential, never derived from the private key.
    public var prfSecret: Data?
    /// The credential's `largeBlob`, if the relying party stored one.
    public var largeBlob: Data?

    public init(
        credentialID: Data, relyingPartyID: String, userHandle: Data, userName: String, userDisplayName: String = "",
        privateKeyPKCS8: Data, createdAt: Date, prfSecret: Data? = nil, largeBlob: Data? = nil
    ) throws {
        self.credentialID = credentialID
        self.relyingPartyID = relyingPartyID.lowercased()
        self.userHandle = userHandle
        self.userName = userName
        self.userDisplayName = userDisplayName
        self.privateKeyPKCS8 = privateKeyPKCS8
        // Whole seconds, so a credential equals itself after a round trip through its field.
        self.createdAt = Date(timeIntervalSince1970: createdAt.timeIntervalSince1970.rounded(.down))
        self.prfSecret = prfSecret
        self.largeBlob = largeBlob
        try validate()
    }

    private func validate() throws {
        guard PasskeyCredential.credentialIDLengthRange.contains(credentialID.count) else {
            throw PasskeyCodingError.invalid("credentialID")
        }
        guard !relyingPartyID.isEmpty, relyingPartyID.utf8.count <= PasskeyCredential.maximumRelyingPartyIDLength
        else { throw PasskeyCodingError.invalid("relyingPartyID") }
        guard PasskeyCredential.userHandleLengthRange.contains(userHandle.count) else {
            throw PasskeyCodingError.invalid("userHandle")
        }
        guard userName.utf8.count <= PasskeyCredential.maximumNameLength else {
            throw PasskeyCodingError.invalid("userName")
        }
        guard userDisplayName.utf8.count <= PasskeyCredential.maximumNameLength else {
            throw PasskeyCodingError.invalid("userDisplayName")
        }
        guard !privateKeyPKCS8.isEmpty, privateKeyPKCS8.count <= PasskeyCredential.maximumPrivateKeyLength else {
            throw PasskeyCodingError.invalid("privateKey")
        }
        guard createdAt.timeIntervalSince1970.isFinite, abs(createdAt.timeIntervalSince1970) < 1e11 else {
            throw PasskeyCodingError.invalid("createdAt")
        }
        if let prfSecret, prfSecret.count != PasskeyCredential.prfSecretLength {
            throw PasskeyCodingError.invalid("prfSecret")
        }
        if let largeBlob, largeBlob.count > PasskeyCredential.maximumLargeBlobLength {
            throw PasskeyCodingError.invalid("largeBlob")
        }
    }

    /// What is stored: text only, so the binary values have exactly one spelling.
    private struct Stored: Codable {
        var createdAt: Int64
        var credentialID: String
        var largeBlob: String?
        var prfSecret: String?
        var privateKey: String
        var rpID: String
        var userDisplayName: String
        var userHandle: String
        var userName: String
    }

    /// The value of a `.passkey` field.
    public func fieldValue() throws -> String {
        let stored = Stored(
            createdAt: Int64(createdAt.timeIntervalSince1970),
            credentialID: Base64URL.encode(credentialID),
            largeBlob: largeBlob.map { Base64URL.encode($0) },
            prfSecret: prfSecret.map { Base64URL.encode($0) },
            privateKey: Base64URL.encode(privateKeyPKCS8),
            rpID: relyingPartyID,
            userDisplayName: userDisplayName,
            userHandle: Base64URL.encode(userHandle),
            userName: userName)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let text = String(decoding: try encoder.encode(stored), as: UTF8.self)
        guard text.utf8.count <= PasskeyCredential.maximumFieldLength else { throw PasskeyCodingError.tooLong }
        return text
    }

    public init(fieldValue: String) throws {
        guard fieldValue.utf8.count <= PasskeyCredential.maximumFieldLength else { throw PasskeyCodingError.tooLong }
        let stored: Stored
        do {
            stored = try JSONDecoder().decode(Stored.self, from: Data(fieldValue.utf8))
        } catch {
            throw PasskeyCodingError.malformed
        }
        func binary(_ text: String, _ name: String) throws -> Data {
            guard let data = Base64URL.decode(text) else { throw PasskeyCodingError.invalid(name) }
            return data
        }
        // The stored ID is compared as written: a mixed-case one is refused, not folded into a different party's.
        guard stored.rpID == stored.rpID.lowercased() else { throw PasskeyCodingError.invalid("relyingPartyID") }
        try self.init(
            credentialID: binary(stored.credentialID, "credentialID"),
            relyingPartyID: stored.rpID,
            userHandle: binary(stored.userHandle, "userHandle"),
            userName: stored.userName,
            userDisplayName: stored.userDisplayName,
            privateKeyPKCS8: binary(stored.privateKey, "privateKey"),
            createdAt: Date(timeIntervalSince1970: TimeInterval(stored.createdAt)),
            prfSecret: stored.prfSecret.map { try binary($0, "prfSecret") },
            largeBlob: stored.largeBlob.map { try binary($0, "largeBlob") })
    }
}

extension Field {
    /// A `.passkey` field holding `credential`.
    public static func passkey(_ credential: PasskeyCredential, id: UUID = UUID(), label: String = "Passkey") throws
        -> Field
    {
        Field(id: id, kind: .passkey, label: label, value: try credential.fieldValue())
    }

    /// The credential in a `.passkey` field. Throws for any other kind and for a value that does not decode.
    public func passkeyCredential() throws -> PasskeyCredential {
        guard kind == .passkey else { throw PasskeyCodingError.notAPasskeyField }
        return try PasskeyCredential(fieldValue: value)
    }
}
