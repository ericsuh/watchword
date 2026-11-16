import Crypto
import Foundation
import SecureMemory
import WatchwordEnvelope

/// The account header as a device publishes it on the sync transport (docs/02-architecture.md §7.7, PRD F5.2,
/// F10.2): everything a new device needs, with the account password and the Secret Key, to derive the Account Unlock
/// Key and open the keyset.
///
/// ```
/// magic "WWAH"  formatVersion u8 = 1
/// accountID 16  generation u64  author deviceID 16
/// kdfAlgorithm u8 (1 = PBKDF2-HMAC-SHA256)  iterations u32  saltLength u16  salt
/// unlockKeyID 16  keysetVersion u64
/// credentialID 32  genesisID 32
/// wrappedKeyset (u16 length)          the keyset sealed under the AUK, exactly as the local store holds it
/// binding (u16 length)                sealed under the AUK: SHA-256 of every byte above ‖ personalVaultID 16
/// ── everything above is signed ──
/// accountSignature (u8 length, 64)  deviceSignature (u8 length)
/// ```
///
/// Nothing in it is secret, and all of it is hostile until authenticated (A1 holds the store):
///
/// - **Parsing** bounds every length and validates the KDF parameters on both sides before any derivation, so a
///   header from the store can neither weaken the derivation nor turn it into a hang (SEC5, SEC9).
/// - **A new device** has no key to check signatures with. What authenticates the header to it is the `binding`: an
///   AEAD under the AUK it derives from what the person typed, over a digest of every other field. A header that
///   opens was written by someone who knew the password and the Secret Key; one altered in any field does not open.
///   The binding carries the two things a new device must not take from the store on trust: the registry's genesis
///   entry and credential entry (in the digest), and which vault is the personal one.
/// - **A device that already has the account** cannot open a header made with a password it has not been given. It
///   takes one as a *candidate* only if the account key and a registered device signed it and the registry holds
///   its credential entry, and adopts it only when the person unlocks with the new password (§7.8).
public struct AccountHeaderObject: Sendable, Hashable {
    public static let maximumLength = 8192
    static let maximumWrappedLength = 1024
    static let magic = Array("WWAH".utf8)
    static let formatVersion: UInt8 = 1
    /// The binding's schema version; the keyset wrap under the same key uses 1, so neither opens as the other.
    public static let bindingSchemaVersion: UInt64 = 2

    public var accountID: UUID
    /// The credential generation: 0 at account creation, one more with every password change.
    public var generation: UInt64
    /// The device that wrote this header.
    public var author: UUID
    public var kdf: KDFParameters
    public var salt: [UInt8]
    public var unlockKeyID: UUID
    public var keysetVersion: UInt64
    /// The registry entry that starts this credential generation (the genesis entry for generation 0).
    public var credentialID: ObjectDigest
    /// The registry's genesis entry.
    public var genesisID: ObjectDigest
    public var wrappedKeyset: [UInt8]
    public var binding: [UInt8]
    public var accountSignature: [UInt8]
    public var deviceSignature: [UInt8]

    public init(
        accountID: UUID, generation: UInt64, author: UUID, kdf: KDFParameters, salt: [UInt8], unlockKeyID: UUID,
        keysetVersion: UInt64, credentialID: ObjectDigest, genesisID: ObjectDigest, wrappedKeyset: [UInt8],
        binding: [UInt8] = [], accountSignature: [UInt8] = [], deviceSignature: [UInt8] = []
    ) {
        self.accountID = accountID
        self.generation = generation
        self.author = author
        self.kdf = kdf
        self.salt = salt
        self.unlockKeyID = unlockKeyID
        self.keysetVersion = keysetVersion
        self.credentialID = credentialID
        self.genesisID = genesisID
        self.wrappedKeyset = wrappedKeyset
        self.binding = binding
        self.accountSignature = accountSignature
        self.deviceSignature = deviceSignature
    }

    // MARK: - Encoding

    /// Everything the binding's digest covers.
    var boundPart: [UInt8] {
        var out = Self.magic
        out.append(Self.formatVersion)
        out += accountID.byteArray + AccountBytes.littleEndian(generation) + author.byteArray
        out.append(1)
        out += AccountBytes.littleEndian(kdf.iterations) + AccountBytes.field(salt)
        out += unlockKeyID.byteArray + AccountBytes.littleEndian(keysetVersion)
        out += credentialID.bytes + genesisID.bytes
        out += AccountBytes.field(wrappedKeyset)
        return out
    }

    /// What the account key (`Signatures`) and the author's device key (`DeviceSignatures`) sign, both under
    /// `SignatureDomain.accountHeader`.
    public var signedPart: [UInt8] {
        boundPart + AccountBytes.field(binding)
    }

    public func serialized() -> [UInt8] {
        signedPart + AccountBytes.shortField(accountSignature) + AccountBytes.shortField(deviceSignature)
    }

    /// Parses a header exactly and validates its KDF parameters. Nothing here authenticates it.
    public static func parse(_ bytes: [UInt8]) throws -> AccountHeaderObject {
        guard bytes.count <= maximumLength else { throw AccountFormatError.tooLong(bytes.count) }
        var reader = AccountByteReader(bytes)
        guard try reader.read(4) == magic else { throw AccountFormatError.badMagic }
        let version = try reader.byte()
        guard version == formatVersion else { throw AccountFormatError.unsupportedVersion(version) }
        let accountID = try reader.uuid()
        let generation = try reader.uint64()
        let author = try reader.uuid()
        let algorithm = try reader.byte()
        guard algorithm == 1 else { throw AccountFormatError.unsupportedKDF(algorithm) }
        let iterations = try reader.uint32()
        let salt = try reader.field(maximum: KDFParameters.maximumSaltLength)
        let kdf = KDFParameters(iterations: iterations, saltLength: salt.count)
        do {
            try kdf.validate()
        } catch let error as KDFValidationError {
            throw AccountFormatError.kdf(error)
        }
        let unlockKeyID = try reader.uuid()
        let keysetVersion = try reader.uint64()
        // Cannot fail: the lengths are right by construction.
        let credentialID = ObjectDigest(bytes: try reader.read(ObjectDigest.byteCount))!
        let genesisID = ObjectDigest(bytes: try reader.read(ObjectDigest.byteCount))!
        var header = AccountHeaderObject(
            accountID: accountID, generation: generation, author: author, kdf: kdf, salt: salt,
            unlockKeyID: unlockKeyID, keysetVersion: keysetVersion, credentialID: credentialID, genesisID: genesisID,
            wrappedKeyset: try reader.field(maximum: maximumWrappedLength))
        header.binding = try reader.field(maximum: maximumWrappedLength)
        header.accountSignature = try reader.shortField(maximum: 64)
        header.deviceSignature = try reader.shortField(maximum: 128)
        guard reader.remaining == 0 else { throw AccountFormatError.trailingBytes }
        return header
    }

    // MARK: - The binding

    func bindingContext() -> EnvelopeContext {
        EnvelopeContext(
            recordID: accountID, vaultID: accountID, schemaVersion: Self.bindingSchemaVersion, kind: .accountHeader,
            keyID: unlockKeyID, recordVersion: generation)
    }

    /// Seals the binding under the AUK this header's parameters derive. Call once every other bound field is set.
    public mutating func bind<R: RandomNumberGenerator>(
        personalVaultID: UUID, unlockKey: EncryptionKey, using generator: inout R
    ) throws {
        binding = try RecordCipher.seal(
            AccountBytes.sha256(boundPart) + personalVaultID.byteArray, context: bindingContext(), key: unlockKey,
            using: &generator)
    }

    /// Opens the binding with the AUK derived from what the person typed, and returns the personal vault's ID. Fails
    /// with `CryptoError.authenticationFailed` — the one error a wrong password, a wrong Secret Key and a tampered
    /// header share — unless every bound field is exactly what the writer sealed.
    public func openBinding(with unlockKey: EncryptionKey) throws -> UUID {
        guard unlockKey.keyID == unlockKeyID else { throw CryptoError.authenticationFailed }
        let plaintext: SecureBytes
        do {
            plaintext = try RecordCipher.open(
                binding, context: bindingContext(), key: unlockKey, maximumLength: Self.maximumWrappedLength)
        } catch {
            throw CryptoError.authenticationFailed
        }
        defer { plaintext.zeroise() }
        // Neither half is secret: a digest of public fields and a vault ID.
        let bytes = plaintext.unprotectedCopy()
        guard bytes.count == 32 + 16, Array(bytes[..<32]) == AccountBytes.sha256(boundPart) else {
            throw CryptoError.authenticationFailed
        }
        return UUID(byteArray: Array(bytes[32...]))
    }

    // MARK: - Signatures

    /// Checks both signatures: the account key's, and the author device's under the key the registry gives for it.
    public func verifySignatures(accountSigningKey: [UInt8], deviceKey: DevicePublicKey) throws {
        try Signatures.verify(
            accountSignature, for: signedPart, domain: .accountHeader, signingKey: accountSigningKey)
        try DeviceSignatures.verify(
            deviceSignature, for: signedPart, domain: .accountHeader, deviceID: author, key: deviceKey)
    }
}
