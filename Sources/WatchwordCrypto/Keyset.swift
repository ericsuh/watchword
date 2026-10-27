#if canImport(CryptoKit) || os(Linux)
    #if canImport(CryptoKit)
        import CryptoKit
    #else
        import Crypto
    #endif
    import Foundation
    import SecureMemory
    import WatchwordEnvelope

    /// The account's long-term keys, wrapped by the Account Unlock Key (docs/02-architecture.md §4).
    ///
    /// - `symmetricKey` (Ksym) wraps vault keys this account owns.
    /// - The X25519 key receives HPKE-wrapped vault keys from other members.
    /// - The Ed25519 key signs membership records, log segments, key grants and the public key bundle.
    ///
    /// The private keys are held as 32-byte seeds in `SecureBytes`; CryptoKit key objects are rebuilt for each operation,
    /// so `zeroise()` on lock destroys every copy this module owns.
    ///
    /// Wrapped form: an `.accountHeader` envelope under AUK whose plaintext is
    /// `version(1) ‖ KsymKeyID(16) ‖ Ksym(32) ‖ X25519 seed(32) ‖ Ed25519 seed(32)`, bound to the account ID.
    public struct Keyset: Sendable {
        public static let formatVersion: UInt8 = 1
        public static let schemaVersion: UInt64 = 1
        static let serializedLength = 1 + 16 + 32 + 32 + 32
        /// Generous upper bound on a wrapped keyset envelope, enforced before parsing (SEC9).
        static let maximumWrappedLength = 1024

        public let accountID: UUID
        public let symmetricKey: EncryptionKey
        let agreementSeed: SecureBytes
        let signingSeed: SecureBytes

        init(accountID: UUID, symmetricKey: EncryptionKey, agreementSeed: SecureBytes, signingSeed: SecureBytes) {
            self.accountID = accountID
            self.symmetricKey = symmetricKey
            self.agreementSeed = agreementSeed
            self.signingSeed = signingSeed
        }

        public static func generate<R: RandomNumberGenerator>(accountID: UUID, using generator: inout R) -> Keyset {
            Keyset(
                accountID: accountID,
                symmetricKey: .generate(using: &generator),
                agreementSeed: SecureBytes(randomCount: 32, using: &generator),
                signingSeed: SecureBytes(randomCount: 32, using: &generator)
            )
        }

        public static func generate(accountID: UUID) -> Keyset {
            var generator = SystemRandomNumberGenerator()
            return generate(accountID: accountID, using: &generator)
        }

        func agreementPrivateKey() throws -> Curve25519.KeyAgreement.PrivateKey {
            try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: agreementSeed)
        }

        func signingPrivateKey() throws -> Curve25519.Signing.PrivateKey {
            try Curve25519.Signing.PrivateKey(rawRepresentation: signingSeed)
        }

        /// The public half, self-signed, for publishing in the account record.
        public func publicKeyBundle() throws -> PublicKeyBundle {
            let agreementKey = Array(try agreementPrivateKey().publicKey.rawRepresentation)
            let signingKey = Array(try signingPrivateKey().publicKey.rawRepresentation)
            let content = PublicKeyBundle.signedContent(
                accountID: accountID, agreementKey: agreementKey, signingKey: signingKey)
            return try PublicKeyBundle(
                accountID: accountID,
                agreementKey: agreementKey,
                signingKey: signingKey,
                selfSignature: sign(content, domain: .publicKeyBundle)
            )
        }

        public func sign(_ message: [UInt8], domain: SignatureDomain) throws -> [UInt8] {
            Array(try signingPrivateKey().signature(for: Signatures.signedBytes(domain: domain, message: message)))
        }

        public func zeroise() {
            symmetricKey.zeroise()
            agreementSeed.zeroise()
            signingSeed.zeroise()
        }

        public var isZeroised: Bool {
            symmetricKey.isZeroised && agreementSeed.isZeroised && signingSeed.isZeroised
        }

        // MARK: - Wrapping under the Account Unlock Key

        public static func wrapContext(accountID: UUID, unlockKeyID: UUID, recordVersion: UInt64 = 0) -> EnvelopeContext
        {
            EnvelopeContext(
                recordID: accountID,
                vaultID: accountID,
                schemaVersion: schemaVersion,
                kind: .accountHeader,
                keyID: unlockKeyID,
                recordVersion: recordVersion
            )
        }

        public func wrap<R: RandomNumberGenerator>(
            with unlockKey: EncryptionKey,
            recordVersion: UInt64 = 0,
            using generator: inout R
        ) throws -> [UInt8] {
            let plaintext = SecureBytes.concatenating([
                SecureBytes(copying: [Keyset.formatVersion] + symmetricKey.keyID.byteArray),
                symmetricKey.material,
                agreementSeed,
                signingSeed,
            ])
            defer { plaintext.zeroise() }
            return try RecordCipher.seal(
                plaintext,
                context: Keyset.wrapContext(
                    accountID: accountID, unlockKeyID: unlockKey.keyID, recordVersion: recordVersion),
                key: unlockKey,
                using: &generator
            )
        }

        public func wrap(with unlockKey: EncryptionKey, recordVersion: UInt64 = 0) throws -> [UInt8] {
            var generator = SystemRandomNumberGenerator()
            return try wrap(with: unlockKey, recordVersion: recordVersion, using: &generator)
        }

        /// Unwraps a keyset. A wrong password or Secret Key surfaces as `CryptoError.authenticationFailed`, never as
        /// anything more specific.
        public static func unwrap(
            _ envelope: [UInt8],
            accountID: UUID,
            with unlockKey: EncryptionKey,
            recordVersion: UInt64 = 0
        ) throws -> Keyset {
            let plaintext = try RecordCipher.open(
                envelope,
                context: wrapContext(accountID: accountID, unlockKeyID: unlockKey.keyID, recordVersion: recordVersion),
                key: unlockKey,
                maximumLength: maximumWrappedLength
            )
            defer { plaintext.zeroise() }
            guard plaintext.count == serializedLength else { throw CryptoError.malformedKeyset }
            guard plaintext[0] == formatVersion else { throw CryptoError.unsupportedKeysetVersion(plaintext[0]) }
            let symmetricKeyID = UUID(byteArray: Array(plaintext[1..<17]))
            return Keyset(
                accountID: accountID,
                symmetricKey: try EncryptionKey(keyID: symmetricKeyID, material: plaintext.extracting(17..<49)),
                agreementSeed: plaintext.extracting(49..<81),
                signingSeed: plaintext.extracting(81..<113)
            )
        }
    }

    /// An account's published public keys with a self-signature (docs/02-architecture.md §4).
    ///
    /// Constructing one validates it: lengths, that the X25519 key is not a low-order point (whose shared secret with
    /// anyone is all zeros, so a vault key "wrapped" to it would be readable by whoever substituted it), that the Ed25519
    /// key is not of small order (for which one signature verifies for every message), and the self-signature. A
    /// `PublicKeyBundle` value has therefore passed all four. The self-signature proves possession of
    /// the signing key, not identity; identity is the out-of-band `fingerprint` comparison (F4.2).
    public struct PublicKeyBundle: Sendable, Hashable {
        public let accountID: UUID
        public let agreementKey: [UInt8]
        public let signingKey: [UInt8]
        public let selfSignature: [UInt8]

        public init(accountID: UUID, agreementKey: [UInt8], signingKey: [UInt8], selfSignature: [UInt8]) throws {
            try PublicKeyBundle.validateAgreementKey(agreementKey)
            let content = PublicKeyBundle.signedContent(
                accountID: accountID, agreementKey: agreementKey, signingKey: signingKey)
            try Signatures.verify(selfSignature, for: content, domain: .publicKeyBundle, signingKey: signingKey)
            self.accountID = accountID
            self.agreementKey = agreementKey
            self.signingKey = signingKey
            self.selfSignature = selfSignature
        }

        public var fingerprint: Fingerprint {
            Fingerprint(accountID: accountID, agreementKey: agreementKey, signingKey: signingKey)
        }

        /// Canonical CBOR `{1: accountID, 2: agreementKey, 3: signingKey}`.
        static func signedContent(accountID: UUID, agreementKey: [UInt8], signingKey: [UInt8]) -> [UInt8] {
            CBORValue.map([1: .uuid(accountID), 2: .bytes(agreementKey), 3: .bytes(signingKey)]).encoded()
        }

        /// Rejects anything that is not a usable X25519 public key. A clamped scalar is a multiple of the cofactor, so a
        /// probe agreement with any low-order point yields the all-zero secret (RFC 7748 §6.1, RFC 9180 §7.1.4).
        static func validateAgreementKey(_ raw: [UInt8]) throws {
            guard raw.count == 32, let publicKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: raw) else {
                throw CryptoError.invalidPublicKey
            }
            let probe = Curve25519.KeyAgreement.PrivateKey()
            guard let shared = try? probe.sharedSecretFromKeyAgreement(with: publicKey),
                !(shared == [UInt8](repeating: 0, count: 32))
            else {
                throw CryptoError.invalidPublicKey
            }
        }
    }
#endif
