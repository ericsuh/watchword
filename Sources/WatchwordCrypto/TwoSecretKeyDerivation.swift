#if canImport(CryptoKit) && canImport(CommonCrypto)
    import CryptoKit
    import Foundation
    import SecureMemory
    import WatchwordEnvelope

    /// Two-secret key derivation: account password + Secret Key → Account Unlock Key (docs/02-architecture.md §4,
    /// ADR 0003).
    ///
    /// ```
    /// salt' = HKDF-SHA256(ikm: saltA, salt: accountID, info: "WW-salt-v1")
    /// Kp    = PBKDF2-HMAC-SHA256(NFKD(password), salt', iterations)          (CommonCrypto)
    /// Ks    = HKDF-SHA256(ikm: SK, salt: accountID, info: "WW-2SKD-v1")
    /// AUK   = HKDF-SHA256(ikm: Kp ‖ Ks, salt: accountID, info: "WW-AUK-v1")
    /// ```
    ///
    /// Combining with HKDF rather than XOR settles review finding D7 (ADR 0003, "Combining"). Neither input alone yields
    /// AUK under either construction; HKDF additionally has no catastrophic failure mode if the inputs are ever equal or
    /// related (XOR of equal inputs is the all-zero key) and binds the account ID once more.
    ///
    /// The password is NFKD-normalised so the same password typed on two keyboards (precomposed vs combining accents,
    /// full-width forms) derives the same key. It is not trimmed: silently changing what someone typed is worse than a
    /// failed unlock they can retry.
    ///
    /// `KDFParameters.validate()` runs first, so a tampered header can neither weaken (floor) nor stall (ceiling) the
    /// derivation (SEC5, SEC9).
    public enum TwoSecretKeyDerivation {
        static let saltInfo = Array("WW-salt-v1".utf8)
        static let secretKeyInfo = Array("WW-2SKD-v1".utf8)
        static let combineInfo = Array("WW-AUK-v1".utf8)

        public static func accountUnlockKey(
            password: String,
            secretKey: SecretKey,
            accountID: UUID,
            parameters: KDFParameters,
            salt: [UInt8],
            keyID: UUID
        ) throws -> EncryptionKey {
            try parameters.validate()
            guard salt.count == parameters.saltLength else {
                throw CryptoError.saltLengthMismatch(expected: parameters.saltLength, actual: salt.count)
            }
            let passwordKey = try self.passwordKey(
                password: password, accountID: accountID, parameters: parameters, salt: salt)
            defer { passwordKey.zeroise() }
            let secretKeyKey = self.secretKeyKey(secretKey: secretKey, accountID: accountID)
            defer { secretKeyKey.zeroise() }
            let combined = SecureBytes.concatenating([passwordKey, secretKeyKey])
            defer { combined.zeroise() }
            let unlockKey = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: combined.symmetricKey,
                salt: accountID.byteArray,
                info: combineInfo,
                outputByteCount: EncryptionKey.byteCount
            )
            return try EncryptionKey(keyID: keyID, material: SecureBytes(copying: unlockKey))
        }

        /// Kp. `parameters` must already be validated.
        static func passwordKey(
            password: String,
            accountID: UUID,
            parameters: KDFParameters,
            salt: [UInt8]
        ) throws -> SecureBytes {
            var utf8 = Array(password.decomposedStringWithCompatibilityMapping.utf8)
            guard !utf8.isEmpty else { throw CryptoError.emptyPassword }
            let passwordBytes = SecureBytes(wiping: &utf8)
            defer { passwordBytes.zeroise() }
            let accountSalt = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: salt),
                salt: accountID.byteArray,
                info: saltInfo,
                outputByteCount: 32
            )
            return try PBKDF2.sha256(
                password: passwordBytes,
                salt: SecureBytes(copying: accountSalt).unprotectedCopy(),
                iterations: parameters.iterations,
                outputByteCount: EncryptionKey.byteCount
            )
        }

        /// Ks.
        static func secretKeyKey(secretKey: SecretKey, accountID: UUID) -> SecureBytes {
            SecureBytes(
                copying: HKDF<SHA256>.deriveKey(
                    inputKeyMaterial: secretKey.bytes.symmetricKey,
                    salt: accountID.byteArray,
                    info: secretKeyInfo,
                    outputByteCount: EncryptionKey.byteCount
                ))
        }
    }
#endif
