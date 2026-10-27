// The one platform conditional left in the cryptographic core (ADR 0006). CryptoKit has no PBKDF2, and swift-crypto's
// (`CryptoExtras`) compiles BoringSSL into every build that links it, so Apple builds call CommonCrypto here and only
// Linux, where the build exists to run the tests, takes swift-crypto's.
#if canImport(CommonCrypto)
    import CommonCrypto
#else
    import Crypto
    import CryptoExtras
#endif

/// PBKDF2-HMAC-SHA256 (ADR 0003): CommonCrypto on Apple platforms, swift-crypto on Linux (ADR 0006).
///
/// It lives in `SecureMemory` rather than `WatchwordCrypto` because the CommonCrypto call passes raw pointers, and
/// ADR 0001 confines unsafe code to this module. Doing the call here also means the password is read straight out of
/// protected storage and the derived key written straight into it. The Linux path cannot promise that: swift-crypto
/// derives into an ordinary buffer it does not zeroise. Linux builds exist to run the tests and never ship.
///
/// This is the bare primitive: it enforces no iteration floor, so known-answer tests can use the RFC vectors. Policy
/// (`KDFParameters` floors and ceilings, SEC5/SEC9) is enforced by `TwoSecretKeyDerivation`, its only production caller
/// besides calibration.
public enum PBKDF2 {
    public enum Failure: Error, Equatable, Sendable {
        case invalidParameters
        case derivationFailed(status: Int32)
    }

    public static func sha256(
        password: SecureBytes,
        salt: [UInt8],
        iterations: UInt32,
        outputByteCount: Int
    ) throws -> SecureBytes {
        guard iterations > 0, outputByteCount > 0, !salt.isEmpty else { throw Failure.invalidParameters }
        return try derive(password: password, salt: salt, iterations: iterations, outputByteCount: outputByteCount)
    }
}

#if canImport(CommonCrypto)
    extension PBKDF2 {
        private static func derive(
            password: SecureBytes,
            salt: [UInt8],
            iterations: UInt32,
            outputByteCount: Int
        ) throws -> SecureBytes {
            // The salt is not secret; it goes through SecureBytes only so every pointer here comes from one audited type.
            let saltBytes = SecureBytes(copying: salt)
            let output = SecureBytes(count: outputByteCount)
            try
                unsafe (output.initializeStorage { derived in
                    let status =
                        unsafe (password.withLiveBytes { passwordBytes in
                            unsafe (saltBytes.withLiveBytes { saltBuffer in
                                unsafe (CCKeyDerivationPBKDF(
                                    CCPBKDFAlgorithm(kCCPBKDF2),
                                    passwordBytes.baseAddress?.assumingMemoryBound(to: CChar.self),
                                    passwordBytes.count,
                                    saltBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                    saltBuffer.count,
                                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                    iterations,
                                    derived.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                    derived.count
                                ))
                            })
                        })
                    guard status == Int32(kCCSuccess) else { throw Failure.derivationFailed(status: status) }
                })
            return output
        }
    }
#else
    extension PBKDF2 {
        private static func derive(
            password: SecureBytes,
            salt: [UInt8],
            iterations: UInt32,
            outputByteCount: Int
        ) throws -> SecureBytes {
            // `KDF.Insecure` is swift-crypto's name for "no floor enforced here"; the floor is `KDFParameters`'.
            let key: SymmetricKey
            do {
                key = try KDF.Insecure.PBKDF2.deriveKey(
                    from: password, salt: salt, using: .sha256, outputByteCount: outputByteCount,
                    unsafeUncheckedRounds: Int(iterations))
            } catch {
                // BoringSSL's PKCS5_PBKDF2_HMAC reports failure as 0 and swift-crypto passes on nothing more.
                throw Failure.derivationFailed(status: 0)
            }
            return SecureBytes(copying: key)
        }
    }
#endif
