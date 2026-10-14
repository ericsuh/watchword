#if canImport(CommonCrypto)
    import CommonCrypto

    /// PBKDF2-HMAC-SHA256 from CommonCrypto (ADR 0003).
    ///
    /// It lives in `SecureMemory` rather than `WatchwordCrypto` because the call passes raw pointers, and ADR 0001 confines
    /// unsafe code to this module. Doing the call here also means the password is read straight out of protected
    /// storage and the derived key written straight into it.
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
#endif
