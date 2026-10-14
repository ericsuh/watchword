#if canImport(CryptoKit)
    import CryptoKit
    import Foundation
    import SecureMemory
    import Testing
    import WatchwordEnvelope
    import WatchwordTestSupport

    @testable import WatchwordCrypto

    enum Fixtures {
        static let accountID = UUID(uuidString: "6F1C2A3B-4D5E-4F60-8172-839405A6B7C8")!
        static let vaultID = UUID(uuidString: "11111111-2222-4333-8444-555555555555")!

        static func itemContext(key: EncryptionKey, recordVersion: UInt64 = 1) -> EnvelopeContext {
            EnvelopeContext(
                recordID: UUID(uuidString: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")!,
                vaultID: vaultID,
                schemaVersion: 1,
                kind: .item,
                keyID: key.keyID,
                recordVersion: recordVersion
            )
        }
    }

    @Suite("Record sealing")
    struct RecordSealingTests {
        @Test("seal then open returns the plaintext", arguments: [0, 1, 15, 16, 17, 1_000, 70_000])
        func roundTrip(_ size: Int) throws {
            var generator = SeededGenerator(seed: UInt64(size) + 1)
            let key = EncryptionKey.generate(using: &generator)
            let plaintext = (0..<size).map { UInt8(truncatingIfNeeded: $0 &* 31) }
            var sealer = RecordSealer(key: key)
            let context = Fixtures.itemContext(key: key)
            let envelope = try sealer.seal(plaintext, context: context, using: &generator)
            #expect(envelope.count == EnvelopeHeader.fixedPrefixLength + context.canonicalAAD().count + size + 16)
            #expect(Array(try RecordCipher.open(envelope, context: context, key: key)) == plaintext)
            #expect(sealer.sealCount == 1)
        }

        @Test("the same seed reproduces the same envelope; a different one does not")
        func determinismUnderSeededGenerator() throws {
            func seal(seed: UInt64) throws -> [UInt8] {
                var generator = SeededGenerator(seed: seed)
                let key = EncryptionKey.generate(using: &generator)
                var sealer = RecordSealer(key: key)
                return try sealer.seal(Array("x".utf8), context: Fixtures.itemContext(key: key), using: &generator)
            }
            #expect(try seal(seed: 1) == seal(seed: 1))
            #expect(try seal(seed: 1) != seal(seed: 2))
        }

        @Test("a key of the wrong length is refused")
        func keyLength() {
            #expect(throws: CryptoError.invalidKeyLength(16)) {
                try EncryptionKey(keyID: UUID(), material: SecureBytes(count: 16))
            }
        }
    }

    #if canImport(CommonCrypto)
        @Suite("Two-secret key derivation")
        struct TwoSecretKeyDerivationTests {
            static let secretKey = try! SecretKey(bytes: SecureBytes(copying: Array(0..<16)))
            static let salt = Array(0x40..<0x60) as [UInt8]

            static func derive(
                _ password: String, secretKey: SecretKey = secretKey, accountID: UUID = Fixtures.accountID
            )
                throws -> [UInt8]
            {
                Array(
                    try TwoSecretKeyDerivation.accountUnlockKey(
                        password: password,
                        secretKey: secretKey,
                        accountID: accountID,
                        parameters: .baseline,
                        salt: salt,
                        keyID: UUID()
                    ).material)
            }

            /// Expected AUK from an independent Python implementation of the §4 derivation (hashlib PBKDF2, HMAC-based HKDF).
            @Test("matches an independent implementation of the derivation")
            func knownAnswer() throws {
                #expect(
                    try TwoSecretKeyDerivationTests.derive("correct horse battery staple")
                        == [UInt8](hex: "81315d220d38ac0fd85f1d84ae6b96fe470b7dfaff73259b4252cd9e16f27f8b"))
            }

            @Test("passwords are NFKD-normalised, so equivalent spellings unlock the same account")
            func normalisation() throws {
                let expected = [UInt8](hex: "f8af405be2af90bb90f0e3f63a99b2ee16f11b876176590328424bff9c7a633f")
                // Full-width C plus combining acute plus the "fi" ligature; plain decomposed; precomposed.
                for spelling in ["\u{FF23}afe\u{0301} \u{FB01}", "Cafe\u{0301} fi", "Caf\u{00E9} fi"] {
                    #expect(try TwoSecretKeyDerivationTests.derive(spelling) == expected)
                }
            }

            @Test("each secret and the account ID change the result")
            func everyInputMatters() throws {
                let base = try TwoSecretKeyDerivationTests.derive("pw")
                #expect(try TwoSecretKeyDerivationTests.derive("pW") != base)
                let otherKey = try SecretKey(bytes: SecureBytes(copying: Array(1...16)))
                #expect(try TwoSecretKeyDerivationTests.derive("pw", secretKey: otherKey) != base)
                #expect(try TwoSecretKeyDerivationTests.derive("pw", accountID: UUID()) != base)
            }
        }

        @Suite("KDF calibration")
        struct KDFCalibrationTests {
            @Test(
                "scales the probe to the target and clamps to the two-sided bounds",
                arguments: zip(
                    [
                        Duration.milliseconds(25), .milliseconds(10), .milliseconds(1), .zero, .milliseconds(-5),
                        .seconds(10),
                    ],
                    [UInt32(650_000), 1_500_000, 15_000_000, 650_000, 650_000, 650_000]
                ))
            func scaling(_ probe: Duration, _ expected: UInt32) {
                #expect(KDFCalibration.iterations(probeIterations: 50_000, probeDuration: probe) == expected)
            }

            @Test("a near-zero probe time hits the ceiling, never overflows")
            func ceiling() {
                #expect(
                    KDFCalibration.iterations(probeIterations: 50_000, probeDuration: .nanoseconds(1))
                        == KDFParameters.maximumIterations)
            }

            /// Informational on CI hardware (docs/03-implementation-plan.md, milestone 1 exit criteria): the result must
            /// validate, and the measured derivation time is reported rather than asserted.
            @Test("calibration on this machine produces valid parameters")
            func calibrateHere() throws {
                let parameters = try KDFCalibration.calibrate(clock: ContinuousClock())
                try parameters.validate()
                var generator = SystemRandomNumberGenerator()
                let password = SecureBytes(randomCount: 16, using: &generator)
                let elapsed = try ContinuousClock().measure {
                    _ = try PBKDF2.sha256(
                        password: password, salt: [1, 2, 3, 4], iterations: parameters.iterations, outputByteCount: 32)
                }
                print("KDF calibration: \(parameters.iterations) iterations took \(elapsed) here (target 300 ms)")
            }
        }
    #endif

    @Suite("Keyset, vault keys and grants")
    struct KeysetTests {
        @Test("a keyset round-trips through its AUK wrap")
        func keysetRoundTrip() throws {
            var generator = SeededGenerator(seed: 21)
            let unlockKey = EncryptionKey.generate(using: &generator)
            let keyset = Keyset.generate(accountID: Fixtures.accountID, using: &generator)
            let wrapped = try keyset.wrap(with: unlockKey, using: &generator)
            let unwrapped = try Keyset.unwrap(wrapped, accountID: Fixtures.accountID, with: unlockKey)
            #expect(unwrapped.symmetricKey.keyID == keyset.symmetricKey.keyID)
            #expect(unwrapped.symmetricKey.material.constantTimeEquals(keyset.symmetricKey.material))
            #expect(unwrapped.agreementSeed.constantTimeEquals(keyset.agreementSeed))
            #expect(unwrapped.signingSeed.constantTimeEquals(keyset.signingSeed))
            #expect(try unwrapped.publicKeyBundle().fingerprint == keyset.publicKeyBundle().fingerprint)
        }

        @Test("the public key bundle is self-signed and validates on construction")
        func bundle() throws {
            let keyset = Keyset.generate(accountID: Fixtures.accountID)
            let bundle = try keyset.publicKeyBundle()
            let rebuilt = try PublicKeyBundle(
                accountID: bundle.accountID,
                agreementKey: bundle.agreementKey,
                signingKey: bundle.signingKey,
                selfSignature: bundle.selfSignature
            )
            #expect(rebuilt.fingerprint == bundle.fingerprint)
        }

        /// Expected digits from an independent Python implementation.
        @Test("fingerprints render as sixty digits in twelve groups")
        func fingerprintKnownAnswer() {
            let fingerprint = Fingerprint(
                accountID: Fixtures.accountID, agreementKey: Array(0..<32), signingKey: Array(32..<64))
            #expect(
                fingerprint.safetyNumber == "93687 58027 87177 41603 50892 28718 32741 22347 72669 19989 44368 22911")
        }

        @Test("signatures verify only for their own domain")
        func signatureDomains() throws {
            let keyset = Keyset.generate(accountID: Fixtures.accountID)
            let signingKey = try keyset.publicKeyBundle().signingKey
            let message = Array("membership epoch 1".utf8)
            let signature = try keyset.sign(message, domain: .membership)
            try Signatures.verify(signature, for: message, domain: .membership, signingKey: signingKey)
            for other in SignatureDomain.allCases where other != .membership {
                #expect(throws: CryptoError.signatureInvalid) {
                    try Signatures.verify(signature, for: message, domain: other, signingKey: signingKey)
                }
            }
        }

        @Test("a vault key round-trips through the owner's wrap")
        func personalVaultKey() throws {
            var generator = SeededGenerator(seed: 22)
            let keyset = Keyset.generate(accountID: Fixtures.accountID, using: &generator)
            let vaultKey = VaultKey.generate(vaultID: Fixtures.vaultID, using: &generator)
            let wrapped = try vaultKey.wrap(for: keyset, using: &generator)
            let unwrapped = try VaultKey.unwrap(
                wrapped, vaultID: Fixtures.vaultID, keyID: vaultKey.key.keyID, with: keyset)
            #expect(unwrapped.key.material.constantTimeEquals(vaultKey.key.material))
        }

        @Test("a vault key grant opens for its recipient and yields a working key")
        func grantRoundTrip() throws {
            let owner = Keyset.generate(accountID: UUID())
            let member = Keyset.generate(accountID: UUID())
            let vaultKey = VaultKey.generate(vaultID: Fixtures.vaultID)
            let grant = try VaultKeyGrant.seal(vaultKey, to: member.publicKeyBundle(), from: owner)
            let received = try grant.open(as: member, from: owner.publicKeyBundle())
            #expect(received.key.keyID == vaultKey.key.keyID)
            #expect(received.key.material.constantTimeEquals(vaultKey.key.material))

            var sealer = RecordSealer(key: vaultKey.key)
            let context = Fixtures.itemContext(key: vaultKey.key)
            let record = try sealer.seal(Array("shared bank PIN".utf8), context: context)
            #expect(
                Array(try RecordCipher.open(record, context: context, key: received.key))
                    == Array("shared bank PIN".utf8))
        }
    }
#endif
