#if canImport(CryptoKit) || os(Linux)
    #if canImport(CryptoKit)
        import CryptoKit
    #else
        import Crypto
    #endif
    import Foundation
    import Testing
    import WatchwordEnvelope
    import WatchwordTestSupport

    @testable import SecureMemory
    @testable import WatchwordCrypto

    /// Milestone 1 adversarial obligations (docs/04-test-plan.md §6.1). The attacker is a sync store (A1) that can read,
    /// reorder, rewrite and substitute any record, header or published key, or a broken platform dependency (RNG).
    @Suite("Adversarial: crypto core", .tags(.adversarial))
    struct AdversarialCryptoTests {
        static let vaultA = UUID()
        static let vaultB = UUID()

        private static func sealedRecord(size: Int = 64, seed: UInt64 = 1) throws
            -> (key: EncryptionKey, context: EnvelopeContext, bytes: [UInt8], plaintext: [UInt8])
        {
            var generator = SeededGenerator(seed: seed)
            let key = EncryptionKey.generate(using: &generator)
            let context = EnvelopeContext(
                recordID: UUID.randomVersion4(using: &generator), vaultID: vaultA, schemaVersion: 1, kind: .item,
                keyID: key.keyID,
                recordVersion: 5)
            let plaintext = (0..<size).map { UInt8(truncatingIfNeeded: $0) }
            return (
                key, context, try RecordCipher.seal(plaintext, context: context, key: key, using: &generator), plaintext
            )
        }

        // MARK: Tampering

        /// Each region fails for its own reason: header fields by a parser check before decryption, and the nonce, the
        /// ciphertext and the tag by AEAD authentication. Asserting the specific error catches a regression in which layer
        /// rejects what (review finding R11).
        @Test("flipping any byte of a sealed record makes it fail to open, for the right reason; nothing is returned")
        func everyByteFlip() throws {
            let (key, context, bytes, _) = try Self.sealedRecord()
            let nonceRange = 23..<35
            let payloadStart = EnvelopeHeader.fixedPrefixLength + context.canonicalAAD().count
            for position in bytes.indices {
                for mask: UInt8 in [0x01, 0x80] {
                    var mutated = bytes
                    mutated[position] ^= mask
                    if nonceRange.contains(position) || position >= payloadStart {
                        #expect(throws: CryptoError.authenticationFailed, "flip \(mask) at byte \(position)") {
                            _ = try RecordCipher.open(mutated, context: context, key: key)
                        }
                    } else {
                        #expect(throws: EnvelopeError.self, "flip \(mask) at byte \(position)") {
                            _ = try RecordCipher.open(mutated, context: context, key: key)
                        }
                    }
                }
            }
        }

        @Test("flipping sampled bytes of a long record fails authentication")
        func longRecordFlips() throws {
            let (key, context, bytes, _) = try Self.sealedRecord(size: 200_000)
            var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 3))
            let payloadStart = EnvelopeHeader.fixedPrefixLength + context.canonicalAAD().count
            for _ in 0..<TestEnvironment.iterations(standard: 64, long: 4_096) {
                var mutated = bytes
                mutated[Int.random(in: payloadStart..<bytes.count, using: &generator)] ^= 0x01
                #expect(throws: CryptoError.authenticationFailed) {
                    _ = try RecordCipher.open(mutated, context: context, key: key)
                }
            }
        }

        @Test("truncating a sealed record at any length fails closed, before decryption until a tag's worth remains")
        func truncation() throws {
            let (key, context, bytes, _) = try Self.sealedRecord(size: 16)
            let payloadStart = EnvelopeHeader.fixedPrefixLength + context.canonicalAAD().count
            for length in 0..<bytes.count {
                let truncated = Array(bytes[0..<length])
                if length < payloadStart + Envelope.tagLength {
                    #expect(throws: EnvelopeError.self) {
                        _ = try RecordCipher.open(truncated, context: context, key: key)
                    }
                } else {
                    #expect(throws: CryptoError.authenticationFailed) {
                        _ = try RecordCipher.open(truncated, context: context, key: key)
                    }
                }
            }
        }

        @Test("a key-sized record refuses an oversized envelope before parsing it")
        func perKindSizeCap() throws {
            let keyset = Keyset.generate(accountID: UUID())
            let huge = [UInt8](repeating: 0, count: 1_000_000)
            #expect(throws: EnvelopeError.tooLarge(huge.count)) {
                _ = try VaultKey.unwrap(huge, vaultID: Self.vaultA, keyID: UUID(), with: keyset)
            }
            #expect(throws: EnvelopeError.tooLarge(huge.count)) {
                _ = try Keyset.unwrap(huge, accountID: UUID(), with: keyset.symmetricKey)
            }
        }

        // MARK: Swap, replay, downgrade

        @Test("a record copied into another vault's slot is rejected by the AAD comparison, before decryption")
        func swapIntoAnotherVault() throws {
            let (key, context, bytes, _) = try Self.sealedRecord()
            var slot = context
            slot.vaultID = Self.vaultB
            #expect(throws: EnvelopeError.contextMismatch) { _ = try RecordCipher.open(bytes, context: slot, key: key) }
        }

        @Test("rewriting the embedded AAD to match the new slot still fails: the AEAD binds the header")
        func forgedAADFailsAuthentication() throws {
            let (key, context, bytes, _) = try Self.sealedRecord()
            var slot = context
            slot.vaultID = Self.vaultB
            let original = try Envelope.parse(bytes, expecting: context)
            let forgedHeader = try EnvelopeHeader(
                kind: slot.kind, keyID: slot.keyID, nonce: original.header.nonce, aad: slot.canonicalAAD())
            let forged = try Envelope(header: forgedHeader, ciphertext: original.ciphertext).serialized()
            #expect(throws: CryptoError.authenticationFailed) {
                _ = try RecordCipher.open(forged, context: slot, key: key)
            }
        }

        @Test("an old version cannot be presented as a newer one")
        func replayAsNewerVersion() throws {
            let (key, context, bytes, _) = try Self.sealedRecord()
            var newer = context
            newer.recordVersion += 1
            #expect(throws: EnvelopeError.contextMismatch) {
                _ = try RecordCipher.open(bytes, context: newer, key: key)
            }
        }

        @Test("an item record cannot be opened as a key wrap (kind confusion)")
        func kindConfusion() throws {
            let (key, context, bytes, _) = try Self.sealedRecord()
            var asWrap = context
            asWrap.kind = .vaultKeyWrap
            #expect(throws: EnvelopeError.kindMismatch(expected: .vaultKeyWrap, actual: .item)) {
                _ = try RecordCipher.open(bytes, context: asWrap, key: key)
            }
        }

        @Test("a different key fails authentication; a mislabelled key is refused before decryption")
        func wrongKey() throws {
            let (key, context, bytes, _) = try Self.sealedRecord()
            let impostor = try EncryptionKey(keyID: key.keyID, material: SecureBytes(count: 32))
            #expect(throws: CryptoError.authenticationFailed) {
                _ = try RecordCipher.open(bytes, context: context, key: impostor)
            }
            var generator = SeededGenerator(seed: 99)
            let other = EncryptionKey.generate(using: &generator)
            #expect(throws: CryptoError.keyMismatch(expected: other.keyID, actual: key.keyID)) {
                _ = try RecordCipher.open(bytes, context: context, key: other)
            }
        }

        @Test("sealing refuses a context naming a different key")
        func sealerKeyMismatch() throws {
            var generator = SeededGenerator(seed: 9)
            let key = EncryptionKey.generate(using: &generator)
            let context = EnvelopeContext(
                recordID: UUID(), vaultID: UUID(), schemaVersion: 1, kind: .item, keyID: UUID())
            #expect(throws: CryptoError.keyMismatch(expected: key.keyID, actual: context.keyID)) {
                _ = try RecordCipher.seal([1], context: context, key: key, using: &generator)
            }
        }

        // MARK: Nonces

        @Test("a generator that repeats is caught by the nonce guard before a second encryption")
        func repeatingGeneratorDetected() throws {
            var generator = RepeatingGenerator(words: [0xDEAD_BEEF, 0xFEED_FACE])
            let key = try EncryptionKey(keyID: UUID(), material: SecureBytes(copying: Array(0..<32)))
            let context = EnvelopeContext(
                recordID: UUID(), vaultID: UUID(), schemaVersion: 1, kind: .item, keyID: key.keyID)
            _ = try RecordCipher.seal([1], context: context, key: key, using: &generator)
            #expect(throws: CryptoError.nonceReuseDetected) {
                _ = try RecordCipher.seal([2], context: context, key: key, using: &generator)
            }
            #expect(key.sealCount == 1)
        }

        @Test("nonces are unique across many encryptions under one key")
        func nonceUniqueness() throws {
            let count = TestEnvironment.iterations(standard: 100_000, long: 1_000_000)
            var generator = SystemRandomNumberGenerator()
            let key = EncryptionKey.generate(using: &generator)
            let context = EnvelopeContext(
                recordID: UUID(), vaultID: UUID(), schemaVersion: 1, kind: .item, keyID: key.keyID)
            var nonces = Set<[UInt8]>()
            nonces.reserveCapacity(count)
            let nonceRange = 23..<35
            for _ in 0..<count {
                nonces.insert(
                    Array(try RecordCipher.seal([], context: context, key: key, using: &generator)[nonceRange]))
            }
            #expect(nonces.count == count)
        }

        // MARK: Keyset and 2SKD

        @Test("a keyset wrap opens only under its own AUK, account and version")
        func keysetBinding() throws {
            var generator = SeededGenerator(seed: 31)
            let accountID = UUID.randomVersion4(using: &generator)
            let unlockKey = EncryptionKey.generate(using: &generator)
            let keyset = Keyset.generate(accountID: accountID, using: &generator)
            let wrapped = try keyset.wrap(with: unlockKey, recordVersion: 3, using: &generator)

            let wrongPassword = try EncryptionKey(
                keyID: unlockKey.keyID, material: SecureBytes(randomCount: 32, using: &generator))
            #expect(throws: CryptoError.authenticationFailed) {
                _ = try Keyset.unwrap(wrapped, accountID: accountID, with: wrongPassword, recordVersion: 3)
            }
            #expect(throws: EnvelopeError.contextMismatch) {
                _ = try Keyset.unwrap(wrapped, accountID: UUID(), with: unlockKey, recordVersion: 3)
            }
            #expect(throws: EnvelopeError.contextMismatch) {
                _ = try Keyset.unwrap(wrapped, accountID: accountID, with: unlockKey, recordVersion: 4)
            }
        }

        #if canImport(CommonCrypto)
            @Test(
                "2SKD refuses tampered KDF parameters before deriving anything",
                arguments: [UInt32(1_000), 649_999, 25_000_001])
            func kdfDowngradeAtDerivation(_ iterations: UInt32) {
                let parameters = KDFParameters(iterations: iterations)
                #expect(throws: KDFValidationError.self) {
                    _ = try TwoSecretKeyDerivation.accountUnlockKey(
                        password: "pw", secretKey: .generate(), accountID: UUID(), parameters: parameters,
                        salt: [UInt8](repeating: 0, count: 32), keyID: UUID())
                }
            }

            @Test("2SKD refuses a salt that does not match the declared length, and an empty password")
            func saltAndPassword() {
                #expect(throws: CryptoError.saltLengthMismatch(expected: 32, actual: 16)) {
                    _ = try TwoSecretKeyDerivation.accountUnlockKey(
                        password: "pw", secretKey: .generate(), accountID: UUID(), parameters: .baseline,
                        salt: [UInt8](repeating: 0, count: 16), keyID: UUID())
                }
                #expect(throws: CryptoError.emptyPassword) {
                    _ = try TwoSecretKeyDerivation.accountUnlockKey(
                        password: "", secretKey: .generate(), accountID: UUID(), parameters: .baseline,
                        salt: [UInt8](repeating: 0, count: 32), keyID: UUID())
                }
            }

            @Test("a wrong password or a wrong Secret Key cannot unwrap the keyset")
            func wrongSecretsCannotUnwrap() throws {
                let accountID = UUID()
                let secretKey = SecretKey.generate()
                let salt = [UInt8](repeating: 7, count: 32)
                let keyID = UUID()
                func unlockKey(_ password: String, _ secretKey: SecretKey) throws -> EncryptionKey {
                    try TwoSecretKeyDerivation.accountUnlockKey(
                        password: password, secretKey: secretKey, accountID: accountID, parameters: .baseline,
                        salt: salt,
                        keyID: keyID)
                }
                let wrapped = try Keyset.generate(accountID: accountID).wrap(with: unlockKey("right", secretKey))
                for wrong in [try unlockKey("wrong", secretKey), try unlockKey("right", .generate())] {
                    #expect(throws: CryptoError.authenticationFailed) {
                        _ = try Keyset.unwrap(wrapped, accountID: accountID, with: wrong)
                    }
                }
            }
        #endif

        // MARK: Published keys and grants

        /// Low-order X25519 points (libsodium's blocklist; each verified to yield an all-zero shared secret). A vault key
        /// HPKE-wrapped to one of these is readable by whoever substituted it.
        static let lowOrderPoints: [String] = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ]

        @Test("low-order X25519 keys are rejected when a bundle is constructed", arguments: lowOrderPoints)
        func lowOrderAgreementKeys(_ hex: String) throws {
            let honest = try Keyset.generate(accountID: UUID()).publicKeyBundle()
            #expect(throws: CryptoError.invalidPublicKey) {
                _ = try PublicKeyBundle(
                    accountID: honest.accountID, agreementKey: [UInt8](hex: hex), signingKey: honest.signingKey,
                    selfSignature: honest.selfSignature)
            }
        }

        @Test("a server that substitutes a published X25519 key breaks the self-signature")
        func substitutedAgreementKey() throws {
            let honest = try Keyset.generate(accountID: UUID()).publicKeyBundle()
            let attacker = try Keyset.generate(accountID: honest.accountID).publicKeyBundle()
            #expect(throws: CryptoError.signatureInvalid) {
                _ = try PublicKeyBundle(
                    accountID: honest.accountID, agreementKey: attacker.agreementKey, signingKey: honest.signingKey,
                    selfSignature: honest.selfSignature)
            }
        }

        @Test("a fully re-signed substitute bundle is valid but has a different fingerprint, which F4.2 catches")
        func substitutedBundleChangesFingerprint() throws {
            let accountID = UUID()
            let honest = try Keyset.generate(accountID: accountID).publicKeyBundle()
            let substitute = try Keyset.generate(accountID: accountID).publicKeyBundle()
            #expect(substitute.fingerprint != honest.fingerprint)
            #expect(substitute.fingerprint.safetyNumber != honest.fingerprint.safetyNumber)
        }

        @Test("a grant to a substituted recipient key cannot be opened by the real recipient")
        func grantToSubstitutedKey() throws {
            let owner = Keyset.generate(accountID: UUID())
            let member = Keyset.generate(accountID: UUID())
            let attacker = Keyset.generate(accountID: member.accountID)
            let vaultKey = VaultKey.generate(vaultID: Self.vaultA)
            let grant = try VaultKeyGrant.seal(vaultKey, to: attacker.publicKeyBundle(), from: owner)
            #expect(throws: CryptoError.grantMismatch) {
                _ = try grant.open(
                    as: member, from: owner.publicKeyBundle(), vaultID: Self.vaultA, keyID: vaultKey.key.keyID)
            }
        }

        @Test("a grant signed by anyone but the expected sender is rejected")
        func grantFromWrongSigner() throws {
            let owner = Keyset.generate(accountID: UUID())
            let member = Keyset.generate(accountID: UUID())
            let impostor = Keyset.generate(accountID: owner.accountID)
            let grant = try VaultKeyGrant.seal(
                VaultKey.generate(vaultID: Self.vaultA), to: member.publicKeyBundle(), from: impostor)
            #expect(throws: CryptoError.signatureInvalid) {
                _ = try grant.open(as: member, from: owner.publicKeyBundle(), vaultID: Self.vaultA, keyID: grant.keyID)
            }

            let stranger = Keyset.generate(accountID: UUID())
            let unrelated = try VaultKeyGrant.seal(
                VaultKey.generate(vaultID: Self.vaultA), to: member.publicKeyBundle(), from: stranger)
            #expect(throws: CryptoError.grantMismatch) {
                _ = try unrelated.open(
                    as: member, from: owner.publicKeyBundle(), vaultID: Self.vaultA, keyID: unrelated.keyID)
            }
        }

        @Test("altering any field of a grant breaks its signature")
        func grantFieldTampering() throws {
            let owner = Keyset.generate(accountID: UUID())
            let member = Keyset.generate(accountID: UUID())
            let ownerBundle = try owner.publicKeyBundle()
            let g = try VaultKeyGrant.seal(
                VaultKey.generate(vaultID: Self.vaultA), to: member.publicKeyBundle(), from: owner)
            func flip(_ bytes: [UInt8]) -> [UInt8] { [bytes[0] ^ 1] + bytes.dropFirst() }
            let tampered = [
                VaultKeyGrant(
                    vaultID: Self.vaultB, keyID: g.keyID, senderAccountID: g.senderAccountID,
                    recipientAccountID: g.recipientAccountID, recipientAgreementKey: g.recipientAgreementKey,
                    encapsulatedKey: g.encapsulatedKey, ciphertext: g.ciphertext, signature: g.signature),
                VaultKeyGrant(
                    vaultID: g.vaultID, keyID: UUID(), senderAccountID: g.senderAccountID,
                    recipientAccountID: g.recipientAccountID, recipientAgreementKey: g.recipientAgreementKey,
                    encapsulatedKey: g.encapsulatedKey, ciphertext: g.ciphertext, signature: g.signature),
                VaultKeyGrant(
                    vaultID: g.vaultID, keyID: g.keyID, senderAccountID: g.senderAccountID,
                    recipientAccountID: g.recipientAccountID, recipientAgreementKey: g.recipientAgreementKey,
                    encapsulatedKey: flip(g.encapsulatedKey), ciphertext: g.ciphertext, signature: g.signature),
                VaultKeyGrant(
                    vaultID: g.vaultID, keyID: g.keyID, senderAccountID: g.senderAccountID,
                    recipientAccountID: g.recipientAccountID, recipientAgreementKey: g.recipientAgreementKey,
                    encapsulatedKey: g.encapsulatedKey, ciphertext: flip(g.ciphertext), signature: g.signature),
                VaultKeyGrant(
                    vaultID: g.vaultID, keyID: g.keyID, senderAccountID: g.senderAccountID,
                    recipientAccountID: g.recipientAccountID, recipientAgreementKey: g.recipientAgreementKey,
                    encapsulatedKey: g.encapsulatedKey, ciphertext: g.ciphertext, signature: flip(g.signature)),
            ]
            // Each is opened at the location its own label claims, so what is exercised is the signature, not the
            // location check (which `grantFiledUnderAnotherVault` covers).
            for grant in tampered {
                #expect(throws: CryptoError.signatureInvalid) {
                    _ = try grant.open(as: member, from: ownerBundle, vaultID: grant.vaultID, keyID: grant.keyID)
                }
            }
        }

        /// A narrow layer: someone who can sign but not decrypt (a stolen signing key without the vault key) cannot
        /// relabel an existing grant, because HPKE's `info` binds vault and key. It is no defence against a legitimate
        /// signer, who can seal a fresh grant under any label; the location check is (see `grantFiledUnderAnotherVault`).
        @Test("a re-signed grant relabelled to another vault fails HPKE authentication")
        func grantRelabelFailsHPKE() throws {
            let owner = Keyset.generate(accountID: UUID())
            let member = Keyset.generate(accountID: UUID())
            let g = try VaultKeyGrant.seal(
                VaultKey.generate(vaultID: Self.vaultA), to: member.publicKeyBundle(), from: owner)
            let relabelled = VaultKeyGrant(
                vaultID: Self.vaultB, keyID: g.keyID, senderAccountID: g.senderAccountID,
                recipientAccountID: g.recipientAccountID, recipientAgreementKey: g.recipientAgreementKey,
                encapsulatedKey: g.encapsulatedKey, ciphertext: g.ciphertext, signature: [])
            let resigned = VaultKeyGrant(
                vaultID: relabelled.vaultID, keyID: relabelled.keyID, senderAccountID: relabelled.senderAccountID,
                recipientAccountID: relabelled.recipientAccountID,
                recipientAgreementKey: relabelled.recipientAgreementKey,
                encapsulatedKey: relabelled.encapsulatedKey, ciphertext: relabelled.ciphertext,
                signature: try owner.sign(relabelled.signedContent, domain: .vaultKeyGrant))
            #expect(throws: CryptoError.authenticationFailed) {
                _ = try resigned.open(
                    as: member, from: owner.publicKeyBundle(), vaultID: Self.vaultB, keyID: resigned.keyID)
            }
        }

        /// Review finding R2: entitlement is per vault, so the vault a grant installs a key into must be the vault whose
        /// grant table it was found in, never the grant's own label.
        @Test("a validly signed grant filed under another vault's or key's slot is refused before decryption")
        func grantFiledUnderAnotherVault() throws {
            let adminOfA = Keyset.generate(accountID: UUID())
            let member = Keyset.generate(accountID: UUID())
            let attackerKnownKey = VaultKey.generate(vaultID: Self.vaultB)
            let grant = try VaultKeyGrant.seal(attackerKnownKey, to: member.publicKeyBundle(), from: adminOfA)
            let sender = try adminOfA.publicKeyBundle()
            #expect(throws: CryptoError.grantMismatch) {
                _ = try grant.open(as: member, from: sender, vaultID: Self.vaultA, keyID: grant.keyID)
            }
            #expect(throws: CryptoError.grantMismatch) {
                _ = try grant.open(as: member, from: sender, vaultID: Self.vaultB, keyID: UUID())
            }
            let opened = try grant.open(as: member, from: sender, vaultID: Self.vaultB, keyID: grant.keyID)
            #expect(opened.vaultID == Self.vaultB)
        }

        @Test("a vault-key wrap moved to another vault's or key's slot is refused before decryption")
        func vaultKeyWrapMoved() throws {
            var generator = SeededGenerator(seed: 41)
            let keyset = Keyset.generate(accountID: UUID(), using: &generator)
            let vaultKey = VaultKey.generate(vaultID: Self.vaultA, using: &generator)
            let wrapped = try vaultKey.wrap(for: keyset, using: &generator)
            #expect(throws: EnvelopeError.contextMismatch) {
                _ = try VaultKey.unwrap(wrapped, vaultID: Self.vaultB, keyID: vaultKey.key.keyID, with: keyset)
            }
            #expect(throws: EnvelopeError.contextMismatch) {
                _ = try VaultKey.unwrap(wrapped, vaultID: Self.vaultA, keyID: UUID(), with: keyset)
            }
        }

        /// Review finding R3: the nonce guard belongs to the key, so it spans separate wraps and copies of the key value,
        /// not just one sealer's lifetime. Without that, two vault keys wrapped under one Ksym with a repeated nonce would
        /// satisfy ct1 ⊕ ct2 = vk1 ⊕ vk2, and a former member holding one would learn the other.
        @Test("a repeated nonce across two key wraps under the same Ksym is refused")
        func nonceReuseAcrossWraps() throws {
            let keyset = Keyset.generate(accountID: UUID())
            let first = VaultKey.generate(vaultID: Self.vaultA)
            let second = VaultKey.generate(vaultID: Self.vaultB)
            var generator = RepeatingGenerator(words: [0x0123_4567_89AB_CDEF, 0x0F1E_2D3C])
            var replay = generator
            _ = try first.wrap(for: keyset, using: &generator)
            #expect(throws: CryptoError.nonceReuseDetected) { _ = try second.wrap(for: keyset, using: &replay) }

            let copy = keyset.symmetricKey
            #expect(copy.sealCount == 1, "copies of a key share its nonce ledger")
        }

        /// Every small-order encoding, with the sign bit both clear and set.
        static let smallOrderKeyEncodings: [[UInt8]] =
            Signatures.smallOrderEncodings
            + Signatures.smallOrderEncodings.map { key -> [UInt8] in
                var flipped = key
                flipped[31] |= 0x80
                return flipped
            }

        @Test(
            "small-order Ed25519 signing keys are rejected, including the universal-signature identity key",
            arguments: smallOrderKeyEncodings)
        func smallOrderSigningKeys(_ key: [UInt8]) throws {
            // R = identity, S = 0: verifies for every message under a lax verifier when the key is the identity.
            let universal = [UInt8(1)] + [UInt8](repeating: 0, count: 63)
            #expect(throws: CryptoError.weakSigningKey) {
                try Signatures.verify(universal, for: Array("anything".utf8), domain: .membership, signingKey: key)
            }
            let honest = try Keyset.generate(accountID: UUID()).publicKeyBundle()
            #expect(throws: CryptoError.weakSigningKey) {
                _ = try PublicKeyBundle(
                    accountID: honest.accountID, agreementKey: honest.agreementKey, signingKey: key,
                    selfSignature: universal)
            }
        }

        @Test("a signature for one purpose never verifies for another")
        func signatureDomainSeparation() throws {
            let keyset = Keyset.generate(accountID: UUID())
            let bundle = try keyset.publicKeyBundle()
            let segment = Array("log segment 42".utf8)
            let signature = try keyset.sign(segment, domain: .logSegment)
            #expect(throws: CryptoError.signatureInvalid) {
                try Signatures.verify(signature, for: segment, domain: .membership, signingKey: bundle.signingKey)
            }
            // A raw Ed25519 signature over the bare message (no domain prefix) is not accepted either.
            let raw = try keyset.signingPrivateKey().signature(for: segment)
            #expect(throws: CryptoError.signatureInvalid) {
                try Signatures.verify(Array(raw), for: segment, domain: .logSegment, signingKey: bundle.signingKey)
            }
        }

        @Test("fingerprints differing in one digest bit compare unequal")
        func fingerprintEquality() {
            let a = Fingerprint(accountID: UUID(), agreementKey: Array(0..<32), signingKey: Array(32..<64))
            let b = Fingerprint(accountID: UUID(), agreementKey: Array(0..<32), signingKey: Array(32..<64))
            #expect(a == a)
            #expect(a != b)
        }

        // MARK: Zeroisation

        @Test("zeroising a keyset, a vault key and a Secret Key wipes every buffer")
        func zeroisation() throws {
            let keyset = Keyset.generate(accountID: UUID())
            let vaultKey = VaultKey.generate(vaultID: UUID())
            let secretKey = SecretKey.generate()
            let buffers = [
                keyset.symmetricKey.material, keyset.agreementSeed, keyset.signingSeed, vaultKey.key.material,
                secretKey.bytes,
            ]
            #expect(buffers.allSatisfy { !$0.storageIsAllZero() })
            keyset.zeroise()
            vaultKey.zeroise()
            secretKey.zeroise()
            #expect(keyset.isZeroised)
            #expect(buffers.allSatisfy { $0.isZeroised && $0.storageIsAllZero() })
        }
    }
#endif
