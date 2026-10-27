#if canImport(CryptoKit) || os(Linux)
    #if canImport(CryptoKit)
        import CryptoKit
    #else
        import Crypto
    #endif
    import Foundation
    import SecureMemory
    import WatchwordEnvelope

    /// A vault key wrapped to another member with HPKE and signed by the sender (docs/02-architecture.md §4, §8; PRD SEC3).
    ///
    /// - HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM (RFC 9180).
    /// - `info = "WW-vaultkey-v1" ‖ vaultID ‖ keyID`, so a grant cannot be re-labelled as another vault or key epoch.
    /// - HPKE associated data is canonical CBOR of sender, recipient and the recipient's X25519 key.
    /// - The sender's Ed25519 signature (domain `.vaultKeyGrant`) covers every field, including the encapsulated key and
    ///   ciphertext. Base mode does not authenticate the sender; the signature does.
    ///
    /// Opening checks, in order and before any decryption: the grant's vault and key IDs are those of the storage location
    /// it was found in; the claimed sender is the expected one; the signature verifies under that sender's
    /// (fingerprint-verified) key; the grant is addressed to this account and to its current X25519 key. A grant filed
    /// under the wrong vault, to a substituted key, from a substituted sender, or with any field altered fails closed.
    /// The HPKE `info` binding is a further layer only against someone who can sign but not decrypt: any legitimate
    /// signer can seal a fresh grant under any label, which is why the location check exists.
    public struct VaultKeyGrant: Sendable, Hashable {
        public let vaultID: UUID
        public let keyID: UUID
        public let senderAccountID: UUID
        public let recipientAccountID: UUID
        public let recipientAgreementKey: [UInt8]
        public let encapsulatedKey: [UInt8]
        public let ciphertext: [UInt8]
        public let signature: [UInt8]

        /// Memberwise, for grants read back from storage. Nothing is trusted until `open` verifies it.
        public init(
            vaultID: UUID,
            keyID: UUID,
            senderAccountID: UUID,
            recipientAccountID: UUID,
            recipientAgreementKey: [UInt8],
            encapsulatedKey: [UInt8],
            ciphertext: [UInt8],
            signature: [UInt8]
        ) {
            self.vaultID = vaultID
            self.keyID = keyID
            self.senderAccountID = senderAccountID
            self.recipientAccountID = recipientAccountID
            self.recipientAgreementKey = recipientAgreementKey
            self.encapsulatedKey = encapsulatedKey
            self.ciphertext = ciphertext
            self.signature = signature
        }

        static var ciphersuite: HPKE.Ciphersuite {
            HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_256)
        }

        static func info(vaultID: UUID, keyID: UUID) -> Data {
            Data(Array("WW-vaultkey-v1".utf8) + vaultID.byteArray + keyID.byteArray)
        }

        static func associatedData(sender: UUID, recipient: UUID, recipientAgreementKey: [UInt8]) -> [UInt8] {
            CBORValue.map([1: .uuid(sender), 2: .uuid(recipient), 3: .bytes(recipientAgreementKey)]).encoded()
        }

        /// Canonical CBOR of every field but the signature.
        var signedContent: [UInt8] {
            CBORValue.map([
                1: .uuid(vaultID),
                2: .uuid(keyID),
                3: .uuid(senderAccountID),
                4: .uuid(recipientAccountID),
                5: .bytes(recipientAgreementKey),
                6: .bytes(encapsulatedKey),
                7: .bytes(ciphertext),
            ]).encoded()
        }

        /// `recipient` must be a bundle whose fingerprint the sender has verified (F4.2); constructing it already checked
        /// its self-signature and rejected low-order keys.
        public static func seal(_ vaultKey: VaultKey, to recipient: PublicKeyBundle, from sender: Keyset) throws
            -> VaultKeyGrant
        {
            let recipientKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipient.agreementKey)
            var hpke = try HPKE.Sender(
                recipientKey: recipientKey,
                ciphersuite: ciphersuite,
                info: info(vaultID: vaultKey.vaultID, keyID: vaultKey.key.keyID)
            )
            let ciphertext = try hpke.seal(
                vaultKey.key.material,
                authenticating: associatedData(
                    sender: sender.accountID, recipient: recipient.accountID,
                    recipientAgreementKey: recipient.agreementKey)
            )
            let unsigned = VaultKeyGrant(
                vaultID: vaultKey.vaultID,
                keyID: vaultKey.key.keyID,
                senderAccountID: sender.accountID,
                recipientAccountID: recipient.accountID,
                recipientAgreementKey: recipient.agreementKey,
                encapsulatedKey: Array(hpke.encapsulatedKey),
                ciphertext: Array(ciphertext),
                signature: []
            )
            return VaultKeyGrant(
                vaultID: unsigned.vaultID,
                keyID: unsigned.keyID,
                senderAccountID: unsigned.senderAccountID,
                recipientAccountID: unsigned.recipientAccountID,
                recipientAgreementKey: unsigned.recipientAgreementKey,
                encapsulatedKey: unsigned.encapsulatedKey,
                ciphertext: unsigned.ciphertext,
                signature: try sender.sign(unsigned.signedContent, domain: .vaultKeyGrant)
            )
        }

        /// Opens a grant found at the storage location of `vaultID`'s key `keyID`.
        ///
        /// `vaultID` and `keyID` come from where the grant was found, never from the grant (the rule `VaultKey.unwrap`
        /// follows too). Entitlement is per vault: without this check, a sender entitled to grant keys for one vault
        /// could file a grant labelled with another vault, where they have no say, and a caller indexing by the grant's
        /// own label would install an attacker-known key there (review finding R2).
        ///
        /// `expectedSender` is the fingerprint-verified bundle of whoever is entitled to grant keys for `vaultID`. Which
        /// accounts are entitled (admins as of the previous membership state) is decided by the membership chain,
        /// milestone 4.
        public func open(as recipient: Keyset, from expectedSender: PublicKeyBundle, vaultID: UUID, keyID: UUID) throws
            -> VaultKey
        {
            guard self.vaultID == vaultID, self.keyID == keyID else { throw CryptoError.grantMismatch }
            guard senderAccountID == expectedSender.accountID else { throw CryptoError.grantMismatch }
            try Signatures.verify(
                signature, for: signedContent, domain: .vaultKeyGrant, signingKey: expectedSender.signingKey)
            let ownAgreementKey = Array(try recipient.agreementPrivateKey().publicKey.rawRepresentation)
            guard recipientAccountID == recipient.accountID, recipientAgreementKey == ownAgreementKey else {
                throw CryptoError.grantMismatch
            }
            var plaintext: Data
            do {
                var hpke = try HPKE.Recipient(
                    privateKey: recipient.agreementPrivateKey(),
                    ciphersuite: VaultKeyGrant.ciphersuite,
                    info: VaultKeyGrant.info(vaultID: vaultID, keyID: keyID),
                    encapsulatedKey: Data(encapsulatedKey)
                )
                plaintext = try hpke.open(
                    ciphertext,
                    authenticating: VaultKeyGrant.associatedData(
                        sender: senderAccountID, recipient: recipientAccountID,
                        recipientAgreementKey: recipientAgreementKey)
                )
            } catch {
                throw CryptoError.authenticationFailed
            }
            return VaultKey(
                vaultID: vaultID, key: try EncryptionKey(keyID: keyID, material: SecureBytes(wiping: &plaintext)))
        }
    }
#endif
