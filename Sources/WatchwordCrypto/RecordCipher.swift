#if canImport(CryptoKit)
    import CryptoKit
    import Foundation
    import SecureMemory
    import WatchwordEnvelope

    /// A 96-bit AES-GCM nonce, stored compactly so a sealer can remember every one it issued.
    struct Nonce96: Hashable, Sendable {
        let high: UInt64
        let low: UInt32

        init<R: RandomNumberGenerator>(using generator: inout R) {
            high = generator.next()
            low = UInt32(truncatingIfNeeded: generator.next())
        }

        var bytes: [UInt8] {
            (0..<8).map { UInt8(truncatingIfNeeded: high >> (8 * $0)) }
                + (0..<4).map { UInt8(truncatingIfNeeded: low >> (8 * UInt32($0))) }
        }
    }

    /// Seals records under one key into envelopes (docs/02-architecture.md §5, PRD SEC1/SEC2).
    ///
    /// Nonces are 96 random bits per encryption. The sealer also remembers every nonce it has issued and refuses to reuse
    /// one (`CryptoError.nonceReuseDetected`): with a working CSPRNG that never fires, so it is a tripwire for a broken or
    /// mis-injected generator, which is the realistic way GCM nonces repeat (docs/04-test-plan.md §6.1). The guard spans one
    /// sealer's lifetime; across processes, uniqueness rests on the CSPRNG and on rotating keys long before the 2^32
    /// random-nonce limit of NIST SP 800-38D §8.3.
    ///
    /// The AEAD authenticates the entire serialized header, which embeds `EnvelopeContext.canonicalAAD()`.
    public struct RecordSealer: Sendable {
        /// Bounds the nonce memory (roughly 32 MiB at the limit). Far above any single session's writes.
        public static let maximumSeals = 1 << 20

        public let key: EncryptionKey
        private var issuedNonces: Set<Nonce96> = []

        public init(key: EncryptionKey) {
            self.key = key
        }

        public var sealCount: Int {
            issuedNonces.count
        }

        public mutating func seal<R: RandomNumberGenerator>(
            _ plaintext: some DataProtocol,
            context: EnvelopeContext,
            using generator: inout R
        ) throws -> [UInt8] {
            guard context.keyID == key.keyID else {
                throw CryptoError.keyMismatch(expected: key.keyID, actual: context.keyID)
            }
            guard issuedNonces.count < RecordSealer.maximumSeals else { throw CryptoError.sealLimitReached }
            let nonce = Nonce96(using: &generator)
            guard issuedNonces.insert(nonce).inserted else { throw CryptoError.nonceReuseDetected }

            let header = try EnvelopeHeader(
                kind: context.kind, keyID: context.keyID, nonce: nonce.bytes, aad: context.canonicalAAD())
            let sealed = try AES.GCM.seal(
                plaintext,
                using: key.material.symmetricKey,
                nonce: AES.GCM.Nonce(data: nonce.bytes),
                authenticating: header.serialized()
            )
            return try Envelope(header: header, ciphertext: Array(sealed.ciphertext) + Array(sealed.tag)).serialized()
        }

        public mutating func seal(_ plaintext: some DataProtocol, context: EnvelopeContext) throws -> [UInt8] {
            var generator = SystemRandomNumberGenerator()
            return try seal(plaintext, context: context, using: &generator)
        }
    }

    public enum RecordCipher {
        /// Opens an envelope found at the storage location described by `context`.
        ///
        /// Every structural and context check (`Envelope.parse`) runs before decryption. Decryption either returns the
        /// whole plaintext, in protected storage, or throws `CryptoError.authenticationFailed`; there is no partial result.
        public static func open(_ bytes: [UInt8], context: EnvelopeContext, key: EncryptionKey) throws -> SecureBytes {
            guard context.keyID == key.keyID else {
                throw CryptoError.keyMismatch(expected: key.keyID, actual: context.keyID)
            }
            let envelope = try Envelope.parse(bytes, expecting: context)
            let split = envelope.ciphertext.count - Envelope.tagLength
            do {
                let box = try AES.GCM.SealedBox(
                    nonce: AES.GCM.Nonce(data: envelope.header.nonce),
                    ciphertext: envelope.ciphertext[..<split],
                    tag: envelope.ciphertext[split...]
                )
                var plaintext = try AES.GCM.open(
                    box, using: key.material.symmetricKey, authenticating: envelope.authenticatedData)
                return SecureBytes(wiping: &plaintext)
            } catch {
                throw CryptoError.authenticationFailed
            }
        }
    }
#endif
