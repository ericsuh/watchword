import Crypto
import Foundation
import SecureMemory
import WatchwordEnvelope

/// Seals and opens records as envelopes (docs/02-architecture.md §5, PRD SEC1/SEC2).
///
/// Nonces are 96 random bits per encryption, and every nonce is claimed in the key's `NonceLedger` before use: a
/// repeat throws `CryptoError.nonceReuseDetected` instead of encrypting a second message under the same nonce. With
/// a working CSPRNG that never fires; it is a tripwire for a broken or mis-injected generator (docs/04-test-plan.md
/// §6.1). The ledger belongs to the key, so it spans record seals, key wraps and copies of the key value. Across
/// processes, uniqueness rests on the CSPRNG and on rotating keys long before the 2^32 random-nonce limit of NIST
/// SP 800-38D §8.3.
///
/// The AEAD authenticates the entire serialized header, which embeds `EnvelopeContext.canonicalAAD()`.
public enum RecordCipher {
    public static func seal<R: RandomNumberGenerator>(
        _ plaintext: some DataProtocol,
        context: EnvelopeContext,
        key: EncryptionKey,
        using generator: inout R
    ) throws -> [UInt8] {
        guard context.keyID == key.keyID else {
            throw CryptoError.keyMismatch(expected: key.keyID, actual: context.keyID)
        }
        let first = generator.next()
        let second = generator.next()
        let nonce =
            (0..<8).map { UInt8(truncatingIfNeeded: first >> (56 - 8 * $0)) }
            + (0..<4).map { UInt8(truncatingIfNeeded: second >> (24 - 8 * $0)) }
        switch key.nonceLedger.claim(nonce) {
        case .fresh: break
        case .reused: throw CryptoError.nonceReuseDetected
        case .limitReached: throw CryptoError.sealLimitReached
        }

        let header = try EnvelopeHeader(
            kind: context.kind, keyID: context.keyID, nonce: nonce, aad: context.canonicalAAD())
        let sealed = try AES.GCM.seal(
            plaintext,
            using: key.material.symmetricKey,
            nonce: AES.GCM.Nonce(data: nonce),
            authenticating: header.serialized()
        )
        return try Envelope(header: header, ciphertext: Array(sealed.ciphertext) + Array(sealed.tag)).serialized()
    }

    public static func seal(_ plaintext: some DataProtocol, context: EnvelopeContext, key: EncryptionKey) throws
        -> [UInt8]
    {
        var generator = SystemRandomNumberGenerator()
        return try seal(plaintext, context: context, key: key, using: &generator)
    }

    /// Opens an envelope found at the storage location described by `context`.
    ///
    /// Every structural and context check (`Envelope.parse`) runs before decryption. Decryption either returns the
    /// whole plaintext, in protected storage, or throws `CryptoError.authenticationFailed`; there is no partial
    /// result. `maximumLength` lets callers whose record is small (a wrapped key) refuse a large one before any
    /// copy (SEC9).
    public static func open(
        _ bytes: [UInt8],
        context: EnvelopeContext,
        key: EncryptionKey,
        maximumLength: Int = Envelope.maximumLength
    ) throws -> SecureBytes {
        guard context.keyID == key.keyID else {
            throw CryptoError.keyMismatch(expected: key.keyID, actual: context.keyID)
        }
        let envelope = try Envelope.parse(bytes, expecting: context, maximumLength: maximumLength)
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
