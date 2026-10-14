import Foundation

/// Why a cryptographic operation refused. Typed so tests assert on the reason (CLAUDE.md, "Errors, not optionals").
public enum CryptoError: Error, Equatable, Sendable {
    /// An AEAD or HPKE tag did not verify: wrong key, wrong password or Secret Key, or tampered ciphertext. One case
    /// on purpose — which of those it was is not distinguishable from the ciphertext, and must not appear to be.
    case authenticationFailed
    case invalidKeyLength(Int)
    /// The context names a different key from the one supplied.
    case keyMismatch(expected: UUID, actual: UUID)
    /// The random number generator produced a nonce this sealer already used. A working CSPRNG never does this in
    /// practice, so it means the generator is broken; refusing beats encrypting two messages under one nonce.
    case nonceReuseDetected
    /// The sealer reached `RecordSealer.maximumSeals`; start a new one (and keep rotating keys well before 2^32).
    case sealLimitReached
    case emptyPassword
    case saltLengthMismatch(expected: Int, actual: Int)
    case signatureInvalid
    case malformedKeyset
    case unsupportedKeysetVersion(UInt8)
    /// Wrong length, not a curve point, or (X25519) a low-order point whose shared secret is all zeros.
    case invalidPublicKey
    /// A vault-key grant addressed to someone else, or claiming a sender other than the one expected.
    case grantMismatch
}
