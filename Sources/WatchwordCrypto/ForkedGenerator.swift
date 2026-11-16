import Crypto
import Foundation

/// A generator for work that runs away from the actor that owns an injected generator (docs/02-architecture.md §14.1:
/// an import file's parse, off the session's actor so that `lock()` never waits for it). The owner's generator cannot
/// be shared across threads, and a copy of a seeded one would replay the owner's own stream, so the work gets a fork:
/// HMAC-SHA-256, in counter mode, under 32 bytes drawn from the owner's generator on its actor. Under
/// `SystemRandomNumberGenerator` the fork is as unpredictable as the system's; under a test's seeded generator it is
/// as reproducible.
///
/// For identifiers (item and field IDs) only. Key material, salts and nonces come from the injected generator itself,
/// on its owner's actor.
public struct ForkedGenerator: RandomNumberGenerator, Sendable {
    private let key: SymmetricKey
    private var counter: UInt64 = 0
    private var buffered: [UInt64] = []

    /// Draws the fork's key from `generator`, which advances it by four words.
    public init(forkingFrom generator: inout some RandomNumberGenerator) {
        var seed: [UInt8] = []
        for _ in 0..<4 {
            let word = generator.next()
            seed += (0..<8).map { UInt8(truncatingIfNeeded: word >> (8 * $0)) }
        }
        key = SymmetricKey(data: seed)
    }

    public mutating func next() -> UInt64 {
        if buffered.isEmpty {
            let block = (0..<8).map { UInt8(truncatingIfNeeded: counter >> (8 * $0)) }
            counter &+= 1
            let mac = Array(HMAC<SHA256>.authenticationCode(for: block, using: key))
            buffered = stride(from: 24, through: 0, by: -8).map { offset in
                mac[offset..<(offset + 8)].reversed().reduce(0) { $0 << 8 | UInt64($1) }
            }
        }
        return buffered.removeLast()
    }
}
