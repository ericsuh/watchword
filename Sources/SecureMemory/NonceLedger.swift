import Foundation

/// Every 96-bit AEAD nonce issued under one key, shared by every copy of that key (docs/02-architecture.md §5).
///
/// The ledger belongs to the key rather than to whoever happens to be sealing with it, so a repeat is caught across
/// all of them: record seals, key wraps, and copies of the key value. With a working CSPRNG a repeat never happens;
/// the ledger is a tripwire for a broken or mis-injected generator, which is the realistic way GCM nonces repeat.
/// It lives in `SecureMemory` only because a thread-safe class is an unchecked `Sendable` claim, and ADR 0001
/// confines those here; it contains no unsafe code.
public final class NonceLedger: @unchecked Sendable {
    public enum Claim: Equatable, Sendable {
        case fresh
        case reused
        case limitReached
    }

    /// Bounds the ledger at roughly 32 MiB. A key that reaches it must be rotated; NIST SP 800-38D §8.3 caps random
    /// 96-bit nonces at 2^32 per key across all devices, so one device sealing 2^20 under a key is already a signal.
    public static let capacity = 1 << 20

    private struct Nonce: Hashable {
        let high: UInt64
        let low: UInt32
    }

    private let lock = NSLock()
    private var issued: Set<Nonce> = []

    public init() {}

    /// Records `nonce` (12 bytes) unless it was already issued or the ledger is full.
    public func claim(_ nonce: [UInt8]) -> Claim {
        precondition(nonce.count == 12, "AEAD nonces are 12 bytes")
        let high = nonce[0..<8].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        let low = nonce[8..<12].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        lock.lock()
        defer { lock.unlock() }
        guard issued.count < NonceLedger.capacity else { return .limitReached }
        return issued.insert(Nonce(high: high, low: low)).inserted ? .fresh : .reused
    }

    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return issued.count
    }
}
