import Foundation

#if canImport(Darwin)
    import Darwin
#elseif canImport(Glibc)
    import Glibc
#elseif canImport(Musl)
    import Musl
#endif

/// A fixed-length heap buffer for key material (docs/02-architecture.md §11, PRD SEC4).
///
/// - **Zeroisation.** `zeroise()` overwrites the whole allocation with `memset_s` (Darwin) or `explicit_bzero`
///   (glibc), which the optimiser may not elide, and `deinit` does the same before freeing.
/// - **Use after zeroise traps.** An all-zero buffer read back as a key is the worst key there is: a record sealed
///   with it is readable by anyone. A lock racing an in-flight encryption must therefore crash, not encrypt.
/// - **Page locking, best effort.** Storage is page-aligned and a whole number of pages, so one buffer never shares a
///   page with another. That matters because `mlock` does not nest: if two buffers shared a page, releasing either
///   would `munlock` the page under the other. Whether locking succeeded is reported, not assumed (`isPageLocked`);
///   iOS and a low `RLIMIT_MEMLOCK` can refuse it.
/// - **Excluded from core dumps** on Linux (`MADV_DONTDUMP`). Darwin has no equivalent.
/// - **Nothing prints.** `description`, `debugDescription` and the reflection mirror are redacted, so `print`,
///   `dump` and string interpolation cannot show the contents. There is deliberately no `Codable`, `Hashable` or
///   `Equatable`.
/// - **Copying out is possible, and should be named.** The type is a `Collection` only because CryptoKit's sealing
///   APIs take `DataProtocol`, so `Array(bytes)`, `Data(bytes)` and `elementsEqual` (which is not constant-time) do
///   compile. Production code must not use them: use `unprotectedCopy()` for the rare non-secret copy-out (a salt),
///   so every escape is searchable, and `constantTimeEquals` to compare (review finding R6).
///
/// Contents are fixed at initialisation; `zeroise()` is the only mutation. All access goes through a lock, so the
/// type is safe to share across concurrency domains.
public final class SecureBytes: @unchecked Sendable {
    /// Number of bytes of key material (not the size of the page-rounded allocation).
    public let count: Int

    /// Whether `mlock` accepted the allocation. Informational: a `false` here is not an error.
    public let isPageLocked: Bool

    // The base address is stored as an integer rather than as an `UnsafeMutableRawPointer` so the class has no stored
    // property of unsafe type. Each conversion back to a pointer is an `unsafe` expression, which keeps every pointer
    // use visible in review and to the `strict-memory-safety` CI job. The allocation lives exactly as long as `self`.
    private let address: UInt
    private let capacity: Int
    private let lock = NSRecursiveLock()
    private var zeroised = false
    /// Reads in progress. The lock is recursive, so without this a `zeroise()` on the same thread as a read (a lock
    /// handler run synchronously from inside a CryptoKit call) would wipe the bytes under the reader instead of
    /// trapping (review finding R7).
    private var activeReaders = 0
    let zeroisationProbe: ZeroisationProbe?

    static let pageSize = Int(getpagesize())

    private var base: UnsafeMutableRawPointer {
        unsafe (UnsafeMutableRawPointer(bitPattern: address)!)
    }

    /// Allocates `count` zeroed bytes of page-aligned storage.
    init(count: Int, zeroisationProbe: ZeroisationProbe?) {
        precondition(count >= 0 && count <= Int.max - SecureBytes.pageSize, "invalid SecureBytes count \(count)")
        let pageSize = SecureBytes.pageSize
        let capacity = Swift.max(1, (count + pageSize - 1) / pageSize) * pageSize
        let pointer = UnsafeMutableRawPointer.allocate(byteCount: capacity, alignment: pageSize)
        unsafe (pointer.initializeMemory(as: UInt8.self, repeating: 0, count: capacity))
        isPageLocked = unsafe (mlock(pointer, capacity)) == 0
        #if os(Linux)
            _ = unsafe (madvise(pointer, capacity, MADV_DONTDUMP))
        #endif
        self.address = UInt(bitPattern: pointer)
        self.capacity = capacity
        self.count = count
        self.zeroisationProbe = zeroisationProbe
    }

    deinit {
        wipeStorage()
        zeroisationProbe?.record(storageIsAllZero())
        if isPageLocked {
            _ = unsafe (munlock(base, capacity))
        }
        unsafe (base.deallocate())
    }

    /// `count` zero bytes.
    public convenience init(count: Int) {
        self.init(count: count, zeroisationProbe: nil)
    }

    /// Copies `bytes` into protected storage. The source is left as it was; prefer `init(wiping:)` when the caller
    /// owns the only copy.
    public convenience init<C: Collection>(copying bytes: C) where C.Element == UInt8 {
        self.init(copying: bytes, zeroisationProbe: nil)
    }

    convenience init<C: Collection>(copying bytes: C, zeroisationProbe: ZeroisationProbe?) where C.Element == UInt8 {
        self.init(count: bytes.count, zeroisationProbe: zeroisationProbe)
        unsafe (initializeStorage { destination in unsafe (destination.copyBytes(from: bytes)) })
    }

    /// Copies `source` into protected storage, then overwrites `source` with zeros.
    ///
    /// The wipe reaches the caller's buffer only if it is uniquely referenced; a shared copy-on-write buffer is copied
    /// before being written, which leaves the other references untouched. The stores cannot be optimised away because
    /// `source` stays alive in the caller.
    public convenience init(wiping source: inout [UInt8]) {
        self.init(copying: source)
        for index in source.indices {
            source[index] = 0
        }
    }

    /// `Data` variant of `init(wiping:)`, for values CryptoKit hands back (`rawRepresentation`, `open`).
    public convenience init(wiping source: inout Data) {
        self.init(copying: source)
        source.resetBytes(in: source.startIndex..<source.endIndex)
    }

    /// `count` bytes drawn straight into protected storage, with no intermediate array.
    ///
    /// Production passes `SystemRandomNumberGenerator`; tests pass a seeded generator (CLAUDE.md, "Randomness is
    /// injected").
    public convenience init<R: RandomNumberGenerator>(randomCount count: Int, using generator: inout R) {
        self.init(count: count, zeroisationProbe: nil)
        unsafe (initializeStorage { destination in
            var offset = 0
            while offset < count {
                let word = generator.next()
                let take = Swift.min(8, count - offset)
                for i in 0..<take {
                    unsafe (destination[offset + i] = UInt8(truncatingIfNeeded: word >> (8 * i)))
                }
                offset += take
            }
        })
    }

    /// The concatenation of `parts`, built directly in protected storage.
    public static func concatenating(_ parts: [SecureBytes]) -> SecureBytes {
        let result = SecureBytes(count: parts.reduce(0) { $0 + $1.count }, zeroisationProbe: nil)
        unsafe (result.initializeStorage { destination in
            var offset = 0
            for part in parts {
                let slot = unsafe (UnsafeMutableRawBufferPointer(rebasing: destination[offset..<(offset + part.count)]))
                unsafe (part.withLiveBytes(slot.copyMemory(from:)))
                offset += part.count
            }
        })
        return result
    }

    /// A protected copy of `range`.
    public func extracting(_ range: Range<Int>) -> SecureBytes {
        precondition(range.lowerBound >= 0 && range.upperBound <= count, "range \(range) outside 0..<\(count)")
        let result = SecureBytes(count: range.count, zeroisationProbe: nil)
        unsafe (result.initializeStorage { destination in
            unsafe (withLiveBytes { source in
                unsafe (destination.copyMemory(from: UnsafeRawBufferPointer(rebasing: source[range])))
            })
        })
        return result
    }

    /// An ordinary array with the same bytes, which cannot be zeroised. For values that are not secret (a salt) or
    /// that must leave protected storage by design; named so that every such escape is searchable.
    public func unprotectedCopy() -> [UInt8] {
        unsafe (withLiveBytes { unsafe (Array($0)) })
    }

    /// Compares contents without an early exit on the first differing byte (`ConstantTime`).
    public func constantTimeEquals(_ other: SecureBytes) -> Bool {
        if self === other { return unsafe (withLiveBytes { _ in true }) }
        // Lock in a fixed (address) order so two threads comparing a with b and b with a cannot deadlock.
        let (first, second) = address < other.address ? (self, other) : (other, self)
        return
            unsafe (first.withLiveBytes { a in
                unsafe (second.withLiveBytes { b in unsafe (ConstantTime.equal(a, b)) })
            })
    }

    /// Overwrites the storage with zeros. Idempotent; any later read traps, and so does zeroising during a read on the
    /// same thread. (Another thread's `zeroise()` waits for the read to finish.)
    public func zeroise() {
        lock.lock()
        defer { lock.unlock() }
        precondition(activeReaders == 0, "SecureBytes zeroised while being read")
        wipeStorage()
        zeroised = true
    }

    public var isZeroised: Bool {
        lock.lock()
        defer { lock.unlock() }
        return zeroised
    }

    /// Write access to the storage while a value is being constructed, before it is visible to anyone else. Only
    /// initializers and factory functions in this module call it; contents are fixed once they return.
    func initializeStorage(_ body: (UnsafeMutableRawBufferPointer) throws -> Void) rethrows {
        lock.lock()
        defer { lock.unlock() }
        try unsafe (body(UnsafeMutableRawBufferPointer(start: base, count: count)))
    }

    /// Runs `body` over the live bytes while holding the lock.
    func withLiveBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        lock.lock()
        defer { lock.unlock() }
        precondition(!zeroised, "SecureBytes read after zeroise(); refusing to hand out an all-zero key")
        activeReaders += 1
        defer { activeReaders -= 1 }
        return try unsafe (body(UnsafeRawBufferPointer(start: base, count: count)))
    }

    /// Test seam: inspects the whole allocation without the use-after-zeroise trap
    /// (docs/04-test-plan.md §6.1, "Zeroisation").
    func storageIsAllZero() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let storage = unsafe (UnsafeRawBufferPointer(start: base, count: capacity))
        return unsafe (storage.allSatisfy { $0 == 0 })
    }

    /// Test seam for the page-isolation property described in the type's documentation.
    var storageIsPageIsolated: Bool {
        address % UInt(SecureBytes.pageSize) == 0 && capacity % SecureBytes.pageSize == 0
    }

    private func wipeStorage() {
        unsafe (SecureBytes.wipe(UnsafeMutableRawBufferPointer(start: base, count: capacity)))
    }

    private static func wipe(_ buffer: UnsafeMutableRawBufferPointer) {
        guard let start = buffer.baseAddress, buffer.count > 0 else { return }
        #if canImport(Darwin)
            _ = unsafe (memset_s(start, buffer.count, 0, buffer.count))
        #else
            unsafe (explicit_bzero(start, buffer.count))
        #endif
    }
}

extension SecureBytes: RandomAccessCollection {
    public var startIndex: Int { 0 }
    public var endIndex: Int { count }

    public subscript(position: Int) -> UInt8 {
        precondition(position >= 0 && position < count, "SecureBytes index \(position) out of range")
        return unsafe (withLiveBytes { unsafe ($0[position]) })
    }

    public func withContiguousStorageIfAvailable<R>(_ body: (UnsafeBufferPointer<UInt8>) throws -> R) rethrows -> R? {
        try unsafe (withLiveBytes { raw in try unsafe (body(raw.assumingMemoryBound(to: UInt8.self))) })
    }
}

/// Lets CryptoKit consume key material directly (`SymmetricKey(data:)`, `PrivateKey(rawRepresentation:)`), without an
/// intermediate unprotected copy on our side.
extension SecureBytes: ContiguousBytes {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try unsafe (withLiveBytes(body))
    }
}

/// Lets CryptoKit seal key material (`AES.GCM.seal`, `HPKE.Sender.seal`) without an intermediate unprotected copy.
extension SecureBytes: DataProtocol {
    public var regions: CollectionOfOne<SecureBytes> { CollectionOfOne(self) }
}

extension SecureBytes: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "SecureBytes(\(count) bytes, redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .class) }
}

/// Test seam: records whether a buffer's storage read all-zero at the moment it was released, which is the only way
/// to observe `deinit` zeroisation without reading freed memory.
final class ZeroisationProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var observation: Bool?

    func record(_ storageWasAllZero: Bool) {
        lock.lock()
        observation = storageWasAllZero
        lock.unlock()
    }

    var observedAllZeroAtRelease: Bool? {
        lock.lock()
        defer { lock.unlock() }
        return observation
    }
}
