import Foundation
import SecureMemory

/// What the range API says about one password.
public enum PwnedPasswordResult: Hashable, Sendable, Codable {
    /// Not in the breach corpus as of the range's retrieval.
    case notFound
    /// In the corpus, seen this many times (saturating at `UInt32.max`).
    case found(occurrences: UInt32)

    public var isBreached: Bool {
        if case .found = self { return true }
        return false
    }
}

/// Every breached suffix under one prefix, as the range API returned it: public data, the same for everyone who asks
/// about that prefix.
///
/// Which prefixes a device holds is *not* public: each is twenty bits of the SHA-1 of one of the person's passwords,
/// enough to throw out all but about one in a million guesses offline. So a persisted set of ranges must be sealed
/// like the items themselves (`PwnedRangeCache`).
public struct PwnedRange: Hashable, Sendable {
    /// Suffix (18 bytes, packed as `PasswordDigest.suffix`) then the count (4 bytes, big-endian).
    static let entrySize = PasswordDigest.suffixByteCount + 4

    public let prefix: PwnedRangePrefix
    /// `entrySize` bytes per breached suffix, in the order the server listed them. No zero counts: padding is dropped
    /// while parsing.
    let packed: [UInt8]

    init(prefix: PwnedRangePrefix, packed: [UInt8]) {
        self.prefix = prefix
        self.packed = packed
    }

    /// Number of breached suffixes.
    public var count: Int {
        packed.count / Self.entrySize
    }

    /// Whether `digest` is in the range, or `nil` if the digest belongs to another prefix.
    ///
    /// Every entry is compared, in full, whether or not an earlier one matched, and the count is selected without a
    /// branch: the time taken says nothing about whether, or where, the suffix was found. The caller learns the
    /// answer for its own password and nothing about which other suffixes the range holds.
    func result(for digest: PasswordDigest) -> PwnedPasswordResult? {
        guard digest.prefix == prefix else { return nil }
        let suffix = digest.suffix
        var occurrences: UInt32 = 0
        var offset = 0
        while offset + Self.entrySize <= packed.count {
            var difference: UInt8 = 0
            for index in 0..<PasswordDigest.suffixByteCount {
                difference |= packed[offset + index] ^ suffix[index]
            }
            // All ones when the suffixes are equal, zero otherwise: 0 - 1 borrows through every bit, 1...255 do not.
            let mask = UInt32(truncatingIfNeeded: (Int32(difference) - 1) >> 31)
            var entryCount: UInt32 = 0
            for index in 0..<4 {
                entryCount = entryCount << 8 | UInt32(packed[offset + PasswordDigest.suffixByteCount + index])
            }
            occurrences |= entryCount & mask
            offset += Self.entrySize
        }
        return occurrences == 0 ? .notFound : .found(occurrences: occurrences)
    }
}

public enum PwnedRangeParseError: Error, Equatable, Sendable {
    /// More bytes than a range can be. Nothing is parsed: a truncated range could hide the one line that matters.
    case tooLarge
    /// More lines than a range can have.
    case tooManyLines
    /// Not one line in the body was a range line: an error page, a proxy's block page, an empty body.
    case nothingUsable
}

/// Reads a range response: `SUFFIX:COUNT` lines, 35 hexadecimal characters and a decimal count.
///
/// Lenient about what a well-meaning server or proxy might do to the text (either line ending, either case, stray
/// white space, a byte-order mark, blank lines, lines it does not understand, which are skipped), and bounded about
/// everything a hostile one might (total size, line count, digits in a count). The body is read once, front to back,
/// whatever it contains.
enum PwnedRangeParser {
    /// A range is about 2,000 lines of about 45 bytes today; this leaves room for the corpus to grow tenfold.
    static let maximumBytes = 2 * 1024 * 1024
    static let maximumLines = 50_000

    struct Outcome: Equatable {
        var range: PwnedRange
        /// Lines with a zero count: `Add-Padding` filler, discarded (PRD F9.1).
        var paddingLines: Int
        /// Lines that were not `SUFFIX:COUNT`.
        var skippedLines: Int
    }

    static func parse(_ body: [UInt8], prefix: PwnedRangePrefix) throws -> Outcome {
        guard body.count <= maximumBytes else { throw PwnedRangeParseError.tooLarge }
        var packed: [UInt8] = []
        var padding = 0
        var skipped = 0
        var lines = 0
        var start = body.startIndex
        // A UTF-8 byte-order mark, if a proxy added one.
        if body.count >= 3, body[0] == 0xEF, body[1] == 0xBB, body[2] == 0xBF { start = 3 }
        while start < body.endIndex {
            var end = start
            while end < body.endIndex, body[end] != UInt8(ascii: "\n") { end += 1 }
            let line = trimmed(body[start..<end])
            start = end + 1
            guard !line.isEmpty else { continue }
            lines += 1
            guard lines <= maximumLines else { throw PwnedRangeParseError.tooManyLines }
            switch entry(line) {
            case .entry(let suffix, let count):
                packed.append(contentsOf: suffix)
                packed.append(UInt8(truncatingIfNeeded: count >> 24))
                packed.append(UInt8(truncatingIfNeeded: count >> 16))
                packed.append(UInt8(truncatingIfNeeded: count >> 8))
                packed.append(UInt8(truncatingIfNeeded: count))
            case .padding:
                padding += 1
            case .malformed:
                skipped += 1
            }
        }
        guard !packed.isEmpty || padding > 0 else { throw PwnedRangeParseError.nothingUsable }
        return Outcome(range: PwnedRange(prefix: prefix, packed: packed), paddingLines: padding, skippedLines: skipped)
    }

    private enum Line {
        case entry(suffix: [UInt8], count: UInt32)
        case padding
        case malformed
    }

    private static func isBlank(_ byte: UInt8) -> Bool {
        byte == UInt8(ascii: " ") || byte == UInt8(ascii: "\t") || byte == UInt8(ascii: "\r")
    }

    private static func trimmed(_ slice: ArraySlice<UInt8>) -> ArraySlice<UInt8> {
        var slice = slice
        while let first = slice.first, isBlank(first) { slice = slice.dropFirst() }
        while let last = slice.last, isBlank(last) { slice = slice.dropLast() }
        return slice
    }

    private static func entry(_ line: ArraySlice<UInt8>) -> Line {
        let hexLength = 2 * PasswordDigest.suffixByteCount - 1
        guard line.count > hexLength + 1, line[line.startIndex + hexLength] == UInt8(ascii: ":") else {
            return .malformed
        }
        var suffix = [UInt8](repeating: 0, count: PasswordDigest.suffixByteCount)
        for index in 0..<hexLength {
            guard let nibble = HexNibble.value(line[line.startIndex + index]) else { return .malformed }
            suffix[index / 2] |= index % 2 == 0 ? nibble << 4 : nibble
        }
        let digits = trimmed(line[(line.startIndex + hexLength + 1)...])
        guard !digits.isEmpty else { return .malformed }
        // Saturating: a count beyond 32 bits, or with a thousand digits, is "very many", not an overflow.
        var count: UInt32 = 0
        for digit in digits {
            guard digit >= UInt8(ascii: "0"), digit <= UInt8(ascii: "9") else { return .malformed }
            let (product, overflowed) = count.multipliedReportingOverflow(by: 10)
            let (sum, carried) = product.addingReportingOverflow(UInt32(digit - UInt8(ascii: "0")))
            count = overflowed || carried ? UInt32.max : sum
        }
        return count == 0 ? .padding : .entry(suffix: suffix, count: count)
    }
}

/// A range and when it was fetched: what the prefix cache holds (PRD F9.1).
public struct CachedPwnedRange: Hashable, Sendable {
    public let range: PwnedRange
    public let fetchedAt: Date

    public init(range: PwnedRange, fetchedAt: Date) {
        self.range = range
        self.fetchedAt = fetchedAt
    }
}

public enum PwnedRangeCodecError: Error, Equatable, Sendable {
    case malformed
}

/// A compact form for the session to seal and store: `"WWPR"`, a version byte, the prefix in three bytes, the fetch
/// time as whole seconds since 1970 (eight bytes), the entry count (four bytes), then the entries. Big-endian.
///
/// Decoding checks every field and the exact length. It is meant for bytes the session has already authenticated; the
/// checks are there so that a damaged or foreign blob is a typed error, not a wrong answer.
extension CachedPwnedRange {
    private static let magic = Array("WWPR".utf8)
    private static let version: UInt8 = 1
    private static let headerSize = 4 + 1 + 3 + 8 + 4
    static let maximumEntries = PwnedRangeParser.maximumLines

    public func encoded() -> [UInt8] {
        var out = Self.magic
        out.append(Self.version)
        let prefix = range.prefix.value
        out.append(contentsOf: [UInt8(prefix >> 16 & 0xFF), UInt8(prefix >> 8 & 0xFF), UInt8(prefix & 0xFF)])
        let seconds = UInt64(bitPattern: Int64(fetchedAt.timeIntervalSince1970.rounded(.down)))
        out.append(contentsOf: (0..<8).map { UInt8(truncatingIfNeeded: seconds >> UInt64(8 * (7 - $0))) })
        let count = UInt32(range.count)
        out.append(contentsOf: (0..<4).map { UInt8(truncatingIfNeeded: count >> UInt32(8 * (3 - $0))) })
        out.append(contentsOf: range.packed)
        return out
    }

    public init(decoding bytes: [UInt8]) throws {
        guard bytes.count >= Self.headerSize, Array(bytes[0..<4]) == Self.magic, bytes[4] == Self.version else {
            throw PwnedRangeCodecError.malformed
        }
        let rawPrefix = UInt32(bytes[5]) << 16 | UInt32(bytes[6]) << 8 | UInt32(bytes[7])
        guard let prefix = PwnedRangePrefix(value: rawPrefix) else { throw PwnedRangeCodecError.malformed }
        var seconds: UInt64 = 0
        for index in 8..<16 { seconds = seconds << 8 | UInt64(bytes[index]) }
        var count: UInt32 = 0
        for index in 16..<20 { count = count << 8 | UInt32(bytes[index]) }
        guard count <= UInt32(Self.maximumEntries),
            bytes.count == Self.headerSize + Int(count) * PwnedRange.entrySize
        else { throw PwnedRangeCodecError.malformed }
        let packed = Array(bytes[Self.headerSize...])
        // What the parser would never have produced is not a cache entry: a zero count, or a set low nibble in the
        // suffix's last byte.
        var offset = 0
        while offset < packed.count {
            let last = packed[offset + PasswordDigest.suffixByteCount - 1]
            let counted = packed[(offset + PasswordDigest.suffixByteCount)..<(offset + PwnedRange.entrySize)]
            guard last & 0x0F == 0, counted.contains(where: { $0 != 0 }) else { throw PwnedRangeCodecError.malformed }
            offset += PwnedRange.entrySize
        }
        // Dates this far from now are not fetch times; refusing them also keeps the conversion below exact.
        let signed = Int64(bitPattern: seconds)
        guard signed >= 0, signed < 1 << 40 else { throw PwnedRangeCodecError.malformed }
        self.init(
            range: PwnedRange(prefix: prefix, packed: packed), fetchedAt: Date(timeIntervalSince1970: Double(signed)))
    }

    /// The length every sealed cache record is padded to: comfortably above the largest range the service serves
    /// today (about a thousand suffixes, 22 bytes each). A range larger than this is padded to the next multiple.
    /// Without it a record's length said how many breached suffixes its range holds, a public property that narrows
    /// which prefix it is (review §Z, Z89).
    public static let paddingBucket = 32 * 1024

    /// `encoded()` followed by zero bytes up to a multiple of `paddingBucket` (at least one bucket), so that what is
    /// sealed has the same length for every range up to the bucket.
    public func encodedPadded() -> [UInt8] {
        var out = encoded()
        let bucket = Self.paddingBucket
        let padded = max(bucket, (out.count + bucket - 1) / bucket * bucket)
        out.append(contentsOf: repeatElement(0, count: padded - out.count))
        return out
    }

    /// Reads what `encodedPadded()` wrote: the entry, exactly as `init(decoding:)` reads it, then nothing but zeros.
    public init(decodingPadded bytes: [UInt8]) throws {
        guard bytes.count >= Self.headerSize else { throw PwnedRangeCodecError.malformed }
        var count = 0
        for index in 16..<20 { count = count << 8 | Int(bytes[index]) }
        guard count <= Self.maximumEntries else { throw PwnedRangeCodecError.malformed }
        let length = Self.headerSize + count * PwnedRange.entrySize
        guard bytes.count >= length, bytes[length...].allSatisfy({ $0 == 0 }) else {
            throw PwnedRangeCodecError.malformed
        }
        try self.init(decoding: Array(bytes[..<length]))
    }
}

/// The prefix cache port (PRD F9.1, docs/02-architecture.md §13).
///
/// The cache exists for two reasons: not to ask twice, and so that an observer of the network cannot tell *when* a
/// password was looked at again. Expiry is the client's decision (`PwnedPasswordsClient.cacheLifetime`), made against
/// the time it is given; an implementation only stores and returns.
///
/// The ranges are public, but the *set of prefixes* is derived from the person's passwords (see `PwnedRange`), and
/// docs/adr/0005-hibp-while-locked.md allows nothing of that kind to outlive the keys in the clear, in memory or at
/// rest. So `HygieneEngine.lock()` calls `lock()` here, and after it returns no prefix may be readable without the
/// vault's keys: a cache that lives in memory forgets everything; one that persists must have sealed what it wrote
/// under a key that is gone when the vault locks, drops its plaintext copies, and reads and writes nothing until
/// the session unlocks it again. `CachedPwnedRange.encoded()` is the plaintext to seal. It should also stay on the
/// device: it is a cache.
///
/// Every entry belongs to a partition, the vault whose item's check fetched it (`HygieneEngine` passes the item's
/// vault ID), and answers checks for that vault only. A check answered from the cache costs no request and so no
/// pacing token, and its time is published with the vault's synced scan results; with one cache for every vault, a
/// member of a shared vault (A4) could plant items there and read from those times whether some password in a vault
/// they are not in shares a prefix with a candidate of theirs (review §Z, Z88). The same prefix in two vaults is two
/// entries, and two requests.
public protocol PwnedRangeCache: Sendable {
    /// The entry for `prefix` stored for `partition`, however old, or `nil`.
    func cachedRange(for prefix: PwnedRangePrefix, in partition: UUID) async -> CachedPwnedRange?
    /// Stores `entry` for `partition`, replacing any entry for the same prefix there. Failing to store is not an
    /// error.
    func store(_ entry: CachedPwnedRange, in partition: UUID) async
    /// Forgets the entry for `prefix` in `partition`, if there is one.
    func remove(_ prefix: PwnedRangePrefix, in partition: UUID) async
    /// Forgets everything, at rest included.
    func removeAll() async
    /// The vault is locking. When this returns, nothing the cache holds can be read without the vault's keys.
    func lock() async
}

/// A cache that lives as long as the vault is unlocked: the default until the session persists one, and what tests
/// use. It holds its entries in the clear, so `lock()` empties it.
///
/// Bounded twice over: beyond `capacity` prefixes, or `maximumBytes` of ranges, the oldest entries go. A range is
/// some tens of kilobytes today, so the defaults keep a large vault's worth; the byte limit is what holds if a server
/// starts sending ranges at the parser's megabyte ceiling.
public actor InMemoryPwnedRangeCache: PwnedRangeCache {
    public static let defaultCapacity = 512
    public static let defaultMaximumBytes = 32 * 1024 * 1024

    private let capacity: Int
    private let maximumBytes: Int
    private var entries: [PwnedRangeCacheKey: CachedPwnedRange] = [:]
    private var bytes = 0

    public init(
        capacity: Int = InMemoryPwnedRangeCache.defaultCapacity,
        maximumBytes: Int = InMemoryPwnedRangeCache.defaultMaximumBytes
    ) {
        self.capacity = max(1, capacity)
        self.maximumBytes = max(0, maximumBytes)
    }

    public func cachedRange(for prefix: PwnedRangePrefix, in partition: UUID) -> CachedPwnedRange? {
        entries[PwnedRangeCacheKey(partition: partition, prefix: prefix)]
    }

    public func store(_ entry: CachedPwnedRange, in partition: UUID) {
        let key = PwnedRangeCacheKey(partition: partition, prefix: entry.range.prefix)
        bytes -= entries[key]?.range.packed.count ?? 0
        entries[key] = entry
        bytes += entry.range.packed.count
        while entries.count > capacity || (bytes > maximumBytes && !entries.isEmpty) {
            // Oldest first; the key breaks ties so eviction is deterministic.
            let oldest = entries.min { lhs, rhs in
                if lhs.value.fetchedAt != rhs.value.fetchedAt { return lhs.value.fetchedAt < rhs.value.fetchedAt }
                return lhs.key < rhs.key
            }
            guard let oldest else { break }
            bytes -= oldest.value.range.packed.count
            entries[oldest.key] = nil
        }
    }

    public func remove(_ prefix: PwnedRangePrefix, in partition: UUID) {
        let key = PwnedRangeCacheKey(partition: partition, prefix: prefix)
        bytes -= entries.removeValue(forKey: key)?.range.packed.count ?? 0
    }

    public func removeAll() {
        entries.removeAll()
        bytes = 0
    }

    public func lock() {
        removeAll()
    }

    /// Every entry, ordered by prefix, then partition: what a persisting session would seal.
    public func snapshot() -> [CachedPwnedRange] {
        entries.sorted { $0.key < $1.key }.map(\.value)
    }

    public var count: Int {
        entries.count
    }
}

/// Where a cached range is filed: the partition (the vault whose check fetched it) and the prefix.
public struct PwnedRangeCacheKey: Hashable, Sendable, Comparable {
    public var partition: UUID
    public var prefix: PwnedRangePrefix

    public init(partition: UUID, prefix: PwnedRangePrefix) {
        self.partition = partition
        self.prefix = prefix
    }

    /// By prefix, then by the partition's bytes.
    public static func < (lhs: PwnedRangeCacheKey, rhs: PwnedRangeCacheKey) -> Bool {
        if lhs.prefix.value != rhs.prefix.value { return lhs.prefix.value < rhs.prefix.value }
        return lhs.partition.uuidString < rhs.partition.uuidString
    }
}
