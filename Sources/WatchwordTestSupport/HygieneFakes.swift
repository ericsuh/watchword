import Foundation
import WatchwordHygiene

public enum FakeHTTPError: Error, Equatable, Sendable {
    /// The test scripted no reply for this request.
    case nothingScripted
    /// A scripted transport failure: offline, timeout, TLS.
    case offline
}

/// The `HTTPClient` fake (docs/04-test-plan.md §2, §6.6): it records every request exactly as a real adapter would
/// have sent it, so a test can assert on everything that would have left the device, and it never touches a network.
///
/// Replies come from a queue first, then from the handler, and with neither the request fails: an unexpected
/// request is a test failure, not a silent 200.
public actor FakeHTTPClient: HTTPClient {
    public enum Reply: Sendable {
        case response(HTTPResponse)
        case failure
    }

    public private(set) var requests: [HTTPRequest] = []
    private var queue: [Reply] = []
    private var handler: (@Sendable (HTTPRequest) -> Reply)?
    private var holding = false
    private var held: [CheckedContinuation<Void, Never>] = []
    private var arrivals: [CheckedContinuation<Void, Never>] = []

    public init() {}

    public func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        requests.append(request)
        if holding {
            await withCheckedContinuation { continuation in
                held.append(continuation)
                for arrival in arrivals { arrival.resume() }
                arrivals.removeAll()
            }
        }
        let reply: Reply
        if !queue.isEmpty {
            reply = queue.removeFirst()
        } else if let handler {
            reply = handler(request)
        } else {
            throw FakeHTTPError.nothingScripted
        }
        switch reply {
        case .response(let response): return response
        case .failure: throw FakeHTTPError.offline
        }
    }

    // MARK: Scripting

    public func enqueue(_ replies: Reply...) {
        queue.append(contentsOf: replies)
    }

    public func enqueue(status: Int, headers: [String: String] = [:], body: String = "") {
        queue.append(.response(HTTPResponse(status: status, headers: headers, body: Array(body.utf8))))
    }

    /// Answers every request the queue does not.
    public func respond(_ handler: @escaping @Sendable (HTTPRequest) -> Reply) {
        self.handler = handler
    }

    /// Makes requests wait, mid-flight, until `release()`: how a test puts a lock between a request and its response
    /// without sleeping.
    public func hold() {
        holding = true
    }

    /// Returns once a request is waiting.
    public func waitForHeldRequest() async {
        guard held.isEmpty else { return }
        await withCheckedContinuation { arrivals.append($0) }
    }

    public func release() {
        holding = false
        for continuation in held { continuation.resume() }
        held.removeAll()
    }

    public func forgetRequests() {
        requests.removeAll()
    }
}

/// A prefix cache that counts what is asked of it and stored in it, so a test can say "nothing was persisted", and
/// that can hold a store in mid-air, so a test can put a lock between a check and its entry reaching the cache.
public actor RecordingPwnedRangeCache: PwnedRangeCache {
    public private(set) var entries: [PwnedRangeCacheKey: CachedPwnedRange] = [:]
    public private(set) var lookups: [PwnedRangePrefix] = []
    /// The partition of each lookup, in order (`lookups` holds the prefixes).
    public private(set) var lookupPartitions: [UUID] = []
    public private(set) var stores: [CachedPwnedRange] = []
    public private(set) var locks = 0
    private var holding = false
    private var held: [CheckedContinuation<Void, Never>] = []
    private var arrivals: [CheckedContinuation<Void, Never>] = []

    public init() {}

    public func cachedRange(for prefix: PwnedRangePrefix, in partition: UUID) -> CachedPwnedRange? {
        lookups.append(prefix)
        lookupPartitions.append(partition)
        return entries[PwnedRangeCacheKey(partition: partition, prefix: prefix)]
    }

    public func store(_ entry: CachedPwnedRange, in partition: UUID) async {
        stores.append(entry)
        if holding {
            await withCheckedContinuation { continuation in
                held.append(continuation)
                for arrival in arrivals { arrival.resume() }
                arrivals.removeAll()
            }
        }
        // Written after the wait: the worst case, an entry that lands after whatever happened meanwhile.
        entries[PwnedRangeCacheKey(partition: partition, prefix: entry.range.prefix)] = entry
    }

    public func remove(_ prefix: PwnedRangePrefix, in partition: UUID) {
        entries[PwnedRangeCacheKey(partition: partition, prefix: prefix)] = nil
    }

    public func removeAll() {
        entries.removeAll()
    }

    public func lock() {
        locks += 1
        entries.removeAll()
    }

    /// Plants an entry without counting it as a store: a cache file someone else wrote.
    public func plant(_ entry: CachedPwnedRange, under prefix: PwnedRangePrefix, in partition: UUID) {
        entries[PwnedRangeCacheKey(partition: partition, prefix: prefix)] = entry
    }

    /// Makes stores wait, before they write, until `releaseStores()`.
    public func holdStores() {
        holding = true
    }

    /// Returns once a store is waiting.
    public func waitForHeldStore() async {
        guard held.isEmpty else { return }
        await withCheckedContinuation { arrivals.append($0) }
    }

    public func releaseStores() {
        holding = false
        for continuation in held { continuation.resume() }
        held.removeAll()
    }
}

/// A checkpoint a test can stop at: `HygieneEngine.unlock` awaits one between items, and a test that passes
/// `gate.pass` there can hold the unlock after a chosen number of items, act (lock, save, cancel) while it is held,
/// and let it go, all without sleeping.
public actor CheckpointGate {
    public private(set) var passes = 0
    private let holdAt: Int
    private var arrived = false
    private var held: CheckedContinuation<Void, Never>?
    private var arrival: CheckedContinuation<Void, Never>?

    /// - Parameter passes: the pass to hold at, counting from one.
    public init(holdingAfter passes: Int) {
        holdAt = passes
    }

    /// The checkpoint itself.
    public func pass() async {
        passes += 1
        guard passes == holdAt else { return }
        arrived = true
        arrival?.resume()
        arrival = nil
        await withCheckedContinuation { held = $0 }
    }

    /// Returns once the checkpoint is holding.
    public func waitUntilHeld() async {
        guard !arrived else { return }
        await withCheckedContinuation { arrival = $0 }
    }

    public func release() {
        held?.resume()
        held = nil
    }
}

/// A stand-in for the Pwned Passwords range API, answering from a table of breached SHA-1 digests in the format the
/// real service documents: `SUFFIX:COUNT` lines separated by CRLF, with `Add-Padding` filler (zero counts) bringing
/// each response to between 800 and 1,000 lines.
///
/// The digests in `digests` were computed with Python's `hashlib.sha1`, not with the code under test (CLAUDE.md,
/// "Known-answer vectors").
public struct SimulatedPwnedPasswords: Sendable {
    /// `hashlib.sha1(password.encode()).hexdigest().upper()` for the passwords the hygiene tests use.
    public static let digests: [String: String] = [
        "password": "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8",
        "123456": "7C4A8D09CA3762AF61E59520943DC26494F8941B",
        "correct horse battery staple": "ABF7AAD6438836DBE526AA231ABDE2D0EEF74D42",
        "hunter2": "F3BBBD66A63D4BF1747940578EC3D0103530E21D",
        "Tr0ub4dor&3": "874572E7A5AE6A49466A6AC578B98ADBA78C6AA6",
        "qwerty": "B1B3773A05C0ED0176787A4F1574FF0075F7521E",
        "letmein": "B7A875FC1EA228B9061041B7CEC4BD3C52AB3CE3",
        "x7#Vq9!mLp2$Zr8@Wn4&": "DB2F277AB9202A2167238FC5AB5ECF5B94B21EED",
        "unbreached-Zq7!example": "D5D436F76F7638DE34350D88821F6BEB3DA44113",
        "pässwörd": "F517DDF1D32A112FF1AD55C66D1B12CB38E7E8F7",
        "": "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
        "shared-secret-1": "D23097AE337C270478913E88AFAE326F84885615",
        "another-Unique_9": "E5B7F870256384542688C6AAD2595A3664571975",
        "p@ssw0rd": "57B2AD99044D337197C0C39FD3823568FF81E48A",
        "iloveyou": "EE8D8728F435FD550F83852AABAB5234CE1DA528",
        "monkey": "AB87D24BDC7452E55738DEB5F868E1F16DEA5ACE",
        "dragon": "AF8978B1797B72ACFFF9595A5A2A373EC3D9106D",
        "V3ry-Un1que+Phrase": "6DB52D94925CBB143879B6F0E460F30EDAED359C",
        "second-password-in-item": "7EFC4E2731605B473265E187B6B62D436BD80270",
        "abc123": "6367C48DD193D56EA7B0BAAD25B19455E529F5EE",
    ]

    /// Upper-case SHA-1 hex to the number of times it was seen.
    public let breached: [String: UInt32]
    public let seed: UInt64
    public let padded: Bool

    /// - Parameter breached: passwords from `digests` and how often each was seen.
    public init(breached: [String: UInt32], seed: UInt64 = 1, padded: Bool = true) {
        var table: [String: UInt32] = [:]
        for (password, count) in breached {
            guard let digest = Self.digests[password] else {
                preconditionFailure("no independent SHA-1 recorded for this test password; add it to digests")
            }
            table[digest] = count
        }
        self.breached = table
        self.seed = seed
        self.padded = padded
    }

    /// The response body for one prefix: the table's entries under it, some other real-looking entries, and padding.
    public func body(forPrefix prefix: String) -> String {
        var generator = SeededGenerator(seed: seed ^ UInt64(prefix.hashValueStable))
        var lines: [String] = []
        for (digest, count) in breached where digest.hasPrefix(prefix) {
            lines.append("\(digest.dropFirst(5)):\(count)")
        }
        for _ in 0..<40 {
            lines.append("\(Self.randomSuffix(&generator)):\(1 + Int(generator.next() % 5000))")
        }
        if padded {
            let total = 800 + Int(generator.next() % 201)
            while lines.count < total {
                lines.append("\(Self.randomSuffix(&generator)):0")
            }
        }
        // The service does not promise an order; shuffle so no test depends on one.
        lines.shuffle(using: &generator)
        return lines.joined(separator: "\r\n")
    }

    /// Answers a request the way the service would, including refusing anything that is not a range request.
    public func reply(to request: HTTPRequest) -> FakeHTTPClient.Reply {
        let marker = "/range/"
        guard request.url.absoluteString.hasPrefix("https://api.pwnedpasswords.com" + marker),
            request.headers["User-Agent"] != nil
        else { return .response(HTTPResponse(status: 400)) }
        let prefix = String(request.url.path.dropFirst(marker.count))
        guard prefix.count == 5, prefix.allSatisfy(\.isHexDigit) else { return .response(HTTPResponse(status: 400)) }
        return .response(
            HTTPResponse(
                status: 200, headers: ["Content-Type": "text/plain"], body: Array(body(forPrefix: prefix).utf8)))
    }

    public static func randomSuffix<G: RandomNumberGenerator>(_ generator: inout G) -> String {
        let digits = Array("0123456789ABCDEF")
        return String((0..<35).map { _ in digits[Int(generator.next() % 16)] })
    }
}

extension String {
    /// A hash that is the same in every process (unlike `hashValue`), for seeding.
    fileprivate var hashValueStable: UInt64 {
        var hash: UInt64 = 0xCBF2_9CE4_8422_2325
        for byte in utf8 {
            hash = (hash ^ UInt64(byte)) &* 0x0000_0100_0000_01B3
        }
        return hash
    }
}
