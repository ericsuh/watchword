import Foundation
import SecureMemory
import Testing
import WatchwordTestSupport

@testable import WatchwordHygiene

/// Fixtures here are written to the range API's documented response format (`SUFFIX:COUNT`, CRLF, zero-count
/// padding). They were not captured from the live service: it is not reachable from the sessions these tests are
/// developed in, and tests never call it (docs/04-test-plan.md §6.6). Digests come from Python's `hashlib`.
enum RangeFixtures {
    static let prefix = PwnedRangePrefix("5BAA6")!
    /// SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8.
    static let passwordSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

    static let unpadded = [
        "003D68EB55068C33ACE09247EE4C639306B:3",
        "1D2DA4053E34E76F6576ED1DA63134B5E2A:2",
        "\(passwordSuffix):10434004",
        "1E4C9B93F3F0682250B6CF8331B7EE68FD9:7",
        "FFB5E6B1B5D2C4D4B5C1F3E1D3A1A0C9E8F:1",
    ].joined(separator: "\r\n")

    static let padded =
        unpadded + "\r\n"
        + [
            "0A1B2C3D4E5F60718293A4B5C6D7E8F9012:0",
            "9F8E7D6C5B4A39281706F5E4D3C2B1A0987:0",
            "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDE:0",
        ].joined(separator: "\r\n")

    static func response(_ body: String, status: Int = 200, headers: [String: String] = [:]) -> FakeHTTPClient.Reply {
        .response(HTTPResponse(status: status, headers: headers, body: Array(body.utf8)))
    }
}

@Suite("Pwned Passwords: digest and prefix")
struct PasswordDigestTests {
    @Test(
        "the prefix is the first five hex characters of SHA-1, as hashlib computes it",
        arguments: SimulatedPwnedPasswords.digests.sorted { $0.key < $1.key })
    func prefixMatchesIndependentSHA1(_ vector: (key: String, value: String)) {
        let digest = PasswordDigest(utf8Of: vector.key)
        #expect(digest.prefix.description == String(vector.value.prefix(5)))
    }

    @Test(
        "the suffix is the other thirty-five, found in a range that lists it and not in one that does not",
        arguments: SimulatedPwnedPasswords.digests.sorted { $0.key < $1.key })
    func suffixMatchesIndependentSHA1(_ vector: (key: String, value: String)) throws {
        let digest = PasswordDigest(utf8Of: vector.key)
        let suffix = String(vector.value.dropFirst(5))
        let listed = try PwnedRangeParser.parse(Array("\(suffix):42".utf8), prefix: digest.prefix).range
        #expect(listed.result(for: digest) == .found(occurrences: 42))
        // One nibble different, in the last place: the comparison covers all thirty-five.
        let last = suffix.last == "0" ? "1" : "0"
        let near = try PwnedRangeParser.parse(Array("\(suffix.dropLast())\(last):42".utf8), prefix: digest.prefix)
        #expect(near.range.result(for: digest) == .notFound)
    }

    @Test("hashing SecureBytes gives the same digest as hashing the string")
    func secureBytesInput() throws {
        let fromBytes = PasswordDigest(password: SecureBytes(copying: Array("password".utf8)))
        #expect(fromBytes.prefix == RangeFixtures.prefix)
        let range = try PwnedRangeParser.parse(Array(RangeFixtures.unpadded.utf8), prefix: RangeFixtures.prefix).range
        #expect(range.result(for: fromBytes) == .found(occurrences: 10_434_004))
    }

    @Test("a prefix parses from exactly five hex digits and prints in upper case")
    func prefixParsing() {
        #expect(PwnedRangePrefix("5baa6")?.description == "5BAA6")
        #expect(PwnedRangePrefix("00000")?.value == 0)
        #expect(PwnedRangePrefix("FFFFF")?.value == 0xFFFFF)
        for bad in ["", "5BAA", "5BAA61", "5BAAG", "5BAA ", "５BAA6", "5BAA6\n"] {
            #expect(PwnedRangePrefix(bad) == nil)
        }
        #expect(PwnedRangePrefix(value: 1 << 20) == nil)
    }

    @Test("a digest prints and reflects as nothing")
    func redaction() {
        let digest = PasswordDigest(utf8Of: "password")
        #expect("\(digest)" == "PasswordDigest(redacted)")
        #expect(String(reflecting: digest) == "PasswordDigest(redacted)")
        #expect(Mirror(reflecting: digest).children.isEmpty)
        var dumped = ""
        dump(digest, to: &dumped)
        #expect(!dumped.contains("1E4C"))
    }

    @Test("a digest of another prefix gets no answer from a range")
    func wrongPrefix() throws {
        let range = try PwnedRangeParser.parse(Array(RangeFixtures.unpadded.utf8), prefix: RangeFixtures.prefix).range
        #expect(range.result(for: PasswordDigest(utf8Of: "123456")) == nil)
    }
}

@Suite("Pwned Passwords: range parser")
struct PwnedRangeParserTests {
    func parse(_ body: String) throws -> PwnedRangeParser.Outcome {
        try PwnedRangeParser.parse(Array(body.utf8), prefix: RangeFixtures.prefix)
    }

    @Test("an unpadded response parses to its entries")
    func unpadded() throws {
        let outcome = try parse(RangeFixtures.unpadded)
        #expect(outcome.range.count == 5)
        #expect(outcome.paddingLines == 0)
        #expect(outcome.skippedLines == 0)
        #expect(outcome.range.result(for: PasswordDigest(utf8Of: "password")) == .found(occurrences: 10_434_004))
    }

    @Test("zero-count padding lines are discarded")
    func padded() throws {
        let outcome = try parse(RangeFixtures.padded)
        #expect(outcome.range.count == 5)
        #expect(outcome.paddingLines == 3)
        #expect(outcome.range == (try parse(RangeFixtures.unpadded)).range)
    }

    @Test("a password whose own line is padding is not breached")
    func ownLineIsPadding() throws {
        let outcome = try parse("\(RangeFixtures.passwordSuffix):0\r\nABCDEFABCDEFABCDEFABCDEFABCDEFABCDE:5")
        #expect(outcome.range.result(for: PasswordDigest(utf8Of: "password")) == .notFound)
    }

    @Test("line endings, case, white space, blank lines and a byte-order mark are tolerated")
    func lenient() throws {
        let body =
            "\u{FEFF}\n\n  \(RangeFixtures.passwordSuffix.lowercased()) : 12 \r\n\r\n"
            + "\t1D2DA4053E34E76F6576ED1DA63134B5E2A:2\n"
        let outcome = try parse(body)
        #expect(outcome.range.count == 1)
        #expect(outcome.skippedLines == 1)
        #expect(outcome.range.result(for: PasswordDigest(utf8Of: "password")) == .notFound)
    }

    @Test("lower-case suffixes match")
    func lowerCase() throws {
        let outcome = try parse("\(RangeFixtures.passwordSuffix.lowercased()):9")
        #expect(outcome.range.result(for: PasswordDigest(utf8Of: "password")) == .found(occurrences: 9))
    }

    @Test(
        "malformed lines are skipped, and the good lines around them still count",
        arguments: [
            "not a range line",
            "1E4C9B93F3F0682250B6CF8331B7EE68FD:5",
            "1E4C9B93F3F0682250B6CF8331B7EE68FD88:5",
            "1E4C9B93F3F0682250B6CF8331B7EE68FDG:5",
            "\(RangeFixtures.passwordSuffix)",
            "\(RangeFixtures.passwordSuffix):",
            "\(RangeFixtures.passwordSuffix):-1",
            "\(RangeFixtures.passwordSuffix):1e9",
            "\(RangeFixtures.passwordSuffix):12:13",
            "\(RangeFixtures.passwordSuffix);12",
            ":",
            "<html><body>blocked</body></html>",
            "\u{0}\u{1}\u{2}",
        ])
    func malformedLineSkipped(_ line: String) throws {
        let good = "1D2DA4053E34E76F6576ED1DA63134B5E2A:2"
        let outcome = try parse("\(good)\r\n\(line)\r\n003D68EB55068C33ACE09247EE4C639306B:3")
        #expect(outcome.range.count == 2)
        #expect(outcome.skippedLines == 1)
        #expect(outcome.range.result(for: PasswordDigest(utf8Of: "password")) == .notFound)
    }

    @Test("a body with no range line at all is an error, not 'not breached'")
    func nothingUsable() {
        for body in ["", "\r\n\r\n", "<html>captive portal</html>", "{\"error\": true}", "\u{FEFF}"] {
            #expect(throws: PwnedRangeParseError.nothingUsable) { try parse(body) }
        }
    }

    @Test("a body of padding only is a valid, empty range")
    func paddingOnly() throws {
        let outcome = try parse("0A1B2C3D4E5F60718293A4B5C6D7E8F9012:0")
        #expect(outcome.range.count == 0)
        #expect(outcome.range.result(for: PasswordDigest(utf8Of: "password")) == .notFound)
    }

    @Test("counts saturate instead of overflowing")
    func hugeCounts() throws {
        let digest = PasswordDigest(utf8Of: "password")
        #expect(
            try parse("\(RangeFixtures.passwordSuffix):4294967295").range.result(for: digest)
                == .found(occurrences: UInt32.max))
        #expect(
            try parse("\(RangeFixtures.passwordSuffix):4294967296").range.result(for: digest)
                == .found(occurrences: UInt32.max))
        let enormous = String(repeating: "9", count: 5000)
        #expect(
            try parse("\(RangeFixtures.passwordSuffix):\(enormous)").range.result(for: digest)
                == .found(occurrences: UInt32.max))
        // Leading zeros are a number like any other.
        #expect(
            try parse("\(RangeFixtures.passwordSuffix):000017").range.result(for: digest) == .found(occurrences: 17))
        #expect(try parse("\(RangeFixtures.passwordSuffix):0000").paddingLines == 1)
    }

    @Test("a body over the size limit is refused whole")
    func tooLarge() {
        let line = "0A1B2C3D4E5F60718293A4B5C6D7E8F9012:1\r\n"
        let body = [UInt8](repeating: UInt8(ascii: "A"), count: PwnedRangeParser.maximumBytes + 1)
        #expect(throws: PwnedRangeParseError.tooLarge) {
            try PwnedRangeParser.parse(body, prefix: RangeFixtures.prefix)
        }
        // Exactly at the limit is still read; it is the line cap that stops this one.
        let many = String(repeating: line, count: PwnedRangeParser.maximumBytes / line.utf8.count)
        #expect(throws: PwnedRangeParseError.tooManyLines) { try parse(many) }
    }

    @Test("more lines than a range can have is refused, even when each is tiny")
    func tooManyLines() {
        let body = String(repeating: "x\n", count: PwnedRangeParser.maximumLines + 1)
        #expect(throws: PwnedRangeParseError.tooManyLines) { try parse(body) }
    }

    @Test("a range at the line limit parses, and a megabyte without a newline is one skipped line")
    func atTheLimits() throws {
        var generator = SeededGenerator(seed: 7)
        var lines: [String] = []
        for _ in 0..<PwnedRangeParser.maximumLines {
            lines.append("\(SimulatedPwnedPasswords.randomSuffix(&generator)):1")
        }
        let outcome = try parse(lines.joined(separator: "\n"))
        #expect(outcome.range.count == PwnedRangeParser.maximumLines)

        let blob = String(repeating: "A", count: 1_000_000) + "\n\(RangeFixtures.passwordSuffix):3"
        let other = try parse(blob)
        #expect(other.skippedLines == 1)
        #expect(other.range.count == 1)
    }

    @Test("a simulated padded response has between 800 and 1,000 lines and parses to its real entries")
    func simulatedResponse() throws {
        let server = SimulatedPwnedPasswords(breached: ["password": 10_434_004])
        let body = server.body(forPrefix: "5BAA6")
        let lineCount = body.split(separator: "\r\n").count
        #expect((800...1000).contains(lineCount))
        let outcome = try parse(body)
        #expect(outcome.range.count == 41)
        #expect(outcome.paddingLines == lineCount - 41)
        #expect(outcome.range.result(for: PasswordDigest(utf8Of: "password")) == .found(occurrences: 10_434_004))
    }
}

@Suite("Pwned Passwords: cache entries")
struct PwnedRangeCacheTests {
    static let fetched = Date(timeIntervalSince1970: 1_800_000_000)

    static func entry(_ body: String = RangeFixtures.unpadded) throws -> CachedPwnedRange {
        CachedPwnedRange(
            range: try PwnedRangeParser.parse(Array(body.utf8), prefix: RangeFixtures.prefix).range,
            fetchedAt: fetched)
    }

    @Test("an entry survives encoding")
    func roundTrip() throws {
        let entry = try Self.entry()
        let decoded = try CachedPwnedRange(decoding: entry.encoded())
        #expect(decoded == entry)
        #expect(decoded.range.result(for: PasswordDigest(utf8Of: "password")) == .found(occurrences: 10_434_004))
    }

    @Test("the encoding is the documented layout")
    func layout() throws {
        let entry = try Self.entry("\(RangeFixtures.passwordSuffix):258")
        let bytes = entry.encoded()
        #expect(Array(bytes[0..<5]) == Array("WWPR".utf8) + [1])
        #expect(Array(bytes[5..<8]) == [0x05, 0xBA, 0xA6])
        #expect(Array(bytes[8..<16]) == [0, 0, 0, 0, 0x6B, 0x49, 0xD2, 0x00])
        #expect(Array(bytes[16..<20]) == [0, 0, 0, 1])
        // The 35 suffix nibbles, then a zero nibble; then the count.
        #expect(
            Array(bytes[20...])
                == [UInt8](hex: "1E4C9B93F3F0682250B6CF8331B7EE68FD80") + [0, 0, 1, 2])
    }

    @Test("a damaged encoding is refused")
    func damaged() throws {
        let good = try Self.entry().encoded()
        var cases: [[UInt8]] = [[], Array(good.dropLast()), good + [0], Array(good.prefix(19))]
        var magic = good
        magic[0] ^= 1
        cases.append(magic)
        var version = good
        version[4] = 2
        cases.append(version)
        var prefix = good
        prefix[5] = 0x10
        cases.append(prefix)
        var count = good
        count[19] &+= 1
        cases.append(count)
        var hugeCount = good
        hugeCount[16] = 0xFF
        cases.append(hugeCount)
        var zeroCount = good
        for index in 38..<42 { zeroCount[index] = 0 }
        cases.append(zeroCount)
        var nibble = good
        nibble[37] |= 0x01
        cases.append(nibble)
        var future = good
        future[8] = 0x7F
        cases.append(future)
        for bytes in cases {
            #expect(throws: PwnedRangeCodecError.malformed) { try CachedPwnedRange(decoding: bytes) }
        }
    }

    @Test("the in-memory cache keeps the newest entries within its capacity")
    func capacity() async throws {
        let cache = InMemoryPwnedRangeCache(capacity: 3)
        for value in 0..<5 {
            let prefix = PwnedRangePrefix(value: UInt32(value))!
            let range = try PwnedRangeParser.parse(Array("\(RangeFixtures.passwordSuffix):1".utf8), prefix: prefix)
                .range
            await cache.store(
                CachedPwnedRange(range: range, fetchedAt: Self.fetched.addingTimeInterval(Double(value))))
        }
        #expect(await cache.count == 3)
        #expect(await cache.snapshot().map(\.range.prefix.value) == [2, 3, 4])
        await cache.removeAll()
        #expect(await cache.count == 0)
    }

    @Test("the in-memory cache is bounded in bytes as well as in entries")
    func byteLimit() async throws {
        // Three ranges of one entry (22 bytes) each fit in 64 bytes; a fourth pushes the oldest out.
        let cache = InMemoryPwnedRangeCache(capacity: 100, maximumBytes: 70)
        for value in 0..<4 {
            let prefix = PwnedRangePrefix(value: UInt32(value))!
            let range = try PwnedRangeParser.parse(Array("\(RangeFixtures.passwordSuffix):1".utf8), prefix: prefix)
                .range
            await cache.store(
                CachedPwnedRange(range: range, fetchedAt: Self.fetched.addingTimeInterval(Double(value))))
        }
        #expect(await cache.snapshot().map(\.range.prefix.value) == [1, 2, 3])
        // Replacing an entry does not count it twice.
        for _ in 0..<10 { await cache.store(try Self.entry("\(RangeFixtures.passwordSuffix):1")) }
        #expect(await cache.count >= 2)
        // A range larger than the whole budget is not kept.
        let tiny = InMemoryPwnedRangeCache(capacity: 100, maximumBytes: 10)
        await tiny.store(try Self.entry())
        #expect(await tiny.count == 0)
    }
}

@Suite("Pwned Passwords: client")
struct PwnedPasswordsClientTests {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)
    static let agent = HygieneUserAgent(version: "1.2.3")!

    struct Rig {
        let http = FakeHTTPClient()
        let cache = RecordingPwnedRangeCache()
        var client: PwnedPasswordsClient { PwnedPasswordsClient(http: http, cache: cache, userAgent: agent) }
    }

    @Test("a check sends one GET for the five-character prefix, with padding requested and the user agent set")
    func request() async throws {
        let rig = Rig()
        await rig.http.enqueue(RangeFixtures.response(RangeFixtures.padded))
        let check = try await rig.client.check(PasswordDigest(utf8Of: "password"), now: Self.now)
        #expect(check.result == .found(occurrences: 10_434_004))
        #expect(check.source == .network)
        let requests = await rig.http.requests
        #expect(requests.count == 1)
        #expect(requests[0].method == .get)
        #expect(requests[0].url.absoluteString == "https://api.pwnedpasswords.com/range/5BAA6")
        #expect(requests[0].headers == ["Add-Padding": "true", "User-Agent": "Watchword/1.2.3"])
        #expect(requests[0].maximumResponseBytes == 2 * 1024 * 1024)
    }

    @Test("a password that is not in the range is not found")
    func notFound() async throws {
        let rig = Rig()
        await rig.http.enqueue(RangeFixtures.response(RangeFixtures.padded))
        // SHA-1("unbreached-Zq7!example") starts D5D43; any range without its suffix will do.
        let check = try await rig.client.check(PasswordDigest(utf8Of: "unbreached-Zq7!example"), now: Self.now)
        #expect(check.result == .notFound)
        #expect(await rig.http.requests[0].url.path == "/range/D5D43")
    }

    @Test("a second check within seven days is answered from the cache, without a request")
    func cached() async throws {
        let rig = Rig()
        await rig.http.enqueue(RangeFixtures.response(RangeFixtures.padded))
        let digest = PasswordDigest(utf8Of: "password")
        _ = try await rig.client.check(digest, now: Self.now)
        let later = Self.now.addingTimeInterval(7 * 86400 - 1)
        let second = try await rig.client.check(digest, now: later)
        #expect(second == PwnedCheck(result: .found(occurrences: 10_434_004), source: .cache, rangeFetchedAt: Self.now))
        #expect(await rig.http.requests.count == 1)
        #expect(await rig.cache.stores.count == 1)
    }

    @Test("a cached range expires after seven days")
    func expiry() async throws {
        let rig = Rig()
        await rig.http.enqueue(RangeFixtures.response(RangeFixtures.padded))
        await rig.http.enqueue(RangeFixtures.response("\(RangeFixtures.passwordSuffix):11000000"))
        let digest = PasswordDigest(utf8Of: "password")
        _ = try await rig.client.check(digest, now: Self.now)
        let check = try await rig.client.check(digest, now: Self.now.addingTimeInterval(7 * 86400))
        #expect(check.source == .network)
        #expect(check.result == .found(occurrences: 11_000_000))
        #expect(await rig.http.requests.count == 2)
    }

    @Test("a cached range dated in the future is not trusted")
    func futureEntry() async throws {
        let rig = Rig()
        let planted = try PwnedRangeCacheTests.entry("0A1B2C3D4E5F60718293A4B5C6D7E8F9012:1")
        await rig.cache.plant(
            CachedPwnedRange(range: planted.range, fetchedAt: Self.now.addingTimeInterval(3600)),
            under: RangeFixtures.prefix)
        await rig.http.enqueue(RangeFixtures.response(RangeFixtures.padded))
        let check = try await rig.client.check(PasswordDigest(utf8Of: "password"), now: Self.now)
        #expect(check.source == .network)
        #expect(check.result.isBreached)
    }

    @Test("a cache that returns another prefix's range is ignored")
    func wrongCacheEntry() async throws {
        let rig = Rig()
        let other = PwnedRangePrefix("00000")!
        let range = try PwnedRangeParser.parse(Array(RangeFixtures.unpadded.utf8), prefix: other).range
        await rig.cache.plant(CachedPwnedRange(range: range, fetchedAt: Self.now), under: RangeFixtures.prefix)
        await rig.http.enqueue(RangeFixtures.response(RangeFixtures.padded))
        let check = try await rig.client.check(PasswordDigest(utf8Of: "password"), now: Self.now)
        #expect(check.source == .network)
    }

    @Test("freshAfter makes a pass ask again once, then reuse what it fetched")
    func freshAfter() async throws {
        let rig = Rig()
        await rig.http.enqueue(RangeFixtures.response(RangeFixtures.padded))
        await rig.http.enqueue(RangeFixtures.response(RangeFixtures.padded))
        let digest = PasswordDigest(utf8Of: "password")
        _ = try await rig.client.check(digest, now: Self.now)
        let passStart = Self.now.addingTimeInterval(86400)
        let first = try await rig.client.check(digest, now: passStart.addingTimeInterval(5), freshAfter: passStart)
        #expect(first.source == .network)
        let second = try await rig.client.check(digest, now: passStart.addingTimeInterval(9), freshAfter: passStart)
        #expect(second.source == .cache)
        #expect(await rig.http.requests.count == 2)
    }

    @Test(
        "HTTP 429 is a retryable outcome that honours Retry-After within bounds",
        arguments: zip(
            ["2", "  30 ", "0", "86400", "99999999999999999999", "-5", "soon", "Wed, 21 Oct 2026 07:28:00 GMT", ""],
            [2.0, 30, 1, 3600, 3600, 60, 60, 60, 60]))
    func rateLimited(_ header: String, _ expected: Double) async {
        let rig = Rig()
        await rig.http.enqueue(status: 429, headers: ["retry-after": header])
        await #expect(throws: PwnedPasswordsError.rateLimited(retryAfter: expected)) {
            try await rig.client.check(PasswordDigest(utf8Of: "password"), now: Self.now)
        }
        #expect(PwnedPasswordsError.rateLimited(retryAfter: expected).isRetryable)
        #expect(await rig.cache.stores.isEmpty)
    }

    @Test("HTTP 429 without Retry-After waits a minute")
    func rateLimitedWithoutHeader() async {
        let rig = Rig()
        await rig.http.enqueue(status: 429)
        await #expect(throws: PwnedPasswordsError.rateLimited(retryAfter: 60)) {
            try await rig.client.check(PasswordDigest(utf8Of: "password"), now: Self.now)
        }
    }

    @Test("HTTP 5xx is a retryable outcome", arguments: [500, 502, 503, 504, 599])
    func serverError(_ status: Int) async {
        let rig = Rig()
        await rig.http.enqueue(status: status, body: RangeFixtures.padded)
        let expected = PwnedPasswordsError.serverUnavailable(status: status, retryAfter: 300)
        await #expect(throws: expected) {
            try await rig.client.check(PasswordDigest(utf8Of: "password"), now: Self.now)
        }
        #expect(expected.isRetryable)
        #expect(expected.retryAfter == 300)
        #expect(await rig.cache.stores.isEmpty)
    }

    @Test("HTTP 503 honours Retry-After")
    func serverErrorWithRetryAfter() async {
        let rig = Rig()
        await rig.http.enqueue(status: 503, headers: ["Retry-After": "120"])
        await #expect(throws: PwnedPasswordsError.serverUnavailable(status: 503, retryAfter: 120)) {
            try await rig.client.check(PasswordDigest(utf8Of: "password"), now: Self.now)
        }
    }

    @Test(
        "any other status is an error, never an answer; a redirect is not followed",
        arguments: [100, 201, 204, 301, 302, 307, 400, 401, 403, 404, 418])
    func otherStatus(_ status: Int) async {
        let rig = Rig()
        await rig.http.enqueue(
            status: status, headers: ["Location": "https://evil.example/range/5BAA6"], body: RangeFixtures.padded)
        await #expect(throws: PwnedPasswordsError.unexpectedStatus(status)) {
            try await rig.client.check(PasswordDigest(utf8Of: "password"), now: Self.now)
        }
        #expect(!PwnedPasswordsError.unexpectedStatus(status).isRetryable)
        #expect(await rig.http.requests.count == 1)
        #expect(await rig.cache.stores.isEmpty)
    }

    @Test("a transport failure is retryable and stores nothing")
    func transport() async {
        let rig = Rig()
        await rig.http.enqueue(.failure)
        await #expect(throws: PwnedPasswordsError.transport) {
            try await rig.client.check(PasswordDigest(utf8Of: "password"), now: Self.now)
        }
        #expect(PwnedPasswordsError.transport.isRetryable)
        #expect(await rig.cache.stores.isEmpty)
    }

    @Test("a body over the limit is refused even if the adapter delivered it")
    func oversizedBody() async {
        let rig = Rig()
        let body = [UInt8](repeating: UInt8(ascii: "\n"), count: 2 * 1024 * 1024 + 1)
        await rig.http.enqueue(.response(HTTPResponse(status: 200, body: body)))
        await #expect(throws: PwnedPasswordsError.responseTooLarge) {
            try await rig.client.check(PasswordDigest(utf8Of: "password"), now: Self.now)
        }
        #expect(await rig.cache.stores.isEmpty)
    }

    @Test("a 200 that is not a range is malformed, not 'not breached'")
    func malformedBody() async {
        let rig = Rig()
        await rig.http.enqueue(status: 200, body: "<html><body>Access denied by policy</body></html>")
        await #expect(throws: PwnedPasswordsError.malformedResponse) {
            try await rig.client.check(PasswordDigest(utf8Of: "password"), now: Self.now)
        }
        #expect(await rig.cache.stores.isEmpty)
    }

    @Test("permission withdrawn while the request is in flight: nothing is stored or answered")
    func interrupted() async {
        let rig = Rig()
        await rig.http.enqueue(RangeFixtures.response(RangeFixtures.padded))
        await #expect(throws: PwnedPasswordsError.interrupted) {
            try await rig.client.check(PasswordDigest(utf8Of: "password"), now: Self.now) { false }
        }
        #expect(await rig.cache.stores.isEmpty)
    }

    @Test("a user agent accepts a version and nothing that could break out of the header")
    func userAgent() {
        #expect(HygieneUserAgent(version: "1.0")?.value == "Watchword/1.0")
        #expect(HygieneUserAgent(version: "2.4.1-beta+7")?.value == "Watchword/2.4.1-beta+7")
        for bad in ["", "1.0\r\nX-Injected: 1", "1.0 (evil)", "1/0", "１.0", String(repeating: "1", count: 33)] {
            #expect(HygieneUserAgent(version: bad) == nil)
        }
    }

    @Test("response headers are found whatever their case")
    func headerLookup() {
        let response = HTTPResponse(status: 429, headers: ["RETRY-AFTER": "9", "retry-after": "3", "X": "y"])
        #expect(response.header("Retry-After") == "9")
        #expect(response.header("x") == "y")
        #expect(response.header("missing") == nil)
    }

    @Test("a request prints its host and header names, never a path or a value")
    func requestRedaction() {
        let request = PwnedPasswordsClient(
            http: FakeHTTPClient(), cache: InMemoryPwnedRangeCache(), userAgent: Self.agent
        )
        .request(for: RangeFixtures.prefix)
        let printed = "\(request) \(String(reflecting: request))"
        #expect(printed.contains("api.pwnedpasswords.com"))
        #expect(!printed.contains("5BAA6"))
        #expect(!printed.contains("1.2.3"))
        #expect(Mirror(reflecting: request).children.isEmpty)
    }
}
