import Crypto
import Foundation
import SecureMemory
import Testing
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordHygiene

/// Milestone 6 adversarial obligations for hygiene (docs/04-test-plan.md §6.6).
///
/// The adversaries. Hygiene is the one feature that talks to a third party, so two of these are not in the table of
/// docs/02-architecture.md §2 and are described in §13:
/// - **The service and the network path** (the Have I Been Pwned operator, its CDN, a TLS-intercepting proxy the
///   device trusts): sees every request this module makes and chooses every response. Must learn no more than five
///   hexadecimal characters of any password's hash, must not be able to redirect a request to another host, and must
///   not be able to exhaust the device or switch the scanner off with a response. What it can always do is lie by
///   omission (leave a breached suffix out); nothing on the device can detect that.
/// - **A2 and A3, a thief with the device while the vault is locked**, and **A8, local malware reading files**:
///   read everything at rest. Must find nothing derived from a password: no hash, no prefix, no reuse token, no
///   breach result (ADR 0005). So with keys absent nothing is hashed and nothing is handed out to persist.
/// - **A4, a malicious household member** with write access to a shared vault: chooses the items the victim's
///   device analyses. Must not be able to make that device hammer the API or spend unbounded time on one item.
///
/// Every request is asserted on `FakeHTTPClient`, which records exactly what a real adapter would have been asked to
/// send; nothing here touches a network.
@Suite("Adversarial: hygiene and breach checks", .tags(.adversarial))
struct AdversarialHygieneTests {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)
    static let vault = UUID(uuidString: "0C0C0C0C-0000-4000-8000-00000000000C")!

    /// SHA-1 by way of swift-crypto directly, to state what a request may contain; the digests the client's
    /// *answers* are checked against come from Python (`SimulatedPwnedPasswords.digests`).
    static func sha1Hex(_ password: String) -> String {
        Insecure.SHA1.hash(data: Array(password.utf8)).map { byte in
            let digits = String(byte, radix: 16, uppercase: true)
            return byte < 0x10 ? "0" + digits : digits
        }.joined()
    }

    static func item(_ number: Int, passwords: [String], version: UInt64 = 1, extra: [Field] = []) -> Item {
        let id = UUID(
            uuidString: "00000000-0000-4000-8000-" + String(repeating: "0", count: 12 - String(number).count)
                + String(number))!
        // Fixed field IDs, so nothing random can happen to look like part of a digest.
        let fields = passwords.enumerated().map { index, password in
            Field(
                id: UUID(
                    uuidString: "F0000000-0000-4000-8000-" + String(repeating: "0", count: 12 - String(index).count)
                        + String(index))!, kind: .password, label: "Password", value: password)
        }
        return Item(
            id: id, vaultID: vault, title: "Item \(number)", scopes: [ServiceScope(host: "example.com")],
            fields: fields + extra, createdAt: now, modifiedAt: now, version: version)
    }

    struct Rig {
        let http = FakeHTTPClient()
        let cache = RecordingPwnedRangeCache()
        let clock = FakeClock(AdversarialHygieneTests.now)
        let engine: HygieneEngine

        init(breached: [String: UInt32] = [:], scanPolicy: ScanPolicy = .standard, answer: Bool = true) async {
            let client = PwnedPasswordsClient(http: http, cache: cache, userAgent: HygieneUserAgent(version: "1.0")!)
            engine = HygieneEngine(client: client, scanPolicy: scanPolicy, random: SeededGenerator(seed: 3))
            if answer {
                let server = SimulatedPwnedPasswords(breached: breached)
                await http.respond { server.reply(to: $0) }
            }
        }

        func unlock(_ items: [Item], ledger: ScanLedger = ScanLedger()) async throws -> SecureBytes {
            let key = SecureBytes(copying: [UInt8](repeating: 0x5A, count: 32))
            try await engine.unlock(reuseKey: key, ledger: ledger, items: items, now: await clock.now())
            return key
        }

        func runUntilIdle(_ items: [Item], limit: Int = 20_000) async -> [ScanOutcome] {
            var outcomes: [ScanOutcome] = []
            for _ in 0..<limit {
                let now = await clock.now()
                switch await engine.next(now: now) {
                case .scan(let id, _):
                    guard let item = items.first(where: { $0.id == id }) else { return outcomes }
                    outcomes.append(await engine.scan(item, now: now))
                case .wait(let until, _):
                    await clock.set(until)
                case .idle, .locked:
                    return outcomes
                }
            }
            return outcomes
        }
    }

    // MARK: What leaves the device

    /// The service and the network path, seeing every request of a full scan, a weekly re-scan and the retries after
    /// failures. Each request must be exactly `GET https://api.pwnedpasswords.com/range/<five hex>` with exactly
    /// the two required headers: nothing else of the hash, no identifier, no other host.
    @Test("no request ever carries more than five hex characters of a hash, another header or another host")
    func onlyThePrefixLeaves() async throws {
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 2026))
        var passwords = [
            "password", "", "pässwörd", "🔑🔑🔑", String(repeating: "A", count: 5000), "/range/../x", "?a=b#c",
        ]
        for _ in 0..<TestEnvironment.iterations(standard: 60, long: 600) {
            let length = 1 + Int(generator.next() % 40)
            passwords.append(
                String((0..<length).map { _ in Character(UnicodeScalar(UInt8(33 + generator.next() % 94))) }))
        }
        let items = passwords.enumerated().map {
            Self.item($0.offset + 1, passwords: [$0.element, "second-\($0.offset)"])
        }
        let rig = await Rig(breached: ["password": 9])
        // A rate limit, an outage and a dropped connection along the way: retries must look the same.
        await rig.http.enqueue(status: 429, headers: ["Retry-After": "5"])
        await rig.http.enqueue(status: 503)
        await rig.http.enqueue(.failure)
        _ = try await rig.unlock(items)
        _ = await rig.runUntilIdle(items)
        await rig.clock.advance(by: 8 * 86400)
        _ = await rig.runUntilIdle(items)

        let allowed = Set(passwords.filter { !$0.isEmpty }.map { String(Self.sha1Hex($0).prefix(5)) })
            .union(passwords.indices.map { String(Self.sha1Hex("second-\($0)").prefix(5)) })
        let requests = await rig.http.requests
        #expect(requests.count >= 2 * allowed.count)
        for request in requests {
            #expect(request.method == .get)
            #expect(request.url.host == .pwnedPasswords)
            #expect(request.url.absoluteString.hasPrefix("https://api.pwnedpasswords.com/range/"))
            let prefix = String(request.url.path.dropFirst("/range/".count))
            #expect(request.url.path == "/range/" + prefix)
            #expect(prefix.utf8.count == 5)
            #expect(prefix.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x46) })
            #expect(allowed.contains(prefix))
            #expect(request.headers == ["Add-Padding": "true", "User-Agent": "Watchword/1.0"])
            #expect(request.maximumResponseBytes == 2 * 1024 * 1024)
        }
        // And the sixth character never follows: no request URL is the start of a longer piece of any digest.
        let digests = passwords.map(Self.sha1Hex)
        for request in requests {
            let text = request.url.absoluteString + request.headers.values.joined()
            for digest in digests {
                #expect(!text.contains(digest.prefix(6)))
            }
        }
    }

    /// The service and the network path, answering with redirects and with bodies full of URLs. The client must
    /// never ask anywhere else: the only hosts a request can name are the two constants, and a 3xx is an error.
    @Test("a redirect or a URL in a response never produces a request to another host")
    func noOtherHost() async throws {
        let rig = await Rig(answer: false)
        let items = [Self.item(1, passwords: ["password"]), Self.item(2, passwords: ["hunter2"])]
        for status in [301, 302, 303, 307, 308] {
            await rig.http.enqueue(
                status: status,
                headers: ["Location": "https://evil.example/range/5BAA6", "Refresh": "0; url=http://evil.example"],
                body: "https://evil.example/collect?h=5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")
        }
        await rig.http.respond { _ in
            .response(HTTPResponse(status: 200, body: Array("see https://evil.example/\r\n".utf8)))
        }
        _ = try await rig.unlock(items)
        let outcomes = await rig.runUntilIdle(items, limit: 200)
        #expect(outcomes.contains(.failed(.unexpectedStatus(301))))
        #expect(!outcomes.contains { if case .scanned = $0 { return true } else { return false } })
        let requests = await rig.http.requests
        #expect(!requests.isEmpty)
        #expect(requests.allSatisfy { $0.url.host == .pwnedPasswords && !$0.url.absoluteString.contains("evil") })
        #expect(HygieneHost.pwnedPasswords.name == "api.pwnedpasswords.com")
        #expect(HygieneHost.haveIBeenPwned.name == "haveibeenpwned.com")
    }

    /// The service, which would learn who the person is if an address were ever sent. A scan of items that hold
    /// email addresses must send none: the breached-account lookup happens only through `IdentifierDisclosure`,
    /// which only a person's explicit action constructs (PRD F9.4).
    @Test("a scan never sends an email address or contacts the breached-account API")
    func scansSendNoIdentifier() async throws {
        let email = Field(kind: .email, label: "Email", value: "alice@example.com")
        let user = Field(kind: .username, label: "Username", value: "alice-the-username")
        let items = (1...5).map { Self.item($0, passwords: ["pw-\($0)-Zq7!"], extra: [email, user]) }
        let rig = await Rig()
        _ = try await rig.unlock(items)
        _ = await rig.runUntilIdle(items)
        _ = try await rig.engine.report(now: Self.now)
        for request in await rig.http.requests {
            #expect(request.url.host == .pwnedPasswords)
            let text = request.url.absoluteString + request.headers.map { $0.key + $0.value }.joined()
            #expect(!text.contains("alice"))
            #expect(!text.contains("example.com"))
            #expect(!text.contains("Item"))
        }
    }

    /// A person's API key and address, which an attacker who can influence either string (a pasted key, an imported
    /// address) would use to add a header or change the path. Both types refuse anything that could.
    @Test("an API key or address cannot inject a header, a path or a host")
    func noInjection() async throws {
        for key in [
            "abcdef0123456789\r\nHost: evil.example", "abcdef0123456789\nX: y", "abcdef 0123456789abc",
            "abcdef0123456789\u{0}",
        ] {
            #expect(HIBPAPIKey(key) == nil)
        }
        for address in ["a@b.c\r\nHost: evil.example", "a@b.c/../../range/00000", "a@evil.example/x@b.c", "a@b.c?x=1"] {
            guard let parsed = EmailAddress(address) else { continue }
            let url = HTTPSURL.breachedAccount(parsed)
            #expect(url.host == .haveIBeenPwned)
            let segment = url.path.dropFirst("/api/v3/breachedaccount/".count).dropLast("?truncateResponse=false".count)
            #expect(url.path.hasPrefix("/api/v3/breachedaccount/"))
            #expect(url.path.hasSuffix("?truncateResponse=false"))
            #expect(!segment.contains("/") && !segment.contains("?") && !segment.contains("#"))
            #expect(segment.utf8.allSatisfy { $0 > 0x20 && $0 < 0x7F })
        }
        #expect(HygieneUserAgent(version: "1.0\r\nCookie: a=b") == nil)

        let http = FakeHTTPClient()
        await http.enqueue(status: 404)
        let client = BreachedAccountClient(http: http, userAgent: HygieneUserAgent(version: "1.0")!)
        let address = try #require(EmailAddress("a/../b@example.com"))
        _ = try await client.breaches(
            disclosing: .confirmedByPerson(sending: address), apiKey: try #require(HIBPAPIKey("0123456789abcdef")))
        let request = try #require(await http.requests.first)
        #expect(
            request.url.absoluteString
                == "https://haveibeenpwned.com/api/v3/breachedaccount/a%2F..%2Fb%40example.com?truncateResponse=false")
        #expect(Set(request.headers.keys) == ["hibp-api-key", "User-Agent"])
    }

    // MARK: Keys absent

    /// A2/A3/A8: whoever reads the device while the vault is locked. A scheduler asked to run without keys must do
    /// nothing, for any state of the ledger and any items.
    @Test("with keys absent the schedule never asks for a scan and never changes the ledger")
    func scheduleLocked() {
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 77))
        for _ in 0..<TestEnvironment.iterations(standard: 200, long: 5000) {
            var entries: [UUID: ScanLedger.Entry] = [:]
            var candidates: [ScanCandidate] = []
            for _ in 0..<Int(generator.next() % 20) {
                let id = UUID()
                candidates.append(ScanCandidate(id: id, version: generator.next() % 4))
                if generator.next() % 2 == 0 {
                    entries[id] = .init(
                        itemVersion: generator.next() % 4,
                        scannedAt: Self.now.addingTimeInterval(Double(generator.next() % 2_000_000) - 1_000_000),
                        results: [:])
                }
            }
            let started =
                generator.next() % 3 == 0 ? nil : Self.now.addingTimeInterval(-Double(generator.next() % 1_000_000))
            let ledger = ScanLedger(
                entries: entries, fullScanStartedAt: started,
                fullScanCompletedAt: generator.next() % 2 == 0 ? started : nil)
            var schedule = ScanSchedule(ledger: ledger)
            #expect(schedule.decide(candidates: candidates, keysResident: false, now: Self.now) == .locked)
            #expect(schedule.ledger == ledger)
        }
    }

    /// A2/A3/A8 again, at the engine: before the first unlock and after a lock, every entry point that would hash a
    /// password or hand out something derived from one must refuse, the network and the cache must not be touched,
    /// and the reuse key must be gone from memory.
    @Test("with keys absent nothing is hashed, sent, cached or handed out to persist")
    func engineLocked() async throws {
        let rig = await Rig(breached: ["password": 3])
        let items = [Self.item(1, passwords: ["password"]), Self.item(2, passwords: ["hunter2"])]

        func expectInert() async {
            #expect(await rig.engine.isUnlocked == false)
            #expect(await rig.engine.next(now: Self.now) == .locked)
            #expect(await rig.engine.scan(items[0], now: Self.now) == .locked)
            await #expect(throws: HygieneEngineError.locked) { try await rig.engine.update(items[1]) }
            await #expect(throws: HygieneEngineError.locked) { try await rig.engine.report(now: Self.now) }
            await #expect(throws: HygieneEngineError.locked) { try await rig.engine.ledger() }
            await #expect(throws: HygieneEngineError.locked) { try await rig.engine.items(using: "password") }
            #expect(await rig.http.requests.isEmpty)
            #expect(await rig.cache.lookups.isEmpty)
            #expect(await rig.cache.stores.isEmpty)
        }
        await expectInert()

        let key = try await rig.unlock(items)
        #expect(!key.isZeroised)
        await rig.engine.lock()
        #expect(key.isZeroised)
        await expectInert()
    }

    /// A3: the device is taken, or auto-lock fires, while a range request is in flight. The response arrives after
    /// the keys are gone; it must be dropped. Nothing is cached (the prefix is derived from a password), nothing
    /// reaches the ledger, and the next unlock starts from the ledger as it was.
    @Test("a lock while a request is in flight wins: the response is dropped and nothing is stored")
    func lockDuringRequest() async throws {
        let rig = await Rig(breached: ["password": 3])
        let item = Self.item(1, passwords: ["password"])
        _ = try await rig.unlock([item])
        await rig.http.hold()
        async let outcome = rig.engine.scan(item, now: Self.now)
        await rig.http.waitForHeldRequest()
        await rig.engine.lock()
        await rig.http.release()
        #expect(await outcome == .interrupted)
        #expect(await rig.cache.stores.isEmpty)
        #expect(await rig.http.requests.count == 1)

        _ = try await rig.unlock([item])
        #expect(try await rig.engine.ledger().entries.isEmpty)
        #expect(try await rig.engine.report(now: Self.now).items.first?.breachStatus == .notChecked)
    }

    /// The same moment, but the person unlocks again before the old response arrives. The scan belongs to the
    /// session that ended; it must not write its result into the new one.
    @Test("a scan from before a lock cannot write into the session after it")
    func staleScanAcrossRelock() async throws {
        let rig = await Rig(breached: ["password": 3])
        let item = Self.item(1, passwords: ["password"])
        _ = try await rig.unlock([item])
        await rig.http.hold()
        async let outcome = rig.engine.scan(item, now: Self.now)
        await rig.http.waitForHeldRequest()
        await rig.engine.lock()
        _ = try await rig.unlock([item])
        await rig.http.release()
        #expect(await outcome == .interrupted)
        #expect(try await rig.engine.ledger().entries.isEmpty)
        #expect(await rig.cache.stores.isEmpty)
    }

    /// A2/A8 reading whatever the session persisted. The ledger is sealed by the session, but even its plaintext
    /// must hold nothing computed from a password except the per-field answer: no prefix, no hash, no token.
    @Test("the ledger holds no hash, prefix or token; analyses and digests are not encodable at all")
    func ledgerContents() async throws {
        let rig = await Rig(breached: ["password": 10_434_004])
        let item = Self.item(1, passwords: ["password"])
        _ = try await rig.unlock([item])
        _ = await rig.runUntilIdle([item])
        let ledger = try await rig.engine.ledger()
        let text = String(decoding: try JSONEncoder().encode(ledger), as: UTF8.self).uppercased()
        let digest = Self.sha1Hex("password")
        #expect(!text.contains(digest.prefix(5)))
        #expect(!text.contains(digest.dropFirst(5).prefix(8)))
        #expect(!text.contains("PASSWORD"))
        #expect(text.contains("10434004"))
        // The types that do hold password-derived material give the compiler no way to store them.
        #expect(!((PasswordDigest(utf8Of: "x") as Any) is any Encodable))
        let key = try ReuseKey(SecureBytes(copying: [UInt8](repeating: 1, count: 32)))
        #expect(!((key.token(forUTF8Of: "x") as Any) is any Encodable))
        #expect(!((ReuseIndex() as Any) is any Encodable))
        let analysis = ItemAnalyzer(estimator: StrengthEstimator(referenceYear: 2026)).analyse(item, reuseKey: key)
        #expect(!((analysis as Any) is any Encodable))
        let report = try await rig.engine.report(now: Self.now)
        #expect(!((report as Any) is any Encodable))
    }

    /// Anyone who can read a log, a crash report or a debugger's summary (A8, and N5's "no crash reporting that
    /// could include secrets"). Nothing derived from a password, and no API key, may appear when a value is printed,
    /// interpolated, reflected or dumped.
    @Test("nothing secret can be printed")
    func redaction() throws {
        let digestHex = Self.sha1Hex("password")
        let digest = PasswordDigest(utf8Of: "password")
        let key = try ReuseKey(SecureBytes(copying: [UInt8](repeating: 1, count: 32)))
        let token = key.token(forUTF8Of: "password")
        let apiKey = try #require(HIBPAPIKey("feedfacefeedfacefeedface"))
        var printed = "\(digest)\(token)\(key)\(apiKey)"
        for value in [digest as Any, token, key, apiKey] {
            printed += String(describing: value) + String(reflecting: value)
            dump(value, to: &printed)
        }
        #expect(!printed.uppercased().contains(digestHex.dropFirst(5).prefix(6)))
        #expect(!printed.contains("feedface"))
        #expect(!printed.contains(token.bytes.hex.prefix(8)))
        #expect(!printed.contains("[1, 1, 1"))
    }

    // MARK: Hostile responses

    /// The service or a trusted-root proxy, answering 200 with something that is not a range. "Not breached" must
    /// never be the result of a response that could not be read: the item stays unchecked.
    @Test(
        "a response that cannot be read is never an answer",
        arguments: [
            "", "<html><body>Blocked by your administrator</body></html>", "{\"statusCode\":200}", "\r\n\r\n\r\n",
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8", "0:0", String(repeating: "x:1\n", count: 60_000),
        ])
    func unreadableResponse(_ body: String) async throws {
        let rig = await Rig(answer: false)
        await rig.http.respond { _ in .response(HTTPResponse(status: 200, body: Array(body.utf8))) }
        let item = Self.item(1, passwords: ["password"])
        _ = try await rig.unlock([item])
        let outcome = await rig.engine.scan(item, now: Self.now)
        #expect(outcome == .failed(.malformedResponse) || outcome == .failed(.responseTooLarge))
        #expect(try await rig.engine.report(now: Self.now).items.first?.breachStatus == .notChecked)
        #expect(await rig.cache.stores.isEmpty)
    }

    /// The service, listing the person's suffix in any position, in either case, among padding, duplicates and
    /// junk. Whether the password is found must not depend on where the line is or what surrounds it.
    @Test("a listed suffix is found wherever it is in the range, and only the listed one")
    func positionIndependent() throws {
        let digest = PasswordDigest(utf8Of: "password")
        let prefix = try #require(PwnedRangePrefix("5BAA6"))
        let wanted = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
        var generator = SeededGenerator(seed: 9)
        var filler: [String] = []
        for index in 0..<999 {
            let count = index % 3 == 0 ? 0 : 1 + generator.next() % 1000
            filler.append("\(SimulatedPwnedPasswords.randomSuffix(&generator)):\(count)")
        }
        for position in [0, 1, 500, 998, 999] {
            var lines = filler
            lines.insert(position % 2 == 0 ? "\(wanted):4242" : "\(wanted.lowercased()):4242", at: position)
            let range = try PwnedRangeParser.parse(Array(lines.joined(separator: "\r\n").utf8), prefix: prefix).range
            #expect(range.result(for: digest) == .found(occurrences: 4242))
        }
        let absent = try PwnedRangeParser.parse(Array(filler.joined(separator: "\r\n").utf8), prefix: prefix).range
        #expect(absent.result(for: digest) == .notFound)
        // Every suffix one character away is a different password.
        for index in wanted.indices {
            var near = Array(wanted)
            let offset = wanted.distance(from: wanted.startIndex, to: index)
            near[offset] = near[offset] == "0" ? "1" : "0"
            let range = try PwnedRangeParser.parse(Array("\(String(near)):5".utf8), prefix: prefix).range
            #expect(range.result(for: digest) == .notFound)
        }
    }

    /// The service, trying to switch the scanner off with an enormous `Retry-After`, or to make it spin with a zero
    /// one. The wait is held between one second and one hour, and the scan completes once the service behaves.
    @Test("Retry-After can neither stop the scanner for good nor make it spin")
    func retryAfterBounded() async throws {
        let rig = await Rig()
        let items = (1...3).map { Self.item($0, passwords: ["pw-\($0)-Zq7!"]) }
        await rig.http.enqueue(status: 429, headers: ["Retry-After": "999999999999"])
        await rig.http.enqueue(status: 429, headers: ["Retry-After": "0"])
        await rig.http.enqueue(status: 503, headers: ["Retry-After": "-1"])
        _ = try await rig.unlock(items)
        let start = await rig.clock.now()
        let outcomes = await rig.runUntilIdle(items)
        #expect(outcomes.first == .failed(.rateLimited(retryAfter: 3600)))
        #expect(outcomes.filter { if case .scanned = $0 { return true } else { return false } }.count == 3)
        let elapsed = await rig.clock.now().timeIntervalSince(start)
        #expect(elapsed >= 3600 + 60)
        #expect(elapsed <= 3 * 3600)
        #expect(await rig.http.requests.count == 6)
    }

    /// A8 with write access to an unsealed cache file, or a cache adapter with a bug: entries for the wrong prefix,
    /// dated in the future, or older than a week must not answer a check. (An entry that is well-formed, current and
    /// simply false cannot be detected here, which is why the persisted cache must be sealed; §13.)
    @Test("a planted cache entry that is misfiled, post-dated or stale is not believed")
    func plantedCache() async throws {
        let empty = try PwnedRangeParser.parse(
            Array("0A1B2C3D4E5F60718293A4B5C6D7E8F9012:1".utf8), prefix: PwnedRangePrefix("5BAA6")!
        ).range
        let misfiled = try PwnedRangeParser.parse(
            Array("0A1B2C3D4E5F60718293A4B5C6D7E8F9012:1".utf8), prefix: PwnedRangePrefix("00000")!
        ).range
        let plants = [
            CachedPwnedRange(range: misfiled, fetchedAt: Self.now),
            CachedPwnedRange(range: empty, fetchedAt: Self.now.addingTimeInterval(10 * 365 * 86400)),
            CachedPwnedRange(range: empty, fetchedAt: Self.now.addingTimeInterval(-7 * 86400 - 1)),
        ]
        for plant in plants {
            let rig = await Rig(breached: ["password": 3])
            await rig.cache.plant(plant, under: PwnedRangePrefix("5BAA6")!)
            let item = Self.item(1, passwords: ["password"])
            _ = try await rig.unlock([item])
            #expect(await rig.engine.scan(item, now: Self.now) == .scanned(breachedPasswords: 1, networkRequests: 1))
        }
    }

    // MARK: Hostile items

    /// A4, a household member who fills a shared vault with thousands of items (or an import that does). The
    /// victim's device must not turn that into a burst of requests: at most the burst at once, then one per spacing.
    @Test("thousands of new items do not become a burst of requests")
    func requestRateIsBounded() async throws {
        let policy = ScanPolicy(requestSpacing: 2, burst: 5, maximumJitter: 0)
        let rig = await Rig(scanPolicy: policy)
        let items = (1...2000).map { Self.item($0, passwords: ["pw-\($0)-Zq7!"]) }
        _ = try await rig.unlock(items)
        let start = await rig.clock.now()
        // Drive the engine as fast as it allows for one simulated minute.
        var saveAttempts = 0
        while await rig.clock.now() < start.addingTimeInterval(60) {
            let now = await rig.clock.now()
            switch await rig.engine.next(now: now) {
            case .scan(let id, _):
                _ = await rig.engine.scan(items.first { $0.id == id }!, now: now)
            case .wait(let until, _):
                // Meanwhile the UI "saves" other items and asks for each to be checked at once.
                for item in items.suffix(50) where saveAttempts < 500 {
                    saveAttempts += 1
                    if case .scanned = await rig.engine.scan(item, now: now) {
                        Issue.record("a save bypassed the rate limit")
                    }
                }
                await rig.clock.set(min(until, start.addingTimeInterval(60)))
            case .idle, .locked:
                Issue.record("the scan should not be finished")
                return
            }
        }
        let sent = await rig.http.requests.count
        #expect(sent <= 5 + 30 + 1)
        #expect(sent >= 30)
    }

    /// A4 again: one item with thousands of password fields, megabyte-long passwords and megabyte-long titles. The
    /// analysis and the scan of one item are bounded: at most sixteen passwords are assessed and checked, each
    /// assessment looks at 64 characters, and the requests are paid for at the usual rate afterwards.
    @Test("one hostile item costs a bounded amount of work and requests")
    func hostileItem() async throws {
        let huge = String(repeating: "aA1!|7", count: 200_000)
        let passwords = (0..<3000).map { $0 < 4 ? "\(huge)\($0)" : "p-\($0)-aA1!|7aA1!|7" }
        var item = Self.item(1, passwords: passwords)
        item.title = String(repeating: "T", count: 1_000_000)
        item.scopes = (0..<5000).map { ServiceScope(host: "h\($0).example.com") }
        let rig = await Rig()
        let clock = ContinuousClock()
        let elapsed = try await clock.measure { _ = try await rig.unlock([item]) }
        #expect(elapsed < .seconds(20))
        let outcome = await rig.engine.scan(item, now: Self.now)
        #expect(outcome == .scanned(breachedPasswords: 0, networkRequests: 16))
        #expect(await rig.http.requests.count == 16)
        let report = try await rig.engine.report(now: Self.now)
        #expect(report.totals.passwords == 16)
        #expect(try await rig.engine.ledger().entries[item.id]?.results.count == 16)
        // Sixteen requests were made at once, so the next may not go for sixteen spacings less the burst.
        let other = Self.item(2, passwords: ["pw-2-Zq7!"])
        try await rig.engine.update(other)
        let wait = ScanPolicy.standard.requestSpacing * Double(16 - ScanPolicy.standard.burst + 1)
        #expect(await rig.engine.scan(other, now: Self.now) == .deferred(until: Self.now.addingTimeInterval(wait)))
    }

    /// A4, or the service through the breached-account API: text that will be shown to a person. Control and
    /// bidirectional-override characters from the network are removed, and the service's HTML is never carried.
    @Test("text from the breached-account API is reduced to bounded plain text")
    func breachTextIsPlain() throws {
        let body = """
            [{"Name":"Evil\\u202E\\u0007\\u0000","Title":"<script>alert(1)</script>\\u2066",
              "Domain":"evil.example\\r\\nX: y",
              "Description":"<img src=x onerror=alert(1)>","LogoPath":"https://evil.example/track.png",
              "DataClasses":["Passwords\\u200F","\\u0000"]}]
            """
        let breach = try #require(try BreachedAccountClient.parse(Array(body.utf8)).first)
        #expect(breach.name == "Evil")
        #expect(breach.title == "<script>alert(1)</script>")
        #expect(breach.domain == "evil.exampleX: y")
        #expect(breach.dataClasses == ["Passwords"])
        var dumped = ""
        dump(breach, to: &dumped)
        #expect(!dumped.contains("onerror"))
        #expect(!dumped.contains("track.png"))
    }
}
