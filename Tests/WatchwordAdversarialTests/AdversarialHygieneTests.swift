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

        init(
            breached: [String: UInt32] = [:], scanPolicy: ScanPolicy = .standard, answer: Bool = true,
            gate: CheckpointGate? = nil
        ) async {
            let client = PwnedPasswordsClient(http: http, cache: cache, userAgent: HygieneUserAgent(version: "1.0")!)
            engine = HygieneEngine(
                client: client, policy: HygienePolicy(), scanPolicy: scanPolicy, random: SeededGenerator(seed: 3)
            ) { await gate?.pass() }
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
            let text = request.url.absoluteString + request.headers.fields.values.joined()
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
            let text = request.url.absoluteString + request.headers.fields.map { $0.key + $0.value }.joined()
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
        #expect(request.headers.names == ["User-Agent", "hibp-api-key"])
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

    /// A3, or anyone who can read the process's memory after the vault has locked (the adversary lock-time
    /// zeroisation exists for). The prefix cache names twenty bits of the SHA-1 of every password that was checked,
    /// enough to reject all but one in a million guesses offline, so it must be gone when the keys are.
    @Test("after a lock the default prefix cache holds no prefix")
    func cacheEmptiedAtLock() async throws {
        let http = FakeHTTPClient()
        let server = SimulatedPwnedPasswords(breached: [:])
        await http.respond { server.reply(to: $0) }
        let cache = InMemoryPwnedRangeCache()
        let engine = HygieneEngine(
            client: PwnedPasswordsClient(http: http, cache: cache, userAgent: HygieneUserAgent(version: "1.0")!),
            random: SeededGenerator(seed: 3))
        let items = [Self.item(1, passwords: ["hunter2"]), Self.item(2, passwords: ["letmein"])]
        let key = SecureBytes(copying: [UInt8](repeating: 0x5A, count: 32))
        try await engine.unlock(reuseKey: key, ledger: ScanLedger(), items: items, now: Self.now)
        for item in items {
            #expect(await engine.scan(item, now: Self.now) == .scanned(breachedPasswords: 0, networkRequests: 1))
        }
        // The prefixes are those of Python's hashlib.sha1 for the two passwords (`SimulatedPwnedPasswords.digests`).
        #expect(await cache.snapshot().map(\.range.prefix.hex) == ["B7A87", "F3BBB"])
        await engine.lock()
        #expect(await cache.snapshot().isEmpty)
        #expect(await cache.count == 0)
        #expect(key.isZeroised)
    }

    /// The same adversary, and the one moment the rule above could slip: the range has been fetched, the client has
    /// been told the vault is still unlocked, and the lock lands before the entry reaches the cache. The entry
    /// arrives after the lock emptied the cache; it must not stay.
    @Test("a lock while a range is being stored still leaves the cache empty")
    func lockDuringStore() async throws {
        let rig = await Rig(breached: ["password": 3])
        let item = Self.item(1, passwords: ["password"])
        _ = try await rig.unlock([item])
        await rig.cache.holdStores()
        async let outcome = rig.engine.scan(item, now: Self.now)
        await rig.cache.waitForHeldStore()
        await rig.engine.lock()
        #expect(await rig.cache.locks == 1)
        await rig.cache.releaseStores()
        #expect(await outcome == .interrupted)
        #expect(await rig.cache.entries.isEmpty)

        _ = try await rig.unlock([item])
        #expect(try await rig.engine.ledger().entries.isEmpty)
    }

    /// A4, who fills a shared vault with items, and A3, who takes the device while it is unlocking. `unlock`
    /// analyses every item, and an actor runs one call at a time; if it did that in one go, a lock would wait for
    /// the whole vault and the reuse key would stay resident meanwhile. It stops at the next item instead.
    @Test("a lock during unlock waits for one item, not for the vault")
    func lockDuringUnlock() async throws {
        let gate = CheckpointGate(holdingAfter: 3)
        let rig = await Rig(gate: gate)
        let items = (1...500).map { Self.item($0, passwords: ["pw-\($0)-Zq7!"]) }
        let key = SecureBytes(copying: [UInt8](repeating: 0x5A, count: 32))
        let unlocking = Task {
            try await rig.engine.unlock(reuseKey: key, ledger: ScanLedger(), items: items, now: Self.now)
        }
        await gate.waitUntilHeld()
        // Three items in, with 497 to go, the lock runs to completion.
        await rig.engine.lock()
        #expect(key.isZeroised)
        #expect(await rig.engine.isUnlocked == false)
        await gate.release()
        await #expect(throws: HygieneEngineError.locked) { try await unlocking.value }
        #expect(await gate.passes == 3)
        #expect(await rig.engine.isUnlocked == false)
        await #expect(throws: HygieneEngineError.locked) { try await rig.engine.report(now: Self.now) }
        #expect(await rig.http.requests.isEmpty)
    }

    /// The same, when the session stops the unlock by cancelling its task (which needs no turn on the actor at
    /// all). A cancelled unlock must not leave the engine half-unlocked with a live reuse key.
    @Test("a cancelled unlock stops at the next item and leaves the engine locked")
    func cancelledUnlock() async throws {
        let gate = CheckpointGate(holdingAfter: 3)
        let rig = await Rig(gate: gate)
        let items = (1...500).map { Self.item($0, passwords: ["pw-\($0)-Zq7!"]) }
        let key = SecureBytes(copying: [UInt8](repeating: 0x5A, count: 32))
        let unlocking = Task {
            try await rig.engine.unlock(reuseKey: key, ledger: ScanLedger(), items: items, now: Self.now)
        }
        await gate.waitUntilHeld()
        unlocking.cancel()
        await gate.release()
        await #expect(throws: CancellationError.self) { try await unlocking.value }
        #expect(await gate.passes == 3)
        #expect(await rig.engine.isUnlocked == false)
        #expect(key.isZeroised)
    }

    /// A reader of the device's memory after a lock (A2, A3), where the lock was a second `unlock` that the session
    /// cancelled: the engine was unlocked, with the prefixes of the person's passwords in its cache, and a new
    /// unlock began and was cancelled. "Locked" must mean what `lock()` means, cache included; otherwise the set of
    /// prefixes (twenty bits of each password's hash) outlives the keys in memory.
    @Test("a cancelled unlock over an unlocked engine leaves it locked with no prefix in the cache")
    func cancelledReunlockEmptiesTheCache() async throws {
        // Three passes for the first unlock; the second is held after its second item.
        let gate = CheckpointGate(holdingAfter: 5)
        let rig = await Rig(gate: gate)
        let items = (1...3).map { Self.item($0, passwords: ["pw-\($0)-Zq7!"]) }
        let first = try await rig.unlock(items)
        _ = await rig.runUntilIdle(items)
        #expect(await rig.cache.entries.count == 3)

        let key = SecureBytes(copying: [UInt8](repeating: 0x6B, count: 32))
        let unlocking = Task {
            try await rig.engine.unlock(reuseKey: key, ledger: ScanLedger(), items: items, now: Self.now)
        }
        await gate.waitUntilHeld()
        unlocking.cancel()
        await gate.release()
        await #expect(throws: CancellationError.self) { try await unlocking.value }
        #expect(await rig.engine.isUnlocked == false)
        #expect(first.isZeroised)
        #expect(key.isZeroised)
        #expect(await rig.cache.entries.isEmpty)
        #expect(await rig.cache.locks >= 1)
    }

    /// The service and the network path, which answer the server's side of the rate limit. A phone locks and
    /// unlocks many times a day; if each unlock forgot `Retry-After` and refilled the burst, the service would see
    /// a burst of range requests at every unlock, while asking for quiet.
    @Test("a lock and unlock neither forgets Retry-After nor buys a new burst of requests")
    func pacingSurvivesLock() async throws {
        let rig = await Rig()
        let items = (1...40).map { Self.item($0, passwords: ["pw-\($0)-Zq7!"]) }
        var ledger = ScanLedger()
        _ = try await rig.unlock(items)
        await rig.http.enqueue(status: 429, headers: ["Retry-After": "3600"])
        let start = await rig.clock.now()
        // An hour of unlocking every minute and asking each time what to do.
        for _ in 0..<59 {
            let now = await rig.clock.now()
            if case .scan(let id, _) = await rig.engine.next(now: now) {
                _ = await rig.engine.scan(items.first { $0.id == id }!, now: now)
            }
            ledger = try await rig.engine.ledger()
            await rig.engine.lock()
            await rig.clock.advance(by: 60)
            _ = try await rig.unlock(items, ledger: ledger)
        }
        #expect(await rig.clock.now() < start.addingTimeInterval(3600))
        #expect(await rig.http.requests.count == 1)
    }

    /// The service and the network path again, this time failing one prefix and answering the rest. If the scanner
    /// kept asking for the item that failed, an attacker on the path could stop every other password in the vault
    /// from being checked by refusing a single range, for ever.
    @Test("refusing one range does not stop the rest of the vault from being checked")
    func oneRefusedRangeDoesNotStall() async throws {
        for refusal in [FakeHTTPClient.Reply.response(HTTPResponse(status: 503)), .failure] {
            let rig = await Rig(breached: ["letmein": 4])
            let server = SimulatedPwnedPasswords(breached: ["letmein": 4])
            // F3BBB is the range of "hunter2", which the most urgent item holds.
            await rig.http.respond { $0.url.path.hasSuffix("/F3BBB") ? refusal : server.reply(to: $0) }
            let passwords = ["hunter2", "letmein", "pw-3-Zq7!", "pw-4-Zq7!", "pw-5-Zq7!", "pw-6-Zq7!"]
            let items = passwords.enumerated().map { Self.item($0.offset + 1, passwords: [$0.element]) }
            _ = try await rig.unlock(items)
            let start = await rig.clock.now()
            while await rig.clock.now() < start.addingTimeInterval(86400) {
                let now = await rig.clock.now()
                switch await rig.engine.next(now: now) {
                case .scan(let id, _): _ = await rig.engine.scan(items.first { $0.id == id }!, now: now)
                case .wait(let until, _): await rig.clock.set(max(until, now.addingTimeInterval(1)))
                case .idle, .locked: Issue.record("the refused item is still due")
                }
            }
            let report = try await rig.engine.report(now: await rig.clock.now())
            #expect(report.totals.itemsAwaitingBreachCheck == 1)
            #expect(report.item(items[0].id)?.breachStatus == .notChecked)
            #expect(report.item(items[1].id)?.findings.first?.kind == .breachedPassword)
            let paths = await rig.http.requests.map(\.url.path)
            #expect(Set(paths).count == 6)
            // Within the first minute and a bit, everything else has been asked for.
            #expect(paths.prefix(6).filter { $0.hasSuffix("/F3BBB") }.count == 1)
            // And the refused range is retried at the backoff's pace, not hammered: about once an hour.
            #expect(paths.filter { $0.hasSuffix("/F3BBB") }.count <= 30)
        }
    }

    /// The same adversary, against the vault as it is really used: unlocked for a short while every ten minutes,
    /// for a day. One range is refused every time (a 503, a dropped connection, or a page of HTML with status 200).
    /// The refusal's backoff outlasts each unlock, so if the scanner forgot at each lock which item had failed, it
    /// would ask for that same range first at every unlock and never reach another item. The session carries the
    /// ledger across the lock; in the second arrangement the process is also new each time (the app was terminated
    /// while locked), so nothing but the ledger is carried.
    @Test(
        "refusing one range does not stop the rest of the vault being checked across locks and restarts",
        arguments: [20.0, 45, 300])
    func oneRefusedRangeDoesNotStallAcrossLocks(unlockedFor: TimeInterval) async throws {
        let html = FakeHTTPClient.Reply.response(
            HTTPResponse(status: 200, headers: [:], body: Array("<html><body>Please sign in</body></html>".utf8)))
        for refusal in [FakeHTTPClient.Reply.response(HTTPResponse(status: 503)), .failure, html] {
            for newProcessEachUnlock in [false, true] {
                let http = FakeHTTPClient()
                let server = SimulatedPwnedPasswords(breached: ["letmein": 4])
                // F3BBB is the range of "hunter2", which the most urgent item holds.
                await http.respond { $0.url.path.hasSuffix("/F3BBB") ? refusal : server.reply(to: $0) }
                func engine() -> HygieneEngine {
                    HygieneEngine(
                        client: PwnedPasswordsClient(
                            http: http, cache: InMemoryPwnedRangeCache(), userAgent: HygieneUserAgent(version: "1.0")!),
                        random: SeededGenerator(seed: 3))
                }
                let passwords = ["hunter2", "letmein"] + (3...8).map { "pw-\($0)-Zq7!" }
                let items = passwords.enumerated().map { Self.item($0.offset + 1, passwords: [$0.element]) }
                let clock = FakeClock(Self.now)
                var current = engine()
                var ledger = ScanLedger()
                var unlocksUntilChecked: Int?
                for unlock in 0..<144 {
                    let unlockedAt = Self.now.addingTimeInterval(Double(unlock) * 600)
                    await clock.set(unlockedAt)
                    if newProcessEachUnlock { current = engine() }
                    let key = SecureBytes(copying: [UInt8](repeating: 0x5A, count: 32))
                    try await current.unlock(reuseKey: key, ledger: ledger, items: items, now: unlockedAt)
                    unlocked: while true {
                        let now = await clock.now()
                        switch await current.next(now: now) {
                        case .scan(let id, _):
                            _ = await current.scan(items.first { $0.id == id }!, now: now)
                            // What the session does after every scan, failed or not: seal and store the ledger.
                            ledger = try await current.ledger()
                        case .wait(let until, _):
                            guard until < unlockedAt.addingTimeInterval(unlockedFor) else { break unlocked }
                            await clock.set(max(until, now.addingTimeInterval(1)))
                        case .idle, .locked:
                            Issue.record("the refused item is still due")
                            break unlocked
                        }
                    }
                    if unlocksUntilChecked == nil {
                        let report = try await current.report(now: await clock.now())
                        if report.totals.itemsAwaitingBreachCheck == 1 { unlocksUntilChecked = unlock + 1 }
                    }
                    await current.lock()
                }
                // At worst the first unlock is spent on the refused range, and the second reaches every other item.
                #expect((unlocksUntilChecked ?? .max) <= 2, "new process each unlock: \(newProcessEachUnlock)")
                let paths = await http.requests.map(\.url.path)
                #expect(Set(paths).count == 8)
                let refused = paths.filter { $0.hasSuffix("/F3BBB") }.count
                // Asked for again, since it may recover, but never more than the backoff allows within an unlock.
                #expect(refused >= 2)
                #expect(refused <= 144 * Int(1 + unlockedFor / 60))
                #expect(ledger.failures.count == 1)
                #expect(ledger.failures[items[0].id] != nil)
            }
        }
    }

    /// The session's own race, which a member of a shared vault can provoke by saving an item again and again
    /// (A4): the scanner fetched version 1, and version 2, with a breached password, was saved before the scan
    /// call arrived. The stale copy must not put version 1's clean result, or version 1's analysis, in its place.
    @Test("a stale copy of an item cannot mark its newer, breached password as checked and clear")
    func staleCopyCannotClear() async throws {
        let rig = await Rig(breached: ["hunter2": 5])
        let old = Self.item(1, passwords: ["pw-1-Zq7!"])
        _ = try await rig.unlock([old])
        _ = await rig.runUntilIdle([old])
        let new = Self.item(1, passwords: ["hunter2"], version: 2)
        try await rig.engine.update(new)
        #expect(await rig.engine.scan(old, now: Self.now) == .stale)
        #expect(try await rig.engine.update(old) == false)
        let report = try await rig.engine.report(now: Self.now)
        #expect(report.items.first?.breachStatus == .notChecked)
        #expect(try await rig.engine.items(using: "hunter2") == [new.id])
        #expect(await rig.engine.next(now: Self.now) == .scan(item: new.id, reason: .changed))
    }

    /// A4 or a hostile import, writing an item Watchtower will misread: two password fields under one field ID,
    /// the breached one first, or a seventeenth password beyond the number checked per item. Neither may come out
    /// as "clear".
    @Test("a breached password cannot hide behind a duplicate field ID or beyond the per-item cap")
    func noFalseClear() async throws {
        let rig = await Rig(breached: ["password": 3])
        var twins = Self.item(1, passwords: ["password", "pw-1-Zq7!-unbreached"])
        twins.fields[1].id = twins.fields[0].id
        let many = Self.item(2, passwords: (0..<16).map { "pw-2-\($0)-Zq7!" } + ["password"])
        _ = try await rig.unlock([twins, many])
        #expect(await rig.engine.scan(twins, now: Self.now) == .scanned(breachedPasswords: 1, networkRequests: 2))
        await rig.clock.advance(by: 3600)
        let later = await rig.clock.now()
        #expect(await rig.engine.scan(many, now: later) == .scanned(breachedPasswords: 0, networkRequests: 16))
        let report = try await rig.engine.report(now: later)
        #expect(report.item(twins.id)?.breachStatus == .breached(checkedAt: Self.now))
        #expect(report.item(twins.id)?.findings.first?.kind == .breachedPassword)
        #expect(report.item(many.id)?.breachStatus == .incomplete(checkedAt: later))
        #expect(report.item(many.id)?.findings.contains { $0.kind == .tooManyPasswords } == true)
        for item in report.items {
            if case .clear = item.breachStatus {
                Issue.record("an item with an unchecked or breached password is clear")
            }
        }
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

    /// The same reader. A strength estimate is derived from the password too: for one entry of a public list the
    /// exact figure is the entry's rank, which names the password, and an analysis carries it beside the item's
    /// title. And a request's URL is the person's email address (the breached-account lookup) or twenty bits of a
    /// password's hash (a range), with the API key among its headers.
    @Test("an estimate, an analysis, a URL, an address and a request's headers print nothing that identifies")
    func redactionOfDerivedValues() throws {
        let estimator = StrengthEstimator(referenceYear: 2026)
        var printed = ""
        func show(_ value: Any) {
            printed += "\(value) " + String(describing: value) + String(reflecting: value)
            dump(value, to: &printed)
        }
        // Entries 10, 16, 17 and 53 of the list: the exact estimates are 10, 16, 17 and 53 guesses.
        for password in ["dragon", "monkey", "letmein", "iloveyou"] {
            let assessment = estimator.assess(password)
            #expect(assessment.weakness == .commonPassword)
            show(assessment)
        }
        var item = Self.item(1, passwords: ["dragon", "Tr0ub4dor&3"])
        item.title = "Private-Title"
        let key = try ReuseKey(SecureBytes(copying: [UInt8](repeating: 1, count: 32)))
        let analysis = ItemAnalyzer(estimator: estimator).analyse(item, reuseKey: key)
        show(analysis)
        show(analysis.passwords)
        #expect(!printed.contains("guesses"))
        #expect(!printed.contains("commonPassword"))
        #expect(!printed.contains("Private-Title"))
        #expect(!printed.contains(analysis.passwords[0].reuseToken.bytes.hex.prefix(8)))
        // No number that could be an estimate: every digit run printed is part of an ID, a version or a score.
        for estimate in ["1.0", "1.04", "1.2", "1.23", "1.72", "11.0"] {
            #expect(!printed.contains(estimate))
        }

        printed = ""
        let address = try #require(EmailAddress("alice.smith@example.org"))
        let disclosure = IdentifierDisclosure.confirmedByPerson(sending: address)
        let agent = try #require(HygieneUserAgent(version: "1.0"))
        let lookup = BreachedAccountClient(http: FakeHTTPClient(), userAgent: agent)
            .request(disclosing: disclosure, apiKey: try #require(HIBPAPIKey("feedfacefeedfacefeedface")))
        let digest = PasswordDigest(utf8Of: "password")
        let range = PwnedPasswordsClient(http: FakeHTTPClient(), cache: InMemoryPwnedRangeCache(), userAgent: agent)
            .request(for: digest.prefix)
        let cached = CachedPwnedRange(
            range: try PwnedRangeParser.parse(
                Array("0A1B2C3D4E5F60718293A4B5C6D7E8F9012:7".utf8), prefix: digest.prefix
            ).range, fetchedAt: Self.now)
        let ledger = ScanLedger(
            entries: [
                item.id: .init(itemVersion: 1, scannedAt: Self.now, results: [item.id: .found(occurrences: 424_242)])
            ])
        for value in [
            address as Any, disclosure, lookup, lookup.url, lookup.headers, range, range.url, digest.prefix, cached,
            ledger,
        ] {
            show(value)
        }
        // A breach count all but names the password, so a ledger does not print its results.
        #expect(!printed.contains("424242"))
        #expect(!printed.contains("alice"))
        #expect(!printed.contains("smith"))
        #expect(!printed.contains("example.org"))
        #expect(!printed.contains("feedface"))
        #expect(!printed.uppercased().contains("5BAA6"))
        #expect(!printed.contains("/range/"))
        #expect(!printed.contains("breachedaccount"))
        // What an adapter needs is still there, under the two accessors to search for.
        #expect(lookup.url.absoluteString.hasSuffix("/alice.smith%40example.org?truncateResponse=false"))
        #expect(lookup.headers.fields["hibp-api-key"] == "feedfacefeedfacefeedface")
        #expect(range.url.absoluteString == "https://api.pwnedpasswords.com/range/5BAA6")
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
            let item = Self.item(1, passwords: ["password"])
            await rig.cache.plant(plant, under: PwnedRangePrefix("5BAA6")!, in: item.vaultID)
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
        // And the report does not pretend the other 2,984 were looked at.
        #expect(report.items.first?.breachStatus == .incomplete(checkedAt: Self.now))
        #expect(report.items.first?.findings.contains { $0.detail == .notAnalysed(passwords: 2984) } == true)
        // Sixteen requests were made at once, so the next may not go for sixteen spacings less the burst.
        let other = Self.item(2, passwords: ["pw-2-Zq7!"])
        try await rig.engine.update(other)
        let wait = ScanPolicy.standard.requestSpacing * Double(16 - ScanPolicy.standard.burst + 1)
        #expect(await rig.engine.scan(other, now: Self.now) == .deferred(until: Self.now.addingTimeInterval(wait)))
    }

    /// A4 once more, choosing the *characters*. The estimator looks every stretch of a password up in its word
    /// lists, in up to ten readings. Done by building and hashing a string per stretch, a password of combining
    /// marks between look-alike digits cost several hundred times an ordinary one (hashing a non-ASCII string
    /// normalises it), and a vault of such items held the engine, and so a lock, for minutes. The work is counted
    /// in table steps, which no machine or script changes, and is bounded.
    @Test("a password of combining marks and look-alikes costs no more dictionary work than one of letters")
    func hostileScriptsCostNoMore() {
        func steps(_ password: String) -> Int {
            var matcher = StrengthMatcher(
                Array(password.unicodeScalars.prefix(StrengthEstimator.maximumAnalysedLength)),
                personal: PersonalDictionary([]), referenceYear: 2026, repeatDepth: 2)
            _ = matcher.matchAll()
            return matcher.dictionarySteps
        }
        // What a password of words and look-alike digits costs, at the full analysed length.
        let wordy = "p4ssw0rd1 l3tm31n! 7r0ub4d0r 1l0v3y0u! m0nk3y1 dr4g0n7 qw3r7y| b4s3b4ll"
        let designed = String(repeating: "a\u{323}\u{301}1o\u{31B}\u{323}|\u{F73}7", count: 7)
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 31))
        let pieces: [String] = ["\u{323}", "\u{301}", "\u{31B}", "\u{F73}", "1", "|", "7", "a", "o", "\u{200D}", "é"]
        var hostile = [designed]
        for _ in 0..<TestEnvironment.iterations(standard: 200, long: 5000) {
            hostile.append((0..<64).map { _ in pieces[Int(generator.next() % UInt64(pieces.count))] }.joined())
        }
        // Ten readings of 64 scalars. Words walk a few scalars into the table from each start and marks walk
        // none, so hostile text costs about what words cost, and both are far below the ceiling of ten readings
        // of 64 starts of the longest word.
        let ordinary = steps(wordy)
        let worst = hostile.map(steps).max() ?? 0
        #expect(steps(designed) <= 10 * 64 * 3)
        #expect(worst <= 3 * ordinary)
        #expect(ordinary <= 10 * 64 * (RankedDictionary.embedded.maximumWordLength + 1))

        // And the time, measured against the wordy password on the same machine in the same moment, so the bound
        // holds on a slow or busy one: the best of several runs of each. It was more than a hundred times.
        let estimator = StrengthEstimator(referenceYear: 2026)
        let clock = ContinuousClock()
        func best(_ password: String) -> Duration {
            (0..<7).map { _ in clock.measure { for _ in 0..<5 { _ = estimator.assess(password) } } }.min() ?? .zero
        }
        _ = estimator.assess(wordy)
        let baseline = best(wordy)
        for password in hostile.prefix(20) {
            #expect(best(password) <= baseline * 10)
        }
    }

    /// The service through the breached-account API (or a proxy the device trusts), answering the person's lookup
    /// with as many breaches as two megabytes hold. The count must be bounded while reading: decoding all 160,000
    /// before counting them cost many seconds of CPU for a response that was always going to be refused.
    @Test("a breached-account response of very many tiny breaches is refused without decoding them all")
    func breachCountBoundedWhileReading() throws {
        let entry = "{\"Name\":\"a\"},"
        var body = Array("[".utf8)
        while body.count + entry.utf8.count + 16 < 2 * 1024 * 1024 { body.append(contentsOf: entry.utf8) }
        // Whatever comes after the limit is not looked at: this last entry would make the response malformed.
        body.append(contentsOf: "{\"Name\":7}]".utf8)
        let clock = ContinuousClock()
        var thrown: (any Error)?
        let elapsed = clock.measure {
            do { _ = try BreachedAccountClient.parse(body) } catch { thrown = error }
        }
        #expect(thrown as? BreachedAccountError == .responseTooLarge)
        // A fraction of a second in practice (it was seventeen); the bound is loose because CI machines are shared.
        #expect(elapsed < .seconds(8))
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
