import Foundation
import SecureMemory
import Testing
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordHygiene

/// The engine as the session will drive it: unlock, loop on `next`, scan, lock (docs/02-architecture.md §13).
struct EngineRig {
    let http = FakeHTTPClient()
    let cache = RecordingPwnedRangeCache()
    let clock = FakeClock(HygieneFixtures.now)
    let engine: HygieneEngine

    init(
        breached: [String: UInt32] = [:], policy: HygienePolicy = HygienePolicy(), scanPolicy: ScanPolicy = .standard
    ) async {
        let client = PwnedPasswordsClient(http: http, cache: cache, userAgent: HygieneUserAgent(version: "1.0")!)
        engine = HygieneEngine(
            client: client, policy: policy, scanPolicy: scanPolicy, random: SeededGenerator(seed: 11))
        let server = SimulatedPwnedPasswords(breached: breached)
        await http.respond { server.reply(to: $0) }
    }

    func unlock(_ items: [Item], ledger: ScanLedger = ScanLedger()) async throws {
        // A fresh copy each time: the engine zeroises the key it was given when it locks.
        let key = SecureBytes(copying: (0..<32).map { UInt8($0) })
        try await engine.unlock(reuseKey: key, ledger: ledger, items: items, now: await clock.now())
    }

    /// Runs the loop the session runs, moving the clock through waits. Returns the outcomes of the scans.
    @discardableResult
    func runUntilIdle(_ items: [Item], limit: Int = 5000) async -> [ScanOutcome] {
        var outcomes: [ScanOutcome] = []
        for _ in 0..<limit {
            let now = await clock.now()
            switch await engine.next(now: now) {
            case .scan(let id, _):
                guard let item = items.first(where: { $0.id == id }) else {
                    Issue.record("the engine asked for an item it was not given")
                    return outcomes
                }
                outcomes.append(await engine.scan(item, now: now))
            case .wait(let until, _):
                await clock.set(until)
            case .idle, .locked:
                return outcomes
            }
        }
        Issue.record("the engine never became idle")
        return outcomes
    }
}

@Suite("Hygiene engine")
struct HygieneEngineTests {
    @Test("unlock, scan to idle, report: breached, reused and weak passwords are all found")
    func endToEnd() async throws {
        let rig = await EngineRig(breached: ["hunter2": 17_043, "password": 10_434_004])
        let items = [
            HygieneFixtures.item(1, title: "Bank", password: "hunter2"),
            HygieneFixtures.item(2, title: "Forum", password: "password"),
            HygieneFixtures.item(3, title: "Mail"),
            HygieneFixtures.item(4, title: "Shop", password: "shared-secret-1"),
            HygieneFixtures.item(5, title: "Club", password: "shared-secret-1"),
            HygieneFixtures.item(6, title: "Notes", password: nil),
            HygieneFixtures.item(7, title: "Old", trashedAt: HygieneFixtures.now),
        ]
        try await rig.unlock(items)
        let outcomes = await rig.runUntilIdle(items)
        #expect(outcomes.count == 5)
        #expect(outcomes[0] == .scanned(breachedPasswords: 1, networkRequests: 1))

        let report = try await rig.engine.report(now: await rig.clock.now())
        #expect(report.totals.items == 6)
        #expect(report.totals.itemsAwaitingBreachCheck == 0)
        #expect(report.totals.itemsByKind[.breachedPassword] == 2)
        #expect(report.totals.itemsByKind[.reusedPassword] == 2)
        #expect(report.item(HygieneFixtures.id(1))?.findings.first?.detail == .breached(occurrences: 17_043))
        #expect(
            report.item(HygieneFixtures.id(2))?.findings.map(\.kind).prefix(2) == [.breachedPassword, .weakPassword])
        #expect(report.item(HygieneFixtures.id(3))?.breachStatus == .clear(checkedAt: HygieneFixtures.now))
        #expect(report.item(HygieneFixtures.id(6))?.breachStatus == .notApplicable)
        #expect(report.item(HygieneFixtures.id(7)) == nil)
        #expect(report.totals.lastFullScanCompletedAt != nil)

        // Items 4 and 5 share a password, so a prefix: four requests for five scans.
        #expect(await rig.http.requests.count == 4)
        #expect(outcomes.filter { $0 == .scanned(breachedPasswords: 0, networkRequests: 0) }.count == 1)
    }

    @Test("an item saved while unlocked is checked at once and the report follows")
    func save() async throws {
        let rig = await EngineRig(breached: ["hunter2": 5])
        var item = HygieneFixtures.item(1)
        try await rig.unlock([item])
        await rig.runUntilIdle([item])
        #expect(
            try await rig.engine.report(now: HygieneFixtures.now).items[0].breachStatus
                == .clear(checkedAt: HygieneFixtures.now))

        // The person changes the password to a breached one.
        item.fields[1].value = "hunter2"
        item.version = 2
        try await rig.engine.update(item)
        let now = await rig.clock.now()
        #expect(try await rig.engine.report(now: now).items[0].breachStatus == .notChecked)
        #expect(await rig.engine.next(now: now) == .scan(item: item.id, reason: .changed))
        #expect(await rig.engine.scan(item, now: now) == .scanned(breachedPasswords: 1, networkRequests: 1))
        #expect(try await rig.engine.report(now: now).items[0].breachStatus == .breached(checkedAt: now))
    }

    @Test("the editor can ask whether a password is already in use")
    func reuseLookup() async throws {
        let rig = await EngineRig()
        try await rig.unlock([HygieneFixtures.item(1, password: "shared-secret-1"), HygieneFixtures.item(2)])
        #expect(try await rig.engine.items(using: "shared-secret-1") == [HygieneFixtures.id(1)])
        #expect(try await rig.engine.items(using: "something-else").isEmpty)
        #expect(await rig.http.requests.isEmpty)
    }

    @Test("trashing or deleting an item takes it out of the report and the ledger")
    func removal() async throws {
        let rig = await EngineRig()
        var first = HygieneFixtures.item(1, password: "shared-secret-1")
        let second = HygieneFixtures.item(2, password: "shared-secret-1")
        try await rig.unlock([first, second])
        await rig.runUntilIdle([first, second])
        #expect(try await rig.engine.report(now: HygieneFixtures.now).totals.itemsByKind[.reusedPassword] == 2)

        first.trashedAt = HygieneFixtures.now
        first.version = 2
        try await rig.engine.update(first)
        var report = try await rig.engine.report(now: HygieneFixtures.now)
        #expect(report.items.map(\.id) == [second.id])
        #expect(report.totals.itemsByKind[.reusedPassword] == nil)
        #expect(try await rig.engine.ledger().entries[first.id] == nil)
        #expect(await rig.engine.scan(first, now: HygieneFixtures.now) == .nothingToCheck)

        await rig.engine.remove(second.id)
        report = try await rig.engine.report(now: HygieneFixtures.now)
        #expect(report.items.isEmpty)
        #expect(try await rig.engine.ledger().entries.isEmpty)
    }

    @Test("a persisted ledger carries results across a lock, and changed items are rescanned after unlock")
    func relock() async throws {
        let rig = await EngineRig(breached: ["hunter2": 5])
        var items = [HygieneFixtures.item(1, password: "hunter2"), HygieneFixtures.item(2), HygieneFixtures.item(3)]
        try await rig.unlock(items)
        await rig.runUntilIdle(items)
        let ledger = try await rig.engine.ledger()
        await rig.engine.lock()
        await rig.http.forgetRequests()

        // While locked, sync replaced item 2. A day later the vault is unlocked with the stored ledger.
        await rig.clock.advance(by: 86400)
        items[1].version = 8
        try await rig.unlock(items, ledger: ledger)
        var report = try await rig.engine.report(now: await rig.clock.now())
        #expect(report.item(items[0].id)?.breachStatus == .breached(checkedAt: HygieneFixtures.now))
        #expect(report.item(items[1].id)?.breachStatus == .notChecked)
        let outcomes = await rig.runUntilIdle(items)
        // One scan, for the changed item; its range is still cached, so nothing is sent.
        #expect(outcomes == [.scanned(breachedPasswords: 0, networkRequests: 0)])
        #expect(await rig.http.requests.isEmpty)
        report = try await rig.engine.report(now: await rig.clock.now())
        #expect(report.totals.itemsAwaitingBreachCheck == 0)
    }

    @Test("the weekly pass asks the server again, once per prefix, and spreads its requests")
    func weeklyPass() async throws {
        let rig = await EngineRig()
        let items = (1...8).map { HygieneFixtures.item($0) }
        try await rig.unlock(items)
        await rig.runUntilIdle(items)
        #expect(await rig.http.requests.count == 8)
        await rig.http.forgetRequests()

        // Six days on, nothing is due and nothing is asked.
        await rig.clock.advance(by: 6 * 86400)
        #expect(await rig.runUntilIdle(items).isEmpty)
        #expect(await rig.http.requests.isEmpty)

        // On the seventh day the pass begins. The cache is not yet seven days old for the later items, but the pass
        // asks afresh all the same.
        await rig.clock.advance(by: 86400)
        let began = await rig.clock.now()
        let outcomes = await rig.runUntilIdle(items)
        #expect(outcomes.count == 8)
        #expect(outcomes.allSatisfy { $0 == .scanned(breachedPasswords: 0, networkRequests: 1) })
        #expect(await rig.http.requests.count == 8)
        // Seven gaps of at least the spacing each.
        #expect(await rig.clock.now() >= began.addingTimeInterval(7 * ScanPolicy.standard.requestSpacing))
        #expect(try await rig.engine.ledger().fullScanCompletedAt != nil)
    }

    @Test("a failing server backs the scan off, and the scan finishes once it recovers")
    func recovery() async throws {
        let rig = await EngineRig()
        let items = (1...3).map { HygieneFixtures.item($0) }
        try await rig.unlock(items)
        await rig.http.enqueue(status: 429, headers: ["Retry-After": "120"])
        await rig.http.enqueue(status: 503)
        await rig.http.enqueue(.failure)
        let start = await rig.clock.now()
        let outcomes = await rig.runUntilIdle(items)
        #expect(
            Array(outcomes.prefix(3)) == [
                .failed(.rateLimited(retryAfter: 120)), .failed(.serverUnavailable(status: 503, retryAfter: 300)),
                .failed(.transport),
            ])
        #expect(outcomes.suffix(3).allSatisfy { $0 == .scanned(breachedPasswords: 0, networkRequests: 1) })
        #expect(await rig.clock.now() >= start.addingTimeInterval(120 + 300 + 240))
        #expect(try await rig.engine.report(now: await rig.clock.now()).totals.itemsAwaitingBreachCheck == 0)
    }

    @Test("a save's check is deferred, not sent, while the server has asked for quiet")
    func deferred() async throws {
        let rig = await EngineRig()
        let items = [HygieneFixtures.item(1), HygieneFixtures.item(2)]
        try await rig.unlock(items)
        await rig.http.enqueue(status: 429, headers: ["Retry-After": "600"])
        let now = await rig.clock.now()
        #expect(await rig.engine.scan(items[0], now: now) == .failed(.rateLimited(retryAfter: 600)))
        #expect(await rig.engine.scan(items[1], now: now) == .deferred(until: now.addingTimeInterval(600)))
        #expect(await rig.http.requests.count == 1)
    }

    @Test("only one scan runs at a time")
    func singleFlight() async throws {
        let rig = await EngineRig()
        let items = [HygieneFixtures.item(1), HygieneFixtures.item(2)]
        try await rig.unlock(items)
        await rig.http.hold()
        let now = await rig.clock.now()
        async let first = rig.engine.scan(items[0], now: now)
        await rig.http.waitForHeldRequest()
        #expect(await rig.engine.scan(items[1], now: now) == .busy)
        if case .wait = await rig.engine.next(now: now) {
        } else {
            Issue.record("next() should wait while a scan is in flight")
        }
        await rig.http.release()
        #expect(await first == .scanned(breachedPasswords: 0, networkRequests: 1))
    }

    @Test("an item with several passwords is checked field by field")
    func severalPasswords() async throws {
        let rig = await EngineRig(breached: ["hunter2": 9])
        let second = Field(id: HygieneFixtures.fieldID(1, 2), kind: .password, label: "Old", value: "hunter2")
        let item = HygieneFixtures.item(1, extra: [second])
        try await rig.unlock([item])
        let now = await rig.clock.now()
        #expect(await rig.engine.scan(item, now: now) == .scanned(breachedPasswords: 1, networkRequests: 2))
        let entry = try #require(try await rig.engine.ledger().entries[item.id])
        #expect(entry.results == [HygieneFixtures.fieldID(1): .notFound, second.id: .found(occurrences: 9)])
        let report = try await rig.engine.report(now: now)
        #expect(report.items[0].findings.first?.fieldID == second.id)
    }

    @Test("the site directory is used only when the app chooses one")
    func directoryOptIn() async throws {
        let item = HygieneFixtures.item(1, host: "github.com")
        let plain = await EngineRig()
        try await plain.unlock([item])
        #expect(try await plain.engine.report(now: HygieneFixtures.now).totals.itemsByKind[.twoFactorAvailable] == nil)
        let informed = await EngineRig(policy: HygienePolicy(siteDirectory: EmbeddedSiteDirectory()))
        try await informed.unlock([item])
        #expect(try await informed.engine.report(now: HygieneFixtures.now).totals.itemsByKind[.twoFactorAvailable] == 1)
    }

    @Test("a short reuse key is refused and the engine stays locked")
    func shortKey() async {
        let rig = await EngineRig()
        await #expect(throws: ReuseKeyError.tooShort) {
            try await rig.engine.unlock(
                reuseKey: SecureBytes(copying: [1, 2, 3]), ledger: ScanLedger(), items: [], now: HygieneFixtures.now)
        }
        #expect(await rig.engine.isUnlocked == false)
        let spent = SecureBytes(copying: [UInt8](repeating: 7, count: 32))
        spent.zeroise()
        await #expect(throws: ReuseKeyError.zeroised) {
            try await rig.engine.unlock(reuseKey: spent, ledger: ScanLedger(), items: [], now: HygieneFixtures.now)
        }
    }
}
