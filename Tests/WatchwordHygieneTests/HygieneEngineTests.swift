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

    /// - Parameter gate: if given, `unlock` passes through it after each item, so a test can hold it there.
    init(
        breached: [String: UInt32] = [:], policy: HygienePolicy = HygienePolicy(), scanPolicy: ScanPolicy = .standard,
        gate: CheckpointGate? = nil
    ) async {
        let client = PwnedPasswordsClient(http: http, cache: cache, userAgent: HygieneUserAgent(version: "1.0")!)
        engine = HygieneEngine(
            client: client, policy: policy, scanPolicy: scanPolicy, random: SeededGenerator(seed: 11)
        ) { await gate?.pass() }
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
        // One scan, for the changed item. The lock emptied the prefix cache, so its range is asked for again.
        #expect(outcomes == [.scanned(breachedPasswords: 0, networkRequests: 1)])
        #expect(await rig.http.requests.count == 1)
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

    @Test("an older copy of an item changes nothing: it cannot replace the newer analysis or mark it checked")
    func staleCopy() async throws {
        let rig = await EngineRig(breached: ["hunter2": 5])
        var item = HygieneFixtures.item(1)
        try await rig.unlock([item])
        await rig.runUntilIdle([item])
        // The session fetched version 1 for a scan; before it could call `scan`, the person saved version 2, with
        // a breached password.
        let fetchedEarlier = item
        item.fields[1].value = "hunter2"
        item.version = 2
        #expect(try await rig.engine.update(item))
        let now = await rig.clock.now()
        #expect(await rig.engine.scan(fetchedEarlier, now: now) == .stale)
        #expect(try await rig.engine.update(fetchedEarlier) == false)

        #expect(try await rig.engine.report(now: now).items[0].breachStatus == .notChecked)
        #expect(await rig.engine.next(now: now) == .scan(item: item.id, reason: .changed))
        #expect(try await rig.engine.items(using: "hunter2") == [item.id])
        #expect(try await rig.engine.ledger().entries[item.id]?.itemVersion == 1)
        #expect(await rig.engine.scan(item, now: now) == .scanned(breachedPasswords: 1, networkRequests: 1))
        #expect(try await rig.engine.report(now: now).items[0].breachStatus == .breached(checkedAt: now))
    }

    @Test("an item saved while its ranges are being fetched is not recorded as checked")
    func savedDuringScan() async throws {
        let rig = await EngineRig(breached: ["hunter2": 5])
        var item = HygieneFixtures.item(1)
        try await rig.unlock([item])
        let now = await rig.clock.now()
        await rig.http.hold()
        let scanning = item
        async let outcome = rig.engine.scan(scanning, now: now)
        await rig.http.waitForHeldRequest()
        item.fields[1].value = "hunter2"
        item.version = 2
        try await rig.engine.update(item)
        await rig.http.release()
        #expect(await outcome == .stale)
        #expect(try await rig.engine.ledger().entries[item.id] == nil)
        #expect(try await rig.engine.report(now: now).items[0].breachStatus == .notChecked)
        #expect(await rig.engine.next(now: now) == .scan(item: item.id, reason: .created))
        #expect(await rig.engine.scan(scanning, now: now) == .stale)
        #expect(await rig.engine.scan(item, now: now) == .scanned(breachedPasswords: 1, networkRequests: 1))
    }

    @Test("a copy from before an item was trashed or deleted does not bring it back")
    func staleAfterRemoval() async throws {
        let rig = await EngineRig()
        let first = HygieneFixtures.item(1)
        let second = HygieneFixtures.item(2)
        try await rig.unlock([first, second])
        let now = await rig.clock.now()

        var trashed = first
        trashed.trashedAt = now
        trashed.version = 2
        try await rig.engine.update(trashed)
        #expect(await rig.engine.scan(first, now: now) == .stale)
        #expect(try await rig.engine.update(first) == false)
        // The same version, not trashed: the copy the scanner fetched just before the trash was written.
        var before = trashed
        before.trashedAt = nil
        #expect(await rig.engine.scan(before, now: now) == .stale)

        await rig.engine.remove(second.id)
        #expect(await rig.engine.scan(second, now: now) == .stale)
        #expect(try await rig.engine.report(now: now).items.isEmpty)
        #expect(await rig.http.requests.isEmpty)

        // Restored, as a newer version, it is an item again.
        var restored = first
        restored.version = 3
        #expect(try await rig.engine.update(restored))
        #expect(try await rig.engine.report(now: now).items.map(\.id) == [first.id])
    }

    @Test("a lock and unlock does not forget the server's Retry-After")
    func backoffSurvivesLock() async throws {
        let rig = await EngineRig()
        let items = (1...8).map { HygieneFixtures.item($0) }
        try await rig.unlock(items)
        await rig.http.enqueue(status: 429, headers: ["Retry-After": "3600"])
        let start = await rig.clock.now()
        #expect(await rig.engine.scan(items[0], now: start) == .failed(.rateLimited(retryAfter: 3600)))
        let ledger = try await rig.engine.ledger()
        await rig.engine.lock()

        // The phone is unlocked again ten seconds later, as phones are.
        await rig.clock.advance(by: 10)
        try await rig.unlock(items, ledger: ledger)
        let now = await rig.clock.now()
        #expect(await rig.engine.next(now: now) == .wait(until: start.addingTimeInterval(3600), .backoff))
        #expect(await rig.engine.scan(items[1], now: now) == .deferred(until: start.addingTimeInterval(3600)))
        #expect(await rig.http.requests.count == 1)
    }

    @Test("a lock and unlock does not hand the scanner a fresh burst")
    func burstSurvivesLock() async throws {
        let rig = await EngineRig()
        let items = (1...12).map { HygieneFixtures.item($0) }
        try await rig.unlock(items)
        let now = await rig.clock.now()
        for _ in 0..<5 {
            guard case .scan(let id, _) = await rig.engine.next(now: now) else {
                Issue.record("expected the burst")
                return
            }
            _ = await rig.engine.scan(items.first { $0.id == id }!, now: now)
        }
        #expect(await rig.http.requests.count == 5)
        for _ in 0..<3 {
            let ledger = try await rig.engine.ledger()
            await rig.engine.lock()
            try await rig.unlock(items, ledger: ledger)
            #expect(await rig.engine.next(now: now) == .wait(until: now.addingTimeInterval(2), .pacing))
            #expect(await rig.engine.scan(items[11], now: now) == .deferred(until: now.addingTimeInterval(2)))
        }
        #expect(await rig.http.requests.count == 5)
    }

    /// Twenty times over, at one instant: a scan is started, the vault locks while its request is in flight, and
    /// the vault is unlocked again. Each of those requests was sent, so each is paid for.
    @Test(
        "requests made by scans that a lock interrupts are charged to the rate limit",
        arguments: [true, false])
    func interruptedScansPay(unlockBeforeTheResponse: Bool) async throws {
        let rig = await EngineRig()
        let items = (1...20).map { HygieneFixtures.item($0) }
        try await rig.unlock(items)
        let now = await rig.clock.now()
        var interrupted = 0
        for _ in 0..<20 {
            guard case .scan(let id, _) = await rig.engine.next(now: now) else { break }
            let item = try #require(items.first { $0.id == id })
            await rig.http.hold()
            async let outcome = rig.engine.scan(item, now: now)
            await rig.http.waitForHeldRequest()
            let ledger = try await rig.engine.ledger()
            await rig.engine.lock()
            if unlockBeforeTheResponse { try await rig.unlock(items, ledger: ledger) }
            await rig.http.release()
            #expect(await outcome == .interrupted)
            if !unlockBeforeTheResponse { try await rig.unlock(items, ledger: ledger) }
            interrupted += 1
        }
        // The burst, and then the scanner is told to wait like any other.
        #expect(interrupted == ScanPolicy.standard.burst)
        #expect(await rig.http.requests.count == ScanPolicy.standard.burst)
        #expect(await rig.engine.next(now: now) == .wait(until: now.addingTimeInterval(2), .pacing))
        #expect(await rig.engine.scan(items[0], now: now) == .deferred(until: now.addingTimeInterval(2)))
        // Nothing but the pacing was written: no result, and no failure held against an item.
        let ledger = try await rig.engine.ledger()
        #expect(ledger.entries.isEmpty)
        #expect(ledger.failures.isEmpty)
    }

    @Test(
        "a Retry-After that arrives just after a lock is still honoured after the unlock",
        arguments: [true, false])
    func refusalAfterLockStands(unlockBeforeTheResponse: Bool) async throws {
        let rig = await EngineRig()
        let items = (1...3).map { HygieneFixtures.item($0) }
        try await rig.unlock(items)
        let now = await rig.clock.now()
        await rig.http.hold()
        await rig.http.enqueue(status: 429, headers: ["Retry-After": "900"])
        async let outcome = rig.engine.scan(items[0], now: now)
        await rig.http.waitForHeldRequest()
        await rig.engine.lock()
        if unlockBeforeTheResponse { try await rig.unlock(items) }
        await rig.http.release()
        #expect(await outcome == .interrupted)
        if !unlockBeforeTheResponse { try await rig.unlock(items) }
        #expect(await rig.engine.next(now: now) == .wait(until: now.addingTimeInterval(900), .backoff))
        #expect(await rig.engine.scan(items[1], now: now) == .deferred(until: now.addingTimeInterval(900)))
        #expect(await rig.http.requests.count == 1)
        // The item is not held to have failed: its check was interrupted, not refused, as far as the ledger goes.
        #expect(try await rig.engine.ledger().failures.isEmpty)
    }

    @Test("a failed check is in the ledger the session stores, and a completed one takes it out again")
    func failureIsInTheLedger() async throws {
        let rig = await EngineRig()
        let items = [HygieneFixtures.item(1, version: 4), HygieneFixtures.item(2)]
        try await rig.unlock(items)
        await rig.http.enqueue(status: 503)
        let now = await rig.clock.now()
        #expect(await rig.engine.scan(items[0], now: now) == .failed(.serverUnavailable(status: 503, retryAfter: 300)))
        var ledger = try await rig.engine.ledger()
        #expect(ledger.failures == [items[0].id: .init(itemVersion: 4, count: 1, failedAt: now)])
        #expect(ledger.entries.isEmpty)
        // Carried across a lock by the session, it sends the item to the back at the next unlock.
        await rig.engine.lock()
        await rig.clock.advance(by: 600)
        try await rig.unlock(items, ledger: ledger)
        let later = await rig.clock.now()
        #expect(await rig.engine.next(now: later) == .scan(item: items[1].id, reason: .created))
        #expect(await rig.engine.scan(items[0], now: later) == .scanned(breachedPasswords: 0, networkRequests: 1))
        ledger = try await rig.engine.ledger()
        #expect(ledger.failures.isEmpty)
        // A failure for an item that has since gone does not come back with the ledger.
        await rig.http.enqueue(status: 503)
        #expect(
            await rig.engine.scan(items[1], now: later) == .failed(.serverUnavailable(status: 503, retryAfter: 300)))
        ledger = try await rig.engine.ledger()
        #expect(ledger.failures.count == 1)
        await rig.engine.lock()
        try await rig.unlock([items[0]], ledger: ledger)
        #expect(try await rig.engine.ledger().failures.isEmpty)
    }

    @Test("an unlock over an unlocked engine is a lock first: the old key is zeroised and the cache emptied")
    func reunlockLocksFirst() async throws {
        let rig = await EngineRig()
        let items = (1...3).map { HygieneFixtures.item($0) }
        let first = SecureBytes(copying: [UInt8](repeating: 7, count: 32))
        try await rig.engine.unlock(reuseKey: first, ledger: ScanLedger(), items: items, now: HygieneFixtures.now)
        await rig.runUntilIdle(items)
        #expect(await rig.cache.entries.count == 3)

        try await rig.unlock(items)
        #expect(first.isZeroised)
        #expect(await rig.cache.locks == 1)
        #expect(await rig.cache.entries.isEmpty)
        #expect(await rig.engine.isUnlocked)
    }

    @Test("an unlock that fails over an unlocked engine leaves it locked, with the cache emptied")
    func failedReunlock() async throws {
        let rig = await EngineRig()
        let items = (1...3).map { HygieneFixtures.item($0) }
        let key = SecureBytes(copying: [UInt8](repeating: 7, count: 32))
        try await rig.engine.unlock(reuseKey: key, ledger: ScanLedger(), items: items, now: HygieneFixtures.now)
        await rig.runUntilIdle(items)
        #expect(await rig.cache.entries.count == 3)
        // The same buffer again: the lock that an unlock begins with zeroises it, so it is no key.
        await #expect(throws: ReuseKeyError.zeroised) {
            try await rig.engine.unlock(reuseKey: key, ledger: ScanLedger(), items: items, now: HygieneFixtures.now)
        }
        #expect(await rig.engine.isUnlocked == false)
        #expect(await rig.cache.entries.isEmpty)
        #expect(await rig.cache.locks == 1)
        // A key that is not one is refused before anything is touched: the engine stays as it was.
        try await rig.unlock(items)
        await rig.runUntilIdle(items)
        await #expect(throws: ReuseKeyError.tooShort) {
            try await rig.engine.unlock(
                reuseKey: SecureBytes(copying: [1, 2, 3]), ledger: ScanLedger(), items: [], now: HygieneFixtures.now)
        }
        #expect(await rig.engine.isUnlocked)
        #expect(await rig.cache.entries.count == 3)
    }

    @Test("while unlock is still analysing, nothing is decided or reported, and a save made meanwhile is kept")
    func analysing() async throws {
        let gate = CheckpointGate(holdingAfter: 2)
        let rig = await EngineRig(gate: gate)
        let loaded = (1...5).map { HygieneFixtures.item($0) }
        var items = loaded
        let unlocking = Task { try await rig.unlock(loaded) }
        await gate.waitUntilHeld()
        let now = await rig.clock.now()
        #expect(await rig.engine.isUnlocked)
        #expect(await rig.engine.isAnalysing)
        #expect(await rig.engine.next(now: now) == .wait(until: now.addingTimeInterval(2), .analysing))
        #expect(await rig.engine.scan(items[0], now: now) == .busy)
        await #expect(throws: HygieneEngineError.analysing) { try await rig.engine.report(now: now) }

        // Meanwhile the person edits the fifth item, which unlock has not reached, and deletes the fourth.
        items[4].fields[1].value = "password"
        items[4].version = 2
        #expect(try await rig.engine.update(items[4]))
        await rig.engine.remove(items[3].id)

        await gate.release()
        try await unlocking.value
        #expect(await rig.engine.isAnalysing == false)
        let report = try await rig.engine.report(now: now)
        #expect(Set(report.items.map(\.id)) == Set(items.map(\.id)).subtracting([items[3].id]))
        // Unlock's own copy of the fifth item was version 1, with a strong password; it did not replace the edit.
        #expect(report.item(items[4].id)?.findings.contains { $0.kind == .weakPassword } == true)
        #expect(await rig.engine.next(now: now) == .scan(item: items[0].id, reason: .created))
        #expect(await rig.http.requests.isEmpty)
    }

    @Test("a second unlock supersedes one still analysing")
    func supersededUnlock() async throws {
        let gate = CheckpointGate(holdingAfter: 1)
        let rig = await EngineRig(gate: gate)
        let items = (1...3).map { HygieneFixtures.item($0) }
        let first = Task { try await rig.unlock(items) }
        await gate.waitUntilHeld()
        try await rig.unlock([items[0]])
        await gate.release()
        await #expect(throws: HygieneEngineError.locked) { try await first.value }
        #expect(try await rig.engine.report(now: HygieneFixtures.now).items.map(\.id) == [items[0].id])
    }

    @Test("two password fields that share an ID cannot hide a breached password behind a clean one")
    func duplicateFieldIDs() async throws {
        for breachedFirst in [true, false] {
            let rig = await EngineRig(breached: ["password": 9])
            // Nothing makes field IDs distinct: an import, or another member of a shared vault, can write this.
            let shared = HygieneFixtures.fieldID(1)
            let strong = HygieneFixtures.strongPassword(1)
            let values = breachedFirst ? ["password", strong] : [strong, "password"]
            var item = HygieneFixtures.item(1, password: nil)
            item.fields += values.map { Field(id: shared, kind: .password, label: "Password", value: $0) }
            try await rig.unlock([item])
            let now = await rig.clock.now()
            #expect(await rig.engine.scan(item, now: now) == .scanned(breachedPasswords: 1, networkRequests: 2))
            #expect(try await rig.engine.ledger().entries[item.id]?.results == [shared: .found(occurrences: 9)])
            let hygiene = try #require(try await rig.engine.report(now: now).item(item.id))
            #expect(hygiene.breachStatus == .breached(checkedAt: now))
            #expect(hygiene.findings.filter { $0.kind == .breachedPassword }.count == 1)
            #expect(hygiene.findings.first?.detail == .breached(occurrences: 9))
        }
    }

    @Test("an item with more passwords than are checked is never called clear")
    func tooManyPasswords() async throws {
        let rig = await EngineRig(breached: ["password": 9])
        let extra = (2...16).map {
            Field(
                id: HygieneFixtures.fieldID(1, $0), kind: .password, label: "Password \($0)",
                value: HygieneFixtures.strongPassword(100 + $0))
        }
        // The seventeenth password is the breached one, and it is beyond the cap.
        let seventeenth = Field(id: HygieneFixtures.fieldID(1, 17), kind: .password, label: "Old", value: "password")
        let item = HygieneFixtures.item(1, extra: extra + [seventeenth])
        try await rig.unlock([item])
        let now = await rig.clock.now()
        #expect(await rig.engine.scan(item, now: now) == .scanned(breachedPasswords: 0, networkRequests: 16))
        let report = try await rig.engine.report(now: now)
        let hygiene = try #require(report.item(item.id))
        #expect(hygiene.breachStatus == .incomplete(checkedAt: now))
        let finding = try #require(hygiene.findings.first { $0.kind == .tooManyPasswords })
        #expect(finding.severity == .low)
        #expect(finding.detail == .notAnalysed(passwords: 1))
        #expect(hygiene.badges.contains(HygieneBadge(kind: .tooManyPasswords, severity: .low)))
        #expect(report.itemsNeedingAttention.map(\.id) == [item.id])
        #expect(report.totals.itemsAwaitingBreachCheck == 0)
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
