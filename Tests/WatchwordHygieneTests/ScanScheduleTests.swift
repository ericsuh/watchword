import Foundation
import Testing
import WatchwordHygiene
import WatchwordTestSupport

/// PRD F9.2 and ADR 0005 as a table over an injected clock (docs/04-test-plan.md §6.6). Time only moves when a test
/// moves `FakeClock`.
@Suite("Breach scan scheduling")
struct ScanScheduleTests {
    static let week: TimeInterval = 7 * 24 * 60 * 60

    static func id(_ number: Int) -> UUID {
        UUID(
            uuidString: "00000000-0000-0000-0000-" + String(repeating: "0", count: 12 - String(number).count)
                + String(number))!
    }

    static func candidates(_ count: Int, version: UInt64 = 1) -> [ScanCandidate] {
        (1...count).map { ScanCandidate(id: id($0), version: version) }
    }

    /// Scans whatever the schedule asks for, moving the clock through its waits, until it is idle. Returns the items
    /// scanned, in order.
    static func drain(
        _ schedule: inout ScanSchedule, _ candidates: [ScanCandidate], clock: FakeClock, networkRequests: Int = 1,
        limit: Int = 10_000
    ) async -> [UUID] {
        var scanned: [UUID] = []
        for _ in 0..<limit {
            let now = await clock.now()
            switch schedule.decide(candidates: candidates, keysResident: true, now: now) {
            case .scan(let item, _):
                let version = candidates.first { $0.id == item }?.version ?? 0
                schedule.recordScan(
                    item: item, version: version, results: [:], networkRequests: networkRequests, now: now,
                    jitter: 0.5)
                scanned.append(item)
            case .wait(let until, _):
                await clock.set(until)
            case .idle, .locked:
                return scanned
            }
        }
        Issue.record("the schedule never became idle")
        return scanned
    }

    @Test("with keys absent the answer is locked, whatever is due, and the ledger is untouched")
    func locked() async {
        let clock = FakeClock()
        var schedule = ScanSchedule()
        let before = schedule.ledger
        #expect(schedule.decide(candidates: Self.candidates(5), keysResident: false, now: await clock.now()) == .locked)
        #expect(schedule.ledger == before)
        #expect(schedule.ledger.fullScanStartedAt == nil)
    }

    @Test("a new item is due at once, as created")
    func created() async {
        let clock = FakeClock()
        var schedule = ScanSchedule()
        let decision = schedule.decide(candidates: Self.candidates(1), keysResident: true, now: await clock.now())
        #expect(decision == .scan(item: Self.id(1), reason: .created))
    }

    @Test("an edited item is due again, as changed, ahead of the weekly pass")
    func edited() async {
        let clock = FakeClock()
        var schedule = ScanSchedule()
        _ = await Self.drain(&schedule, Self.candidates(3), clock: clock)
        await clock.advance(by: Self.week + 60)
        var edited = Self.candidates(3)
        edited[2] = ScanCandidate(id: Self.id(3), version: 2)
        let decision = schedule.decide(candidates: edited, keysResident: true, now: await clock.now())
        #expect(decision == .scan(item: Self.id(3), reason: .changed))
    }

    @Test("after an unlock, only items changed since their last scan are due")
    func changedSinceLastScan() async {
        let clock = FakeClock()
        var schedule = ScanSchedule()
        _ = await Self.drain(&schedule, Self.candidates(4), clock: clock)
        // Locked for a day; sync changed two items meanwhile.
        await clock.advance(by: 86400)
        #expect(schedule.decide(candidates: Self.candidates(4), keysResident: false, now: await clock.now()) == .locked)
        var after = Self.candidates(4)
        after[0] = ScanCandidate(id: Self.id(1), version: 9)
        after[3] = ScanCandidate(id: Self.id(4), version: 3)
        var resumed = ScanSchedule(ledger: schedule.ledger)
        let scanned = await Self.drain(&resumed, after, clock: clock)
        #expect(scanned == [Self.id(1), Self.id(4)])
    }

    @Test("everything current: idle until a week after the pass began")
    func idle() async {
        let clock = FakeClock()
        let start = await clock.now()
        var schedule = ScanSchedule()
        _ = await Self.drain(&schedule, Self.candidates(3), clock: clock)
        let decision = schedule.decide(candidates: Self.candidates(3), keysResident: true, now: await clock.now())
        #expect(decision == .idle(nextFullScanAt: start.addingTimeInterval(Self.week)))
        #expect(schedule.ledger.fullScanCompletedAt != nil)
    }

    @Test("a week after a pass began, every item is due again, oldest scan first")
    func weekly() async {
        let clock = FakeClock()
        var schedule = ScanSchedule()
        let first = await Self.drain(&schedule, Self.candidates(6), clock: clock)
        #expect(first.count == 6)
        await clock.advance(by: Self.week - 3600)
        if case .idle = schedule.decide(candidates: Self.candidates(6), keysResident: true, now: await clock.now()) {
        } else {
            Issue.record("a pass began before the week was up")
        }
        await clock.advance(by: 3600)
        let now = await clock.now()
        #expect(
            schedule.decide(candidates: Self.candidates(6), keysResident: true, now: now)
                == .scan(item: first[0], reason: .weekly))
        let second = await Self.drain(&schedule, Self.candidates(6), clock: clock)
        #expect(second == first)
        #expect(schedule.passInProgressSince == nil)
    }

    @Test("a pass interrupted by a lock resumes where it stopped at the next unlock")
    func resumes() async {
        let clock = FakeClock()
        var schedule = ScanSchedule()
        let all = Self.candidates(10)
        _ = await Self.drain(&schedule, all, clock: clock)
        await clock.advance(by: Self.week)
        let passStart = await clock.now()

        // Four items into the weekly pass, the vault locks.
        var done: [UUID] = []
        while done.count < 4 {
            let now = await clock.now()
            switch schedule.decide(candidates: all, keysResident: true, now: now) {
            case .scan(let item, let reason):
                #expect(reason == .weekly)
                schedule.recordScan(item: item, version: 1, results: [:], networkRequests: 1, now: now, jitter: 0)
                done.append(item)
            case .wait(let until, _):
                await clock.set(until)
            default:
                Issue.record("unexpected decision")
                return
            }
        }
        let persisted = schedule.ledger
        #expect(persisted.fullScanStartedAt == passStart)
        #expect(persisted.fullScanCompletedAt == nil)

        // Locked overnight: nothing happens. A new process unlocks with the persisted ledger.
        #expect(schedule.decide(candidates: all, keysResident: false, now: await clock.now()) == .locked)
        await clock.advance(by: 12 * 3600)
        var resumed = ScanSchedule(ledger: persisted)
        let rest = await Self.drain(&resumed, all, clock: clock)
        #expect(Set(rest) == Set(all.map(\.id)).subtracting(done))
        #expect(rest.count == 6)
        // The next pass is due a week after this one began, not after it finished.
        let decision = resumed.decide(candidates: all, keysResident: true, now: await clock.now())
        #expect(decision == .idle(nextFullScanAt: passStart.addingTimeInterval(Self.week)))
    }

    @Test("requests burst up to the limit, then go one per spacing")
    func pacing() async {
        let clock = FakeClock()
        let start = await clock.now()
        let policy = ScanPolicy(requestSpacing: 2, burst: 3, maximumJitter: 0)
        var schedule = ScanSchedule(policy: policy)
        let all = Self.candidates(8)
        var times: [TimeInterval] = []
        for _ in 0..<1000 where times.count < 8 {
            let now = await clock.now()
            switch schedule.decide(candidates: all, keysResident: true, now: now) {
            case .scan(let item, _):
                schedule.recordScan(item: item, version: 1, results: [:], networkRequests: 1, now: now, jitter: 0)
                times.append(now.timeIntervalSince(start))
            case .wait(let until, let reason):
                #expect(reason == .pacing)
                #expect(until > now)
                await clock.set(until)
            default:
                Issue.record("unexpected decision")
            }
        }
        #expect(times == [0, 0, 0, 2, 4, 6, 8, 10])
    }

    @Test("checks answered from the cache cost nothing and wait for nothing")
    func cacheHitsAreFree() async {
        let clock = FakeClock()
        let start = await clock.now()
        var schedule = ScanSchedule(policy: ScanPolicy(burst: 2))
        let scanned = await Self.drain(&schedule, Self.candidates(50), clock: clock, networkRequests: 0)
        #expect(scanned.count == 50)
        #expect(await clock.now() == start)
    }

    @Test("the weekly pass adds jitter to its spacing")
    func jitter() async {
        let clock = FakeClock()
        let policy = ScanPolicy(requestSpacing: 2, burst: 5, maximumJitter: 4)
        var schedule = ScanSchedule(policy: policy)
        let all = Self.candidates(3)
        _ = await Self.drain(&schedule, all, clock: clock)
        await clock.advance(by: Self.week)
        var now = await clock.now()
        guard case .scan(let item, .weekly) = schedule.decide(candidates: all, keysResident: true, now: now) else {
            Issue.record("expected a weekly scan")
            return
        }
        schedule.recordScan(item: item, version: 1, results: [:], networkRequests: 1, now: now, jitter: 0.75)
        #expect(
            schedule.decide(candidates: all, keysResident: true, now: now)
                == .wait(until: now.addingTimeInterval(2 + 3), .pacing))
        // An out-of-range jitter is held to the range.
        await clock.advance(by: 5)
        now = await clock.now()
        guard case .scan(let next, .weekly) = schedule.decide(candidates: all, keysResident: true, now: now) else {
            Issue.record("expected a weekly scan")
            return
        }
        schedule.recordScan(item: next, version: 1, results: [:], networkRequests: 1, now: now, jitter: 99)
        #expect(
            schedule.decide(candidates: all, keysResident: true, now: now)
                == .wait(until: now.addingTimeInterval(2 + 4), .pacing))
    }

    @Test("a rate-limit response backs every request off for at least Retry-After")
    func backoffHonoursRetryAfter() async {
        let clock = FakeClock()
        var schedule = ScanSchedule()
        let all = Self.candidates(3)
        let now = await clock.now()
        guard case .scan(let item, _) = schedule.decide(candidates: all, keysResident: true, now: now) else { return }
        schedule.recordFailure(
            item: item, error: .rateLimited(retryAfter: 900), networkRequests: 1, now: now, jitter: 0)
        #expect(
            schedule.decide(candidates: all, keysResident: true, now: now)
                == .wait(until: now.addingTimeInterval(900), .backoff))
        #expect(schedule.earliestStart(for: Self.id(2), now: now) == now.addingTimeInterval(900))
        await clock.advance(by: 900)
        let later = await clock.now()
        // The request after the backoff is for a different item: the one that failed has gone to the back.
        #expect(
            schedule.decide(candidates: all, keysResident: true, now: later)
                == .scan(item: Self.id(2), reason: .created))
        #expect(item == Self.id(1))
        #expect(schedule.ledger.entries.isEmpty)
    }

    @Test("an item whose check keeps failing goes to the back, so the rest of the vault is still checked")
    func failingItemDoesNotStall() async {
        let clock = FakeClock()
        var schedule = ScanSchedule()
        let all = Self.candidates(6)
        let bad = Self.id(1)
        var scanned: [UUID] = []
        var attemptsOnBad = 0
        for _ in 0..<200 where scanned.count < 5 {
            let now = await clock.now()
            switch schedule.decide(candidates: all, keysResident: true, now: now) {
            case .scan(let item, _) where item == bad:
                attemptsOnBad += 1
                schedule.recordFailure(
                    item: item, error: .serverUnavailable(status: 503, retryAfter: 300), networkRequests: 1,
                    now: now, jitter: 0)
            case .scan(let item, _):
                schedule.recordScan(item: item, version: 1, results: [:], networkRequests: 1, now: now, jitter: 0)
                scanned.append(item)
            case .wait(let until, _):
                await clock.set(until)
            default:
                Issue.record("unexpected decision")
                return
            }
        }
        // The first request went to the most urgent item, which failed; every other item was then checked before
        // it was asked for a second time.
        #expect(Set(scanned) == Set(all.map(\.id)).subtracting([bad]))
        #expect(attemptsOnBad == 1)
        // Then it is the only one due, and is retried at the backoff's pace.
        await clock.advance(by: 60)
        let now = await clock.now()
        #expect(schedule.decide(candidates: all, keysResident: true, now: now) == .scan(item: bad, reason: .created))
    }

    @Test("of two items that failed, the one that failed longer ago is tried first")
    func failedLongestAgoFirst() async {
        let clock = FakeClock()
        var schedule = ScanSchedule(policy: ScanPolicy(initialBackoff: 10, maximumBackoff: 10))
        let all = Self.candidates(2)
        var order: [UUID] = []
        for _ in 0..<6 {
            let now = await clock.now()
            guard case .scan(let item, _) = schedule.decide(candidates: all, keysResident: true, now: now) else {
                Issue.record("expected a scan")
                return
            }
            order.append(item)
            schedule.recordFailure(item: item, error: .transport, networkRequests: 1, now: now, jitter: 0)
            await clock.advance(by: 10)
        }
        #expect(order == [Self.id(1), Self.id(2), Self.id(1), Self.id(2), Self.id(1), Self.id(2)])
    }

    @Test("a pass that cannot finish does not stop the next one: a week on, the other items are checked again")
    func unfinishedPassDoesNotBlockTheNext() async {
        let clock = FakeClock()
        let start = await clock.now()
        var schedule = ScanSchedule()
        let all = Self.candidates(3)
        let bad = Self.id(1)
        var healthyScans: [Date] = []
        // Thirty days, with one item whose range is never usable.
        while await clock.now() < start.addingTimeInterval(30 * 86400) {
            let now = await clock.now()
            switch schedule.decide(candidates: all, keysResident: true, now: now) {
            case .scan(let item, _) where item == bad:
                schedule.recordFailure(item: item, error: .malformedResponse, networkRequests: 1, now: now, jitter: 0)
            case .scan(let item, _):
                schedule.recordScan(item: item, version: 1, results: [:], networkRequests: 1, now: now, jitter: 0)
                if item == Self.id(2) { healthyScans.append(now) }
            case .wait(let until, _):
                guard until > now else {
                    Issue.record("a wait that ends now is a loop")
                    return
                }
                await clock.set(until)
            default:
                Issue.record("the failing item is still due, so the schedule is never idle")
                return
            }
        }
        // Day 0, then once in each weekly pass: days 7, 14, 21 and 28.
        #expect(healthyScans.count == 5)
        for (index, time) in healthyScans.enumerated() {
            let expected = start.addingTimeInterval(Double(index) * Self.week)
            #expect(time >= expected && time < expected.addingTimeInterval(3600))
        }
        // The pass in progress is never called finished while an item in it has not been checked.
        #expect(schedule.ledger.fullScanCompletedAt == nil)
    }

    @Test("waiting on a set-aside item never sleeps through the start of the next pass")
    func retryWaitEndsAtTheNextPass() async {
        let clock = FakeClock()
        let start = await clock.now()
        let policy = ScanPolicy(initialBackoff: 1, maximumBackoff: 1, itemRetryInitial: 6 * 86400)
        var schedule = ScanSchedule(policy: policy)
        let all = Self.candidates(1)
        // Fails twice: the second retry is twelve days out, past the next pass.
        for _ in 0..<2 {
            let now = await clock.now()
            guard case .scan(let item, _) = schedule.decide(candidates: all, keysResident: true, now: now) else {
                Issue.record("expected a scan")
                return
            }
            schedule.recordFailure(item: item, error: .responseTooLarge, networkRequests: 1, now: now, jitter: 0)
            await clock.advance(by: 6 * 86400)
        }
        await clock.set(start.addingTimeInterval(6 * 86400 + 60))
        let now = await clock.now()
        #expect(
            schedule.decide(candidates: all, keysResident: true, now: now)
                == .wait(until: start.addingTimeInterval(Self.week), .retry))
    }

    @Test("a pass whose start is slightly ahead of the clock still scans each item once")
    func passStartSlightlyAhead() async {
        let clock = FakeClock()
        var schedule = ScanSchedule()
        let all = Self.candidates(3)
        _ = await Self.drain(&schedule, all, clock: clock)
        await clock.advance(by: 86400)
        let now = await clock.now()
        // A pass in progress that began 200 seconds from now: the clock was put back during it, or the ledger
        // came from a clock that ran fast. Well inside the tolerance for clock error.
        var ledger = schedule.ledger
        ledger.fullScanStartedAt = now.addingTimeInterval(200)
        ledger.fullScanCompletedAt = nil
        var resumed = ScanSchedule(ledger: ledger)
        let scanned = await Self.drain(&resumed, all, clock: clock, limit: 500)
        #expect(scanned.count == 3)
        #expect(Set(scanned) == Set(all.map(\.id)))
        #expect(resumed.ledger.fullScanStartedAt == now)
        #expect(resumed.passInProgressSince == nil)
        // The pass's start is no later than any scan made in it, so a range cached during the pass counts as fresh.
        #expect(resumed.ledger.entries.values.allSatisfy { $0.scannedAt >= now })
    }

    @Test("the rate limit and the backoff are handed on to the next schedule, so a lock does not reset them")
    func pacingIsCarried() async {
        let clock = FakeClock()
        let policy = ScanPolicy(requestSpacing: 2, burst: 5, maximumJitter: 0)
        var schedule = ScanSchedule(policy: policy)
        let all = Self.candidates(20)
        let now = await clock.now()
        // The burst is spent, and then the server asks for an hour of quiet.
        for _ in 0..<5 {
            guard case .scan(let item, _) = schedule.decide(candidates: all, keysResident: true, now: now) else {
                Issue.record("expected a scan")
                return
            }
            schedule.recordScan(item: item, version: 1, results: [:], networkRequests: 1, now: now, jitter: 0)
        }
        #expect(
            schedule.decide(candidates: all, keysResident: true, now: now)
                == .wait(until: now.addingTimeInterval(2), .pacing))
        var relocked = ScanSchedule(ledger: schedule.ledger, policy: policy, pacing: schedule.pacing)
        #expect(
            relocked.decide(candidates: all, keysResident: true, now: now)
                == .wait(until: now.addingTimeInterval(2), .pacing))
        // Without the pacing, the same moment would have been a fresh burst.
        var forgetful = ScanSchedule(ledger: schedule.ledger, policy: policy)
        if case .scan = forgetful.decide(candidates: all, keysResident: true, now: now) {
        } else {
            Issue.record("a schedule with no pacing starts with a full burst")
        }

        schedule.recordFailure(
            item: Self.id(6), error: .rateLimited(retryAfter: 3600), networkRequests: 1, now: now, jitter: 0)
        relocked = ScanSchedule(ledger: schedule.ledger, policy: policy, pacing: schedule.pacing)
        let later = now.addingTimeInterval(10)
        #expect(
            relocked.decide(candidates: all, keysResident: true, now: later)
                == .wait(until: now.addingTimeInterval(3600), .backoff))
        #expect(relocked.earliestStart(for: Self.id(7), now: later) == now.addingTimeInterval(3600))
    }

    @Test("pacing handed in never holds more than the policy's burst")
    func pacingIsBounded() async {
        let clock = FakeClock()
        let generous = ScanSchedule(policy: ScanPolicy(burst: 50))
        var schedule = ScanSchedule(policy: ScanPolicy(burst: 2, maximumJitter: 0), pacing: generous.pacing)
        let scanned = await Self.drain(&schedule, Self.candidates(4), clock: clock)
        #expect(scanned.count == 4)
        // Two at once, then one per spacing: four seconds for the last two.
        #expect(await clock.now() == Date(timeIntervalSince1970: 1_800_000_000 + 4))
    }

    @Test("repeated failures back off exponentially, up to the maximum, and a success resets it")
    func exponentialBackoff() async {
        let clock = FakeClock()
        let policy = ScanPolicy(initialBackoff: 60, maximumBackoff: 600)
        var schedule = ScanSchedule(policy: policy)
        let all = Self.candidates(1)
        var waits: [TimeInterval] = []
        for _ in 0..<6 {
            let now = await clock.now()
            guard case .scan(let item, _) = schedule.decide(candidates: all, keysResident: true, now: now) else {
                Issue.record("expected a scan")
                return
            }
            schedule.recordFailure(item: item, error: .transport, networkRequests: 1, now: now, jitter: 0)
            guard case .wait(let until, .backoff) = schedule.decide(candidates: all, keysResident: true, now: now)
            else {
                Issue.record("expected a backoff")
                return
            }
            waits.append(until.timeIntervalSince(now))
            await clock.set(until)
        }
        #expect(waits == [60, 120, 240, 480, 600, 600])
        let now = await clock.now()
        schedule.recordScan(item: Self.id(1), version: 1, results: [:], networkRequests: 1, now: now, jitter: 0)
        schedule.recordFailure(item: Self.id(1), error: .transport, networkRequests: 1, now: now, jitter: 0)
        #expect(schedule.earliestStart(for: Self.id(1), now: now) == now.addingTimeInterval(60))
    }

    @Test("an item whose range cannot be used is set aside, and the others are still scanned")
    func itemRetry() async {
        let clock = FakeClock()
        let policy = ScanPolicy(initialBackoff: 10, itemRetryInitial: 3600)
        var schedule = ScanSchedule(policy: policy)
        let all = Self.candidates(3)
        let start = await clock.now()
        guard case .scan(let bad, _) = schedule.decide(candidates: all, keysResident: true, now: start) else { return }
        schedule.recordFailure(item: bad, error: .malformedResponse, networkRequests: 1, now: start, jitter: 0)
        await clock.advance(by: 10)
        var scanned: [UUID] = []
        for _ in 0..<10 {
            let now = await clock.now()
            switch schedule.decide(candidates: all, keysResident: true, now: now) {
            case .scan(let item, _):
                schedule.recordScan(item: item, version: 1, results: [:], networkRequests: 1, now: now, jitter: 0)
                scanned.append(item)
            case .wait(let until, let reason):
                #expect(reason == .retry)
                #expect(until == start.addingTimeInterval(3600))
                #expect(Set(scanned) == Set(all.map(\.id)).subtracting([bad]))
                return
            default:
                Issue.record("unexpected decision")
                return
            }
        }
        Issue.record("the failing item was never set aside")
    }

    @Test("a lock during a scan is not held against the server or the item")
    func interruptedIsNotAFailure() async {
        let clock = FakeClock()
        var schedule = ScanSchedule()
        let now = await clock.now()
        schedule.recordFailure(item: Self.id(1), error: .interrupted, networkRequests: 0, now: now, jitter: 0)
        #expect(
            schedule.decide(candidates: Self.candidates(1), keysResident: true, now: now)
                == .scan(item: Self.id(1), reason: .created))
    }

    @Test("a clock put back does not strand the scanner behind a future start time or a far-off backoff")
    func clockRollback() async {
        let clock = FakeClock()
        var schedule = ScanSchedule()
        let all = Self.candidates(2)
        _ = await Self.drain(&schedule, all, clock: clock)
        let now = await clock.now()
        schedule.recordFailure(
            item: Self.id(1), error: .rateLimited(retryAfter: 3600), networkRequests: 1, now: now, jitter: 0)
        // The clock goes back a year.
        await clock.set(now.addingTimeInterval(-365 * 86400))
        let past = await clock.now()
        var resumed = ScanSchedule(ledger: schedule.ledger)
        let scanned = await Self.drain(&resumed, all, clock: clock)
        #expect(Set(scanned) == Set(all.map(\.id)))
        #expect(resumed.ledger.fullScanStartedAt == past)
        // And in the same run, the backoff is cut to the longest the policy allows.
        guard
            case .wait(let until, .backoff) = schedule.decide(
                candidates: [ScanCandidate(id: Self.id(1), version: 2)], keysResident: true, now: past)
        else {
            Issue.record("expected a bounded backoff")
            return
        }
        #expect(until <= past.addingTimeInterval(ScanPolicy.standard.maximumBackoff))
    }

    @Test("pruning drops entries for items that are gone")
    func prune() async {
        let clock = FakeClock()
        var schedule = ScanSchedule()
        _ = await Self.drain(&schedule, Self.candidates(4), clock: clock)
        schedule.prune(keeping: [Self.id(1), Self.id(3)])
        #expect(Set(schedule.ledger.entries.keys) == [Self.id(1), Self.id(3)])
        schedule.forget(Self.id(1))
        #expect(schedule.reason(for: ScanCandidate(id: Self.id(1), version: 1), now: await clock.now()) == .created)
    }

    @Test("a policy is held within sane bounds whatever it is given")
    func policyBounds() {
        let policy = ScanPolicy(
            fullScanInterval: 0, requestSpacing: 0, burst: 0, maximumJitter: -1, initialBackoff: 0, maximumBackoff: 0,
            itemRetryInitial: 0, itemRetryMaximum: 0, clockTolerance: -5)
        #expect(policy.fullScanInterval == 3600)
        #expect(policy.requestSpacing == 0.25)
        #expect(policy.burst == 1)
        #expect(policy.maximumJitter == 0)
        #expect(policy.initialBackoff == 1)
        #expect(policy.maximumBackoff == 1)
        #expect(policy.itemRetryMaximum >= policy.itemRetryInitial)
        #expect(policy.clockTolerance == 0)
        #expect(ScanPolicy(burst: 1_000_000).burst == 50)
    }
}

@Suite("Scan ledger")
struct ScanLedgerTests {
    static let field = UUID(uuidString: "AAAAAAAA-0000-0000-0000-000000000001")!
    static let other = UUID(uuidString: "AAAAAAAA-0000-0000-0000-000000000002")!

    static func ledger() -> ScanLedger {
        ScanLedger(
            entries: [
                ScanScheduleTests.id(1): .init(
                    itemVersion: 7, scannedAt: Date(timeIntervalSince1970: 1_800_000_100),
                    results: [field: .found(occurrences: 12), other: .notFound]),
                ScanScheduleTests.id(2): .init(
                    itemVersion: 1, scannedAt: Date(timeIntervalSince1970: 1_800_000_200), results: [:]),
            ],
            fullScanStartedAt: Date(timeIntervalSince1970: 1_800_000_000), fullScanCompletedAt: nil)
    }

    @Test("a ledger survives JSON encoding, and encodes the same bytes every time")
    func roundTrip() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(Self.ledger())
        #expect(try JSONDecoder().decode(ScanLedger.self, from: data) == Self.ledger())
        #expect(try encoder.encode(Self.ledger()) == data)
    }

    @Test("the encoding holds nothing but IDs, versions, times and counts")
    func contents() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let text = String(decoding: try encoder.encode(Self.ledger()), as: UTF8.self)
        #expect(
            text == """
                {"entries":[{"fields":["AAAAAAAA-0000-0000-0000-000000000001","AAAAAAAA-0000-0000-0000-000000000002"],\
                "item":"00000000-0000-0000-0000-000000000001","occurrences":[12,0],"scannedAt":1800000100,"version":7},\
                {"fields":[],"item":"00000000-0000-0000-0000-000000000002","occurrences":[],"scannedAt":1800000200,\
                "version":1}],"fullScanStartedAt":1800000000}
                """)
    }

    static func entryJSON(
        item: String = "00000000-0000-0000-0000-000000000001", version: Int = 1, scannedAt: Int = 5,
        fields: [String] = [], occurrences: [Int] = []
    ) -> String {
        let quoted = fields.map { "\"\($0)\"" }.joined(separator: ",")
        let counts = occurrences.map(String.init).joined(separator: ",")
        return "{\"item\":\"\(item)\",\"version\":\(version),\"scannedAt\":\(scannedAt),"
            + "\"fields\":[\(quoted)],\"occurrences\":[\(counts)]}"
    }

    @Test(
        "a damaged ledger is a decoding error",
        arguments: [
            "{}",
            // A field without a count.
            "{\"entries\":[\(entryJSON(fields: [field.uuidString]))]}",
            // A time before 1970.
            "{\"entries\":[\(entryJSON(scannedAt: -5))]}",
            // The same item twice.
            "{\"entries\":[\(entryJSON()),\(entryJSON(version: 2, scannedAt: 6))]}",
            // The same field twice.
            "{\"entries\":[\(entryJSON(fields: [field.uuidString, field.uuidString], occurrences: [1, 2]))]}",
            // A time beyond any date.
            "{\"entries\":[],\"fullScanStartedAt\":99999999999999999}",
            "{\"entries\":[\(entryJSON(item: "not-a-uuid"))]}",
        ])
    func damaged(_ json: String) {
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(ScanLedger.self, from: Data(json.utf8))
        }
    }

    @Test("a well-formed entry of the same shape decodes, so the cases above fail for the reason given")
    func wellFormed() throws {
        let json = "{\"entries\":[\(Self.entryJSON(fields: [Self.field.uuidString], occurrences: [3]))]}"
        let ledger = try JSONDecoder().decode(ScanLedger.self, from: Data(json.utf8))
        #expect(ledger.entries[ScanScheduleTests.id(1)]?.results == [Self.field: .found(occurrences: 3)])
    }

    @Test("too many results for one item is refused")
    func tooManyResults() throws {
        let fields = (0..<65).map { _ in "\"\(UUID().uuidString)\"" }.joined(separator: ",")
        let counts = (0..<65).map { _ in "1" }.joined(separator: ",")
        let json = """
            {"entries":[{"item":"00000000-0000-0000-0000-000000000001","version":1,"scannedAt":5,\
            "fields":[\(fields)],"occurrences":[\(counts)]}]}
            """
        #expect(throws: DecodingError.self) { try JSONDecoder().decode(ScanLedger.self, from: Data(json.utf8)) }
    }

    @Test("the oldest scan is unknown as soon as one item has not been scanned at its current version")
    func oldestScan() {
        let ledger = Self.ledger()
        let both = [
            ScanCandidate(id: ScanScheduleTests.id(1), version: 7),
            ScanCandidate(id: ScanScheduleTests.id(2), version: 1),
        ]
        #expect(ledger.oldestScan(of: both) == Date(timeIntervalSince1970: 1_800_000_100))
        #expect(ledger.oldestScan(of: [ScanCandidate(id: ScanScheduleTests.id(1), version: 8)]) == nil)
        #expect(ledger.oldestScan(of: both + [ScanCandidate(id: ScanScheduleTests.id(3), version: 1)]) == nil)
    }
}
