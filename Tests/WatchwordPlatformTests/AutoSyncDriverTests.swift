import Foundation
import Testing
import WatchwordKit
import WatchwordPlatform
import WatchwordSync

/// A clock the test moves by hand, and a `sleep` that returns when the clock reaches the date asked for: the driver's
/// timers run without the test waiting for time to pass.
final class ManualTime: @unchecked Sendable {
    private let lock = NSLock()
    private var current = Date(timeIntervalSince1970: 1_800_000_000)
    private var sleepers: [(Date, CheckedContinuation<Void, any Error>)] = []

    var now: Date { lock.withLock { current } }

    var pendingSleeps: Int { lock.withLock { sleepers.count } }

    func sleep(until date: Date) async throws {
        try await withCheckedThrowingContinuation { continuation in
            let resumeNow: Bool = lock.withLock {
                if date <= current { return true }
                sleepers.append((date, continuation))
                return false
            }
            if resumeNow { continuation.resume() }
        }
    }

    func advance(by seconds: TimeInterval) {
        let due: [CheckedContinuation<Void, any Error>] = lock.withLock {
            current = current.addingTimeInterval(seconds)
            let due = sleepers.filter { $0.0 <= current }.map(\.1)
            sleepers.removeAll { $0.0 <= current }
            return due
        }
        for continuation in due { continuation.resume() }
    }
}

/// Every sync the driver starts, and the outcome each is to report.
final class SyncLog: @unchecked Sendable {
    private let lock = NSLock()
    private var modes: [AutoSyncMode] = []
    private var outcomes: [AutoSyncOutcome] = []
    let stream: AsyncStream<AutoSyncMode>
    private let continuation: AsyncStream<AutoSyncMode>.Continuation

    init() {
        (stream, continuation) = AsyncStream.makeStream(of: AutoSyncMode.self)
    }

    func answer(_ outcomes: AutoSyncOutcome...) {
        lock.withLock { self.outcomes += outcomes }
    }

    var started: [AutoSyncMode] { lock.withLock { modes } }

    func run(_ mode: AutoSyncMode) -> AutoSyncOutcome {
        let outcome = lock.withLock {
            modes.append(mode)
            return outcomes.isEmpty ? .succeeded : outcomes.removeFirst()
        }
        continuation.yield(mode)
        return outcome
    }
}

/// The driver of `AutoSyncPolicy` (docs/02-architecture.md §7.9): it starts what the policy decides, when it decides,
/// and records the outcome. The rules themselves are the policy's suite ("Automatic sync policy").
@Suite("Automatic sync driver")
struct AutoSyncDriverTests {
    let time = ManualTime()
    let log = SyncLog()

    func driver() -> AutoSyncDriver {
        let (time, log) = (time, log)
        return AutoSyncDriver(
            now: { time.now }, sleep: { try await time.sleep(until: $0) }, sync: { log.run($0) })
    }

    /// The next sync the driver starts, or `nil` if none starts within ten seconds (a bound on waiting for an event,
    /// so a broken driver fails the test instead of hanging it; nothing waits for time to pass).
    func nextSync() async -> AutoSyncMode? {
        let stream = log.stream
        return await withTaskGroup(of: AutoSyncMode?.self) { group in
            group.addTask {
                var iterator = stream.makeAsyncIterator()
                return await iterator.next()
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: 10_000_000_000)
                return nil
            }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first
        }
    }

    /// Lets the driver's tasks run until it has armed a timer or finished a sync.
    func settle(_ driver: AutoSyncDriver) async {
        for _ in 0..<200 {
            if await !driver.state.inFlight, time.pendingSleeps > 0 { return }
            await Task.yield()
        }
    }

    @Test("an unlock syncs at once, in full; a local change waits for the debounce, then syncs")
    func unlockAndChange() async throws {
        let driver = driver()
        await driver.record(.unlocked)
        #expect(await nextSync() == .full)
        await settle(driver)
        await driver.record(.localChange)
        await settle(driver)
        #expect(log.started.count == 1)
        // The debounce, and the minimum spacing after the unlock's sync, which is the longer.
        time.advance(by: AutoSyncSettings.standard.saveDebounce)
        await settle(driver)
        #expect(log.started.count == 1)
        time.advance(by: AutoSyncSettings.standard.minimumInterval - AutoSyncSettings.standard.saveDebounce)
        #expect(await nextSync() == .full)
        await driver.stop()
    }

    @Test("while locked, the periodic sync is download-only")
    func locked() async throws {
        let driver = driver()
        await driver.record(.locked)
        #expect(await nextSync() == .downloadOnly)
        await settle(driver)
        time.advance(by: AutoSyncSettings.standard.lockedInterval)
        #expect(await nextSync() == .downloadOnly)
        await driver.stop()
    }

    @Test("a throttled sync waits as long as the transport asked before retrying")
    func throttled() async throws {
        log.answer(.throttled(retryAfter: 600))
        let driver = driver()
        await driver.record(.unlocked)
        #expect(await nextSync() == .full)
        await settle(driver)
        #expect(await driver.state.requestedWait == 600)
        time.advance(by: 599)
        await settle(driver)
        #expect(log.started.count == 1)
        time.advance(by: 1)
        #expect(await nextSync() == .full)
        await driver.stop()
    }

    @Test("after stop, nothing more is started")
    func stop() async throws {
        let driver = driver()
        await driver.record(.unlocked)
        #expect(await nextSync() == .full)
        await settle(driver)
        await driver.stop()
        time.advance(by: 86_400)
        await driver.record(.remoteChangeHint)
        for _ in 0..<50 { await Task.yield() }
        #expect(log.started.count == 1)
    }

    @Test("outcomes are read from the report and from errors")
    func outcomes() {
        var report = AccountSyncReport()
        #expect(AutoSyncOutcome(report) == .succeeded)
        report.transportUnavailable = true
        #expect(AutoSyncOutcome(report) == .failed)
        report.transportFailure = .rateLimited(retryAfter: 5)
        #expect(AutoSyncOutcome(report) == .throttled(retryAfter: 5))
        #expect(AutoSyncOutcome(SyncTransportError.rateLimited(retryAfter: nil)) == .throttled(retryAfter: nil))
        #expect(AutoSyncOutcome(SyncTransportError.notAuthenticated) == .failed)
    }
}
