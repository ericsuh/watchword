import Foundation
import Testing

@testable import WatchwordSync

@Suite("Automatic sync policy")
struct AutoSyncPolicyTests {
    static let start = Date(timeIntervalSince1970: 1_800_000_000)
    let settings = AutoSyncSettings.standard

    /// A state in which one sync has just succeeded at `start`, unlocked.
    static func synced(unlocked: Bool = true) -> AutoSyncState {
        var state = AutoSyncState()
        if unlocked { AutoSyncPolicy.record(.unlocked, at: start, in: &state) }
        AutoSyncPolicy.record(.syncStarted, at: start, in: &state)
        AutoSyncPolicy.record(.syncSucceeded, at: start, in: &state)
        return state
    }

    func at(_ seconds: TimeInterval) -> Date {
        Self.start.addingTimeInterval(seconds)
    }

    @Test("an unlock syncs at once, whatever else is pending")
    func unlock() {
        var state = Self.synced()
        AutoSyncPolicy.record(.locked, at: at(1), in: &state)
        AutoSyncPolicy.record(.unlocked, at: at(2), in: &state)
        #expect(AutoSyncPolicy.decide(now: at(2), state: state, settings: settings) == .sync(.full, .unlocked))
        // Even inside a backoff: the person is waiting.
        AutoSyncPolicy.record(.syncStarted, at: at(2), in: &state)
        AutoSyncPolicy.record(.syncFailed, at: at(3), in: &state)
        AutoSyncPolicy.record(.locked, at: at(4), in: &state)
        AutoSyncPolicy.record(.unlocked, at: at(5), in: &state)
        #expect(AutoSyncPolicy.decide(now: at(5), state: state, settings: settings) == .sync(.full, .unlocked))
    }

    @Test("a burst of saves is one sync, after the last of them, and never later than the cap after the first")
    func saveDebounce() {
        var state = Self.synced()
        AutoSyncPolicy.record(.localChange, at: at(100), in: &state)
        #expect(AutoSyncPolicy.decide(now: at(100), state: state, settings: settings) == .wait(until: at(105)))
        AutoSyncPolicy.record(.localChange, at: at(103), in: &state)
        #expect(AutoSyncPolicy.decide(now: at(105), state: state, settings: settings) == .wait(until: at(108)))
        #expect(AutoSyncPolicy.decide(now: at(108), state: state, settings: settings) == .sync(.full, .localChange))

        // Saving every four seconds for ever does not postpone the sync beyond the cap.
        var busy = Self.synced()
        var time: TimeInterval = 100
        while time < 100 + settings.maximumSaveDelay {
            AutoSyncPolicy.record(.localChange, at: at(time), in: &busy)
            #expect(AutoSyncPolicy.decide(now: at(time), state: busy, settings: settings) != .sync(.full, .localChange))
            time += 4
        }
        #expect(
            AutoSyncPolicy.decide(now: at(100 + settings.maximumSaveDelay), state: busy, settings: settings)
                == .sync(.full, .localChange))
    }

    @Test("a save made while a sync runs is not forgotten when that sync ends")
    func saveDuringSync() {
        var state = Self.synced()
        AutoSyncPolicy.record(.localChange, at: at(100), in: &state)
        AutoSyncPolicy.record(.syncStarted, at: at(105), in: &state)
        #expect(AutoSyncPolicy.decide(now: at(106), state: state, settings: settings) == .wait(until: nil))
        AutoSyncPolicy.record(.localChange, at: at(106), in: &state)
        AutoSyncPolicy.record(.syncSucceeded, at: at(107), in: &state)
        // Due after the debounce, and not before the minimum spacing from the sync that just ran.
        #expect(AutoSyncPolicy.decide(now: at(107), state: state, settings: settings) == .wait(until: at(115)))
        #expect(AutoSyncPolicy.decide(now: at(115), state: state, settings: settings) == .sync(.full, .localChange))
    }

    @Test("remote-change hints are coalesced, and download-only while locked (F7.5)")
    func hints() {
        var state = Self.synced()
        AutoSyncPolicy.record(.remoteChangeHint, at: at(200), in: &state)
        AutoSyncPolicy.record(.remoteChangeHint, at: at(201), in: &state)
        #expect(AutoSyncPolicy.decide(now: at(200), state: state, settings: settings) == .wait(until: at(202)))
        #expect(AutoSyncPolicy.decide(now: at(202), state: state, settings: settings) == .sync(.full, .remoteChange))

        var locked = Self.synced(unlocked: false)
        AutoSyncPolicy.record(.remoteChangeHint, at: at(200), in: &locked)
        #expect(
            AutoSyncPolicy.decide(now: at(202), state: locked, settings: settings)
                == .sync(.downloadOnly, .remoteChange))
        // A hint is consumed by the sync it caused.
        AutoSyncPolicy.record(.syncStarted, at: at(202), in: &locked)
        AutoSyncPolicy.record(.syncSucceeded, at: at(203), in: &locked)
        #expect(
            AutoSyncPolicy.decide(now: at(204), state: locked, settings: settings)
                == .wait(until: at(202 + settings.lockedInterval)))
    }

    @Test("syncs periodically: often while unlocked, rarely and download-only while locked")
    func periodic() {
        let unlocked = Self.synced()
        #expect(
            AutoSyncPolicy.decide(now: at(60), state: unlocked, settings: settings)
                == .wait(until: at(settings.periodicInterval)))
        #expect(
            AutoSyncPolicy.decide(now: at(settings.periodicInterval), state: unlocked, settings: settings)
                == .sync(.full, .periodic))
        let locked = Self.synced(unlocked: false)
        #expect(
            AutoSyncPolicy.decide(now: at(settings.periodicInterval), state: locked, settings: settings)
                == .wait(until: at(settings.lockedInterval)))
        #expect(
            AutoSyncPolicy.decide(now: at(settings.lockedInterval), state: locked, settings: settings)
                == .sync(.downloadOnly, .periodic))
        // Never synced at all: now.
        #expect(
            AutoSyncPolicy.decide(now: Self.start, state: AutoSyncState(), settings: settings)
                == .sync(.downloadOnly, .periodic))
    }

    @Test("local changes made while locked do not ask for a sync that could not publish them")
    func lockedChangesWait() {
        var state = Self.synced()
        AutoSyncPolicy.record(.localChange, at: at(10), in: &state)
        AutoSyncPolicy.record(.locked, at: at(11), in: &state)
        #expect(
            AutoSyncPolicy.decide(now: at(100), state: state, settings: settings)
                == .wait(until: at(settings.lockedInterval)))
        // A download-only sync does not consume them; the unlock publishes them.
        AutoSyncPolicy.record(.syncStarted, at: at(settings.lockedInterval), in: &state)
        AutoSyncPolicy.record(.syncSucceeded, at: at(settings.lockedInterval + 1), in: &state)
        #expect(state.firstUnsyncedChangeAt != nil)
        AutoSyncPolicy.record(.unlocked, at: at(settings.lockedInterval + 2), in: &state)
        #expect(
            AutoSyncPolicy.decide(now: at(settings.lockedInterval + 2), state: state, settings: settings)
                == .sync(.full, .unlocked))
    }

    @Test("failures back off, doubling up to a cap; a success clears the backoff")
    func backoff() {
        var state = Self.synced()
        var now: TimeInterval = 1_000
        var expected = settings.backoffBase
        for _ in 0..<12 {
            AutoSyncPolicy.record(.syncStarted, at: at(now), in: &state)
            AutoSyncPolicy.record(.syncFailed, at: at(now), in: &state)
            // Triggers do not cut the backoff short.
            AutoSyncPolicy.record(.localChange, at: at(now), in: &state)
            AutoSyncPolicy.record(.remoteChangeHint, at: at(now), in: &state)
            #expect(
                AutoSyncPolicy.decide(now: at(now + expected - 1), state: state, settings: settings)
                    == .wait(until: at(now + expected)))
            guard
                case .sync(.full, _) = AutoSyncPolicy.decide(now: at(now + expected), state: state, settings: settings)
            else {
                Issue.record("no retry after \(expected) seconds")
                return
            }
            now += expected
            expected = min(expected * 2, settings.backoffMaximum)
        }
        #expect(expected == settings.backoffMaximum)
        AutoSyncPolicy.record(.syncStarted, at: at(now), in: &state)
        AutoSyncPolicy.record(.syncSucceeded, at: at(now), in: &state)
        #expect(state.consecutiveFailures == 0)
        #expect(
            AutoSyncPolicy.decide(now: at(now + 1), state: state, settings: settings)
                == .wait(until: at(now + settings.periodicInterval)))
        #expect(AutoSyncPolicy.backoff(after: 0, settings) == 0)
        #expect(AutoSyncPolicy.backoff(after: 1_000_000, settings) == settings.backoffMaximum)
    }

    @Test("a failure with nothing else pending is retried once its backoff has passed")
    func retry() {
        var state = Self.synced()
        AutoSyncPolicy.record(.syncStarted, at: at(50), in: &state)
        AutoSyncPolicy.record(.syncFailed, at: at(51), in: &state)
        #expect(
            AutoSyncPolicy.decide(now: at(52), state: state, settings: settings)
                == .wait(until: at(51 + settings.backoffBase)))
        #expect(
            AutoSyncPolicy.decide(now: at(51 + settings.backoffBase), state: state, settings: settings)
                == .sync(.full, .retry))
    }

    @Test("nothing is decided while a sync is in flight, and no two automatic syncs start too close together")
    func spacing() {
        var state = Self.synced()
        AutoSyncPolicy.record(.remoteChangeHint, at: at(1), in: &state)
        // The hint's own delay has passed, the minimum spacing has not.
        #expect(
            AutoSyncPolicy.decide(now: at(4), state: state, settings: settings)
                == .wait(until: at(settings.minimumInterval)))
        AutoSyncPolicy.record(.syncStarted, at: at(settings.minimumInterval), in: &state)
        AutoSyncPolicy.record(.remoteChangeHint, at: at(settings.minimumInterval + 1), in: &state)
        #expect(
            AutoSyncPolicy.decide(now: at(settings.minimumInterval + 60), state: state, settings: settings)
                == .wait(until: nil))
    }

    @Test("a clock that moved backwards never makes the policy wait for ever")
    func clockMovedBack() {
        var state = Self.synced()
        AutoSyncPolicy.record(.syncStarted, at: at(10_000), in: &state)
        AutoSyncPolicy.record(.syncFailed, at: at(10_000), in: &state)
        // Now is long before the last attempt: neither the backoff nor the spacing can be shown not to have passed.
        guard case .sync = AutoSyncPolicy.decide(now: at(5), state: state, settings: settings) else {
            Issue.record("waited on a time in the future")
            return
        }
    }
}

@Suite("Account object names")
struct AccountObjectLocationTests {
    static let account = UUID(uuidString: "AC000000-0000-4000-8000-0000000000AC")!
    static let vault = UUID(uuidString: "7A000000-0000-4000-8000-000000000001")!
    static let key = UUID(uuidString: "4E400000-0000-4000-8000-000000000001")!
    static let device = UUID(uuidString: "D0000000-0000-4000-8000-0000000000A0")!
    static let entryID = String(repeating: "0123456789abcdef", count: 4)

    static let locations: [AccountObjectLocation] = [
        .header(accountID: account, generation: 3, author: device),
        .registryEntry(accountID: account, id: entryID),
        .vaultKey(accountID: account, vaultID: vault, keyID: key, author: device),
        .vaultDeletion(accountID: account, vaultID: vault, author: device),
        .vaultShared(accountID: account, vaultID: vault, author: device),
    ]

    @Test("every location round-trips through its name", arguments: locations)
    func roundTrip(_ location: AccountObjectLocation) {
        #expect(AccountObjectLocation(name: location.name) == location)
        #expect(location.name.hasPrefix(AccountObjectLocation.accountPrefix(Self.account)))
        #expect(location.accountID == Self.account)
        // Never a sync object, and the reverse.
        #expect(SyncObjectLocation(name: location.name) == nil)
    }

    @Test("names are exact: no other spelling of a name is an account object")
    func exactNames() {
        let header = Self.locations[0].name
        let registry = Self.locations[1].name
        let vaultKey = Self.locations[2].name
        let hostile = [
            header.lowercased(), header + "/", header + ".wwe", "/" + header,
            header.replacingOccurrences(of: "-D", with: "-d"),
            header.replacingOccurrences(of: "00000000000000000003", with: "3"),
            header.replacingOccurrences(of: "00000000000000000003", with: "0000000000000000000३"),
            registry.uppercased(), registry + "0", String(registry.dropLast()), registry + "/x",
            registry.replacingOccurrences(of: "0123", with: "012g"),
            vaultKey + "/extra", vaultKey.replacingOccurrences(of: "/key/", with: "/keys/"),
            vaultKey.replacingOccurrences(of: "/key/", with: "/../key/"),
            "account/\(Self.account.uuidString)/vault/\(Self.vault.uuidString)/deleted",
            "account/\(Self.account.uuidString)/vault/\(Self.vault.uuidString)/deleted/\(Self.device.uuidString)/x",
            "account/\(Self.account.uuidString)/other/x", "account//header/x",
            "accounts/\(Self.account.uuidString)/header/x",
            SyncObjectLocation.segment(vaultID: Self.vault, author: Self.device, sequence: 1).name, "",
        ]
        for name in hostile {
            #expect(AccountObjectLocation(name: name) == nil, "\(name)")
        }
    }
}

extension AutoSyncPolicyTests {
    @Test("a transport's requested wait lengthens the backoff, held to the policy's maximum, and a success clears it")
    func throttled() {
        var state = Self.synced()
        AutoSyncPolicy.record(.syncStarted, at: at(100), in: &state)
        AutoSyncPolicy.record(.syncThrottled(retryAfter: 300), at: at(101), in: &state)
        #expect(AutoSyncPolicy.decide(now: at(200), state: state, settings: settings) == .wait(until: at(401)))
        #expect(AutoSyncPolicy.decide(now: at(401), state: state, settings: settings) == .sync(.full, .retry))

        // A wait of a year is a claim by the store (A1): an hour at most.
        AutoSyncPolicy.record(.syncStarted, at: at(500), in: &state)
        AutoSyncPolicy.record(.syncThrottled(retryAfter: 365 * 86_400), at: at(501), in: &state)
        let capped = at(501).addingTimeInterval(settings.backoffMaximum)
        #expect(AutoSyncPolicy.decide(now: at(600), state: state, settings: settings) == .wait(until: capped))

        // No wait named, or a shorter one than the doubling backoff: the doubling backoff.
        AutoSyncPolicy.record(.syncStarted, at: at(5000), in: &state)
        AutoSyncPolicy.record(.syncThrottled(retryAfter: nil), at: at(5001), in: &state)
        let doubling = AutoSyncPolicy.backoff(after: state.consecutiveFailures, settings)
        #expect(AutoSyncPolicy.backoff(after: state, settings) == doubling)
        AutoSyncPolicy.record(.syncStarted, at: at(9000), in: &state)
        AutoSyncPolicy.record(.syncThrottled(retryAfter: -.infinity), at: at(9001), in: &state)
        #expect(
            AutoSyncPolicy.backoff(after: state, settings)
                == AutoSyncPolicy.backoff(after: state.consecutiveFailures, settings))

        AutoSyncPolicy.record(.syncStarted, at: at(20000), in: &state)
        AutoSyncPolicy.record(.syncSucceeded, at: at(20001), in: &state)
        #expect(state.requestedWait == nil)
        #expect(AutoSyncPolicy.backoff(after: state, settings) == 0)
    }
}
