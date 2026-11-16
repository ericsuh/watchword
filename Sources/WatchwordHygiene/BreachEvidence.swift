import Foundation

/// Who a breach status rests on (docs/02-architecture.md §13.9).
public enum BreachSource: Hashable, Sendable {
    /// This device's own checks.
    case thisDevice
    /// At least in part, checks another device of the vault synced: for a breach, one this device has not seen for
    /// itself; for "clear", a password this device has not checked itself.
    case anotherDevice
}

/// Everything known about one password of one item, and the rules that weigh it (ADR 0005, amendment of 2026-11-16;
/// docs/02-architecture.md §13.9). The one place the report and the schedule read results from, so they cannot
/// disagree.
///
/// - **This device's own check** comes from the ledger: by binding, so it counts at whatever version the item is now
///   as long as the password is the one checked; by version only for an entry from before bindings were kept.
/// - **A breach another device reported** and this device took in (`ScanLedger.Reported`) stays until this device's
///   own later check of the password.
/// - **Other devices' synced checks**: one dated more than the clock's tolerance ahead is ignored, and the rest count
///   as no later than now, so no synced time postpones anything past the policy's own intervals.
///
/// Breached if this device found the password breached, or another device reported it and this device has no newer
/// check of its own that found it clear. A synced "not found" never outweighs a breach: it only counts as a check.
struct PasswordBreachEvidence {
    var own: (result: PwnedPasswordResult, at: Date)?
    var reported: ScanLedger.Reported?
    var remote: [SyncedScanEvidence.Observation] = []

    init(
        _ password: PasswordFact, of analysis: ItemAnalysis, ledger: ScanLedger, synced: SyncedScanEvidence?,
        now: Date, tolerance: TimeInterval
    ) {
        if let entry = ledger.entries[analysis.id] {
            // By binding; and at the version checked, by field as well, which is how an entry from before bindings
            // were kept reads, and how two password fields sharing an ID share the worse result (§13.7).
            let byVersion = entry.itemVersion == analysis.version ? entry.results[password.fieldID] : nil
            if let result = entry.result(for: password.ledgerBinding) ?? byVersion {
                own = (result, entry.scannedAt)
            }
        }
        reported = ledger.reported[analysis.id]?[password.ledgerBinding]
        if let synced, synced.itemID == analysis.id, synced.itemVersion == analysis.version {
            remote = (synced.fields[password.fieldID] ?? []).compactMap {
                Self.bounded($0, now: now, tolerance: tolerance)
            }
        }
    }

    /// A synced observation as this device may use it: none if dated more than `tolerance` ahead of `now`, and
    /// otherwise dated no later than `now`.
    static func bounded(_ observation: SyncedScanEvidence.Observation, now: Date, tolerance: TimeInterval)
        -> SyncedScanEvidence.Observation?
    {
        guard observation.scannedAt <= now.addingTimeInterval(tolerance) else { return nil }
        return SyncedScanEvidence.Observation(
            device: observation.device, scannedAt: min(observation.scannedAt, now), result: observation.result)
    }

    /// Whether a breach reported at `at` stands against this device's own check: only an own check that is newer and
    /// found the password clear outweighs it.
    private func standsAgainstOwn(_ at: Date) -> Bool {
        guard let own, own.result == .notFound else { return true }
        return own.at <= at
    }

    /// The breach, if the password counts as breached: the most occurrences any source gives, the latest time a
    /// source found it, and whether this device found it itself.
    var breach: (occurrences: UInt32, at: Date, ownFinding: Bool)? {
        var occurrences: UInt32 = 0
        var at: Date?
        var ownFinding = false
        if let own, case .found(let count) = own.result {
            occurrences = max(occurrences, count)
            at = max(at ?? own.at, own.at)
            ownFinding = true
        }
        if let reported, standsAgainstOwn(reported.reportedAt) {
            occurrences = max(occurrences, reported.occurrences)
            at = max(at ?? reported.reportedAt, reported.reportedAt)
        }
        for observation in remote {
            guard case .found(let count) = observation.result, standsAgainstOwn(observation.scannedAt) else {
                continue
            }
            occurrences = max(occurrences, count)
            at = max(at ?? observation.scannedAt, observation.scannedAt)
        }
        guard let at else { return nil }
        return (max(1, occurrences), at, ownFinding)
    }

    /// The latest check of the password, by anyone: what the schedule and "clear" rest on.
    var coveredAt: Date? {
        var times = remote.map(\.scannedAt)
        if let own { times.append(own.at) }
        if let reported { times.append(reported.reportedAt) }
        return times.max()
    }

    /// This device's own latest check of the password.
    var ownCoveredAt: Date? {
        own?.at
    }
}

/// An item's passwords weighed together.
struct ItemBreachEvidence {
    let passwords: [PasswordBreachEvidence]

    init(
        _ analysis: ItemAnalysis, ledger: ScanLedger, synced: SyncedScanEvidence?, now: Date, tolerance: TimeInterval
    ) {
        passwords = analysis.passwords.map {
            PasswordBreachEvidence($0, of: analysis, ledger: ledger, synced: synced, now: now, tolerance: tolerance)
        }
    }

    /// When every password was last checked by anyone, the oldest of those; `nil` if one never was.
    var coveredAt: Date? {
        Self.oldest(passwords.map(\.coveredAt))
    }

    /// The same, counting only this device's own checks.
    var ownCoveredAt: Date? {
        Self.oldest(passwords.map(\.ownCoveredAt))
    }

    private static func oldest(_ times: [Date?]) -> Date? {
        var oldest: Date?
        for time in times {
            guard let time else { return nil }
            oldest = min(oldest ?? time, time)
        }
        return oldest
    }
}

/// A count all but names the password, so a report another device made prints as nothing more than that it exists.
extension ScanLedger.Reported: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "Reported(count withheld)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}

extension SyncedScanEvidence.Observation: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "SyncedScanEvidence.Observation(device: \(device), result withheld)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["device": device], displayStyle: .struct) }
}
