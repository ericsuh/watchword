import Foundation
import Observation
import WatchwordHygiene
import WatchwordKit

/// One item in a section of the security report.
public struct HygieneRow: Hashable, Sendable, Identifiable {
    /// The item and the finding's kind and field, so one item can be listed once per field.
    public let id: String
    public let itemID: UUID
    public let title: String
    public let severity: HygieneSeverity
    public let summary: String
    public let explanation: String
    /// Where a breach status came from when it was not this device's own check (`ItemHygiene.breachSource`).
    public let source: String?
    /// For a reused password, the titles of the other items using it.
    public let sharedWith: [String]
}

public struct HygieneSection: Hashable, Sendable, Identifiable {
    public enum Kind: String, Hashable, Sendable {
        case breached, reused, weak, other
    }

    public let kind: Kind
    public let rows: [HygieneRow]
    public var id: String { kind.rawValue }

    public var title: String {
        switch kind {
        case .breached: return "Breached passwords"
        case .reused: return "Reused passwords"
        case .weak: return "Weak passwords"
        case .other: return "Other suggestions"
        }
    }

    public var footer: String {
        switch kind {
        case .breached:
            return "These passwords appear in known data breaches. Change them on the website, then here."
        case .reused:
            return "If one of these sites is breached, the others are at risk too. Give each its own password."
        case .weak: return "These passwords could be guessed. Generate a new one for each."
        case .other: return "Ways to make these items safer."
        }
    }
}

/// The security report (PRD F9.1–F9.3) and the breach scan behind it, driven from the screen through
/// `VaultSession.runHygieneStep()`. The report is the core's, already decided and worded; this model sorts it into
/// the sections the screen shows and paces the scan as the schedule asks.
@MainActor
@Observable
public final class HygieneModel: LockSensitive {
    public typealias Sleep = @Sendable (Duration) async throws -> Void

    public private(set) var sections: [HygieneSection] = []
    public private(set) var isAvailable = true
    public private(set) var itemsNeedingAttention = 0
    public private(set) var itemsAwaitingBreachCheck = 0
    public private(set) var lastFullScan: Date?
    /// What the last "Check now" did, in words.
    public private(set) var scanStatus: String?
    /// When the schedule allows the next check, if it stopped on a wait.
    public private(set) var nextCheckAt: Date?
    public private(set) var isWorking = false
    public private(set) var isScanning = false
    public var errorMessage: String?
    /// Whether this build can reach Pwned Passwords (`URLSessionHTTPClient` is still to come; until then only
    /// UI-test builds check breaches).
    public let breachChecksAvailable: Bool

    /// A wait the scan sits out on screen; anything longer ends the run and names the time.
    public static let longestInlineWait: TimeInterval = 10
    public static let maximumSteps = 200

    private let context: ScreenContext
    private let now: @Sendable () async -> Date
    private let sleep: Sleep

    public init(
        context: ScreenContext, breachChecksAvailable: Bool, now: @escaping @Sendable () async -> Date = { Date() },
        sleep: @escaping Sleep = { try await Task.sleep(for: $0) }
    ) {
        self.context = context
        self.breachChecksAvailable = breachChecksAvailable
        self.now = now
        self.sleep = sleep
        context.locks?.register(self)
    }

    /// The report names items; it goes with the keys.
    public func dropOnLock() {
        sections = []
        scanStatus = nil
    }

    public func load() async {
        await perform { try await reload() }
    }

    /// Runs the breach scan until the schedule says everything is current or asks for a wait longer than
    /// `longestInlineWait`, sitting out shorter ones, at most `maximumSteps` checks. Nothing is sent while locked.
    public func checkNow() async {
        guard breachChecksAvailable, !isScanning else { return }
        isScanning = true
        defer { isScanning = false }
        scanStatus = nil
        nextCheckAt = nil
        var checked = 0
        var failed = 0
        await perform {
            steps: for _ in 0..<Self.maximumSteps {
                switch try await context.session.runHygieneStep() {
                case .scanned(_, let outcome):
                    switch outcome {
                    case .scanned: checked += 1
                    case .failed: failed += 1
                    default: break
                    }
                case .idle(let next):
                    nextCheckAt = next
                    break steps
                case .wait(let until, let reason):
                    let delay = until.timeIntervalSince(await self.now())
                    guard reason != .backoff, delay <= Self.longestInlineWait else {
                        nextCheckAt = until
                        break steps
                    }
                    if delay > 0 { try await self.sleep(.milliseconds(Int64((delay * 1000).rounded(.up)))) }
                }
            }
            scanStatus = Self.describe(checked: checked, failed: failed)
            try await reload()
        }
    }

    static func describe(checked: Int, failed: Int) -> String {
        var parts = [checked == 0 ? "Nothing needed checking" : "\(checked) item(s) checked"]
        if failed > 0 { parts.append("\(failed) check(s) did not complete and will be retried") }
        return parts.joined(separator: "; ") + "."
    }

    private func reload() async throws {
        let report: HygieneReport
        do {
            report = try await context.session.hygieneReport()
        } catch VaultError.hygieneNotConfigured {
            isAvailable = false
            sections = []
            return
        }
        isAvailable = true
        sections = Self.sections(of: report)
        itemsNeedingAttention = report.totals.itemsNeedingAttention
        itemsAwaitingBreachCheck = report.totals.itemsAwaitingBreachCheck
        lastFullScan = report.totals.lastFullScanCompletedAt
    }

    static func sections(of report: HygieneReport) -> [HygieneSection] {
        let titles = Dictionary(
            report.items.map { ($0.id, $0.title.isEmpty ? "Untitled" : $0.title) },
            uniquingKeysWith: { first, _ in first })
        var grouped: [HygieneSection.Kind: [HygieneRow]] = [:]
        for item in report.items where !item.isArchived {
            for finding in item.findings where finding.severity >= .low {
                let kind: HygieneSection.Kind
                switch finding.kind {
                case .breachedPassword: kind = .breached
                case .reusedPassword: kind = .reused
                case .weakPassword: kind = .weak
                default: kind = .other
                }
                var sharedWith: [String] = []
                if case .reused(let others) = finding.detail { sharedWith = others.compactMap { titles[$0] } }
                let source: String? =
                    finding.kind == .breachedPassword && item.breachSource == .anotherDevice
                    ? "Reported by another device of this vault" : nil
                grouped[kind, default: []].append(
                    HygieneRow(
                        id: "\(item.id.uuidString)/\(finding.kind.rawValue)/\(finding.fieldID?.uuidString ?? "")",
                        itemID: item.id, title: titles[item.id] ?? "Untitled", severity: finding.severity,
                        summary: finding.summary, explanation: finding.explanation, source: source,
                        sharedWith: sharedWith))
            }
        }
        return [HygieneSection.Kind.breached, .reused, .weak, .other].compactMap { kind in
            guard let rows = grouped[kind], !rows.isEmpty else { return nil }
            return HygieneSection(kind: kind, rows: rows.sorted { ($0.severity, $1.title) > ($1.severity, $0.title) })
        }
    }

    private func perform(_ body: () async throws -> Void) async {
        isWorking = true
        defer { isWorking = false }
        errorMessage = await ScreenOperation(context: context).run(body)
    }
}
