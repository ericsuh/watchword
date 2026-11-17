import Foundation

public enum HygieneSeverity: Int, Hashable, Sendable, Comparable, CaseIterable {
    /// Worth knowing; nothing is wrong.
    case info = 0
    case low = 1
    case medium = 2
    case high = 3
    /// The password is known to attackers.
    case critical = 4

    public static func < (lhs: HygieneSeverity, rhs: HygieneSeverity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

/// What the report can say about an item, in the order findings of equal severity are listed.
public enum HygieneFindingKind: Int, Hashable, Sendable, Comparable, CaseIterable {
    /// The password is in the Pwned Passwords corpus (PRD F9.1).
    case breachedPassword = 0
    /// Another item uses the same password (F9.3).
    case reusedPassword = 1
    /// The estimator scores the password below strong (F9.3).
    case weakPassword = 2
    /// The site is listed as supporting authenticator-app codes and the item has none (F9.3).
    case twoFactorAvailable = 3
    /// A web address in the item is plain `http` (F9.3).
    case insecureURL = 4
    /// The site is listed as supporting passkeys and the item has none (F11.8).
    case passkeyAvailable = 5
    /// A password and nothing else, on a site nothing is known about (F11.8).
    case passwordOnly = 6
    /// The password has not changed for a long time.
    case oldPassword = 7
    /// The item has more passwords than are analysed in one item; the rest were not checked at all.
    case tooManyPasswords = 8

    public static func < (lhs: HygieneFindingKind, rhs: HygieneFindingKind) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

public struct HygieneFinding: Hashable, Sendable {
    /// The facts behind a finding, for a UI that wants to word or localise it itself.
    public enum Detail: Hashable, Sendable {
        case none
        /// Times the password appears in the corpus; `UInt32.max` means "at least".
        case breached(occurrences: UInt32)
        /// The other items with the same password, in a stable order.
        case reused(sharedWith: [UUID])
        case weak(score: StrengthScore, weakness: StrengthWeakness?)
        case unchanged(since: Date)
        /// How many of the item's passwords were not looked at.
        case notAnalysed(passwords: Int)
    }

    public let kind: HygieneFindingKind
    public let severity: HygieneSeverity
    /// The field the finding is about, when it is about one.
    public let fieldID: UUID?
    /// A few words, for a list row.
    public let summary: String
    /// What is wrong and what to do, in plain language. Never contains a password or any part of one.
    public let explanation: String
    public let detail: Detail
}

/// What a list row shows beside an item: one per kind of finding that is at least `low`.
public struct HygieneBadge: Hashable, Sendable {
    public let kind: HygieneFindingKind
    public let severity: HygieneSeverity
}

public enum BreachStatus: Hashable, Sendable {
    /// The item has no password to check.
    case notApplicable
    /// Not checked at its current version yet: unknown, and shown as such (ADR 0005, consequences).
    case notChecked
    /// Every password in the item was checked and none is in the corpus.
    case clear(checkedAt: Date)
    case breached(checkedAt: Date)
    /// The passwords that were checked are not in the corpus, but the item has more than are checked in one item
    /// (`ItemAnalyzer.maximumPasswordsPerItem`). Not clear, and not waiting for anything: the rest will not be
    /// checked until they are moved to items of their own.
    case incomplete(checkedAt: Date)
}

public struct ItemHygiene: Hashable, Sendable, Identifiable {
    public let id: UUID
    public let title: String
    public let isArchived: Bool
    /// Most severe first; then in `HygieneFindingKind` order; then by field.
    public let findings: [HygieneFinding]
    /// Most severe first.
    public let badges: [HygieneBadge]
    public let breachStatus: BreachStatus
    /// Whose checks the breach status rests on; `nil` while it is `notApplicable` or `notChecked`.
    public let breachSource: BreachSource?

    /// The worst finding's severity, or `nil` if there is none.
    public var severity: HygieneSeverity? {
        findings.first?.severity
    }
}

/// The Watchtower-style report (PRD F9.3): everything the UI shows, already decided, worded and ordered.
///
/// A value built from in-memory analyses and the scan ledger while the vault is unlocked. It holds item titles, so it
/// is as private as the vault and goes when the vault locks; it holds no password, hash or token.
public struct HygieneReport: Hashable, Sendable {
    public struct Totals: Hashable, Sendable {
        public let items: Int
        public let passwords: Int
        /// Items with at least one finding of `low` or above.
        public let itemsNeedingAttention: Int
        /// Items with at least one finding of each kind.
        public let itemsByKind: [HygieneFindingKind: Int]
        /// Items by their worst severity.
        public let itemsBySeverity: [HygieneSeverity: Int]
        /// Items whose passwords have not been breach-checked at their current version.
        public let itemsAwaitingBreachCheck: Int
        /// The oldest breach check among items that have one, so stale results are visible (ADR 0005).
        public let oldestBreachCheck: Date?
        public let lastFullScanCompletedAt: Date?
        public let fullScanInProgress: Bool
    }

    public let generatedAt: Date
    /// Every analysed item: those needing attention first (worst first), then the rest; ties by title, then by ID.
    public let items: [ItemHygiene]
    public let totals: Totals

    /// The items the report screen lists.
    public var itemsNeedingAttention: [ItemHygiene] {
        items.filter { ($0.severity ?? .info) >= .low }
    }

    public func item(_ id: UUID) -> ItemHygiene? {
        items.first { $0.id == id }
    }

    /// The badges for one item, for the item list.
    public func badges(for id: UUID) -> [HygieneBadge] {
        item(id)?.badges ?? []
    }

    /// Builds the report. Pure: equal inputs give an equal report, in the same order.
    ///
    /// - Parameters:
    ///   - analyses: one per item (not trashed), in any order.
    ///   - ledger: this device's breach results; one counts for the password it judged (by binding), or, in an entry
    ///     from before bindings were kept, for the item version it was made for.
    ///   - synced: what other devices of each item's vault reported (`SyncedScanEvidence`), for the item version it
    ///     was matched against. A synced "not found" counts as a check and never outweighs a breach.
    ///   - clockTolerance: a synced check dated further ahead of `now` than this is ignored.
    public static func make(
        analyses: [ItemAnalysis], ledger: ScanLedger, now: Date, policy: HygienePolicy = HygienePolicy(),
        synced: [UUID: SyncedScanEvidence] = [:], clockTolerance: TimeInterval = ScanPolicy.standard.clockTolerance
    ) -> HygieneReport {
        var reuse = ReuseIndex()
        for analysis in analyses { reuse.set(analysis.reuseTokens, for: analysis.id) }

        var items: [ItemHygiene] = []
        var byKind: [HygieneFindingKind: Int] = [:]
        var bySeverity: [HygieneSeverity: Int] = [:]
        var awaiting = 0
        var oldest: Date?
        var passwords = 0
        for analysis in analyses {
            passwords += analysis.passwords.count
            let evidence = ItemBreachEvidence(
                analysis, ledger: ledger, synced: synced[analysis.id], now: now, tolerance: clockTolerance)
            let item = itemHygiene(analysis, evidence: evidence, reuse: reuse, now: now, policy: policy)
            switch item.breachStatus {
            case .notChecked: awaiting += 1
            case .breached(let at), .clear(let at), .incomplete(let at): oldest = min(oldest ?? at, at)
            case .notApplicable: break
            }
            for kind in Set(item.findings.map(\.kind)) { byKind[kind, default: 0] += 1 }
            if let severity = item.severity { bySeverity[severity, default: 0] += 1 }
            items.append(item)
        }
        items.sort { lhs, rhs in
            let left = lhs.severity?.rawValue ?? -1
            let right = rhs.severity?.rawValue ?? -1
            if left != right { return left > right }
            // Lower-cased and compared by bytes: the same order on every device and in every locale.
            let leftTitle = Array(lhs.title.lowercased().utf8)
            let rightTitle = Array(rhs.title.lowercased().utf8)
            if leftTitle != rightTitle { return leftTitle.lexicographicallyPrecedes(rightTitle) }
            return lhs.id.uuidString < rhs.id.uuidString
        }
        let totals = Totals(
            items: items.count, passwords: passwords,
            itemsNeedingAttention: items.filter { ($0.severity ?? .info) >= .low }.count,
            itemsByKind: byKind, itemsBySeverity: bySeverity, itemsAwaitingBreachCheck: awaiting,
            oldestBreachCheck: oldest, lastFullScanCompletedAt: ledger.fullScanCompletedAt,
            fullScanInProgress: ledger.fullScanStartedAt != nil && ledger.fullScanCompletedAt == nil)
        return HygieneReport(generatedAt: now, items: items, totals: totals)
    }

    private static func itemHygiene(
        _ analysis: ItemAnalysis, evidence: ItemBreachEvidence, reuse: ReuseIndex, now: Date, policy: HygienePolicy
    ) -> ItemHygiene {
        var findings: [HygieneFinding] = []
        var breachedAt: Date?
        var breachSeenHere = false
        for (password, known) in zip(analysis.passwords, evidence.passwords) {
            if let breach = known.breach {
                breachedAt = max(breachedAt ?? breach.at, breach.at)
                breachSeenHere = breachSeenHere || breach.ownFinding
                findings.append(
                    .breached(
                        field: password.fieldID, occurrences: breach.occurrences, reportedBySync: !breach.ownFinding))
            }
            let others = reuse.items(sharing: password.reuseToken, besides: analysis.id)
            if !others.isEmpty { findings.append(.reused(field: password.fieldID, sharedWith: others)) }
            if password.strength.score < .strong { findings.append(.weak(field: password.fieldID, password.strength)) }
            if let limit = policy.oldPasswordAge, let since = password.currentSince,
                now.timeIntervalSince(since) > limit
            {
                findings.append(.unchanged(field: password.fieldID, since: since, now: now))
            }
        }
        if analysis.passwordsNotAnalysed > 0 {
            findings.append(.tooManyPasswords(notAnalysed: analysis.passwordsNotAnalysed))
        }
        for field in analysis.insecureURLFields { findings.append(.insecureURL(field: field)) }
        if !analysis.passwords.isEmpty, !analysis.hasPasskey {
            if !analysis.hasOneTimeCode, analysis.siteCapabilities.contains(.oneTimeCodes) {
                findings.append(.twoFactorAvailable)
            }
            if analysis.siteCapabilities.contains(.passkeys) {
                findings.append(.passkeyAvailable)
            } else if !analysis.hasOneTimeCode, !analysis.siteCapabilities.contains(.oneTimeCodes) {
                findings.append(.passwordOnly)
            }
        }
        findings.sort { lhs, rhs in
            if lhs.severity != rhs.severity { return lhs.severity > rhs.severity }
            if lhs.kind != rhs.kind { return lhs.kind < rhs.kind }
            return (lhs.fieldID?.uuidString ?? "") < (rhs.fieldID?.uuidString ?? "")
        }
        // Two fields that share an ID (nothing makes field IDs distinct) can produce the same finding twice.
        var distinct = Set<HygieneFinding>()
        findings = findings.filter { distinct.insert($0).inserted }
        var worst: [HygieneFindingKind: HygieneSeverity] = [:]
        for finding in findings where finding.severity >= .low {
            worst[finding.kind] = max(worst[finding.kind] ?? finding.severity, finding.severity)
        }
        let badges = worst.map { HygieneBadge(kind: $0.key, severity: $0.value) }.sorted { lhs, rhs in
            if lhs.severity != rhs.severity { return lhs.severity > rhs.severity }
            return lhs.kind < rhs.kind
        }
        let status: BreachStatus
        var source: BreachSource?
        if analysis.passwords.isEmpty {
            status = .notApplicable
        } else if let breachedAt {
            status = .breached(checkedAt: breachedAt)
            source = breachSeenHere ? .thisDevice : .anotherDevice
        } else if let checkedAt = evidence.coveredAt {
            // "Clear" is a statement about every password in the item, so it is not made when some were never
            // looked at, by this device or another.
            status =
                analysis.passwordsNotAnalysed > 0 ? .incomplete(checkedAt: checkedAt) : .clear(checkedAt: checkedAt)
            source = evidence.ownCoveredAt == nil ? .anotherDevice : .thisDevice
        } else {
            status = .notChecked
        }
        return ItemHygiene(
            id: analysis.id, title: analysis.title, isArchived: analysis.isArchived, findings: findings,
            badges: badges, breachStatus: status, breachSource: source)
    }
}

extension HygieneFinding {
    static func breached(field: UUID, occurrences: UInt32, reportedBySync: Bool = false) -> HygieneFinding {
        let times: String
        if occurrences == UInt32.max {
            times = "more than four billion times"
        } else if occurrences == 1 {
            times = "once"
        } else {
            times = "\(occurrences) times"
        }
        return HygieneFinding(
            kind: .breachedPassword, severity: .critical, fieldID: field, summary: "Password found in a data breach",
            explanation: (reportedBySync
                ? "Another device that shares this vault found this password in known data breaches (\(times)), "
                : "This password appears in known data breaches (\(times)), ")
                + "so it is on the lists attackers try first. Change it now, here and anywhere else it was used.",
            detail: .breached(occurrences: occurrences))
    }

    static func reused(field: UUID, sharedWith others: [UUID]) -> HygieneFinding {
        let count = others.count == 1 ? "1 other item" : "\(others.count) other items"
        return HygieneFinding(
            kind: .reusedPassword, severity: .high, fieldID: field, summary: "Password used on more than one account",
            explanation: "\(count) in your vaults use this same password. If any one of those sites is breached, "
                + "every account sharing the password is exposed. Give each account its own.",
            detail: .reused(sharedWith: others))
    }

    static func weak(field: UUID, _ strength: StrengthAssessment) -> HygieneFinding {
        HygieneFinding(
            kind: .weakPassword, severity: strength.score <= .weak ? .high : .medium, fieldID: field,
            summary: strength.score <= .weak ? "Weak password" : "Password could be stronger",
            explanation: strength.explanation + " Replace it with a generated password.",
            detail: .weak(score: strength.score, weakness: strength.weakness))
    }

    static func unchanged(field: UUID, since: Date, now: Date) -> HygieneFinding {
        let years = Int(now.timeIntervalSince(since) / (365.25 * 24 * 60 * 60))
        let age = years <= 1 ? "more than a year" : "more than \(years) years"
        return HygieneFinding(
            kind: .oldPassword, severity: .info, fieldID: field, summary: "Old password",
            explanation: "This password has not changed for \(age). Age alone is not a reason to change a strong, "
                + "unique password, but an old one predates the breaches this report can see.",
            detail: .unchanged(since: since))
    }

    static func tooManyPasswords(notAnalysed count: Int) -> HygieneFinding {
        let rest = count == 1 ? "1 more password" : "\(count) more passwords"
        return HygieneFinding(
            kind: .tooManyPasswords, severity: .low, fieldID: nil, summary: "Too many passwords to check",
            explanation: "This item holds \(rest) than are checked in one item "
                + "(\(ItemAnalyzer.maximumPasswordsPerItem)). They were not checked for breaches, strength or "
                + "reuse. Move them to items of their own.",
            detail: .notAnalysed(passwords: count))
    }

    static func insecureURL(field: UUID) -> HygieneFinding {
        HygieneFinding(
            kind: .insecureURL, severity: .low, fieldID: field, summary: "Unencrypted web address",
            explanation: "This item has a web address that starts with http://, so anything typed there travels "
                + "unencrypted. Use the https:// address if the site has one.",
            detail: .none)
    }

    static let twoFactorAvailable = HygieneFinding(
        kind: .twoFactorAvailable, severity: .medium, fieldID: nil, summary: "Two-step verification available",
        explanation: "This site is listed as supporting two-step verification with an authenticator app, and this "
            + "item has no one-time code. Turning it on protects the account even if the password leaks.",
        detail: .none)

    static let passkeyAvailable = HygieneFinding(
        kind: .passkeyAvailable, severity: .low, fieldID: nil, summary: "Passkey available",
        explanation: "This site is listed as supporting passkeys, and this item has only a password. A passkey "
            + "cannot be phished, guessed or reused; add one in the site's security settings.",
        detail: .none)

    static let passwordOnly = HygieneFinding(
        kind: .passwordOnly, severity: .info, fieldID: nil, summary: "Password only",
        explanation: "This account is protected by a password alone. If the site offers passkeys or two-step "
            + "verification, turning one on protects it against phishing.",
        detail: .none)
}
