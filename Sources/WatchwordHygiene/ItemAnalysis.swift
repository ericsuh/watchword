import Foundation
import WatchwordModel

/// The choices the report leaves to the app.
public struct HygienePolicy: Sendable {
    /// A password unchanged for longer than this is mentioned, as information only: forced rotation is not advice
    /// this app gives (NIST SP 800-63B), but a very old password predates most of what the report knows. `nil` turns
    /// the check off.
    public var oldPasswordAge: TimeInterval?
    /// Where "this site supports two-step verification or passkeys" comes from. Nothing, unless the app chooses a
    /// directory (`EmbeddedSiteDirectory`, or its own).
    public var siteDirectory: any SiteDirectory

    public init(
        oldPasswordAge: TimeInterval? = 3 * 365 * 24 * 60 * 60, siteDirectory: any SiteDirectory = NoSiteDirectory()
    ) {
        self.oldPasswordAge = oldPasswordAge
        self.siteDirectory = siteDirectory
    }
}

/// Everything the report needs to know about one password, and nothing that could reproduce it.
public struct PasswordFact: Hashable, Sendable {
    public let fieldID: UUID
    public let strength: StrengthAssessment
    /// For the reuse index. In memory only (`ReuseToken`).
    let reuseToken: ReuseToken
    /// When this value became the field's value, from the item's history; `nil` if the item carries no usable
    /// timestamps.
    public let currentSince: Date?
}

/// One item, reduced to what the hygiene report is built from. Made while keys are resident (`ItemAnalyzer`), kept
/// in memory until lock, never persisted: the title is as private as the item, and the reuse tokens are derived from
/// its passwords.
public struct ItemAnalysis: Hashable, Sendable, Identifiable {
    public let id: UUID
    public let version: UInt64
    public let title: String
    public let isArchived: Bool
    public let passwords: [PasswordFact]
    /// `url` fields whose address is plain `http`.
    public let insecureURLFields: [UUID]
    public let hasOneTimeCode: Bool
    public let hasPasskey: Bool
    /// What the policy's directory says about the item's sites; empty when it says nothing.
    public let siteCapabilities: SiteCapabilities

    var reuseTokens: Set<ReuseToken> {
        Set(passwords.map(\.reuseToken))
    }

    var candidate: ScanCandidate {
        ScanCandidate(id: id, version: version)
    }
}

/// Turns an item into an `ItemAnalysis` (PRD F9.3): strength of each password, the token for reuse detection, how
/// long each password has been current, plain-`http` addresses, and which stronger sign-in methods the item has.
///
/// Pure: the same item, key, policy and reference year give the same analysis. It hashes passwords (under the reuse
/// key), so it runs only while keys are resident; `HygieneEngine` is what guarantees that.
public struct ItemAnalyzer: Sendable {
    /// Passwords beyond this many in one item are not analysed or checked: an item is one account, and a shared item
    /// with thousands of password fields would otherwise buy thousands of estimates and range requests in one step.
    public static let maximumPasswordsPerItem = 16

    public let estimator: StrengthEstimator
    public let policy: HygienePolicy

    public init(estimator: StrengthEstimator, policy: HygienePolicy = HygienePolicy()) {
        self.estimator = estimator
        self.policy = policy
    }

    /// The password fields the scanner and the report look at, in field order.
    public static func passwordFields(of item: Item) -> [Field] {
        Array(item.fields.lazy.filter { $0.kind == .password && !$0.value.isEmpty }.prefix(maximumPasswordsPerItem))
    }

    public func analyse(_ item: Item, reuseKey: ReuseKey) -> ItemAnalysis {
        // What an attacker who knows the account tries first.
        var personal = [item.title]
        personal.append(contentsOf: item.loginNames)
        personal.append(contentsOf: item.scopes.map(\.host))
        let passwords = Self.passwordFields(of: item).map { field in
            PasswordFact(
                fieldID: field.id,
                strength: estimator.assess(field.value, personalInputs: personal),
                reuseToken: reuseKey.token(forUTF8Of: field.value),
                currentSince: Self.currentSince(field, in: item))
        }
        var capabilities: SiteCapabilities = []
        for scope in item.scopes.prefix(64) {
            capabilities.formUnion(policy.siteDirectory.capabilities(ofHost: scope.host))
        }
        return ItemAnalysis(
            id: item.id, version: item.version, title: item.title, isArchived: item.archived, passwords: passwords,
            insecureURLFields: item.fields.filter { $0.kind == .url && Self.isInsecureURL($0.value) }.map(\.id),
            hasOneTimeCode: item.fields.contains { $0.kind == .totp && !$0.value.isEmpty },
            hasPasskey: item.fields.contains { $0.kind == .passkey && !$0.value.isEmpty },
            siteCapabilities: capabilities)
    }

    /// When `field`'s present value became current: the latest time at which the item's history shows a *different*
    /// value (or no such field) being replaced, or the item's creation if history shows none.
    ///
    /// Asking for the latest differing entry, not walking the list in order, gives the same answer however a merge
    /// ordered the history, and gets a password that was changed and changed back right.
    static func currentSince(_ field: Field, in item: Item) -> Date? {
        var since = item.createdAt
        for entry in item.history {
            let earlier = entry.fields.first { $0.id == field.id }
            if earlier?.value != field.value, entry.replacedAt > since { since = entry.replacedAt }
        }
        // Items made without a clock carry the epoch; that is "unknown", not "fifty years old".
        return since.timeIntervalSince1970 > 0 ? since : nil
    }

    /// Whether `text` is an `http://` address somewhere other than this machine. Anything that is not clearly one
    /// is not flagged.
    static func isInsecureURL(_ text: String) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let scheme = "http://"
        guard trimmed.hasPrefix(scheme), trimmed.utf8.count <= 2048 else { return false }
        var authority = trimmed.dropFirst(scheme.count).prefix { $0 != "/" && $0 != "?" && $0 != "#" }
        if let at = authority.lastIndex(of: "@") { authority = authority[authority.index(after: at)...] }
        guard !authority.isEmpty else { return false }
        let host: Substring
        if authority.hasPrefix("[") {
            host = authority.prefix { $0 != "]" }.dropFirst()
        } else {
            host = authority.prefix { $0 != ":" }
        }
        // Loopback cannot be intercepted on the network, and a local service rarely has a certificate.
        if host == "localhost" || host.hasSuffix(".localhost") || host == "::1" { return false }
        if host.hasPrefix("127."), host.allSatisfy({ $0.isNumber || $0 == "." }) { return false }
        return !host.isEmpty
    }
}
