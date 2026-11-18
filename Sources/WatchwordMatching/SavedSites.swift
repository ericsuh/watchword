import Foundation
import WatchwordModel

/// How a host someone is about to add as a scope stands against what is saved (PRD F11.7).
public enum NewHostStanding: Hashable, Sendable {
    /// Nothing saved resembles it, or something the person saved themselves already covers it.
    case ordinary
    /// It resembles a saved site that it is not (`resembles` names them, sorted), or it cannot be verified by eye
    /// (a label outside ASCII or in punycode, a label mixing scripts; `resembles` is then empty), or it could not be
    /// read as a hostname at all. Adding it needs a confirmation that names the site and the item.
    case needsConfirmation(resembles: [String])

    public var needsConfirmation: Bool { self != .ordinary }
}

/// An account already saved that a new item would affect on some host.
public struct AffectedAccount: Hashable, Sendable {
    public let itemID: UUID
    public let vaultID: UUID
    public let title: String
    /// The host on which it happens: one the new item is scoped to, or a saved host below one of its scopes.
    public let host: String

    public init(itemID: UUID, vaultID: UUID, title: String, host: String) {
        self.itemID = itemID
        self.vaultID = vaultID
        self.title = title
        self.host = host
    }
}

/// What adding one item would do to the accounts AutoFill already offers (review finding Z62).
public struct ScopeOverlap: Hashable, Sendable {
    /// Accounts the new item would outrank on a host they are offered on today: the extension would no longer list
    /// or release them there.
    public var hidden: [AffectedAccount] = []
    /// Accounts it would be offered beside: a tie, or an item of a shared vault next to one of the person's own. The
    /// person then chooses between them every time, and a save offers both for update.
    public var beside: [AffectedAccount] = []
    /// The item's scopes cover more saved hosts than were examined; what is listed is not everything.
    public var isTruncated = false

    public init() {}

    public var isEmpty: Bool { hidden.isEmpty && beside.isEmpty && !isTruncated }
}

/// The saved items as the gate ranks among them, for everything that judges a host or an item *before* it is saved:
/// the gate itself, the item editor's confirmation and the import preview (review findings Z60 to Z62, Z65).
///
/// One view, so that the three cannot drift: every item outside the trash, each with only the scopes the scope policy
/// accepts (a stored `com` scope matches nothing and recognises nothing), and which vaults other accounts write. A
/// caller says which vaults are the person's own; every other vault an item names counts as shared.
public struct SavedSites: Sendable {
    /// What the gate ranks among.
    public let items: [Item]
    /// The vaults accounts other than this one may write.
    public let sharedVaults: Set<UUID>

    /// - Parameters:
    ///   - stored: The items as stored, trashed ones included.
    ///   - ownVaults: The vaults only this account writes, by the session's answer. Every other vault is shared.
    public init(stored: [Item], ownVaults: Set<UUID>) {
        let ranked = stored.filter { !$0.isTrashed }.map { item -> Item in
            var view = item
            view.scopes = item.scopes.filter(ScopePolicy.isAcceptable)
            return view
        }
        items = ranked
        sharedVaults = Set(stored.map(\.vaultID)).subtracting(ownVaults)
    }

    // MARK: The gate

    public func candidates(on host: NormalizedHost) -> Result<ItemRanking, FillRefusal> {
        AutoFillGate.candidates(on: host, among: items, sharedVaults: sharedVaults)
    }

    public func decide(for identifier: ServiceIdentifier) -> FillDecision {
        AutoFillGate.decide(for: identifier, among: items, sharedVaults: sharedVaults)
    }

    public func authorize(
        _ item: Item, for identifier: ServiceIdentifier, oneTimeCode: Bool = false
    ) -> Result<NormalizedHost, FillRefusal> {
        oneTimeCode
            ? AutoFillGate.authorizeOneTimeCode(item, for: identifier, among: items, sharedVaults: sharedVaults)
            : AutoFillGate.authorize(item, for: identifier, among: items, sharedVaults: sharedVaults)
    }

    /// The look-alike assessment of a page's host, by trust domain (`PhishingDetector.SiteIndex`).
    public func assess(_ host: NormalizedHost) -> PhishingAssessment {
        PhishingDetector.assess(host: host, againstItemsIn: items, sharedVaults: sharedVaults)
    }

    /// This view with its comparisons worked out once, for judging hosts and items before they are saved.
    public func prepared() -> Prepared {
        Prepared(self)
    }
}

/// `SavedSites` prepared for many questions: each saved scope's skeleton and name computed once, and the items
/// indexed by host. Built for one save or one import preview, not per AutoFill request.
extension SavedSites {
    public struct Prepared: Sendable {
        public let sites: SavedSites
        private let index: PhishingDetector.SiteIndex
        /// Items by the host of each scope, and saved hosts by each name above them, for `overlap`.
        private let byHost: [String: [Int]]
        private let hostsBelow: [String: [String]]

        /// Saved hosts below one scope that `overlap` examines.
        public static let maximumHostsExamined = 64

        init(_ sites: SavedSites) {
            self.sites = sites
            index = PhishingDetector.SiteIndex(items: sites.items, sharedVaults: sites.sharedVaults)
            var byHost: [String: [Int]] = [:]
            var below: [String: Set<String>] = [:]
            for (position, item) in sites.items.enumerated() {
                for scope in item.scopes {
                    byHost[scope.host, default: []].append(position)
                    var rest = Substring(scope.host)
                    while let dot = rest.firstIndex(of: ".") {
                        rest = rest[rest.index(after: dot)...]
                        below[String(rest), default: []].insert(scope.host)
                    }
                }
            }
            self.byHost = byHost
            hostsBelow = below.mapValues { $0.sorted() }
        }

        private var items: [Item] { sites.items }
        private var sharedVaults: Set<UUID> { sites.sharedVaults }

        /// How many saved scopes one `standing(ofNewHost:)` compares a host with.
        public var comparisonsPerHost: Int { index.count }

        /// How `host`, about to become a scope of an item, stands against what is saved. `otherScopes` are the scopes
        /// the same item would hold beside it, in a vault of the person's own or not: a host the item's other scopes
        /// already cover is the item's own, and a host that resembles one of them is a look-alike of it.
        ///
        /// `vault` is the item's vault: a scope of another shared vault does not make the host recognised for it
        /// (review finding Z76). `nil` lets no shared vault vouch.
        public func standing(
            ofNewHost host: String, beside otherScopes: [ServiceScope] = [], inSharedVault: Bool = false,
            inVault vault: UUID? = nil
        ) -> NewHostStanding {
            standing(ofNewHost: host, beside: otherScopes, vouching: true, inSharedVault: inSharedVault, vault: vault)
        }

        /// As `standing(ofNewHost:beside:)`, for scopes that are not the person's word (an import file's, a member's):
        /// `otherScopes` are compared with the host for resemblance only, so `amaz0n.com` beside `amazon.com` in one
        /// entry needs a confirmation, and a host they cover is not thereby recognised (review findings Z72, Z74).
        public func standing(
            ofNewHost host: String, resemblingOnly otherScopes: [ServiceScope], inSharedVault: Bool = false,
            inVault vault: UUID? = nil
        ) -> NewHostStanding {
            standing(ofNewHost: host, beside: otherScopes, vouching: false, inSharedVault: inSharedVault, vault: vault)
        }

        private func standing(
            ofNewHost host: String, beside otherScopes: [ServiceScope], vouching: Bool, inSharedVault: Bool,
            vault: UUID?
        ) -> NewHostStanding {
            guard let normalized = try? HostNormalizer.normalize(ServiceIdentifier(host, kind: .domain)) else {
                return .needsConfirmation(resembles: [])
            }
            var assessment = index.assess(normalized, forItemIn: vault)
            let others = PhishingDetector.ScopeIndex(otherScopes.filter(ScopePolicy.isAcceptable))
            if others.count > 0 {
                if others.matches(normalized) {
                    guard vouching else { return Self.standing(of: assessment, host: host, normalized: normalized) }
                    // Covered by the item's own scopes. In a shared vault that is a member's word, which stands unless
                    // the host resembles something outside the item.
                    if !inSharedVault || !assessment.isSuspicious { assessment = .recognized }
                } else if case .suspicious(let signals, let names) = others.assess(normalized) {
                    var merged = Set(names)
                    var all = signals
                    if case .suspicious(let found, let already) = assessment {
                        merged.formUnion(already)
                        all.formUnion(found)
                    }
                    assessment = .suspicious(signals: all, impersonating: merged.sorted())
                }
            }
            return Self.standing(of: assessment, host: host, normalized: normalized)
        }

        private static func standing(
            of assessment: PhishingAssessment, host: String, normalized: NormalizedHost
        ) -> NewHostStanding {
            switch assessment {
            case .recognized:
                return .ordinary
            case .suspicious(_, let impersonating):
                return .needsConfirmation(resembles: impersonating)
            case .unrecognized:
                // Nothing saved resembles it, but a host outside ASCII, or one in punycode, is not what it looks like
                // until the person has read its ASCII form.
                let unreadable =
                    !normalized.isASCII || !host.unicodeScalars.allSatisfy(\.isASCII)
                    || normalized.labels.contains { $0.hasPrefix("xn--") }
                return unreadable ? .needsConfirmation(resembles: []) : .ordinary
            }
        }

        // MARK: Before an item is saved

        /// What an item scoped `scopes`, in `vaultID`, would do to the accounts already offered, on every host where it
        /// and a saved item both match: the hosts it is scoped to, and the saved hosts below a scope of its that includes
        /// subdomains. An archived or excluded new item is judged like any other: it ranks all the same, and would hide
        /// an account while offering nothing in its place.
        ///
        /// - Parameter isOwnVault: Whether `vaultID` is a vault only this account writes, by the session's answer.
        public func overlap(ofAdding scopes: [ServiceScope], inVault vaultID: UUID, isOwnVault: Bool) -> ScopeOverlap {
            var overlap = ScopeOverlap()
            let usable = scopes.filter(ScopePolicy.isAcceptable)
            guard !usable.isEmpty else { return overlap }
            let candidate = Item(vaultID: vaultID, title: "", scopes: usable, fields: [])
            var shared = sharedVaults
            if isOwnVault { shared.remove(vaultID) } else { shared.insert(vaultID) }

            var hosts: [String] = []
            var seenHosts = Set<String>()
            for scope in usable {
                if seenHosts.insert(scope.host).inserted { hosts.append(scope.host) }
                guard scope.includeSubdomains, let below = hostsBelow[scope.host] else { continue }
                if below.count > Self.maximumHostsExamined { overlap.isTruncated = true }
                for host in below.prefix(Self.maximumHostsExamined) where seenHosts.insert(host).inserted {
                    hosts.append(host)
                }
            }

            var hidden = Set<AffectedAccount>()
            var beside = Set<AffectedAccount>()
            for value in hosts {
                guard let host = try? HostNormalizer.validate(host: value) else { continue }
                // The saved items that can match here: scoped to the host, or to a name above it.
                var positions = Set(byHost[value] ?? [])
                var rest = Substring(value)
                while let dot = rest.firstIndex(of: ".") {
                    rest = rest[rest.index(after: dot)...]
                    positions.formUnion(byHost[String(rest)] ?? [])
                }
                guard !positions.isEmpty else { continue }
                let relevant = positions.sorted().map { items[$0] }
                let before = ItemRanker.rank(items: relevant, host: host, sharedVaults: shared).primary
                    .filter { !$0.item.archived && !$0.item.excludedFromSuggestions }
                guard !before.isEmpty else { continue }
                let after = ItemRanker.rank(items: relevant + [candidate], host: host, sharedVaults: shared).primary
                guard after.contains(where: { $0.item.id == candidate.id }) else { continue }
                for match in before {
                    let account = AffectedAccount(
                        itemID: match.item.id, vaultID: match.item.vaultID, title: match.item.title, host: value)
                    if after.contains(where: { $0.item.id == match.item.id }) {
                        beside.insert(account)
                    } else {
                        hidden.insert(account)
                    }
                }
            }
            func ordered(_ accounts: Set<AffectedAccount>) -> [AffectedAccount] {
                accounts.sorted {
                    ($0.host, $0.title, $0.itemID.uuidString) < ($1.host, $1.title, $1.itemID.uuidString)
                }
            }
            overlap.hidden = ordered(hidden)
            overlap.beside = ordered(beside)
            return overlap
        }
    }
}
