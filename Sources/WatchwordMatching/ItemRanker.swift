import Foundation
import WatchwordModel

/// One item that matched the requested host, with the best of its scope matches.
public struct RankedMatch: Sendable, Hashable {
    public let item: Item
    public let match: ScopeMatch
    /// `true` when an item entitled to shadow this one (see `ItemRanker`) matched the same host with a strictly
    /// higher specificity. A shadowed item is never offered, listed or released on that host by the AutoFill extension (PRD F6.6); it
    /// stays reachable in the app.
    public let isShadowed: Bool
}

public struct ItemRanking: Sendable, Hashable {
    /// The items nothing shadows, sorted by title: the suggestions to offer. Among the vaults only this account
    /// writes these all share the top specificity. An item of a shared vault can stand beside them at another
    /// specificity (see `ItemRanker`), which makes the ranking ambiguous: the person chooses.
    public let primary: [RankedMatch]
    /// Items that matched less specifically than an item entitled to shadow them, sorted by specificity descending
    /// then title.
    public let shadowed: [RankedMatch]

    public var isEmpty: Bool { primary.isEmpty && shadowed.isEmpty }

    /// `true` when more than one item is unshadowed, so the UI must let the person choose rather than filling the
    /// first one (PRD F6.6, F11.5): accounts that tie, or an item of a shared vault beside one of the person's own.
    public var isAmbiguous: Bool { primary.count > 1 }
}

/// Implements the ranking rule of PRD F6.6 / architecture §9: the most specific scope wins, less
/// specific matches are shadowed. This is what keeps an Amazon retail login off the AWS console
/// sign-in page even though both live under `amazon.com`.
///
/// **A vault is a trust domain** (review finding Z60). Shadowing is a statement by whoever wrote the more specific
/// scope: "on this host, that other account is not the one". In a vault only this account writes, the person made
/// it. In a shared vault any member who may write made it, and a member who plants an item scoped one label below
/// the person's own login would otherwise take that login out of AutoFill there, or stand in its place as the
/// destination of the next saved password. So an item is shadowed only by a more specific match **in its own vault,
/// or in a vault only this account writes**; an item of a shared vault never shadows an item of another vault. Where
/// the two classes meet on a host both stay in `primary`, the ranking is ambiguous, and nothing is filled or written
/// without the person choosing between entries that name their vaults.
public enum ItemRanker {
    /// - Parameter sharedVaults: The vaults accounts other than this one may write (the session's answer, never the
    ///   item's own claim). Items of every other vault are taken to be the person's own. A caller that holds items
    ///   of more than one vault must pass it; the default suits one vault's items and tests.
    public static func rank(items: [Item], host: NormalizedHost, sharedVaults: Set<UUID> = []) -> ItemRanking {
        var matched: [(item: Item, match: ScopeMatch)] = []
        for item in items {
            var best: ScopeMatch?
            for scope in item.scopes {
                guard let candidate = ScopeMatcher.match(scope, host: host) else { continue }
                if let current = best, candidate.specificity <= current.specificity { continue }
                best = candidate
            }
            if let best {
                matched.append((item, best))
            }
        }
        guard !matched.isEmpty else { return ItemRanking(primary: [], shadowed: []) }

        // The specificity an item must reach not to be shadowed: the best among the person's own vaults, and for
        // an item of a shared vault also the best in that vault.
        var topOwn = Int.min
        var topInSharedVault: [UUID: Int] = [:]
        for entry in matched {
            let specificity = entry.match.specificity
            if sharedVaults.contains(entry.item.vaultID) {
                topInSharedVault[entry.item.vaultID] = max(topInSharedVault[entry.item.vaultID] ?? .min, specificity)
            } else {
                topOwn = max(topOwn, specificity)
            }
        }
        func isShadowed(_ entry: (item: Item, match: ScopeMatch)) -> Bool {
            entry.match.specificity < max(topOwn, topInSharedVault[entry.item.vaultID] ?? .min)
        }

        let primarySorted = matched.filter { !isShadowed($0) }.sorted { $0.item.title < $1.item.title }
        let primary = primarySorted.map { RankedMatch(item: $0.item, match: $0.match, isShadowed: false) }

        let shadowedSorted = matched.filter(isShadowed).sorted { lhs, rhs in
            if lhs.match.specificity != rhs.match.specificity {
                return lhs.match.specificity > rhs.match.specificity
            }
            return lhs.item.title < rhs.item.title
        }
        let shadowed = shadowedSorted.map { RankedMatch(item: $0.item, match: $0.match, isShadowed: true) }

        return ItemRanking(primary: primary, shadowed: shadowed)
    }

    /// Normalize the OS-provided identifier, then rank. Any normalization failure yields an empty
    /// ranking (fail closed) and the error for logging.
    public static func rank(
        items: [Item],
        identifier: ServiceIdentifier,
        sharedVaults: Set<UUID> = []
    ) -> (ItemRanking, HostNormalizationError?) {
        do {
            let host = try HostNormalizer.normalize(identifier)
            return (rank(items: items, host: host, sharedVaults: sharedVaults), nil)
        } catch let error as HostNormalizationError {
            return (ItemRanking(primary: [], shadowed: []), error)
        } catch {
            return (ItemRanking(primary: [], shadowed: []), .invalidHost(identifier.identifier))
        }
    }

    /// Defence in depth for the AutoFill request handler: before returning a credential for
    /// `item`, confirm the item actually matches the requested host and is not shadowed.
    public static func isSelectable(
        _ item: Item, for host: NormalizedHost, among items: [Item], sharedVaults: Set<UUID> = []
    ) -> Bool {
        rank(items: items, host: host, sharedVaults: sharedVaults).primary.contains { $0.item.id == item.id }
    }
}
