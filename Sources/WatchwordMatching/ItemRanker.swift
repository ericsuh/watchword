import Foundation
import WatchwordModel

/// One item that matched the requested host, with the best of its scope matches.
public struct RankedMatch: Sendable, Hashable {
    public let item: Item
    public let match: ScopeMatch
    /// `true` when another item matched the same host with a strictly higher specificity.
    /// Shadowed items are listed under "other accounts on this site" and are never pre-selected.
    public let isShadowed: Bool
}

public struct ItemRanking: Sendable, Hashable {
    /// Items with the top specificity, sorted by title. These are the suggestions to offer.
    public let primary: [RankedMatch]
    /// Items that matched less specifically, sorted by specificity descending then title.
    public let shadowed: [RankedMatch]

    public var isEmpty: Bool { primary.isEmpty && shadowed.isEmpty }

    /// `true` when more than one item ties for the top specificity, so the UI must let the person
    /// choose rather than filling the first one (PRD F6.6, F11.5).
    public var isAmbiguous: Bool { primary.count > 1 }
}

/// Implements the ranking rule of PRD F6.6 / architecture §9: the most specific scope wins, less
/// specific matches are shadowed. This is what keeps an Amazon retail login off the AWS console
/// sign-in page even though both live under `amazon.com`.
public enum ItemRanker {
    public static func rank(items: [Item], host: NormalizedHost) -> ItemRanking {
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

        guard let top = matched.map({ $0.match.specificity }).max() else {
            return ItemRanking(primary: [], shadowed: [])
        }

        let atTop = matched.filter { $0.match.specificity == top }
        let belowTop = matched.filter { $0.match.specificity < top }

        let primarySorted = atTop.sorted { $0.item.title < $1.item.title }
        let primary = primarySorted.map { RankedMatch(item: $0.item, match: $0.match, isShadowed: false) }

        let shadowedSorted = belowTop.sorted { lhs, rhs in
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
        identifier: ServiceIdentifier
    ) -> (ItemRanking, HostNormalizationError?) {
        do {
            let host = try HostNormalizer.normalize(identifier)
            return (rank(items: items, host: host), nil)
        } catch let error as HostNormalizationError {
            return (ItemRanking(primary: [], shadowed: []), error)
        } catch {
            return (ItemRanking(primary: [], shadowed: []), .invalidHost(identifier.identifier))
        }
    }

    /// Defence in depth for the AutoFill request handler: before returning a credential for
    /// `item`, confirm the item actually matches the requested host and is not shadowed.
    public static func isSelectable(_ item: Item, for host: NormalizedHost, among items: [Item]) -> Bool {
        rank(items: items, host: host).primary.contains { $0.item.id == item.id }
    }
}
