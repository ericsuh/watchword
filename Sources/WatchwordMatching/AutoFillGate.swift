import Foundation
import WatchwordModel

/// Why the gate will not hand a credential to the system.
public enum FillRefusal: Error, Hashable, Sendable {
    /// The identifier the system supplied is not a usable hostname.
    case unusableIdentifier(HostNormalizationError)
    /// Nothing is scoped to this host.
    case noMatchingItem(PhishingAssessment)
    /// The caller asked to fill an item that is not scoped to this host. This is the
    /// defence-in-depth case: a UI bug or a tampered record must not become a wrong-site fill.
    case itemNotScopedToHost(PhishingAssessment)
}

/// What the AutoFill extension is permitted to do for one request.
public enum FillDecision: Hashable, Sendable {
    /// Exactly one item is the most specific match: safe to fill, including without interaction.
    case fill(RankedMatch)
    /// Several items tie for most specific (two accounts on one site). The person must pick; the
    /// extension must not choose for them.
    case chooseAmong([RankedMatch])
    /// Nothing may be filled.
    case refuse(FillRefusal)

    public var isFill: Bool {
        if case .fill = self { return true }
        return false
    }
}

/// The single chokepoint through which a credential may reach the operating system.
///
/// PRD SEC6 says the extension never returns a credential for a service identifier the item is
/// not scoped to. Routing every response through `authorize(_:for:among:)` makes that a property
/// of one testable function rather than a convention spread across view controllers.
public enum AutoFillGate {
    /// What to offer for an incoming request.
    public static func decide(for identifier: ServiceIdentifier, among items: [Item]) -> FillDecision {
        let host: NormalizedHost
        do {
            host = try HostNormalizer.normalize(identifier)
        } catch let error as HostNormalizationError {
            return .refuse(.unusableIdentifier(error))
        } catch {
            return .refuse(.unusableIdentifier(.invalidHost(identifier.identifier)))
        }

        let ranking = ItemRanker.rank(items: items, host: host)
        guard !ranking.primary.isEmpty else {
            return .refuse(.noMatchingItem(PhishingDetector.assess(host: host, againstItemsIn: items)))
        }
        if ranking.isAmbiguous {
            return .chooseAmong(ranking.primary)
        }
        return .fill(ranking.primary[0])
    }

    /// Final check before returning `item`'s secret to the system. Call this even when the person
    /// explicitly chose the item: the question is not "did they pick it" but "is this item
    /// actually for this site".
    public static func authorize(
        _ item: Item,
        for identifier: ServiceIdentifier,
        among items: [Item]
    ) -> Result<NormalizedHost, FillRefusal> {
        let host: NormalizedHost
        do {
            host = try HostNormalizer.normalize(identifier)
        } catch let error as HostNormalizationError {
            return .failure(.unusableIdentifier(error))
        } catch {
            return .failure(.unusableIdentifier(.invalidHost(identifier.identifier)))
        }

        guard ItemRanker.isSelectable(item, for: host, among: items) else {
            return .failure(.itemNotScopedToHost(PhishingDetector.assess(host: host, againstItemsIn: items)))
        }
        return .success(host)
    }

    /// Whether a one-time code may be placed on the clipboard or returned for this host.
    ///
    /// Held to the same rule as a password: a TOTP typed into a look-alike site is immediately
    /// replayable by the attacker, so a mismatch refuses rather than warns (PRD F11.4).
    public static func authorizeOneTimeCode(
        _ item: Item,
        for identifier: ServiceIdentifier,
        among items: [Item]
    ) -> Result<NormalizedHost, FillRefusal> {
        authorize(item, for: identifier, among: items)
    }
}
