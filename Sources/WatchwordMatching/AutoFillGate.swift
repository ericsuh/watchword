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
    /// The page was loaded over plain `http` (PRD F6.9). Nothing is filled into it, whatever is scoped to its host
    /// and whatever the person chose: the page's content, its scripts and the form's destination are all open to
    /// anyone on the network path. Carries the host so the UI can name it.
    case insecurePage(NormalizedHost)
    /// Items are scoped to this host, but only in vaults other accounts write, and the host resembles a site saved in
    /// another vault (review finding Z60). A scope is evidence about a host only within its own trust domain: a
    /// member of a shared vault who scopes an item to `amaz0n.com` has not vouched for it on behalf of the person
    /// whose own vault holds `amazon.com`, so the host is treated as the look-alike it may be and nothing is offered
    /// on it. The same holds for a host that cannot be verified by eye (a label mixing scripts, punycode that did not
    /// decode), which then names no site. It stops being refused when an item in a vault only this account writes is
    /// scoped to the host, which is the person saying so themselves. The assessment is always `suspicious`.
    case resemblesSavedSite(PhishingAssessment)
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
///
/// Both entry points refuse a page loaded over plain `http` before anything is matched (PRD F6.9, owner decision
/// 2026-11-16): `insecurePage`, for every request that would put a secret into a page, an explicit choice included.
/// A domain identifier, which carries no scheme, is judged on its host as before.
public enum AutoFillGate {
    /// The host of a page the gate may fill: the identifier normalised, and not a page loaded over plain `http`.
    /// Every decision starts here, and so does any request that puts something into a page without releasing an
    /// item (generating a password for it).
    public static func page(_ identifier: ServiceIdentifier) -> Result<NormalizedHost, FillRefusal> {
        let host: NormalizedHost
        do {
            host = try HostNormalizer.normalize(identifier)
        } catch let error as HostNormalizationError {
            return .failure(.unusableIdentifier(error))
        } catch {
            return .failure(.unusableIdentifier(.invalidHost(identifier.identifier)))
        }
        guard !HostNormalizer.isPlainHTTPPage(identifier) else { return .failure(.insecurePage(host)) }
        return .success(host)
    }

    /// What may be offered on a page the gate has read: the ranking, or why nothing is offered there.
    ///
    /// `sharedVaults` names the vaults accounts other than this one may write, as for `ItemRanker.rank`. Where the
    /// only items scoped to the host are in such vaults, the host is still compared with what the other vaults hold,
    /// and one that resembles a site saved there is refused as `resemblesSavedSite`.
    public static func candidates(
        on host: NormalizedHost, among items: [Item], sharedVaults: Set<UUID> = []
    ) -> Result<ItemRanking, FillRefusal> {
        let ranking = ItemRanker.rank(items: items, host: host, sharedVaults: sharedVaults)
        guard !ranking.primary.isEmpty else {
            return .failure(
                .noMatchingItem(PhishingDetector.assess(host: host, againstItemsIn: items, sharedVaults: sharedVaults)))
        }
        // An item of the person's own that matches is never shadowed by a shared vault's, so this is exactly the
        // case in which nothing of the person's own is scoped to the host.
        if ranking.primary.allSatisfy({ sharedVaults.contains($0.item.vaultID) }) {
            let assessment = PhishingDetector.assess(host: host, againstItemsIn: items, sharedVaults: sharedVaults)
            if assessment.isSuspicious { return .failure(.resemblesSavedSite(assessment)) }
        }
        return .success(ranking)
    }

    /// What to offer for an incoming request.
    public static func decide(
        for identifier: ServiceIdentifier, among items: [Item], sharedVaults: Set<UUID> = []
    ) -> FillDecision {
        let host: NormalizedHost
        switch page(identifier) {
        case .success(let found): host = found
        case .failure(let refusal): return .refuse(refusal)
        }

        switch candidates(on: host, among: items, sharedVaults: sharedVaults) {
        case .failure(let refusal): return .refuse(refusal)
        case .success(let ranking): return ranking.isAmbiguous ? .chooseAmong(ranking.primary) : .fill(ranking.primary[0])
        }
    }

    /// Final check before returning `item`'s secret to the system. Call this even when the person
    /// explicitly chose the item: the question is not "did they pick it" but "is this item
    /// actually for this site".
    public static func authorize(
        _ item: Item,
        for identifier: ServiceIdentifier,
        among items: [Item],
        sharedVaults: Set<UUID> = []
    ) -> Result<NormalizedHost, FillRefusal> {
        let host: NormalizedHost
        switch page(identifier) {
        case .success(let found): host = found
        case .failure(let refusal): return .failure(refusal)
        }

        switch candidates(on: host, among: items, sharedVaults: sharedVaults) {
        case .failure(.noMatchingItem(let assessment)):
            return .failure(.itemNotScopedToHost(assessment))
        case .failure(let refusal):
            return .failure(refusal)
        case .success(let ranking):
            guard ranking.primary.contains(where: { $0.item.id == item.id }) else {
                return .failure(
                    .itemNotScopedToHost(
                        PhishingDetector.assess(host: host, againstItemsIn: items, sharedVaults: sharedVaults)))
            }
            return .success(host)
        }
    }

    /// Whether a one-time code may be placed on the clipboard or returned for this host.
    ///
    /// Held to the same rule as a password: a TOTP typed into a look-alike site is immediately
    /// replayable by the attacker, so a mismatch refuses rather than warns (PRD F11.4).
    public static func authorizeOneTimeCode(
        _ item: Item,
        for identifier: ServiceIdentifier,
        among items: [Item],
        sharedVaults: Set<UUID> = []
    ) -> Result<NormalizedHost, FillRefusal> {
        authorize(item, for: identifier, among: items, sharedVaults: sharedVaults)
    }
}
