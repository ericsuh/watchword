import WatchwordModel
import XCTest

@testable import WatchwordMatching

/// End-to-end matching for PRD scenario S1 (Amazon retail vs AWS root, same email).
final class ItemRankerTests: XCTestCase {
    private func host(_ value: String) throws -> NormalizedHost {
        try HostNormalizer.normalize(ServiceIdentifier(value, kind: .domain))
    }

    func testRetailSiteOffersOnlyRetailAccount() throws {
        let ranking = ItemRanker.rank(items: ScenarioFixtures.all, host: try host("www.amazon.com"))
        XCTAssertEqual(ranking.primary.map(\.item.title), ["Amazon"])
        XCTAssertTrue(ranking.shadowed.isEmpty, "AWS must not appear at all on the retail site")
    }

    func testAWSSignInOffersAWSFirstAndShadowsRetail() throws {
        let ranking = ItemRanker.rank(items: ScenarioFixtures.all, host: try host("signin.aws.amazon.com"))
        XCTAssertEqual(ranking.primary.map(\.item.title), ["AWS root"])
        XCTAssertEqual(ranking.shadowed.map(\.item.title), ["Amazon"])
        XCTAssertTrue(ranking.shadowed.allSatisfy { $0.isShadowed })
        XCTAssertFalse(ranking.isAmbiguous)
    }

    func testAWSConsoleSubdomainStillPrefersAWS() throws {
        let ranking = ItemRanker.rank(items: ScenarioFixtures.all, host: try host("us-east-1.console.aws.amazon.com"))
        XCTAssertEqual(ranking.primary.map(\.item.title), ["AWS root"])
    }

    func testTOTPReturnedForEachSiteBelongsToTheRightItem() throws {
        let items = ScenarioFixtures.all
        let aws = ItemRanker.rank(items: items, host: try host("signin.aws.amazon.com")).primary.first?.item
        let retail = ItemRanker.rank(items: items, host: try host("amazon.com")).primary.first?.item
        XCTAssertTrue(aws?.field(.totp)?.value.contains("secret=AWSROOT") ?? false)
        XCTAssertTrue(retail?.field(.totp)?.value.contains("secret=RETAIL") ?? false)
    }

    func testExcludedHostRemovesRetailFromAWSEntirely() throws {
        var retail = ScenarioFixtures.amazonRetail
        retail.scopes = [
            ServiceScope(host: "amazon.com", includeSubdomains: true, excludedHosts: ["aws.amazon.com"])
        ]
        let ranking = ItemRanker.rank(
            items: [retail, ScenarioFixtures.awsRoot], host: try host("signin.aws.amazon.com"))
        XCTAssertEqual(ranking.primary.map(\.item.title), ["AWS root"])
        XCTAssertTrue(ranking.shadowed.isEmpty)
    }

    func testUnrelatedHostMatchesNothing() throws {
        XCTAssertTrue(ItemRanker.rank(items: ScenarioFixtures.all, host: try host("amazon.co.uk")).isEmpty)
    }

    func testIsSelectableRejectsShadowedItem() throws {
        let items = ScenarioFixtures.all
        let awsHost = try host("signin.aws.amazon.com")
        XCTAssertFalse(ItemRanker.isSelectable(ScenarioFixtures.amazonRetail, for: awsHost, among: items))
        XCTAssertTrue(ItemRanker.isSelectable(ScenarioFixtures.awsRoot, for: awsHost, among: items))
    }

    func testRankingFromOSIdentifierFailsClosedOnBadInput() {
        let identifier = ServiceIdentifier("ftp://amazon.com", kind: .url)
        let (ranking, error) = ItemRanker.rank(items: ScenarioFixtures.all, identifier: identifier)
        XCTAssertTrue(ranking.isEmpty)
        XCTAssertEqual(error, .unsupportedScheme("ftp"))
    }

    /// Two accounts on the same site tie, and the extension must not pick one for the person.
    func testTwoAccountsOnOneSiteAreAmbiguous() throws {
        var second = ScenarioFixtures.amazonRetail
        second.title = "Amazon (household)"
        let ranking = ItemRanker.rank(
            items: [ScenarioFixtures.amazonRetail, second], host: try host("www.amazon.com"))
        XCTAssertTrue(ranking.isAmbiguous)
        XCTAssertEqual(ranking.primary.count, 2)
    }

    // MARK: A vault is a trust domain (review finding Z60)

    private func item(_ title: String, vault: UUID, _ scope: ServiceScope) -> Item {
        Item(vaultID: vault, title: title, scopes: [scope], fields: [])
    }

    /// An item of a shared vault never shadows an item of a vault only this account writes: both stay, and the
    /// ranking is a choice.
    func testSharedVaultItemDoesNotShadowAnOwnItem() throws {
        let shared = UUID()
        let own = item("Own", vault: ScenarioFixtures.vault, ServiceScope(host: "amazon.com"))
        let planted = item("Planted", vault: shared, ServiceScope(host: "www.amazon.com", includeSubdomains: false))
        let target = try host("www.amazon.com")

        let ranking = ItemRanker.rank(items: [own, planted], host: target, sharedVaults: [shared])
        XCTAssertEqual(ranking.primary.map(\.item.title), ["Own", "Planted"])
        XCTAssertTrue(ranking.shadowed.isEmpty)
        XCTAssertTrue(ranking.isAmbiguous)
        XCTAssertTrue(ItemRanker.isSelectable(own, for: target, among: [own, planted], sharedVaults: [shared]))
        XCTAssertTrue(ItemRanker.isSelectable(planted, for: target, among: [own, planted], sharedVaults: [shared]))

        // With both in vaults the person alone writes, the more specific shadows, as it always did.
        let alone = ItemRanker.rank(items: [own, planted], host: target)
        XCTAssertEqual(alone.primary.map(\.item.title), ["Planted"])
        XCTAssertEqual(alone.shadowed.map(\.item.title), ["Own"])
    }

    /// The person's own, more specific item still shadows a shared vault's (their AWS login keeps the household's
    /// Amazon login off the console), and a shared vault's items shadow each other.
    func testOwnItemsAndTheSameVaultStillShadow() throws {
        let shared = UUID()
        let household = item("Household", vault: shared, ServiceScope(host: "amazon.com"))
        let householdAWS = item(
            "Household AWS", vault: shared, ServiceScope(host: "signin.aws.amazon.com", includeSubdomains: false))
        let ownAWS = item(
            "Own AWS", vault: ScenarioFixtures.vault, ServiceScope(host: "aws.amazon.com"))
        let target = try host("signin.aws.amazon.com")

        let ownOverShared = ItemRanker.rank(items: [household, ownAWS], host: target, sharedVaults: [shared])
        XCTAssertEqual(ownOverShared.primary.map(\.item.title), ["Own AWS"])
        XCTAssertEqual(ownOverShared.shadowed.map(\.item.title), ["Household"])

        let withinVault = ItemRanker.rank(items: [household, householdAWS], host: target, sharedVaults: [shared])
        XCTAssertEqual(withinVault.primary.map(\.item.title), ["Household AWS"])
        XCTAssertEqual(withinVault.shadowed.map(\.item.title), ["Household"])

        // All three: the household's own more specific item shadows the household's, the person's own stays.
        let all = ItemRanker.rank(items: [household, householdAWS, ownAWS], host: target, sharedVaults: [shared])
        XCTAssertEqual(all.primary.map(\.item.title), ["Household AWS", "Own AWS"])
        XCTAssertEqual(all.shadowed.map(\.item.title), ["Household"])
    }

    /// Two shared vaults have different members: neither's item shadows the other's.
    func testOneSharedVaultDoesNotShadowAnother() throws {
        let first = UUID()
        let second = UUID()
        let wide = item("Family", vault: first, ServiceScope(host: "amazon.com"))
        let narrow = item("Club", vault: second, ServiceScope(host: "www.amazon.com", includeSubdomains: false))
        let ranking = ItemRanker.rank(
            items: [wide, narrow], host: try host("www.amazon.com"), sharedVaults: [first, second])
        XCTAssertEqual(ranking.primary.map(\.item.title), ["Club", "Family"])
        XCTAssertTrue(ranking.shadowed.isEmpty)
    }

    func testRankingPerformanceWithManyItems() throws {
        var items: [Item] = []
        for i in 0..<5_000 {
            let scopes = [ServiceScope(host: "site\(i).example")]
            items.append(Item(vaultID: ScenarioFixtures.vault, title: "site \(i)", scopes: scopes, fields: []))
        }
        items.append(contentsOf: ScenarioFixtures.all)
        let target = try host("signin.aws.amazon.com")
        measure {
            _ = ItemRanker.rank(items: items, host: target)
        }
    }
}
