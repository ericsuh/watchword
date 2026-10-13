import WatchwordModel
import XCTest
@testable import WatchwordMatching

/// End-to-end matching for PRD scenario S1 (Amazon retail vs AWS root, same email).
final class ItemRankerTests: XCTestCase {
    func testRetailSiteOffersOnlyRetailAccount() {
        let ranking = ItemRanker.rank(items: ScenarioFixtures.all, host: "www.amazon.com")
        XCTAssertEqual(ranking.primary.map(\.item.title), ["Amazon"])
        XCTAssertTrue(ranking.shadowed.isEmpty, "AWS must not appear at all on the retail site")
    }

    func testAWSSignInOffersAWSFirstAndShadowsRetail() {
        let ranking = ItemRanker.rank(items: ScenarioFixtures.all, host: "signin.aws.amazon.com")
        XCTAssertEqual(ranking.primary.map(\.item.title), ["AWS root"])
        XCTAssertEqual(ranking.shadowed.map(\.item.title), ["Amazon"])
        XCTAssertTrue(ranking.shadowed.allSatisfy(\.isShadowed))
    }

    func testAWSConsoleSubdomainStillPrefersAWS() {
        let ranking = ItemRanker.rank(items: ScenarioFixtures.all, host: "us-east-1.console.aws.amazon.com")
        XCTAssertEqual(ranking.primary.map(\.item.title), ["AWS root"])
    }

    func testTOTPReturnedForEachSiteBelongsToTheRightItem() {
        let items = ScenarioFixtures.all
        let aws = ItemRanker.rank(items: items, host: "signin.aws.amazon.com").primary.first?.item
        let retail = ItemRanker.rank(items: items, host: "amazon.com").primary.first?.item
        XCTAssertTrue(aws?.field(.totp)?.value.contains("secret=AWSROOT") ?? false)
        XCTAssertTrue(retail?.field(.totp)?.value.contains("secret=RETAIL") ?? false)
    }

    func testExcludedHostRemovesRetailFromAWSEntirely() {
        var retail = ScenarioFixtures.amazonRetail
        retail.scopes = [
            ServiceScope(host: "amazon.com", includeSubdomains: true, excludedHosts: ["aws.amazon.com"])
        ]
        let ranking = ItemRanker.rank(items: [retail, ScenarioFixtures.awsRoot], host: "signin.aws.amazon.com")
        XCTAssertEqual(ranking.primary.map(\.item.title), ["AWS root"])
        XCTAssertTrue(ranking.shadowed.isEmpty)
    }

    func testUnrelatedHostMatchesNothing() {
        let ranking = ItemRanker.rank(items: ScenarioFixtures.all, host: "amazon.co.uk")
        XCTAssertTrue(ranking.isEmpty)
    }

    func testIsSelectableRejectsShadowedItem() {
        let items = ScenarioFixtures.all
        let host = "signin.aws.amazon.com"
        XCTAssertFalse(ItemRanker.isSelectable(ScenarioFixtures.amazonRetail, for: host, among: items))
        XCTAssertTrue(ItemRanker.isSelectable(ScenarioFixtures.awsRoot, for: host, among: items))
    }

    func testRankingFromOSIdentifierFailsClosedOnBadInput() {
        let identifier = ServiceIdentifier("ftp://amazon.com", kind: .url)
        let (ranking, error) = ItemRanker.rank(items: ScenarioFixtures.all, identifier: identifier)
        XCTAssertTrue(ranking.isEmpty)
        XCTAssertEqual(error, .unsupportedScheme("ftp"))
    }

    func testRankingPerformanceWithManyItems() {
        var items: [Item] = []
        for i in 0..<5_000 {
            let scopes = [ServiceScope(host: "site\(i).example")]
            items.append(Item(vaultID: ScenarioFixtures.vault, title: "site \(i)", scopes: scopes, fields: []))
        }
        items.append(contentsOf: ScenarioFixtures.all)
        measure {
            _ = ItemRanker.rank(items: items, host: "signin.aws.amazon.com")
        }
    }
}
