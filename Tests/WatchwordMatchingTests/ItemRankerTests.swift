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
