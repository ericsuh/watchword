import XCTest
@testable import WatchwordMatching

final class HostNormalizerTests: XCTestCase {
    func testDomainIdentifierIsLowercasedAndTrailingDotStripped() throws {
        let host = try HostNormalizer.normalize(ServiceIdentifier("WWW.Amazon.COM.", kind: .domain))
        XCTAssertEqual(host, "www.amazon.com")
    }

    func testURLIdentifierExtractsHostIgnoringPathQueryAndPort() throws {
        let host = try HostNormalizer.normalize(
            ServiceIdentifier("https://signin.aws.amazon.com:443/signin?redirect=x#frag", kind: .url)
        )
        XCTAssertEqual(host, "signin.aws.amazon.com")
    }

    func testIPv6LiteralIsAccepted() throws {
        let host = try HostNormalizer.normalize(ServiceIdentifier("http://[::1]:8080/", kind: .url))
        XCTAssertEqual(host, "::1")
    }

    func testEmptyIdentifierIsRejected() {
        XCTAssertThrowsError(try HostNormalizer.normalize(ServiceIdentifier("   ", kind: .domain))) { error in
            XCTAssertEqual(error as? HostNormalizationError, .empty)
        }
    }

    func testDomainWithPathIsRejected() {
        XCTAssertThrowsError(try HostNormalizer.normalize(ServiceIdentifier("amazon.com/login", kind: .domain)))
    }
}
