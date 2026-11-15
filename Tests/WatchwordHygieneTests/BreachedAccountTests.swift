import Foundation
import Testing
import WatchwordTestSupport

@testable import WatchwordHygiene

/// PRD F9.4. The response below is written to the shape the service documents for its breach model; it was not
/// captured from the live service, and tests never call it.
@Suite("Breached-account lookup")
struct BreachedAccountTests {
    static let agent = HygieneUserAgent(version: "1.0")!
    static let key = HIBPAPIKey("0123456789abcdef0123456789abcdef")!
    static let address = EmailAddress("alice@example.com")!

    static let body = """
        [
          {"Name":"Adobe","Title":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04",
           "AddedDate":"2013-12-04T00:00:00Z","PwnCount":152445165,
           "Description":"In October 2013, <a href=\\"https://evil.example\\">153 million</a> Adobe accounts…",
           "DataClasses":["Email addresses","Password hints","Passwords","Usernames"],
           "IsVerified":true,"IsFabricated":false,"IsSensitive":false,"IsRetired":false,"IsSpamList":false,
           "LogoPath":"https://logos.example/Adobe.png"},
          {"Name":"Gawker","Title":"Gawker","Domain":"gawker.com","BreachDate":"2010-12-11","PwnCount":1247574,
           "DataClasses":["Email addresses","Passwords","Usernames"],"IsVerified":true,"IsSensitive":false},
          {"Name":"Stratfor","Title":"Stratfor","Domain":"stratfor.com","BreachDate":"2011-12-24","PwnCount":859777,
           "DataClasses":["Credit cards","Email addresses"],"IsVerified":true,"IsSensitive":true}
        ]
        """

    struct Rig {
        let http = FakeHTTPClient()
        var client: BreachedAccountClient { BreachedAccountClient(http: http, userAgent: agent) }

        func lookup() async throws -> [AccountBreach] {
            try await client.breaches(disclosing: .confirmedByPerson(sending: address), apiKey: key)
        }
    }

    @Test("a lookup sends the address, percent-encoded, to the breached-account endpoint with the person's key")
    func request() async throws {
        let rig = Rig()
        await rig.http.enqueue(status: 200, body: Self.body)
        _ = try await rig.lookup()
        let requests = await rig.http.requests
        #expect(requests.count == 1)
        #expect(
            requests[0].url.absoluteString
                == "https://haveibeenpwned.com/api/v3/breachedaccount/alice%40example.com?truncateResponse=false")
        #expect(
            requests[0].headers
                == ["hibp-api-key": "0123456789abcdef0123456789abcdef", "User-Agent": "Watchword/1.0"])
        #expect(requests[0].method == .get)
    }

    @Test("breaches come back newest first, as bounded plain text, without the service's HTML")
    func parsed() async throws {
        let rig = Rig()
        await rig.http.enqueue(status: 200, body: Self.body)
        let breaches = try await rig.lookup()
        #expect(breaches.map(\.name) == ["Adobe", "Stratfor", "Gawker"])
        #expect(breaches[0].domain == "adobe.com")
        #expect(breaches[0].breachDate == "2013-10-04")
        #expect(breaches[0].accountCount == 152_445_165)
        #expect(breaches[0].dataClasses == ["Email addresses", "Password hints", "Passwords", "Usernames"])
        #expect(breaches[0].isVerified)
        #expect(breaches[1].isSensitive)
        var dumped = ""
        dump(breaches, to: &dumped)
        #expect(!dumped.contains("evil.example"))
        #expect(!dumped.contains("logos.example"))
    }

    @Test("404 means the address is in no breach")
    func notFound() async throws {
        let rig = Rig()
        await rig.http.enqueue(status: 404)
        #expect(try await rig.lookup().isEmpty)
    }

    @Test(
        "other statuses are typed errors",
        arguments: zip(
            [401, 403, 429, 503, 302, 400],
            [
                BreachedAccountError.keyRejected, .forbidden, .rateLimited(retryAfter: 6),
                .serverUnavailable(status: 503, retryAfter: 6), .unexpectedStatus(302), .unexpectedStatus(400),
            ]))
    func statuses(_ status: Int, _ expected: BreachedAccountError) async {
        let rig = Rig()
        await rig.http.enqueue(status: status, headers: ["retry-after": "6", "Location": "https://evil.example/"])
        await #expect(throws: expected) { try await rig.lookup() }
        #expect(await rig.http.requests.count == 1)
    }

    @Test("a transport failure is a typed error")
    func transport() async {
        let rig = Rig()
        await rig.http.enqueue(.failure)
        await #expect(throws: BreachedAccountError.transport) { try await rig.lookup() }
    }

    @Test(
        "bodies that are not a breach list are refused",
        arguments: [
            "", "{}", "null", "[1,2,3]", "[{\"Title\":\"no name\"}]", "<html></html>", "[{\"Name\":5}]",
            String(repeating: "[", count: 100_000),
        ])
    func malformed(_ body: String) async {
        let rig = Rig()
        await rig.http.enqueue(status: 200, body: body)
        await #expect(throws: BreachedAccountError.malformedResponse) { try await rig.lookup() }
    }

    @Test("an oversized body is refused")
    func oversized() async {
        let rig = Rig()
        let body = [UInt8](repeating: UInt8(ascii: " "), count: 2 * 1024 * 1024 + 1)
        await rig.http.enqueue(.response(HTTPResponse(status: 200, body: body)))
        await #expect(throws: BreachedAccountError.responseTooLarge) { try await rig.lookup() }
    }

    @Test("too many breaches is refused; fields of the wrong type are treated as absent; text is cleaned")
    func bounded() throws {
        let many = "[" + (0..<2001).map { "{\"Name\":\"B\($0)\"}" }.joined(separator: ",") + "]"
        #expect(throws: BreachedAccountError.responseTooLarge) { try BreachedAccountClient.parse(Array(many.utf8)) }

        let longName = String(repeating: "n", count: 5000)
        let classes = (0..<500).map { "\"c\($0)\"" }.joined(separator: ",")
        let odd = """
            [{"Name":"  Odd\\u202Ename\\u0000\\n ","Title":7,"Domain":["x"],"BreachDate":"04/10/2013","PwnCount":-3,
              "DataClasses":"Passwords","IsVerified":"yes"},
             {"Name":"Odd\\u202Ename"},
             {"Name":"\\u0000"},
             {"Name":"\(longName)","DataClasses":[\(classes)]}]
            """
        let breaches = try BreachedAccountClient.parse(Array(odd.utf8))
        #expect(breaches.count == 2)
        let first = try #require(breaches.first { $0.name == "Oddname" })
        #expect(first.title == "Oddname")
        #expect(first.domain == nil)
        #expect(first.breachDate == nil)
        #expect(first.accountCount == nil)
        #expect(first.dataClasses.isEmpty)
        #expect(!first.isVerified)
        let long = try #require(breaches.first { $0.name != "Oddname" })
        #expect(long.name.count == 128)
        #expect(long.dataClasses.count == 64)
    }

    @Test(
        "addresses that are not plainly an email address are refused",
        arguments: [
            "", "a", "@", "a@", "@b", "a@b@c", "alice example@example.com", "alice@exam ple.com", "alice@example.com\n",
            "alice@example.com\r\nX-Injected: 1", "alice\u{0}@example.com", "alice\u{202E}@example.com",
            "alice\u{200B}@example.com", String(repeating: "a", count: 250) + "@b.co",
        ])
    func badAddress(_ text: String) {
        #expect(EmailAddress(text) == nil)
    }

    @Test(
        "the address is one path segment whatever it contains",
        arguments: zip(
            [
                "alice@example.com", "a+b/c?d#e%f@example.com", "üser@exämple.de", "o'brien@example.co.uk",
                "../../x@y.z",
            ],
            [
                "alice%40example.com", "a%2Bb%2Fc%3Fd%23e%25f%40example.com", "%C3%BCser%40ex%C3%A4mple.de",
                "o%27brien%40example.co.uk", "..%2F..%2Fx%40y.z",
            ]))
    func encoding(_ text: String, _ expected: String) throws {
        // Expected values from Python's urllib.parse.quote(address, safe="").
        let address = try #require(EmailAddress(text))
        #expect(
            HTTPSURL.breachedAccount(address).path == "/api/v3/breachedaccount/\(expected)?truncateResponse=false")
    }

    @Test(
        "an API key is letters and digits only",
        arguments: [
            "", "short", "0123456789abcdef\r\nX: y", "0123456789abcdef 0123", String(repeating: "a", count: 129),
        ])
    func badKey(_ text: String) {
        #expect(HIBPAPIKey(text) == nil)
    }

    @Test("the key never appears in anything printed")
    func keyRedaction() {
        let request = BreachedAccountClient(http: FakeHTTPClient(), userAgent: Self.agent)
            .request(disclosing: .confirmedByPerson(sending: Self.address), apiKey: Self.key)
        var printed = "\(Self.key) \(String(reflecting: Self.key)) \(request) \(String(reflecting: request))"
        dump(Self.key, to: &printed)
        dump(request, to: &printed)
        #expect(!printed.contains("0123456789abcdef"))
        #expect(!printed.contains("alice"))
        #expect(printed.contains("hibp-api-key"))
    }
}
