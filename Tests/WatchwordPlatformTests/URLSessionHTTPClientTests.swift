#if canImport(Darwin)
    import Foundation
    import Security
    import Testing
    import WatchwordPlatform

    @testable import WatchwordHygiene

    /// Shared by the HTTP client's suites: requests on prefixes no other test uses, through a client whose only
    /// "network" is `StubURLProtocol`.
    enum HTTPFixtures {
        static func client(limits: URLSessionHTTPClient.Limits = .standard) -> URLSessionHTTPClient {
            URLSessionHTTPClient(limits: limits, protocolClasses: [StubURLProtocol.self])
        }

        /// A range request for `prefix` (five hex digits), as `PwnedPasswordsClient` makes it.
        static func rangeRequest(_ prefix: String, maximumResponseBytes: Int = 1 << 20) -> HTTPRequest {
            HTTPRequest(
                url: .pwnedRange(PwnedRangePrefix(prefix)!),
                headers: ["User-Agent": "Watchword/1.0", "Add-Padding": "true"],
                maximumResponseBytes: maximumResponseBytes)
        }

        static func path(_ prefix: String) -> String { "/range/" + prefix.uppercased() }
    }

    /// `URLSessionHTTPClient` keeps the `HTTPClient` port's promises (docs/02-architecture.md §13.8): exactly the
    /// request given, an ephemeral session with nothing stored, the answer as it came. Hostile servers are the
    /// adversarial suite's ("Apple adapters: HTTP client").
    @Suite("URLSession HTTP client")
    struct URLSessionHTTPClientTests {
        @Test("sends exactly the method, URL and headers given, and returns status, headers and body as received")
        func exchange() async throws {
            let prefix = "A0001"
            StubURLProtocol.registry.set(
                .respond(status: 200, headers: ["Content-Type": "text/plain"], body: Array("ABC:1\r\n".utf8)),
                forPath: HTTPFixtures.path(prefix))
            let response = try await HTTPFixtures.client().send(HTTPFixtures.rangeRequest(prefix))
            #expect(response.status == 200)
            #expect(response.body == Array("ABC:1\r\n".utf8))
            #expect(response.header("content-type") == "text/plain")

            let sent = try #require(StubURLProtocol.registry.requests(path: HTTPFixtures.path(prefix)).first)
            #expect(sent.httpMethod == "GET")
            #expect(sent.url?.absoluteString == "https://api.pwnedpasswords.com/range/A0001")
            #expect(sent.value(forHTTPHeaderField: "User-Agent") == "Watchword/1.0")
            #expect(sent.value(forHTTPHeaderField: "Add-Padding") == "true")
            #expect(sent.value(forHTTPHeaderField: "Cookie") == nil)
            #expect(sent.value(forHTTPHeaderField: "Authorization") == nil)
            #expect(sent.httpShouldHandleCookies == false)
            #expect(sent.cachePolicy == .reloadIgnoringLocalAndRemoteCacheData)
        }

        @Test("error statuses are answers, returned as they are", arguments: [404, 429, 500, 503])
        func statuses(_ status: Int) async throws {
            let prefix = String(format: "B%04d", status)
            StubURLProtocol.registry.set(
                .respond(status: status, headers: ["Retry-After": "7"], body: []), forPath: HTTPFixtures.path(prefix))
            let response = try await HTTPFixtures.client().send(HTTPFixtures.rangeRequest(prefix))
            #expect(response.status == status)
            #expect(response.header("Retry-After") == "7")
        }

        @Test("a body of exactly the limit is accepted")
        func exactlyAtLimit() async throws {
            let prefix = "C0001"
            StubURLProtocol.registry.set(
                .respond(status: 200, headers: [:], body: Array(repeating: 0x41, count: 4096)),
                forPath: HTTPFixtures.path(prefix))
            let response = try await HTTPFixtures.client().send(
                HTTPFixtures.rangeRequest(prefix, maximumResponseBytes: 4096))
            #expect(response.body.count == 4096)
        }

        @Test("the session stores nothing: ephemeral, no cookies, credentials or cache, TLS 1.2 at least, bounded")
        func configuration() {
            let limits = URLSessionHTTPClient.Limits(idleTimeout: 9, totalTimeout: 21)
            let configuration = URLSessionHTTPClient.configuration(limits: limits, protocolClasses: [])
            #expect(configuration.httpCookieStorage == nil)
            #expect(configuration.httpCookieAcceptPolicy == .never)
            #expect(configuration.httpShouldSetCookies == false)
            #expect(configuration.urlCredentialStorage == nil)
            #expect(configuration.urlCache == nil)
            #expect(configuration.requestCachePolicy == .reloadIgnoringLocalAndRemoteCacheData)
            #expect(configuration.timeoutIntervalForRequest == 9)
            #expect(configuration.timeoutIntervalForResource == 21)
            #expect(configuration.tlsMinimumSupportedProtocolVersion.rawValue >= tls_protocol_version_t.TLSv12.rawValue)
            #expect(configuration.waitsForConnectivity == false)
        }

        @Test("the request carries the URL the module built and nothing it did not")
        func requestShape() throws {
            let request = try URLSessionHTTPClient.urlRequest(
                for: HTTPFixtures.rangeRequest("D0001"), timeout: 5)
            #expect(request.url?.scheme == "https")
            #expect(request.url?.host(percentEncoded: false) == "api.pwnedpasswords.com")
            #expect(request.allHTTPHeaderFields?.keys.sorted() == ["Add-Padding", "User-Agent"])
            #expect(request.httpBody == nil)
            #expect(request.timeoutInterval == 5)
        }
    }
#endif
