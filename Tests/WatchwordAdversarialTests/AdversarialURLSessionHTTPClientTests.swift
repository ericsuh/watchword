#if canImport(Darwin)
    import Foundation
    import Testing
    import WatchwordPlatform

    @testable import WatchwordHygiene

    /// `URLSessionHTTPClient` against a hostile server (docs/02-architecture.md §13.2, §13.8).
    ///
    /// Threat model: **A1 on the network path or at the service** — a compromised or impersonated Pwned Passwords
    /// endpoint (inside TLS: a mis-issued certificate, a CDN, the operator), able to answer any request with any status,
    /// headers and body, at any pace. It must not be able to exhaust memory (an endless or huge body), hold a scan open
    /// (a server that never answers, or drips), or send the request — the prefix and the API key header — to another
    /// host or over plain HTTP by redirecting. Runs on a Mac only (`URLSession`); required there through its `darwin:`
    /// line in `adversarial-suites.txt` (docs/04-test-plan.md §6.6).
    @Suite("Adversarial: Apple adapters: HTTP client", .tags(.adversarial))
    struct AdversarialURLSessionHTTPClientTests {
        static func client(
            deadline: @escaping URLSessionHTTPClient.Deadline = URLSessionHTTPClient.standardDeadline
        ) -> URLSessionHTTPClient {
            URLSessionHTTPClient(limits: .standard, protocolClasses: [StubURLProtocol.self], deadline: deadline)
        }

        /// A deadline that has already passed: the exchange is given up as soon as it has started, whatever the
        /// clock says, so a test of a server that never answers waits for nothing.
        static let passed: URLSessionHTTPClient.Deadline = { _ in }

        static func request(_ prefix: String, maximumResponseBytes: Int = 64 << 10) -> HTTPRequest {
            HTTPRequest(
                url: .pwnedRange(PwnedRangePrefix(prefix)!),
                headers: ["User-Agent": "Watchword/1.0", "Add-Padding": "true"],
                maximumResponseBytes: maximumResponseBytes)
        }

        static func path(_ prefix: String) -> String { "/range/" + prefix }

        /// A1 answers with a body one byte over the limit, and with one of 16 MiB: reading stops at the limit.
        @Test("a body over the limit is refused, however large", arguments: [64 << 10 + 1, 16 << 20])
        func oversized(_ size: Int) async {
            let prefix = String(format: "E%04X", size & 0xFFFF)
            StubURLProtocol.registry.set(
                .respond(status: 200, headers: [:], body: Array(repeating: 0x30, count: size)),
                forPath: Self.path(prefix))
            await #expect(throws: URLSessionHTTPClientError.responseTooLarge) {
                try await Self.client().send(Self.request(prefix))
            }
        }

        /// A1 accepts the connection and never answers, or sends the headers and a few bytes and then nothing: the
        /// client gives up at its deadline rather than holding the scan open, and the exchange is cancelled. The
        /// deadline is injected (already passed), so no test waits on a clock.
        @Test("a server that never answers, or answers and stalls, is given up on", arguments: ["F0001", "F0002"])
        func slow(_ prefix: String) async {
            StubURLProtocol.registry.set(
                prefix == "F0001" ? .stall : .drip(prefix: Array("00000".utf8)), forPath: Self.path(prefix))
            await #expect(throws: URLSessionHTTPClientError.timedOut) {
                try await Self.client(deadline: Self.passed).send(Self.request(prefix))
            }
        }

        /// A limit of infinity, NaN or a negative number (from a corrupted setting) must neither trap the conversion
        /// to nanoseconds nor switch the deadline off.
        @Test("time limits are held to their range, whatever is asked")
        func clampedLimits() {
            for (asked, held) in zip(
                [Double.infinity, -.infinity, .nan, -5, 0, 1e300, 30], [600.0, 0.001, 600, 0.001, 0.001, 600, 30])
            {
                let limits = URLSessionHTTPClient.Limits(idleTimeout: asked, totalTimeout: asked)
                #expect(limits.totalTimeout == held)
                #expect(limits.idleTimeout == held)
                #expect(limits.totalNanoseconds <= 600_000_000_000)
            }
        }

        /// A1 redirects the range request to a host of its choosing, or to plain HTTP on the same host: the request
        /// (with its headers) never reaches the new location, and the client returns the 3xx as the answer, which the
        /// range client reads as a failed check.
        @Test(
            "a redirect is never followed, to another host or to plain HTTP",
            arguments: zip(
                ["C1001", "C1002"],
                ["https://collector.example/range/C1001", "http://api.pwnedpasswords.com/range/C1002"]))
        func redirect(_ prefix: String, _ location: String) async throws {
            StubURLProtocol.registry.set(.redirect(location: location), forPath: Self.path(prefix))
            let target = URL(string: location)!
            do {
                let response = try await Self.client().send(Self.request(prefix))
                #expect((300..<400).contains(response.status))
            } catch {
                // Refusing outright is as good: nothing was sent on.
            }
            let followed = StubURLProtocol.registry.requests(host: target.host(percentEncoded: false)).filter {
                $0.url?.absoluteString == location
            }
            #expect(followed.isEmpty)
        }

        /// The clients check the size again, but the adapter must stop by itself: a body exactly at the limit plus a
        /// trickle afterwards is refused, not buffered.
        @Test("a body that reaches the limit and keeps coming is refused")
        func limitThenMore() async {
            let prefix = "D1001"
            StubURLProtocol.registry.set(.drip(prefix: Array(repeating: 0x31, count: 2048)), forPath: Self.path(prefix))
            await #expect(throws: URLSessionHTTPClientError.responseTooLarge) {
                try await Self.client().send(Self.request(prefix, maximumResponseBytes: 1024))
            }
        }
    }
#endif
