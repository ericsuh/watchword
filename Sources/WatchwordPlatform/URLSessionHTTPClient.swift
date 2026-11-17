#if canImport(Darwin)
    import Foundation
    import Security
    import WatchwordHygiene

    /// Why a request did not complete. The hygiene clients treat every thrown error alike, as "try again later"
    /// (`HTTPClient`), so these exist for tests and for the reason a developer reads; none is ever shown with a URL.
    public enum URLSessionHTTPClientError: Error, Equatable, Sendable {
        /// The request's URL is not `https` on the host it names (cannot happen through `HTTPSURL`; checked anyway).
        case invalidRequest
        /// The decoded body passed `HTTPRequest.maximumResponseBytes`; reading stopped there.
        case responseTooLarge
        /// The whole exchange took longer than `Limits.totalTimeout`.
        case timedOut
        /// The answer was not an HTTP response from the host asked, over `https`.
        case unexpectedResponse
    }

    /// The production `HTTPClient` (docs/02-architecture.md §13.8): `URLSession`, configured to be the narrowest
    /// client that can reach the two hosts of `HygieneHost`, keeping each promise the port's documentation lists.
    ///
    /// - **Ephemeral**, with no cookie storage (and cookies neither sent nor accepted), no credential storage and no
    ///   cache, so nothing about one request is kept for the next or written to disk.
    /// - **No redirects**: the session's and the task's delegate refuse every one, so the 3xx response is returned as it
    ///   is and nothing, headers included, goes to a host the module did not choose. A response from any URL but the one
    ///   asked is refused.
    /// - **TLS only**: the URL must be `https` on the request's host, with the system's own certificate validation
    ///   (no challenge handler) and TLS 1.2 at least.
    /// - **Bounded**: the decoded body is counted as it arrives and reading stops one byte past
    ///   `maximumResponseBytes` (URLSession decodes `Content-Encoding`, so a compressed response cannot expand past it);
    ///   an idle timeout, a resource timeout and an overall deadline of its own bound the time a server can hold a scan.
    /// - **Minimal headers**: exactly the request's, plus a `User-Agent` of `Watchword` if it names none, and
    ///   `Accept-Language: *` in place of the device's languages, which URLSession would otherwise add (it cannot be
    ///   told to send none). URLSession still adds `Accept` and `Accept-Encoding`.
    /// - **Quiet**: nothing is logged, and errors carry no URL.
    ///
    /// A proxy the system or a device-management profile configures is used, as for any app: it sees the host, and,
    /// if it is trusted to intercept TLS, the five-character prefix (§13.8). The decompression limit is enforced on the
    /// decoded bytes URLSession hands over, but no test shows it against a compressed body: a URL-loading stub's bytes
    /// are not decoded by URLSession's HTTP stack.
    ///
    /// A thin adapter on purpose: what is asked, how often, and what an answer means are `WatchwordHygiene`'s, tested
    /// on Linux against `FakeHTTPClient`; this file only moves bytes. The A1 cases (oversized, slow, redirecting
    /// servers) are the adversarial suite "Apple adapters: HTTP client", run on a Mac.
    public final class URLSessionHTTPClient: HTTPClient, Sendable {
        public struct Limits: Sendable, Hashable {
            /// Every time limit is held to this range: a limit of zero, a negative one, NaN or infinity must neither
            /// trap converting it nor switch the limit off.
            public static let range: ClosedRange<TimeInterval> = 0.001...600

            /// The longest a response may go without a byte (`timeoutIntervalForRequest`).
            public var idleTimeout: TimeInterval
            /// The longest one exchange may take, connection to last byte.
            public var totalTimeout: TimeInterval

            public init(idleTimeout: TimeInterval = 15, totalTimeout: TimeInterval = 30) {
                self.idleTimeout = Self.clamped(idleTimeout)
                self.totalTimeout = Self.clamped(totalTimeout)
            }

            /// `seconds` within `range`; NaN is the upper bound.
            public static func clamped(_ seconds: TimeInterval) -> TimeInterval {
                guard !seconds.isNaN else { return range.upperBound }
                return min(max(seconds, range.lowerBound), range.upperBound)
            }

            /// `totalTimeout` in nanoseconds, which cannot overflow: at most 600 s.
            public var totalNanoseconds: UInt64 {
                UInt64(Self.clamped(totalTimeout) * 1_000_000_000)
            }

            public static let standard = Limits()
        }

        /// Returns when the exchange's overall time is up. The default sleeps for `Limits.totalTimeout`; tests pass one
        /// that returns when they say.
        public typealias Deadline = @Sendable (Limits) async -> Void

        public static let standardDeadline: Deadline = { limits in
            try? await Task.sleep(nanoseconds: limits.totalNanoseconds)
        }

        public let limits: Limits
        let session: URLSession
        private let redirects: RedirectRefusal
        private let deadline: Deadline

        public convenience init(limits: Limits = .standard) {
            self.init(limits: limits, protocolClasses: [])
        }

        /// `protocolClasses` puts URL-loading stubs in front of the network, for tests: they see exactly what would be
        /// sent, and answer as a hostile server would. `deadline` replaces the overall timer.
        package init(
            limits: Limits, protocolClasses: [AnyClass],
            deadline: @escaping Deadline = URLSessionHTTPClient.standardDeadline
        ) {
            self.limits = limits
            self.deadline = deadline
            redirects = RedirectRefusal()
            session = URLSession(
                configuration: Self.configuration(limits: limits, protocolClasses: protocolClasses),
                delegate: redirects, delegateQueue: nil)
        }

        deinit {
            // A session holds its delegate until invalidated.
            session.invalidateAndCancel()
        }

        package static func configuration(limits: Limits, protocolClasses: [AnyClass]) -> URLSessionConfiguration {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.httpCookieStorage = nil
            configuration.httpCookieAcceptPolicy = .never
            configuration.httpShouldSetCookies = false
            configuration.urlCredentialStorage = nil
            configuration.urlCache = nil
            configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            configuration.timeoutIntervalForRequest = Limits.clamped(limits.idleTimeout)
            configuration.timeoutIntervalForResource = Limits.clamped(limits.totalTimeout)
            configuration.waitsForConnectivity = false
            configuration.httpShouldUsePipelining = false
            configuration.httpMaximumConnectionsPerHost = 2
            configuration.tlsMinimumSupportedProtocolVersion = .TLSv12
            if !protocolClasses.isEmpty {
                configuration.protocolClasses = protocolClasses + (configuration.protocolClasses ?? [])
            }
            return configuration
        }

        public func send(_ request: HTTPRequest) async throws -> HTTPResponse {
            let urlRequest = try Self.urlRequest(for: request, timeout: Limits.clamped(limits.idleTimeout))
            let host = request.url.host.name
            let maximum = max(0, request.maximumResponseBytes)
            let (deadline, limits) = (deadline, limits)
            return try await withThrowingTaskGroup(of: HTTPResponse.self) { group in
                group.addTask { try await self.exchange(urlRequest, host: host, maximumBytes: maximum) }
                group.addTask {
                    await deadline(limits)
                    try Task.checkCancellation()
                    throw URLSessionHTTPClientError.timedOut
                }
                defer { group.cancelAll() }
                guard let first = try await group.next() else { throw URLSessionHTTPClientError.timedOut }
                return first
            }
        }

        /// The request exactly as given: its method, its URL and its headers, no cookies, no cache.
        package static func urlRequest(for request: HTTPRequest, timeout: TimeInterval) throws -> URLRequest {
            guard let url = URL(string: request.url.absoluteString), url.scheme == "https",
                url.host(percentEncoded: false) == request.url.host.name, url.port == nil
            else { throw URLSessionHTTPClientError.invalidRequest }
            var urlRequest = URLRequest(
                url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: timeout)
            urlRequest.httpMethod = request.method.rawValue
            urlRequest.httpShouldHandleCookies = false
            urlRequest.httpShouldUsePipelining = false
            for (name, value) in request.headers.fields {
                urlRequest.setValue(value, forHTTPHeaderField: name)
            }
            if urlRequest.value(forHTTPHeaderField: "User-Agent") == nil {
                urlRequest.setValue("Watchword", forHTTPHeaderField: "User-Agent")
            }
            if urlRequest.value(forHTTPHeaderField: "Accept-Language") == nil {
                urlRequest.setValue("*", forHTTPHeaderField: "Accept-Language")
            }
            return urlRequest
        }

        private func exchange(_ request: URLRequest, host: String, maximumBytes: Int) async throws -> HTTPResponse {
            let (bytes, response) = try await session.bytes(for: request, delegate: redirects)
            guard let http = response as? HTTPURLResponse, let url = http.url, url.scheme == "https",
                url.host(percentEncoded: false) == host, url.path == request.url?.path
            else {
                bytes.task.cancel()
                throw URLSessionHTTPClientError.unexpectedResponse
            }
            var body: [UInt8] = []
            body.reserveCapacity(min(maximumBytes, 64 << 10))
            for try await byte in bytes {
                guard body.count < maximumBytes else {
                    bytes.task.cancel()
                    throw URLSessionHTTPClientError.responseTooLarge
                }
                body.append(byte)
            }
            return HTTPResponse(status: http.statusCode, headers: Self.headers(of: http), body: body)
        }

        static func headers(of response: HTTPURLResponse) -> [String: String] {
            var headers: [String: String] = [:]
            for (key, value) in response.allHeaderFields {
                if let name = key as? String, let value = value as? String { headers[name] = value }
            }
            return headers
        }
    }

    /// Refuses every redirect, as the session's delegate and as each task's: the 3xx response is the answer.
    final class RedirectRefusal: NSObject, URLSessionTaskDelegate, Sendable {
        func urlSession(
            _ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
            newRequest request: URLRequest
        ) async -> URLRequest? {
            nil
        }
    }
#endif
