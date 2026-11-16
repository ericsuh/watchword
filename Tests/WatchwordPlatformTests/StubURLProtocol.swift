#if canImport(Darwin)
    import Foundation

    /// A URL-loading stub standing in for the network, so `URLSessionHTTPClient` is exercised through a real
    /// `URLSession` with no server: each test claims a path of its own and says how the "server" answers it, and every
    /// request that reaches the stub is recorded. (A copy lives in each test target that needs one; test code only.)
    final class StubURLProtocol: URLProtocol {
        enum Behaviour: Sendable {
            case respond(status: Int, headers: [String: String], body: [UInt8])
            /// A 302 to `location`; a client that follows it makes a request the registry records.
            case redirect(location: String)
            /// Never answers.
            case stall
            /// Sends the headers and `prefix` of the body, then nothing more.
            case drip(prefix: [UInt8])
        }

        final class Registry: @unchecked Sendable {
            private let lock = NSLock()
            private var behaviours: [String: Behaviour] = [:]
            private var requests: [URLRequest] = []

            func set(_ behaviour: Behaviour, forPath path: String) {
                lock.withLock { behaviours[path] = behaviour }
            }

            func behaviour(forPath path: String) -> Behaviour? {
                lock.withLock { behaviours[path] }
            }

            func record(_ request: URLRequest) {
                lock.withLock { requests.append(request) }
            }

            /// Every request seen whose path is `path` or whose host is `host`.
            func requests(path: String? = nil, host: String? = nil) -> [URLRequest] {
                lock.withLock {
                    requests.filter {
                        (path != nil && $0.url?.path == path)
                            || (host != nil && $0.url?.host(percentEncoded: false) == host)
                    }
                }
            }
        }

        static let registry = Registry()

        override class func canInit(with request: URLRequest) -> Bool { true }

        override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

        override func startLoading() {
            Self.registry.record(request)
            guard let url = request.url else { return }
            switch Self.registry.behaviour(forPath: url.path) {
            case .respond(let status, let headers, let body)?:
                let response = HTTPURLResponse(
                    url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
                client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
                client?.urlProtocol(self, didLoad: Data(body))
                client?.urlProtocolDidFinishLoading(self)
            case .redirect(let location)?:
                let response = HTTPURLResponse(
                    url: url, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: ["Location": location])!
                client?.urlProtocol(
                    self, wasRedirectedTo: URLRequest(url: URL(string: location)!), redirectResponse: response)
                // Refused, the loading system goes on with the redirect response itself, as an HTTP stack would.
                client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
                client?.urlProtocolDidFinishLoading(self)
            case .stall?:
                break
            case .drip(let prefix)?:
                let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [:])!
                client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
                client?.urlProtocol(self, didLoad: Data(prefix))
            case nil:
                client?.urlProtocol(self, didFailWithError: URLError(.cannotFindHost))
            }
        }

        override func stopLoading() {}
    }
#endif
