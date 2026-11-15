import Crypto
import Foundation
import WatchwordMatching
import WatchwordModel

public enum RelyingPartyIDError: Error, Equatable, Sendable {
    /// Not unambiguously a hostname (`HostNormalizer` refused it).
    case notAHostname(HostNormalizationError)
    /// A hostname, but not in the one spelling a relying party ID has: lower-case ASCII (A-labels for an
    /// internationalised name), no trailing dot, no surrounding whitespace. The ID is hashed into every assertion, so a
    /// second spelling would be a second identity.
    case notCanonical(String)
    /// An IP address. WebAuthn relying party IDs are domain names.
    case ipAddress(String)
    /// A public suffix or single-label host: a credential scoped to it would belong to unrelated owners (PRD F11.2).
    case scopeRejected(ScopeValidationError)
}

/// A WebAuthn relying party ID that has passed the same checks as any service scope (PRD F6.2, F11.2;
/// docs/02-architecture.md §9.1).
///
/// The only way to obtain one is `init(_:)`, so the authenticator cannot hash, store or sign for a string that has not
/// been through `HostNormalizer` and `ScopePolicy`. The operating system has already checked the ID against the page's
/// origin; this is the second, independent check, and it is the one a stored credential is compared with.
public struct RelyingPartyID: Hashable, Sendable, CustomStringConvertible {
    /// Lower-case ASCII, exactly as it is hashed.
    public let value: String

    public init(_ raw: String) throws {
        let host: NormalizedHost
        do {
            host = try HostNormalizer.normalize(ServiceIdentifier(raw, kind: .domain))
        } catch let error as HostNormalizationError {
            throw RelyingPartyIDError.notAHostname(error)
        } catch {
            throw RelyingPartyIDError.notAHostname(.invalidHost(raw))
        }
        guard host.value == raw, host.isASCII else { throw RelyingPartyIDError.notCanonical(raw) }
        // An IPv6 literal contains a colon; a dotted name whose last label is all digits is an IPv4 address.
        let lastLabel = host.labels.last ?? ""
        guard !raw.contains(":"), !lastLabel.allSatisfy(\.isNumber) else {
            throw RelyingPartyIDError.ipAddress(raw)
        }
        do {
            try ScopePolicy.validate(ServiceScope(host: raw))
        } catch let error as ScopeValidationError {
            throw RelyingPartyIDError.scopeRejected(error)
        }
        value = raw
    }

    public var description: String { value }

    /// SHA-256 of the ID: the first 32 bytes of authenticator data.
    public var hash: Data {
        Data(SHA256.hash(data: Data(value.utf8)))
    }

    /// The ID as the service identifier the gate matches items against. A passkey is released only by an item that
    /// `AutoFillGate` authorises for its relying party, in addition to the stored ID matching exactly.
    public var serviceIdentifier: ServiceIdentifier {
        ServiceIdentifier(value, kind: .domain)
    }

    /// The scope a new item created for a passkey of this relying party gets. Subdomains are included because that is
    /// what a relying party ID means: the credential is usable from the ID's host and every host below it.
    public var scope: ServiceScope {
        ServiceScope(host: value, includeSubdomains: true)
    }
}
