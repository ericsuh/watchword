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
    /// The ID as `HostNormalizer` gives it, the form every scope and every request is compared in. For an
    /// internationalised ID this can be the Unicode form of `value`'s A-labels (Foundation maps a URL's host as IDNA
    /// does, and a domain normalises as its URL does), so matching uses this and hashing uses `value`.
    public let host: NormalizedHost

    public init(_ raw: String) throws {
        let host: NormalizedHost
        do {
            host = try HostNormalizer.normalize(ServiceIdentifier(raw, kind: .domain))
        } catch let error as HostNormalizationError {
            throw RelyingPartyIDError.notAHostname(error)
        } catch {
            throw RelyingPartyIDError.notAHostname(.invalidHost(raw))
        }
        // The one spelling is judged on the raw bytes: lower-case ASCII letters, digits, hyphens and inner dots. The
        // normalised host may differ from it only by decoding A-labels, so it must keep the same labels' count.
        let canonical =
            raw.utf8.allSatisfy { byte in
                (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte)
                    || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
                    || byte == UInt8(ascii: "-") || byte == UInt8(ascii: ".")
            }
            && !raw.hasPrefix(".") && !raw.hasSuffix(".") && !raw.contains("..")
        let rawLabels = raw.split(separator: ".", omittingEmptySubsequences: false)
        guard canonical, host.labels.count == rawLabels.count, host.isASCII ? host.value == raw : raw.contains("xn--")
        else { throw RelyingPartyIDError.notCanonical(raw) }
        // An IPv6 literal contains a colon; a dotted name whose last label is all digits is an IPv4 address.
        let lastLabel = rawLabels.last.map(String.init) ?? ""
        guard !lastLabel.allSatisfy(\.isNumber) else {
            throw RelyingPartyIDError.ipAddress(raw)
        }
        // Both forms must pass: the embedded suffix list may name an internationalised suffix in either.
        do {
            try ScopePolicy.validate(ScopePolicy.newScope(forHost: raw))
            try ScopePolicy.validate(ScopePolicy.newScope(forHost: host.value))
        } catch let error as ScopeValidationError {
            throw RelyingPartyIDError.scopeRejected(error)
        }
        value = raw
        self.host = host
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
    /// what a relying party ID means: the credential is usable from the ID's host and every host below it. The one
    /// exception is a relying party at a shared-hosting suffix (`ScopePolicy.newScope`, review finding Z63): its
    /// subdomains are other tenants, so the item is scoped to the host alone. The gate matches a passkey against the
    /// relying party ID, never the page, so the passkey itself is unaffected.
    /// It is in the normalised form, so it matches `serviceIdentifier` whatever Foundation does with A-labels.
    public var scope: ServiceScope {
        ScopePolicy.newScope(forHost: host.value)
    }
}
