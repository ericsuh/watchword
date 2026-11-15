import Foundation
import WatchwordMatching
import WatchwordModel

/// The opaque string a published identity carries so the extension can find its item again
/// (`ASCredentialIdentity.recordIdentifier`).
///
/// It names an item, and for a passkey or one-time code the field: random UUIDs, lower-case, joined by `/`. Nothing
/// else goes in it, because the operating system stores it in plaintext (docs/02-architecture.md §2, "Also disclosed
/// by design"). When the system hands one back it is a lookup key and nothing more: the item it names still has to
/// pass `AutoFillGate` for the host of the request.
public struct RecordIdentifier: Hashable, Sendable {
    public let itemID: UUID
    public let fieldID: UUID?

    public init(itemID: UUID, fieldID: UUID? = nil) {
        self.itemID = itemID
        self.fieldID = fieldID
    }

    public var text: String {
        let item = itemID.uuidString.lowercased()
        guard let fieldID else { return item }
        return item + "/" + fieldID.uuidString.lowercased()
    }

    /// Strict: exactly the spelling `text` produces, or `nil`.
    public init?(_ text: String) {
        let parts = text.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2, let itemID = RecordIdentifier.uuid(parts[0]) else { return nil }
        if parts.count == 2 {
            guard let fieldID = RecordIdentifier.uuid(parts[1]) else { return nil }
            self.init(itemID: itemID, fieldID: fieldID)
        } else {
            self.init(itemID: itemID)
        }
    }

    private static func uuid(_ text: Substring) -> UUID? {
        guard text.utf8.count == 36, let id = UUID(uuidString: String(text)), id.uuidString.lowercased() == text else {
            return nil
        }
        return id
    }
}

/// One entry of the operating system's credential identity store: what QuickType and the passkey sheet show before
/// the extension runs (PRD F6.1; docs/02-architecture.md §9.1, "Published identities").
///
/// Mirrors `ASPasswordCredentialIdentity`, `ASPasskeyCredentialIdentity` and `ASOneTimeCodeCredentialIdentity`.
/// Everything in one is plaintext outside the app, so each case holds only what the system needs to offer the
/// credential and to ask for it: never a title, a note, a tag or a secret.
public enum CredentialIdentity: Hashable, Sendable {
    case password(PasswordIdentity)
    case passkey(PasskeyIdentity)
    case oneTimeCode(OneTimeCodeIdentity)

    public var recordIdentifier: RecordIdentifier {
        switch self {
        case .password(let identity): return identity.recordIdentifier
        case .passkey(let identity): return identity.recordIdentifier
        case .oneTimeCode(let identity): return identity.recordIdentifier
        }
    }
}

public struct PasswordIdentity: Hashable, Sendable {
    /// A scope host of the item, published as a domain.
    public let host: String
    public let user: String
    public let recordIdentifier: RecordIdentifier
    /// The specificity an exact match on `host` scores (`2 × labels + 1`), so the system can prefer
    /// `signin.aws.amazon.com` to `amazon.com` (PRD F6.6). The extension's own ranking is authoritative regardless.
    public let rank: Int

    public init(host: String, user: String, recordIdentifier: RecordIdentifier, rank: Int) {
        self.host = host
        self.user = user
        self.recordIdentifier = recordIdentifier
        self.rank = rank
    }
}

public struct PasskeyIdentity: Hashable, Sendable {
    public let relyingPartyID: String
    public let userName: String
    public let credentialID: Data
    public let userHandle: Data
    public let recordIdentifier: RecordIdentifier
    public let rank: Int

    public init(
        relyingPartyID: String, userName: String, credentialID: Data, userHandle: Data,
        recordIdentifier: RecordIdentifier, rank: Int
    ) {
        self.relyingPartyID = relyingPartyID
        self.userName = userName
        self.credentialID = credentialID
        self.userHandle = userHandle
        self.recordIdentifier = recordIdentifier
        self.rank = rank
    }
}

public struct OneTimeCodeIdentity: Hashable, Sendable {
    public let host: String
    /// The account the code is for: the item's first login name, or the account in the `otpauth` label.
    public let label: String
    public let recordIdentifier: RecordIdentifier

    public init(host: String, label: String, recordIdentifier: RecordIdentifier) {
        self.host = host
        self.label = label
        self.recordIdentifier = recordIdentifier
    }
}

/// What to remove from and add to the identity store.
public struct IdentityDifference: Hashable, Sendable {
    public var removals: [CredentialIdentity]
    public var additions: [CredentialIdentity]

    public var isEmpty: Bool { removals.isEmpty && additions.isEmpty }

    public init(removals: [CredentialIdentity], additions: [CredentialIdentity]) {
        self.removals = removals
        self.additions = additions
    }
}

/// Decides which identities exist for which items. Pure, and item-local: an item's identities depend on that item
/// alone, which is what makes the incremental difference for one changed item exact.
///
/// Publishes nothing for an item that is in the trash, archived or marked `excludedFromSuggestions` (PRD F6.8), for a
/// scope the scope policy would refuse, for a passkey its own item is not scoped to, or for a passkey its relying
/// party reported unknown (F6.7).
public enum CredentialIdentityPlanner {
    /// A hostile or careless item (a thousand scopes, a hundred usernames) must not flood the store.
    public static let maximumIdentitiesPerItem = 64

    public static func identities(for item: Item) -> [CredentialIdentity] {
        guard !item.isTrashed, !item.archived, !item.excludedFromSuggestions else { return [] }
        var result: [CredentialIdentity] = []
        var seen = Set<CredentialIdentity>()
        func add(_ identity: CredentialIdentity) {
            guard result.count < maximumIdentitiesPerItem, seen.insert(identity).inserted else { return }
            result.append(identity)
        }

        // Passkeys first: there is one per credential, and the cap must not starve them.
        for field in item.fields where field.kind == .passkey && field.reportedUnknownAt == nil {
            guard let credential = try? field.passkeyCredential(),
                let relyingParty = try? RelyingPartyID(credential.relyingPartyID),
                let host = try? HostNormalizer.normalize(relyingParty.serviceIdentifier),
                item.scopes.contains(where: { ScopeMatcher.match($0, host: host) != nil })
            else { continue }
            add(
                .passkey(
                    PasskeyIdentity(
                        relyingPartyID: relyingParty.value, userName: credential.userName,
                        credentialID: credential.credentialID, userHandle: credential.userHandle,
                        recordIdentifier: RecordIdentifier(itemID: item.id, fieldID: field.id),
                        rank: 2 * host.labelCount + 1)))
        }

        let hosts = publishableHosts(of: item)
        let users = uniqued(item.loginNames.filter { !$0.isEmpty })
        if item.field(.password) != nil {
            for host in hosts {
                for user in users {
                    add(
                        .password(
                            PasswordIdentity(
                                host: host.value, user: user, recordIdentifier: RecordIdentifier(itemID: item.id),
                                rank: 2 * host.labelCount + 1)))
                }
            }
        }
        for field in item.fields where field.kind == .totp {
            guard let parameters = try? field.otpParameters() else { continue }
            guard let label = users.first ?? parameters.account, !label.isEmpty else { continue }
            for host in hosts {
                add(
                    .oneTimeCode(
                        OneTimeCodeIdentity(
                            host: host.value, label: label,
                            recordIdentifier: RecordIdentifier(itemID: item.id, fieldID: field.id))))
            }
        }
        return result
    }

    public static func identities(for items: [Item]) -> [CredentialIdentity] {
        items.flatMap { identities(for: $0) }
    }

    /// What changes in the store when `old` becomes `new`; `nil` stands for an item that does not exist (created or
    /// deleted). Removals and additions are disjoint.
    public static func difference(from old: Item?, to new: Item?) -> IdentityDifference {
        let before = old.map { identities(for: $0) } ?? []
        let after = new.map { identities(for: $0) } ?? []
        let beforeSet = Set(before)
        let afterSet = Set(after)
        return IdentityDifference(
            removals: before.filter { !afterSet.contains($0) }, additions: after.filter { !beforeSet.contains($0) })
    }

    /// The item's scope hosts that are hostnames the scope policy accepts, in scope order, each once.
    private static func publishableHosts(of item: Item) -> [NormalizedHost] {
        var hosts: [NormalizedHost] = []
        for scope in item.scopes where ScopePolicy.isAcceptable(scope) {
            guard let host = try? HostNormalizer.normalize(ServiceIdentifier(scope.host, kind: .domain)),
                host.value == scope.host, !hosts.contains(host)
            else { continue }
            hosts.append(host)
        }
        return hosts
    }

    private static func uniqued(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }
}

/// Whether the system store accepts identities, and how.
public struct CredentialIdentityStoreState: Hashable, Sendable {
    /// The person has enabled Watchword as an AutoFill provider.
    public var isEnabled: Bool
    public var supportsIncrementalUpdates: Bool

    public init(isEnabled: Bool, supportsIncrementalUpdates: Bool) {
        self.isEnabled = isEnabled
        self.supportsIncrementalUpdates = supportsIncrementalUpdates
    }
}

/// The identity store port. Production: an adapter over `ASCredentialIdentityStore`, in the app and the extension.
/// Tests: `FakeCredentialIdentityPublisher` in `WatchwordTestSupport`.
public protocol CredentialIdentityPublisher: Sendable {
    func state() async -> CredentialIdentityStoreState
    /// Replaces everything this app has published.
    func replaceAll(with identities: [CredentialIdentity]) async throws
    /// Removes, then adds.
    func apply(_ difference: IdentityDifference) async throws
}

/// Publishing itself: the planner's output through the port.
public enum CredentialIdentityPublishing {
    /// Publishes exactly the identities of `items`, replacing whatever was there. Run after every unlock, and after
    /// sync changes items. Does nothing while the provider is not enabled.
    @discardableResult
    public static func publishAll(
        _ items: [Item], to publisher: any CredentialIdentityPublisher
    ) async throws -> [CredentialIdentity] {
        guard await publisher.state().isEnabled else { return [] }
        let identities = CredentialIdentityPlanner.identities(for: items)
        try await publisher.replaceAll(with: identities)
        return identities
    }

    /// Publishes one item's change. A store without incremental updates needs the whole list, so `all` supplies the
    /// items as they are after the change.
    @discardableResult
    public static func publishChange(
        from old: Item?, to new: Item?, all: @Sendable () async throws -> [Item],
        to publisher: any CredentialIdentityPublisher
    ) async throws -> IdentityDifference {
        let difference = CredentialIdentityPlanner.difference(from: old, to: new)
        let state = await publisher.state()
        guard state.isEnabled, !difference.isEmpty else { return difference }
        if state.supportsIncrementalUpdates {
            try await publisher.apply(difference)
        } else {
            try await publisher.replaceAll(with: CredentialIdentityPlanner.identities(for: try await all()))
        }
        return difference
    }
}
