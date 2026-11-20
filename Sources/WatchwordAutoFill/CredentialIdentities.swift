import Foundation
import WatchwordMatching
import WatchwordModel

/// The opaque string a published identity carries so the extension can find its item again
/// (`ASCredentialIdentity.recordIdentifier`).
///
/// It names an item, and for a passkey or one-time code the field: random UUIDs, lower-case, joined by `/`. Nothing
/// else goes in it, because the operating system stores it in plaintext (docs/02-architecture.md §2, "Also disclosed
/// by design"). When the system hands one back it is a lookup key and nothing more: a passkey's item still has to
/// pass `AutoFillGate` for the relying party of the request, and a password or code identity still has to be one
/// `CredentialIdentityPlanner` would publish for the vault as it is now.
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
    /// A scope host of the item, published as a domain. Always the root of its site, with a scope that covers the
    /// whole site (see `CredentialIdentityPlanner`).
    public let host: String
    public let user: String
    public let recordIdentifier: RecordIdentifier
    /// The specificity an exact match on `host` scores (`2 × labels + 1`).
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

/// Decides which identities exist for which items. Pure.
///
/// **An identity is published only if Watchword would answer it wherever the system may offer it.** For a password
/// or a one-time code the system hands the stored identity back on a tap and does not say which page or app the
/// person is on (`provideCredentialWithoutUserInteraction(for:)`), and which pages a stored identity is offered on
/// is the system's own matching, which is not documented and is at least as wide as the registrable domain as far
/// as anyone has observed. So on that path `AutoFillGate` cannot be asked about the page, and the question it would
/// answer has to be settled here, for every page the system might pick. An item gets a password or code identity
/// for a scope host only when
///
/// - the scope covers the whole site: its host is the site's root (`PublicSuffix.broadestSite`, which errs wide),
///   subdomains are included and no host is excluded, so there is no page of the site the item is not for;
/// - no other item outside the trash holds a scope below that host, so there is no page of the site where another
///   account is more specific and this one would be an "other account" (PRD F6.6, scenario S1); and
/// - no other item scoped to that same host shares the name the suggestion would show, so two accounts that tie
///   are told apart by what the person tapped (F11.5); and no item of another trust class (one of the two in a
///   shared vault, the other in another vault) is scoped to that host at all, since a name can differ by bytes and
///   not to the eye, and the system's rows do not name a vault (review finding Z70).
///
/// Everything else (the Amazon retail login once an AWS item exists, a login saved for one exact host) is reached
/// through the extension's list, which is told the page and asks the gate. A passkey identity is published only
/// if the gate would release the passkey for its relying party, which every passkey request names, and, for an item
/// of a shared vault, only if no item of another vault is among what the gate offers there (Z70).
///
/// Nothing is published for an item that is in the trash, archived or marked `excludedFromSuggestions` (F6.8), for
/// an item whose ID another item shares, for a scope the scope policy would refuse, or for a passkey its relying
/// party reported unknown (F6.7).
///
/// Because of the second and third rules an item's identities depend on the other items, so the difference for one
/// changed item is taken between two whole sets.
public enum CredentialIdentityPlanner {
    /// A hostile or careless item (a thousand scopes, a hundred usernames) must not flood the store.
    public static let maximumIdentitiesPerItem = 64

    /// The identities to publish for a vault holding exactly `items`, every one of them taken to be in a vault only
    /// this account writes. For tests only, and internal for that reason (review finding Z78): given a session's
    /// items it would publish a shared vault's as the person's own. What a session returns is published through
    /// `identities(for: CredentialSnapshot)`, which knows which vaults are shared.
    static func identities(for items: [Item]) -> [CredentialIdentity] {
        let snapshot = VaultSnapshot(ownItems: items)
        return snapshot.all.flatMap { identities(for: $0, in: snapshot) }
    }

    /// The identities to publish for what the vault returned.
    public static func identities(for contents: CredentialSnapshot) -> [CredentialIdentity] {
        identities(in: VaultSnapshot(contents))
    }

    static func identities(in snapshot: VaultSnapshot) -> [CredentialIdentity] {
        snapshot.all.flatMap { identities(for: $0, in: snapshot) }
    }

    /// What changes in the store when the vault's items go from `old` to `new`. Removals and additions are
    /// disjoint. As `identities(for: [Item])`: the items are taken to be the person's own, so tests only (Z78).
    static func difference(from old: [Item], to new: [Item]) -> IdentityDifference {
        difference(from: identities(for: old), to: identities(for: new))
    }

    static func difference(from before: [CredentialIdentity], to after: [CredentialIdentity]) -> IdentityDifference {
        let beforeSet = Set(before)
        let afterSet = Set(after)
        return IdentityDifference(
            removals: before.filter { !afterSet.contains($0) }, additions: after.filter { !beforeSet.contains($0) })
    }

    /// The identities of one item among the others of `snapshot`. Also what the requests made without the person
    /// check an identity against: one that is not in this list is not answered.
    static func identities(for item: Item, in snapshot: VaultSnapshot) -> [CredentialIdentity] {
        guard snapshot.isInUse(item) else { return [] }
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
                case .success = ReleaseGate.authorize(
                    itemID: item.id, for: [relyingParty.serviceIdentifier], in: snapshot),
                !snapshot.meetsAnotherTrustClass(item, on: host)
            else { continue }
            add(
                .passkey(
                    PasskeyIdentity(
                        relyingPartyID: relyingParty.value, userName: credential.userName,
                        credentialID: credential.credentialID, userHandle: credential.userHandle,
                        recordIdentifier: RecordIdentifier(itemID: item.id, fieldID: field.id),
                        rank: 2 * host.labelCount + 1)))
        }

        let sites = wholeSites(of: item, in: snapshot)
        let users = uniqued(item.loginNames.filter { !$0.isEmpty })
        // The password a fill would return: the item's first, and only if there is something in it.
        if let password = item.field(.password), !password.value.isEmpty {
            for site in sites {
                for user in users where !site.takenNames.contains(user) {
                    add(
                        .password(
                            PasswordIdentity(
                                host: site.host.value, user: user, recordIdentifier: RecordIdentifier(itemID: item.id),
                                rank: 2 * site.host.labelCount + 1)))
                }
            }
        }
        // A code identity shows one name. Two code fields in one item would be two suggestions nobody could tell
        // apart, so only an item with a single code field has its code suggested.
        let codes = item.fields.filter { $0.kind == .totp }
        if codes.count == 1, let parameters = try? codes[0].otpParameters(),
            let label = users.first ?? parameters.account, !label.isEmpty
        {
            for site in sites where !site.takenNames.contains(label) {
                add(
                    .oneTimeCode(
                        OneTimeCodeIdentity(
                            host: site.host.value, label: label,
                            recordIdentifier: RecordIdentifier(itemID: item.id, fieldID: codes[0].id))))
            }
        }
        return result
    }

    /// A site the item is for in its entirety and where no other item is more specific anywhere, with the names
    /// the other accounts on that site would be suggested under.
    private struct WholeSite {
        var host: NormalizedHost
        var takenNames: Set<String>
    }

    /// "No other item" means no item of any vault. An item of a shared vault never shadows the person's own on a
    /// page (`ItemRanker`), but it does stand beside it there, and that is a choice for the person, which a tap that
    /// names no page cannot be: so a member of a shared vault can take a site's suggestion out of the keyboard by
    /// saving something below it, and can never direct one. For the same reason an item of another trust class
    /// scoped to the very host withdraws the site for both, whatever names they show (Z70): the system's rows carry
    /// no vault, and a name can differ by bytes and not to the eye. An item of a shared vault must also pass the
    /// gate for its own host, which refuses one that resembles a site saved in another vault.
    private static func wholeSites(of item: Item, in snapshot: VaultSnapshot) -> [WholeSite] {
        var sites: [WholeSite] = []
        let others = snapshot.rankable.filter { $0.id != item.id }
        for scope in item.scopes
        where ScopePolicy.isAcceptable(scope) && scope.includeSubdomains && scope.excludedHosts.isEmpty {
            guard let host = try? HostNormalizer.normalize(ServiceIdentifier(scope.host, kind: .domain)),
                host.value == scope.host, PublicSuffix.broadestSite(of: host) == host.value,
                !sites.contains(where: { $0.host == host })
            else { continue }
            if snapshot.isShared(item) {
                guard case .success = snapshot.candidates(on: host) else { continue }
            }
            let below = "." + host.value
            var takenNames = Set<String>()
            var isWithdrawn = false
            for other in others {
                // Stored scope hosts are compared in their canonical spelling, whatever a record carries.
                let hosts = other.scopes.map { ServiceScope.canonicalHost($0.host) }
                if hosts.contains(where: { $0.hasSuffix(below) }) {
                    isWithdrawn = true
                    break
                }
                guard hosts.contains(host.value) else { continue }
                // Where the two classes meet at the host, a name the person cannot tell apart by eye (a Cyrillic
                // letter, a trailing space) would make two rows alike that the system shows without their vaults:
                // neither has a suggestion (review finding Z70).
                if snapshot.crossesTrust(item, other) {
                    isWithdrawn = true
                    break
                }
                takenNames.formUnion(suggestedNames(of: other))
            }
            if !isWithdrawn { sites.append(WholeSite(host: host, takenNames: takenNames)) }
        }
        return sites
    }

    /// Every name a suggestion for `item` could show: its login names and the accounts of its code fields.
    private static func suggestedNames(of item: Item) -> Set<String> {
        var names = Set(item.loginNames)
        for field in item.fields where field.kind == .totp {
            if let account = (try? field.otpParameters())?.account { names.insert(account) }
        }
        return names
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
    /// sync changes items. Does nothing while the provider is not enabled. The items are taken to be the person's
    /// own (`CredentialIdentityPlanner.identities(for: [Item])`), so tests only (Z78); what a session returns goes
    /// through `publishAll(_: CredentialSnapshot, to:)`.
    @discardableResult
    static func publishAll(
        _ items: [Item], to publisher: any CredentialIdentityPublisher
    ) async throws -> [CredentialIdentity] {
        try await publish(VaultSnapshot(ownItems: items), to: publisher)
    }

    /// Publishes exactly the identities of what the vault returned, replacing whatever was there.
    @discardableResult
    public static func publishAll(
        _ contents: CredentialSnapshot, to publisher: any CredentialIdentityPublisher
    ) async throws -> [CredentialIdentity] {
        try await publish(VaultSnapshot(contents), to: publisher)
    }

    @discardableResult
    static func publish(
        _ snapshot: VaultSnapshot, to publisher: any CredentialIdentityPublisher
    ) async throws -> [CredentialIdentity] {
        guard await publisher.state().isEnabled else { return [] }
        let identities = CredentialIdentityPlanner.identities(in: snapshot)
        try await publisher.replaceAll(with: identities)
        return identities
    }

    /// Publishes one item's change: `old` became `new`, where `nil` stands for an item that does not exist (created
    /// or deleted). `all` supplies every item as it is after the change, with its vaults. One item's change can add
    /// or remove another item's identities (a new, more specific account takes a less specific one out of the
    /// keyboard), so the difference is taken between the whole sets before and after.
    @discardableResult
    public static func publishChange(
        from old: Item?, to new: Item?, all: @Sendable () async throws -> CredentialSnapshot,
        to publisher: any CredentialIdentityPublisher
    ) async throws -> IdentityDifference {
        let state = await publisher.state()
        guard state.isEnabled else { return IdentityDifference(removals: [], additions: []) }
        let contents = try await all()
        return try await publishChange(from: old, to: new, among: contents.items, state: state, to: publisher) {
            var changed = contents
            changed.items = $0
            return VaultSnapshot(changed)
        }
    }

    /// As above, for items that are all the person's own: tests only (Z78).
    @discardableResult
    static func publishChange(
        from old: Item?, to new: Item?, all: @Sendable () async throws -> [Item],
        to publisher: any CredentialIdentityPublisher
    ) async throws -> IdentityDifference {
        let state = await publisher.state()
        guard state.isEnabled else { return IdentityDifference(removals: [], additions: []) }
        return try await publishChange(from: old, to: new, among: try await all(), state: state, to: publisher) {
            VaultSnapshot(ownItems: $0)
        }
    }

    private static func publishChange(
        from old: Item?, to new: Item?, among after: [Item], state: CredentialIdentityStoreState,
        to publisher: any CredentialIdentityPublisher, snapshot: ([Item]) -> VaultSnapshot
    ) async throws -> IdentityDifference {
        var before = after
        if let changed = new?.id ?? old?.id {
            before.removeAll { $0.id == changed }
        }
        if let old { before.append(old) }
        let published = CredentialIdentityPlanner.identities(in: snapshot(after))
        let difference = CredentialIdentityPlanner.difference(
            from: CredentialIdentityPlanner.identities(in: snapshot(before)), to: published)
        guard !difference.isEmpty else { return difference }
        if state.supportsIncrementalUpdates {
            try await publisher.apply(difference)
        } else {
            try await publisher.replaceAll(with: published)
        }
        return difference
    }
}
