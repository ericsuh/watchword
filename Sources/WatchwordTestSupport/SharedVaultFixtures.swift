import Foundation
import WatchwordCrypto
import WatchwordKit
import WatchwordSharing
import WatchwordStore
import WatchwordSync

/// Records every share revocation a session asks for (PRD F4.3a), in order.
public actor RecordingShareAccess: ShareAccessControl {
    public private(set) var revoked: [(account: UUID, vault: UUID)] = []

    public init() {}

    public func revokeAccess(of accountID: UUID, to vaultID: UUID) {
        revoked.append((accountID, vaultID))
    }
}

/// One account of a household that shares vaults through real `VaultSession`s (docs/02-architecture.md §8.8): a
/// device syncing over the household's transport, with sharing configured over in-memory state and contacts, and
/// its key bundle published in the household's directory. Each account has its own device registry on the
/// transport, as on real devices.
public struct SharingAccount: Sendable {
    public let vault: TestVault
    public let state: InMemorySharingStateStore
    public let contacts: InMemoryVerifiedContactStore
    public let shareAccess: RecordingShareAccess
    public let accountID: UUID
    public let bundle: PublicKeyBundle

    public var session: VaultSession {
        vault.session
    }

    public var safetyNumber: String {
        bundle.fingerprint.safetyNumber
    }

    public static func make(
        over transport: any SyncTransport, directory: InMemoryKeyBundleDirectory, seed: UInt64,
        hygiene: HygieneSettings? = nil, board: (any SharingBoard)? = nil
    ) async throws -> SharingAccount {
        let vault = TestVault.syncing(over: transport, seed: seed, hygiene: hygiene)
        try await vault.createAccount()
        let state = InMemorySharingStateStore()
        let contacts = InMemoryVerifiedContactStore()
        let shareAccess = RecordingShareAccess()
        await vault.session.configureSharing(
            SharingSettings(
                state: state, contacts: contacts, directory: directory, shareAccess: shareAccess, board: board))
        let bundle = try await vault.session.publicKeyBundle()
        await directory.publish(bundle)
        // Publishes the account's registry, which other members check this device's signatures against.
        try await vault.session.sync()
        return SharingAccount(
            vault: vault, state: state, contacts: contacts, shareAccess: shareAccess,
            accountID: bundle.accountID, bundle: bundle)
    }

    /// Invites `invitee` to `vaultID` the way a person does: compares their safety number first, then invites; the
    /// invitee compares the owner's (`ownerSafetyNumber`) and accepts.
    public func invite(_ invitee: SharingAccount, to vaultID: UUID, as role: MemberRole, owner: SharingAccount)
        async throws
    {
        try await session.verifyContact(invitee.accountID, evidence: .safetyNumber(invitee.safetyNumber))
        let invitation = try await session.invite(invitee.accountID, to: vaultID, as: role)
        try await invitee.session.acceptInvitation(invitation, ownerEvidence: .safetyNumber(owner.safetyNumber))
    }

    /// Runs a vault sharing code session with `joiner` the way two people do (ADR 0010): this account shows the
    /// number, the joiner types it, this account types the joiner's six digits, and the joiner types this account's.
    /// Each ends with the other pinned. Returns the two final statuses.
    @discardableResult
    public func checkSharingCode(with joiner: SharingAccount) async throws -> (
        starter: SharingCodeStatus, joiner: SharingCodeStatus
    ) {
        let started = try await session.startSharingCodeSession()
        _ = try await joiner.session.joinSharingCodeSession(number: try Self.require(started.number))
        _ = try await session.refreshSharingCodeSession()
        let shown = try await joiner.session.refreshSharingCodeSession()
        let accepted = try await session.enterSharingCode(try Self.require(shown.ownCode))
        let done = try await joiner.session.enterSharingCode(try Self.require(accepted.ownCode))
        return (accepted, done)
    }

    struct MissingValue: Error {}

    static func require<T>(_ value: T?) throws -> T {
        guard let value else { throw MissingValue() }
        return value
    }
}

/// A transport, a key directory and the accounts that share through them.
public struct SharedVaultHousehold: Sendable {
    public let transport = InMemorySyncTransport()
    public let directory = InMemoryKeyBundleDirectory()
    /// Where the household's vault sharing code sessions meet (ADR 0010).
    public let board = InMemorySharingBoard()

    public init() {}

    public func account(seed: UInt64, hygiene: HygieneSettings? = nil) async throws -> SharingAccount {
        try await SharingAccount.make(
            over: transport, directory: directory, seed: seed, hygiene: hygiene, board: board)
    }

    /// An owner with a new shared vault called `name`, and one member per role, each invited and joined.
    public func household(roles: [MemberRole], name: String = "Household", seed: UInt64 = 300) async throws
        -> (vaultID: UUID, owner: SharingAccount, members: [SharingAccount])
    {
        let owner = try await account(seed: seed)
        let vaultID = try await owner.session.createVault(name: name).id
        try await owner.session.shareVault(vaultID)
        var members: [SharingAccount] = []
        for (index, role) in roles.enumerated() {
            let member = try await account(seed: seed + 17 * UInt64(index + 1))
            try await owner.invite(member, to: vaultID, as: role, owner: owner)
            members.append(member)
        }
        try await owner.session.sync()
        for member in members { try await member.session.sync() }
        return (vaultID, owner, members)
    }
}

/// One account's view of the household's transport, run by the store (A1): it can stop showing that account any
/// object created under a prefix from now on, and show everything again later. Writes pass through, so the
/// account's own objects land on the shared store whatever it is shown.
public actor WithholdingTransport: SyncTransport {
    public let base: InMemorySyncTransport
    private var frozen: [String: Set<String>] = [:]

    public init(base: InMemorySyncTransport) {
        self.base = base
    }

    /// From now on, objects created under `prefix` are withheld from this view.
    public func withholdNew(under prefix: String) async {
        frozen[prefix] = Set(await base.list(prefix: prefix))
    }

    public func reveal() {
        frozen = [:]
    }

    private func isWithheld(_ name: String) -> Bool {
        frozen.contains { prefix, shown in name.hasPrefix(prefix) && !shown.contains(name) }
    }

    public func list(prefix: String) async throws -> [String] {
        await base.list(prefix: prefix).filter { !isWithheld($0) }
    }

    public func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        guard !isWithheld(name) else { return nil }
        return try await base.fetch(name, maximumLength: maximumLength)
    }

    public func create(_ name: String, contents: [UInt8]) async throws {
        try await base.create(name, contents: contents)
    }

    public func delete(_ name: String) async throws {
        await base.delete(name)
    }
}

extension SharedVaultHousehold {
    /// An account whose view of the transport the store controls.
    public func withheldAccount(seed: UInt64, hygiene: HygieneSettings? = nil) async throws -> (
        account: SharingAccount, view: WithholdingTransport
    ) {
        let view = WithholdingTransport(base: transport)
        return (
            try await SharingAccount.make(over: view, directory: directory, seed: seed, hygiene: hygiene, board: board),
            view
        )
    }
}
