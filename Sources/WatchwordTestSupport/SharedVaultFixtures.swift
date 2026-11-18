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
        hygiene: HygieneSettings? = nil, configuration: SyncConfiguration? = nil
    ) async throws -> SharingAccount {
        let vault =
            configuration.map {
                TestVault(
                    sync: SyncSettings(state: InMemorySyncStateStore(), transport: transport, configuration: $0),
                    seed: seed, hygiene: hygiene)
            } ?? TestVault.syncing(over: transport, seed: seed, hygiene: hygiene)
        try await vault.createAccount()
        let state = InMemorySharingStateStore()
        let contacts = InMemoryVerifiedContactStore()
        let shareAccess = RecordingShareAccess()
        await vault.session.configureSharing(
            SharingSettings(state: state, contacts: contacts, directory: directory, shareAccess: shareAccess))
        let bundle = try await vault.session.publicKeyBundle()
        await directory.publish(bundle)
        // Publishes the account's registry, which other members check this device's signatures against.
        try await vault.session.sync()
        return SharingAccount(
            vault: vault, state: state, contacts: contacts, shareAccess: shareAccess,
            accountID: bundle.accountID, bundle: bundle)
    }

    /// Another device of this account (PRD F5.2), enrolled from the transport with the password and the Secret Key,
    /// unlocked, with sharing configured over sharing state and contacts of its own: pins, ledgers and stream
    /// indexes are per device (review finding S35), so it starts with none. `modifiedClient` makes it an adversary's
    /// modified client (`VaultSession.playModifiedClient`, Z162): it writes, accepts and publishes in a shared vault
    /// whatever its ID, where an honest client whose ID does not commit refuses to.
    public func enrolledDevice(
        deviceID: UUID? = nil, over transport: any SyncTransport, directory: InMemoryKeyBundleDirectory,
        modifiedClient: Bool = false
    ) async throws -> SharingAccount {
        let device = try await vault.enrolledDevice(deviceID: deviceID, over: transport)
        if modifiedClient { await device.session.playModifiedClient() }
        let state = InMemorySharingStateStore()
        let contacts = InMemoryVerifiedContactStore()
        let shareAccess = RecordingShareAccess()
        await device.session.configureSharing(
            SharingSettings(state: state, contacts: contacts, directory: directory, shareAccess: shareAccess))
        try await device.session.unlock(password: TestVault.password)
        try await device.session.sync()
        return SharingAccount(
            vault: device, state: state, contacts: contacts, shareAccess: shareAccess, accountID: accountID,
            bundle: bundle)
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
}

/// A transport, a key directory and the accounts that share through them.
public struct SharedVaultHousehold: Sendable {
    public let transport = InMemorySyncTransport()
    public let directory = InMemoryKeyBundleDirectory()

    public init() {}

    public func account(seed: UInt64, hygiene: HygieneSettings? = nil, configuration: SyncConfiguration? = nil)
        async throws -> SharingAccount
    {
        try await SharingAccount.make(
            over: transport, directory: directory, seed: seed, hygiene: hygiene, configuration: configuration)
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
    private var hidden: Set<String> = []

    public init(base: InMemorySyncTransport) {
        self.base = base
    }

    /// From now on, objects created under `prefix` are withheld from this view.
    public func withholdNew(under prefix: String) async {
        frozen[prefix] = Set(await base.list(prefix: prefix))
    }

    /// From now on exactly these objects are withheld from this view, whatever else is created.
    public func withhold(_ names: Set<String>) {
        hidden.formUnion(names)
    }

    public func reveal() {
        frozen = [:]
        hidden = []
    }

    private func isWithheld(_ name: String) -> Bool {
        hidden.contains(name) || frozen.contains { prefix, shown in name.hasPrefix(prefix) && !shown.contains(name) }
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
    /// Another device of `account`, its ID committing to the account (Z157) unless `deviceID` names it. A device
    /// named that way is an adversary's, under another device's ID (S33), so it is a modified client too (Z162): an
    /// honest one would refuse to accept an invitation or write in a shared vault with an ID that commits to nothing.
    public func secondDevice(of account: SharingAccount, deviceID: UUID? = nil) async throws -> SharingAccount {
        try await account.enrolledDevice(
            deviceID: deviceID, over: transport, directory: directory, modifiedClient: deviceID != nil)
    }

    /// An account whose view of the transport the store controls.
    public func withheldAccount(seed: UInt64, hygiene: HygieneSettings? = nil) async throws -> (
        account: SharingAccount, view: WithholdingTransport
    ) {
        let view = WithholdingTransport(base: transport)
        return (try await SharingAccount.make(over: view, directory: directory, seed: seed, hygiene: hygiene), view)
    }
}
