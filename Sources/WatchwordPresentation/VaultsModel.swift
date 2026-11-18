import Foundation
import Observation
import WatchwordKit
import WatchwordSharing

/// A shared vault as its row and its banner show it (PRD F4.3, F4.5).
public struct VaultSharing: Hashable, Sendable {
    /// This account's role; `nil` once it was removed or left.
    public let role: MemberRole?
    public let memberCount: Int
    /// Why this account cannot write here now, worded; `nil` while it can.
    public let readOnlyReason: String?
    /// Why this account cannot rename the vault, worded; `nil` while it can. Only the owner and administrators name a
    /// shared vault (docs/02-architecture.md §8.7): the session decides (`SharedVaultStatus.mayRename`) and refuses
    /// again in `renameVault`; this is its answer in words, for the control that offers a rename.
    public let renameRefusal: String?
    /// The vault has gone on in a format this version cannot read: read-only until the app is updated (§8.9).
    public let requiresNewerVersion: Bool
    /// Versions held aside in this vault, for the quarantine screen (review finding S49).
    public let heldAside: Int
    public let rotationPending: Bool

    public init(_ status: SharedVaultStatus) {
        role = status.role
        memberCount = status.membership.members.count
        requiresNewerVersion = status.requiresNewerVersion
        switch status.writePermission {
        case .allowed: readOnlyReason = nil
        case .refused(let refusal): readOnlyReason = ErrorWording.readOnly(refusal)
        }
        renameRefusal = status.mayRename ? nil : readOnlyReason ?? ErrorWording.renameRefused
        heldAside = status.heldAside
        rotationPending = !status.pendingRotation.isEmpty
    }

    /// "Owner", "Administrator", "Can edit", "Read only", or "Not a member".
    public var roleName: String {
        role.map(MemberRow.name(of:)) ?? "Not a member"
    }
}

/// One vault in the vault list (PRD F2.1).
public struct VaultRow: Hashable, Sendable, Identifiable {
    public let id: UUID
    /// The vault's name, or "Unnamed vault" while its description has not arrived.
    public let name: String
    public let isPersonal: Bool
    public let createdAt: Date?
    /// `nil` for a vault that is not shared, or for one that is unavailable here (`unavailability`).
    public let sharing: VaultSharing?
    /// A shared vault with no verified ledger on this device, and why: shared, and closed here until the owner is
    /// checked again or the vault is set up on this device again (`VaultSession.unavailableSharedVaults`; V19, V31,
    /// V33). Never shown as one of the account's own.
    public let unavailability: SharedVaultUnavailability?

    /// Shared and unavailable on this device.
    public var awaitingOwnerCheck: Bool { unavailability != nil }

    public var isReadOnly: Bool { awaitingOwnerCheck || sharing?.readOnlyReason != nil }

    /// Whether this account may rename the vault: always for one that is not shared, and for a shared one only as its
    /// owner or an administrator (docs/02-architecture.md §8.7). The session's answer, not the screen's.
    public var mayRename: Bool { renameRefusal == nil }

    /// Why this account cannot rename the vault, worded; `nil` while it can.
    public var renameRefusal: String? {
        unavailability.map(ErrorWording.unavailable) ?? sharing?.renameRefusal
    }

    /// Whose vault this is and this account's part in it, from the session's facts rather than the name: an
    /// administrator can name a shared vault anything, "Personal" included, and a client that does not keep the rule
    /// can try (review of the account screens, finding 4). Shown wherever a vault is named, beside the name.
    public var badge: String {
        if isPersonal { return "Your own vault" }
        switch unavailability {
        case .ownerNotChecked?: return "Shared · check its owner"
        case .notSetUp?: return "Shared · not set up here"
        case nil: break
        }
        guard let sharing else { return "Only you" }
        if sharing.role == .owner { return "Shared by you" }
        return "Shared with you · " + sharing.roleName
    }

    /// The name with the badge, for menus and pickers that show one line.
    public var label: String { "\(name) (\(badge))" }

    /// Whether other accounts can read what is saved here.
    public var isShared: Bool { sharing != nil || awaitingOwnerCheck }

    /// What the row says under the name.
    public var detail: String {
        if isPersonal { return "Your own vault. It is never shared." }
        switch unavailability {
        case .ownerNotChecked?: return "Shared. Check its owner again before it can be used here."
        case .notSetUp?: return "Shared. Set it up on this device before it can be used here."
        case nil: break
        }
        guard let sharing else { return "Only you" }
        if sharing.requiresNewerVersion { return "Read-only: update Watchword" }
        let members = sharing.memberCount == 1 ? "1 member" : "\(sharing.memberCount) members"
        return "Shared, \(members). You: \(sharing.roleName)"
    }

    public init(_ info: VaultInfo, sharing: VaultSharing?, unavailability: SharedVaultUnavailability? = nil) {
        id = info.id
        name = info.name.isEmpty ? "Unnamed vault" : info.name
        isPersonal = info.isPersonal
        createdAt = info.createdAt
        self.sharing = sharing
        // The session's word, from either source: a vault it lists as unavailable is never shown as the account's own.
        self.unavailability =
            unavailability ?? (info.isSharedUnavailable && sharing == nil ? .notSetUp(owner: nil) : nil)
    }
}

extension VaultRow {
    /// Every vault the account can open, with each shared vault's standing: the one way a screen lists vaults, so
    /// every list labels them alike (`badge`). Sharing facts that cannot be read leave a vault unlabelled as shared
    /// only if the session reports no sharing at all.
    public static func load(from session: VaultSession) async throws -> [VaultRow] {
        let vaults = try await session.vaults()
        var shared: [UUID: VaultSharing] = [:]
        for id in (try? await session.sharedVaultIDs()) ?? [] {
            if let status = try? await session.sharedVaultStatus(id) { shared[id] = VaultSharing(status) }
        }
        let unavailable = (try? await session.unavailableSharedVaults()) ?? [:]
        return vaults.map { VaultRow($0, sharing: shared[$0.id], unavailability: unavailable[$0.id]) }
    }
}

/// The vault list, and creating and renaming vaults (PRD F2.1).
@MainActor
@Observable
public final class VaultsModel {
    public private(set) var rows: [VaultRow] = []
    /// Whether this build can share vaults at all (sharing needs sync and a key directory, which production builds
    /// do not have yet).
    public private(set) var sharingAvailable = false
    /// This account's safety number, for someone inviting it to compare (PRD F4.2); `nil` while sharing is not
    /// available.
    public private(set) var fingerprint: OwnFingerprint?
    public private(set) var isWorking = false
    public var errorMessage: String?

    private let context: ScreenContext

    public init(context: ScreenContext) {
        self.context = context
    }

    public func load() async {
        await perform {
            let session = context.session
            let vaults = try await session.vaults()
            var shared: [UUID: VaultSharing] = [:]
            var unavailable: [UUID: SharedVaultUnavailability] = [:]
            do {
                for id in try await session.sharedVaultIDs() {
                    shared[id] = VaultSharing(try await session.sharedVaultStatus(id))
                }
                unavailable = try await session.unavailableSharedVaults()
                sharingAvailable = true
                if fingerprint == nil, let bundle = try? await session.publicKeyBundle() {
                    fingerprint = OwnFingerprint(bundle)
                }
            } catch is SharedVaultError {
                sharingAvailable = false
            }
            rows = vaults.map { VaultRow($0, sharing: shared[$0.id], unavailability: unavailable[$0.id]) }
        }
    }

    public func row(_ id: UUID) -> VaultRow? {
        rows.first { $0.id == id }
    }

    /// Why `name` cannot be a vault's name, or `nil` if it can. The session checks again.
    public static func problem(withName name: String) -> String? {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return "Enter a name." }
        if trimmed.count > VaultMetadataCodec.maximumNameLength {
            return "Use at most \(VaultMetadataCodec.maximumNameLength) characters."
        }
        return nil
    }

    /// Creates a vault and returns its ID.
    @discardableResult
    public func create(name: String) async -> UUID? {
        var created: UUID?
        await perform {
            created = try await context.session.createVault(name: name).id
            try await reloadRows()
        }
        return created
    }

    public func rename(_ id: UUID, to name: String) async -> Bool {
        await perform {
            try await context.session.renameVault(id: id, to: name)
            try await reloadRows()
        }
    }

    private func reloadRows() async throws {
        let session = context.session
        let vaults = try await session.vaults()
        var shared: [UUID: VaultSharing] = [:]
        var unavailable: [UUID: SharedVaultUnavailability] = [:]
        if sharingAvailable {
            for id in (try? await session.sharedVaultIDs()) ?? [] {
                if let status = try? await session.sharedVaultStatus(id) { shared[id] = VaultSharing(status) }
            }
            unavailable = (try? await session.unavailableSharedVaults()) ?? [:]
        }
        rows = vaults.map { VaultRow($0, sharing: shared[$0.id], unavailability: unavailable[$0.id]) }
    }

    @discardableResult
    private func perform(_ body: () async throws -> Void) async -> Bool {
        isWorking = true
        defer { isWorking = false }
        errorMessage = await ScreenOperation(context: context).run(body)
        return errorMessage == nil
    }
}
