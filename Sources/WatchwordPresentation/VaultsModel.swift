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
    /// `nil` for a vault that is not shared.
    public let sharing: VaultSharing?

    public var isReadOnly: Bool { sharing?.readOnlyReason != nil }

    /// What the row says under the name.
    public var detail: String {
        if isPersonal { return "Your own vault. It is never shared." }
        guard let sharing else { return "Only you" }
        if sharing.requiresNewerVersion { return "Read-only: update Watchword" }
        let members = sharing.memberCount == 1 ? "1 member" : "\(sharing.memberCount) members"
        return "Shared, \(members). You: \(sharing.roleName)"
    }

    public init(_ info: VaultInfo, sharing: VaultSharing?) {
        id = info.id
        name = info.name.isEmpty ? "Unnamed vault" : info.name
        isPersonal = info.isPersonal
        createdAt = info.createdAt
        self.sharing = sharing
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
            do {
                for id in try await session.sharedVaultIDs() {
                    shared[id] = VaultSharing(try await session.sharedVaultStatus(id))
                }
                sharingAvailable = true
                if fingerprint == nil, let bundle = try? await session.publicKeyBundle() {
                    fingerprint = OwnFingerprint(bundle)
                }
            } catch is SharedVaultError {
                sharingAvailable = false
            }
            rows = vaults.map { VaultRow($0, sharing: shared[$0.id]) }
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
        if sharingAvailable {
            for id in (try? await session.sharedVaultIDs()) ?? [] {
                if let status = try? await session.sharedVaultStatus(id) { shared[id] = VaultSharing(status) }
            }
        }
        rows = vaults.map { VaultRow($0, sharing: shared[$0.id]) }
    }

    @discardableResult
    private func perform(_ body: () async throws -> Void) async -> Bool {
        isWorking = true
        defer { isWorking = false }
        errorMessage = await ScreenOperation(context: context).run(body)
        return errorMessage == nil
    }
}
