import Foundation
import Observation
import WatchwordEnvelope
import WatchwordKit
import WatchwordSync

/// One version sync kept aside, as the quarantine screen lists it (PRD F7.7; review findings U5, Y37, S49).
///
/// What is shown is what the device knows without opening the version: where it is kept, what it is a version of
/// (the item as it is now on this device), who wrote it and its number. The version itself stays sealed: it was
/// refused, so nothing in it is trusted enough to show as an item.
public struct QuarantineRow: Hashable, Sendable, Identifiable {
    public let version: QuarantinedVersion
    public let vaultName: String
    public let isSharedVault: Bool
    /// The item's title on this device, or what the record is.
    public let subject: String
    public let author: String
    public var id: String { version.id }

    public var isDeletion: Bool { version.entry.isDeletion }

    /// "Version 1052 by Pat's iPad", or "Deletion by …".
    public var summary: String {
        (isDeletion ? "Deletion" : "Version \(version.entry.version)") + " by \(author)"
    }

    /// Why it is here, for the person deciding whether to keep or discard it: §8.7's account only for a version the
    /// write judge held aside, U5's for one refused as implausible (review of the account screens, finding 7).
    public var explanation: String {
        switch version.reason {
        case .heldAside:
            return "Held aside in a shared vault: it carries changes that no longer count, such as one made after a "
                + "member's access ended, or an edit made after merging one. The item shows the version before it. "
                + "Nothing in it was applied."
        case .implausibleVersion:
            return "Held back because its version number jumped far beyond anything written in this vault. It may "
                + "come from a damaged device or from tampering. Nothing in it was applied."
        case .unmerged:
            return "Held back because it could not be combined with the version on this device. Nothing in it was "
                + "applied."
        case .recordInAnotherVault:
            return "Held back because another vault on this device already holds a record with the same identifier. "
                + "Nothing in it was applied, and the other vault's record was not changed."
        }
    }
}

/// The versions sync held aside, in every vault, and discarding them (PRD F7.6, F7.7). Discarding is the person's
/// choice and needs the vault unlocked; keeping costs nothing, so it is the default and needs no action.
@MainActor
@Observable
public final class QuarantineModel: LockSensitive {
    public private(set) var rows: [QuarantineRow] = []
    public private(set) var isSyncConfigured: Bool
    public private(set) var isWorking = false
    public var errorMessage: String?

    private let context: ScreenContext

    public init(context: ScreenContext) {
        self.context = context
        isSyncConfigured = context.session.isSyncConfigured
        context.locks?.register(self)
    }

    /// The rows name items; they go with the keys.
    public func dropOnLock() {
        rows = []
    }

    /// Held-aside versions from shared vaults (S49: the UI must show them).
    public var sharedRows: [QuarantineRow] { rows.filter(\.isSharedVault) }

    public func load() async {
        await perform { try await reload() }
    }

    public func discard(_ row: QuarantineRow) async {
        await perform {
            try await context.session.discardQuarantined([row.version])
            try await reload()
        }
    }

    private func reload() async throws {
        let session = context.session
        let versions = try await session.quarantine()
        guard !versions.isEmpty else {
            rows = []
            return
        }
        let vaults = Dictionary(
            try await session.vaults(includingDeleted: true).map { ($0.id, $0) },
            uniquingKeysWith: { first, _ in first })
        let shared = Set((try? await session.sharedVaultIDs()) ?? [])
        let devices = Dictionary(
            ((try? await session.devices()) ?? []).map { ($0.id, DeviceRow.reference($0)) },
            uniquingKeysWith: { first, _ in first })
        // The item's title on this device, looked up once per record; `.some(nil)` for a record it does not have.
        var titles: [String: String?] = [:]
        var result: [QuarantineRow] = []
        for version in versions {
            let entry = version.entry
            let titleKey = version.vaultID.uuidString + "/" + entry.recordID.uuidString
            if titles[titleKey] == nil {
                // Only an item of the vault the version is kept in: a record ID is the version's claim, and one that
                // names an item of another vault must not borrow that item's title.
                let item = (try? await session.item(id: entry.recordID)).flatMap {
                    $0.vaultID == version.vaultID ? $0 : nil
                }
                titles[titleKey] = .some(item.map { $0.title.isEmpty ? "Untitled" : $0.title })
            }
            let title = titles[titleKey] ?? nil
            let subject: String
            switch entry.kind {
            case .item: subject = title ?? "An item this device does not have"
            case .vaultMetadata: subject = "The vault's name"
            case .scanStatus: subject = "Breach-check results for " + (title ?? "an item")
            default: subject = "A record of another kind"
            }
            let vaultName = vaults[version.vaultID].map { $0.name.isEmpty ? "Unnamed vault" : $0.name } ?? "A vault"
            result.append(
                QuarantineRow(
                    version: version, vaultName: vaultName,
                    isSharedVault: shared.contains(version.vaultID) || version.reason == .heldAside,
                    subject: subject,
                    author: devices[entry.device] ?? "a device of another member (\(shortIdentifier(entry.device)))"))
        }
        rows = result
    }

    private func perform(_ body: () async throws -> Void) async {
        isWorking = true
        defer { isWorking = false }
        errorMessage = await ScreenOperation(context: context).run(body)
    }
}
