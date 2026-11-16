import Foundation
import WatchwordCrypto
import WatchwordKit
import WatchwordSync

/// Something about the last sync the person should know or act on, beyond its one-line summary (PRD F7;
/// docs/02-architecture.md §7.8, ADR 0009).
public enum SyncNotice: Hashable, Sendable, Identifiable {
    /// A stream stopped at something this version cannot read: nothing past it is merged until the app is updated
    /// (`SyncReport.requiresNewerVersion`, or a shared vault gone on in a later format).
    case updateRequired
    /// The account password was changed on another device and has not been entered here.
    case awaitingNewPassword
    case deviceRevoked
    case deviceNotRegistered
    case registryUnavailable
    /// This device was due to write a snapshot and held it back because these devices' objects carried entries it
    /// cannot read (`SyncReport.snapshotWithheldBy`): the devices to update.
    case snapshotWithheld(by: [String])
    /// Versions kept aside for the person to look at (`quarantined` and `heldAside`).
    case keptAside(Int)

    public var id: String {
        switch self {
        case .updateRequired: return "updateRequired"
        case .awaitingNewPassword: return "awaitingNewPassword"
        case .deviceRevoked: return "deviceRevoked"
        case .deviceNotRegistered: return "deviceNotRegistered"
        case .registryUnavailable: return "registryUnavailable"
        case .snapshotWithheld: return "snapshotWithheld"
        case .keptAside: return "keptAside"
        }
    }

    public var text: String {
        switch self {
        case .updateRequired:
            return "Update Watchword: some changes were made by a newer version and wait, unread, until you do. "
                + "Nothing has been lost."
        case .awaitingNewPassword:
            return "Your account password was changed on another device. Lock Watchword and unlock it with the new "
                + "password to go on syncing. If you did not change it, see Devices."
        case .deviceRevoked:
            return "This device was removed from your account. It no longer sends or receives changes."
        case .deviceNotRegistered:
            return "This device is not registered with your account yet. It receives changes, and sends none until "
                + "it is."
        case .registryUnavailable:
            return "This device cannot check your other devices yet. Nothing they sent has been trusted."
        case .snapshotWithheld(let names):
            return "Older devices need updating before this one can tidy the shared storage: "
                + names.joined(separator: ", ") + "."
        case .keptAside(let count):
            return "\(count) change(s) were held aside for you to review. See Held-Aside Changes."
        }
    }
}

/// What the last sync did, for Settings and the Devices screen.
public struct SyncSummary: Hashable, Sendable {
    /// One line: what was received and sent, or why nothing was.
    public let headline: String
    public let notices: [SyncNotice]

    public var updateRequired: Bool { notices.contains(.updateRequired) }

    /// `names` gives device names by ID (`VaultSession.devices()`); a device it lacks is another account's, in a
    /// shared vault.
    public init(_ report: AccountSyncReport, deviceNames names: [UUID: String] = [:]) {
        let combined = report.combined
        headline = SyncSummary.describe(combined)
        var notices: [SyncNotice] = []
        if combined.requiresNewerVersion || report.sharing.values.contains(where: \.requiresNewerVersion) {
            notices.append(.updateRequired)
        }
        if report.awaitingNewPassword { notices.append(.awaitingNewPassword) }
        switch report.deviceStanding {
        case .revoked: notices.append(.deviceRevoked)
        case .unknown: notices.append(.deviceNotRegistered)
        case .active, nil: break
        }
        if report.registryUnavailable { notices.append(.registryUnavailable) }
        if !combined.snapshotWithheldBy.isEmpty {
            let named = combined.snapshotWithheldBy.map { id in
                names[id].flatMap { $0.isEmpty ? nil : $0 } ?? "a device of another member (\(shortIdentifier(id)))"
            }
            notices.append(.snapshotWithheld(by: named.sorted()))
        }
        let kept = combined.quarantined.count + combined.heldAside.count
        if kept > 0 { notices.append(.keptAside(kept)) }
        self.notices = notices
    }

    /// The one line about a sync's outcome. The words "received" and "sent" are what the UI tests wait for.
    public static func describe(_ report: SyncReport) -> String {
        if report.transportUnavailable { return "Sync storage could not be reached. Nothing was sent." }
        if !report.rejected.isEmpty, report.rejected.allSatisfy({ $0.reason == .keyring(.trustedKeyUnavailable) }) {
            return "Changes will be downloaded and checked after you unlock."
        }
        if report.deferredUntilUnlock && !report.awaitingNewPassword && !report.deviceRevoked {
            return "Changes were downloaded and will be applied when you unlock."
        }
        var parts: [String] = []
        if report.applied > 0 { parts.append("\(report.applied) change(s) received") }
        if report.pushedEntries > 0 { parts.append("\(report.pushedEntries) change(s) sent") }
        if !report.rejected.isEmpty {
            parts.append("\(report.rejected.count) object(s) failed verification and were ignored")
        }
        if !report.quarantined.isEmpty {
            parts.append("\(report.quarantined.count) implausible change(s) held for review")
        }
        if !report.heldAside.isEmpty {
            parts.append("\(report.heldAside.count) change(s) in a shared vault held aside")
        }
        if report.awaitingNewPassword { parts.append("waiting for the new account password") }
        return parts.isEmpty ? "Up to date." : sentence(parts)
    }

    static func sentence(_ parts: [String]) -> String {
        let joined = parts.joined(separator: "; ")
        return joined.prefix(1).uppercased() + joined.dropFirst() + "."
    }
}
