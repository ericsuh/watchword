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
    /// The sync storage was reset, or no longer holds what this device does, and the person has not said whether to
    /// upload it again (`AccountSyncReport.storeNeedsReupload`; docs/02-architecture.md §7.10). The one notice with a
    /// question behind it: `DevicesModel.askToUploadAgain`.
    case storageNeedsUpload
    /// Shared vaults that this device cannot upload again after a reset (`ReuploadRefusal.sharedVault`).
    case sharedVaultsNotUploaded(Int)
    /// Vaults the person asked to upload again that do not fit in one upload (`ReuploadRefusal.tooLarge`).
    case vaultsTooLargeToUpload(Int)

    public var id: String {
        switch self {
        case .updateRequired: return "updateRequired"
        case .awaitingNewPassword: return "awaitingNewPassword"
        case .deviceRevoked: return "deviceRevoked"
        case .deviceNotRegistered: return "deviceNotRegistered"
        case .registryUnavailable: return "registryUnavailable"
        case .snapshotWithheld: return "snapshotWithheld"
        case .keptAside: return "keptAside"
        case .storageNeedsUpload: return "storageNeedsUpload"
        case .sharedVaultsNotUploaded: return "sharedVaultsNotUploaded"
        case .vaultsTooLargeToUpload: return "vaultsTooLargeToUpload"
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
        case .storageNeedsUpload:
            return "Your sync storage was emptied or reset, and no longer holds everything this device does. "
                + "Nothing on this device has been lost, and nothing has been uploaded again. Until you decide, "
                + "changes made here may not reach your other devices."
        case .sharedVaultsNotUploaded(let count):
            return "\(count) shared vault(s) cannot be uploaded again from this device after the reset. They stay "
                + "on this device, readable and unchanged, and do not sync."
        case .vaultsTooLargeToUpload(let count):
            return "\(count) vault(s) are too large to upload again in one piece. They stay on this device, "
                + "unchanged."
        }
    }
}

/// The question a person is asked before anything is uploaded again after the sync storage was reset
/// (docs/02-architecture.md §7.10; owner decision, 2026-11-17: re-upload, "but ask the user first"). It says that the
/// data is gone from the storage and may have been deleted on purpose, exactly what this device would upload, that
/// uploading undoes a deletion made elsewhere, and what cannot be uploaded. Words only: the session decides what is
/// uploaded, and checks that this is still the plan the person saw.
public struct ReuploadQuestion: Hashable, Sendable {
    /// The plan the wording describes, handed back to the session with a yes.
    public let plan: ReuploadPlan
    public let title: String
    /// What happened, and that it may have been deliberate.
    public let explanation: String
    /// What this device would upload.
    public let upload: String
    /// What a yes undoes.
    public let warning: String
    /// What cannot be uploaded, or `nil`.
    public let notUploaded: String?
    public let confirmLabel: String
    public let declineLabel: String

    public init(_ plan: ReuploadPlan) {
        self.plan = plan
        title = "Upload your vaults again?"
        explanation =
            "Your sync storage no longer holds your Watchword data: it was emptied or reset. That can happen when "
            + "the data is deleted in the storage's settings, on this device or another, and it may have been done "
            + "on purpose. Everything is still on this device."
        let live = plan.vaults.filter { !$0.isDeleted }
        let items = live.reduce(0) { $0 + $1.itemCount }
        var upload =
            "If you continue, this device uploads everything it holds: \(Self.count(items, "item")) in "
            + "\(Self.count(live.count, "vault")), encrypted as before, with the encrypted keys and the list of "
            + "devices your other devices need to read them."
        let deleted = plan.vaults.count - live.count
        if deleted > 0 {
            upload +=
                " It also uploads the record of \(Self.count(deleted, "deleted vault")), so that "
                + (deleted == 1 ? "it stays" : "they stay") + " deleted everywhere."
        }
        self.upload = upload
        warning =
            "Uploading puts the data back in the sync storage. If you, or someone using another of your devices, "
            + "deleted it there deliberately, this undoes that deletion. Your other devices keep what they hold "
            + "and will each ask the same question if they have something to add."
        if plan.sharedVaults.isEmpty {
            notUploaded = nil
        } else {
            notUploaded =
                "\(Self.count(plan.sharedVaults.count, "shared vault")) cannot be uploaded again from one member's "
                + "device. " + (plan.sharedVaults.count == 1 ? "It stays" : "They stay")
                + " on this device, readable and unchanged, and will not sync."
        }
        confirmLabel = "Upload Again"
        declineLabel = "Not Now"
    }

    /// The whole question as paragraphs, in the order a screen shows them.
    public var paragraphs: [String] {
        [explanation, upload, warning] + (notUploaded.map { [$0] } ?? [])
    }

    static func count(_ number: Int, _ noun: String) -> String {
        "\(number) \(noun)\(number == 1 ? "" : "s")"
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
        if report.storeNeedsReupload { notices.append(.storageNeedsUpload) }
        let refusals = report.reuploadRefusals.values
        let shared = refusals.filter { $0 == .sharedVault }.count
        if shared > 0 { notices.append(.sharedVaultsNotUploaded(shared)) }
        let tooLarge = refusals.filter { $0 == .tooLarge }.count
        if tooLarge > 0 { notices.append(.vaultsTooLargeToUpload(tooLarge)) }
        self.notices = notices
    }

    /// Whether the person should be asked about uploading again (`SyncNotice.storageNeedsUpload`).
    public var storageNeedsUpload: Bool { notices.contains(.storageNeedsUpload) }

    /// The one line about a sync's outcome. The words "received" and "sent" are what the UI tests wait for.
    public static func describe(_ report: SyncReport) -> String {
        if report.transportFailure == .storeReset {
            return "Sync storage was emptied or reset. Nothing was sent, and nothing was uploaded again."
        }
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
