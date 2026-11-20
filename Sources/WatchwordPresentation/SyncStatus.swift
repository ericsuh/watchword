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
    /// A restore onto other hardware has not finished moving this device's sync records to its new identity
    /// (`AccountSyncReport.deviceMigrationIncomplete`, review of round 11, Z185): it receives changes and sends none,
    /// in any vault, until the move is made. Each sync and each unlock tries it again (Z181), and the text says that
    /// and no more (review of round 20, Z243): not that it finishes by itself, which a failure that lasts (a sharing
    /// store that cannot read a chain row the move needs, `restoredChainUnreadable`; a registry that cannot be
    /// evaluated, `registryUnavailable`) makes untrue, and where it lasts another notice says why; nor any step of the
    /// person's. A move that waits for sharing (`moveAwaitsSharing`, Z229) is tried and waits, in a process without
    /// sharing; the app configures sharing before its unlock.
    case deviceMigrationIncomplete
    /// What a restore left can be told here only from a record of this device's earlier identities that the sharing
    /// store could not read (`AccountSyncReport.restoredChainUnreadable`, review of round 20, Z240): deletions wait,
    /// and so does everything else if it is still moving its sync records over, for as long as the store fails. The
    /// text says only that a restore's leftovers cannot be ruled out (review of round 21, Z250): a device never
    /// restored whose shared vault's state is lost or damaged asks for the record too, and "before it was restored"
    /// was untrue there.
    case restoredChainUnreadable
    /// Unlocked, this sync downloaded and applied and sent nothing, because this device could not read its own key
    /// from the Keychain (`AccountSyncReport.ownDeviceKeyWait`, `.unreadable`; review of round 23, Z264): the Keychain
    /// can be closed while the device itself is locked. Read again at each sync.
    case deviceKeyUnreadable
    /// Unlocked, this sync downloaded and applied and sent nothing, because this device has still to register under a
    /// key of its own (`AccountSyncReport.ownDeviceKeyWait`, `.registering`; Z264), as a store restored onto other
    /// hardware does before its registration as a new device, which each sync and each unlock make.
    case deviceRegistering
    /// This device was due to write a snapshot and held it back because these devices' objects carried entries it
    /// cannot read (`SyncReport.snapshotWithheldBy`): the devices to update.
    case snapshotWithheld(by: [String])
    /// This device was due to write a snapshot and held it back because it holds versions aside, or could not keep
    /// one for want of room (`SyncReport.snapshotWithheldForQuarantine`, review findings Z26, Z37): until the person
    /// has looked at them, it does not let the sync storage be tidied past them.
    case snapshotWithheldForReview
    /// Versions kept aside for the person to look at (`quarantined` and `heldAside`).
    case keptAside(Int)
    /// This device's deletions are not going out, because an item it moved or made has reached nobody else: it is in
    /// a shared vault this account may not write to now, or one not set up here, or was held aside
    /// (`AccountSyncReport.deletionsHeldBack`).
    case deletionsHeldBack
    /// This device's deletions, in every vault, are not going out because these items of a shared vault hold an edit
    /// that has reached nobody else, made under an earlier identity of this device or by a device that is not counted
    /// in shared vaults (`AccountSyncReport.copiesNobodyReceived`, review finding Z171). By vault name and title.
    case copiesReachedNobody([UnreceivedCopy])
    /// This device's deletions, in every vault, are not going out because these items of a shared vault hold changes
    /// made on this device before it was restored that it has not sent yet, for want of the vault's key here
    /// (`AccountSyncReport.restoredWorkWaiting`, review of round 12, M1). By vault name and title, with a choice to
    /// stop waiting for each vault that will not open here (`AccountSyncReport.restoredWorkMayStopWaiting`, review of
    /// round 14, L2).
    case restoredWorkWaiting([UnreceivedCopy], stopWaiting: [SyncNoticeAction])
    /// These items of a shared vault hold changes made on this device before it was restored, in a vault this account
    /// is no longer a member of or that was deleted: they stay on this device only, and hold nothing back
    /// (`AccountSyncReport.restoredWorkKeptHere`, review of round 13, M3). By vault name and title.
    case restoredWorkKeptHere([UnreceivedCopy])
    /// Nothing made on this device in these vaults is going out, new edits included, and nothing from others there is
    /// applied, until a restore's carry of what this device held there before it was restored has finished
    /// (`AccountSyncReport.publishingHeldForCarry`, review of round 14, L4). By vault name, sorted, and how many more
    /// whose names could not be read.
    case publishingHeldForCarry([String], unnamed: Int)
    /// This device could not finish checking a shared vault's changes against who may write there now (its take-out
    /// of what no longer counts failed on local storage, `AccountSyncReport.takeOutUnfinished`, review of round 24,
    /// Z268): deletions made on this device wait until it has, and so does what it made in that vault (Z270). Not
    /// `deletionsHeldBack`, which says something moved has not reached the other devices, untrue here. Tried again at
    /// each sync.
    case takeOutUnfinished

    /// What the person can do about it from the notice itself: none, or one choice per vault it applies to.
    public var actions: [SyncNoticeAction] {
        if case .restoredWorkWaiting(_, let stopWaiting) = self { return stopWaiting }
        return []
    }

    public var id: String {
        switch self {
        case .updateRequired: return "updateRequired"
        case .awaitingNewPassword: return "awaitingNewPassword"
        case .deviceRevoked: return "deviceRevoked"
        case .deviceNotRegistered: return "deviceNotRegistered"
        case .registryUnavailable: return "registryUnavailable"
        case .deviceMigrationIncomplete: return "deviceMigrationIncomplete"
        case .restoredChainUnreadable: return "restoredChainUnreadable"
        case .deviceKeyUnreadable: return "deviceKeyUnreadable"
        case .deviceRegistering: return "deviceRegistering"
        case .snapshotWithheld: return "snapshotWithheld"
        case .snapshotWithheldForReview: return "snapshotWithheldForReview"
        case .keptAside: return "keptAside"
        case .deletionsHeldBack: return "deletionsHeldBack"
        case .copiesReachedNobody: return "copiesReachedNobody"
        case .restoredWorkWaiting: return "restoredWorkWaiting"
        case .restoredWorkKeptHere: return "restoredWorkKeptHere"
        case .publishingHeldForCarry: return "publishingHeldForCarry"
        case .takeOutUnfinished: return "takeOutUnfinished"
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
        case .deviceMigrationIncomplete:
            return "This device is still moving its sync records over from before it was restored. It receives "
                + "changes and sends none until that is done, and tries again at each sync and each unlock. Nothing "
                + "has been lost."
        case .restoredChainUnreadable:
            return "This device could not read part of its sharing records, and without it cannot rule out that "
                + "changes from before a restore of this device are still to be sent. Until it can, deletions made on "
                + "this device wait, and so does everything else it sends if it is still moving its sync records "
                + "over. It tries again at each sync. Nothing has been lost."
        case .deviceKeyUnreadable:
            return "This device could not read its own key from the Keychain, which can happen while the device is "
                + "locked. Changes were downloaded, and none were applied or sent. It tries again at each sync. "
                + "Nothing has been lost."
        case .deviceRegistering:
            return "This device is still registering with your account, for example after being restored onto new "
                + "hardware. Until it has, changes are downloaded, and none are applied or sent. It tries again at "
                + "each sync and each unlock. Nothing has been lost."
        case .snapshotWithheld(let names):
            return "Older devices need updating before this one can tidy the shared storage: "
                + names.joined(separator: ", ") + "."
        case .snapshotWithheldForReview:
            return "This device is not tidying the sync storage while changes are held aside for you, so that none "
                + "of them is lost. Review them under Held-Aside Changes."
        case .keptAside(let count):
            return "\(count) change(s) were held aside for you to review. See Held-Aside Changes."
        case .deletionsHeldBack:
            return "Deletions made on this device are waiting. Something it moved or added has not reached your "
                + "other devices: it is in a shared vault this device cannot write to now, or was held aside. They "
                + "go out once it has, or once you discard it under Held-Aside Changes."
        case .copiesReachedNobody(let copies):
            let shown = copies.prefix(3).map(\.phrase)
            let more = copies.count > shown.count ? " and \(copies.count - shown.count) more" : ""
            let one = copies.count == 1
            return "Deletions made on this device are waiting, in every vault, because "
                + shown.joined(separator: ", ") + more + (one ? " has" : " have") + " reached nobody else: "
                + (one ? "it holds" : "they hold") + " changes from a setup of your devices that shared vaults do "
                + "not count, such as this device before it was restored. Move " + (one ? "it" : "each") + " out of "
                + "the shared vault from this device, or delete " + (one ? "it" : "each") + ", and the deletions go "
                + "out."
        case .restoredWorkWaiting(let copies, let stopWaiting):
            let shown = copies.prefix(3).map(\.phrase)
            let more = copies.count > shown.count ? " and \(copies.count - shown.count) more" : ""
            let one = copies.count == 1
            let waiting =
                "Deletions made on this device are waiting, in every vault, because "
                + shown.joined(separator: ", ") + more + (one ? " holds" : " hold") + " changes made on this device "
                + "before it was restored, which it sends first. They go out after " + (one ? "it" : "them") + "."
            guard !stopWaiting.isEmpty else { return waiting + " This device tries again at each sync." }
            return waiting + " A shared vault that will not open on this device holds some of them: you can choose "
                + "to stop waiting for it, and what was made there before the restore stays on this device only."
        case .restoredWorkKeptHere(let copies):
            let shown = copies.prefix(3).map(\.phrase)
            let more = copies.count > shown.count ? " and \(copies.count - shown.count) more" : ""
            let one = copies.count == 1
            return shown.joined(separator: ", ") + more + (one ? " holds" : " hold") + " changes made on this "
                + "device before it was restored, in a shared vault you are no longer a member of or that was "
                + "deleted. " + (one ? "They stay" : "Those changes stay") + " on this device only, and deletions "
                + "made here are not waiting for them."
        case .publishingHeldForCarry(let names, let unnamed):
            let vaults =
                names.map { "“\($0)”" }
                + (unnamed == 0 ? [] : [unnamed == 1 ? "a shared vault" : "\(unnamed) shared vaults"])
            let one = vaults.count == 1 && unnamed <= 1
            return "Changes made on this device in " + Self.list(vaults) + " are waiting, and changes from others "
                + (one ? "there" : "in " + (vaults.count == 2 ? "them" : "those vaults")) + " are not shown yet: "
                + "before they go out, this device has to finish carrying over the changes it made "
                + (one ? "there" : "in each") + " before it was restored. It tries again at each sync. Nothing has "
                + "been lost."
        case .takeOutUnfinished:
            return "This device could not finish checking a shared vault's changes. Until it has, deletions made on "
                + "this device wait, and so do its changes in that vault. It tries again at each sync. Nothing has "
                + "been lost."
        }
    }
}

extension SyncNotice {
    /// “A”, “A and B”, “A, B and C”.
    static func list(_ names: [String]) -> String {
        guard let last = names.last else { return "" }
        guard names.count > 1 else { return last }
        return names.dropLast().joined(separator: ", ") + " and " + last
    }
}

/// Something the person can do from a notice (`SyncNotice.action`), with what it means, for the button and the
/// confirmation that asks before it is done.
public enum SyncNoticeAction: Hashable, Sendable {
    /// Stop waiting to send what a restore left in one shared vault, `vault` its name where it could be read
    /// (`VaultSession.stopWaitingForRestoredWork(in:)`, review of round 13, M3): the person's choice, offered only for
    /// a vault that will not open on this device (review of round 14, L2).
    case stopWaitingForRestoredWork(vaultID: UUID, vault: String?)

    /// The vault the action applies to: one action per vault, and the screen names each by it (its accessibility
    /// identifier, review of round 15, Z215).
    public var vaultID: UUID {
        switch self {
        case .stopWaitingForRestoredWork(let vaultID, _): return vaultID
        }
    }

    public var title: String {
        switch self {
        case .stopWaitingForRestoredWork(_, let vault):
            return "Stop Waiting for " + (vault.map { "“\($0)”" } ?? "This Vault")
        }
    }

    /// What the confirmation says before the action is taken.
    public var confirmation: String {
        switch self {
        case .stopWaitingForRestoredWork(_, let vault):
            let name = vault.map { "“\($0)”" } ?? "this shared vault"
            return "The changes this device made in " + name + " before it was restored stay on this device only: "
                + "they are not sent to the vault's other members, now or later, even if the vault opens here again. "
                + "Neither are changes you make to those items on this device afterwards. Deletions made on this "
                + "device then go out."
        }
    }
}

/// An item of a shared vault that has reached nobody else (`SyncNotice.copiesReachedNobody`): its vault's name and
/// its title, which the vault list and the item list show anyway; nothing secret.
public struct UnreceivedCopy: Hashable, Sendable, Comparable {
    /// `nil` where the name is empty or could not be read.
    public let vault: String?
    public let title: String?

    public init(vault: String?, title: String?) {
        self.vault = vault.flatMap { $0.isEmpty ? nil : $0 }
        self.title = title.flatMap { $0.isEmpty ? nil : $0 }
    }

    /// “Bank” in “Household”, or the fallbacks.
    var phrase: String {
        (title.map { "“\($0)”" } ?? "an item") + " in " + (vault.map { "“\($0)”" } ?? "a shared vault")
    }

    public static func < (lhs: UnreceivedCopy, rhs: UnreceivedCopy) -> Bool {
        (lhs.vault ?? "", lhs.title ?? "") < (rhs.vault ?? "", rhs.title ?? "")
    }
}

/// What the last sync did, for Settings and the Devices screen.
public struct SyncSummary: Hashable, Sendable {
    /// One line: what was received and sent, or why nothing was.
    public let headline: String
    public let notices: [SyncNotice]
    /// The vaults `SyncNotice.restoredWorkWaiting` offers to stop waiting for (its actions, `perform(_:using:)`).
    public let restoredWorkVaults: [UUID]

    public var updateRequired: Bool { notices.contains(.updateRequired) }

    /// `names` gives device names by ID (`VaultSession.devices()`); a device it lacks is another account's, in a
    /// shared vault. `vaultNames` and `itemTitles` name the copies of `AccountSyncReport.copiesNobodyReceived`
    /// (`loading(_:deviceNames:from:)` reads them from the session); one they lack is worded "a shared vault" or
    /// "an item".
    public init(
        _ report: AccountSyncReport, deviceNames names: [UUID: String] = [:], vaultNames: [UUID: String] = [:],
        itemTitles: [UUID: String] = [:]
    ) {
        let combined = report.combined
        headline = SyncSummary.describe(combined, ownDeviceKeyWait: report.ownDeviceKeyWait)
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
        if report.deviceMigrationIncomplete { notices.append(.deviceMigrationIncomplete) }
        if !report.restoredChainUnreadable.isEmpty { notices.append(.restoredChainUnreadable) }
        switch report.ownDeviceKeyWait {
        case .unreadable: notices.append(.deviceKeyUnreadable)
        case .registering: notices.append(.deviceRegistering)
        case nil: break
        }
        if !combined.snapshotWithheldBy.isEmpty {
            let named = combined.snapshotWithheldBy.map { id in
                names[id].flatMap { $0.isEmpty ? nil : $0 } ?? "a device of another member (\(shortIdentifier(id)))"
            }
            notices.append(.snapshotWithheld(by: named.sorted()))
        }
        if combined.snapshotWithheldForQuarantine { notices.append(.snapshotWithheldForReview) }
        let kept = combined.quarantined.count + combined.heldAside.count + combined.collided.count
        if kept > 0 { notices.append(.keptAside(kept)) }
        var copies: [UnreceivedCopy] = []
        for (vaultID, items) in report.copiesNobodyReceived {
            for itemID in items { copies.append(UnreceivedCopy(vault: vaultNames[vaultID], title: itemTitles[itemID])) }
        }
        if !copies.isEmpty { notices.append(.copiesReachedNobody(copies.sorted())) }
        var waiting: [UnreceivedCopy] = []
        for (vaultID, items) in report.restoredWorkWaiting {
            for itemID in items {
                waiting.append(UnreceivedCopy(vault: vaultNames[vaultID], title: itemTitles[itemID]))
            }
        }
        // Stop Waiting, per vault, only where the vault will not open here (review of round 14, L2).
        let stoppable = report.restoredWorkWaiting.filter {
            !$0.value.isEmpty && report.restoredWorkMayStopWaiting.contains($0.key)
        }.keys.map { (id: $0, name: vaultNames[$0].flatMap { $0.isEmpty ? nil : $0 }) }.sorted {
            ($0.name ?? "", $0.id.uuidString) < ($1.name ?? "", $1.id.uuidString)
        }
        restoredWorkVaults = stoppable.map(\.id)
        if !waiting.isEmpty {
            notices.append(
                .restoredWorkWaiting(
                    waiting.sorted(),
                    stopWaiting: stoppable.map { .stopWaitingForRestoredWork(vaultID: $0.id, vault: $0.name) }))
        }
        var keptHere: [UnreceivedCopy] = []
        for (vaultID, items) in report.restoredWorkKeptHere {
            for itemID in items {
                keptHere.append(UnreceivedCopy(vault: vaultNames[vaultID], title: itemTitles[itemID]))
            }
        }
        if !keptHere.isEmpty { notices.append(.restoredWorkKeptHere(keptHere.sorted())) }
        if !report.publishingHeldForCarry.isEmpty {
            let held = report.publishingHeldForCarry.map { vaultNames[$0].flatMap { $0.isEmpty ? nil : $0 } }
            let named = held.compactMap { $0 }
            notices.append(.publishingHeldForCarry(named.sorted(), unnamed: held.count - named.count))
        }
        if !report.takeOutUnfinished.isEmpty { notices.append(.takeOutUnfinished) }
        let explained = Set(report.copiesNobodyReceived.keys).union(report.restoredWorkWaiting.keys)
            .union(report.restoredChainUnreadable)
        if !report.deletionsHeldBack.subtracting(explained).isEmpty {
            notices.append(.deletionsHeldBack)
        }
        self.notices = notices
    }

    /// The summary with the names `init` needs read from `session`: the vaults' names, and the titles of the items in
    /// `AccountSyncReport.copiesNobodyReceived`, `restoredWorkWaiting` and `restoredWorkKeptHere`. A name that cannot
    /// be read (the session locked, the item gone) is left to `init`'s fallback.
    public static func loading(
        _ report: AccountSyncReport, deviceNames names: [UUID: String] = [:], from session: VaultSession
    )
        async -> SyncSummary
    {
        let named =
            report.copiesNobodyReceived.values.flatMap { $0 } + report.restoredWorkWaiting.values.flatMap { $0 }
            + report.restoredWorkKeptHere.values.flatMap { $0 }
        guard !named.isEmpty || !report.publishingHeldForCarry.isEmpty else {
            return SyncSummary(report, deviceNames: names)
        }
        let vaults = (try? await session.vaults(includingDeleted: true)) ?? []
        var titles: [UUID: String] = [:]
        for itemID in named {
            titles[itemID] = try? await session.item(id: itemID).title
        }
        return SyncSummary(
            report, deviceNames: names,
            vaultNames: Dictionary(vaults.map { ($0.id, $0.name) }, uniquingKeysWith: { first, _ in first }),
            itemTitles: titles)
    }

    /// Does what a notice's action says (`SyncNotice.actions`), once the person has confirmed it
    /// (`SyncNoticeAction.confirmation`): for `stopWaitingForRestoredWork`, in the one vault it names. The caller syncs
    /// again afterwards, so that the deletions go out and the notice is gone.
    public func perform(_ action: SyncNoticeAction, using session: VaultSession) async throws {
        switch action {
        case .stopWaitingForRestoredWork(let vaultID, _):
            try await session.stopWaitingForRestoredWork(in: vaultID)
        }
    }

    /// The one line about a sync's outcome. The words "received" and "sent" are what the UI tests wait for.
    /// `ownDeviceKeyWait` is the account's (`AccountSyncReport.ownDeviceKeyWait`): where it says why an unlocked sync
    /// only downloaded, the line says that, not "when you unlock" (review of round 23, Z264).
    public static func describe(_ report: SyncReport, ownDeviceKeyWait: OwnDeviceKeyWait? = nil) -> String {
        if report.transportUnavailable { return "Sync storage could not be reached. Nothing was sent." }
        if !report.rejected.isEmpty, report.rejected.allSatisfy({ $0.reason == .keyring(.trustedKeyUnavailable) }) {
            return "Changes will be downloaded and checked after you unlock."
        }
        if report.deferredUntilUnlock && !report.awaitingNewPassword && !report.deviceRevoked {
            switch ownDeviceKeyWait {
            case .unreadable:
                return "Changes were downloaded and will be applied once this device can read its own key."
            case .registering:
                return "Changes were downloaded and will be applied once this device has finished registering."
            case nil:
                return "Changes were downloaded and will be applied when you unlock."
            }
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
        if !report.collided.isEmpty {
            parts.append("\(report.collided.count) change(s) held for review, named like a record of another vault")
        }
        if report.quarantineFull > 0 {
            parts.append("\(report.quarantineFull) more could not be kept for review: the held-aside list is full")
        }
        // This device's own stream (review findings Z21, Z24): its changes are not going out. Worded without the two
        // words the UI tests wait for.
        if report.ownStreamExhausted {
            parts.append("this device's own changes cannot go out in one of its vaults")
        } else if report.ownStreamUnverified != nil {
            parts.append("this device's own changes are held back until its place in the sync storage is clear")
        } else if report.ownStreamConflict != nil {
            // Its next place is taken (review finding Z137): a crash after publishing, a restored copy of this device,
            // or an object someone else put there. Nothing is lost, and deletions wait with the rest.
            parts.append(
                "this device found its place in the sync storage already taken; some of its own changes, and its "
                    + "deletions, wait for the next sync")
        }
        if report.ownStreamSteppedOver != nil {
            // Another account wrote in this device's place in a shared vault (review finding Z146): what this device
            // publishes there may count for nobody else. Nothing here is lost.
            parts.append(
                "another member's device wrote in this device's place in a shared vault, so its changes there may "
                    + "not reach the others")
        }
        if report.awaitingNewPassword { parts.append("waiting for the new account password") }
        return parts.isEmpty ? "Up to date." : sentence(parts)
    }

    static func sentence(_ parts: [String]) -> String {
        let joined = parts.joined(separator: "; ")
        return joined.prefix(1).uppercased() + joined.dropFirst() + "."
    }
}
