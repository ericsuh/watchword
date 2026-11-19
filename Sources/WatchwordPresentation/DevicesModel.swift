import Foundation
import Observation
import WatchwordCrypto
import WatchwordKit

/// One device of the account, for the Devices screen (PRD F10.2; docs/02-architecture.md §7.8).
///
/// A device's name is whatever was typed where it enrolled, by whoever enrolled it, so it is shown as text and never
/// trusted to say anything else (review of the account screens, finding 8): which device is this one comes from its
/// ID (`isThisDevice`), shown apart from the name, and the name is cleaned of control and formatting characters (bidi
/// overrides among them) and of any "(this device)" it claims.
public struct DeviceRow: Hashable, Sendable, Identifiable {
    public let id: UUID
    /// The cleaned name, never marked as this device: `isThisDevice` says that.
    public let name: String
    public let addedAt: Date?
    public let isThisDevice: Bool
    public let isRevoked: Bool
    /// "Added by “Pat's iPhone”", "Removed by this device", or `nil`.
    public let detail: String?

    public var mayRevoke: Bool { !isThisDevice && !isRevoked }

    /// The longest name shown; the session keeps at most 64 characters anyway.
    public static let maximumNameLength = 64

    init(_ device: DeviceInfo, references: [UUID: String]) {
        id = device.id
        name = Self.displayName(device)
        addedAt = device.addedAt
        isThisDevice = device.isThisDevice
        isRevoked = device.isRevoked
        if let revokedBy = device.revokedBy {
            detail = "Removed by \(references[revokedBy] ?? "another device")"
        } else if let addedBy = device.addedBy {
            detail = "Added by \(references[addedBy] ?? "another device")"
        } else {
            detail = nil
        }
    }

    /// The device's cleaned name, or "Device 1A2B3C4D" for one with none.
    public static func displayName(_ device: DeviceInfo) -> String {
        let name = clean(device.name)
        return name.isEmpty ? "Device \(shortIdentifier(device.id))" : name
    }

    /// How a sentence names the device: "this device", from its ID, or the cleaned name in quotation marks.
    public static func reference(_ device: DeviceInfo) -> String {
        device.isThisDevice ? "this device" : "“\(displayName(device))”"
    }

    /// `raw` without control, formatting or separator characters, with runs of white space made one space, without
    /// any "(this device)" or quotation marks it holds, and at most `maximumNameLength` characters.
    public static func clean(_ raw: String) -> String {
        var scalars = String.UnicodeScalarView()
        for scalar in raw.unicodeScalars {
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator, .surrogate, .privateUse, .unassigned:
                scalars.append(" ")
            default:
                scalars.append(scalar)
            }
        }
        var text = String(scalars).replacingOccurrences(of: "“", with: "").replacingOccurrences(of: "”", with: "")
        while let range = text.range(of: "(this device)", options: [.caseInsensitive]) {
            text.removeSubrange(range)
        }
        let words = text.split(whereSeparator: { $0.isWhitespace })
        return String(words.joined(separator: " ").prefix(maximumNameLength))
    }
}

/// What the person chooses when removing a device (docs/02-architecture.md §7.8): change the account password in the
/// same step, which is the default and the only safe choice if the device may have been unlocked by someone else, or
/// keep it, which needs both of the facts that make that safe confirmed.
public struct RevocationForm: Hashable, Sendable {
    public var changesPassword = true
    public var currentPassword = ""
    public var newPassword = ""
    public var confirmation = ""
    /// "The device was locked when it left my hands."
    public var deviceWasLocked = false
    /// "Nobody who may have it knows the account password."
    public var passwordUnknownToHolder = false

    public init() {}

    /// Why the form cannot be sent yet, or `nil`.
    public var problem: String? {
        if currentPassword.isEmpty { return "Enter your current account password." }
        if changesPassword {
            if newPassword.count < VaultConfiguration.minimumPasswordLength {
                return "Use at least \(VaultConfiguration.minimumPasswordLength) characters for the new password."
            }
            if newPassword != confirmation { return "The new passwords do not match." }
            if newPassword == currentPassword { return "Choose a new password different from the current one." }
        } else if !(deviceWasLocked && passwordUnknownToHolder) {
            return "Keeping the password is safe only if both statements are true. Otherwise, change it."
        }
        return nil
    }

    public var choice: RevocationPasswordChoice? {
        guard problem == nil else { return nil }
        return changesPassword
            ? .change(current: currentPassword, new: newPassword) : .keepPassword(current: currentPassword)
    }
}

/// A password change made on another device that this one does not follow, as the Devices screen lists it for the
/// person to choose (review findings Z1, Z8): who made it, and what following it would do here.
public struct PasswordChangeRow: Hashable, Sendable, Identifiable {
    public let id: UUID
    /// The device that made the change, as a sentence names it.
    public let deviceName: String
    public let summary: String
    /// `false` for a change that would remove this device, or that the registry cannot follow at all.
    public let mayFollow: Bool

    init(_ change: PendingPasswordChange, names: [UUID: String]) {
        id = change.device
        let name = names[change.device] ?? "a device this one does not know"
        deviceName = name
        let revoked = change.revokedDevices.filter { $0 != change.device }
            .map { names[$0] ?? "a device this one does not know" }
        var text = "The account password was changed on \(name)"
        text += change.isFork ? ", at the same time as the change this device follows." : "."
        if !change.registeredBeforeFollowed {
            text += " That device was added after the password this device has was set."
        }
        if !change.isDescribed {
            text += " Select it to see what following it would do."
        } else if change.revokesThisDevice {
            text += " That change removes this device from your account, so it cannot be followed here."
        } else if !change.canBeFollowed {
            text += " It cannot be followed."
        } else if !revoked.isEmpty {
            text += " Following it removes \(revoked.joined(separator: ", ")) from your account."
        }
        summary = text
        // Not yet worked out: the session refuses a change that removes this device or cannot be followed anyway.
        mayFollow = !change.isDescribed || (change.canBeFollowed && !change.revokesThisDevice)
    }
}

/// The account's devices, removing one, and the state of sync on this device (PRD F7, F10.2).
@MainActor
@Observable
public final class DevicesModel: LockSensitive {
    public private(set) var rows: [DeviceRow] = []
    public private(set) var standing: DeviceStanding?
    /// The password was changed on another device and has not been entered here (`isAwaitingNewPassword`).
    public private(set) var awaitingNewPassword = false
    /// The password changes this device does not follow, one per device that made any: more than one means the
    /// account's devices disagree, and the person says which change is theirs by the device they made it on.
    public private(set) var passwordChanges: [PasswordChangeRow] = []
    public private(set) var sync: SyncSummary?
    public private(set) var isSyncConfigured: Bool
    public private(set) var isWorking = false
    public var errorMessage: String?
    public private(set) var notice: String?
    /// The removal being filled in, passwords included: here rather than in the view, so a lock clears it whatever is
    /// on screen (finding 6).
    public var revocation = RevocationForm()
    /// The question about uploading again after the sync storage was reset, while it is on screen
    /// (docs/02-architecture.md §7.10). Set only by `askToUploadAgain`, which a person's tap calls.
    public private(set) var reuploadQuestion: ReuploadQuestion?
    /// The last sync says the storage was reset and the person has not uploaded again: the screen offers the question
    /// (`askToUploadAgain`). Still true after "Not Now"; declining decides nothing for good.
    public var storageNeedsUpload: Bool { sync?.storageNeedsUpload ?? false }

    private let context: ScreenContext
    /// How many locks this model has been told of: a sync notes it first, and stores nothing it made across one.
    private var lockGeneration = 0

    public init(context: ScreenContext) {
        self.context = context
        isSyncConfigured = context.session.isSyncConfigured
        context.locks?.register(self)
    }

    public func dropOnLock() {
        lockGeneration &+= 1
        revocation = RevocationForm()
        // A question answered after a lock would be answered unread.
        reuploadQuestion = nil
        // The last sync's summary names items and vaults by title (Z171): it does not outlast the keys (Z176).
        sync = nil
    }

    /// How sentences name each device, by ID, for wording reports that name devices.
    public var names: [UUID: String] {
        Dictionary(
            rows.map { ($0.id, $0.isThisDevice ? "this device" : "“\($0.name)”") },
            uniquingKeysWith: { first, _ in first })
    }

    public func load() async {
        await perform { try await reload() }
    }

    public func syncNow() async {
        guard isSyncConfigured else { return }
        // The summary is stored after the sync's awaits, and a lock that landed during them has cleared it already
        // (Z176): one made across a lock is dropped, not stored on a locked screen (review of round 10, Z183).
        // The session's own count too, which moves in `lock()` itself, before this model is told (review of round 11,
        // Z188); read again after the awaits, so that a lock after that read reaches `dropOnLock` after the store.
        let sessionLocks = await context.session.lockCount
        let generation = lockGeneration
        await perform {
            let report = try await context.session.syncAll()
            try await reload()
            let summary = await SyncSummary.loading(report, deviceNames: names, from: context.session)
            let unlocked = await context.session.lockCount == sessionLocks
            guard unlocked, generation == lockGeneration else { return }
            sync = summary
        }
    }

    // MARK: - After the sync storage was reset (docs/02-architecture.md §7.10)

    /// Prepares the question: what this device would upload, read from the device alone. Nothing is uploaded and the
    /// storage is not asked anything.
    public func askToUploadAgain() async {
        guard isSyncConfigured else { return }
        await perform {
            reuploadQuestion = ReuploadQuestion(try await context.session.reuploadPlan())
        }
    }

    /// "Not Now": the question goes away and nothing else happens. The notice stays, and the person can be asked
    /// again whenever they choose.
    public func declineUpload() {
        context.recordActivity()
        reuploadQuestion = nil
    }

    /// "Upload Again": the person's yes to `question`, which is the one they were shown, and the only caller of
    /// `VaultSession.reuploadAfterStoreReset`. A question can only be made from what this device holds
    /// (`askToUploadAgain`), and the session checks that it still holds exactly that: if something changed since,
    /// nothing is uploaded and the question is made again from what it holds now, for the person to read before they
    /// answer. Returns whether the upload was made.
    @discardableResult
    public func confirmUpload(_ question: ReuploadQuestion) async -> Bool {
        var done = false
        reuploadQuestion = nil
        // As `syncNow`: the summary names copies by title (Z171), is read from the session, and is dropped if a lock
        // landed during the awaits (Z176, Z183).
        let generation = lockGeneration
        await perform {
            do {
                let report = try await context.session.reuploadAfterStoreReset(confirming: question.plan)
                try await reload()
                let summary = await SyncSummary.loading(report, deviceNames: names, from: context.session)
                guard generation == lockGeneration else { return }
                sync = summary
                if Self.uploadFinished(report, uploading: question.plan) {
                    notice = "This device uploaded what it holds. Your other devices will pick it up when they sync."
                    done = true
                }
            } catch VaultError.reuploadNotConfirmed {
                reuploadQuestion = ReuploadQuestion(try await context.session.reuploadPlan())
                throw VaultError.reuploadNotConfirmed
            }
        }
        return done
    }

    /// Whether `report`, the sync of an upload of `plan`, uploaded everything the plan named: nothing is still asked
    /// for, the transport did not stop, and every vault the plan uploads ran. A vault left locked or waiting for a new
    /// password uploaded nothing, and the question is not pending for it only because no engine could look (review
    /// finding SR21). Only the plan's vaults, the account's own unshared ones (those the session marks before it
    /// starts the store again), are asked: a shared vault waiting for a key it has not been granted yet is reported as
    /// waiting for an unlock too, is never uploaded from one member's device, and must not keep a complete upload from
    /// being told as one (review finding SR28).
    public static func uploadFinished(_ report: AccountSyncReport, uploading plan: ReuploadPlan) -> Bool {
        let uploaded = Set(plan.vaults.map(\.id))
        let ran = !report.vaults.contains { vaultID, vault in
            uploaded.contains(vaultID) && (vault.deferredUntilUnlock || vault.awaitingNewPassword)
        }
        return !report.storeNeedsReupload && report.transportFailure == nil && ran
    }

    /// Removes a device. Both choices take the current password; the session refuses this device and unknown ones.
    public func revoke(_ device: DeviceRow, with form: RevocationForm) async -> Bool {
        guard let choice = form.choice else {
            errorMessage = form.problem
            return false
        }
        var done = false
        await perform {
            try await context.session.revokeDevice(device.id, password: choice)
            // Other devices learn of it at their next sync; this one tells them now where it can.
            if isSyncConfigured { _ = try? await context.session.syncAll() }
            try await reload()
            notice =
                form.changesPassword
                ? "“\(device.name)” was removed and your account password changed. Use the new password from now on."
                : "“\(device.name)” was removed."
            done = true
        }
        return done
    }

    /// Follows the password change made on the device the person names, with the password this device follows now
    /// and that change's password: for someone who unlocked with the password this device still had
    /// (`ignoringPasswordChange`), and for bringing this device over to a change made at the same time as the one it
    /// follows. Both passwords are asked for every time, as for removing a device (Z14).
    public func follow(_ change: PasswordChangeRow, current: String, password: String) async -> Bool {
        var done = false
        await perform {
            try await context.session.followPasswordChange(by: change.id, current: current, password: password)
            if isSyncConfigured { _ = try? await context.session.syncAll() }
            try await reload()
            notice = "This device now uses the password set on \(change.deviceName)."
            done = true
        }
        return done
    }

    /// Works out what following `change` would do, for a row the list did not describe (Z13).
    public func describe(_ change: PasswordChangeRow) async {
        await perform {
            let described = try await context.session.describePasswordChange(by: change.id)
            let row = PasswordChangeRow(described, names: names)
            passwordChanges = passwordChanges.map { $0.id == row.id ? row : $0 }
        }
    }

    private func reload() async throws {
        let session = context.session
        let devices = try await session.devices()
        let references = Dictionary(
            devices.map { ($0.id, DeviceRow.reference($0)) }, uniquingKeysWith: { first, _ in first })
        rows = devices.map { DeviceRow($0, references: references) }
        standing = try? await session.deviceStanding()
        awaitingNewPassword = (try? await session.isAwaitingNewPassword()) ?? false
        passwordChanges = ((try? await session.pendingPasswordChanges()) ?? []).map {
            PasswordChangeRow($0, names: names)
        }
    }

    private func perform(_ body: () async throws -> Void) async {
        isWorking = true
        defer { isWorking = false }
        notice = nil
        errorMessage = await ScreenOperation(context: context).run(body)
    }
}
