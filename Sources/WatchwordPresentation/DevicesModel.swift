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

/// The account's devices, removing one, and the state of sync on this device (PRD F7, F10.2).
@MainActor
@Observable
public final class DevicesModel: LockSensitive {
    public private(set) var rows: [DeviceRow] = []
    public private(set) var standing: DeviceStanding?
    /// The password was changed on another device and has not been entered here (`isAwaitingNewPassword`).
    public private(set) var awaitingNewPassword = false
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

    public init(context: ScreenContext) {
        self.context = context
        isSyncConfigured = context.session.isSyncConfigured
        context.locks?.register(self)
    }

    public func dropOnLock() {
        revocation = RevocationForm()
        // A question answered after a lock would be answered unread.
        reuploadQuestion = nil
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
        await perform {
            let report = try await context.session.syncAll()
            try await reload()
            sync = SyncSummary(report, deviceNames: names)
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
        await perform {
            do {
                let report = try await context.session.reuploadAfterStoreReset(confirming: question.plan)
                try await reload()
                sync = SyncSummary(report, deviceNames: names)
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

    private func reload() async throws {
        let session = context.session
        let devices = try await session.devices()
        let references = Dictionary(
            devices.map { ($0.id, DeviceRow.reference($0)) }, uniquingKeysWith: { first, _ in first })
        rows = devices.map { DeviceRow($0, references: references) }
        standing = try? await session.deviceStanding()
        awaitingNewPassword = (try? await session.isAwaitingNewPassword()) ?? false
    }

    private func perform(_ body: () async throws -> Void) async {
        isWorking = true
        defer { isWorking = false }
        notice = nil
        errorMessage = await ScreenOperation(context: context).run(body)
    }
}
