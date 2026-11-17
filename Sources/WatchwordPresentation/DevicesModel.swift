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

    private let context: ScreenContext

    public init(context: ScreenContext) {
        self.context = context
        isSyncConfigured = context.session.isSyncConfigured
        context.locks?.register(self)
    }

    public func dropOnLock() {
        revocation = RevocationForm()
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
