import Foundation
import Observation
import WatchwordCrypto
import WatchwordKit

/// One device of the account, for the Devices screen (PRD F10.2; docs/02-architecture.md §7.8).
public struct DeviceRow: Hashable, Sendable, Identifiable {
    public let id: UUID
    public let name: String
    public let addedAt: Date?
    public let isThisDevice: Bool
    public let isRevoked: Bool
    /// "Added by Pat's iPhone", "Removed by Pat's Mac", or `nil`.
    public let detail: String?

    public var mayRevoke: Bool { !isThisDevice && !isRevoked }

    init(_ device: DeviceInfo, names: [UUID: String]) {
        id = device.id
        name = Self.displayName(device)
        addedAt = device.addedAt
        isThisDevice = device.isThisDevice
        isRevoked = device.isRevoked
        if let revokedBy = device.revokedBy {
            detail = "Removed by \(names[revokedBy] ?? "another device")"
        } else if let addedBy = device.addedBy {
            detail = "Added by \(names[addedBy] ?? "another device")"
        } else {
            detail = nil
        }
    }

    static func displayName(_ device: DeviceInfo) -> String {
        let name = device.name.isEmpty ? "Device \(shortIdentifier(device.id))" : device.name
        return device.isThisDevice ? "\(name) (this device)" : name
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
public final class DevicesModel {
    public private(set) var rows: [DeviceRow] = []
    public private(set) var standing: DeviceStanding?
    /// The password was changed on another device and has not been entered here (`isAwaitingNewPassword`).
    public private(set) var awaitingNewPassword = false
    public private(set) var sync: SyncSummary?
    public private(set) var isSyncConfigured: Bool
    public private(set) var isWorking = false
    public var errorMessage: String?
    public private(set) var notice: String?

    private let context: ScreenContext

    public init(context: ScreenContext) {
        self.context = context
        isSyncConfigured = context.session.isSyncConfigured
    }

    /// Device names by ID, for wording reports that name devices.
    public var names: [UUID: String] {
        Dictionary(rows.map { ($0.id, $0.name) }, uniquingKeysWith: { first, _ in first })
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
                ? "\(device.name) was removed and your account password changed. Use the new password from now on."
                : "\(device.name) was removed."
            done = true
        }
        return done
    }

    private func reload() async throws {
        let session = context.session
        let devices = try await session.devices()
        let names = Dictionary(
            devices.map { ($0.id, DeviceRow.displayName($0)) }, uniquingKeysWith: { first, _ in first })
        rows = devices.map { DeviceRow($0, names: names) }
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
