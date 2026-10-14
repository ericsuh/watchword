import Foundation
import Observation
import WatchwordCrypto
import WatchwordKit
import WatchwordModel

/// UI state over a `VaultSession`. Holds decrypted items only while unlocked and drops them on every lock.
@MainActor
@Observable
final class AppModel {
    enum Phase: Equatable {
        case loading
        case unavailable(String)
        case onboarding
        case emergencyKit(EmergencyKit)
        case locked
        case unlocked
    }

    private(set) var phase: Phase = .loading
    private(set) var items: [Item] = []
    private(set) var unreadableCount = 0
    private(set) var quickUnlockEnabled = false
    private(set) var quickUnlockAllowed = false
    var errorMessage: String?
    var isWorking = false

    let session: VaultSession?

    init(environment: AppEnvironment) {
        switch environment {
        case .ready(let session):
            self.session = session
        case .unavailable(let message):
            session = nil
            phase = .unavailable(message)
        }
    }

    var personalVaultID: UUID?

    func start() async {
        guard let session else { return }
        do {
            let status = try await session.status()
            personalVaultID = await session.personalVaultID
            quickUnlockEnabled = status.quickUnlock != nil
            quickUnlockAllowed = status.quickUnlock == .allowed
            switch status.state {
            case .noAccount: phase = .onboarding
            case .locked: phase = .locked
            case .unlocked: try await reload()
            }
        } catch {
            show(error)
        }
    }

    // MARK: Account

    func createAccount(password: String, confirmation: String) async {
        guard let session else { return }
        guard password == confirmation else {
            errorMessage = "The passwords do not match."
            return
        }
        await perform {
            let kit = try await session.createAccount(password: password)
            self.personalVaultID = await session.personalVaultID
            self.phase = .emergencyKit(kit)
        }
    }

    func confirmEmergencyKitSaved() async {
        guard let session else { return }
        await perform {
            try await session.confirmEmergencyKitSaved()
            try await self.reload()
        }
    }

    func unlock(password: String) async {
        guard let session else { return }
        await perform {
            try await session.unlock(password: password)
            try await self.reload()
        }
    }

    func quickUnlock() async {
        guard let session else { return }
        await perform {
            try await session.quickUnlock(prompt: "Unlock your Watchword vault")
            try await self.reload()
        }
        await refreshStatus()
    }

    func setQuickUnlock(_ enabled: Bool) async {
        guard let session else { return }
        await perform {
            if enabled { try await session.enableQuickUnlock() } else { try await session.disableQuickUnlock() }
        }
        await refreshStatus()
    }

    func lock() async {
        await session?.lock()
        didLock()
    }

    private func didLock() {
        items = []
        unreadableCount = 0
        phase = .locked
        Clipboard.clearIfOurs()
        Task { await refreshStatus() }
    }

    private func refreshStatus() async {
        guard let session, let status = try? await session.status() else { return }
        quickUnlockEnabled = status.quickUnlock != nil
        quickUnlockAllowed = status.quickUnlock == .allowed
    }

    // MARK: Auto-lock (F5.5)

    /// Activity is recorded on navigation and actions (selection, search, reveal, copy, edit, save) rather than on
    /// every touch: a root-level tap gesture would swallow `Button` taps inside SwiftUI lists on iOS.
    func recordActivity() {
        guard phase == .unlocked, let session else { return }
        Task { await session.recordActivity() }
    }

    func handle(_ event: AutoLockEvent) async {
        guard let session else { return }
        if await session.handle(event) != nil, phase == .unlocked {
            didLock()
        }
    }

    // MARK: Items

    func reload() async throws {
        guard let session else { return }
        let listing = try await session.items()
        items = listing.items.filter { !$0.isTrashed }
        unreadableCount = listing.unreadable.count
        phase = .unlocked
    }

    func save(_ item: Item) async -> Bool {
        guard let session else { return false }
        var saved = false
        await perform {
            try await session.save(item)
            try await self.reload()
            saved = true
        }
        return saved
    }

    func trash(_ item: Item) async {
        guard let session else { return }
        await perform {
            try await session.trash(id: item.id)
            try await self.reload()
        }
    }

    func emergencyKit() async -> EmergencyKit? {
        guard let session else { return nil }
        do {
            return try await session.emergencyKit()
        } catch {
            show(error)
            return nil
        }
    }

    // MARK: Errors

    private func perform(_ body: @MainActor () async throws -> Void) async {
        recordActivity()
        isWorking = true
        defer { isWorking = false }
        errorMessage = nil
        do {
            try await body()
        } catch {
            show(error)
        }
    }

    private func show(_ error: Error) {
        if case VaultError.locked = error {
            didLock()
        }
        errorMessage = Self.message(for: error)
    }

    static func message(for error: Error) -> String {
        switch error {
        case CryptoError.authenticationFailed:
            return "Incorrect password."
        case VaultError.passwordTooShort(let minimum):
            return "Use at least \(minimum) characters."
        case VaultError.secretKeyMissing:
            return "This device does not have your Secret Key. Enter it from your Emergency Kit."
        case VaultError.scopeRejected:
            return "That website address is too broad. Enter the site's own domain, such as example.com."
        case VaultError.quickUnlockRefused(let reason):
            switch reason {
            case .enrolmentChanged:
                return "Biometric settings changed. Enter your password, then turn quick unlock on again."
            case .biometryUnavailable:
                return "Biometric unlock is not available on this device."
            default:
                return "Enter your account password."
            }
        case VaultError.biometricAuthenticationFailed:
            return "Not recognised. Try again or enter your password."
        case KeychainError.userCancelled:
            return ""
        default:
            return "Something went wrong. Your vault is unchanged."
        }
    }
}
