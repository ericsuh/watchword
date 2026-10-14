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
    private var monitoring = false

    func start() async {
        guard let session else { return }
        startMonitoring()
        do {
            let status = try await session.status()
            personalVaultID = await session.personalVaultID
            quickUnlockEnabled = status.quickUnlock != nil
            quickUnlockAllowed = status.quickUnlock == .allowed
            switch status.state {
            case .noAccount: phase = .onboarding
            case .locked: phase = .locked
            case .unlocked: try await enterVault()
            }
        } catch {
            show(error)
        }
    }

    /// Auto-lock checks and sleep/screen-lock observers live here, with the session, rather than in a view: on macOS
    /// the app outlives its window, and a view-owned timer would stop while the vault stayed unlocked (F5.5).
    private func startMonitoring() {
        guard !monitoring else { return }
        monitoring = true
        Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(15))
                guard let self else { return }
                await self.handle(.tick)
            }
        }
        Task { [weak self] in
            for await _ in PlatformLifecycle.sleepNotifications.map({ _ in () }).values {
                guard let self else { return }
                await self.handle(.systemSleep)
            }
        }
        PlatformLifecycle.installPrivacyShield()
    }

    /// After an unlock: the vault, unless the Emergency Kit was never confirmed, in which case the kit again (F5.1).
    private func enterVault() async throws {
        guard let session else { return }
        if try await !session.status().emergencyKitConfirmed {
            phase = .emergencyKit(try await session.emergencyKit())
            return
        }
        try await reload()
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
            try await self.enterVault()
        }
    }

    func quickUnlock() async {
        guard let session else { return }
        await perform {
            try await session.quickUnlock(prompt: "Unlock your Watchword vault")
            try await self.enterVault()
        }
        await refreshStatus()
    }

    /// Turning quick unlock on needs the account password (it restarts the F5.4 password interval).
    func enableQuickUnlock(password: String) async {
        guard let session else { return }
        await perform { try await session.enableQuickUnlock(password: password) }
        await refreshStatus()
    }

    func disableQuickUnlock() async {
        guard let session else { return }
        await perform { try await session.disableQuickUnlock() }
        await refreshStatus()
    }

    func lock() async {
        await session?.lock()
        didLock(.requested)
    }

    /// Drops everything decrypted and shows the unlock screen, from any phase that showed vault contents or the
    /// Secret Key. The clipboard is cleared on every lock except backgrounding, which on iOS is how a person switches
    /// to the app they are pasting into; the copy still expires after 60 s (F5.6).
    private func didLock(_ reason: LockReason) {
        items = []
        unreadableCount = 0
        switch phase {
        case .unlocked, .emergencyKit: phase = .locked
        default: break
        }
        if reason != .backgrounded {
            Clipboard.clearIfOurs()
        }
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
        guard let session else { return }
        Task {
            if let reason = await session.recordActivity() { didLock(reason) }
        }
    }

    func handle(_ event: AutoLockEvent) async {
        guard let session else { return }
        if let reason = await session.handle(event) {
            didLock(reason)
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
            didLock(.requested)
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
