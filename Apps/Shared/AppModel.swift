import Foundation
import Observation
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordPresentation
import WatchwordSharing
import WatchwordStore
import WatchwordSync

/// UI state over a `VaultSession`. Holds decrypted items only while unlocked and drops them on every lock. The screens
/// added after milestone 2 keep their state in `WatchwordPresentation`'s models, which get the session through
/// `screenContext`; what lives here is what more than one screen needs: the phase, the items, the vaults and the last
/// sync.
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
    /// The account's vaults, with each shared vault's standing, for the list's filter and for read-only vaults.
    private(set) var vaults: [VaultRow] = []
    /// The vault the item list shows; `nil` for every vault.
    var vaultFilter: UUID?
    /// What the last sync did, for Settings.
    private(set) var lastSync: SyncSummary?
    /// The last unlock was refused because the account password was changed on another device (PRD F10.1). The unlock
    /// screen then offers the way out for a person who did not make that change (docs/02-architecture.md §7.8).
    private(set) var passwordChangedElsewhere = false
    /// Whether this build checks passwords against Pwned Passwords (only UI-test builds, until the network adapter).
    let breachChecksAvailable: Bool
    var errorMessage: String?
    var isWorking = false

    let session: VaultSession?
    /// Every lock of the session, for the screen models to drop what they hold (`LockSensitive`), whether or not
    /// their views are still on screen.
    let lockSignal: LockSignal
    /// When revealed secrets are hidden again (F5.7, Z95): the platform reports, the views compare.
    let privacy = ScreenPrivacy()
    /// The staging folder, swept on every lock through the signal, and by this model at launch, at every unlock and
    /// at termination (Z80).
    let staging: StagingSweeper
    #if DEBUG
        private(set) var uiTestPeer: UITestPeer?
        private(set) var uiTestPeerStatus: String?
        private var uiTestSharing: SharingSettings?
        /// The last invitation the app issued, for the hook that has the other person accept it.
        var uiTestInvitation: Invitation?
        /// The last archive the app exported, for the restore screen's UI-test source.
        var uiTestArchive: [UInt8]?
    #endif

    init(environment: AppEnvironment) {
        lockSignal = LockSignal()
        staging = StagingSweeper(locks: lockSignal)
        switch environment {
        case .ready(let session):
            self.session = session
            breachChecksAvailable = false
        #if DEBUG
            case .uiTest(let session, let peer, let sharing):
                self.session = session
                uiTestPeer = peer
                uiTestSharing = sharing
                breachChecksAvailable = true
        #endif
        case .unavailable(let message):
            session = nil
            breachChecksAvailable = false
            phase = .unavailable(message)
        }
    }

    var personalVaultID: UUID?
    private var monitoring = false

    /// What the screen models are given: the session, activity for auto-lock, and a way to report a lock.
    var screenContext: ScreenContext? {
        guard let session else { return nil }
        return ScreenContext(
            session: session, recordActivity: { [weak self] in self?.recordActivity() },
            didLock: { [weak self] in self?.didLock(.requested) }, locks: lockSignal)
    }

    var syncStatus: String? { lastSync?.headline }

    func start() async {
        // Before anything is shown (AppEnvironment.make has swept once already, before the session was built).
        staging.sweep()
        guard let session else { return }
        await lockSignal.watch(session)
        #if DEBUG
            if let uiTestSharing { await session.configureSharing(uiTestSharing) }
        #endif
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
        PlatformLifecycle.installPrivacyShield(privacy) { [weak self] in self?.prepareForTermination() }
    }

    /// The app is about to end (macOS `applicationWillTerminate`, iOS `willTerminateNotification`): what every screen
    /// model drops on a lock goes now, synchronously, since a lock of the session would finish after the process, and
    /// the staging folder is swept (Z80).
    func prepareForTermination() {
        lockSignal.fire()
        privacy.locked()
        staging.sweep()
        Clipboard.clearIfOurs()
    }

    /// After an unlock: the vault, unless the Emergency Kit was never confirmed, in which case the kit again (F5.1).
    /// The session shows that kit without the password only to keys opened with it (Z86): after a quick unlock the
    /// vault opens and the kit is in Settings, behind the password. Every unlock sweeps the staging folder (Z80).
    private func enterVault() async throws {
        guard let session else { return }
        staging.sweep()
        if try await !session.status().emergencyKitConfirmed {
            do {
                phase = .emergencyKit(try await session.unconfirmedEmergencyKit())
                return
            } catch VaultError.accountPasswordRequired {}
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
        await unlock(password: password, ignoringPasswordChange: false)
    }

    /// For the person who did not change the password elsewhere: unlocks with the password this device still has, so
    /// they can remove the device that changed it and choose a password of their own (§7.8).
    func unlockIgnoringPasswordChange(password: String) async {
        await unlock(password: password, ignoringPasswordChange: true)
    }

    private func unlock(password: String, ignoringPasswordChange: Bool) async {
        guard let session else { return }
        await perform {
            do {
                try await session.unlock(password: password, ignoringPasswordChange: ignoringPasswordChange)
            } catch VaultError.passwordChangedOnAnotherDevice {
                self.passwordChangedElsewhere = true
                throw VaultError.passwordChangedOnAnotherDevice
            }
            self.passwordChangedElsewhere = false
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
        lockSignal.fire()
        privacy.locked()
        items = []
        vaults = []
        unreadableCount = 0
        switch phase {
        case .unlocked, .emergencyKit: phase = .locked
        default: break
        }
        if reason != .backgrounded {
            Clipboard.clearIfOurs()
        }
        #if DEBUG
            uiTestArchive = nil
        #endif
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

    // MARK: Items and vaults

    func reload() async throws {
        guard let session else { return }
        let listing = try await session.items()
        items = listing.items.filter { !$0.isTrashed }
        unreadableCount = listing.unreadable.count
        try await reloadVaults()
        phase = .unlocked
    }

    /// The vaults and each shared vault's standing (PRD F2.1, F4.5).
    func reloadVaults() async throws {
        guard let session else { return }
        vaults = try await VaultRow.load(from: session)
        if let vaultFilter, !vaults.contains(where: { $0.id == vaultFilter }) { self.vaultFilter = nil }
    }

    /// The items the list shows: the chosen vault's, or every vault's.
    var listedItems: [Item] {
        guard let vaultFilter else { return items }
        return items.filter { $0.vaultID == vaultFilter }
    }

    func vault(_ id: UUID) -> VaultRow? {
        vaults.first { $0.id == id }
    }

    /// Why `vaultID` cannot be written to by this account now, or `nil` (PRD F4.5; §8.9). The session refuses such a
    /// write whatever the screen offers; this is what the screen says instead of offering it.
    func readOnlyReason(_ vaultID: UUID) -> String? {
        vault(vaultID)?.readOnlyReason
    }

    /// Where a new item goes: the vault the list shows, if this account may write to it, else Personal.
    var newItemVaultID: UUID? {
        if let vaultFilter, readOnlyReason(vaultFilter) == nil { return vaultFilter }
        return personalVaultID
    }

    /// Saves through the editor's model, which turns the session's refusal of a look-alike host into the questions
    /// the editor shows (PRD F11.7; `ItemEditorModel`). `false` when nothing was written: an error is in
    /// `errorMessage`, or `editor.prompts` is waiting for the person.
    func save(_ item: Item, with editor: ItemEditorModel, confirmed: Bool = false) async -> Bool {
        isWorking = true
        defer { isWorking = false }
        let stored = confirmed ? await editor.confirmAndSave() : await editor.save(item)
        errorMessage = editor.errorMessage
        guard stored != nil else { return false }
        await perform { try await self.reload() }
        return true
    }

    func trash(_ item: Item) async {
        guard let session else { return }
        await perform {
            try await session.trash(id: item.id)
            try await self.reload()
        }
    }

    // MARK: Sync (PRD F7)

    var isSyncConfigured: Bool {
        session?.isSyncConfigured ?? false
    }

    func syncNow() async {
        guard let session, session.isSyncConfigured else { return }
        lastSync = nil
        await perform {
            let report = try await session.syncAll()
            let devices = (try? await session.devices()) ?? []
            let names = Dictionary(
                devices.map { ($0.id, DeviceRow.reference($0)) }, uniquingKeysWith: { first, _ in first })
            self.lastSync = SyncSummary(report, deviceNames: names)
            if self.phase == .unlocked { try await self.reload() }
        }
    }

    /// The person's choice between conflicting values (PRD F7.6); the values not chosen are discarded.
    func resolveConflict(_ item: Item, group: ItemGroup, choosing value: ItemGroupValue) async {
        guard let session else { return }
        await perform {
            try await session.resolveConflict(itemID: item.id, group: group, choosing: value)
            try await self.reload()
        }
    }

    #if DEBUG
        // MARK: UI-test hooks (Debug builds launched with --uitest only)

        /// The simulated other device renames every item, as if edited there.
        func renameOnOtherDevice() async {
            await onOtherDevice("Renamed on the other device.") { peer, kit in
                try await peer.renameItems(appending: " elsewhere", kit: kit)
            }
        }

        /// The other device joins the account, so the Devices screen has one to remove.
        func joinOtherDevice() async {
            await onOtherDevice("The other device joined.") { peer, kit in try await peer.join(kit: kit) }
        }

        /// The other device changes the account password to `UITestPeer.changedPassword`.
        func changePasswordOnOtherDevice() async {
            await onOtherDevice("The password was changed on the other device.") { peer, kit in
                try await peer.changePassword(kit: kit)
            }
        }

        /// The other device writes a version this one holds aside.
        func makeImplausibleEditOnOtherDevice() async {
            await onOtherDevice("The other device made an implausible edit.") { peer, kit in
                try await peer.makeImplausibleEdit(kit: kit)
            }
        }

        private func onOtherDevice(
            _ done: String, _ body: @escaping @Sendable (UITestPeer, EmergencyKit) async throws -> Void
        ) async {
            guard let uiTestPeer, let session else { return }
            uiTestPeerStatus = nil
            await perform {
                let kit = try await self.uiTestKit(session)
                try await body(uiTestPeer, kit)
                self.uiTestPeerStatus = done
            }
        }

        /// The kit for the other device, opened with the password the test launched with, or the one the other device
        /// changed it to (Z86: the kit needs the account password).
        private func uiTestKit(_ session: VaultSession) async throws -> EmergencyKit {
            let launched = ProcessInfo.processInfo.environment[UITestPeer.passwordVariable] ?? ""
            do {
                return try await session.emergencyKit(password: launched)
            } catch CryptoError.authenticationFailed {
                return try await session.emergencyKit(password: UITestPeer.changedPassword)
            }
        }

        /// The other person's account ID, for the invite screen to fill in.
        func householdAccountID() async -> String? {
            guard let uiTestPeer, let session else { return nil }
            do {
                return try await uiTestPeer.householdAccountID(publishing: session.publicKeyBundle()).uuidString
            } catch {
                show(error)
                return nil
            }
        }

        /// The other person accepts the last invitation the app issued.
        func householdAcceptsInvitation() async {
            guard let uiTestPeer, let invitation = uiTestInvitation else { return }
            uiTestPeerStatus = nil
            await perform {
                try await uiTestPeer.acceptInvitation(invitation)
                self.uiTestPeerStatus = "The other person accepted the invitation."
            }
        }
    #endif

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
        errorMessage = ErrorWording.message(for: error)
    }
}
