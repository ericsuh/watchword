import Foundation
import Observation
import WatchwordKit

/// The Emergency Kit screen (PRD F5.1, F10.2): the Secret Key on screen and the kit's PDF for the file mover.
///
/// Opened two ways. With a kit, during onboarding: the one `createAccount` returned, or after a password unlock the
/// one the person has not confirmed yet (`VaultSession.unconfirmedEmergencyKit`). Without one, from Settings: the
/// account password is asked for and checked by the session in the same call (`emergencyKit(password:)`, Z86), so
/// whoever holds the unlocked app, quick-unlocked or not, cannot read out the Secret Key.
///
/// The PDF is written by the app itself into the swept `StagingFolder` (on iOS with complete protection: the kit is
/// saved only while the app is in front) and handed to the file mover, as an export is, not to the system's file
/// exporter, which says nothing about what it stages (Z84). The staged copy goes when the mover is done, when the
/// screen closes and on every lock, and with the folder at the next launch if the process dies first. The Secret Key
/// is hidden again whenever `ScreenPrivacy` conceals (Z95). The formatted key is a `String`, not wipeable (SEC4);
/// the model drops it on close and on lock.
@MainActor
@Observable
public final class EmergencyKitModel: LockSensitive {
    /// The PDF's file name.
    public static let filename = "Watchword Emergency Kit.pdf"
    /// The standing line about where to keep it (`EmergencyKitText.storageWarning`).
    public static let storageWarning = EmergencyKitText.storageWarning

    /// The kit, once shown: given for onboarding, or opened with the password.
    public private(set) var kit: EmergencyKit?
    public var password = ""
    public private(set) var isWorking = false
    public var errorMessage: String?
    /// Whether this is onboarding's kit, which the person confirms having saved.
    public let isOnboarding: Bool
    public let staging: StagingFolder

    private let context: ScreenContext
    private let privacy: ScreenPrivacy
    /// The concealment count when the key was last shown; it is shown only while that is still the count.
    private var shownAt: UInt64?
    /// The PDF in `staging`, until the mover is done with it.
    public private(set) var stagedPDF: URL?

    public init(
        context: ScreenContext, privacy: ScreenPrivacy, kit: EmergencyKit? = nil, staging: StagingFolder = .standard
    ) {
        self.context = context
        self.privacy = privacy
        self.kit = kit
        self.isOnboarding = kit != nil
        self.staging = staging
        if kit != nil, privacy.mayReveal { shownAt = privacy.concealments }
        context.locks?.register(self)
    }

    /// The password is still to be asked for.
    public var needsPassword: Bool { kit == nil }

    /// Whether the Secret Key is on screen now: shown since the last concealment, and the screen not captured.
    public var showsSecretKey: Bool {
        kit != nil && privacy.mayReveal && shownAt == privacy.concealments
    }

    /// Why the key is hidden, when it is.
    public var hiddenReason: String? {
        guard kit != nil, !showsSecretKey else { return nil }
        return privacy.isCaptured
            ? "Hidden while your screen is being recorded or shared."
            : "Hidden while Watchword was in the background."
    }

    /// Opens the kit with the account password, which goes as soon as it is handed over.
    public func open() async {
        let password = self.password
        self.password = ""
        guard !password.isEmpty else {
            errorMessage = "Enter your account password."
            return
        }
        isWorking = true
        defer { isWorking = false }
        errorMessage = await ScreenOperation(context: context).run {
            let opened = try await context.session.emergencyKit(password: password)
            kit = opened
            shownAt = privacy.mayReveal ? privacy.concealments : nil
        }
    }

    /// Shows the key again after a concealment; refused while the screen is captured.
    public func revealSecretKey() {
        guard kit != nil, privacy.mayReveal else { return }
        shownAt = privacy.concealments
    }

    /// Writes the PDF into a folder of its own in `staging` with `render`, which the app gives (the PDF is drawn by
    /// `WatchwordPlatform`) and which writes the file with `options`. Returns the file for the mover.
    public func stagePDF(
        options: Data.WritingOptions, render: (EmergencyKit, URL, Data.WritingOptions) throws -> Void
    ) throws -> URL {
        guard let kit else { throw CocoaError(.fileNoSuchFile) }
        removeStagedPDF()
        let url = try staging.stage(named: Self.filename) { url in
            try render(kit, url, options.union(.withoutOverwriting))
        }
        stagedPDF = url
        return url
    }

    /// After the mover, saved or not: the staged copy goes.
    public func finishSaving() {
        removeStagedPDF()
    }

    /// The screen closes: the staged copy, the typed password and, outside onboarding, the kit go.
    public func close() {
        removeStagedPDF()
        password = ""
        if !isOnboarding { kit = nil }
        shownAt = nil
    }

    public func dropOnLock() {
        removeStagedPDF()
        password = ""
        kit = nil
        shownAt = nil
    }

    private func removeStagedPDF() {
        if let stagedPDF { staging.remove(stagedPDF) }
        stagedPDF = nil
    }
}
