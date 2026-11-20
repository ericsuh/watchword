import Foundation
import Observation

/// When a secret the person revealed on screen is hidden again (PRD F5.7; review §Z, Z95).
///
/// F5.7's two promises are the secure entry fields and the cover over the app-switcher snapshot. Neither reaches a
/// value once it is shown: a revealed password, a one-time-code secret, a conflict or merge value, the Secret Key on
/// the Emergency Kit are plain text, recorded and mirrored like any other. What the app does beyond that, and what
/// this type decides, is to hide every revealed value again whenever the app stops being the active app (an app
/// switch, the notification centre, a call), and whenever the screen starts being captured (a recording, AirPlay, a
/// shared screen, as far as iOS reports it), and to refuse to reveal while it is captured. On macOS the app's windows
/// also ask to be left out of screen capture (`NSWindow.sharingType = .none`), and a value is hidden again when the
/// app resigns active. Whether a shared screen or a recording then shows the windows blank is not promised: later
/// macOS versions are reported to capture them anyway, and docs/04-test-plan.md's manual check for F5.7 is the gate
/// (review finding Z134). It does not stop a camera, and on iOS it cannot stop a capture the system does not report.
///
/// The platform code only reports events; views compare `concealments` with the value they read when a secret was
/// revealed (`RevealedSecrets`), so whatever is open on screen is hidden by the same rule.
@MainActor
@Observable
public final class ScreenPrivacy {
    /// Whether the screen is being recorded, mirrored or shared, as the system reports it.
    public private(set) var isCaptured = false
    /// Increases every time what is revealed must be hidden again.
    public private(set) var concealments: UInt64 = 0

    public init() {}

    /// Whether a secret may be shown now.
    public var mayReveal: Bool { !isCaptured }

    /// The app is no longer the active app (it may be about to be snapshotted or covered by another).
    public func resignedActive() {
        concealments &+= 1
    }

    /// The scenes the system reports captured now. The screen counts as captured while any connected one is (review
    /// finding Z130: an iPad window opened later, or the one scene that was captured closing, must count).
    private var capturedScenes: Set<AnyHashable> = []

    /// The system reports the screen captured or no longer captured, for an app with one scene (macOS reports no
    /// capture). Starting to capture hides everything; ending it reveals nothing again.
    public func captureChanged(_ captured: Bool) {
        captureChanged(captured, in: AnyHashable("the screen"))
    }

    /// The system reports one scene (an iPad window) captured or no longer captured: each connected scene reports,
    /// the first time as it connects and then on every change.
    public func captureChanged(_ captured: Bool, in scene: AnyHashable) {
        if captured {
            capturedScenes.insert(scene)
        } else {
            capturedScenes.remove(scene)
        }
        update()
    }

    /// A scene was disconnected (its window closed): what it last reported no longer counts.
    public func sceneDisconnected(_ scene: AnyHashable) {
        capturedScenes.remove(scene)
        update()
    }

    private func update() {
        let captured = !capturedScenes.isEmpty
        if captured && !isCaptured { concealments &+= 1 }
        isCaptured = captured
    }

    /// The vault locked: whatever is revealed goes with the keys.
    public func locked() {
        concealments &+= 1
    }
}

/// The secrets one screen has revealed, each hidden again by the next concealment (`ScreenPrivacy`). A view keeps one
/// in `@State` and asks `isRevealed`; nothing needs to watch for the events.
public struct RevealedSecrets<ID: Hashable>: Equatable {
    private var revealedAt: [ID: UInt64] = [:]

    public init() {}

    /// Reveals `id`, unless the screen is captured (then `false`, and nothing changes).
    @MainActor
    @discardableResult
    public mutating func reveal(_ id: ID, under privacy: ScreenPrivacy) -> Bool {
        guard privacy.mayReveal else { return false }
        revealedAt[id] = privacy.concealments
        return true
    }

    public mutating func hide(_ id: ID) {
        revealedAt[id] = nil
    }

    /// Shows `id` if hidden, hides it if shown.
    @MainActor
    public mutating func toggle(_ id: ID, under privacy: ScreenPrivacy) {
        if isRevealed(id, under: privacy) { hide(id) } else { reveal(id, under: privacy) }
    }

    /// Whether `id` is shown now: revealed since the last concealment, and the screen not captured.
    @MainActor
    public func isRevealed(_ id: ID, under privacy: ScreenPrivacy) -> Bool {
        privacy.mayReveal && revealedAt[id] == privacy.concealments
    }

    public mutating func hideAll() {
        revealedAt = [:]
    }
}
