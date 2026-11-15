import XCTest

#if canImport(UIKit)
    import UIKit
#endif

/// Screenshot capture for the screenshot tour (docs/04-test-plan.md §5): each call attaches one picture of the app to
/// the running test, kept whether or not the test passes, under a name `mise run app:screenshots` turns into
/// `Screenshots/<platform>/<name>.png`.
///
/// Adding a screen to the tour is one line where the tour reaches it:
///
///     Screens.capture("vault-list", in: app, showing: "Every vault this account can open")
///
/// Names are numbered in the order they are captured (`07-vault-list`), so the files sort in flow order and a screen
/// added in the middle renumbers the ones after it. A name is lower-case words joined by hyphens and is used once.
///
/// Only a `--uitest` launch may be captured: in-memory ports and an account made by the test itself, so no real vault,
/// Keychain item or secret is ever in a picture. The Secret Key and the passwords that do appear belong to that
/// throwaway account and are generated afresh on every run.
@MainActor
enum Screens {
    /// The name of the text attachment that lists every captured screen, one `name<TAB>caption` line each, which is
    /// how `app:screenshots` knows what to expect in the result bundle.
    static let indexName = "screens-index"

    /// What the task sets (through xcodebuild's `TEST_RUNNER_` prefix) to ask for the dark set.
    static let appearanceVariable = "WATCHWORD_SCREENSHOT_APPEARANCE"

    /// Every screen captured so far in this test process, in order.
    private static var captured: [(name: String, caption: String)] = []

    /// `07-item-detail` for the seventh screen: the name of its attachment and, later, of its file.
    private static func numbered(_ name: String, at position: Int) -> String {
        (position < 10 ? "0" : "") + "\(position)-\(name)"
    }

    /// The arguments every tour launch needs: `--uitest`, and `--uitest-dark` when the dark set was asked for.
    static var launchArguments: [String] {
        let dark = ProcessInfo.processInfo.environment[appearanceVariable] == "dark"
        return dark ? ["--uitest", "--uitest-dark"] : ["--uitest"]
    }

    /// An iPad is toured in landscape, where the list and the detail are side by side as they are on the Mac. An
    /// iPhone stays in portrait, and the Mac has no orientation.
    static func prepareDevice() {
        #if os(iOS)
            if UIDevice.current.userInterfaceIdiom == .pad {
                XCUIDevice.shared.orientation = .landscapeLeft
            }
        #endif
    }

    /// Attaches a picture of the app as it is now: the app's window on macOS (not the whole screen, which would show
    /// whatever else is on the machine), the whole screen on iOS (so the keyboard and system dialogs are in it).
    ///
    /// Capture after the thing that settles the screen: XCUITest waits for the app to be idle around every tap and
    /// keystroke, so a capture that follows one sees finished animations, and one that follows only
    /// `waitForExistence` may catch a sheet or the keyboard half way.
    ///
    /// - Parameters:
    ///   - name: Lower-case words joined by hyphens, such as `item-detail`; unique within the run.
    ///   - app: The app under test, launched with `launchArguments`.
    ///   - caption: One line for the index saying what the picture should show.
    static func capture(
        _ name: String, in app: XCUIApplication, showing caption: String = "",
        file: StaticString = #filePath, line: UInt = #line
    ) {
        let allowed = Set("abcdefghijklmnopqrstuvwxyz0123456789-")
        let wellFormed =
            !name.isEmpty && name.count <= 40 && name.allSatisfy(allowed.contains)
            && !name.hasPrefix("-") && !name.hasSuffix("-") && !name.contains("--")
        guard wellFormed, captured.count < 99, !captured.contains(where: { $0.name == name }) else {
            XCTFail("'\(name)' is not a usable screen name, or was captured already", file: file, line: line)
            return
        }
        guard app.launchArguments.contains("--uitest") else {
            XCTFail(
                "only a --uitest launch may be captured: anything else could show a real vault", file: file, line: line)
            return
        }
        let label = numbered(name, at: captured.count + 1)

        #if os(macOS)
            let window = app.windows.firstMatch
            guard window.waitForExistence(timeout: 10) else {
                XCTFail("no window to capture for \(label)", file: file, line: line)
                return
            }
            let screenshot = window.screenshot()
        #else
            let screenshot = XCUIScreen.main.screenshot()
        #endif

        let attachment = XCTAttachment(screenshot: screenshot)
        attachment.name = label
        attachment.lifetime = .keepAlways
        XCTContext.runActivity(named: "Screen \(label)") { $0.add(attachment) }
        // A tab or a line break in a caption would break the index's one-line-per-screen format.
        let oneLine = caption.split(whereSeparator: { $0.isNewline || $0 == "\t" }).joined(separator: " ")
        captured.append((name, oneLine))
    }

    /// Attaches the list of everything captured so far in this run. A tour calls it last: a tour that fails part way
    /// attaches no index, and the task reports that rather than an incomplete set.
    static func attachIndex() {
        let lines = captured.enumerated().map { "\(numbered($1.name, at: $0 + 1))\t\($1.caption)\n" }.joined()
        let attachment = XCTAttachment(string: lines)
        attachment.name = indexName
        attachment.lifetime = .keepAlways
        XCTContext.runActivity(named: "Screens index (\(captured.count) screens)") { $0.add(attachment) }
    }
}
