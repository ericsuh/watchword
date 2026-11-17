import XCTest

/// Milestone 3 UI test, run on iOS and macOS (docs/04-test-plan.md §5): a version the other device wrote far above
/// anything seen is held aside rather than merged (review finding U5), listed with its item, vault and device, and
/// discarded only by the person's confirmed choice (PRD F7.7). A UI-test launch lowers the jump the app accepts to
/// 16 (`UITestPeer.maximumVersionJump`), so the real sync path produces it.
final class QuarantineTests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
        // A hang fails with a report rather than eating the job (`app:test` turns the allowances on).
        executionTimeAllowance = 600
    }

    @MainActor
    func testDiscardAHeldAsideVersion() throws {
        step("launch")
        let app = XCUIApplication.launchedWithAccount()
        app.addItem(title: "Library")
        app.openSettings()
        app.syncNow()
        step("the implausible edit")
        app.runPeerHook(AccessibilityID.Debug.peerImplausible, expecting: "implausible edit")
        app.syncNow(expecting: "held for review")

        step("quarantine: discard")
        app.openScreen(AccessibilityID.Settings.quarantine)
        let row = app.element(AccessibilityID.Quarantine.row(0))
        XCTAssertTrue(row.waitForExistence(timeout: 15), app.debugDescription)
        XCTAssertTrue(
            app.staticTexts.matching(NSPredicate(format: "label == %@ OR value == %@", "Library", "Library"))
                .firstMatch.exists, "the held-aside version does not name its item")
        app.tap(AccessibilityID.Quarantine.discard(0))
        // Keeping is the default: the dialog's cancel keeps it, and only its Discard removes it.
        app.confirm("Discard")
        XCTAssertTrue(app.element(AccessibilityID.Quarantine.empty).waitForExistence(timeout: 15), app.debugDescription)
        app.closeScreen()
    }
}
