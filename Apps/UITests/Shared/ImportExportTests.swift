import XCTest

/// Milestone 7 UI tests, run on iOS and macOS (docs/04-test-plan.md §5), in three launches, each within its allowance:
/// - an import whose duplicate must be decided first, where a merge names the website it would add, off until
///   accepted, with the password hidden (PRD F8.2, F11.2), and a lock with that review open, after which it is gone
///   (review of the account screens, finding 6);
/// - an export that shows the plaintext warning and the report before the file is saved, gone after a lock too
///   (F8.4);
/// - a backup made and restored, with its date shown (F8.5).
/// The import reads `UITestSamples.importCSV`, and the restore the archive just made, through UI-test buttons rather
/// than the system's file picker, which XCUITest cannot drive reliably on both platforms; "Lock now" is a Debug-only
/// stand-in for auto-lock with the screen up. Each step prints a timestamped `STEP` line, so a run that stops (the
/// first iOS run timed out evaluating a query, with no diagnostics) says where from the log.
final class ImportExportTests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
        // A hang fails with a report rather than eating the job (`app:test` turns the allowances on).
        executionTimeAllowance = 600
    }

    @MainActor
    func testImportWithADuplicateAndALockDuringTheReview() throws {
        step("launch")
        let app = XCUIApplication.launchedWithAccount()
        let password = OnboardingAndUnlockTests.password
        app.addLogin(title: "Library", host: "citylibrary.org", username: "pat", password: nil)

        step("import: open")
        app.openScreen(AccessibilityID.Settings.importItems)
        step("import: read the sample")
        app.tap(AccessibilityID.Import.uiTestSample)
        XCTAssertTrue(app.element(AccessibilityID.Import.duplicate("Library")).appears(within: 15))
        step("review: the duplicate needs a choice")
        XCTAssertFalse(app.reveal(AccessibilityID.Import.commit, mayBeDisabled: true).isEnabled, "imported undecided")
        step("merge: choose")
        app.tap(AccessibilityID.Import.choice("Library") + ".merge")
        app.reveal(AccessibilityID.Import.host("www.citylibrary.org"))
        let host = app.switches[AccessibilityID.Import.host("www.citylibrary.org")].firstMatch
        XCTAssertEqual(host.value.map { "\($0)" }, "0", "a website accepted for the person")
        XCTAssertTrue(app.reveal(AccessibilityID.Import.reveal("Password")).isPresent, "the password shown, not hidden")

        step("lock: with the review open")
        app.tap(AccessibilityID.Import.reveal("Password"))
        app.tap(AccessibilityID.Debug.lockNow)
        let unlock = app.secureTextFields["unlock.password"]
        XCTAssertTrue(unlock.appears(within: 10), app.debugDescription)
        XCTAssertFalse(host.isPresent, "the review is still on screen after the lock")
        step("lock: unlock")
        unlock.click()
        unlock.enterText(password + "\n")
        XCTAssertTrue(app.buttons["items.add"].appears(within: 15), app.debugDescription)
        step("import: open again")
        app.openScreen(AccessibilityID.Settings.importItems)
        XCTAssertTrue(app.element(AccessibilityID.Import.uiTestSample).appears(within: 5))
        XCTAssertFalse(
            app.element(AccessibilityID.Import.duplicate("Library")).isPresent, "the review outlived the lock")

        step("import: to the end")
        app.tap(AccessibilityID.Import.uiTestSample)
        app.tap(AccessibilityID.Import.choice("Library") + ".merge")
        app.reveal(AccessibilityID.Import.host("www.citylibrary.org"))
        app.switches[AccessibilityID.Import.host("www.citylibrary.org")].firstMatch.toggleOn()
        app.tapWhenEnabled(AccessibilityID.Import.commit)
        app.waitForText("1 added, 1 merged", in: AccessibilityID.Import.summary)
        app.tap(AccessibilityID.Import.done)
        app.closeSettings()
        step("import: the accepted website on the item")
        app.itemRow("Library").firstMatch.click()
        XCTAssertTrue(
            app.staticTexts.matching(
                NSPredicate(format: "label == %@ OR value == %@", "www.citylibrary.org", "www.citylibrary.org")
            ).firstMatch.appears(within: 5), app.debugDescription)
        step("done")
    }

    @MainActor
    func testExportReportAndALock() throws {
        step("launch")
        let app = XCUIApplication.launchedWithAccount()
        let password = OnboardingAndUnlockTests.password
        app.addLogin(title: "Library", host: "citylibrary.org", username: "pat", password: nil)

        step("export: open")
        app.openScreen(AccessibilityID.Settings.export)
        XCTAssertTrue(app.element(AccessibilityID.Export.warning).appears(within: 5))
        step("export: CSV")
        app.tap(AccessibilityID.Export.kind + ".applePasswordsCSV")
        app.enter(password, into: AccessibilityID.Export.password)
        app.tap(AccessibilityID.Export.run)
        step("report")
        app.waitForText("item(s) in the file", in: AccessibilityID.Export.count)
        app.reveal(AccessibilityID.Export.save, at: .below)
        // Scrolled back to: rows out of view leave the hierarchy, so the warning is checked where it stands.
        app.reveal(AccessibilityID.Export.warning, at: .top)

        step("lock: with the report open")
        app.tap(AccessibilityID.Debug.lockNow)
        let unlock = app.secureTextFields["unlock.password"]
        XCTAssertTrue(unlock.appears(within: 10), app.debugDescription)
        step("lock: unlock")
        unlock.click()
        unlock.enterText(password + "\n")
        XCTAssertTrue(app.buttons["items.add"].appears(within: 15), app.debugDescription)
        step("export: open again")
        app.openScreen(AccessibilityID.Settings.export)
        XCTAssertTrue(app.element(AccessibilityID.Export.warning).appears(within: 5))
        XCTAssertFalse(app.element(AccessibilityID.Export.count).isPresent, "the report outlived the lock")
        step("done")
    }

    /// The other half of what was one test with the export above: a backup made and then restored. Apart, each is a
    /// launch and a handful of screens, well inside its allowance on a slow simulator; together they ran 439 s of 600
    /// on a good CI run and past 600 on a slow one.
    @MainActor
    func testBackUpAndRestore() throws {
        step("launch")
        let app = XCUIApplication.launchedWithAccount()
        let password = OnboardingAndUnlockTests.password
        app.addLogin(title: "Library", host: "citylibrary.org", username: "pat", password: nil)

        step("export: open")
        app.openScreen(AccessibilityID.Settings.export)
        XCTAssertTrue(app.element(AccessibilityID.Export.warning).appears(within: 5))
        step("export: archive")
        app.tap(AccessibilityID.Export.kind + ".archive")
        app.enter(password, into: AccessibilityID.Export.password)
        app.enter("garden shed padlock", into: AccessibilityID.Export.passphrase)
        app.enter("garden shed padlock", into: AccessibilityID.Export.passphraseConfirmation)
        app.tap(AccessibilityID.Export.run)
        app.waitForText("item(s) in the file", in: AccessibilityID.Export.count, timeout: 20)
        step("restore: open")
        app.openScreen(AccessibilityID.Settings.restore)
        app.enter("garden shed padlock", into: AccessibilityID.Import.passphrase)
        step("restore: read the archive")
        app.tap(AccessibilityID.Import.uiTestArchive)
        XCTAssertTrue(
            app.element(AccessibilityID.Import.archiveDate).appears(within: 20), app.debugDescription)
        app.closeScreen()
        step("done")
    }
}
