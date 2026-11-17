import XCTest

/// Milestone 7 UI test, run on iOS and macOS (docs/04-test-plan.md §5), in one launch to keep the iOS job short:
/// - an import whose duplicate must be decided first, where a merge names the website it would add, off until
///   accepted, with the password hidden (PRD F8.2, F11.2);
/// - a lock with the merge review open, after which it is gone (review of the account screens, finding 6);
/// - an export that shows the plaintext warning and the report before the file is saved, gone after a lock too;
/// - a backup restored with its date shown (F8.4, F8.5).
/// The import reads `UITestSamples.importCSV`, and the restore the archive just made, through UI-test buttons rather
/// than the system's file picker, which XCUITest cannot drive reliably on both platforms; "Lock now" is a Debug-only
/// stand-in for auto-lock with the screen up.
final class ImportExportTests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
        // A hang fails with a report rather than eating the job (`app:test` turns the allowances on).
        executionTimeAllowance = 300
    }

    @MainActor
    func testImportExportRestoreAndLock() throws {
        let app = XCUIApplication.launchedWithAccount()
        let password = OnboardingAndUnlockTests.password
        app.addLogin(title: "Library", host: "citylibrary.org", username: "pat", password: nil)

        // A duplicate is decided before anything is imported; a merge adds only the host accepted.
        app.openScreen(AccessibilityID.Settings.importItems)
        app.tap(AccessibilityID.Import.uiTestSample)
        XCTAssertTrue(app.element(AccessibilityID.Import.duplicate("Library")).waitForExistence(timeout: 15))
        XCTAssertFalse(
            app.reveal(AccessibilityID.Import.commit, mayBeDisabled: true).isEnabled,
            "imported before the duplicate was decided")
        app.tap(AccessibilityID.Import.choice("Library") + ".merge")
        app.reveal(AccessibilityID.Import.host("www.citylibrary.org"))
        let host = app.switches[AccessibilityID.Import.host("www.citylibrary.org")].firstMatch
        XCTAssertEqual(host.value.map { "\($0)" }, "0", "a website accepted for the person")
        XCTAssertTrue(app.reveal(AccessibilityID.Import.reveal("Password")).exists, "the password shown, not hidden")

        // A lock with the review open: after unlocking, the review is gone.
        app.tap(AccessibilityID.Import.reveal("Password"))
        app.tap(AccessibilityID.Debug.lockNow)
        let unlock = app.secureTextFields["unlock.password"]
        XCTAssertTrue(unlock.waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertFalse(host.exists, "the review is still on screen after the lock")
        unlock.click()
        unlock.typeText(password + "\n")
        XCTAssertTrue(app.buttons["items.add"].waitForExistence(timeout: 15), app.debugDescription)
        app.openScreen(AccessibilityID.Settings.importItems)
        XCTAssertTrue(app.element(AccessibilityID.Import.uiTestSample).waitForExistence(timeout: 5))
        XCTAssertFalse(app.element(AccessibilityID.Import.duplicate("Library")).exists, "the review outlived the lock")

        // Again, to the end.
        app.tap(AccessibilityID.Import.uiTestSample)
        app.tap(AccessibilityID.Import.choice("Library") + ".merge")
        app.reveal(AccessibilityID.Import.host("www.citylibrary.org"))
        app.switches[AccessibilityID.Import.host("www.citylibrary.org")].firstMatch.toggleOn()
        app.tapWhenEnabled(AccessibilityID.Import.commit)
        app.waitForText("1 added, 1 merged", in: AccessibilityID.Import.summary)
        app.tap(AccessibilityID.Import.done)
        app.closeSettings()
        app.itemRow("Library").firstMatch.click()
        XCTAssertTrue(
            app.staticTexts.matching(
                NSPredicate(format: "label == %@ OR value == %@", "www.citylibrary.org", "www.citylibrary.org")
            ).firstMatch.waitForExistence(timeout: 5), app.debugDescription)

        // A plaintext export's warning and report, gone after a lock.
        app.openScreen(AccessibilityID.Settings.export)
        XCTAssertTrue(app.element(AccessibilityID.Export.warning).waitForExistence(timeout: 5))
        app.tap(AccessibilityID.Export.kind + ".applePasswordsCSV")
        app.enter(password, into: AccessibilityID.Export.password)
        app.tap(AccessibilityID.Export.run)
        app.waitForText("item(s) in the file", in: AccessibilityID.Export.count)
        app.reveal(AccessibilityID.Export.save, at: .below)
        // Scrolled back to: rows out of view leave the hierarchy, so the warning is checked where it stands.
        app.reveal(AccessibilityID.Export.warning, at: .top)
        app.tap(AccessibilityID.Debug.lockNow)
        XCTAssertTrue(unlock.waitForExistence(timeout: 10), app.debugDescription)
        unlock.click()
        unlock.typeText(password + "\n")
        XCTAssertTrue(app.buttons["items.add"].waitForExistence(timeout: 15), app.debugDescription)
        app.openScreen(AccessibilityID.Settings.export)
        XCTAssertTrue(app.element(AccessibilityID.Export.warning).waitForExistence(timeout: 5))
        XCTAssertFalse(app.element(AccessibilityID.Export.count).exists, "the report outlived the lock")

        // A backup, restored with its date shown.
        app.tap(AccessibilityID.Export.kind + ".archive")
        app.enter(password, into: AccessibilityID.Export.password)
        app.enter("garden shed padlock", into: AccessibilityID.Export.passphrase)
        app.enter("garden shed padlock", into: AccessibilityID.Export.passphraseConfirmation)
        app.tap(AccessibilityID.Export.run)
        app.waitForText("item(s) in the file", in: AccessibilityID.Export.count, timeout: 20)
        app.openScreen(AccessibilityID.Settings.restore)
        app.enter("garden shed padlock", into: AccessibilityID.Import.passphrase)
        app.tap(AccessibilityID.Import.uiTestArchive)
        XCTAssertTrue(
            app.element(AccessibilityID.Import.archiveDate).waitForExistence(timeout: 20), app.debugDescription)
        app.closeScreen()
    }
}
