import XCTest

/// Milestone 7 UI tests, run on iOS and macOS (docs/04-test-plan.md §5): an import whose duplicate must be decided,
/// where a merge names each website it would add and adds only the one accepted (PRD F8.2, F11.2); and an export that
/// shows the plaintext warning and the report before the file is saved, and a backup restored with its date shown
/// (F8.4, F8.5). The import reads `UITestSamples.importCSV` through a UI-test button rather than the system's file
/// picker, which XCUITest cannot drive reliably on both platforms.
final class ImportExportTests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    @MainActor
    func testImportWithADuplicate() throws {
        let app = XCUIApplication.launchedWithAccount()
        app.addLogin(title: "Library", host: "citylibrary.org", username: "pat", password: nil)

        app.openScreen(AccessibilityID.Settings.importItems)
        app.tap(AccessibilityID.Import.uiTestSample)
        XCTAssertTrue(app.element(AccessibilityID.Import.duplicate("Library")).waitForExistence(timeout: 30))
        XCTAssertFalse(app.reveal(AccessibilityID.Import.commit).isEnabled, "imported before the duplicate was decided")

        app.tap(AccessibilityID.Import.choice("Library") + ".merge")
        let host = app.switches[AccessibilityID.Import.host("www.citylibrary.org")].firstMatch
        XCTAssertTrue(host.waitForExistence(timeout: 30), app.debugDescription)
        XCTAssertEqual(host.value.map { "\($0)" }, "0", "a website accepted for the person")
        XCTAssertTrue(app.element(AccessibilityID.Import.reveal("Password")).exists, "the password shown, not hidden")
        host.toggleOn()
        app.tapWhenEnabled(AccessibilityID.Import.commit)
        app.waitForText("1 added, 1 merged", in: AccessibilityID.Import.summary)
        app.tap(AccessibilityID.Import.done)
        app.closeSettings()

        // The accepted website is the item's now.
        app.itemRow("Library").firstMatch.click()
        XCTAssertTrue(
            app.staticTexts.matching(
                NSPredicate(format: "label == %@ OR value == %@", "www.citylibrary.org", "www.citylibrary.org")
            ).firstMatch.waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertTrue(app.itemRow("Garden club").exists)
    }

    @MainActor
    func testExportShowsTheReportAndABackupRestores() throws {
        let app = XCUIApplication.launchedWithAccount()
        app.addLogin(title: "Library", host: "citylibrary.org", username: "pat", password: nil)

        app.openScreen(AccessibilityID.Settings.export)
        XCTAssertTrue(app.element(AccessibilityID.Export.warning).waitForExistence(timeout: 10))
        app.tap(AccessibilityID.Export.kind + ".applePasswordsCSV")
        app.enter(OnboardingAndUnlockTests.password, into: AccessibilityID.Export.password)
        app.tap(AccessibilityID.Export.run)
        app.waitForText("1 item(s)", in: AccessibilityID.Export.count)
        XCTAssertTrue(app.element(AccessibilityID.Export.save).exists)
        XCTAssertTrue(app.element(AccessibilityID.Export.warning).exists, "the warning went once the file existed")

        app.tap(AccessibilityID.Export.kind + ".archive")
        app.enter(OnboardingAndUnlockTests.password, into: AccessibilityID.Export.password)
        app.enter("garden shed padlock", into: AccessibilityID.Export.passphrase)
        app.enter("garden shed padlock", into: AccessibilityID.Export.passphraseConfirmation)
        app.tap(AccessibilityID.Export.run)
        app.waitForText("1 item(s)", in: AccessibilityID.Export.count)
        app.closeScreen()

        app.openScreen(AccessibilityID.Settings.restore)
        app.enter("garden shed padlock", into: AccessibilityID.Import.passphrase)
        app.tap(AccessibilityID.Import.uiTestArchive)
        XCTAssertTrue(
            app.element(AccessibilityID.Import.archiveDate).waitForExistence(timeout: 60), app.debugDescription)
        app.tap(AccessibilityID.Import.choice("Library") + ".skip")
        app.tapWhenEnabled(AccessibilityID.Import.commit)
        app.waitForText("1 skipped", in: AccessibilityID.Import.summary)
        app.tap(AccessibilityID.Import.done)
    }
}
