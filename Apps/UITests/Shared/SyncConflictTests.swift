import XCTest

/// Milestone 3 UI test, run on iOS and macOS (docs/04-test-plan.md §5): the same item renamed on two devices at once
/// shows both names until the person chooses one (PRD F7.6), and the choice settles it (F7.7). The other device is the
/// app's in-process `UITestPeer`, a second `VaultSession` of the same account syncing over the same in-memory
/// transport, so the whole path runs with the production keyring: AES-GCM records and segments, Ed25519 signatures.
final class SyncConflictTests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    @MainActor
    func testConcurrentRenamesConflictUntilThePersonChooses() throws {
        let app = XCUIApplication()
        app.launchArguments = ["--uitest"]
        app.launchEnvironment["WATCHWORD_UITEST_PASSWORD"] = OnboardingAndUnlockTests.password
        app.launch()
        app.createAccount(password: OnboardingAndUnlockTests.password)

        // An item, published; then the other device renames it.
        app.addItem(title: "Library")
        app.openSettings()
        app.syncNow()
        app.buttons["debug.peerRename"].click()
        XCTAssertTrue(app.staticTexts["debug.peerStatus"].waitForExistence(timeout: 30), app.debugDescription)
        app.buttons["settings.done"].click()

        // Meanwhile it is renamed here too, before this device has seen the other rename.
        let row = app.descendants(matching: .any)["items.row.Library"].firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 10))
        row.click()
        XCTAssertTrue(app.buttons["detail.edit"].firstMatch.waitForExistence(timeout: 10), app.debugDescription)
        app.buttons["detail.edit"].firstMatch.click()
        let title = app.textFields["edit.title"]
        XCTAssertTrue(title.waitForExistence(timeout: 10))
        title.click()
        title.clearAndType("Library here")
        app.buttons["edit.save"].click()
        XCTAssertTrue(app.staticTexts["detail.title"].waitForExistence(timeout: 10), app.debugDescription)

        // Syncing brings the two renames together: both are kept, one shown, the other offered.
        app.backToList()
        app.openSettings()
        app.syncNow(expecting: "received")
        app.buttons["settings.done"].click()
        let renamed = app.descendants(matching: .any).matching(
            NSPredicate(format: "identifier BEGINSWITH %@", "items.row.Library")
        ).firstMatch
        XCTAssertTrue(renamed.waitForExistence(timeout: 10), app.debugDescription)
        renamed.click()
        let conflicts = app.descendants(matching: .any)["detail.conflicts"].firstMatch
        XCTAssertTrue(conflicts.waitForExistence(timeout: 10), app.debugDescription)
        let shown = app.staticTexts["conflict.Title.0.value"].displayedText
        let other = app.staticTexts["conflict.Title.1.value"].displayedText
        XCTAssertEqual(Set([shown, other]), ["Library here", "Library elsewhere"])
        XCTAssertEqual(app.staticTexts["detail.title"].displayedText, shown)

        // The person keeps the other one: it is shown, and the conflict is gone.
        app.buttons["conflict.Title.1"].click()
        XCTAssertTrue(conflicts.waitForNonExistence(timeout: 10), "the conflict is still shown")
        XCTAssertTrue(
            app.staticTexts.matching(identifier: "detail.title").matching(
                NSPredicate(format: "label == %@ OR value == %@", other, other)
            ).firstMatch.waitForExistence(timeout: 10), app.debugDescription)

        // The choice is a new version, published like any edit.
        app.backToList()
        app.openSettings()
        app.syncNow(expecting: "sent")
    }
}

extension XCUIApplication {
    /// Onboarding through to the empty vault, confirming the Emergency Kit.
    func createAccount(password: String) {
        let field = secureTextFields["onboarding.password"]
        XCTAssertTrue(field.waitForExistence(timeout: 10))
        field.click()
        field.typeText(password)
        let confirm = secureTextFields["onboarding.confirm"]
        confirm.click()
        confirm.typeText(password + "\n")
        XCTAssertTrue(staticTexts["kit.secretKey"].waitForExistence(timeout: 30))
        switches["kit.confirmSaved"].toggleOn()
        buttons["kit.continue"].click()
        XCTAssertTrue(buttons["items.add"].waitForExistence(timeout: 10), debugDescription)
    }

    func addItem(title: String) {
        buttons["items.add"].click()
        let field = textFields["edit.title"]
        XCTAssertTrue(field.waitForExistence(timeout: 10))
        field.click()
        field.typeText(title)
        buttons["edit.save"].click()
        XCTAssertTrue(descendants(matching: .any)["items.row.\(title)"].waitForExistence(timeout: 10))
    }

    func openSettings() {
        let settings = buttons["items.settings"].firstMatch
        XCTAssertTrue(settings.waitForExistence(timeout: 10), debugDescription)
        settings.click()
        XCTAssertTrue(buttons["settings.syncNow"].waitForExistence(timeout: 10), debugDescription)
    }

    /// Taps Sync Now and waits for a status that mentions `expecting`.
    func syncNow(expecting: String = "sent") {
        buttons["settings.syncNow"].click()
        let status = staticTexts.matching(identifier: "settings.syncStatus").matching(
            NSPredicate(format: "label CONTAINS %@ OR value CONTAINS %@", expecting, expecting)
        ).firstMatch
        XCTAssertTrue(status.waitForExistence(timeout: 30), debugDescription)
    }

    /// On iPhone the list and the detail are one navigation stack, and Settings lives on the list. On iPad and the
    /// Mac both columns are on screen, so there is nothing to do.
    func backToList() {
        #if os(iOS)
            let settings = buttons["items.settings"].firstMatch
            if !(settings.exists && settings.isHittable) {
                navigationBars.buttons.element(boundBy: 0).tap()
            }
        #endif
    }
}
