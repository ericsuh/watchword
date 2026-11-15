import XCTest

/// The screenshot tour (docs/04-test-plan.md §5): one pass through every flow the app has, on iOS and macOS, that
/// attaches a picture of each major screen for a person to audit. `mise run app:screenshots` runs it and writes the
/// pictures to `Screenshots/<platform>/`; `app:test` runs it too, as one more end-to-end test, so a change that
/// breaks a flow breaks the tour in the ordinary CI job.
///
/// The app is launched with `--uitest` (in-memory ports, an account this test creates), and the other device in the
/// conflict flow is the in-process `UITestPeer`, as in `SyncConflictTests`. Nothing real is ever on screen.
///
/// To add a screen, drive the app to it here and add one `Screens.capture` line. Capture right after a tap or a
/// keystroke where there is one, because XCUITest waits for animations to finish around those; after something that
/// only appears (a sheet closing, the result of an unlock), wait for the element that proves the screen is complete.
final class ScreenshotTourTests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    @MainActor
    func testTourOfEveryScreen() throws {
        let password = OnboardingAndUnlockTests.password
        let app = XCUIApplication()
        app.launchArguments = Screens.launchArguments
        app.launchEnvironment["WATCHWORD_UITEST_PASSWORD"] = password
        app.launch()
        Screens.prepareDevice()

        // Onboarding. The field has the focus already; the tap lets the keyboard finish arriving on iOS.
        let newPassword = app.secureTextFields["onboarding.password"]
        XCTAssertTrue(newPassword.waitForExistence(timeout: 10), app.debugDescription)
        newPassword.click()
        Screens.capture("onboarding", in: app, showing: "Creating the account: choosing the account password")
        newPassword.typeText(password)
        let confirmation = app.secureTextFields["onboarding.confirm"]
        confirmation.click()
        confirmation.typeText(password + "\n")

        // The Emergency Kit. The tap on the key does nothing; it waits for the keyboard to have gone.
        let secretKey = app.staticTexts["kit.secretKey"]
        XCTAssertTrue(secretKey.waitForExistence(timeout: 30), app.debugDescription)
        secretKey.click()
        Screens.capture(
            "emergency-kit", in: app, showing: "The Emergency Kit: the test account's Secret Key, before confirming")
        app.switches["kit.confirmSaved"].toggleOn()
        app.buttons["kit.continue"].click()

        // The vault, empty.
        let add = app.buttons["items.add"]
        XCTAssertTrue(add.waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertTrue(secretKey.waitForNonExistence(timeout: 10), "the Emergency Kit is still shown")
        Screens.capture("item-list-empty", in: app, showing: "The vault with no items yet")

        // A new item, with a generated password.
        add.click()
        let title = app.textFields["edit.title"]
        XCTAssertTrue(title.waitForExistence(timeout: 10), app.debugDescription)
        title.click()
        title.typeText("Library")
        app.textFields["edit.host"].click()
        app.textFields["edit.host"].typeText("citylibrary.org")
        app.textFields["edit.username"].click()
        app.textFields["edit.username"].typeText("pat")
        app.buttons["edit.generate"].click()
        Screens.capture("item-edit", in: app, showing: "A new item, its password filled in by the generator")
        app.buttons["edit.save"].click()
        XCTAssertTrue(app.itemRow("Library").waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertTrue(title.waitForNonExistence(timeout: 10), "the editor is still open")

        // A second item, so the list has more than one row and there is one to move to the trash.
        add.click()
        XCTAssertTrue(title.waitForExistence(timeout: 10), app.debugDescription)
        title.click()
        title.typeText("Garden club")
        app.textFields["edit.host"].click()
        app.textFields["edit.host"].typeText("gardenclub.org")
        app.buttons["edit.save"].click()
        XCTAssertTrue(app.itemRow("Garden club").waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertTrue(title.waitForNonExistence(timeout: 10), "the editor is still open")
        Screens.capture("item-list", in: app, showing: "The vault with two items")

        // An item, with its password hidden and then shown.
        app.itemRow("Library").firstMatch.click()
        XCTAssertTrue(app.staticTexts["detail.title"].waitForExistence(timeout: 10), app.debugDescription)
        let show = app.buttons["Show"].firstMatch
        XCTAssertTrue(show.waitForExistence(timeout: 10), app.debugDescription)
        Screens.capture("item-detail", in: app, showing: "An item, its password hidden")
        show.click()
        XCTAssertTrue(app.buttons["Hide"].firstMatch.waitForExistence(timeout: 10), app.debugDescription)
        Screens.capture("item-detail-revealed", in: app, showing: "The same item with its generated password shown")

        // Moving the other item to the trash asks first (PRD F1.5, F7.7).
        app.backToList()
        app.itemRow("Garden club").firstMatch.click()
        let trash = app.buttons["detail.trash"].firstMatch
        XCTAssertTrue(trash.waitForExistence(timeout: 10), app.debugDescription)
        trash.click()
        let confirmTrash = app.buttons.matching(
            NSPredicate(format: "label == %@ AND identifier != %@", "Move to Trash", "detail.trash")
        ).firstMatch
        XCTAssertTrue(confirmTrash.waitForExistence(timeout: 10), app.debugDescription)
        Screens.capture("trash-confirmation", in: app, showing: "The confirmation before an item moves to the Trash")
        confirmTrash.click()
        XCTAssertTrue(app.descendants(matching: .any)["detail.empty"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.itemRow("Garden club").waitForNonExistence(timeout: 10), "the trashed item is still listed")

        // Locked, and a wrong password.
        app.backToList()
        let lock = app.buttons["items.lock"].firstMatch
        XCTAssertTrue(lock.waitForExistence(timeout: 10), app.debugDescription)
        lock.click()
        let unlock = app.secureTextFields["unlock.password"]
        XCTAssertTrue(unlock.waitForExistence(timeout: 10), app.debugDescription)
        unlock.click()
        Screens.capture("locked", in: app, showing: "The locked app")
        unlock.typeText("not the password\n")
        XCTAssertTrue(app.staticTexts["error"].waitForExistence(timeout: 30), app.debugDescription)
        Screens.capture("unlock-failed", in: app, showing: "The locked app after a wrong password")
        unlock.click()
        unlock.typeText(password + "\n")
        XCTAssertTrue(app.itemRow("Library").waitForExistence(timeout: 30), app.debugDescription)

        // Settings. A --uitest launch adds the section that drives the other device; a release build has none.
        app.openSettings()
        Screens.capture("settings", in: app, showing: "Settings, with the UI-test section that drives the other device")

        // The item is published, renamed on the other device, and renamed here before this device has seen that.
        app.syncNow()
        app.buttons["debug.peerRename"].click()
        XCTAssertTrue(app.staticTexts["debug.peerStatus"].waitForExistence(timeout: 30), app.debugDescription)
        app.closeSettings()
        app.itemRow("Library").firstMatch.click()
        let edit = app.buttons["detail.edit"].firstMatch
        XCTAssertTrue(edit.waitForExistence(timeout: 10), app.debugDescription)
        edit.click()
        XCTAssertTrue(title.waitForExistence(timeout: 10), app.debugDescription)
        title.click()
        title.clearAndType("Library here")
        app.buttons["edit.save"].click()
        XCTAssertTrue(title.waitForNonExistence(timeout: 10), "the editor is still open")

        // Syncing brings the two names together: the list marks the item, and the item offers both (PRD F7.6).
        app.backToList()
        app.openSettings()
        app.syncNow(expecting: "received")
        app.closeSettings()
        let conflicted = app.descendants(matching: .any).matching(
            NSPredicate(format: "identifier BEGINSWITH %@", "items.row.Library")
        ).firstMatch
        XCTAssertTrue(conflicted.waitForExistence(timeout: 10), app.debugDescription)
        Screens.capture("item-list-conflict", in: app, showing: "The list marking an item changed on two devices")
        conflicted.click()
        XCTAssertTrue(
            app.descendants(matching: .any)["detail.conflicts"].firstMatch.waitForExistence(timeout: 10),
            app.debugDescription)
        XCTAssertTrue(app.buttons["conflict.Title.1"].firstMatch.waitForExistence(timeout: 10), app.debugDescription)
        Screens.capture("conflict-resolution", in: app, showing: "The item offering both names, one to keep")

        Screens.attachIndex()
    }
}

extension XCUIApplication {
    /// The list row of the item with this title. On macOS the identifier lands on each of the row's texts, so
    /// callers click `firstMatch`.
    func itemRow(_ title: String) -> XCUIElement {
        descendants(matching: .any)["items.row.\(title)"]
    }

    /// Dismisses Settings and waits until its sheet has gone, so whatever comes next is not pictured or tapped
    /// through a sheet that is still closing.
    func closeSettings() {
        let done = buttons["settings.done"]
        done.click()
        XCTAssertTrue(done.waitForNonExistence(timeout: 10), "Settings is still open")
    }
}
