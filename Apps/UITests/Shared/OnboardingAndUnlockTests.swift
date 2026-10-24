import XCTest

/// Milestone 2 UI smoke test, run on iOS and macOS (docs/04-test-plan.md §5): onboarding with the Emergency Kit
/// confirmation, item creation, lock, a wrong password, unlock, and moving the item to the trash, which needs a
/// confirmation (PRD F1.5, F7.7). The app is launched with `--uitest`, which in Debug builds swaps in in-memory ports,
/// so no real Keychain or vault is touched.
final class OnboardingAndUnlockTests: XCTestCase {
    static let password = "correct horse battery staple"

    override func setUp() {
        continueAfterFailure = false
    }

    @MainActor
    func testOnboardingCreateItemLockAndUnlock() throws {
        let app = XCUIApplication()
        app.launchArguments = ["--uitest"]
        app.launch()

        // Onboarding: a too-short password is refused, then the account is created.
        let password = app.secureTextFields["onboarding.password"]
        XCTAssertTrue(password.waitForExistence(timeout: 10))
        password.click()
        password.typeText("short")
        let confirm = app.secureTextFields["onboarding.confirm"]
        confirm.click()
        confirm.typeText("short\n")
        XCTAssertTrue(app.staticTexts["error"].waitForExistence(timeout: 10))

        password.click()
        password.clearAndType(Self.password)
        confirm.click()
        confirm.clearAndType(Self.password + "\n")

        // Emergency Kit: the Secret Key is shown and Continue needs the confirmation.
        let secretKey = app.staticTexts["kit.secretKey"]
        XCTAssertTrue(secretKey.waitForExistence(timeout: 30))
        let shown = secretKey.displayedText
        XCTAssertTrue(shown.hasPrefix("WW-"), "unexpected Secret Key format: \(shown)")
        XCTAssertFalse(app.buttons["kit.continue"].isEnabled)
        app.switches["kit.confirmSaved"].toggleOn()
        app.buttons["kit.continue"].click()

        // Create an item.
        XCTAssertTrue(app.buttons["items.add"].waitForExistence(timeout: 10), app.debugDescription)
        app.buttons["items.add"].click()
        let title = app.textFields["edit.title"]
        XCTAssertTrue(title.waitForExistence(timeout: 10))
        title.click()
        title.typeText("Library")
        app.textFields["edit.host"].click()
        app.textFields["edit.host"].typeText("citylibrary.org")
        app.textFields["edit.username"].click()
        app.textFields["edit.username"].typeText("pat")
        app.buttons["edit.generate"].click()
        app.buttons["edit.save"].click()
        XCTAssertTrue(app.descendants(matching: .any)["items.row.Library"].waitForExistence(timeout: 10))

        // Lock, fail once, unlock.
        XCTAssertTrue(app.buttons["items.lock"].waitForExistence(timeout: 10), app.debugDescription)
        app.buttons["items.lock"].click()
        let unlock = app.secureTextFields["unlock.password"]
        XCTAssertTrue(unlock.waitForExistence(timeout: 10))
        XCTAssertFalse(app.descendants(matching: .any)["items.row.Library"].exists, "locked vault still shows items")
        unlock.click()
        unlock.typeText("not the password\n")
        XCTAssertTrue(app.staticTexts["error"].waitForExistence(timeout: 30))
        unlock.click()
        unlock.typeText(Self.password + "\n")
        let row = app.descendants(matching: .any)["items.row.Library"]
        XCTAssertTrue(row.waitForExistence(timeout: 30))

        // Move to Trash asks first: the toolbar button only opens the confirmation, and the item stays until the
        // person confirms. The purge 30 days later does not ask again, so this is the explicit action F7.7 needs.
        row.click()
        let trash = app.buttons["detail.trash"]
        XCTAssertTrue(trash.waitForExistence(timeout: 10), app.debugDescription)
        trash.click()
        // The dialog's button may or may not carry its identifier; it is the other button with the same label.
        let confirmTrash = app.buttons.matching(
            NSPredicate(format: "label == %@ AND identifier != %@", "Move to Trash", "detail.trash")
        ).firstMatch
        XCTAssertTrue(confirmTrash.waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertFalse(app.descendants(matching: .any)["detail.empty"].exists, "trashed before the confirmation")
        confirmTrash.click()
        XCTAssertTrue(app.descendants(matching: .any)["detail.empty"].waitForExistence(timeout: 10))
        XCTAssertTrue(row.waitForNonExistence(timeout: 10), "the trashed item is still listed")
    }
}

extension XCUIElement {
    /// The string a SwiftUI `Text` shows. iOS exposes it as the element's label; macOS leaves the label empty and
    /// exposes it as the value.
    var displayedText: String {
        label.isEmpty ? (value as? String ?? "") : label
    }

    func clearAndType(_ text: String) {
        if let value = value as? String, !value.isEmpty {
            #if os(macOS)
                typeKey("a", modifierFlags: .command)
                typeKey(.delete, modifierFlags: [])
            #else
                typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: max(value.count, 20)))
            #endif
        }
        typeText(text)
    }

    /// Turns a SwiftUI `Toggle` on. In an iOS `Form` the switch element spans the whole row and a tap on its centre
    /// does nothing, so the tap goes to the knob at the trailing edge.
    func toggleOn() {
        #if os(macOS)
            click()
        #else
            coordinate(withNormalizedOffset: CGVector(dx: 0.93, dy: 0.5)).tap()
        #endif
        // iOS reports a switch's value as the string "1"; macOS reports a checkbox's as the number 1.
        XCTAssertEqual(value.map { "\($0)" }, "1", "toggle did not turn on")
    }

    #if os(iOS)
        func click() {
            tap()
        }
    #endif
}
