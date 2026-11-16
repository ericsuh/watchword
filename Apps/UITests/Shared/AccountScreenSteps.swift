import XCTest

/// Steps the account-screen UI tests and the screenshot tour share. Elements are found by the identifiers in
/// `AccessibilityID` (Apps/Shared/AccessibilityID.swift, compiled into these bundles too).
extension XCUIApplication {
    /// The first element of any type with `identifier`.
    func element(_ identifier: String) -> XCUIElement {
        descendants(matching: .any)[identifier].firstMatch
    }

    /// The element with `identifier`, scrolled to if it is not on screen yet: a form's rows below the fold are not in
    /// the hierarchy until they have been shown.
    @discardableResult
    func reveal(_ identifier: String, file: StaticString = #filePath, line: UInt = #line) -> XCUIElement {
        let target = element(identifier)
        if !target.waitForExistence(timeout: 3) || !target.isHittable {
            // Down the form first, then back up past where it started.
            for towardsEnd in [true, true, true, true, false, false, false, false, false, false, false, false]
            where !(target.exists && target.isHittable) {
                scroll(towardsEnd: towardsEnd)
            }
        }
        XCTAssertTrue(target.waitForExistence(timeout: 10), debugDescription, file: file, line: line)
        return target
    }

    private func scroll(towardsEnd: Bool) {
        #if os(iOS)
            if towardsEnd { swipeUp() } else { swipeDown() }
        #else
            scrollViews.firstMatch.scroll(byDeltaX: 0, deltaY: towardsEnd ? -240 : 240)
        #endif
    }

    /// Opens Settings and, from it, the account screen whose row has `identifier`, which opens in a sheet of its own.
    func openScreen(_ identifier: String, file: StaticString = #filePath, line: UInt = #line) {
        if !buttons["settings.done"].exists { openSettings() }
        reveal(identifier, file: file, line: line).click()
        XCTAssertTrue(
            buttons[AccessibilityID.screenDone].firstMatch.waitForExistence(timeout: 10), debugDescription,
            file: file, line: line)
    }

    /// Closes the account screen's sheet, from whatever is pushed on it, back to Settings.
    func closeScreen(file: StaticString = #filePath, line: UInt = #line) {
        let done = buttons[AccessibilityID.screenDone].firstMatch
        XCTAssertTrue(done.waitForExistence(timeout: 10), debugDescription, file: file, line: line)
        done.click()
        XCTAssertTrue(
            buttons[AccessibilityID.screenDone].firstMatch.waitForNonExistence(timeout: 10), "the screen is still open",
            file: file, line: line)
    }

    /// Clicks the element with `identifier`, scrolling to it first.
    func tap(_ identifier: String, file: StaticString = #filePath, line: UInt = #line) {
        reveal(identifier, file: file, line: line).click()
    }

    /// Clicks the control with `identifier` once it is enabled: one that waits for something the app does first.
    func tapWhenEnabled(_ identifier: String, file: StaticString = #filePath, line: UInt = #line) {
        let target = reveal(identifier, file: file, line: line)
        let enabled = XCTNSPredicateExpectation(predicate: NSPredicate(format: "isEnabled == true"), object: target)
        XCTAssertEqual(XCTWaiter().wait(for: [enabled], timeout: 30), .completed, "\(identifier) stayed disabled")
        target.click()
    }

    /// Types into the text or secure field with `identifier`.
    func enter(_ text: String, into identifier: String, file: StaticString = #filePath, line: UInt = #line) {
        let field = reveal(identifier, file: file, line: line)
        field.click()
        field.typeText(text)
    }

    /// Clicks the button labelled `label` that is not `excluding`: a confirmation dialog's action, whose label
    /// repeats the button that opened it.
    func confirm(_ label: String, excluding identifier: String = "", file: StaticString = #filePath, line: UInt = #line)
    {
        let button = buttons.matching(
            NSPredicate(format: "label == %@ AND identifier != %@", label, identifier)
        ).firstMatch
        XCTAssertTrue(button.waitForExistence(timeout: 10), debugDescription, file: file, line: line)
        button.click()
    }

    /// Waits for the text with `identifier` to contain `text`.
    func waitForText(
        _ text: String, in identifier: String, timeout: TimeInterval = 30, file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let match = descendants(matching: .any).matching(identifier: identifier).matching(
            NSPredicate(format: "label CONTAINS %@ OR value CONTAINS %@", text, text)
        ).firstMatch
        XCTAssertTrue(match.waitForExistence(timeout: timeout), debugDescription, file: file, line: line)
    }

    /// Runs one of the Settings section's UI-test hooks (`UITestPeer`) and waits for its own report, which names what
    /// it did (`AppModel`'s hooks), so an earlier hook's line is not taken for this one's.
    func runPeerHook(_ identifier: String, expecting text: String, file: StaticString = #filePath, line: UInt = #line) {
        if !buttons["settings.done"].exists { openSettings() }
        tap(identifier, file: file, line: line)
        waitForText(text, in: "debug.peerStatus", timeout: 60, file: file, line: line)
    }

    /// An item with a website, a user name and a password typed in (or generated when `password` is nil).
    func addLogin(title: String, host: String, username: String, password: String?) {
        let add = buttons["items.add"]
        XCTAssertTrue(add.waitForExistence(timeout: 10), debugDescription)
        add.click()
        let field = textFields["edit.title"]
        XCTAssertTrue(field.waitForExistence(timeout: 10), debugDescription)
        field.click()
        field.typeText(title)
        textFields["edit.host"].click()
        textFields["edit.host"].typeText(host)
        textFields["edit.username"].click()
        textFields["edit.username"].typeText(username)
        if let password {
            secureTextFields["edit.password"].click()
            secureTextFields["edit.password"].typeText(password)
        } else {
            buttons["edit.generate"].click()
        }
        buttons["edit.save"].click()
        XCTAssertTrue(itemRow(title).waitForExistence(timeout: 10), debugDescription)
        XCTAssertTrue(field.waitForNonExistence(timeout: 10), "the editor is still open")
    }

    /// Locks from the item list and unlocks with `password`, expecting the vault.
    func lockAndUnlock(password: String) {
        backToList()
        let lock = buttons["items.lock"].firstMatch
        XCTAssertTrue(lock.waitForExistence(timeout: 10), debugDescription)
        lock.click()
        let unlock = secureTextFields["unlock.password"]
        XCTAssertTrue(unlock.waitForExistence(timeout: 10), debugDescription)
        unlock.click()
        unlock.typeText(password + "\n")
        XCTAssertTrue(buttons["items.add"].waitForExistence(timeout: 30), debugDescription)
    }

    /// Launches a `--uitest` app for the account-screen tests and creates the account.
    static func launchedWithAccount(arguments: [String] = ["--uitest"]) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = arguments
        app.launchEnvironment["WATCHWORD_UITEST_PASSWORD"] = OnboardingAndUnlockTests.password
        app.launch()
        app.createAccount(password: OnboardingAndUnlockTests.password)
        return app
    }
}
