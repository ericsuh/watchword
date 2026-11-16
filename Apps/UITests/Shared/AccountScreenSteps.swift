import XCTest

/// Steps the account-screen UI tests and the screenshot tour share. Elements are found by the identifiers in
/// `AccessibilityID` (Apps/Shared/AccessibilityID.swift, compiled into these bundles too).
extension XCUIApplication {
    /// The first element of any type with `identifier`.
    func element(_ identifier: String) -> XCUIElement {
        descendants(matching: .any)[identifier].firstMatch
    }

    /// Where a form's target is likely to be, so that `reveal` scrolls that way first.
    enum FormPosition {
        /// Near the top (Settings' Sync Now and UI-test section): scroll back up only.
        case top
        /// Below the fold (Settings' account rows, a review's last buttons): scroll down only.
        case below
        /// Either: down a little first, then up.
        case anywhere
    }

    /// The element with `identifier`, scrolled to if it is not on screen yet: a form's rows out of view are not in the
    /// hierarchy until they have been shown, and on macOS a row that is in the hierarchy may still be clipped. Bounded:
    /// a few short waits and at most eight scrolls, so a missing element fails in seconds, with the tree attached.
    @discardableResult
    func reveal(
        _ identifier: String, at position: FormPosition = .anywhere, mayBeDisabled: Bool = false,
        file: StaticString = #filePath, line: UInt = #line
    ) -> XCUIElement {
        let target = element(identifier)
        if !(target.waitForExistence(timeout: 2) && target.isHittable) {
            let steps: [Bool]
            switch position {
            case .top: steps = Array(repeating: false, count: 6)
            case .below: steps = Array(repeating: true, count: 6)
            case .anywhere: steps = [true, true, true, false, false, false, false, false]
            }
            for towardsEnd in steps where !(target.exists && target.isHittable) {
                scroll(towardsEnd: towardsEnd, to: identifier)
            }
        }
        if !target.waitForExistence(timeout: 2) {
            attachTree("reveal \(identifier)")
            XCTFail("\(identifier) was not found", file: file, line: line)
        } else if !mayBeDisabled, !waitUntilHittable(target, timeout: 2) {
            // In the hierarchy but not reachable: off the screen, or under a sheet that is still there.
            attachTree("reveal \(identifier)")
            XCTFail("\(identifier) is not hittable", file: file, line: line)
        }
        return target
    }

    /// One step of scrolling the frontmost form. On iOS a swipe, which lands on whatever is on top (a sheet included).
    /// On macOS a scroll-wheel event, which needs a scroll view the pointer can reach: the one holding the target if it
    /// is in the hierarchy, else the frontmost sheet's (sheets nest, so the last one listed is on top), never one a
    /// sheet covers. Nothing is scrolled when there is no such view, so the caller's own check reports what is missing.
    private func scroll(towardsEnd: Bool, to identifier: String) {
        #if os(iOS)
            if towardsEnd { swipeUp() } else { swipeDown() }
        #else
            let holding = scrollViews.containing(.any, identifier: identifier).allElementsBoundByIndex.last
            let frontmost = sheets.allElementsBoundByIndex.last?.scrollViews.firstMatch
            for candidate in [holding, frontmost, windows.firstMatch.scrollViews.firstMatch].compactMap({ $0 })
            where candidate.exists && candidate.isHittable {
                candidate.scroll(byDeltaX: 0, deltaY: towardsEnd ? -240 : 240)
                return
            }
        #endif
    }

    /// Attaches the whole element tree to the running test, kept whether or not it passes, for a failure that the
    /// assertion's own message cannot explain (which window or sheet an element is in, and whether it is hittable).
    func attachTree(_ reason: String) {
        // The window's frame beside the tree: an element outside the screen exists but cannot be hit.
        let frames = "window frame: \(windows.firstMatch.exists ? "\(windows.firstMatch.frame)" : "none")\n"
        let attachment = XCTAttachment(string: frames + debugDescription)
        attachment.name = "element tree: \(reason)"
        attachment.lifetime = .keepAlways
        let screen = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        screen.name = "screen: \(reason)"
        screen.lifetime = .keepAlways
        XCTContext.runActivity(named: "Element tree (\(reason))") {
            $0.add(attachment)
            $0.add(screen)
        }
    }

    /// Waits until `element` can be clicked: it exists and nothing (a sheet still closing, say) covers it.
    @discardableResult
    func waitUntilHittable(_ element: XCUIElement, timeout: TimeInterval = 10) -> Bool {
        let hittable = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "exists == true AND hittable == true"), object: element)
        return XCTWaiter().wait(for: [hittable], timeout: timeout) == .completed
    }

    /// Settings, from wherever the test is: an account screen's sheet is closed first, and Settings opened if it is
    /// not open.
    func showSettings(file: StaticString = #filePath, line: UInt = #line) {
        if buttons[AccessibilityID.screenDone].firstMatch.exists { closeScreen(file: file, line: line) }
        if !buttons["settings.done"].exists {
            backToList()
            openSettings()
        }
    }

    /// Opens Settings and, from it, the account screen whose row has `identifier`, which opens in a sheet of its own.
    /// A click that did not open it (one made while Settings was still settling) is made once more.
    func openScreen(_ identifier: String, file: StaticString = #filePath, line: UInt = #line) {
        showSettings(file: file, line: line)
        let done = buttons[AccessibilityID.screenDone].firstMatch
        for _ in 0..<2 {
            let row = reveal(identifier, at: .below, file: file, line: line)
            waitUntilHittable(row, timeout: 3)
            row.click()
            if done.waitForExistence(timeout: 5) { return }
        }
        attachTree("open \(identifier)")
        XCTFail("\(identifier) did not open its screen", file: file, line: line)
    }

    /// Closes the account screen's sheet, from whatever is pushed on it, back to Settings. Waits for anything above it
    /// (a sheet of its own closing) to have gone first, and clicks again if the first click did not take.
    func closeScreen(file: StaticString = #filePath, line: UInt = #line) {
        let done = buttons[AccessibilityID.screenDone].firstMatch
        guard done.waitForExistence(timeout: 5) else {
            attachTree("close the screen")
            XCTFail("no screen is open", file: file, line: line)
            return
        }
        for _ in 0..<2 {
            waitUntilHittable(done, timeout: 3)
            done.click()
            if done.waitForNonExistence(timeout: 5) { return }
        }
        attachTree("close the screen")
        XCTFail("the screen is still open", file: file, line: line)
    }

    /// Clicks the element with `identifier`, scrolling to it first.
    func tap(_ identifier: String, file: StaticString = #filePath, line: UInt = #line) {
        reveal(identifier, file: file, line: line).click()
    }

    /// Clicks the control with `identifier` once it is enabled: one that waits for something the app does first.
    func tapWhenEnabled(_ identifier: String, file: StaticString = #filePath, line: UInt = #line) {
        // A disabled control may not count as hittable, so it is only required to be there until it is enabled.
        let target = reveal(identifier, mayBeDisabled: true, file: file, line: line)
        let enabled = XCTNSPredicateExpectation(predicate: NSPredicate(format: "isEnabled == true"), object: target)
        XCTAssertEqual(XCTWaiter().wait(for: [enabled], timeout: 15), .completed, "\(identifier) stayed disabled")
        if !waitUntilHittable(target, timeout: 3) {
            attachTree("tap \(identifier)")
            XCTFail("\(identifier) is not hittable", file: file, line: line)
        }
        target.click()
    }

    /// Types into the text or secure field with `identifier`.
    func enter(_ text: String, into identifier: String, file: StaticString = #filePath, line: UInt = #line) {
        let field = reveal(identifier, file: file, line: line)
        field.click()
        field.typeText(text)
    }

    /// Clicks a confirmation dialog's button labelled `label`. The button that opened the dialog is labelled
    /// differently ("Share This Vault…", "Discard…"), so the label alone finds the dialog's.
    func confirm(_ label: String, file: StaticString = #filePath, line: UInt = #line) {
        let button = buttons.matching(NSPredicate(format: "label == %@", label)).firstMatch
        XCTAssertTrue(button.waitForExistence(timeout: 10), debugDescription, file: file, line: line)
        button.click()
    }

    /// Waits for the text with `identifier` to contain `text`.
    func waitForText(
        _ text: String, in identifier: String, timeout: TimeInterval = 15, file: StaticString = #filePath,
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
        showSettings(file: file, line: line)
        reveal(identifier, at: .top, file: file, line: line).click()
        waitForText(text, in: "debug.peerStatus", timeout: 20, file: file, line: line)
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
        XCTAssertTrue(buttons["items.add"].waitForExistence(timeout: 15), debugDescription)
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
