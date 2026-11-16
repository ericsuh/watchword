import XCTest

#if os(macOS)
    /// The sign of a scroll-wheel delta that moves a form towards its end, as `scroll` has found it.
    @MainActor private var macScrollSign: CGFloat = 1
#endif

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

    /// The element with `identifier`, scrolled to if it is not on screen yet. A form's rows out of view are either not
    /// in the hierarchy or in it with a frame outside the visible area (iOS), and asking such an element whether it is
    /// hittable can itself fail ("activation point invalid"); so the frame decides first. An element above the visible
    /// area scrolls the form back, one below scrolls it on, one not there yet scrolls the way `position` says, and one
    /// on screen but not yet hittable (a sheet still animating in) is waited for, not scrolled past. Bounded: at most
    /// eight scrolls and short waits, then a failure with the tree and a screenshot attached.
    @discardableResult
    func reveal(
        _ identifier: String, at position: FormPosition = .anywhere, mayBeDisabled: Bool = false,
        file: StaticString = #filePath, line: UInt = #line
    ) -> XCUIElement {
        let target = element(identifier)
        _ = target.waitForExistence(timeout: 2)
        let defaults: [Bool]
        switch position {
        case .top: defaults = Array(repeating: false, count: 8)
        case .below: defaults = Array(repeating: true, count: 8)
        case .anywhere: defaults = [true, true, true, false, false, false, false, false]
        }
        var scrolls = 0
        while scrolls < defaults.count, !isReachable(target) {
            if target.exists, let towardsEnd = direction(toward: target) {
                scroll(towardsEnd: towardsEnd, to: identifier)
            } else if target.exists, isOnScreen(target) {
                if waitUntilHittable(target, timeout: 2) || mayBeDisabled { break }
                scroll(towardsEnd: defaults[scrolls], to: identifier)
            } else {
                scroll(towardsEnd: defaults[scrolls], to: identifier)
            }
            scrolls += 1
        }
        if !target.waitForExistence(timeout: 2) {
            attachTree("reveal \(identifier)", target: identifier)
            XCTFail("\(identifier) was not found", file: file, line: line)
        } else if !mayBeDisabled, !waitUntilHittable(target, timeout: 2) {
            // In the hierarchy but not reachable: off the screen, or under a sheet that is still there.
            attachTree("reveal \(identifier)", target: identifier)
            XCTFail("\(identifier) is not hittable", file: file, line: line)
        }
        return target
    }

    /// The scrolling container holding `element`, innermost last: a form's rows are in one, toolbar items and header
    /// buttons are not. Found by the element's identifier; `nil` for one with none or outside any container.
    private func container(of element: XCUIElement) -> XCUIElement? {
        let identifier = element.identifier
        guard !identifier.isEmpty else { return nil }
        #if os(iOS)
            let queries = [collectionViews, tables, scrollViews]
        #else
            let queries = [scrollViews, tables, outlines]
        #endif
        for query in queries {
            if let found = query.containing(.any, identifier: identifier).allElementsBoundByIndex.last, found.exists {
                return found
            }
        }
        return nil
    }

    /// The window's frame, joined with the frontmost sheet's on macOS (a sheet may reach past its window's edge).
    private var windowFrame: CGRect {
        var frame = windows.firstMatch.exists ? windows.firstMatch.frame : .zero
        #if os(macOS)
            if let sheet = sheets.allElementsBoundByIndex.last, sheet.exists { frame = frame.union(sheet.frame) }
        #endif
        return frame
    }

    /// Where `element` can be seen and clicked: inside its scrolling container, kept clear of the bars along that
    /// container's edges (a sheet's toolbar at its foot, the home indicator), for a form's row; the window itself,
    /// with no margin, for anything outside a container (a toolbar item such as Done, a header button).
    func visibleFrame(for element: XCUIElement) -> CGRect {
        guard let container = container(of: element) else { return windowFrame }
        let frame = container.frame.intersection(windowFrame)
        return frame.height > 3 * Self.edgeMargin ? frame.insetBy(dx: 0, dy: Self.edgeMargin) : frame
    }

    /// Keeps clear of a bar along an edge of a scrolling container (a toolbar, the home indicator).
    private static let edgeMargin: CGFloat = 36

    /// Whether `element`'s middle is inside the area where it can be seen. Asks nothing of an element not there.
    func isOnScreen(_ element: XCUIElement) -> Bool {
        guard element.exists else { return false }
        let frame = element.frame
        let visible = visibleFrame(for: element)
        return !frame.isEmpty && !visible.isEmpty && visible.contains(CGPoint(x: frame.midX, y: frame.midY))
    }

    /// Which way to scroll to bring `element` into view: towards the end if it is below, back if it is above, `nil`
    /// if it is in view, has no frame, or is in no scrolling container (then scrolling would not move it).
    private func direction(toward element: XCUIElement) -> Bool? {
        guard container(of: element) != nil else { return nil }
        let frame = element.frame
        let visible = visibleFrame(for: element)
        guard !frame.isEmpty, !visible.isEmpty else { return nil }
        if frame.midY > visible.maxY { return true }
        if frame.midY < visible.minY { return false }
        return nil
    }

    /// On screen and hittable; `isHittable` is asked only of an element on screen.
    func isReachable(_ element: XCUIElement) -> Bool {
        isOnScreen(element) && element.isHittable
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
            let target = element(identifier)
            let before = target.exists ? target.frame.midY : nil
            // The window's own list only when no sheet covers it.
            let window = frontmost == nil ? windows.firstMatch.scrollViews.firstMatch : nil
            for candidate in [holding, frontmost, window].compactMap({ $0 })
            where candidate.exists && isOnScreen(candidate) {
                candidate.scroll(byDeltaX: 0, deltaY: (towardsEnd ? -240 : 240) * macScrollSign)
                // Which sign of deltaY moves a form on is learnt from the first scroll that moved the target: had
                // it moved the wrong way, the sign is turned round for every scroll after.
                if let before, target.exists {
                    let moved = target.frame.midY - before
                    if moved != 0, (moved > 0) == towardsEnd { macScrollSign = -macScrollSign }
                }
                return
            }
        #endif
    }

    /// Attaches the whole element tree and a screenshot to the running test, kept whether or not it passes, and prints
    /// a compact account of the same to the log, which can be read where the result bundle cannot: the target's
    /// frame and state, the window's and the frontmost sheet's frames, the area `reveal` judged by, the buttons on
    /// screen, and the start of the tree.
    func attachTree(_ reason: String, target identifier: String? = nil) {
        var lines = ["=== UI-test diagnostics: \(reason)"]
        if let identifier {
            let target = element(identifier)
            if target.exists {
                let hittable = isOnScreen(target) ? "\(target.isHittable)" : "not asked (off the visible area)"
                lines.append(
                    "target \(identifier): frame \(target.frame), exists true, hittable \(hittable), "
                        + "enabled \(target.isEnabled), visible area \(visibleFrame(for: target)), "
                        + "container \(container(of: target).map { "\($0.elementType.rawValue) \($0.frame)" } ?? "none")"
                )
            } else {
                lines.append("target \(identifier): does not exist")
            }
        }
        lines.append("window frame: \(windows.firstMatch.exists ? "\(windows.firstMatch.frame)" : "none")")
        #if os(macOS)
            let sheetFrames = sheets.allElementsBoundByIndex.map { "\($0.frame)" }
            lines.append(
                "sheet frames, frontmost last: \(sheetFrames.isEmpty ? "none" : sheetFrames.joined(separator: ", "))")
        #endif
        for button in buttons.allElementsBoundByIndex.prefix(40) where button.exists {
            lines.append(
                "button \(button.identifier.isEmpty ? "(no id)" : button.identifier) “\(button.label)” \(button.frame)")
        }
        let tree = debugDescription
        lines.append("element tree, first 150 lines:")
        lines += tree.split(separator: "\n", omittingEmptySubsequences: false).prefix(150).map(String.init)
        lines.append("=== end of UI-test diagnostics: \(reason)")
        print(lines.joined(separator: "\n"))

        let attachment = XCTAttachment(string: lines.joined(separator: "\n") + "\n\n" + tree)
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

    /// Waits until `element` can be clicked: on screen, and nothing (a sheet still closing, say) covers it. Polls in
    /// quarter-second waits rather than through a predicate on `hittable`, which fails outright for an element whose
    /// frame is off the screen.
    @discardableResult
    func waitUntilHittable(_ element: XCUIElement, timeout: TimeInterval = 10) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            if isReachable(element) { return true }
            _ = XCTWaiter().wait(for: [XCTestExpectation(description: "a quarter of a second")], timeout: 0.25)
        } while Date() < deadline
        return false
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
        attachTree("open \(identifier)", target: identifier)
        XCTFail("\(identifier) did not open its screen", file: file, line: line)
    }

    /// Closes the account screen's sheet, from whatever is pushed on it, back to Settings. Waits for anything above it
    /// (a sheet of its own closing) to have gone first, and clicks again if the first click did not take.
    func closeScreen(file: StaticString = #filePath, line: UInt = #line) {
        let done = buttons[AccessibilityID.screenDone].firstMatch
        guard done.waitForExistence(timeout: 5) else {
            attachTree("close the screen", target: AccessibilityID.screenDone)
            XCTFail("no screen is open", file: file, line: line)
            return
        }
        for _ in 0..<2 {
            waitUntilHittable(done, timeout: 3)
            done.click()
            if done.waitForNonExistence(timeout: 5) { return }
        }
        attachTree("close the screen", target: AccessibilityID.screenDone)
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
            attachTree("tap \(identifier)", target: identifier)
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
        // A text that appears below the fold of a form (an export's report) is not in the hierarchy until shown: if
        // nothing with the identifier is there after a moment, the form is scrolled on, at most four times.
        if !match.waitForExistence(timeout: min(3, timeout)) {
            for _ in 0..<4 where !element(identifier).exists {
                scroll(towardsEnd: true, to: identifier)
            }
            if !match.waitForExistence(timeout: max(1, timeout - 3)) {
                attachTree("text \(text) in \(identifier)", target: identifier)
                XCTFail("no \(identifier) containing \(text)", file: file, line: line)
            }
        }
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
