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
    ///
    /// Queries are counted here. Each one walks the app's whole accessibility tree (the item list, Settings and the
    /// account screen over it): one to two seconds on a CI simulator, and now and then half a minute. The common
    /// case, an element already in view, is two: its frame, then whether it can be hit. It was five or six, and a
    /// field under the keyboard a dozen more, which made the export test 331 queries and 439 s on a good run.
    @discardableResult
    func reveal(
        _ identifier: String, at position: FormPosition = .anywhere, mayBeDisabled: Bool = false,
        file: StaticString = #filePath, line: UInt = #line
    ) -> XCUIElement {
        let target = element(identifier)
        var frame = presentFrame(of: target)
        // Not there yet (the screen it is on is still arriving) is waited for once, before anything is scrolled.
        if frame == nil, target.appears(within: 2) { frame = presentFrame(of: target) }
        if let frame, isVisible(frame, of: target), target.canBeHit { return target }
        #if os(iOS)
            // A field typed into outside `enter` leaves the keyboard up over the foot of the form, which the window's
            // frame does not show: a row under it passes as on screen and is not hittable.
            dismissKeyboard(ifCovering: frame)
        #endif
        let defaults: [Bool]
        switch position {
        case .top: defaults = Array(repeating: false, count: 8)
        case .below: defaults = Array(repeating: true, count: 8)
        case .anywhere: defaults = [true, true, true, false, false, false, false, false]
        }
        for towardsEnd in defaults {
            guard let frame = presentFrame(of: target) else {
                scroll(towardsEnd: towardsEnd, to: identifier)
                continue
            }
            if isVisible(frame, of: target) {
                if target.canBeHit { return target }
                #if os(iOS)
                    dismissKeyboard(ifCovering: frame)
                #endif
                if waitUntilHittable(target, timeout: 2) || mayBeDisabled { return target }
                scroll(towardsEnd: towardsEnd, to: identifier)
            } else {
                scroll(towardsEnd: direction(toward: target, at: frame) ?? towardsEnd, to: identifier)
            }
        }
        if isReachable(target) { return target }
        if !target.appears(within: 2) {
            attachTree("reveal \(identifier)", target: identifier)
            XCTFail("\(identifier) was not found", file: file, line: line)
        } else if !mayBeDisabled, !waitUntilHittable(target, timeout: 2) {
            // In the hierarchy but not reachable: off the screen, or under a sheet that is still there.
            attachTree("reveal \(identifier)", target: identifier)
            XCTFail("\(identifier) is not hittable", file: file, line: line)
        }
        return target
    }

    /// `element`'s frame if it is in the hierarchy, `nil` if it is not. Whether it is there is asked first: that is
    /// the cheapest query there is, and a snapshot of an element that is not there is looked for three times over
    /// before it gives up. On iOS the frame then comes from a snapshot, which throws where reading `frame` would
    /// record a failure; one that cannot be had of an element that is there (a stalled query) is asked for again,
    /// at most `UIQuery.retries` times.
    func presentFrame(of element: XCUIElement) -> CGRect? {
        guard element.isPresent else { return nil }
        #if os(iOS)
            return details(of: element)?.frame
        #else
            return element.frameNow
        #endif
    }

    /// The frame and state of `element`, from one snapshot; `nil` if it has gone. For an element just seen to be
    /// there, a snapshot that cannot be had is a stalled query or a screen on its way out, so it is asked for again
    /// while the element is still there, with a note in the log each time, and fails the test if it never comes.
    func details(of element: XCUIElement) -> (frame: CGRect, isEnabled: Bool)? {
        for attempt in 0...UIQuery.retries {
            if let snapshot = try? element.snapshot() { return (snapshot.frame, snapshot.isEnabled) }
            guard element.isPresent else { return nil }
            if attempt < UIQuery.retries {
                print(
                    "UI-test note: no snapshot of an element that is there; retry \(attempt + 1) of \(UIQuery.retries)")
            }
        }
        XCTFail(
            "an element that is there gave no snapshot \(UIQuery.retries + 1) times running; the app or the "
                + "simulator's accessibility service is not answering")
        return nil
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

    /// The window's frame, joined with the frontmost sheet's on macOS (a sheet may reach past its window's edge). On
    /// iOS the app fills the screen, so its own frame is the window's, at one query rather than two (an existence
    /// check and a frame): this is asked before every click, and each query is a snapshot of the whole tree.
    private var windowFrame: CGRect {
        #if os(iOS)
            return frameNow
        #else
            var frame = windows.firstMatch.exists ? windows.firstMatch.frame : .zero
            if let sheet = sheets.allElementsBoundByIndex.last, sheet.exists { frame = frame.union(sheet.frame) }
            return frame
        #endif
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
    ///
    /// On iOS that area is the window, kept clear of its edges: a form row out of view has a frame outside it, a sheet
    /// has no toolbar along its foot, and asking which scrolling container holds an element costs a query over the
    /// whole tree each time, which made every step of an iOS run several seconds long. On macOS a sheet's toolbar sits
    /// along the foot of its form, so a row is judged against its own container (`visibleFrame(for:)`).
    func isOnScreen(_ element: XCUIElement) -> Bool {
        guard let frame = presentFrame(of: element) else { return false }
        return isVisible(frame, of: element)
    }

    /// Whether the middle of `frame`, `element`'s own, is inside the area where `element` can be seen.
    private func isVisible(_ frame: CGRect, of element: XCUIElement) -> Bool {
        let visible = visibleArea(for: element)
        return !frame.isEmpty && !visible.isEmpty && visible.contains(CGPoint(x: frame.midX, y: frame.midY))
    }

    /// The area `isOnScreen` judges by: the window kept clear of its edges on iOS, the element's container on macOS.
    private func visibleArea(for element: XCUIElement) -> CGRect {
        #if os(iOS)
            return windowFrame.insetBy(dx: 0, dy: Self.edgeMargin)
        #else
            return visibleFrame(for: element)
        #endif
    }

    /// Which way to scroll to bring `element`, whose frame is `frame`, into view: towards the end if it is below, back
    /// if it is above, `nil` if it is in view, has no frame, or is in no scrolling container (then scrolling would not
    /// move it).
    private func direction(toward element: XCUIElement, at frame: CGRect) -> Bool? {
        #if os(macOS)
            guard container(of: element) != nil else { return nil }
        #endif
        // On iOS, off the window's edge is out of the form's view: a toolbar item never is.
        let visible = visibleArea(for: element)
        guard !frame.isEmpty, !visible.isEmpty else { return nil }
        if frame.midY > visible.maxY { return true }
        if frame.midY < visible.minY { return false }
        return nil
    }

    #if os(iOS)
        /// Puts the keyboard away if it is up and the target, whose frame is `frame`, is under it or not there yet
        /// (`nil`: a row below the fold, which the form will scroll up into the keyboard's place). Asked only once the
        /// quick check has failed, and of the keyboard, whose own small tree answers at once. Return first, which ends
        /// editing in a SwiftUI field with no submit action; then a downward swipe on the form, which a form that
        /// dismisses its keyboard on scrolling honours.
        func dismissKeyboard(ifCovering frame: CGRect?) {
            let keyboard = keyboards.firstMatch
            guard keyboard.isPresent else { return }
            let covered = keyboard.frameNow
            if let frame, !frame.isEmpty, frame.maxY <= covered.minY { return }
            for label in ["Return", "return", "Done", "done", "Go", "go"] {
                let key = keyboard.buttons[label]
                if key.isPresent, key.canBeHit {
                    key.click()
                    if keyboard.disappears(within: 2) { return }
                    break
                }
            }
            // As `scroll` does on iOS: the swipe lands on whatever is on top, the sheet's form included.
            swipeDown()
            if !keyboard.disappears(within: 2) {
                print("UI-test note: the keyboard is still up")
            }
        }
    #endif

    /// On screen and hittable; `isHittable` is asked only of an element on screen.
    func isReachable(_ element: XCUIElement) -> Bool {
        isOnScreen(element) && element.canBeHit
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

    /// Waits until `element` is enabled. Polls as `waitUntilHittable` does, reading the state from a snapshot on iOS:
    /// a predicate on `isEnabled` reads the property, which records a failure of its own when a query stalls.
    func waitUntilEnabled(_ element: XCUIElement, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            #if os(iOS)
                if details(of: element)?.isEnabled == true { return true }
            #else
                if element.isPresent, UIQuery.tolerating("isEnabled", { element.isEnabled }) { return true }
            #endif
            _ = XCTWaiter().wait(for: [XCTestExpectation(description: "a quarter of a second")], timeout: 0.25)
        } while Date() < deadline
        return false
    }

    /// Settings, from wherever the test is: an account screen's sheet is closed first, and Settings opened if it is
    /// not open.
    func showSettings(file: StaticString = #filePath, line: UInt = #line) {
        if buttons[AccessibilityID.screenDone].firstMatch.isPresent { closeScreen(file: file, line: line) }
        if !buttons["settings.done"].isPresent {
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
            // `reveal` returns a row that can be hit, or has failed the test.
            reveal(identifier, at: .below, file: file, line: line).click()
            if done.appears(within: 5) { return }
        }
        attachTree("open \(identifier)", target: identifier)
        XCTFail("\(identifier) did not open its screen", file: file, line: line)
    }

    /// Closes the account screen's sheet, from whatever is pushed on it, back to Settings. Waits for anything above it
    /// (a sheet of its own closing) to have gone first, and clicks again if the first click did not take.
    func closeScreen(file: StaticString = #filePath, line: UInt = #line) {
        let done = buttons[AccessibilityID.screenDone].firstMatch
        guard done.appears(within: 5) else {
            attachTree("close the screen", target: AccessibilityID.screenDone)
            XCTFail("no screen is open", file: file, line: line)
            return
        }
        for _ in 0..<2 {
            waitUntilHittable(done, timeout: 3)
            done.click()
            if done.disappears(within: 5) { return }
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
        XCTAssertTrue(waitUntilEnabled(target, timeout: 15), "\(identifier) stayed disabled", file: file, line: line)
        if !waitUntilHittable(target, timeout: 3) {
            attachTree("tap \(identifier)", target: identifier)
            XCTFail("\(identifier) is not hittable", file: file, line: line)
        }
        target.click()
    }

    /// Chooses the export format whose `ExportKind` raw value is `kind`, and waits until the form shows it chosen (the
    /// row's accessibility value is "Chosen"); a tap that chose nothing is made once more. The rows that depend on the
    /// format (the archive's passphrase fields) are there only once it is chosen: the tour, choosing the archive after
    /// a plaintext export's report had scrolled the form to its foot, went on to look for a passphrase field that the
    /// form never made (iOS, CI run 44416865943). Not a failure of its own when the value is never seen: the step that
    /// needs the format fails, with the tree attached here first.
    func chooseExportKind(_ kind: String, file: StaticString = #filePath, line: UInt = #line) {
        let identifier = AccessibilityID.Export.kind + "." + kind
        let chosen = descendants(matching: .any).matching(identifier: identifier)
            .matching(NSPredicate(format: "value == %@", "Chosen")).firstMatch
        for attempt in 1...2 {
            reveal(identifier, file: file, line: line).click()
            if chosen.appears(within: 5) { return }
            print("UI-test note: \(identifier) was tapped and is not chosen; attempt \(attempt) of 2")
        }
        attachTree("choose \(identifier)", target: identifier)
    }

    /// Types into the single-line text or secure field with `identifier`. On iOS the text ends in Return, which ends
    /// editing in a field with no submit action and puts the keyboard away with the keystrokes already being sent:
    /// left up, it covered the next field or button, and finding that out and dismissing it cost a dozen queries each
    /// time. Not for a field that grows (Return is a line there) or one whose Return submits; on macOS, where Return
    /// would press a sheet's default button, the text is typed alone.
    func enter(_ text: String, into identifier: String, file: StaticString = #filePath, line: UInt = #line) {
        let field = reveal(identifier, file: file, line: line)
        field.click()
        #if os(iOS)
            field.enterText(text + "\n")
        #else
            field.enterText(text)
        #endif
    }

    /// Clicks a confirmation dialog's button labelled `label`. The button that opened the dialog is labelled
    /// differently ("Share This Vault…", "Discard…"), so the label alone finds the dialog's.
    func confirm(_ label: String, file: StaticString = #filePath, line: UInt = #line) {
        let button = buttons.matching(NSPredicate(format: "label == %@", label)).firstMatch
        XCTAssertTrue(button.appears(within: 10), debugDescription, file: file, line: line)
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
        if !match.appears(within: min(3, timeout)) {
            for _ in 0..<4 where !element(identifier).isPresent {
                scroll(towardsEnd: true, to: identifier)
            }
            if !match.appears(within: max(1, timeout - 3)) {
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
        XCTAssertTrue(add.appears(within: 10), debugDescription)
        add.click()
        let field = textFields["edit.title"]
        XCTAssertTrue(field.appears(within: 10), debugDescription)
        field.click()
        field.enterText(title)
        textFields["edit.host"].click()
        textFields["edit.host"].enterText(host)
        textFields["edit.username"].click()
        textFields["edit.username"].enterText(username)
        if let password {
            secureTextFields["edit.password"].click()
            secureTextFields["edit.password"].enterText(password)
        } else {
            buttons["edit.generate"].click()
        }
        buttons["edit.save"].click()
        XCTAssertTrue(itemRow(title).appears(within: 10), debugDescription)
        XCTAssertTrue(field.disappears(within: 10), "the editor is still open")
    }

    /// Locks from the item list and unlocks with `password`, expecting the vault.
    func lockAndUnlock(password: String) {
        backToList()
        let lock = buttons["items.lock"].firstMatch
        XCTAssertTrue(lock.appears(within: 10), debugDescription)
        lock.click()
        let unlock = secureTextFields["unlock.password"]
        XCTAssertTrue(unlock.appears(within: 10), debugDescription)
        unlock.click()
        unlock.enterText(password + "\n")
        XCTAssertTrue(buttons["items.add"].appears(within: 15), debugDescription)
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

extension XCTestCase {
    /// Prints `STEP <time> [<test>] <name>` before a step of a long UI test. `app:diagnose` prints the last of these
    /// for every failed test at the end of the job log, so a test that stopped, even one whose app could not be
    /// queried any more, says where it was.
    func step(_ name: String) {
        print("STEP \(Date().ISO8601Format()) [\(self.name)] \(name)")
    }
}
