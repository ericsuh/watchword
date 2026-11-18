import XCTest
import os

/// Reads from the app that survive a stalled accessibility query.
///
/// Every read of an element (`exists`, `isHittable`, `frame`, a wait, and the lookup at the start of a tap or of
/// typing) is a query the app's accessibility runtime answers. On a CI simulator that answer now and then does not
/// come: XCUITest waits 30 s, asks twice more, and then records "Failed to get matching snapshots: Timed out while
/// evaluating UI query." as a failure of the test, though nothing the test checks was wrong (the tour failed that way
/// looking for a Settings row, with the app idle). `tolerating` runs one such read, takes that one message as
/// expected, and asks again, at most `retries` times. Nothing else is taken: an assertion, a missing element ("No
/// matches found") and a lost app are recorded as they always were, and a query that is still unanswered after the
/// retries fails the test, saying so.
@MainActor
enum UIQuery {
    /// How many times a stalled read is asked again before the test fails.
    static let retries = 2

    /// Runs `body`, one read or one action that begins with a lookup, and returns what it gave. If XCUITest recorded
    /// a query timeout while it ran, the result is not trusted (a stalled `exists` answers false) and `body` runs
    /// again. Each retry prints a `UI-test note:` line, so the log shows how often the simulator stalled.
    ///
    /// An action is safe to repeat here: XCUITest finds the element before it synthesises the tap or the keys, so a
    /// lookup that timed out did nothing.
    @discardableResult
    static func tolerating<T>(
        _ what: String, file: StaticString = #filePath, line: UInt = #line, _ body: () -> T
    ) -> T {
        // The message of exactly this error, and no other: "Failed to get matching snapshots" alone also begins the
        // report of an app that has gone away.
        let timeout = "Timed out while evaluating UI query"
        var attempt = 0
        while true {
            let stalls = OSAllocatedUnfairLock(initialState: 0)
            let options = XCTExpectedFailure.Options()
            options.isStrict = false
            options.issueMatcher = { @Sendable issue in
                guard issue.compactDescription.contains(timeout) else { return false }
                stalls.withLock { $0 += 1 }
                return true
            }
            var result: T?
            XCTExpectFailure("The simulator's accessibility service did not answer a query in time", options: options) {
                result = body()
            }
            let stalled = stalls.withLock { $0 } > 0
            if let result, !stalled { return result }
            if attempt == retries {
                XCTFail(
                    "\(what): the UI query timed out \(retries + 1) times running; the app or the simulator's "
                        + "accessibility service is not answering", file: file, line: line)
                if let result { return result }
                return body()
            }
            attempt += 1
            print("UI-test note: a UI query timed out (\(what)); retry \(attempt) of \(retries)")
        }
    }
}

extension XCUIElement {
    /// `exists`, through `UIQuery.tolerating`.
    var isPresent: Bool {
        UIQuery.tolerating("exists") { exists }
    }

    /// `isHittable`, through `UIQuery.tolerating`. As with `isHittable`, only for an element that is there.
    var canBeHit: Bool {
        UIQuery.tolerating("isHittable") { isHittable }
    }

    /// `frame`, through `UIQuery.tolerating`. As with `frame`, only for an element that is there.
    var frameNow: CGRect {
        UIQuery.tolerating("frame") { frame }
    }

    /// `waitForExistence(timeout:)`, through `UIQuery.tolerating`.
    func appears(within timeout: TimeInterval) -> Bool {
        UIQuery.tolerating("waitForExistence") { waitForExistence(timeout: timeout) }
    }

    /// `waitForNonExistence(timeout:)`, through `UIQuery.tolerating`.
    func disappears(within timeout: TimeInterval) -> Bool {
        UIQuery.tolerating("waitForNonExistence") { waitForNonExistence(timeout: timeout) }
    }

    /// `typeText`, through `UIQuery.tolerating`: the field is looked up before any key is sent, and only once it holds
    /// keyboard focus (`focusForTyping`).
    func enterText(_ text: String) {
        focusForTyping()
        UIQuery.tolerating("typeText") { typeText(text) }
    }

    /// Waits for the element to hold keyboard focus, tapping it again if focus does not arrive. A tap made while the
    /// screen is still settling (an editor presenting, the keyboard arriving) can leave focus where it was, and
    /// `typeText` then fails with "Neither element nor any descendant has keyboard focus" (run 44314899872, an iOS
    /// simulator). Each attempt waits up to two seconds for the focus before tapping again, three attempts in all; if
    /// focus never arrives, the keys are sent anyway and `typeText` reports the failure as before.
    func focusForTyping() {
        let focused = NSPredicate(format: "hasKeyboardFocus == true")
        for _ in 0..<3 {
            let arrived = XCTNSPredicateExpectation(predicate: focused, object: self)
            if XCTWaiter().wait(for: [arrived], timeout: 2) == .completed { return }
            click()
        }
    }
}
