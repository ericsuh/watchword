import XCTest

/// Milestone 3 UI test, run on iOS and macOS (docs/04-test-plan.md §5), in one launch to keep the iOS job short: a
/// password changed on the other device is announced after a sync and refuses the old password here, with the way out
/// shown (PRD F10.1); the person takes the way out, then removes that device from the Devices screen with a password of
/// their own (F10.2, docs/02-architecture.md §7.8), which is the one that opens the vault afterwards. The other device
/// is `UITestPeer`, enrolled over the shared in-memory transport.
final class DeviceRevocationTests: XCTestCase {
    static let newPassword = "a password chosen on revoking"

    override func setUp() {
        continueAfterFailure = false
        // A hang fails with a report rather than eating the job (`app:test` turns the allowances on).
        executionTimeAllowance = 600
    }

    @MainActor
    func testPasswordChangedElsewhereThenRevokeThatDevice() throws {
        step("launch")
        let app = XCUIApplication.launchedWithAccount()
        let password = OnboardingAndUnlockTests.password
        app.openSettings()
        // With nothing to send yet, the first sync's line may say only "Up to date."; every line ends in a full stop.
        app.syncNow(expecting: ".")
        step("the other device joins")
        app.runPeerHook(AccessibilityID.Debug.peerJoin, expecting: "joined")
        step("the password changed elsewhere")
        app.runPeerHook(AccessibilityID.Debug.peerPassword, expecting: "password was changed")
        app.syncNow(expecting: "new account password")
        app.waitForText("changed on another device", in: AccessibilityID.Settings.syncNotice, timeout: 5)
        app.closeSettings()

        // The old password is refused with the way out; this device's password, through that way, opens it.
        step("lock and unlock")
        app.backToList()
        app.buttons["items.lock"].firstMatch.click()
        let unlock = app.secureTextFields["unlock.password"]
        XCTAssertTrue(unlock.waitForExistence(timeout: 10), app.debugDescription)
        unlock.click()
        unlock.typeText(password + "\n")
        XCTAssertTrue(app.element(AccessibilityID.Unlock.passwordChanged).waitForExistence(timeout: 15))
        unlock.click()
        unlock.typeText(password)
        app.tapWhenEnabled(AccessibilityID.Unlock.ignoreChange)
        XCTAssertTrue(app.buttons["items.add"].waitForExistence(timeout: 15), app.debugDescription)

        // The device that changed it is removed, with a new password.
        step("devices: revoke")
        app.openScreen(AccessibilityID.Settings.devices)
        let other = UITestNames.otherDevice
        XCTAssertTrue(
            app.element(AccessibilityID.Devices.row(other)).waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertTrue(app.element(AccessibilityID.Devices.thisDevice).exists, "this device is not marked")
        app.tap(AccessibilityID.Devices.revoke(other))
        app.enter(password, into: AccessibilityID.Devices.current)
        app.enter(Self.newPassword, into: AccessibilityID.Devices.new)
        app.enter(Self.newPassword, into: AccessibilityID.Devices.confirmation)
        app.tap(AccessibilityID.Devices.confirm)
        app.waitForText("was removed", in: AccessibilityID.Devices.notice)
        XCTAssertTrue(app.buttons[AccessibilityID.Devices.confirm].waitForNonExistence(timeout: 5), "still open")
        XCTAssertFalse(app.element(AccessibilityID.Devices.revoke(other)).exists, "a removed device offered again")
        app.closeScreen()
        app.closeSettings()
        step("the new password")
        app.lockAndUnlock(password: Self.newPassword)
    }
}

/// Names `UITestPeer` gives the rest of the household (Apps/Shared/UITestPeer.swift), which the tests cannot import.
enum UITestNames {
    static let otherDevice = "Other UI-test device"
    static let changedPassword = "changed on the other device"
}
