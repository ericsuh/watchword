import XCTest

/// Milestone 3 UI test, run on iOS and macOS (docs/04-test-plan.md §5): the Devices screen lists the account's other
/// device and removes it with a new account password (PRD F10.2, docs/02-architecture.md §7.8); and a password changed
/// on another device is refused here until the person enters it, or takes the account back (F10.1). The other device is
/// `UITestPeer`, enrolled over the shared in-memory transport.
final class DeviceRevocationTests: XCTestCase {
    static let newPassword = "a password chosen on revoking"

    override func setUp() {
        continueAfterFailure = false
    }

    @MainActor
    func testRevokeTheOtherDeviceWithANewPassword() throws {
        let app = XCUIApplication.launchedWithAccount()
        app.openSettings()
        // With nothing to send yet, the first sync's line may say only "Up to date."; every line ends in a full stop.
        app.syncNow(expecting: ".")
        app.runPeerHook(AccessibilityID.Debug.peerJoin, expecting: "joined")
        app.syncNow(expecting: ".")

        app.openScreen(AccessibilityID.Settings.devices)
        let other = UITestNames.otherDevice
        XCTAssertTrue(
            app.element(AccessibilityID.Devices.row(other)).waitForExistence(timeout: 30), app.debugDescription)
        app.tap(AccessibilityID.Devices.revoke(other))
        app.enter(OnboardingAndUnlockTests.password, into: AccessibilityID.Devices.current)
        app.enter(Self.newPassword, into: AccessibilityID.Devices.new)
        app.enter(Self.newPassword, into: AccessibilityID.Devices.confirmation)
        app.tap(AccessibilityID.Devices.confirm)
        app.waitForText("was removed", in: AccessibilityID.Devices.notice)
        XCTAssertFalse(app.element(AccessibilityID.Devices.revoke(other)).exists, "a removed device offered again")
        app.closeScreen()
        app.closeSettings()

        // The account password is the new one from now on.
        app.lockAndUnlock(password: Self.newPassword)
    }

    @MainActor
    func testPasswordChangedOnAnotherDevice() throws {
        let app = XCUIApplication.launchedWithAccount()
        app.openSettings()
        // With nothing to send yet, the first sync's line may say only "Up to date."; every line ends in a full stop.
        app.syncNow(expecting: ".")
        app.runPeerHook(AccessibilityID.Debug.peerPassword, expecting: "password was changed")
        app.syncNow(expecting: "new account password")
        app.waitForText("changed on another device", in: AccessibilityID.Settings.syncNotice)
        app.closeSettings()

        // The old password is refused with an explanation; the new one opens the vault.
        app.backToList()
        app.buttons["items.lock"].firstMatch.click()
        let unlock = app.secureTextFields["unlock.password"]
        XCTAssertTrue(unlock.waitForExistence(timeout: 10))
        unlock.click()
        unlock.typeText(OnboardingAndUnlockTests.password + "\n")
        XCTAssertTrue(app.element(AccessibilityID.Unlock.passwordChanged).waitForExistence(timeout: 30))
        unlock.click()
        unlock.typeText(UITestNames.changedPassword + "\n")
        XCTAssertTrue(app.buttons["items.add"].waitForExistence(timeout: 30), app.debugDescription)
    }
}

/// Names `UITestPeer` gives the rest of the household (Apps/Shared/UITestPeer.swift), which the tests cannot import.
enum UITestNames {
    static let otherDevice = "Other UI-test device"
    static let changedPassword = "changed on the other device"
}
