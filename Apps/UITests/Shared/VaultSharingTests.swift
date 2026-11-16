import XCTest

/// Milestone 2–4 UI test, run on iOS and macOS (docs/04-test-plan.md §5): a vault is created, renamed, shared, and
/// another person invited to it after their safety number is compared (PRD F2.1, F4.1, F4.2). The other person is
/// `UITestPeer`'s second account, which accepts in the same process over the shared in-memory transport, so the
/// membership chain, the grant and both fingerprint checks are the real ones.
final class VaultSharingTests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    @MainActor
    func testCreateRenameShareAndInvite() throws {
        let app = XCUIApplication.launchedWithAccount()
        // The household member checks the owner's signatures against its registry, which the first sync publishes.
        app.openSettings()
        // With nothing to send yet, the first sync's line may say only "Up to date."; every line ends in a full stop.
        app.syncNow(expecting: ".")

        // Create and rename.
        app.openScreen(AccessibilityID.Settings.vaults)
        XCTAssertTrue(app.element(AccessibilityID.Vaults.row("Personal")).waitForExistence(timeout: 10))
        app.tap(AccessibilityID.Vaults.add)
        app.enter("Household", into: AccessibilityID.Vaults.newName)
        app.tap(AccessibilityID.Vaults.create)
        app.tap(AccessibilityID.Vaults.row("Household"))
        app.tap(AccessibilityID.Vault.rename)
        let name = app.reveal(AccessibilityID.Vault.renameField)
        name.click()
        name.clearAndType("Family")
        app.tap(AccessibilityID.Vault.renameSave)
        app.waitForText("Family", in: AccessibilityID.Vault.name, timeout: 10)

        // Share, then invite: the safety number is shown and must be confirmed before a role can be chosen.
        app.tap(AccessibilityID.Vault.share)
        app.confirm("Share")
        XCTAssertTrue(app.element(AccessibilityID.Vault.member("You")).waitForExistence(timeout: 10))
        app.tap(AccessibilityID.Vault.invite)
        app.tap(AccessibilityID.Invite.uiTestFill)
        app.tapWhenEnabled(AccessibilityID.Invite.lookUp)
        XCTAssertTrue(app.element(AccessibilityID.Invite.safetyNumber).waitForExistence(timeout: 15))
        XCTAssertFalse(app.element(AccessibilityID.Invite.send).exists, "a role offered before the comparison")
        app.reveal(AccessibilityID.Invite.comparedByEye)
        app.switches[AccessibilityID.Invite.comparedByEye].firstMatch.toggleOn()
        app.tap(AccessibilityID.Invite.confirm)
        // The role step names who is invited, and claims no comparison beyond the one made.
        app.waitForText("Inviting the account", in: AccessibilityID.Invite.invitee, timeout: 10)
        app.tap(AccessibilityID.Invite.send)
        XCTAssertTrue(app.element(AccessibilityID.Invite.code).waitForExistence(timeout: 15))
        // Done closes the whole screen from here; the invitation screen's own Done only goes back a step.
        app.closeScreen()

        // The other person accepts; after a sync the owner lists them, verified, with the role they were given.
        app.runPeerHook(AccessibilityID.Debug.householdAccept, expecting: "accepted the invitation")
        app.syncNow(expecting: ".")
        app.openScreen(AccessibilityID.Settings.vaults)
        app.tap(AccessibilityID.Vaults.row("Family"))
        let member = app.descendants(matching: .any).matching(
            NSPredicate(
                format: "identifier BEGINSWITH %@ AND NOT identifier ENDSWITH %@", "vault.member.Member ", ".role")
        ).firstMatch
        XCTAssertTrue(member.waitForExistence(timeout: 15), app.debugDescription)
        let role = app.descendants(matching: .any).matching(
            NSPredicate(format: "identifier BEGINSWITH %@ AND identifier ENDSWITH %@", "vault.member.Member ", ".role")
        ).firstMatch
        XCTAssertEqual(role.displayedText, "Can edit")
        app.closeScreen()
    }
}
