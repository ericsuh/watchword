import XCTest

/// Milestone 2–4 UI tests, run on iOS and macOS (docs/04-test-plan.md §5): a vault is created, renamed, shared, and
/// another person invited to it with a vault sharing code (PRD F2.1, F4.1, F4.2; ADR 0010); the same with a scan in
/// each direction; and this account joining the other person's vault. The other person is `UITestPeer`'s second
/// account, driven from the sharing screens' Debug-only buttons, which stand in for a person reading digits off a
/// screen, typing them, or holding up their phone; it runs in the same process over the shared in-memory transport,
/// directory and board, so the session, the pins, the membership chain and the grant are the real ones.
final class VaultSharingTests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
        // A hang fails with a report rather than eating the job (`app:test` turns the allowances on).
        executionTimeAllowance = 600
    }

    /// The members list, once the other person is on it, with the role they were given.
    @MainActor
    private func expectMember(in app: XCUIApplication, vault: String, role: String) {
        app.syncNow(expecting: ".")
        app.openScreen(AccessibilityID.Settings.vaults)
        app.tap(AccessibilityID.Vaults.row(vault))
        let member = app.descendants(matching: .any).matching(
            NSPredicate(
                format: "identifier BEGINSWITH %@ AND NOT identifier ENDSWITH %@", "vault.member.Member ", ".role")
        ).firstMatch
        XCTAssertTrue(member.appears(within: 15), app.debugDescription)
        let shown = app.descendants(matching: .any).matching(
            NSPredicate(format: "identifier BEGINSWITH %@ AND identifier ENDSWITH %@", "vault.member.Member ", ".role")
        ).firstMatch
        XCTAssertEqual(shown.displayedText, role)
        app.closeScreen()
    }

    /// Creates, renames and shares a vault, and opens its invitation screen.
    @MainActor
    private func sharedVault(_ app: XCUIApplication, named name: String) {
        app.openScreen(AccessibilityID.Settings.vaults)
        XCTAssertTrue(app.element(AccessibilityID.Vaults.row("Personal")).appears(within: 10))
        app.tap(AccessibilityID.Vaults.add)
        app.enter("Household", into: AccessibilityID.Vaults.newName)
        app.tap(AccessibilityID.Vaults.create)
        app.tap(AccessibilityID.Vaults.row("Household"))
        if name != "Household" {
            app.tap(AccessibilityID.Vault.rename)
            let field = app.reveal(AccessibilityID.Vault.renameField)
            field.click()
            field.clearAndType(name)
            app.tap(AccessibilityID.Vault.renameSave)
            app.waitForText(name, in: AccessibilityID.Vault.name, timeout: 10)
        }
        app.tap(AccessibilityID.Vault.share)
        app.confirm("Share")
        XCTAssertTrue(app.element(AccessibilityID.Vault.member("You")).appears(within: 10))
        app.tap(AccessibilityID.Vault.invite)
    }

    @MainActor
    func testCreateRenameShareAndInviteWithAVaultSharingCode() throws {
        step("launch")
        let app = XCUIApplication.launchedWithAccount()
        // The household member checks the owner's signatures against its registry, which the first sync publishes.
        app.openSettings()
        // With nothing to send yet, the first sync's line may say only "Up to date."; every line ends in a full stop.
        app.syncNow(expecting: ".")

        step("vaults: create, rename, share")
        sharedVault(app, named: "Family")

        // The vault sharing code: nothing to choose before both codes are checked.
        step("invite: show the code")
        app.tap(AccessibilityID.Invite.startSession)
        XCTAssertTrue(app.element(AccessibilityID.Invite.number).appears(within: 15), app.debugDescription)
        XCTAssertFalse(app.element(AccessibilityID.Invite.send).isPresent, "a role offered before the check")
        app.tap(AccessibilityID.Debug.memberJoins)
        step("invite: type their code, one wrong first")
        XCTAssertTrue(app.element(AccessibilityID.Invite.typedCode).appears(within: 15), app.debugDescription)
        app.enter("000000", into: AccessibilityID.Invite.typedCode)
        app.tap(AccessibilityID.Invite.confirmCode)
        app.waitForText("tries left", in: "error", timeout: 10)
        app.tap(AccessibilityID.Debug.fillMemberCode)
        app.tapWhenEnabled(AccessibilityID.Invite.confirmCode)
        step("invite: their code matched; they type this one")
        XCTAssertTrue(app.element(AccessibilityID.Invite.ownCode).appears(within: 15), app.debugDescription)
        app.waitForText("Inviting the account", in: AccessibilityID.Invite.invitee, timeout: 10)
        app.tap(AccessibilityID.Debug.memberTypes)
        app.tap(AccessibilityID.Invite.send)
        XCTAssertTrue(app.element(AccessibilityID.Invite.sent).appears(within: 15), app.debugDescription)
        step("the other person joins")
        app.tap(AccessibilityID.Debug.memberAcceptsSession)
        app.waitForText("accepted the invitation", in: "debug.peerStatus", timeout: 20)
        app.closeScreen()

        expectMember(in: app, vault: "Family", role: "Can edit")
    }

    #if os(iOS)
        /// The scan in each direction (ADR 0010, Scanning): this device reads the other person's screen in place of
        /// typing their code, through the scanner stand-in a `--uitest` launch has in place of the camera, and the other
        /// person types this device's code. iPhone and iPad only: a Mac shows codes and scans none, and has no stand-in.
        @MainActor
        func testInviteByScanningTheirScreen() throws {
            step("launch")
            let app = XCUIApplication.launchedWithAccount()
            app.openSettings()
            app.syncNow(expecting: ".")
            sharedVault(app, named: "Household")

            app.tap(AccessibilityID.Invite.startSession)
            XCTAssertTrue(app.element(AccessibilityID.Invite.qr).appears(within: 15), app.debugDescription)
            app.tap(AccessibilityID.Debug.memberJoins)
            step("scan their screen")
            XCTAssertTrue(app.element(AccessibilityID.Debug.scanMember).appears(within: 15), app.debugDescription)
            app.tap(AccessibilityID.Debug.scanMember)
            XCTAssertTrue(app.element(AccessibilityID.Invite.ownCode).appears(within: 15), app.debugDescription)
            app.tap(AccessibilityID.Debug.memberTypes)
            app.tap(AccessibilityID.Invite.send)
            XCTAssertTrue(app.element(AccessibilityID.Invite.sent).appears(within: 15), app.debugDescription)
            app.tap(AccessibilityID.Debug.memberAcceptsSession)
            app.waitForText("accepted the invitation", in: "debug.peerStatus", timeout: 20)
            app.closeScreen()

            expectMember(in: app, vault: "Household", role: "Can edit")
        }
    #endif

    #if os(iOS)
        /// The joiner's scan (ADR 0010, Scans; V18, V34): this device reads the other person's screen, which names
        /// nothing until their device has revealed; the screen then names the account check of the keys it read, which
        /// their screen shows on every step, and pins it only on the person's yes. iPhone and iPad only, as above.
        @MainActor
        func testJoinByScanningTheirScreen() throws {
            step("launch")
            let app = XCUIApplication.launchedWithAccount()
            app.openSettings()
            app.syncNow(expecting: ".")
            app.openScreen(AccessibilityID.Settings.vaults)
            app.tap(AccessibilityID.Vaults.accept)

            step("scan their screen")
            XCTAssertTrue(app.element(AccessibilityID.Accept.number).appears(within: 10), app.debugDescription)
            app.tap(AccessibilityID.Debug.memberStarts)
            XCTAssertTrue(app.element(AccessibilityID.Debug.scanMember).appears(within: 10), app.debugDescription)
            app.tap(AccessibilityID.Debug.scanMember)
            step("the scan names their account check; they type this device's code; say it is theirs")
            XCTAssertTrue(app.element(AccessibilityID.Accept.scannedAccount).appears(within: 20), app.debugDescription)
            XCTAssertTrue(app.element(AccessibilityID.Accept.ownAccount).isPresent, app.debugDescription)
            app.tap(AccessibilityID.Debug.memberTypes)
            app.tapWhenEnabled(AccessibilityID.Accept.confirmScan)
            XCTAssertTrue(
                app.element(AccessibilityID.Accept.awaitingInvitation).appears(within: 15), app.debugDescription)
            step("their invitation arrives; join")
            app.tap(AccessibilityID.Debug.memberInvites)
            XCTAssertTrue(app.element(AccessibilityID.Accept.confirmText).appears(within: 20), app.debugDescription)
            app.tap(AccessibilityID.Accept.join)
            XCTAssertTrue(app.element(AccessibilityID.Accept.joined).appears(within: 20), app.debugDescription)
            app.closeScreen()
        }
    #endif

    /// This account joins a vault the other person shares: their number typed here (or their screen scanned), each
    /// types the other's six digits, and their invitation arrives inside the session.
    @MainActor
    func testJoinAnotherPersonsVaultWithAVaultSharingCode() throws {
        step("launch")
        let app = XCUIApplication.launchedWithAccount()
        app.openSettings()
        app.syncNow(expecting: ".")
        app.openScreen(AccessibilityID.Settings.vaults)
        app.tap(AccessibilityID.Vaults.accept)

        step("their code, typed")
        XCTAssertTrue(app.element(AccessibilityID.Accept.number).appears(within: 10), app.debugDescription)
        app.tap(AccessibilityID.Debug.memberStarts)
        app.tapWhenEnabled(AccessibilityID.Accept.joinWithNumber)
        step("their device reveals; each types the other's code")
        XCTAssertTrue(app.element(AccessibilityID.Accept.ownCode).appears(within: 20), app.debugDescription)
        app.tap(AccessibilityID.Debug.memberTypes)
        app.tap(AccessibilityID.Debug.fillMemberCode)
        app.tapWhenEnabled(AccessibilityID.Accept.confirmCode)
        XCTAssertTrue(app.element(AccessibilityID.Accept.awaitingInvitation).appears(within: 15), app.debugDescription)
        step("their invitation arrives; join")
        app.tap(AccessibilityID.Debug.memberInvites)
        XCTAssertTrue(app.element(AccessibilityID.Accept.confirmText).appears(within: 20), app.debugDescription)
        app.tap(AccessibilityID.Accept.join)
        XCTAssertTrue(app.element(AccessibilityID.Accept.joined).appears(within: 20), app.debugDescription)
        app.closeScreen()

        app.syncNow(expecting: ".")
        app.openScreen(AccessibilityID.Settings.vaults)
        XCTAssertTrue(
            app.element(AccessibilityID.Vaults.row("Shared by the household member")).appears(within: 20),
            app.debugDescription)
        app.closeScreen()
    }
}
