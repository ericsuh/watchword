import XCTest

/// The screenshot tour (docs/04-test-plan.md §5): one pass through every flow the app has, on iOS and macOS, that
/// attaches a picture of each major screen for a person to audit. `mise run app:screenshots` runs it and writes the
/// pictures to `Screenshots/<platform>/`; `app:test` runs it too, as one more end-to-end test, so a change that
/// breaks a flow breaks the tour in the ordinary CI job.
///
/// The app is launched with `--uitest` (in-memory ports, an account this test creates), and the other device and the
/// other person are the in-process `UITestPeer`, as in `SyncConflictTests` and the account-screen tests. Nothing real
/// is ever on screen. After the item flows and the conflict come vaults and sharing, the quarantine, the security
/// report, import, export and restore, and last a password changed elsewhere and the device removed for it, which
/// ends the other device's part (so it goes last).
///
/// To add a screen, drive the app to it here and add one `Screens.capture` line. Capture right after a tap or a
/// keystroke where there is one, because XCUITest waits for animations to finish around those; after something that
/// only appears (a sheet closing, the result of an unlock), wait for the element that proves the screen is complete.
final class ScreenshotTourTests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
        // A hang fails with a report rather than eating the job (`app:test` turns the allowances on). The tour
        // is every flow at once.
        executionTimeAllowance = 1800
    }

    @MainActor
    func testTourOfEveryScreen() throws {
        let password = OnboardingAndUnlockTests.password
        let app = XCUIApplication()
        app.launchArguments = Screens.launchArguments
        app.launchEnvironment["WATCHWORD_UITEST_PASSWORD"] = password
        step("launch")
        app.launch()
        Screens.prepareDevice()

        // Onboarding. The field has the focus already; the tap lets the keyboard finish arriving on iOS.
        let newPassword = app.secureTextFields["onboarding.password"]
        XCTAssertTrue(newPassword.appears(within: 10), app.debugDescription)
        newPassword.click()
        Screens.capture("onboarding", in: app, showing: "Creating the account: choosing the account password")
        newPassword.enterText(password)
        let confirmation = app.secureTextFields["onboarding.confirm"]
        confirmation.click()
        confirmation.enterText(password + "\n")

        // The Emergency Kit. The tap on the key does nothing; it waits for the keyboard to have gone.
        let secretKey = app.staticTexts["kit.secretKey"]
        XCTAssertTrue(secretKey.appears(within: 15), app.debugDescription)
        secretKey.click()
        Screens.capture(
            "emergency-kit", in: app, showing: "The Emergency Kit: the test account's Secret Key, before confirming")
        app.switches["kit.confirmSaved"].toggleOn()
        app.buttons["kit.continue"].click()

        // The vault, empty.
        let add = app.buttons["items.add"]
        XCTAssertTrue(add.appears(within: 10), app.debugDescription)
        XCTAssertTrue(secretKey.disappears(within: 10), "the Emergency Kit is still shown")
        Screens.capture("item-list-empty", in: app, showing: "The vault with no items yet")

        // A new item, with a generated password.
        add.click()
        let title = app.textFields["edit.title"]
        XCTAssertTrue(title.appears(within: 10), app.debugDescription)
        title.click()
        title.enterText("Library")
        app.textFields["edit.host"].click()
        app.textFields["edit.host"].enterText("citylibrary.org")
        app.textFields["edit.username"].click()
        app.textFields["edit.username"].enterText("pat")
        app.buttons["edit.generate"].click()
        Screens.capture("item-edit", in: app, showing: "A new item, its password filled in by the generator")
        app.buttons["edit.save"].click()
        XCTAssertTrue(app.itemRow("Library").appears(within: 10), app.debugDescription)
        XCTAssertTrue(title.disappears(within: 10), "the editor is still open")

        // A second item, so the list has more than one row and there is one to move to the trash.
        add.click()
        XCTAssertTrue(title.appears(within: 10), app.debugDescription)
        title.click()
        title.enterText("Garden club")
        app.textFields["edit.host"].click()
        app.textFields["edit.host"].enterText("gardenclub.org")
        app.buttons["edit.save"].click()
        XCTAssertTrue(app.itemRow("Garden club").appears(within: 10), app.debugDescription)
        XCTAssertTrue(title.disappears(within: 10), "the editor is still open")
        Screens.capture("item-list", in: app, showing: "The vault with two items")

        // An item, with its password hidden and then shown.
        app.itemRow("Library").firstMatch.click()
        XCTAssertTrue(app.staticTexts["detail.title"].appears(within: 10), app.debugDescription)
        let show = app.buttons["Show"].firstMatch
        XCTAssertTrue(show.appears(within: 10), app.debugDescription)
        Screens.capture("item-detail", in: app, showing: "An item, its password hidden")
        show.click()
        XCTAssertTrue(app.buttons["Hide"].firstMatch.appears(within: 10), app.debugDescription)
        Screens.capture("item-detail-revealed", in: app, showing: "The same item with its generated password shown")

        // Moving the other item to the trash asks first (PRD F1.5, F7.7).
        app.backToList()
        app.itemRow("Garden club").firstMatch.click()
        let trash = app.buttons["detail.trash"].firstMatch
        XCTAssertTrue(trash.appears(within: 10), app.debugDescription)
        trash.click()
        let confirmTrash = app.buttons.matching(
            NSPredicate(format: "label == %@ AND identifier != %@", "Move to Trash", "detail.trash")
        ).firstMatch
        XCTAssertTrue(confirmTrash.appears(within: 10), app.debugDescription)
        Screens.capture("trash-confirmation", in: app, showing: "The confirmation before an item moves to the Trash")
        confirmTrash.click()
        XCTAssertTrue(app.descendants(matching: .any)["detail.empty"].appears(within: 10))
        XCTAssertTrue(app.itemRow("Garden club").disappears(within: 10), "the trashed item is still listed")

        // Locked, and a wrong password.
        app.backToList()
        let lock = app.buttons["items.lock"].firstMatch
        XCTAssertTrue(lock.appears(within: 10), app.debugDescription)
        lock.click()
        let unlock = app.secureTextFields["unlock.password"]
        XCTAssertTrue(unlock.appears(within: 10), app.debugDescription)
        unlock.click()
        Screens.capture("locked", in: app, showing: "The locked app")
        unlock.enterText("not the password\n")
        XCTAssertTrue(app.staticTexts["error"].appears(within: 15), app.debugDescription)
        Screens.capture("unlock-failed", in: app, showing: "The locked app after a wrong password")
        unlock.click()
        unlock.enterText(password + "\n")
        XCTAssertTrue(app.itemRow("Library").appears(within: 15), app.debugDescription)

        step("settings and the conflict")
        // Settings. A --uitest launch adds the section that drives the other device; a release build has none.
        app.openSettings()
        Screens.capture("settings", in: app, showing: "Settings, with the UI-test section that drives the other device")

        // The item is published, renamed on the other device, and renamed here before this device has seen that.
        app.syncNow()
        app.buttons["debug.peerRename"].click()
        XCTAssertTrue(app.staticTexts["debug.peerStatus"].appears(within: 15), app.debugDescription)
        app.closeSettings()
        app.itemRow("Library").firstMatch.click()
        let edit = app.buttons["detail.edit"].firstMatch
        XCTAssertTrue(edit.appears(within: 10), app.debugDescription)
        edit.click()
        XCTAssertTrue(title.appears(within: 10), app.debugDescription)
        title.click()
        title.clearAndType("Library here")
        app.buttons["edit.save"].click()
        XCTAssertTrue(title.disappears(within: 10), "the editor is still open")

        // Syncing brings the two names together: the list marks the item, and the item offers both (PRD F7.6).
        app.backToList()
        app.openSettings()
        app.syncNow(expecting: "received")
        app.closeSettings()
        let conflicted = app.descendants(matching: .any).matching(
            NSPredicate(format: "identifier BEGINSWITH %@", "items.row.Library")
        ).firstMatch
        XCTAssertTrue(conflicted.appears(within: 10), app.debugDescription)
        Screens.capture("item-list-conflict", in: app, showing: "The list marking an item changed on two devices")
        conflicted.click()
        XCTAssertTrue(
            app.descendants(matching: .any)["detail.conflicts"].firstMatch.appears(within: 10),
            app.debugDescription)
        XCTAssertTrue(app.buttons["conflict.Title.1"].firstMatch.appears(within: 10), app.debugDescription)
        Screens.capture("conflict-resolution", in: app, showing: "The item offering both names, one to keep")
        app.buttons["conflict.Title.1"].firstMatch.click()
        XCTAssertTrue(
            app.descendants(matching: .any)["detail.conflicts"].firstMatch.disappears(within: 10),
            "the conflict is still shown")

        // The quarantine before sharing, as in QuarantineTests: the other device then writes into the Personal vault
        // alone.
        step("tourQuarantine")
        tourQuarantine(app)
        step("tourVaultsAndSharing")
        tourVaultsAndSharing(app)
        step("tourSecurityReport")
        tourSecurityReport(app)
        step("tourImportExportAndRestore")
        tourImportExportAndRestore(app)
        step("tourPasswordChangeAndDevices")
        tourPasswordChangeAndDevices(app, password: password)

        Screens.attachIndex()
    }

    /// Vaults, sharing one and inviting the other person with a vault sharing code, who joins; the full code as the
    /// fallback; and joining the other person's vault (PRD F2.1, F4.1, F4.2; ADR 0010).
    @MainActor
    private func tourVaultsAndSharing(_ app: XCUIApplication) {
        app.backToList()
        app.openScreen(AccessibilityID.Settings.vaults)
        XCTAssertTrue(app.element(AccessibilityID.Vaults.row("Personal")).appears(within: 10))
        Screens.capture("vault-list", in: app, showing: "The vaults: Personal only, before any is created")
        app.tap(AccessibilityID.Vaults.add)
        app.enter("Household", into: AccessibilityID.Vaults.newName)
        Screens.capture("vault-new", in: app, showing: "Naming a new vault")
        app.tap(AccessibilityID.Vaults.create)
        app.tap(AccessibilityID.Vaults.row("Household"))
        XCTAssertTrue(app.element(AccessibilityID.Vault.share).appears(within: 10), app.debugDescription)
        Screens.capture("vault-detail", in: app, showing: "A vault of one's own, not shared yet")
        app.tap(AccessibilityID.Vault.share)
        app.confirm("Share")
        app.tap(AccessibilityID.Vault.invite)
        XCTAssertTrue(app.element(AccessibilityID.Invite.startSession).appears(within: 10), app.debugDescription)
        Screens.capture("invite-start", in: app, showing: "Inviting: what a vault sharing code session asks of both")
        app.tap(AccessibilityID.Invite.startSession)
        XCTAssertTrue(app.element(AccessibilityID.Invite.number).appears(within: 15), app.debugDescription)
        app.element(AccessibilityID.Invite.number).click()
        Screens.capture(
            "invite-sharing-code", in: app, showing: "The vault sharing code and its QR code, for them to type or scan")
        app.tap(AccessibilityID.Debug.memberJoins)
        XCTAssertTrue(app.element(AccessibilityID.Invite.typedCode).appears(within: 15), app.debugDescription)
        app.element(AccessibilityID.Invite.typedCode).click()
        Screens.capture(
            "invite-their-code", in: app, showing: "Their device answered: type the six digits on their screen")
        app.tap(AccessibilityID.Debug.fillMemberCode)
        app.tapWhenEnabled(AccessibilityID.Invite.confirmCode)
        XCTAssertTrue(app.element(AccessibilityID.Invite.ownCode).appears(within: 15), app.debugDescription)
        app.element(AccessibilityID.Invite.ownCode).click()
        Screens.capture(
            "invite-own-code", in: app, showing: "Their code matched: this device's code for them, and the role")
        app.tap(AccessibilityID.Debug.memberTypes)
        app.tap(AccessibilityID.Invite.send)
        XCTAssertTrue(app.element(AccessibilityID.Invite.sent).appears(within: 15), app.debugDescription)
        app.element(AccessibilityID.Invite.sent).click()
        Screens.capture("invite-sent", in: app, showing: "The invitation went to their device inside the session")
        app.tap(AccessibilityID.Debug.memberAcceptsSession)
        app.waitForText("accepted the invitation", in: "debug.peerStatus", timeout: 20)
        // Done closes the whole screen from here; the invitation screen's own Done only goes back a step.
        app.closeScreen()

        app.syncNow(expecting: ".")
        app.openScreen(AccessibilityID.Settings.vaults)
        app.tap(AccessibilityID.Vaults.row("Household"))
        let member = app.descendants(matching: .any).matching(
            NSPredicate(
                format: "identifier BEGINSWITH %@ AND NOT identifier ENDSWITH %@", "vault.member.Member ", ".role")
        ).firstMatch
        XCTAssertTrue(member.appears(within: 15), app.debugDescription)
        Screens.capture(
            "vault-members", in: app, showing: "The shared vault's members: the owner and the person invited")
        // The full code, behind the start screen's secondary action.
        app.tap(AccessibilityID.Vault.invite)
        app.tap(AccessibilityID.Invite.fullCode)
        XCTAssertTrue(app.element(AccessibilityID.Invite.account).appears(within: 10), app.debugDescription)
        app.tap(AccessibilityID.Invite.uiTestFill)
        app.tapWhenEnabled(AccessibilityID.Invite.lookUp)
        XCTAssertTrue(app.element(AccessibilityID.Invite.invitee).appears(within: 15), app.debugDescription)
        app.closeScreen()

        app.openScreen(AccessibilityID.Settings.vaults)
        app.tap(AccessibilityID.Vault.ownSafetyNumber)
        XCTAssertTrue(app.element(AccessibilityID.Vault.fingerprint).appears(within: 10))
        app.element(AccessibilityID.Vault.fingerprint).click()
        Screens.capture(
            "own-full-code", in: app, showing: "This account's full vault sharing code and QR code, the fallback")
        app.closeScreen()

        // Joining the other person's vault.
        app.openScreen(AccessibilityID.Settings.vaults)
        app.tap(AccessibilityID.Vaults.accept)
        XCTAssertTrue(app.element(AccessibilityID.Accept.number).appears(within: 10), app.debugDescription)
        app.tap(AccessibilityID.Debug.memberStarts)
        app.element(AccessibilityID.Accept.number).click()
        Screens.capture("accept-number", in: app, showing: "Accepting: their vault sharing code, typed or scanned")
        app.tapWhenEnabled(AccessibilityID.Accept.joinWithNumber)
        XCTAssertTrue(app.element(AccessibilityID.Accept.ownCode).appears(within: 20), app.debugDescription)
        app.element(AccessibilityID.Accept.ownCode).click()
        Screens.capture(
            "accept-codes", in: app, showing: "This device's six digits for them, and a field for theirs")
        app.tap(AccessibilityID.Debug.memberTypes)
        app.tap(AccessibilityID.Debug.fillMemberCode)
        app.tapWhenEnabled(AccessibilityID.Accept.confirmCode)
        XCTAssertTrue(app.element(AccessibilityID.Accept.awaitingInvitation).appears(within: 15), app.debugDescription)
        app.tap(AccessibilityID.Debug.memberInvites)
        XCTAssertTrue(app.element(AccessibilityID.Accept.confirmText).appears(within: 20), app.debugDescription)
        app.element(AccessibilityID.Accept.confirmText).click()
        Screens.capture("accept-confirm", in: app, showing: "Their invitation arrived: join only on a yes")
        app.tap(AccessibilityID.Accept.join)
        XCTAssertTrue(app.element(AccessibilityID.Accept.joined).appears(within: 20), app.debugDescription)
        app.closeScreen()
        app.openScreen(AccessibilityID.Settings.vaults)
        app.tap(AccessibilityID.Vaults.accept)
        app.tap(AccessibilityID.Accept.fullCode)
        XCTAssertTrue(app.element(AccessibilityID.Accept.code).appears(within: 10), app.debugDescription)
        app.element(AccessibilityID.Accept.code).click()
        Screens.capture("accept-invitation", in: app, showing: "The fallback: pasting an invitation sent as text")
        app.closeScreen()
    }

    /// A version the other device wrote far above anything seen, held aside and listed (PRD F7.7; U5).
    @MainActor
    private func tourQuarantine(_ app: XCUIApplication) {
        app.runPeerHook(AccessibilityID.Debug.peerImplausible, expecting: "implausible edit")
        app.syncNow(expecting: "held for review")
        app.openScreen(AccessibilityID.Settings.quarantine)
        XCTAssertTrue(
            app.element(AccessibilityID.Quarantine.row(0)).appears(within: 15), app.debugDescription)
        Screens.capture("quarantine", in: app, showing: "A change held aside, with its item, vault and device")
        app.tap(AccessibilityID.Quarantine.discard(0))
        app.confirm("Discard")
        XCTAssertTrue(app.element(AccessibilityID.Quarantine.empty).appears(within: 15), app.debugDescription)
        app.closeScreen()
    }

    /// Two items sharing a breached password, and the report after a check (PRD F9.1–F9.3).
    @MainActor
    private func tourSecurityReport(_ app: XCUIApplication) {
        app.closeSettings()
        app.backToList()
        app.addLogin(title: "Forum", host: "forum.example", username: "pat", password: "password")
        app.addLogin(title: "Shop", host: "shop.example", username: "pat", password: "password")
        app.openScreen(AccessibilityID.Settings.hygiene)
        app.tap(AccessibilityID.Hygiene.checkNow)
        app.waitForText("checked", in: AccessibilityID.Hygiene.status, timeout: 20)
        XCTAssertTrue(app.element(AccessibilityID.Hygiene.section("breached")).appears(within: 10))
        Screens.capture(
            "security-report", in: app, showing: "The security report: a breached password, reused by two items")
        app.closeScreen()
    }

    /// An import with a duplicate, a plaintext export's report, a backup, and its restore (PRD F8.1–F8.5).
    @MainActor
    private func tourImportExportAndRestore(_ app: XCUIApplication) {
        app.openScreen(AccessibilityID.Settings.importItems)
        XCTAssertTrue(app.element(AccessibilityID.Import.vault).appears(within: 10))
        Screens.capture("import", in: app, showing: "Importing: the vault and the other app's format")
        app.tap(AccessibilityID.Import.uiTestSample)
        XCTAssertTrue(app.element(AccessibilityID.Import.duplicate("Library")).appears(within: 15))
        app.element(AccessibilityID.Import.duplicate("Library")).click()
        Screens.capture("import-review", in: app, showing: "The import's review: a duplicate waiting for a choice")
        app.tap(AccessibilityID.Import.choice("Library") + ".merge")
        app.reveal(AccessibilityID.Import.host("www.citylibrary.org"))
        let host = app.switches[AccessibilityID.Import.host("www.citylibrary.org")].firstMatch
        XCTAssertTrue(host.appears(within: 15), app.debugDescription)
        Screens.capture(
            "import-merge", in: app,
            showing: "A merge naming the website and sign-in details it would add, none accepted, the password hidden")
        host.toggleOn()
        app.tapWhenEnabled(AccessibilityID.Import.commit)
        app.waitForText("merged", in: AccessibilityID.Import.summary)
        Screens.capture("import-done", in: app, showing: "What the import did")
        app.tap(AccessibilityID.Import.done)

        app.openScreen(AccessibilityID.Settings.export)
        XCTAssertTrue(app.element(AccessibilityID.Export.warning).appears(within: 10))
        Screens.capture("export", in: app, showing: "Export and backup, with the standing plaintext warning")
        app.tap(AccessibilityID.Export.kind + ".applePasswordsCSV")
        app.enter(OnboardingAndUnlockTests.password, into: AccessibilityID.Export.password)
        app.tap(AccessibilityID.Export.run)
        app.waitForText("item(s) in the file", in: AccessibilityID.Export.count)
        app.element(AccessibilityID.Export.count).click()
        Screens.capture(
            "export-report", in: app, showing: "A plaintext export's report, shown before the file is saved")
        app.tap(AccessibilityID.Export.kind + ".archive")
        app.enter(OnboardingAndUnlockTests.password, into: AccessibilityID.Export.password)
        app.enter("garden shed padlock", into: AccessibilityID.Export.passphrase)
        app.enter("garden shed padlock", into: AccessibilityID.Export.passphraseConfirmation)
        app.tap(AccessibilityID.Export.run)
        app.waitForText("item(s) in the file", in: AccessibilityID.Export.count)
        app.closeScreen()

        app.openScreen(AccessibilityID.Settings.restore)
        app.enter("garden shed padlock", into: AccessibilityID.Import.passphrase)
        app.tap(AccessibilityID.Import.uiTestArchive)
        XCTAssertTrue(
            app.element(AccessibilityID.Import.archiveDate).appears(within: 20), app.debugDescription)
        app.element(AccessibilityID.Import.archiveDate).click()
        Screens.capture("restore-review", in: app, showing: "Restoring a backup: the date it was made, first")
        app.closeScreen()
    }

    /// The other device changes the password; this one is told, takes the account back with the password it has,
    /// and removes that device with a new password (PRD F10.1, F10.2; docs/02-architecture.md §7.8).
    @MainActor
    private func tourPasswordChangeAndDevices(_ app: XCUIApplication, password: String) {
        app.runPeerHook(AccessibilityID.Debug.peerPassword, expecting: "password was changed")
        app.syncNow(expecting: "new account password")
        app.waitForText("changed on another device", in: AccessibilityID.Settings.syncNotice)
        Screens.capture("sync-password-changed", in: app, showing: "Settings after a password change on another device")
        app.closeSettings()

        app.backToList()
        app.buttons["items.lock"].firstMatch.click()
        let unlock = app.secureTextFields["unlock.password"]
        XCTAssertTrue(unlock.appears(within: 10), app.debugDescription)
        unlock.click()
        unlock.enterText(password + "\n")
        XCTAssertTrue(app.element(AccessibilityID.Unlock.passwordChanged).appears(within: 15))
        unlock.click()
        Screens.capture(
            "unlock-password-changed", in: app, showing: "The old password refused, and the way out if that was not you"
        )
        unlock.enterText(password)
        app.tapWhenEnabled(AccessibilityID.Unlock.ignoreChange)
        XCTAssertTrue(app.buttons["items.add"].appears(within: 15), app.debugDescription)

        app.openScreen(AccessibilityID.Settings.devices)
        let other = UITestNames.otherDevice
        XCTAssertTrue(
            app.element(AccessibilityID.Devices.row(other)).appears(within: 15), app.debugDescription)
        Screens.capture("devices", in: app, showing: "The account's devices, with the other one's password change")
        app.tap(AccessibilityID.Devices.revoke(other))
        app.enter(password, into: AccessibilityID.Devices.current)
        app.enter(DeviceRevocationTests.newPassword, into: AccessibilityID.Devices.new)
        app.enter(DeviceRevocationTests.newPassword, into: AccessibilityID.Devices.confirmation)
        Screens.capture("device-revoke", in: app, showing: "Removing a device, changing the password in the same step")
        app.tap(AccessibilityID.Devices.confirm)
        app.waitForText("was removed", in: AccessibilityID.Devices.notice)
        Screens.capture("devices-after-revoke", in: app, showing: "The other device removed")
        app.closeScreen()
    }
}

extension XCUIApplication {
    /// The list row of the item with this title. On macOS the identifier lands on each of the row's texts, so
    /// callers click `firstMatch`.
    func itemRow(_ title: String) -> XCUIElement {
        descendants(matching: .any)["items.row.\(title)"]
    }

    /// Dismisses Settings and waits until its sheet has gone, so whatever comes next is not pictured or tapped
    /// through a sheet that is still closing.
    func closeSettings(file: StaticString = #filePath, line: UInt = #line) {
        let done = buttons["settings.done"]
        if !waitUntilHittable(done, timeout: 5) {
            attachTree("close Settings", target: "settings.done")
            XCTFail("Settings' Done cannot be clicked", file: file, line: line)
            return
        }
        done.click()
        if !done.disappears(within: 10) {
            attachTree("close Settings", target: "settings.done")
            XCTFail("Settings is still open", file: file, line: line)
        }
    }
}
