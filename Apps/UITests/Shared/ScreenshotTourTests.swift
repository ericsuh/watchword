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
    }

    @MainActor
    func testTourOfEveryScreen() throws {
        let password = OnboardingAndUnlockTests.password
        let app = XCUIApplication()
        app.launchArguments = Screens.launchArguments
        app.launchEnvironment["WATCHWORD_UITEST_PASSWORD"] = password
        app.launch()
        Screens.prepareDevice()

        // Onboarding. The field has the focus already; the tap lets the keyboard finish arriving on iOS.
        let newPassword = app.secureTextFields["onboarding.password"]
        XCTAssertTrue(newPassword.waitForExistence(timeout: 10), app.debugDescription)
        newPassword.click()
        Screens.capture("onboarding", in: app, showing: "Creating the account: choosing the account password")
        newPassword.typeText(password)
        let confirmation = app.secureTextFields["onboarding.confirm"]
        confirmation.click()
        confirmation.typeText(password + "\n")

        // The Emergency Kit. The tap on the key does nothing; it waits for the keyboard to have gone.
        let secretKey = app.staticTexts["kit.secretKey"]
        XCTAssertTrue(secretKey.waitForExistence(timeout: 30), app.debugDescription)
        secretKey.click()
        Screens.capture(
            "emergency-kit", in: app, showing: "The Emergency Kit: the test account's Secret Key, before confirming")
        app.switches["kit.confirmSaved"].toggleOn()
        app.buttons["kit.continue"].click()

        // The vault, empty.
        let add = app.buttons["items.add"]
        XCTAssertTrue(add.waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertTrue(secretKey.waitForNonExistence(timeout: 10), "the Emergency Kit is still shown")
        Screens.capture("item-list-empty", in: app, showing: "The vault with no items yet")

        // A new item, with a generated password.
        add.click()
        let title = app.textFields["edit.title"]
        XCTAssertTrue(title.waitForExistence(timeout: 10), app.debugDescription)
        title.click()
        title.typeText("Library")
        app.textFields["edit.host"].click()
        app.textFields["edit.host"].typeText("citylibrary.org")
        app.textFields["edit.username"].click()
        app.textFields["edit.username"].typeText("pat")
        app.buttons["edit.generate"].click()
        Screens.capture("item-edit", in: app, showing: "A new item, its password filled in by the generator")
        app.buttons["edit.save"].click()
        XCTAssertTrue(app.itemRow("Library").waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertTrue(title.waitForNonExistence(timeout: 10), "the editor is still open")

        // A second item, so the list has more than one row and there is one to move to the trash.
        add.click()
        XCTAssertTrue(title.waitForExistence(timeout: 10), app.debugDescription)
        title.click()
        title.typeText("Garden club")
        app.textFields["edit.host"].click()
        app.textFields["edit.host"].typeText("gardenclub.org")
        app.buttons["edit.save"].click()
        XCTAssertTrue(app.itemRow("Garden club").waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertTrue(title.waitForNonExistence(timeout: 10), "the editor is still open")
        Screens.capture("item-list", in: app, showing: "The vault with two items")

        // An item, with its password hidden and then shown.
        app.itemRow("Library").firstMatch.click()
        XCTAssertTrue(app.staticTexts["detail.title"].waitForExistence(timeout: 10), app.debugDescription)
        let show = app.buttons["Show"].firstMatch
        XCTAssertTrue(show.waitForExistence(timeout: 10), app.debugDescription)
        Screens.capture("item-detail", in: app, showing: "An item, its password hidden")
        show.click()
        XCTAssertTrue(app.buttons["Hide"].firstMatch.waitForExistence(timeout: 10), app.debugDescription)
        Screens.capture("item-detail-revealed", in: app, showing: "The same item with its generated password shown")

        // Moving the other item to the trash asks first (PRD F1.5, F7.7).
        app.backToList()
        app.itemRow("Garden club").firstMatch.click()
        let trash = app.buttons["detail.trash"].firstMatch
        XCTAssertTrue(trash.waitForExistence(timeout: 10), app.debugDescription)
        trash.click()
        let confirmTrash = app.buttons.matching(
            NSPredicate(format: "label == %@ AND identifier != %@", "Move to Trash", "detail.trash")
        ).firstMatch
        XCTAssertTrue(confirmTrash.waitForExistence(timeout: 10), app.debugDescription)
        Screens.capture("trash-confirmation", in: app, showing: "The confirmation before an item moves to the Trash")
        confirmTrash.click()
        XCTAssertTrue(app.descendants(matching: .any)["detail.empty"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.itemRow("Garden club").waitForNonExistence(timeout: 10), "the trashed item is still listed")

        // Locked, and a wrong password.
        app.backToList()
        let lock = app.buttons["items.lock"].firstMatch
        XCTAssertTrue(lock.waitForExistence(timeout: 10), app.debugDescription)
        lock.click()
        let unlock = app.secureTextFields["unlock.password"]
        XCTAssertTrue(unlock.waitForExistence(timeout: 10), app.debugDescription)
        unlock.click()
        Screens.capture("locked", in: app, showing: "The locked app")
        unlock.typeText("not the password\n")
        XCTAssertTrue(app.staticTexts["error"].waitForExistence(timeout: 30), app.debugDescription)
        Screens.capture("unlock-failed", in: app, showing: "The locked app after a wrong password")
        unlock.click()
        unlock.typeText(password + "\n")
        XCTAssertTrue(app.itemRow("Library").waitForExistence(timeout: 30), app.debugDescription)

        // Settings. A --uitest launch adds the section that drives the other device; a release build has none.
        app.openSettings()
        Screens.capture("settings", in: app, showing: "Settings, with the UI-test section that drives the other device")

        // The item is published, renamed on the other device, and renamed here before this device has seen that.
        app.syncNow()
        app.buttons["debug.peerRename"].click()
        XCTAssertTrue(app.staticTexts["debug.peerStatus"].waitForExistence(timeout: 30), app.debugDescription)
        app.closeSettings()
        app.itemRow("Library").firstMatch.click()
        let edit = app.buttons["detail.edit"].firstMatch
        XCTAssertTrue(edit.waitForExistence(timeout: 10), app.debugDescription)
        edit.click()
        XCTAssertTrue(title.waitForExistence(timeout: 10), app.debugDescription)
        title.click()
        title.clearAndType("Library here")
        app.buttons["edit.save"].click()
        XCTAssertTrue(title.waitForNonExistence(timeout: 10), "the editor is still open")

        // Syncing brings the two names together: the list marks the item, and the item offers both (PRD F7.6).
        app.backToList()
        app.openSettings()
        app.syncNow(expecting: "received")
        app.closeSettings()
        let conflicted = app.descendants(matching: .any).matching(
            NSPredicate(format: "identifier BEGINSWITH %@", "items.row.Library")
        ).firstMatch
        XCTAssertTrue(conflicted.waitForExistence(timeout: 10), app.debugDescription)
        Screens.capture("item-list-conflict", in: app, showing: "The list marking an item changed on two devices")
        conflicted.click()
        XCTAssertTrue(
            app.descendants(matching: .any)["detail.conflicts"].firstMatch.waitForExistence(timeout: 10),
            app.debugDescription)
        XCTAssertTrue(app.buttons["conflict.Title.1"].firstMatch.waitForExistence(timeout: 10), app.debugDescription)
        Screens.capture("conflict-resolution", in: app, showing: "The item offering both names, one to keep")
        app.buttons["conflict.Title.1"].firstMatch.click()
        XCTAssertTrue(
            app.descendants(matching: .any)["detail.conflicts"].firstMatch.waitForNonExistence(timeout: 10),
            "the conflict is still shown")

        tourVaultsAndSharing(app)
        tourQuarantine(app)
        tourSecurityReport(app)
        tourImportExportAndRestore(app)
        tourPasswordChangeAndDevices(app, password: password)

        Screens.attachIndex()
    }

    /// Vaults, sharing one and inviting the other person, who accepts (PRD F2.1, F4.1, F4.2).
    @MainActor
    private func tourVaultsAndSharing(_ app: XCUIApplication) {
        app.backToList()
        app.openScreen(AccessibilityID.Settings.vaults)
        XCTAssertTrue(app.element(AccessibilityID.Vaults.row("Personal")).waitForExistence(timeout: 10))
        Screens.capture("vault-list", in: app, showing: "The vaults: Personal only, before any is created")
        app.tap(AccessibilityID.Vaults.add)
        app.enter("Household", into: AccessibilityID.Vaults.newName)
        Screens.capture("vault-new", in: app, showing: "Naming a new vault")
        app.tap(AccessibilityID.Vaults.create)
        app.tap(AccessibilityID.Vaults.row("Household"))
        XCTAssertTrue(app.element(AccessibilityID.Vault.share).waitForExistence(timeout: 10), app.debugDescription)
        Screens.capture("vault-detail", in: app, showing: "A vault of one's own, not shared yet")
        app.tap(AccessibilityID.Vault.share)
        app.confirm("Share")
        app.tap(AccessibilityID.Vault.invite)
        app.tap(AccessibilityID.Invite.uiTestFill)
        app.tapWhenEnabled(AccessibilityID.Invite.lookUp)
        XCTAssertTrue(app.element(AccessibilityID.Invite.safetyNumber).waitForExistence(timeout: 30))
        app.element(AccessibilityID.Invite.safetyNumber).click()
        Screens.capture(
            "invite-fingerprint", in: app, showing: "Inviting: the other person's safety number, to compare first")
        app.switches[AccessibilityID.Invite.comparedByEye].firstMatch.toggleOn()
        app.tap(AccessibilityID.Invite.confirm)
        app.tap(AccessibilityID.Invite.send)
        XCTAssertTrue(app.element(AccessibilityID.Invite.code).waitForExistence(timeout: 30), app.debugDescription)
        app.element(AccessibilityID.Invite.code).click()
        Screens.capture("invite-code", in: app, showing: "The invitation to send, once the numbers were compared")
        app.tap(AccessibilityID.Invite.done)
        app.closeScreen()

        app.runPeerHook(AccessibilityID.Debug.householdAccept, expecting: "accepted the invitation")
        app.syncNow(expecting: ".")
        app.openScreen(AccessibilityID.Settings.vaults)
        app.tap(AccessibilityID.Vaults.row("Household"))
        let member = app.descendants(matching: .any).matching(
            NSPredicate(
                format: "identifier BEGINSWITH %@ AND NOT identifier ENDSWITH %@", "vault.member.Member ", ".role")
        ).firstMatch
        XCTAssertTrue(member.waitForExistence(timeout: 30), app.debugDescription)
        Screens.capture(
            "vault-members", in: app, showing: "The shared vault's members: the owner and the person invited")
        app.closeScreen()

        app.openScreen(AccessibilityID.Settings.vaults)
        app.tap(AccessibilityID.Vault.ownSafetyNumber)
        XCTAssertTrue(app.element(AccessibilityID.Vault.fingerprint).waitForExistence(timeout: 10))
        app.element(AccessibilityID.Vault.fingerprint).click()
        Screens.capture("own-safety-number", in: app, showing: "This account's own safety number and QR code")
        app.closeScreen()

        app.openScreen(AccessibilityID.Settings.vaults)
        app.tap(AccessibilityID.Vaults.accept)
        XCTAssertTrue(app.element(AccessibilityID.Accept.code).waitForExistence(timeout: 10), app.debugDescription)
        app.element(AccessibilityID.Accept.code).click()
        Screens.capture("accept-invitation", in: app, showing: "Accepting an invitation: pasting it comes first")
        app.closeScreen()
    }

    /// A version the other device wrote far above anything seen, held aside and listed (PRD F7.7; U5).
    @MainActor
    private func tourQuarantine(_ app: XCUIApplication) {
        app.runPeerHook(AccessibilityID.Debug.peerImplausible, expecting: "implausible edit")
        app.syncNow(expecting: "held for review")
        app.openScreen(AccessibilityID.Settings.quarantine)
        XCTAssertTrue(
            app.element(AccessibilityID.Quarantine.row(0)).waitForExistence(timeout: 30), app.debugDescription)
        Screens.capture("quarantine", in: app, showing: "A change held aside, with its item, vault and device")
        app.tap(AccessibilityID.Quarantine.discard(0))
        app.confirm("Discard")
        XCTAssertTrue(app.element(AccessibilityID.Quarantine.empty).waitForExistence(timeout: 30), app.debugDescription)
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
        app.waitForText("checked", in: AccessibilityID.Hygiene.status, timeout: 60)
        XCTAssertTrue(app.element(AccessibilityID.Hygiene.section("breached")).waitForExistence(timeout: 10))
        Screens.capture(
            "security-report", in: app, showing: "The security report: a breached password, reused by two items")
        app.closeScreen()
    }

    /// An import with a duplicate, a plaintext export's report, a backup, and its restore (PRD F8.1–F8.5).
    @MainActor
    private func tourImportExportAndRestore(_ app: XCUIApplication) {
        app.openScreen(AccessibilityID.Settings.importItems)
        XCTAssertTrue(app.element(AccessibilityID.Import.vault).waitForExistence(timeout: 10))
        Screens.capture("import", in: app, showing: "Importing: the vault and the other app's format")
        app.tap(AccessibilityID.Import.uiTestSample)
        XCTAssertTrue(app.element(AccessibilityID.Import.duplicate("Library")).waitForExistence(timeout: 30))
        app.element(AccessibilityID.Import.duplicate("Library")).click()
        Screens.capture("import-review", in: app, showing: "The import's review: a duplicate waiting for a choice")
        app.tap(AccessibilityID.Import.choice("Library") + ".merge")
        let host = app.switches[AccessibilityID.Import.host("www.citylibrary.org")].firstMatch
        XCTAssertTrue(host.waitForExistence(timeout: 30), app.debugDescription)
        Screens.capture(
            "import-merge", in: app,
            showing: "A merge naming the website and sign-in details it would add, none accepted, the password hidden")
        host.toggleOn()
        app.tapWhenEnabled(AccessibilityID.Import.commit)
        app.waitForText("merged", in: AccessibilityID.Import.summary)
        Screens.capture("import-done", in: app, showing: "What the import did")
        app.tap(AccessibilityID.Import.done)

        app.openScreen(AccessibilityID.Settings.export)
        XCTAssertTrue(app.element(AccessibilityID.Export.warning).waitForExistence(timeout: 10))
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
            app.element(AccessibilityID.Import.archiveDate).waitForExistence(timeout: 60), app.debugDescription)
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
        XCTAssertTrue(unlock.waitForExistence(timeout: 10), app.debugDescription)
        unlock.click()
        unlock.typeText(password + "\n")
        XCTAssertTrue(app.element(AccessibilityID.Unlock.passwordChanged).waitForExistence(timeout: 30))
        unlock.click()
        Screens.capture(
            "unlock-password-changed", in: app, showing: "The old password refused, and the way out if that was not you"
        )
        unlock.typeText(password)
        app.tapWhenEnabled(AccessibilityID.Unlock.ignoreChange)
        XCTAssertTrue(app.buttons["items.add"].waitForExistence(timeout: 30), app.debugDescription)

        app.openScreen(AccessibilityID.Settings.devices)
        let other = UITestNames.otherDevice
        XCTAssertTrue(
            app.element(AccessibilityID.Devices.row(other)).waitForExistence(timeout: 30), app.debugDescription)
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
    func closeSettings() {
        let done = buttons["settings.done"]
        done.click()
        XCTAssertTrue(done.waitForNonExistence(timeout: 10), "Settings is still open")
    }
}
