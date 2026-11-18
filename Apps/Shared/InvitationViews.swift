import SwiftUI
import WatchwordPresentation
import WatchwordSharing

/// Inviting someone to a shared vault (PRD F4.1, F4.2; ADR 0010): show the vault sharing code, type the six digits on
/// their screen (or scan it), let them type this device's six, choose a role, and send the invitation, which reaches
/// their device inside the session. The check is not optional: the session refuses to invite an account it has not
/// pinned. The full vault sharing code (sixty digits) is the fallback for two people who cannot be together. Thin: every
/// decision is `InvitationModel`'s and the session's.
struct InviteView: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var model: InvitationModel

    init(vaultID: UUID, context: ScreenContext) {
        _model = State(initialValue: InvitationModel(vaultID: vaultID, context: context))
    }

    var body: some View {
        Form {
            switch model.step {
            case .start:
                start
            case .showCode(let number, let payload):
                showCode(number: number, payload: payload)
            case .typeTheirCode(let attemptsLeft):
                typeTheirCode(attemptsLeft: attemptsLeft)
            case .chooseRole(let code, _):
                if let code { ownCode(code) }
                chooseRole
            case .keysChanged:
                keysChanged
            case .failed(let message):
                failed(message)
            case .nameAccount:
                nameAccount
            case .compareFingerprint(let comparison):
                compare(comparison)
            case .issued(let code):
                issued(code)
            }
            ErrorText(message: model.errorMessage)
        }
        .formStyle(.grouped)
        .navigationTitle("Invite Someone")
        .closesSheet()
        .overlay { if model.isWorking { ProgressView() } }
        // While waiting for their device: look again every two seconds. A cancelled sleep (the step moved on, so the
        // task's id changed) must not refresh once more: that refresh took a finished step back to waiting, and the
        // screen flickered between the two for as long as it was open (the first Mac run's UI tests).
        .task(id: model.isWaiting) {
            while model.isWaiting {
                guard (try? await Task.sleep(for: .seconds(2))) != nil, model.isWaiting else { return }
                await model.refresh()
            }
        }
    }

    // MARK: The vault sharing code

    private var start: some View {
        Group {
            Section {
                Text(
                    "You both need your devices. Yours shows an eight-digit vault sharing code; they type it, or scan "
                        + "it. Then each of you types the six digits the other's screen shows.")
                Button("Show Vault Sharing Code") { Task { await model.startSession() } }
                    .disabled(model.isWorking)
                    .accessibilityIdentifier(AccessibilityID.Invite.startSession)
            } footer: {
                Text(SharingCodeWording.channelWarning)
            }
            Section {
                Button("Use the Full Code Instead") { Task { await model.useFullCode() } }
                    .accessibilityIdentifier(AccessibilityID.Invite.fullCode)
            } footer: {
                Text("For when you cannot be at your devices at the same time: sixty digits, typed.")
            }
        }
    }

    private func showCode(number: String, payload: String) -> some View {
        Group {
            Section {
                SharingDigits(code: number)
                    .accessibilityIdentifier(AccessibilityID.Invite.number)
                QRCodeView(text: payload)
                    .accessibilityIdentifier(AccessibilityID.Invite.qr)
                if let own = model.status?.ownAccount {
                    Text("You are the account \(shortIdentifier(own)).").font(.footnote).foregroundStyle(.secondary)
                }
            } header: {
                Text("Your vault sharing code")
            } footer: {
                Text(
                    "Read these digits to them, or let them scan the code. It is not a secret: it only finds this "
                        + "session, and nothing is shared until you have both typed each other's next code.")
            }
            Section {
                Text("Waiting for their device…").foregroundStyle(.secondary)
                Button("Check Again") { Task { await model.refresh() } }
                    .accessibilityIdentifier(AccessibilityID.Invite.checkAgain)
                #if DEBUG
                    if app.uiTestPeer != nil {
                        Button("The household member types this code (UI test)") {
                            Task {
                                await app.uiTestMemberJoins(number: number)
                                await model.refresh()
                            }
                        }
                        .accessibilityIdentifier(AccessibilityID.Debug.memberJoins)
                    }
                #endif
            }
        }
    }

    private func typeTheirCode(attemptsLeft: Int) -> some View {
        Section {
            TextField("Six digits from their screen", text: $model.typedCode)
                .font(.system(.title2, design: .monospaced))
                .autocorrectionDisabled()
                #if os(iOS)
                    .keyboardType(.numberPad)
                #endif
                .accessibilityIdentifier(AccessibilityID.Invite.typedCode)
            Button("Check") { Task { await model.confirmTheirCode() } }
                .disabled(model.typedCode.isEmpty || model.isWorking)
                .accessibilityIdentifier(AccessibilityID.Invite.confirmCode)
            ScanCodeButton(
                title: "Scan Their Screen", accessibilityID: AccessibilityID.Invite.scan,
                uiTestPayload: { await app.uiTestScanPayload() },
                onScan: { await model.cameraScanned($0) })
            #if DEBUG
                if app.uiTestPeer != nil {
                    Button("Fill in the household member's code (UI test)") {
                        Task { model.typedCode = await app.uiTestMemberCode() ?? "" }
                    }
                    .accessibilityIdentifier(AccessibilityID.Debug.fillMemberCode)
                }
            #endif
        } header: {
            Text("Their confirmation code")
        } footer: {
            Text(
                "Their device answered. Type the six digits their screen shows now. If they do not match, stop: "
                    + "someone may be between you. \(attemptsLeft) tries left.")
        }
    }

    private func ownCode(_ code: String) -> some View {
        Section {
            SharingDigits(code: code)
                .accessibilityIdentifier(AccessibilityID.Invite.ownCode)
            #if DEBUG
                if app.uiTestPeer != nil {
                    Button("The household member types this code (UI test)") {
                        Task { await app.uiTestMemberTypes(code: code) }
                    }
                    .accessibilityIdentifier(AccessibilityID.Debug.memberTypes)
                }
            #endif
        } header: {
            Text("Your confirmation code")
        } footer: {
            Text("Their code matched. Read these six digits to them, so they can check you too.")
        }
    }

    private var keysChanged: some View {
        Section {
            Banner(
                text: "These are not the keys you checked for this account before. Use the new keys only if you "
                    + "know they set up Watchword again, and you just checked them in person.",
                systemImage: "exclamationmark.octagon")
            Button("Use Their New Keys", role: .destructive) { Task { await model.useNewKeys() } }
                .accessibilityIdentifier(AccessibilityID.Invite.useNewKeys)
            Button("Start Over") { Task { await model.startOver() } }
                .accessibilityIdentifier(AccessibilityID.Invite.startOver)
        }
    }

    private func failed(_ message: String) -> some View {
        Section {
            Banner(text: message).accessibilityIdentifier(AccessibilityID.Invite.failed)
            Button("Start Over") { Task { await model.startOver() } }
                .accessibilityIdentifier(AccessibilityID.Invite.startOver)
        }
    }

    // MARK: The full code

    private var nameAccount: some View {
        Section {
            TextField("Their Watchword ID or fingerprint code", text: $model.accountText, axis: .vertical)
                .autocorrectionDisabled()
                #if os(iOS)
                    .textInputAutocapitalization(.never)
                #endif
                .accessibilityIdentifier(AccessibilityID.Invite.account)
            Button("Look Up") { Task { await model.lookUp() } }
                .disabled(model.accountText.isEmpty || model.isWorking)
                .accessibilityIdentifier(AccessibilityID.Invite.lookUp)
            #if DEBUG
                if app.uiTestPeer != nil {
                    Button("Use the UI-test household member") {
                        Task { model.accountText = await app.householdAccountID() ?? "" }
                    }
                    .accessibilityIdentifier(AccessibilityID.Invite.uiTestFill)
                }
            #endif
        } footer: {
            Text("They find both in Settings, Vaults, Your Full Vault Sharing Code.")
        }
    }

    /// The fallback's check: the person types the sixty digits the other device shows. None of the directory's digits
    /// for them are on this screen, only this device's own, for them to type in turn: copying the screen can never
    /// pass the check (docs/06-adversarial-review.md, V17).
    private func compare(_ comparison: FullCodeComparison) -> some View {
        Group {
            Section {
                if model.usesFingerprintCode {
                    // A code pasted from a message says which account, not that its keys are the person's.
                    Text(
                        "The code you pasted only says which account this is. Type their full vault sharing code as "
                            + "well before you go on."
                    )
                    .foregroundStyle(.secondary)
                }
                TextField(
                    "Their full vault sharing code", text: $model.confirmation.typedSafetyNumber, axis: .vertical
                )
                .autocorrectionDisabled()
                #if os(iOS)
                    .keyboardType(.numberPad)
                #endif
                .accessibilityIdentifier(AccessibilityID.Invite.typedNumber)
                Button("Check") { Task { await model.confirmFingerprint() } }
                    .disabled(model.isWorking)
                    .accessibilityIdentifier(AccessibilityID.Invite.confirm)
            } header: {
                Text("Their full vault sharing code")
            } footer: {
                Text(
                    "Type the sixty digits their own device shows in Settings, Vaults, Your Full Vault Sharing Code: "
                        + "read out by them on a call you know is them, or seen on their screen. Your device checks "
                        + "them.")
            }
            Section {
                SafetyNumberGrid(groups: comparison.own.groups)
                    .accessibilityIdentifier(AccessibilityID.Invite.ownSafetyNumber)
            } header: {
                Text("Your full vault sharing code")
            } footer: {
                Text("Yours, not theirs: read it to them if they check you too.")
            }
        }
    }

    // MARK: Inviting

    private var chooseRole: some View {
        Section {
            Text("Inviting \(model.inviteeName).")
                .accessibilityIdentifier(AccessibilityID.Invite.invitee)
            Text(model.verificationText).font(.footnote).foregroundStyle(.secondary)
            Picker("Role", selection: $model.role) {
                ForEach(InvitationModel.roles, id: \.self) { role in
                    Text(MemberRow.name(of: role)).tag(role)
                }
            }
            .accessibilityIdentifier(AccessibilityID.Invite.role)
            Button("Send Invitation") { Task { await model.invite() } }
                .disabled(model.isWorking)
                .accessibilityIdentifier(AccessibilityID.Invite.send)
        } footer: {
            Text("Administrators can invite and remove others; read-only members cannot change items.")
        }
    }

    @ViewBuilder private func issued(_ code: String?) -> some View {
        if let code {
            Section {
                Text(code)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
                    .accessibilityIdentifier(AccessibilityID.Invite.code)
                Button("Copy Invitation") { Clipboard.copy(code) }
                    .accessibilityIdentifier(AccessibilityID.Invite.copy)
                Button("Done") { dismiss() }
                    .accessibilityIdentifier(AccessibilityID.Invite.done)
            } header: {
                Text("Invitation")
            } footer: {
                Text(
                    "Send this to them. It names the vault and you, and is not a secret: before joining, they type "
                        + "your full vault sharing code too.")
            }
            #if DEBUG
                .onAppear { app.uiTestInvitation = model.invitation }
            #endif
        } else {
            Section {
                Label("Invitation sent. It appears on their device now.", systemImage: "checkmark.circle")
                    .accessibilityIdentifier(AccessibilityID.Invite.sent)
                #if DEBUG
                    if app.uiTestPeer != nil {
                        Button("The household member joins (UI test)") {
                            Task { await app.uiTestMemberAcceptsSessionInvitation() }
                        }
                        .accessibilityIdentifier(AccessibilityID.Debug.memberAcceptsSession)
                        if let status = app.uiTestPeerStatus {
                            Text(status).font(.footnote).foregroundStyle(.secondary)
                                .accessibilityIdentifier("debug.peerStatus")
                        }
                    }
                #endif
                Button("Done") { dismiss() }
                    .accessibilityIdentifier(AccessibilityID.Invite.done)
            }
        }
    }
}

/// Accepting an invitation to someone else's shared vault (PRD F4.2; ADR 0010): type the vault sharing code they read
/// out (or scan their screen), read back this device's six digits, type theirs, and join once their invitation
/// arrives. The fallback: paste an invitation and type the owner's full vault sharing code.
struct AcceptInvitationView: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var model: AcceptInvitationModel
    #if DEBUG
        /// The household member's QR code while it shares, for the scanner stand-in.
        @State private var uiTestPayload: String?
    #endif

    init(context: ScreenContext) {
        _model = State(initialValue: AcceptInvitationModel(context: context))
    }

    var body: some View {
        Form {
            switch model.step {
            case .enterNumber:
                enterNumber
            case .waiting:
                Section {
                    Text("Waiting for their device…").foregroundStyle(.secondary)
                        .accessibilityIdentifier(AccessibilityID.Accept.waiting)
                }
            case .showCodeAndType(let code, let payload, let attemptsLeft):
                ownCode(code, payload: payload)
                typeTheirCode(attemptsLeft: attemptsLeft)
            case .confirmScan(let accountID, let code, let payload):
                confirmScan(accountID)
                if let code { ownCode(code, payload: payload) }
            case .awaitingInvitation(let code, let payload):
                if let code { ownCode(code, payload: payload) }
                awaitingInvitation
            case .confirmJoin(let owner):
                Section {
                    Text(
                        "Join a vault shared by the account \(shortIdentifier(owner.accountID))? You checked its keys, "
                            + "and they have not changed."
                    )
                    .accessibilityIdentifier(AccessibilityID.Accept.confirmText)
                    Button("Join Vault") { Task { await model.confirmJoin() } }
                        .disabled(model.isWorking)
                        .accessibilityIdentifier(AccessibilityID.Accept.join)
                    Button("Don’t Join", role: .cancel) { Task { await model.decline() } }
                }
            case .ownerNotVerified(let ownerID):
                Section {
                    Banner(
                        text: "This vault belongs to the account \(shortIdentifier(ownerID)), not to the person you "
                            + "just checked. Check a vault sharing code with its owner too, then accept again."
                    )
                    .accessibilityIdentifier(AccessibilityID.Accept.ownerNotVerified)
                    Button("Start Over") { Task { await model.decline() } }
                        .accessibilityIdentifier(AccessibilityID.Accept.startOver)
                }
            case .keysChanged:
                Section {
                    Banner(
                        text: "These are not the keys you checked for this account before. Use the new keys only if "
                            + "you know they set up Watchword again, and you just checked them in person.",
                        systemImage: "exclamationmark.octagon")
                    Button("Use Their New Keys", role: .destructive) { Task { await model.useNewKeys() } }
                        .accessibilityIdentifier(AccessibilityID.Accept.useNewKeys)
                    Button("Start Over") { Task { await model.decline() } }
                        .accessibilityIdentifier(AccessibilityID.Accept.startOver)
                }
            case .failed(let message):
                Section {
                    Banner(text: message).accessibilityIdentifier(AccessibilityID.Accept.failed)
                    Button("Start Over") { Task { await model.decline() } }
                        .accessibilityIdentifier(AccessibilityID.Accept.startOver)
                }
            case .joined:
                Section {
                    Label("You joined the vault. Its items arrive with the next sync.", systemImage: "checkmark.circle")
                        .accessibilityIdentifier(AccessibilityID.Accept.joined)
                    Button("Done") { dismiss() }
                        .accessibilityIdentifier(AccessibilityID.Accept.done)
                }
            case .enterCode:
                enterCode
            case .compareOwner(let comparison):
                compareOwner(comparison)
            }
            ErrorText(message: model.errorMessage)
        }
        .formStyle(.grouped)
        .navigationTitle("Accept an Invitation")
        .closesSheet()
        .overlay { if model.isWorking { ProgressView() } }
        // While waiting for their device: look again every two seconds. A cancelled sleep (the step moved on, so the
        // task's id changed) must not refresh once more: that refresh took a finished step back to waiting, and the
        // screen flickered between the two for as long as it was open (the first Mac run's UI tests).
        .task(id: model.isWaiting) {
            while model.isWaiting {
                guard (try? await Task.sleep(for: .seconds(2))) != nil, model.isWaiting else { return }
                await model.refresh()
            }
        }
        .onDisappear { Task { try? await app.reloadVaults() } }
    }

    private var enterNumber: some View {
        Group {
            Section {
                TextField("Eight digits", text: $model.numberText)
                    .font(.system(.title2, design: .monospaced))
                    .autocorrectionDisabled()
                    #if os(iOS)
                        .keyboardType(.numberPad)
                    #endif
                    .accessibilityIdentifier(AccessibilityID.Accept.number)
                Button("Continue") { Task { await model.joinWithNumber() } }
                    .disabled(model.numberText.isEmpty || model.isWorking)
                    .accessibilityIdentifier(AccessibilityID.Accept.joinWithNumber)
                ScanCodeButton(
                    title: "Scan Their Screen", accessibilityID: AccessibilityID.Accept.scan,
                    uiTestPayload: { uiTestScanPayload() },
                    onScan: { await model.cameraScanned($0) })
                #if DEBUG
                    if app.uiTestPeer != nil {
                        Button("The household member starts sharing (UI test)") {
                            Task {
                                if let started = await app.uiTestMemberStartsSession() {
                                    model.numberText = started.number
                                    uiTestPayload = started.payload
                                }
                            }
                        }
                        .accessibilityIdentifier(AccessibilityID.Debug.memberStarts)
                    }
                #endif
            } header: {
                Text("Their vault sharing code")
            } footer: {
                Text(
                    "The person inviting you reads eight digits from their screen, or you scan it. "
                        + SharingCodeWording.channelWarning)
            }
            Section {
                Button("Paste an Invitation Instead") { Task { await model.useFullCode() } }
                    .accessibilityIdentifier(AccessibilityID.Accept.fullCode)
            } footer: {
                Text("For an invitation sent as text, checked with the owner's full vault sharing code.")
            }
        }
    }

    private func uiTestScanPayload() -> String? {
        #if DEBUG
            return uiTestPayload
        #else
            return nil
        #endif
    }

    private func ownCode(_ code: String, payload: String) -> some View {
        Section {
            SharingDigits(code: code)
                .accessibilityIdentifier(AccessibilityID.Accept.ownCode)
            QRCodeView(text: payload)
            #if DEBUG
                if app.uiTestPeer != nil {
                    Button("The household member types this code (UI test)") {
                        Task { await app.uiTestMemberTypes(code: code) }
                    }
                    .accessibilityIdentifier(AccessibilityID.Debug.memberTypes)
                }
            #endif
        } header: {
            Text("Your confirmation code")
        } footer: {
            Text("Read these six digits to them, or let them scan the code, so their device can check you.")
        }
    }

    private func typeTheirCode(attemptsLeft: Int) -> some View {
        Section {
            TextField("Six digits from their screen", text: $model.typedCode)
                .font(.system(.title2, design: .monospaced))
                .autocorrectionDisabled()
                #if os(iOS)
                    .keyboardType(.numberPad)
                #endif
                .accessibilityIdentifier(AccessibilityID.Accept.typedCode)
            Button("Check") { Task { await model.confirmTheirCode() } }
                .disabled(model.typedCode.isEmpty || model.isWorking)
                .accessibilityIdentifier(AccessibilityID.Accept.confirmCode)
            #if DEBUG
                if app.uiTestPeer != nil {
                    Button("Fill in the household member's code (UI test)") {
                        Task { model.typedCode = await app.uiTestMemberCode() ?? "" }
                    }
                    .accessibilityIdentifier(AccessibilityID.Debug.fillMemberCode)
                }
            #endif
        } header: {
            Text("Their confirmation code")
        } footer: {
            Text(
                "Once their device has checked yours, it shows six digits. Type them here. \(attemptsLeft) tries left.")
        }
    }

    /// A scan names the account it is for before anything is pinned (ADR 0010, Scans): the person compares it with
    /// what the other screen says ("You are …") and says yes, or stops. Decided by the session; this only asks.
    private func confirmScan(_ accountID: UUID) -> some View {
        Section {
            Text(
                "Your camera read the code of the account \(shortIdentifier(accountID)). Their screen says \"You are "
                    + "the account \(shortIdentifier(accountID))\" if it is theirs."
            )
            .accessibilityIdentifier(AccessibilityID.Accept.scannedAccount)
            Button("It Is Theirs") { Task { await model.confirmScannedAccount() } }
                .disabled(model.isWorking)
                .accessibilityIdentifier(AccessibilityID.Accept.confirmScan)
            Button("Not Them: Start Over", role: .cancel) { Task { await model.decline() } }
                .accessibilityIdentifier(AccessibilityID.Accept.startOver)
        } header: {
            Text("Whose code you scanned")
        } footer: {
            Text("Nothing is kept until you say it is theirs. If two codes were in view, start over and tap theirs.")
        }
    }

    private var awaitingInvitation: some View {
        Section {
            Label("You checked each other. Waiting for their invitation…", systemImage: "checkmark.shield")
                .accessibilityIdentifier(AccessibilityID.Accept.awaitingInvitation)
            #if DEBUG
                if app.uiTestPeer != nil {
                    Button("The household member sends the invitation (UI test)") {
                        Task {
                            await app.uiTestMemberInvites()
                            await model.refresh()
                        }
                    }
                    .accessibilityIdentifier(AccessibilityID.Debug.memberInvites)
                }
            #endif
        }
    }

    private var enterCode: some View {
        Section {
            TextField("Invitation", text: $model.codeText, axis: .vertical)
                .font(.system(.body, design: .monospaced))
                .autocorrectionDisabled()
                #if os(iOS)
                    .textInputAutocapitalization(.characters)
                #endif
                .accessibilityIdentifier(AccessibilityID.Accept.code)
            Button("Continue") { Task { await model.read() } }
                .disabled(model.codeText.isEmpty || model.isWorking)
                .accessibilityIdentifier(AccessibilityID.Accept.read)
        } footer: {
            Text("Paste the invitation the vault's owner sent you.")
        }
    }

    /// The owner's sixty digits, typed from the owner's own device; only this device's own are shown (V17).
    private func compareOwner(_ comparison: FullCodeComparison) -> some View {
        Group {
            Section {
                TextField(
                    "The owner's full vault sharing code", text: $model.confirmation.typedSafetyNumber,
                    axis: .vertical
                )
                .autocorrectionDisabled()
                .accessibilityIdentifier(AccessibilityID.Accept.typedNumber)
                Button("Join Vault") { Task { await model.accept() } }
                    .disabled(model.isWorking)
                    .accessibilityIdentifier(AccessibilityID.Accept.join)
            } header: {
                Text("The owner's full vault sharing code")
            } footer: {
                Text(
                    "Type the sixty digits the owner's own device shows in Settings, Vaults, Your Full Vault Sharing "
                        + "Code. Your device joins only if they match.")
            }
            Section {
                SafetyNumberGrid(groups: comparison.own.groups)
                    .accessibilityIdentifier(AccessibilityID.Accept.ownSafetyNumber)
            } header: {
                Text("Your full vault sharing code")
            } footer: {
                Text("Yours, not the owner's: read it to them if they check you too.")
            }
        }
    }
}

/// Checking a member of a shared vault with a vault sharing code session (ADR 0010), from the member list: for a
/// member not yet verified by this device, or one whose keys changed. Only that member may answer.
struct MemberVerificationView: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var model: MemberVerificationModel

    init(vaultID: UUID, memberID: UUID, context: ScreenContext) {
        _model = State(initialValue: MemberVerificationModel(vaultID: vaultID, memberID: memberID, context: context))
    }

    var body: some View {
        Form {
            switch model.step {
            case .start:
                Section {
                    Text("\(model.memberName) types the vault sharing code your device shows, on their own device.")
                    Button("Show Vault Sharing Code") { Task { await model.startSession() } }
                        .disabled(model.isWorking)
                        .accessibilityIdentifier(AccessibilityID.MemberCheck.start)
                } footer: {
                    Text(SharingCodeWording.channelWarning)
                }
            case .showCode(let number, let payload):
                Section {
                    SharingDigits(code: number).accessibilityIdentifier(AccessibilityID.MemberCheck.number)
                    QRCodeView(text: payload)
                    if let own = model.status?.ownAccount {
                        Text("You are the account \(shortIdentifier(own)).").font(.footnote).foregroundStyle(.secondary)
                    }
                } header: {
                    Text("Your vault sharing code")
                }
            case .typeTheirCode:
                Section {
                    TextField("Six digits from their screen", text: $model.typedCode)
                        .font(.system(.title2, design: .monospaced))
                        .accessibilityIdentifier(AccessibilityID.MemberCheck.typedCode)
                    Button("Check") { Task { await model.confirmTheirCode() } }
                        .disabled(model.typedCode.isEmpty || model.isWorking)
                        .accessibilityIdentifier(AccessibilityID.MemberCheck.confirm)
                    ScanCodeButton(
                        title: "Scan Their Screen", accessibilityID: AccessibilityID.MemberCheck.scan,
                        uiTestPayload: { await app.uiTestScanPayload() },
                        onScan: { await model.cameraScanned($0) })
                } header: {
                    Text("Their confirmation code")
                }
            case .verified(let code):
                Section {
                    Label("\(model.memberName) is verified on this device.", systemImage: "checkmark.shield")
                        .accessibilityIdentifier(AccessibilityID.MemberCheck.verified)
                    if let code {
                        SharingDigits(code: code).accessibilityIdentifier(AccessibilityID.MemberCheck.ownCode)
                        Text("Read these six digits to them, so their device can check yours.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    Button("Done") { dismiss() }
                }
            case .keysChanged:
                Section {
                    Banner(
                        text: "The keys you just checked are not the ones you checked before. Use them only if "
                            + "\(model.memberName) set up Watchword again; they must be the ones this vault lists.",
                        systemImage: "exclamationmark.octagon")
                    Button("Use Their New Keys", role: .destructive) { Task { await model.useNewKeys() } }
                        .accessibilityIdentifier(AccessibilityID.MemberCheck.useNewKeys)
                }
            case .failed(let message):
                Section {
                    Banner(text: message).accessibilityIdentifier(AccessibilityID.MemberCheck.failed)
                }
            }
            ErrorText(message: model.errorMessage)
        }
        .formStyle(.grouped)
        .navigationTitle("Check \(model.memberName)")
        .closesSheet()
        .overlay { if model.isWorking { ProgressView() } }
        // While waiting for their device: look again every two seconds. A cancelled sleep (the step moved on, so the
        // task's id changed) must not refresh once more: that refresh took a finished step back to waiting, and the
        // screen flickered between the two for as long as it was open (the first Mac run's UI tests).
        .task(id: model.isWaiting) {
            while model.isWaiting {
                guard (try? await Task.sleep(for: .seconds(2))) != nil, model.isWaiting else { return }
                await model.refresh()
            }
        }
    }
}
