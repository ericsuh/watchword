import SwiftUI
import WatchwordPresentation
import WatchwordSharing

/// Inviting someone to a shared vault (PRD F4.1, F4.2): name their account, compare safety numbers, choose a role,
/// send the invitation. The comparison is not optional; the session refuses to invite an account whose fingerprint
/// has not been confirmed.
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
            case .nameAccount:
                nameAccount
            case .compareFingerprint(let contact):
                compare(contact)
            case .chooseRole:
                chooseRole
            case .issued(let code):
                issued(code)
            }
            ErrorText(message: model.errorMessage)
        }
        .formStyle(.grouped)
        .navigationTitle("Invite Someone")
        .closesSheet()
        .overlay { if model.isWorking { ProgressView() } }
    }

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
            Text("They find both in Settings, Vaults, Your Safety Number.")
        }
    }

    private func compare(_ contact: ContactSummary) -> some View {
        Group {
            Section {
                SafetyNumberGrid(groups: contact.groups)
                    .accessibilityIdentifier(AccessibilityID.Invite.safetyNumber)
            } header: {
                Text("Their safety number")
            } footer: {
                Text(
                    "Compare this with the number on their device, in person or on a call you know is them. If one "
                        + "digit differs, stop: someone may be between you.")
            }
            Section {
                if model.usesFingerprintCode {
                    // A code pasted from a message says which account, not that its keys are the person's.
                    Text(
                        "The code you pasted only says which account this is. Compare the safety number with them as "
                            + "well before you go on."
                    )
                    .foregroundStyle(.secondary)
                }
                TextField("Type their safety number", text: $model.confirmation.typedSafetyNumber, axis: .vertical)
                    .autocorrectionDisabled()
                    #if os(iOS)
                        .keyboardType(.numberPad)
                    #endif
                    .accessibilityIdentifier(AccessibilityID.Invite.typedNumber)
                Toggle("I compared the two numbers and they match", isOn: $model.confirmation.comparedByEye)
                    .accessibilityIdentifier(AccessibilityID.Invite.comparedByEye)
                Button("Confirm") { Task { await model.confirmFingerprint() } }
                    .disabled(model.isWorking)
                    .accessibilityIdentifier(AccessibilityID.Invite.confirm)
            }
        }
    }

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

    private func issued(_ code: String) -> some View {
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
                "Send this to them. It names the vault and you, and is not a secret: before joining, they compare "
                    + "your safety number too.")
        }
        #if DEBUG
            .onAppear { app.uiTestInvitation = model.invitation }
        #endif
    }
}

/// Accepting an invitation to someone else's shared vault (PRD F4.2): paste it, compare the owner's safety number,
/// join.
struct AcceptInvitationView: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var model: AcceptInvitationModel

    init(context: ScreenContext) {
        _model = State(initialValue: AcceptInvitationModel(context: context))
    }

    var body: some View {
        Form {
            switch model.step {
            case .enterCode:
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
            case .compareOwner(let owner):
                Section {
                    SafetyNumberGrid(groups: owner.groups)
                        .accessibilityIdentifier(AccessibilityID.Accept.ownerNumber)
                } header: {
                    Text("The owner's safety number")
                } footer: {
                    Text("Compare this with the number on the owner's device. Join only if every digit matches.")
                }
                Section {
                    TextField("Type their safety number", text: $model.confirmation.typedSafetyNumber, axis: .vertical)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier(AccessibilityID.Accept.typedNumber)
                    Toggle("I compared the two numbers and they match", isOn: $model.confirmation.comparedByEye)
                        .accessibilityIdentifier(AccessibilityID.Accept.comparedByEye)
                    Button("Join Vault") { Task { await model.accept() } }
                        .disabled(model.isWorking)
                        .accessibilityIdentifier(AccessibilityID.Accept.join)
                }
            case .confirmJoin(let owner):
                Section {
                    Text(
                        "Join a vault shared by the account \(shortIdentifier(owner.accountID))? You compared its "
                            + "safety number before, and its keys have not changed."
                    )
                    .accessibilityIdentifier(AccessibilityID.Accept.confirmText)
                    Button("Join Vault") { Task { await model.confirmJoin() } }
                        .disabled(model.isWorking)
                        .accessibilityIdentifier(AccessibilityID.Accept.join)
                    Button("Don’t Join", role: .cancel) { model.decline() }
                }
            case .joined:
                Section {
                    Label("You joined the vault. Its items arrive with the next sync.", systemImage: "checkmark.circle")
                        .accessibilityIdentifier(AccessibilityID.Accept.joined)
                    Button("Done") { dismiss() }
                        .accessibilityIdentifier(AccessibilityID.Accept.done)
                }
            }
            ErrorText(message: model.errorMessage)
        }
        .formStyle(.grouped)
        .navigationTitle("Accept an Invitation")
        .closesSheet()
        .overlay { if model.isWorking { ProgressView() } }
        .onDisappear { Task { try? await app.reloadVaults() } }
    }
}
