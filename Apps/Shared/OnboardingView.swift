import SwiftUI
import WatchwordKit

/// Account creation (PRD F5.1, F10.2): choose the account password, then save the Emergency Kit.
struct OnboardingView: View {
    @Environment(AppModel.self) private var model
    @State private var password = ""
    @State private var confirmation = ""
    @FocusState private var focus: FocusedField?

    enum FocusedField { case password, confirmation }

    var body: some View {
        Form {
            Section {
                Text("Create your Watchword account")
                    .font(.title2.bold())
                Text(
                    "Your vault is encrypted with your account password and a Secret Key that is generated on this "
                        + "device. Watchword never sees either."
                )
                .foregroundStyle(.secondary)
            }
            Section("Account password") {
                SecureField(
                    "Password (at least \(VaultConfiguration.minimumPasswordLength) characters)", text: $password
                )
                .focused($focus, equals: .password)
                .onSubmit { focus = .confirmation }
                .accessibilityIdentifier("onboarding.password")
                SecureField("Confirm password", text: $confirmation)
                    .focused($focus, equals: .confirmation)
                    .onSubmit(create)
                    .accessibilityIdentifier("onboarding.confirm")
            }
            Section {
                Text(EmergencyKitText.unrecoverableWarning)
                    .font(.footnote)
                ErrorText(message: model.errorMessage)
                Button("Create account", action: create)
                    .disabled(password.isEmpty || model.isWorking)
                    .accessibilityIdentifier("onboarding.create")
            }
        }
        .formStyle(.grouped)
        .scrollDismissesKeyboard(.interactively)
        .frame(maxWidth: 560)
        .overlay { if model.isWorking { ProgressView() } }
        .onAppear { focus = .password }
    }

    private func create() {
        guard !password.isEmpty, !model.isWorking else { return }
        focus = nil
        Task { await model.createAccount(password: password, confirmation: confirmation) }
    }
}
