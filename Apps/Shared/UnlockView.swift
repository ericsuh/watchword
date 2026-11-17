import SwiftUI

struct UnlockView: View {
    @Environment(AppModel.self) private var model
    @State private var password = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.fill").font(.system(size: 44)).foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("Watchword is locked").font(.title2.bold())
            if model.passwordChangedElsewhere {
                // Above the field, clear of the keyboard. For the person who did not make the change
                // (docs/02-architecture.md §7.8): the password this device still has opens it, so they can remove the
                // device that changed it and choose their own.
                VStack(spacing: 8) {
                    Text(
                        "Your account password was changed on another device: enter the new one. If you did not "
                            + "change it, type the password this device knows and choose Unlock with This Device’s "
                            + "Password, then remove the device that changed it in Settings, Devices, choosing a new "
                            + "password as you do."
                    )
                    .font(.footnote)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier(AccessibilityID.Unlock.passwordChanged)
                    Button("Unlock with This Device’s Password") {
                        let entered = password
                        password = ""
                        Task { await model.unlockIgnoringPasswordChange(password: entered) }
                    }
                    .disabled(password.isEmpty || model.isWorking)
                    .accessibilityIdentifier(AccessibilityID.Unlock.ignoreChange)
                }
                .frame(maxWidth: 420)
            }
            SecureField("Account password", text: $password)
                .textContentType(.password)
                .focused($focused)
                .onSubmit(unlock)
                .frame(maxWidth: 360)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("unlock.password")
            Button("Unlock", action: unlock)
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty || model.isWorking)
                .accessibilityIdentifier("unlock.submit")
            if model.quickUnlockAllowed {
                Button("Use biometrics") { Task { await model.quickUnlock() } }
                    .accessibilityIdentifier("unlock.quick")
            }
            ErrorText(message: model.errorMessage)
            if model.isWorking { ProgressView() }
        }
        .padding()
        .onAppear { focused = true }
    }

    private func unlock() {
        let entered = password
        password = ""
        Task { await model.unlock(password: entered) }
    }
}
