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
