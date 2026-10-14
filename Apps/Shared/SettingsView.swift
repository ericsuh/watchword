import SwiftUI
import WatchwordKit

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var kit: EmergencyKit?

    var body: some View {
        NavigationStack {
            Form {
                Section("Quick unlock") {
                    Toggle(
                        "Unlock with biometrics",
                        isOn: Binding(
                            get: { model.quickUnlockEnabled },
                            set: { enabled in Task { await model.setQuickUnlock(enabled) } })
                    )
                    .accessibilityIdentifier("settings.quickUnlock")
                    Text(
                        "Your account password is still required every 14 days, after an update, after three failed "
                            + "attempts, and whenever biometric settings change."
                    )
                    .font(.footnote).foregroundStyle(.secondary)
                }
                Section("Emergency Kit") {
                    Button("Show Emergency Kit…") { Task { kit = await model.emergencyKit() } }
                }
                ErrorText(message: model.errorMessage)
            }
            .formStyle(.grouped)
            .navigationTitle("Settings")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .sheet(item: $kit) { kit in
                EmergencyKitView(kit: kit, isOnboarding: false)
            }
        }
        #if os(macOS)
            .frame(minWidth: 460, minHeight: 360)
        #endif
    }
}

extension EmergencyKit: @retroactive Identifiable {
    public var id: UUID { accountID }
}
