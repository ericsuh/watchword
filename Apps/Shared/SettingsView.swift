import SwiftUI
import WatchwordKit

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var kit: EmergencyKit?
    @State private var askingPassword = false
    @State private var password = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Quick unlock") {
                    Toggle(
                        "Unlock with biometrics",
                        isOn: Binding(
                            get: { model.quickUnlockEnabled },
                            set: { enabled in
                                if enabled {
                                    askingPassword = true
                                } else {
                                    Task { await model.disableQuickUnlock() }
                                }
                            })
                    )
                    .accessibilityIdentifier("settings.quickUnlock")
                    Text(
                        "Your account password is still required every 14 days, after an update, after three failed "
                            + "attempts, and whenever biometric settings change."
                    )
                    .font(.footnote).foregroundStyle(.secondary)
                }
                Section("Sync") {
                    if model.isSyncConfigured {
                        Button("Sync Now") { Task { await model.syncNow() } }
                            .disabled(model.isWorking)
                            .accessibilityIdentifier("settings.syncNow")
                        if let status = model.syncStatus {
                            Text(status).font(.footnote).foregroundStyle(.secondary)
                                .accessibilityIdentifier("settings.syncStatus")
                        }
                    } else {
                        Text("Sync between your devices is not available in this version yet.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
                #if DEBUG
                    if model.uiTestPeer != nil {
                        Section("UI test: another device") {
                            Button("Rename items on the other device") { Task { await model.renameOnOtherDevice() } }
                                .disabled(model.isWorking)
                                .accessibilityIdentifier("debug.peerRename")
                            if let status = model.uiTestPeerStatus {
                                Text(status).font(.footnote).foregroundStyle(.secondary)
                                    .accessibilityIdentifier("debug.peerStatus")
                            }
                        }
                    }
                #endif
                Section("Emergency Kit") {
                    Button("Show Emergency Kit…") { Task { kit = await model.emergencyKit() } }
                }
                ErrorText(message: model.errorMessage)
            }
            .formStyle(.grouped)
            .navigationTitle("Settings")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }.accessibilityIdentifier("settings.done")
                }
            }
            .alert("Enter your account password", isPresented: $askingPassword) {
                SecureField("Account password", text: $password)
                Button("Turn On") {
                    let entered = password
                    password = ""
                    Task { await model.enableQuickUnlock(password: entered) }
                }
                Button("Cancel", role: .cancel) { password = "" }
            } message: {
                Text("Quick unlock starts a new 14-day period before your password is asked for again.")
            }
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
