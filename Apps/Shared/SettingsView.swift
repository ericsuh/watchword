import SwiftUI
import WatchwordKit
import WatchwordPresentation

/// Settings, and the way to every screen about the account rather than one item: vaults and sharing, devices, the
/// quarantine, the security report, import, export and restore.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var kit: EmergencyKit?
    @State private var askingPassword = false
    @State private var password = ""
    @State private var screen: AccountScreen?

    /// The screens about the account rather than one item, each opened in a sheet of its own.
    enum AccountScreen: String, Identifiable {
        case vaults, devices, quarantine, hygiene, importItems, export, restore
        var id: String { rawValue }
    }

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
                        ForEach(model.lastSync?.notices ?? []) { notice in
                            SyncNoticeText(notice: notice)
                                .accessibilityIdentifier(AccessibilityID.Settings.syncNotice)
                        }
                    } else {
                        Text("Sync between your devices is not available in this version yet.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
                // Near the top, where the UI tests find it without scrolling.
                #if DEBUG
                    if model.uiTestPeer != nil {
                        UITestSection()
                    }
                #endif
                if model.screenContext != nil {
                    Section("Your account") {
                        screenButton("Vaults", .vaults, AccessibilityID.Settings.vaults)
                        screenButton("Devices", .devices, AccessibilityID.Settings.devices)
                        screenButton("Held-Aside Changes", .quarantine, AccessibilityID.Settings.quarantine)
                        screenButton("Security Report", .hygiene, AccessibilityID.Settings.hygiene)
                    }
                    Section("Import and export") {
                        screenButton("Import from Another App", .importItems, AccessibilityID.Settings.importItems)
                        screenButton("Export and Back Up", .export, AccessibilityID.Settings.export)
                        screenButton("Restore from a Backup", .restore, AccessibilityID.Settings.restore)
                    }
                }
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
            .sheet(item: $screen) { screen in
                if let context = model.screenContext {
                    ScreenSheet(close: { self.screen = nil }) { destination(screen, context: context) }
                }
            }
        }
        #if os(macOS)
            .frame(minWidth: 560, minHeight: 700)
        #endif
    }

    private func screenButton(_ title: String, _ target: AccountScreen, _ identifier: String) -> some View {
        Button {
            screen = target
        } label: {
            HStack {
                Text(title)
                Spacer()
                Image(systemName: "chevron.right").foregroundStyle(.tertiary).accessibilityHidden(true)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .foregroundStyle(.primary)
        .accessibilityIdentifier(identifier)
    }

    @ViewBuilder private func destination(_ screen: AccountScreen, context: ScreenContext) -> some View {
        switch screen {
        case .vaults: VaultsView(context: context)
        case .devices: DevicesView(context: context)
        case .quarantine: QuarantineView(context: context)
        case .hygiene: HygieneReportView(context: context, breachChecksAvailable: model.breachChecksAvailable)
        case .importItems: ImportView(context: context, restoring: false)
        case .export: ExportView(context: context)
        case .restore: ImportView(context: context, restoring: true)
        }
    }
}

/// One thing about the last sync to act on; "update the app" stands out.
struct SyncNoticeText: View {
    let notice: SyncNotice

    var body: some View {
        if notice == .updateRequired {
            Label(notice.text, systemImage: "arrow.down.app")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.orange)
        } else {
            Text(notice.text).font(.footnote).foregroundStyle(.secondary)
        }
    }
}

#if DEBUG
    /// The section that drives the rest of the UI-test household (`UITestPeer`). A `--uitest` launch only; a release
    /// build has none.
    struct UITestSection: View {
        @Environment(AppModel.self) private var model

        var body: some View {
            Section("UI test: another device") {
                Button("Rename items on the other device") { Task { await model.renameOnOtherDevice() } }
                    .disabled(model.isWorking)
                    .accessibilityIdentifier("debug.peerRename")
                Button("Add the other device") { Task { await model.joinOtherDevice() } }
                    .disabled(model.isWorking)
                    .accessibilityIdentifier(AccessibilityID.Debug.peerJoin)
                Button("Change the password on the other device") {
                    Task { await model.changePasswordOnOtherDevice() }
                }
                .disabled(model.isWorking)
                .accessibilityIdentifier(AccessibilityID.Debug.peerPassword)
                Button("Make an implausible edit on the other device") {
                    Task { await model.makeImplausibleEditOnOtherDevice() }
                }
                .disabled(model.isWorking)
                .accessibilityIdentifier(AccessibilityID.Debug.peerImplausible)
                Button("The other person accepts the invitation") {
                    Task { await model.householdAcceptsInvitation() }
                }
                .disabled(model.isWorking || model.uiTestInvitation == nil)
                .accessibilityIdentifier(AccessibilityID.Debug.householdAccept)
                if let status = model.uiTestPeerStatus {
                    Text(status).font(.footnote).foregroundStyle(.secondary)
                        .accessibilityIdentifier("debug.peerStatus")
                }
            }
        }
    }
#endif

extension EmergencyKit: @retroactive Identifiable {
    public var id: UUID { accountID }
}
