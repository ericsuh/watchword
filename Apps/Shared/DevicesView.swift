import SwiftUI
import WatchwordPresentation

/// The account's devices, removing one, and sync on this device (PRD F7, F10.2; docs/02-architecture.md §7.8).
struct DevicesView: View {
    @Environment(AppModel.self) private var app
    @State private var model: DevicesModel
    @State private var revoking: DeviceRow?

    init(context: ScreenContext) {
        _model = State(initialValue: DevicesModel(context: context))
    }

    var body: some View {
        Form {
            if model.isSyncConfigured {
                Section("Sync") {
                    Button("Sync Now") { Task { await model.syncNow() } }
                        .disabled(model.isWorking)
                        .accessibilityIdentifier(AccessibilityID.Devices.syncNow)
                    if let sync = model.sync {
                        Text(sync.headline).font(.footnote).foregroundStyle(.secondary)
                            .accessibilityIdentifier(AccessibilityID.Devices.syncStatus)
                        ForEach(sync.notices) { notice in
                            SyncNoticeText(notice: notice)
                        }
                    }
                }
            }
            if model.awaitingNewPassword {
                Section {
                    Banner(
                        text: "Your account password was changed on another device. If that was not you, remove "
                            + "that device here, choosing a new password as you do.")
                }
            }
            if model.standing == .revoked {
                Section { Banner(text: SyncNotice.deviceRevoked.text) }
            }
            Section {
                ForEach(model.rows) { device in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(device.name).strikethrough(device.isRevoked)
                            if let addedAt = device.addedAt {
                                Text("Added \(addedAt.formatted(date: .abbreviated, time: .shortened))")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            if let detail = device.detail {
                                Text(detail).font(.caption).foregroundStyle(.secondary)
                            }
                            if device.isRevoked {
                                Text("Removed").font(.caption.weight(.semibold)).foregroundStyle(.red)
                            }
                        }
                        Spacer()
                        if device.mayRevoke {
                            Button("Remove…", role: .destructive) { revoking = device }
                                .buttonStyle(.borderless)
                                .accessibilityIdentifier(AccessibilityID.Devices.revoke(device.name))
                        }
                    }
                    .accessibilityElement(children: .contain)
                    .accessibilityIdentifier(AccessibilityID.Devices.row(device.name))
                }
            } header: {
                Text("Devices")
            } footer: {
                Text("A removed device can no longer send changes. It keeps what it already had until it loses access.")
            }
            if let notice = model.notice {
                Section { Text(notice).accessibilityIdentifier(AccessibilityID.Devices.notice) }
            }
            ErrorText(message: model.errorMessage)
        }
        .formStyle(.grouped)
        .accessibilityIdentifier(AccessibilityID.Devices.list)
        .navigationTitle("Devices")
        .closesSheet()
        .overlay { if model.isWorking { ProgressView() } }
        .task { await model.load() }
        .sheet(item: $revoking) { device in
            RevokeDeviceView(device: device, model: model)
        }
    }
}

/// Removing a device (§7.8). Changing the account password in the same step is the default: it is the only safe
/// choice if the device may have been unlocked by someone else. Keeping the password needs both of the facts that
/// make it safe confirmed. Either way the current password is asked for.
struct RevokeDeviceView: View {
    @Environment(\.dismiss) private var dismiss
    let device: DeviceRow
    let model: DevicesModel
    @State private var form = RevocationForm()

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(
                        "\(device.name) will no longer be able to send changes, and cannot be added again. It keeps "
                            + "whatever it already holds; if someone else may have unlocked it, change your password "
                            + "now so they cannot add another device.")
                }
                Section {
                    Toggle("Change the account password too", isOn: $form.changesPassword)
                        .accessibilityIdentifier(AccessibilityID.Devices.changePassword)
                    SecureField("Current account password", text: $form.currentPassword)
                        .accessibilityIdentifier(AccessibilityID.Devices.current)
                    if form.changesPassword {
                        SecureField("New account password", text: $form.newPassword)
                            .accessibilityIdentifier(AccessibilityID.Devices.new)
                        SecureField("Confirm new password", text: $form.confirmation)
                            .accessibilityIdentifier(AccessibilityID.Devices.confirmation)
                    } else {
                        Toggle("The device was locked when I last had it", isOn: $form.deviceWasLocked)
                            .accessibilityIdentifier(AccessibilityID.Devices.wasLocked)
                        Toggle(
                            "Nobody who may have it knows the account password", isOn: $form.passwordUnknownToHolder
                        )
                        .accessibilityIdentifier(AccessibilityID.Devices.passwordUnknown)
                    }
                }
                if let problem = form.problem, !form.currentPassword.isEmpty {
                    Section { Text(problem).font(.footnote).foregroundStyle(.secondary) }
                }
                ErrorText(message: model.errorMessage)
            }
            .formStyle(.grouped)
            .navigationTitle("Remove \(device.name)")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.accessibilityIdentifier(AccessibilityID.Devices.cancel)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Remove", role: .destructive) {
                        let submitted = form
                        form.currentPassword = ""
                        form.newPassword = ""
                        form.confirmation = ""
                        Task { if await model.revoke(device, with: submitted) { dismiss() } }
                    }
                    .disabled(form.problem != nil || model.isWorking)
                    .accessibilityIdentifier(AccessibilityID.Devices.confirm)
                }
            }
        }
        #if os(macOS)
            .frame(minWidth: 460, minHeight: 420)
        #endif
    }
}
