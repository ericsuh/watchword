import SwiftUI
import WatchwordPresentation
import WatchwordSharing

/// Every vault this account can open, creating one, and accepting an invitation to someone else's (PRD F2.1, F4.2).
struct VaultsView: View {
    @Environment(AppModel.self) private var app
    @State private var model: VaultsModel
    @State private var creating = false
    private let context: ScreenContext

    init(context: ScreenContext) {
        self.context = context
        _model = State(initialValue: VaultsModel(context: context))
    }

    var body: some View {
        List {
            Section {
                ForEach(model.rows) { row in
                    NavigationLink {
                        VaultDetailView(vaultID: row.id, vaults: model, context: context)
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Image(systemName: row.isShared ? "person.2.fill" : "lock.fill")
                                    .foregroundStyle(.secondary)
                                    .accessibilityHidden(true)
                                Text(row.name)
                                if row.sharing?.requiresNewerVersion == true {
                                    Image(systemName: "arrow.down.app").foregroundStyle(.orange)
                                        .accessibilityLabel("Update Watchword to change this vault")
                                }
                            }
                            Text(row.badge).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                            Text(row.detail).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .accessibilityIdentifier(AccessibilityID.Vaults.row(row.name))
                }
            } footer: {
                Text("Each vault has its own key. Items can be moved between vaults; a vault you create can be shared.")
            }
            if model.sharingAvailable {
                Section {
                    if let fingerprint = model.fingerprint {
                        NavigationLink("Your Safety Number") { OwnFingerprintView(fingerprint: fingerprint) }
                            .accessibilityIdentifier(AccessibilityID.Vault.ownSafetyNumber)
                    }
                    NavigationLink("Accept an Invitation") { AcceptInvitationView(context: context) }
                        .accessibilityIdentifier(AccessibilityID.Vaults.accept)
                } footer: {
                    Text("Someone inviting you compares your safety number with theirs for you first.")
                }
            }
            ErrorText(message: model.errorMessage)
        }
        .accessibilityIdentifier(AccessibilityID.Vaults.list)
        .navigationTitle("Vaults")
        .closesSheet()
        .toolbar {
            ToolbarItem {
                Button {
                    creating = true
                } label: {
                    Label("New Vault", systemImage: "plus")
                }
                .accessibilityIdentifier(AccessibilityID.Vaults.add)
            }
        }
        .sheet(isPresented: $creating) {
            VaultNameSheet(
                title: "New Vault", action: "Create", fieldID: AccessibilityID.Vaults.newName,
                saveID: AccessibilityID.Vaults.create, close: { creating = false }
            ) { name in
                let created = await model.create(name: name) != nil
                try? await app.reloadVaults()
                return created
            }
        }
        .task { await model.load() }
        .onDisappear { Task { try? await app.reloadVaults() } }
    }
}

/// One vault: its name, and who it is shared with and how (PRD F2.1, F4.1–F4.5). Everything offered here is
/// checked again by the session; a read-only vault, including one gone on in a later format, offers no change at all.
struct VaultDetailView: View {
    @Environment(AppModel.self) private var app
    let vaults: VaultsModel
    @State private var model: SharedVaultModel
    @State private var renaming = false
    @State private var confirmingShare = false
    @State private var confirmingLeave = false
    @State private var removing: MemberRow?
    private let context: ScreenContext

    init(vaultID: UUID, vaults: VaultsModel, context: ScreenContext) {
        self.vaults = vaults
        self.context = context
        _model = State(initialValue: SharedVaultModel(vaultID: vaultID, context: context))
    }

    private var row: VaultRow? { vaults.row(model.vaultID) }

    var body: some View {
        Form {
            Section {
                Text(row?.name ?? "Vault").font(.title2.bold()).accessibilityIdentifier(AccessibilityID.Vault.name)
                if let createdAt = row?.createdAt {
                    Text("Created \(createdAt.formatted(date: .abbreviated, time: .omitted))")
                        .foregroundStyle(.secondary)
                }
                if row?.isPersonal == true {
                    Text("Your Personal vault is never shared.").foregroundStyle(.secondary)
                }
                if model.sharing?.readOnlyReason == nil {
                    Button("Rename…") { renaming = true }
                        .accessibilityIdentifier(AccessibilityID.Vault.rename)
                }
            }
            if let reason = model.sharing?.readOnlyReason {
                Section {
                    Banner(
                        text: reason,
                        systemImage: model.requiresNewerVersion ? "arrow.down.app" : "lock"
                    )
                    .accessibilityIdentifier(AccessibilityID.Vault.readOnly)
                }
            }
            if row?.isPersonal == false {
                sharingSections
            }
            if let notice = model.notice {
                Section {
                    Text(notice).accessibilityIdentifier(AccessibilityID.Vault.notice)
                }
            }
            ErrorText(message: model.errorMessage ?? vaults.errorMessage)
        }
        .formStyle(.grouped)
        .navigationTitle(row?.name ?? "Vault")
        .closesSheet()
        .overlay { if model.isWorking { ProgressView() } }
        .task { await model.load() }
        .sheet(isPresented: $renaming) {
            VaultNameSheet(
                title: "Rename Vault", action: "Save", initial: row?.name ?? "",
                fieldID: AccessibilityID.Vault.renameField, saveID: AccessibilityID.Vault.renameSave,
                close: { renaming = false }
            ) { name in
                let renamed = await vaults.rename(model.vaultID, to: name)
                try? await app.reloadVaults()
                return renamed
            }
        }
        .confirmationDialog("Share this vault?", isPresented: $confirmingShare, titleVisibility: .visible) {
            Button("Share") { Task { await model.share() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "You become its owner. Nobody else can see it until you invite them, and you compare safety numbers "
                    + "with each person before you do.")
        }
        .confirmationDialog("Leave this vault?", isPresented: $confirmingLeave, titleVisibility: .visible) {
            Button("Leave", role: .destructive) { Task { await model.leave() } }
                .accessibilityIdentifier(AccessibilityID.Vault.leaveConfirm)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Its items go from your devices once an administrator's device has replaced the vault's key.")
        }
        .confirmationDialog(
            "Remove \(removing?.name ?? "this member")?", isPresented: removingBinding, titleVisibility: .visible
        ) {
            Button("Remove", role: .destructive) {
                if let member = removing { Task { await model.remove(member) } }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "They lose access to new changes. The vault's key is replaced and every item sealed again, but what "
                    + "they already copied cannot be taken back.")
        }
    }

    private var removingBinding: Binding<Bool> {
        Binding(get: { removing != nil }, set: { if !$0 { removing = nil } })
    }

    @ViewBuilder private var sharingSections: some View {
        if !model.sharingAvailable {
            Section("Sharing") {
                Text("Sharing vaults is not available in this version yet.").foregroundStyle(.secondary)
            }
        } else if !model.isShared {
            Section("Sharing") {
                Text("Only you can open this vault.").foregroundStyle(.secondary)
                Button("Share This Vault…") { confirmingShare = true }
                    .disabled(model.isWorking)
                    .accessibilityIdentifier(AccessibilityID.Vault.share)
            }
        } else {
            Section("Members") {
                ForEach(model.members) { member in
                    memberRow(member)
                }
                if model.mayInvite {
                    NavigationLink("Invite Someone") { InviteView(vaultID: model.vaultID, context: context) }
                        .accessibilityIdentifier(AccessibilityID.Vault.invite)
                }
            }
            if !model.pending.isEmpty {
                Section("Pending rotation") {
                    ForEach(Array(model.pending.enumerated()), id: \.offset) { index, line in
                        Text(line).accessibilityIdentifier(AccessibilityID.Vault.pending(index))
                    }
                }
            }
            if let heldAside = model.sharing?.heldAside, heldAside > 0 {
                Section {
                    NavigationLink("\(heldAside) change(s) held aside") { QuarantineView(context: context) }
                        .accessibilityIdentifier(AccessibilityID.Vault.heldAside)
                } footer: {
                    Text("Changes that do not count in this vault are kept for you to review, never applied.")
                }
            }
            Section {
                if model.mayRotate {
                    Button("Replace the Vault's Key") { Task { await model.rotate() } }
                        .disabled(model.isWorking)
                        .accessibilityIdentifier(AccessibilityID.Vault.rotate)
                }
                if model.mayLeave {
                    Button("Leave This Vault…", role: .destructive) { confirmingLeave = true }
                        .accessibilityIdentifier(AccessibilityID.Vault.leave)
                }
            }
        }
    }

    private func memberRow(_ member: MemberRow) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(member.name)
                Text(member.roleName).font(.caption).foregroundStyle(.secondary)
                    .accessibilityIdentifier(AccessibilityID.Vault.memberRole(member.name))
                if let trust = member.trustText {
                    Label(
                        trust,
                        systemImage: member.trust == .keysChanged ? "exclamationmark.octagon" : "questionmark.circle"
                    )
                    .font(.caption)
                    .foregroundStyle(member.trust == .keysChanged ? Color.red : Color.orange)
                }
            }
            Spacer()
            let roles = model.roles(assignableTo: member)
            if !roles.isEmpty || model.mayRemove(member) {
                Menu("Change") {
                    ForEach(roles, id: \.self) { role in
                        Button("Make \(MemberRow.name(of: role))") {
                            Task { await model.changeRole(of: member, to: role) }
                        }
                    }
                    if model.mayRemove(member) {
                        Button("Remove…", role: .destructive) { removing = member }
                    }
                }
                .fixedSize()
                .disabled(model.isWorking)
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier(AccessibilityID.Vault.member(member.name))
    }
}
