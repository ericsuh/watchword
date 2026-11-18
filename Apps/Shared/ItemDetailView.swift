import SwiftUI
import WatchwordModel
import WatchwordPresentation

struct ItemDetailView: View {
    @Environment(AppModel.self) private var model
    let item: Item
    let onEdit: () -> Void
    /// Hidden again whenever the app resigns active or the screen is captured (`ScreenPrivacy`, F5.7, Z95).
    @State private var revealed = RevealedSecrets<UUID>()
    @State private var confirmingTrash = false

    var body: some View {
        Form {
            if let reason = model.readOnlyReason(item.vaultID) {
                Section { Banner(text: reason, systemImage: "lock").accessibilityIdentifier("detail.readOnly") }
            }
            ConflictSection(item: item)
            Section {
                Text(item.title).font(.title2.bold()).accessibilityIdentifier("detail.title")
                // The host as it resolves (a Cyrillic look-alike shows as `xn--…`, never as the name it imitates) and
                // how far the scope reaches (review finding Z61).
                ForEach(item.scopes, id: \.host) { scope in
                    Label {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(HostText.ascii(scope.host))
                            Text(HostText.reach(of: scope)).font(.caption).foregroundStyle(.secondary)
                        }
                    } icon: {
                        Image(systemName: "globe")
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier(AccessibilityID.Detail.scope(scope.host))
                }
            }
            Section("Fields") {
                ForEach(item.fields) { field in
                    row(field)
                }
            }
            if !item.notes.isEmpty {
                Section("Notes") { Text(item.notes) }
            }
            if let previous = item.history.first {
                Section("History") {
                    Text(
                        "Previous version replaced \(previous.replacedAt.formatted(date: .abbreviated, time: .shortened))"
                    )
                    .foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .toolbar {
            Button("Edit", action: onEdit).accessibilityIdentifier("detail.edit").disabled(isReadOnly)
            Button("Move to Trash", role: .destructive) { confirmingTrash = true }
                .accessibilityIdentifier("detail.trash")
                .disabled(isReadOnly)
        }
        // Moving to the trash starts the 30-day clock after which the item is purged without asking again (PRD F1.5),
        // so this confirmation is the explicit action F7.7 requires before anything is discarded.
        .confirmationDialog(
            "Move “\(item.title.isEmpty ? "Untitled" : item.title)” to the Trash?",
            isPresented: $confirmingTrash, titleVisibility: .visible
        ) {
            Button("Move to Trash", role: .destructive) { Task { await model.trash(item) } }
                .accessibilityIdentifier("detail.trash.confirm")
            Button("Cancel", role: .cancel) {}
                .accessibilityIdentifier("detail.trash.cancel")
        } message: {
            Text("After 30 days in the Trash it is deleted permanently.")
        }
    }

    /// A read-only vault (PRD F4.5), including one gone on in a later format, offers no change; the session would
    /// refuse one anyway.
    private var isReadOnly: Bool {
        model.readOnlyReason(item.vaultID) != nil
    }

    @ViewBuilder private func row(_ field: Field) -> some View {
        HStack {
            VStack(alignment: .leading) {
                Text(field.label).font(.caption).foregroundStyle(.secondary)
                if field.kind.isSecret && !revealed.isRevealed(field.id, under: model.privacy) {
                    Text("••••••••").accessibilityLabel("Hidden")
                } else {
                    // Secrets are not selectable: a system Copy would bypass the expiring, local-only clipboard (F5.6).
                    if field.kind.isSecret {
                        Text(field.value).font(.system(.body, design: .monospaced)).textSelection(.disabled)
                    } else {
                        Text(field.value).textSelection(.enabled)
                    }
                }
            }
            Spacer()
            if field.kind.isSecret {
                Button(revealed.isRevealed(field.id, under: model.privacy) ? "Hide" : "Show") {
                    model.recordActivity()
                    revealed.toggle(field.id, under: model.privacy)
                }
                .buttonStyle(.borderless)
                .disabled(!model.privacy.mayReveal)
            }
            Button("Copy") {
                model.recordActivity()
                Clipboard.copy(field.value)
            }
            .buttonStyle(.borderless)
            .accessibilityIdentifier("detail.copy.\(field.label)")
        }
    }
}
