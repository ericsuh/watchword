import SwiftUI
import WatchwordModel

struct ItemDetailView: View {
    @Environment(AppModel.self) private var model
    let item: Item
    let onEdit: () -> Void
    @State private var revealed: Set<UUID> = []
    @State private var confirmingTrash = false

    var body: some View {
        Form {
            Section {
                Text(item.title).font(.title2.bold())
                ForEach(item.scopes, id: \.host) { scope in
                    Label(scope.host, systemImage: "globe")
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
            Button("Edit", action: onEdit).accessibilityIdentifier("detail.edit")
            Button("Move to Trash", role: .destructive) { confirmingTrash = true }
                .accessibilityIdentifier("detail.trash")
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

    @ViewBuilder private func row(_ field: Field) -> some View {
        HStack {
            VStack(alignment: .leading) {
                Text(field.label).font(.caption).foregroundStyle(.secondary)
                if field.kind.isSecret && !revealed.contains(field.id) {
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
                Button(revealed.contains(field.id) ? "Hide" : "Show") {
                    model.recordActivity()
                    if revealed.contains(field.id) { revealed.remove(field.id) } else { revealed.insert(field.id) }
                }
                .buttonStyle(.borderless)
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
