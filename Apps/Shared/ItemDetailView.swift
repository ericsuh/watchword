import SwiftUI
import WatchwordModel

struct ItemDetailView: View {
    @Environment(AppModel.self) private var model
    let item: Item
    let onEdit: () -> Void
    @State private var revealed: Set<UUID> = []

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
            Button("Move to Trash", role: .destructive) { Task { await model.trash(item) } }
        }
    }

    @ViewBuilder private func row(_ field: Field) -> some View {
        HStack {
            VStack(alignment: .leading) {
                Text(field.label).font(.caption).foregroundStyle(.secondary)
                if field.kind.isSecret && !revealed.contains(field.id) {
                    Text("••••••••").accessibilityLabel("Hidden")
                } else {
                    Text(field.value).font(field.kind.isSecret ? .system(.body, design: .monospaced) : .body)
                        .textSelection(.enabled)
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
