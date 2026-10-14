import SwiftUI
import WatchwordGenerator
import WatchwordModel

/// Create or edit an item. Scopes are checked by the vault when saving (PRD F11.2); an over-broad host is refused
/// there, not here, so no UI path can skip the check.
struct ItemEditView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var draft: Item
    @State private var hosts: String
    @State private var username: String
    @State private var password: String

    init(item: Item) {
        _draft = State(initialValue: item)
        _hosts = State(initialValue: item.scopes.map(\.host).joined(separator: ", "))
        _username = State(initialValue: item.field(.username)?.value ?? item.field(.email)?.value ?? "")
        _password = State(initialValue: item.field(.password)?.value ?? "")
    }

    var body: some View {
        NavigationStack {
            Form {
                TextField("Title", text: $draft.title).accessibilityIdentifier("edit.title")
                TextField("Websites (comma-separated)", text: $hosts)
                    .autocorrectionDisabled()
                    #if os(iOS)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                    #endif
                    .accessibilityIdentifier("edit.host")
                TextField("Username or email", text: $username)
                    .autocorrectionDisabled()
                    #if os(iOS)
                        .textInputAutocapitalization(.never)
                    #endif
                    .accessibilityIdentifier("edit.username")
                HStack {
                    SecureField("Password", text: $password).accessibilityIdentifier("edit.password")
                    Button("Generate") {
                        var generator = PasswordGenerator()
                        password = (try? generator.generate(RandomPasswordPolicy())) ?? password
                    }
                    .accessibilityIdentifier("edit.generate")
                }
                TextField("Notes", text: $draft.notes, axis: .vertical)
                Toggle("Hide from AutoFill suggestions", isOn: $draft.excludedFromSuggestions)
                ErrorText(message: model.errorMessage)
            }
            .formStyle(.grouped)
            .navigationTitle(draft.title.isEmpty ? "New item" : draft.title)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { Task { if await model.save(assembled()) { dismiss() } } }
                        .disabled(draft.title.isEmpty || model.isWorking)
                        .accessibilityIdentifier("edit.save")
                }
            }
        }
        #if os(macOS)
            .frame(minWidth: 460, minHeight: 420)
        #endif
    }

    private func assembled() -> Item {
        var item = draft
        let existing = Dictionary(item.scopes.map { ($0.host, $0) }, uniquingKeysWith: { first, _ in first })
        item.scopes = hosts.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            .map { existing[ServiceScope.canonicalHost($0)] ?? ServiceScope(host: $0) }
        set(.username, label: "Username", value: username, in: &item)
        set(.password, label: "Password", value: password, in: &item)
        return item
    }

    private func set(_ kind: FieldKind, label: String, value: String, in item: inout Item) {
        if let index = item.fields.firstIndex(where: { $0.kind == kind }) {
            item.fields[index].value = value
        } else if !value.isEmpty {
            item.fields.append(Field(kind: kind, label: label, value: value))
        }
    }
}
