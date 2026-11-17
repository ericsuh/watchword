import SwiftUI
import WatchwordGenerator
import WatchwordModel
import WatchwordPresentation

/// Create or edit an item. Scopes are checked by the vault when saving (PRD F11.2); an over-broad host is refused
/// there, not here, so no UI path can skip the check. A host that resembles a saved site is refused there too until
/// the person confirms it by name (PRD F11.7): the question, which names the site and the item, comes from
/// `ItemEditorModel`.
struct ItemEditView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var editor: ItemEditorModel?
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
                if let vault = model.vault(draft.vaultID) {
                    // Where the item goes, by ownership and role, not by name alone: a member who may write can call
                    // a shared vault "Personal" (review of the account screens, finding 4).
                    Label {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Saving to \(vault.name)")
                            Text(vault.isShared ? "\(vault.badge). Everyone in this vault can see it." : vault.badge)
                                .font(.caption).foregroundStyle(vault.isShared ? Color.orange : Color.secondary)
                        }
                    } icon: {
                        Image(systemName: vault.isShared ? "person.2.fill" : "lock.fill")
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("edit.vault")
                }
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
                    Button("Save") { Task { await save(confirmed: false) } }
                        .disabled(draft.title.isEmpty || model.isWorking)
                        .accessibilityIdentifier("edit.save")
                }
            }
            // One question per look-alike host, each naming the site as it resolves and this item. Nothing has been
            // written when it appears, and "Cancel" leaves it so.
            .confirmationDialog(
                editor?.prompts.first?.title ?? "", isPresented: confirming, titleVisibility: .visible
            ) {
                Button("Add Anyway", role: .destructive) { Task { await save(confirmed: true) } }
                    .accessibilityIdentifier("edit.host.confirm")
                Button("Cancel", role: .cancel) { editor?.cancelConfirmation() }
                    .accessibilityIdentifier("edit.host.cancel")
            } message: {
                Text((editor?.prompts ?? []).map(\.message).joined(separator: "\n\n"))
            }
        }
        #if os(macOS)
            .frame(minWidth: 460, minHeight: 420)
        #endif
    }

    private var confirming: Binding<Bool> {
        Binding(
            get: { editor?.isAwaitingConfirmation ?? false },
            set: { if !$0 { editor?.cancelConfirmation() } })
    }

    private func save(confirmed: Bool) async {
        guard let context = model.screenContext else { return }
        let editor = editor ?? ItemEditorModel(context: context)
        self.editor = editor
        if await model.save(assembled(), with: editor, confirmed: confirmed) { dismiss() }
    }

    private func assembled() -> Item {
        var item = draft
        item.scopes = ItemEditorModel.scopes(from: hosts, keeping: item.scopes)
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
