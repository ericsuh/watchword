import SwiftUI
import UniformTypeIdentifiers
import WatchwordInterchange
import WatchwordKit
import WatchwordPresentation

/// Import from another password manager's file, or restore from an encrypted Watchword archive (PRD F8.1–F8.3, F8.5):
/// choose, review, commit. Nothing is written before the commit, every duplicate needs a choice, and a merge adds no
/// website, sign-in field or URL to an existing item that the person did not accept by name (`MergeChoices`). A
/// restore shows when the archive was made, so that an older archive put in place of the newest is seen for what it is.
struct ImportView: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var model: ImportModel
    @State private var choosingFile = false
    private let restoring: Bool

    /// The largest file read: an archive's bound (`AccountArchive`); the parsers bound the rest themselves.
    static let largestFile = 256 << 20

    init(context: ScreenContext, restoring: Bool) {
        self.restoring = restoring
        _model = State(initialValue: ImportModel(context: context))
    }

    var body: some View {
        Form {
            switch model.stage {
            case .choose:
                choose
            case .review:
                review
            case .done(let summary):
                Section {
                    Label(summary.text, systemImage: "checkmark.circle")
                        .accessibilityIdentifier(AccessibilityID.Import.summary)
                    Button("Done") { dismiss() }
                        .accessibilityIdentifier(AccessibilityID.Import.done)
                } footer: {
                    Text(
                        "Compare the number of items with what you expected before you delete anything from the app "
                            + "you are leaving.")
                }
            }
            ErrorText(message: model.errorMessage)
        }
        .formStyle(.grouped)
        .navigationTitle(restoring ? "Restore from a Backup" : "Import")
        .closesSheet()
        .overlay { if model.isWorking { ProgressView() } }
        .task { await model.load() }
        .fileImporter(isPresented: $choosingFile, allowedContentTypes: contentTypes) { read($0) }
        .onDisappear {
            // Drafts hold every secret in the file: dropped as soon as the screen goes, not only at a lock.
            if model.stage == .review { Task { await model.cancel() } }
            Task { try? await app.reload() }
        }
    }

    private var contentTypes: [UTType] {
        if restoring { return [.data] }
        switch model.format {
        case .passwordCSV: return [.commaSeparatedText, .plainText]
        case .onePUX: return [UTType(filenameExtension: "1pux") ?? .zip, .zip]
        case .credentialExchange: return [.json, .data]
        }
    }

    @ViewBuilder private var choose: some View {
        Section {
            Picker(restoring ? "Restore into" : "Import into", selection: $model.vaultID) {
                ForEach(model.vaults) { vault in
                    Text(vault.name).tag(Optional(vault.id))
                }
            }
            .accessibilityIdentifier(AccessibilityID.Import.vault)
            if !restoring {
                Picker("File from", selection: $model.format) {
                    Text("1Password or Apple Passwords (CSV)").tag(ImportFileFormat.passwordCSV)
                    Text("1Password (.1pux)").tag(ImportFileFormat.onePUX)
                    Text("Credential Exchange (CXF)").tag(ImportFileFormat.credentialExchange)
                }
                .accessibilityIdentifier(AccessibilityID.Import.format)
            }
        } footer: {
            if restoring {
                Text("Every item in the backup goes into the vault you choose, naming the vault it came from.")
            } else {
                Text("Export your passwords from the other app first. Nothing is saved until you review the import.")
            }
        }
        if restoring {
            Section {
                SecureField("Archive passphrase", text: $model.archivePassphrase)
                    .accessibilityIdentifier(AccessibilityID.Import.passphrase)
                SecureField("Secret Key, for another account's backup", text: $model.archiveSecretKey)
                    .accessibilityIdentifier(AccessibilityID.Import.secretKey)
            } footer: {
                Text("Leave the Secret Key empty for a backup of this account: this device has its Secret Key.")
            }
        }
        Section {
            Button(restoring ? "Choose Backup…" : "Choose File…") { choosingFile = true }
                .disabled(model.vaultID == nil || (restoring && model.archivePassphrase.isEmpty) || model.isWorking)
                .accessibilityIdentifier(AccessibilityID.Import.chooseFile)
            #if DEBUG
                if app.uiTestPeer != nil {
                    if restoring {
                        Button("Use the archive just exported") {
                            if let archive = app.uiTestArchive { Task { await model.readArchive(archive) } }
                        }
                        .disabled(app.uiTestArchive == nil || model.archivePassphrase.isEmpty)
                        .accessibilityIdentifier(AccessibilityID.Import.uiTestArchive)
                    } else {
                        Button("Use the UI-test sample file") {
                            model.format = .passwordCSV
                            Task { await model.read(Array(UITestSamples.importCSV.utf8)) }
                        }
                        .accessibilityIdentifier(AccessibilityID.Import.uiTestSample)
                    }
                }
            #endif
        }
    }

    @ViewBuilder private var review: some View {
        if let createdAt = model.archiveCreatedAt {
            Section {
                Label(
                    "This backup was made on \(createdAt.formatted(date: .long, time: .shortened)).",
                    systemImage: "calendar"
                )
                .font(.headline)
                .accessibilityIdentifier(AccessibilityID.Import.archiveDate)
                Text(
                    "If you expected a newer backup, stop here: an older one may have been put in its place, and "
                        + "restoring it would bring back old passwords."
                )
                .font(.footnote).foregroundStyle(.secondary)
            }
        }
        Section(model.formatName) {
            ForEach(Array(model.reportLines.enumerated()), id: \.offset) { _, line in
                Text(line).font(.footnote)
            }
        }
        .accessibilityIdentifier(AccessibilityID.Import.report)
        if !model.duplicates.isEmpty {
            Section {
                ForEach(model.duplicates) { duplicate in
                    DuplicateBlock(model: model, duplicate: duplicate)
                }
            } header: {
                Text("Already in your vault")
            } footer: {
                Text("Choose what to do with each. A merge adds a website or a sign-in detail only if you accept it.")
            }
        }
        Section("Items in the file") {
            ForEach(model.entries) { entry in
                VStack(alignment: .leading, spacing: 2) {
                    Text(entry.title)
                    if !entry.hosts.isEmpty {
                        Text(entry.hosts.joined(separator: ", ")).font(.caption).foregroundStyle(.secondary)
                    }
                    if !entry.apexScopesAdded.isEmpty {
                        Text(
                            "Also offered on \(entry.apexScopesAdded.joined(separator: ", ")), beside its www address."
                        )
                        .font(.caption).foregroundStyle(.orange)
                    }
                    if entry.isDuplicate {
                        Text("Duplicate: see above").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .accessibilityIdentifier(AccessibilityID.Import.entries)
        Section {
            Button(model.undecided.isEmpty ? "Import" : "Choose for every duplicate first") {
                Task { await model.commit() }
            }
            .disabled(!model.canCommit)
            .accessibilityIdentifier(AccessibilityID.Import.commit)
            Button("Cancel", role: .cancel) { Task { await model.cancel() } }
                .accessibilityIdentifier(AccessibilityID.Import.cancel)
        }
    }

    private func read(_ result: Result<URL, any Error>) {
        guard case .success(let url) = result else { return }
        let accessing = url.startAccessingSecurityScopedResource()
        defer { if accessing { url.stopAccessingSecurityScopedResource() } }
        do {
            let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            guard size <= Self.largestFile else {
                model.errorMessage = "That file is too large to be an export or a backup."
                return
            }
            let bytes = [UInt8](try Data(contentsOf: url))
            if restoring {
                Task { await model.readArchive(bytes) }
            } else {
                Task { await model.read(bytes) }
            }
        } catch {
            model.errorMessage = "The file could not be opened."
        }
    }
}

/// One imported entry that duplicates an existing item: the choice, and for a merge everything it would add.
struct DuplicateBlock: View {
    let model: ImportModel
    let duplicate: DuplicateRow

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(duplicate.title).font(.headline)
            if !duplicate.hosts.isEmpty || !duplicate.loginNames.isEmpty {
                Text((duplicate.hosts + duplicate.loginNames).joined(separator: " · "))
                    .font(.caption).foregroundStyle(.secondary)
            }
            ForEach(duplicate.options) { option in
                Text(option.summary).font(.footnote)
            }
            choice("Skip", .skip, id: "skip")
            choice("Keep Both", .keepBoth, id: "keepBoth")
            ForEach(duplicate.options) { option in
                choice("Merge into “\(option.existingTitle)”", .merge(into: option.id), id: "merge")
            }
            if let review = model.merges[duplicate.id] {
                MergeReviewView(model: model, importedID: duplicate.id, review: review)
            }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier(AccessibilityID.Import.duplicate(duplicate.title))
    }

    private func choice(_ title: String, _ value: ImportChoice, id: String) -> some View {
        Button {
            Task { await model.choose(value, for: duplicate.id) }
        } label: {
            HStack {
                Text(title)
                Spacer()
                if model.choices[duplicate.id] == value {
                    Image(systemName: "checkmark").accessibilityLabel("Chosen")
                }
            }
        }
        .buttonStyle(.borderless)
        .disabled(model.isWorking)
        .accessibilityIdentifier(AccessibilityID.Import.choice(duplicate.title) + "." + id)
    }
}

/// What a merge would add to the existing item, each website, sign-in field and URL with its own switch, all off.
/// Secret values are hidden until shown.
struct MergeReviewView: View {
    let model: ImportModel
    let importedID: UUID
    let review: MergeReview

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if !review.hosts.isEmpty {
                Text(
                    "Also offer the existing item on these sites? Each is one more place AutoFill offers its password. "
                        + "Accept only those you know belong to it."
                )
                .font(.footnote)
                ForEach(review.hosts, id: \.self) { host in
                    Toggle(host, isOn: hostBinding(host))
                        .accessibilityIdentifier(AccessibilityID.Import.host(host))
                }
            }
            if !review.signInFields.isEmpty {
                Text("Add these sign-in details?").font(.footnote)
                ForEach(review.signInFields) { field in
                    fieldToggle(field)
                }
            }
            if !review.urlFields.isEmpty {
                Text("Add these URLs? A URL is where you, or the next app, would sign in.").font(.footnote)
                ForEach(review.urlFields) { field in
                    fieldToggle(field)
                }
            }
            let added = review.otherFields + review.tags.map { "tag \($0)" } + (review.addsNotes ? ["notes"] : [])
            if !added.isEmpty {
                Text("The merge also adds: \(added.joined(separator: ", ")).").font(.footnote).foregroundStyle(
                    .secondary)
            }
        }
        .padding(.leading, 8)
    }

    private func fieldToggle(_ field: AdditionField) -> some View {
        HStack {
            Toggle(isOn: fieldBinding(field.id)) {
                VStack(alignment: .leading) {
                    Text(field.label).font(.caption).foregroundStyle(.secondary)
                    if field.isSecret && !model.revealed.contains(field.id) {
                        Text("••••••••").accessibilityLabel("Hidden")
                    } else {
                        Text(field.value)
                            .font(field.isSecret ? Font.system(.body, design: .monospaced) : Font.body)
                            .textSelection(.disabled)
                    }
                }
            }
            .accessibilityIdentifier(AccessibilityID.Import.field(field.label))
            if field.isSecret {
                Button(model.revealed.contains(field.id) ? "Hide" : "Show") {
                    if model.revealed.contains(field.id) {
                        model.revealed.remove(field.id)
                    } else {
                        model.revealed.insert(field.id)
                    }
                }
                .buttonStyle(.borderless)
                .accessibilityIdentifier(AccessibilityID.Import.reveal(field.label))
            }
        }
    }

    private func hostBinding(_ host: String) -> Binding<Bool> {
        Binding(
            get: { model.isAccepted(host: host, for: importedID) },
            set: { model.setHost(host, accepted: $0, for: importedID) })
    }

    private func fieldBinding(_ id: UUID) -> Binding<Bool> {
        Binding(
            get: { model.isAccepted(field: id, for: importedID) },
            set: { model.setField(id, accepted: $0, for: importedID) })
    }
}
