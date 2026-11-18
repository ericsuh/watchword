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
    @Environment(\.screenCloser) private var closer
    @State private var model: ImportModel
    @State private var choosingFile = false
    /// Cleared when a file or backup is chosen and when the review appears: on iOS the keyboard would otherwise stay
    /// up over what comes next.
    @FocusState private var focus: SecretField?

    private enum SecretField: Hashable { case passphrase, secretKey }
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
                    Button("Done") { closer?.close() }
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
        .scrollDismissesKeyboard(.interactively)
        .navigationTitle(restoring ? "Restore from a Backup" : "Import")
        .closesSheet()
        .overlay { if model.isWorking { ProgressView() } }
        .task { await model.load() }
        // Revealed merge values are hidden again when the app resigns active or the screen is captured (Z95).
        .onChange(of: app.privacy.concealments) { model.revealed.removeAll() }
        .onChange(of: model.stage) { focus = nil }
        .fileImporter(isPresented: $choosingFile, allowedContentTypes: contentTypes) { read($0) }
        .confirmationDialog(
            "Accept \(model.hostAwaitingConfirmation?.host.ascii ?? "this address")?",
            isPresented: awaitingHostBinding, titleVisibility: .visible
        ) {
            Button("Accept Anyway", role: .destructive) { model.confirmAwaitingHost() }
                .accessibilityIdentifier(AccessibilityID.Import.hostConfirm)
            Button("Cancel", role: .cancel) { model.cancelAwaitingHost() }
        } message: {
            Text(model.hostAwaitingConfirmation?.host.warning ?? "")
        }
        .onDisappear {
            // Drafts hold every secret in the file: dropped as soon as the screen goes, not only at a lock.
            if model.stage == .review { Task { await model.cancel() } }
            Task { try? await app.reload() }
        }
    }

    private var awaitingHostBinding: Binding<Bool> {
        Binding(
            get: { model.hostAwaitingConfirmation != nil },
            set: { if !$0 { model.cancelAwaitingHost() } })
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
                    Text(vault.label).tag(Optional(vault.id))
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
                // `ImportOptions`, chosen before the file is read (owner decision K6: the apex is opt-out).
                Toggle("Also offer each www address without www", isOn: $model.addsApexOfWWWHosts)
                    .accessibilityIdentifier(AccessibilityID.Import.addsApex)
                Toggle("Also import what the other app kept in its trash", isOn: $model.includesTrash)
                    .accessibilityIdentifier(AccessibilityID.Import.includesTrash)
            } else {
                // The backup's trash is the person's to restore or not (Z82); the review lists what it leaves out.
                Toggle("Also restore what was in the trash", isOn: $model.includesTrash)
                    .accessibilityIdentifier(AccessibilityID.Import.includesTrash)
            }
        } footer: {
            if restoring {
                Text(
                    "Every item in the backup goes into the vault you choose, naming the vault it came from. What "
                        + "you had put in the trash comes back only if you choose it above.")
            } else {
                Text("Export your passwords from the other app first. Nothing is saved until you review the import.")
            }
        }
        if restoring {
            Section {
                SecureField("Archive passphrase", text: $model.archivePassphrase)
                    .focused($focus, equals: .passphrase)
                    .accessibilityIdentifier(AccessibilityID.Import.passphrase)
                SecureField("Secret Key, for another account's backup", text: $model.archiveSecretKey)
                    .focused($focus, equals: .secretKey)
                    .accessibilityIdentifier(AccessibilityID.Import.secretKey)
            } footer: {
                Text("Leave the Secret Key empty for a backup of this account: this device has its Secret Key.")
            }
        }
        Section {
            Button(restoring ? "Choose Backup…" : "Choose File…") {
                focus = nil
                choosingFile = true
            }
            .disabled(model.vaultID == nil || (restoring && model.archivePassphrase.isEmpty) || model.isWorking)
            .accessibilityIdentifier(AccessibilityID.Import.chooseFile)
            #if DEBUG
                if app.uiTestPeer != nil {
                    if restoring {
                        Button("Use the archive just exported") {
                            focus = nil
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
            if !model.optionsLine.isEmpty {
                Text(model.optionsLine).font(.footnote)
            }
            ForEach(Array(model.reportLines.enumerated()), id: \.offset) { _, line in
                Text(line).font(.footnote)
            }
        }
        // A Section is not an accessibility element: without `.contain` its identifier would replace
        // every child's (on macOS the report's own rows lost theirs), so it becomes a container first.
        .accessibilityElement(children: .contain)
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
        if !model.concernsOfNewEntries.isEmpty {
            Section {
                ForEach(model.concernsOfNewEntries) { concern in
                    ConcernBlock(model: model, concern: concern)
                }
            } header: {
                Text("Would change AutoFill")
            } footer: {
                Text("Import one of these only if you know why the file has it. Skipping it leaves AutoFill as it is.")
            }
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier(AccessibilityID.Import.concerns)
        }
        Section("Items in the file") {
            ForEach(model.entries) { entry in
                VStack(alignment: .leading, spacing: 2) {
                    Text(entry.title)
                    // Each host in ASCII with its registrable domain picked out: an entry's hosts need not be one
                    // site's (review finding Z62).
                    ForEach(entry.sites) { site in
                        HostLine(host: site)
                    }
                    if entry.isArchived {
                        Text("Archived in the file").font(.caption).foregroundStyle(.secondary)
                    }
                    if entry.needsDecision && !entry.isDuplicate {
                        Text("Would change AutoFill: see above").font(.caption).foregroundStyle(.orange)
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
        // A Section is not an accessibility element: without `.contain` its identifier would replace
        // every child's (on macOS the report's own rows lost theirs), so it becomes a container first.
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier(AccessibilityID.Import.entries)
        Section {
            Button(
                model.undecided.isEmpty && model.undecidedConcerns.isEmpty
                    ? "Import" : "Choose for every item above first"
            ) {
                Task { await model.commit() }
            }
            .disabled(!model.canCommit)
            .accessibilityIdentifier(AccessibilityID.Import.commit)
            Button("Cancel", role: .cancel) { Task { await model.cancel() } }
                .accessibilityIdentifier(AccessibilityID.Import.cancel)
            #if DEBUG
                if app.uiTestPeer != nil {
                    Button("Lock now (UI test)") { Task { await app.lock() } }
                        .accessibilityIdentifier(AccessibilityID.Debug.lockNow)
                }
            #endif
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
            if let concern = model.concern(for: duplicate.id) {
                ForEach(Array(concern.explanation.enumerated()), id: \.offset) { _, line in
                    Banner(text: "Kept as a separate item: " + line)
                }
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
    @Environment(AppModel.self) private var app
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
                ForEach(review.hosts) { host in
                    hostToggle(host)
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
            // Added by the merge with no switch of their own, so shown in full before it is chosen (review finding
            // Z67): a link or a phone number in a text field is read as the item's own.
            if !review.otherFieldValues.isEmpty || !review.tags.isEmpty || review.addsNotes {
                Text("The merge also adds these, as they are:").font(.footnote)
                ForEach(review.otherFieldValues) { field in
                    fieldValue(field)
                }
                if !review.tags.isEmpty {
                    Text("Tags: " + review.tags.joined(separator: ", ")).font(.footnote)
                }
                if review.addsNotes {
                    VStack(alignment: .leading) {
                        Text("Notes").font(.caption).foregroundStyle(.secondary)
                        Text(review.notes).font(.footnote).textSelection(.disabled)
                    }
                }
            }
        }
        .padding(.leading, 8)
    }

    /// A host as the person should read it before accepting it: ASCII (punycode for any other alphabet), the
    /// registrable domain in bold, how far the scope reaches, and the look-alike warning (docs/05-anti-phishing.md).
    private func hostToggle(_ host: MergeHost) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Toggle(isOn: hostBinding(host.host)) {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 0) {
                        Text(host.prefix).foregroundStyle(.secondary)
                        Text(host.registrable).bold()
                    }
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.disabled)
                    Text(host.reach).font(.caption).foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("\(host.ascii), \(host.reach)")
            }
            .accessibilityIdentifier(AccessibilityID.Import.host(host.host))
            if let warning = host.warning {
                Banner(text: warning).accessibilityIdentifier(AccessibilityID.Import.hostWarning(host.host))
            }
        }
    }

    private func fieldValue(_ field: AdditionField) -> some View {
        HStack {
            VStack(alignment: .leading) {
                Text(field.label).font(.caption).foregroundStyle(.secondary)
                if field.isSecret && !(model.revealed.contains(field.id) && app.privacy.mayReveal) {
                    Text("••••••••").accessibilityLabel("Hidden")
                } else {
                    Text(field.value).font(.footnote).textSelection(.disabled)
                }
            }
            .accessibilityIdentifier(AccessibilityID.Import.field(field.label))
            if field.isSecret {
                Button(model.revealed.contains(field.id) ? "Hide" : "Show") {
                    if model.revealed.contains(field.id) {
                        model.revealed.remove(field.id)
                    } else if app.privacy.mayReveal {
                        model.revealed.insert(field.id)
                    }
                }
                .buttonStyle(.borderless)
                .accessibilityIdentifier(AccessibilityID.Import.reveal(field.label))
            }
        }
    }

    private func fieldToggle(_ field: AdditionField) -> some View {
        HStack {
            Toggle(isOn: fieldBinding(field.id)) {
                VStack(alignment: .leading) {
                    Text(field.label).font(.caption).foregroundStyle(.secondary)
                    if field.isSecret && !(model.revealed.contains(field.id) && app.privacy.mayReveal) {
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
                    } else if app.privacy.mayReveal {
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

/// A host as the person should read it before trusting it: ASCII, the registrable domain in bold, its reach, and the
/// session's look-alike warning where there is one.
struct HostLine: View {
    let host: MergeHost

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 0) {
                Text(host.prefix).foregroundStyle(.secondary)
                Text(host.registrable).bold()
            }
            .font(.system(.caption, design: .monospaced))
            .textSelection(.disabled)
            Text(host.reach).font(.caption2).foregroundStyle(.secondary)
            if let warning = host.warning {
                Banner(text: warning).accessibilityIdentifier(AccessibilityID.Import.hostWarning(host.host))
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(host.ascii), \(host.reach)")
    }
}

/// An entry that duplicates nothing and would still change AutoFill (`ImportConcernRow`): what it would do, then
/// the two answers. There is no merge: it is not the same account as anything saved.
struct ConcernBlock: View {
    let model: ImportModel
    let concern: ImportConcernRow

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(concern.title).font(.headline)
            ForEach(concern.sites) { site in
                HostLine(host: site)
            }
            ForEach(Array(concern.explanation.enumerated()), id: \.offset) { _, line in
                Banner(text: line)
            }
            choice("Skip", .skip, id: "skip")
            choice("Import Anyway", .keepBoth, id: "keepBoth")
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier(AccessibilityID.Import.concern(concern.title))
    }

    private func choice(_ title: String, _ value: ImportChoice, id: String) -> some View {
        Button {
            model.choose(value, forConcern: concern.id)
        } label: {
            HStack {
                Text(title)
                Spacer()
                if model.choices[concern.id] == value {
                    Image(systemName: "checkmark").accessibilityLabel("Chosen")
                }
            }
        }
        .buttonStyle(.borderless)
        .disabled(model.isWorking)
        .accessibilityIdentifier(AccessibilityID.Import.choice(concern.title) + "." + id)
    }
}
