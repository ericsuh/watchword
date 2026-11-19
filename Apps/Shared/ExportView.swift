import SwiftUI
import UniformTypeIdentifiers
import WatchwordPresentation

/// Export and back up (PRD F8.4, F8.5): the encrypted Watchword archive, or a plaintext file for another password
/// manager. The standing warning about plaintext files is on screen for as long as this is. The account password is
/// asked for every time and checked by the session in the same call; the report is shown before the file is saved,
/// since it is what the person reads before deleting anything; and the bytes are dropped once saved. The CSV holds
/// every value exactly as stored (owner decision, 2026-11-16).
///
/// The file is written by the app itself, into the app's staging folder (`StagingFolder`), with
/// `completeFileProtectionUnlessOpen` on iOS, and handed to the system's file mover, which moves it where the person
/// chooses; whatever is left of it is removed when the mover is done, when the screen closes and at every lock, and
/// the whole folder is swept at launch, unlock, lock and termination, so a process that dies with the mover up leaves
/// it no later than the next launch (Z80). On macOS there is no protection class: the file is as safe as the folder
/// the person picks (docs/02-architecture.md §14.1).
struct ExportView: View {
    @Environment(AppModel.self) private var app
    @State private var model: ExportModel
    @State private var moving = false
    @State private var staged: URL?
    /// Cleared when the export runs and when its report appears: on iOS the keyboard would otherwise stay up over the
    /// report and its Save button.
    @FocusState private var focus: SecretField?

    private enum SecretField: Hashable { case password, passphrase, confirmation }

    init(context: ScreenContext) {
        _model = State(initialValue: ExportModel(context: context))
    }

    /// The row of the Save button, which the form scrolls to when the report appears.
    private static let saveRow = "export.saveRow"

    var body: some View {
        ScrollViewReader { proxy in
            form
                .onChange(of: model.file != nil) { _, shown in
                    // The report and its Save button are added at the foot of a form that may already fill the
                    // screen: brought into view, so nobody has to find them by scrolling.
                    guard shown else { return }
                    withAnimation { proxy.scrollTo(Self.saveRow, anchor: .bottom) }
                }
        }
    }

    private var form: some View {
        Form {
            Section {
                Label(ExportModel.plaintextWarning, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .accessibilityIdentifier(AccessibilityID.Export.warning)
            }
            Section("Format") {
                ForEach(ExportKind.allCases) { kind in
                    Button {
                        model.kind = kind
                        model.discardFile()
                    } label: {
                        HStack {
                            Text(kind.title)
                            Spacer()
                            if model.kind == kind { Image(systemName: "checkmark").accessibilityHidden(true) }
                        }
                        // The whole row chooses: a borderless button is hit only where it draws, and on iOS a tap
                        // beside a short title, in the spacer, chose nothing.
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.borderless)
                    // The checkmark, said once: as the row's value, which the UI tests wait for (`chooseExportKind`).
                    .accessibilityValue(model.kind == kind ? "Chosen" : "")
                    .accessibilityAddTraits(model.kind == kind ? .isSelected : [])
                    .accessibilityIdentifier(AccessibilityID.Export.kind + "." + kind.rawValue)
                }
            }
            Section("Vaults") {
                ForEach(model.vaults) { vault in
                    Toggle(vault.label, isOn: vaultBinding(vault.id))
                        .accessibilityIdentifier(AccessibilityID.Export.vault(vault.name))
                }
            }
            Section {
                SecureField("Account password", text: $model.password)
                    .focused($focus, equals: .password)
                    .accessibilityIdentifier(AccessibilityID.Export.password)
                if model.kind == .archive {
                    SecureField("Archive passphrase", text: $model.passphrase)
                        .focused($focus, equals: .passphrase)
                        .accessibilityIdentifier(AccessibilityID.Export.passphrase)
                    SecureField("Confirm archive passphrase", text: $model.passphraseConfirmation)
                        .focused($focus, equals: .confirmation)
                        .accessibilityIdentifier(AccessibilityID.Export.passphraseConfirmation)
                }
                Button(model.kind == .archive ? "Create Backup" : "Export") {
                    focus = nil
                    Task { await model.export() }
                }
                .disabled(model.problem != nil || model.isWorking)
                .accessibilityIdentifier(AccessibilityID.Export.run)
            } footer: {
                if model.kind == .archive {
                    Text(
                        "Restoring the backup needs this passphrase and the Secret Key on your Emergency Kit. Neither "
                            + "is stored in it.")
                } else {
                    Text("Your account password is checked before the file is made.")
                }
            }
            if let file = model.file {
                Section("Before you save it") {
                    Text("\(file.itemCount) item(s) in the file.")
                        .accessibilityIdentifier(AccessibilityID.Export.count)
                    if file.unreadableCount > 0 {
                        Text("\(file.unreadableCount) item(s) could not be read and are not in the file.")
                            .foregroundStyle(.orange)
                    }
                    if file.lines.isEmpty {
                        Text(
                            file.kind.isPlaintext ? "Everything was written as it is." : "Everything is in the backup."
                        )
                        .foregroundStyle(.secondary)
                    }
                    ForEach(Array(file.lines.enumerated()), id: \.offset) { _, line in
                        Text(line).font(.footnote)
                    }
                }
                // A Section is not an accessibility element: without `.contain` its identifier would replace
                // every child's (on macOS the report's own rows lost theirs), so it becomes a container first.
                .accessibilityElement(children: .contain)
                .accessibilityIdentifier(AccessibilityID.Export.report)
                // The buttons in a section of their own, outside that container. Inside it, on iOS, the Save button
                // was never hittable: in full view, enabled, with no keyboard up, while the Export button above,
                // in a section with no container, was (a row's own `.contain`, as in the import's duplicates, does
                // not do this).
                Section {
                    Button("Save File…") { stageAndMove() }
                        .accessibilityIdentifier(AccessibilityID.Export.save)
                        .id(Self.saveRow)
                    #if DEBUG
                        if app.uiTestPeer != nil {
                            Button("Lock now (UI test)") { Task { await app.lock() } }
                                .accessibilityIdentifier(AccessibilityID.Debug.lockNow)
                        }
                    #endif
                }
            }
            ErrorText(message: model.errorMessage)
        }
        .formStyle(.grouped)
        .scrollDismissesKeyboard(.interactively)
        .navigationTitle("Export and Back Up")
        .closesSheet()
        .overlay { if model.isWorking { ProgressView() } }
        .task { await model.load() }
        .onChange(of: model.file) {
            if model.file != nil { focus = nil }
            #if DEBUG
                if app.uiTestPeer != nil, let archive = model.archiveBytes { app.uiTestArchive = archive }
            #endif
        }
        .fileMover(isPresented: $moving, file: staged) { result in
            staged = nil
            switch result {
            case .success: model.finishSaving(saved: true)
            case .failure: model.finishSaving(saved: false)
            }
        }
        .onChange(of: moving) { _, presented in
            // A mover dismissed without an answer leaves nothing behind either.
            guard !presented else { return }
            Task {
                await Task.yield()
                if staged != nil {
                    staged = nil
                    model.finishSaving(saved: false)
                }
            }
        }
        .onDisappear {
            model.discardFile()
            staged = nil
        }
    }

    private func stageAndMove() {
        #if os(iOS)
            let options: Data.WritingOptions = [.completeFileProtectionUnlessOpen]
        #else
            let options: Data.WritingOptions = []
        #endif
        do {
            staged = try model.stage(options: options)
            moving = true
        } catch {
            model.errorMessage = "The file could not be prepared. Nothing was saved."
        }
    }

    private func vaultBinding(_ id: UUID) -> Binding<Bool> {
        Binding(
            get: { model.selectedVaults.contains(id) },
            set: { selected in
                if selected { model.selectedVaults.insert(id) } else { model.selectedVaults.remove(id) }
            })
    }
}
