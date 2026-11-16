import SwiftUI
import UniformTypeIdentifiers
import WatchwordPresentation

/// Export and back up (PRD F8.4, F8.5): the encrypted Watchword archive, or a plaintext file for another password
/// manager. The standing warning about plaintext files is on screen for as long as this is. The account password is
/// asked for every time and checked by the session in the same call; the report is shown before the file is saved,
/// since it is what the person reads before deleting anything; and the bytes are dropped once saved. The CSV holds
/// every value exactly as stored (owner decision, 2026-11-16).
struct ExportView: View {
    @Environment(AppModel.self) private var app
    @State private var model: ExportModel
    @State private var saving = false
    @State private var document: ExportDocument?

    init(context: ScreenContext) {
        _model = State(initialValue: ExportModel(context: context))
    }

    var body: some View {
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
                            if model.kind == kind { Image(systemName: "checkmark").accessibilityLabel("Chosen") }
                        }
                    }
                    .buttonStyle(.borderless)
                    .accessibilityIdentifier(AccessibilityID.Export.kind + "." + kind.rawValue)
                }
            }
            Section("Vaults") {
                ForEach(model.vaults) { vault in
                    Toggle(vault.name, isOn: vaultBinding(vault.id))
                        .accessibilityIdentifier(AccessibilityID.Export.vault(vault.name))
                }
            }
            Section {
                SecureField("Account password", text: $model.password)
                    .accessibilityIdentifier(AccessibilityID.Export.password)
                if model.kind == .archive {
                    SecureField("Archive passphrase", text: $model.passphrase)
                        .accessibilityIdentifier(AccessibilityID.Export.passphrase)
                    SecureField("Confirm archive passphrase", text: $model.passphraseConfirmation)
                        .accessibilityIdentifier(AccessibilityID.Export.passphraseConfirmation)
                }
                Button(model.kind == .archive ? "Create Backup" : "Export") { Task { await model.export() } }
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
                    Button("Save File…") {
                        document = ExportDocument(bytes: file.bytes, kind: file.kind)
                        saving = true
                    }
                    .accessibilityIdentifier(AccessibilityID.Export.save)
                }
                .accessibilityIdentifier(AccessibilityID.Export.report)
            }
            ErrorText(message: model.errorMessage)
        }
        .formStyle(.grouped)
        .navigationTitle("Export and Back Up")
        .closesSheet()
        .overlay { if model.isWorking { ProgressView() } }
        .task { await model.load() }
        .onChange(of: model.file) { _, file in
            #if DEBUG
                if let file, file.kind == .archive, app.uiTestPeer != nil { app.uiTestArchive = file.bytes }
            #endif
        }
        .fileExporter(
            isPresented: $saving, document: document, contentType: document?.contentType ?? .data,
            defaultFilename: model.file?.filename
        ) { result in
            document = nil
            if case .success = result { model.discardFile() }
        }
        .onDisappear {
            model.discardFile()
            document = nil
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

/// An export's bytes for the system file exporter. On iOS the file is written with `completeUnlessOpen` protection
/// (`VaultSession.exportPlaintext`'s contract); the app writes it nowhere else.
struct ExportDocument: FileDocument {
    static let readableContentTypes: [UTType] = [.data]
    static let writableContentTypes: [UTType] = [.commaSeparatedText, .data]

    let bytes: [UInt8]
    let contentType: UTType

    init(bytes: [UInt8], kind: ExportKind) {
        self.bytes = bytes
        contentType = kind == .applePasswordsCSV ? .commaSeparatedText : .data
    }

    init(configuration: ReadConfiguration) throws {
        bytes = [UInt8](configuration.file.regularFileContents ?? Data())
        contentType = .data
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        let wrapper = FileWrapper(regularFileWithContents: Data(bytes))
        #if os(iOS)
            wrapper.fileAttributes[FileAttributeKey.protectionKey.rawValue] =
                FileProtectionType.completeUnlessOpen.rawValue
        #endif
        return wrapper
    }
}
