import SwiftUI
import UniformTypeIdentifiers
import WatchwordKit
import WatchwordPlatform

/// Shows the Secret Key and saves the Emergency Kit PDF where the person chooses (PRD F5.1). The PDF is generated in
/// memory and handed to the system file exporter; the app does not write it anywhere itself, though the system's
/// export machinery may stage a temporary copy while the save is in progress.
struct EmergencyKitView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let kit: EmergencyKit
    let isOnboarding: Bool
    @State private var confirmed = false
    @State private var exporting = false
    @State private var document: PDFFile?

    var body: some View {
        Form {
            Section {
                Text(EmergencyKitText.title).font(.title2.bold())
                Text(EmergencyKitText.instructions).foregroundStyle(.secondary)
            }
            Section("Secret Key") {
                Text(kit.secretKey)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.disabled)
                    .accessibilityIdentifier("kit.secretKey")
            }
            Section {
                Button("Save Emergency Kit PDF…") {
                    do {
                        document = PDFFile(data: try EmergencyKitDocument.pdf(for: kit))
                        exporting = true
                    } catch {
                        model.errorMessage = "The Emergency Kit could not be created."
                    }
                }
                .accessibilityIdentifier("kit.save")
                Text(EmergencyKitText.unrecoverableWarning).font(.footnote)
                if isOnboarding {
                    Toggle("I have saved or printed my Emergency Kit", isOn: $confirmed)
                        .accessibilityIdentifier("kit.confirmSaved")
                    Button("Continue") { Task { await model.confirmEmergencyKitSaved() } }
                        .disabled(!confirmed)
                        .accessibilityIdentifier("kit.continue")
                } else {
                    Button("Done") { dismiss() }
                }
                ErrorText(message: model.errorMessage)
            }
        }
        .formStyle(.grouped)
        .frame(maxWidth: 560)
        .fileExporter(
            isPresented: $exporting, document: document, contentType: .pdf,
            defaultFilename: "Watchword Emergency Kit"
        ) { _ in document = nil }
    }
}

struct PDFFile: FileDocument {
    static let readableContentTypes: [UTType] = [.pdf]
    let data: Data

    init(data: Data) {
        self.data = data
    }

    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}
