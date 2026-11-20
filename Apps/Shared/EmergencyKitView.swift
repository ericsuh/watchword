import SwiftUI
import WatchwordKit
import WatchwordPlatform
import WatchwordPresentation

/// Shows the Secret Key and saves the Emergency Kit PDF where the person chooses (PRD F5.1). From Settings the
/// account password is asked for first and checked by the session (Z86); during onboarding the kit is the one just
/// created, or the unconfirmed one after a password unlock. The PDF is written by the app into its swept staging
/// folder, with complete file protection on iOS, and handed to the system's file mover, as an export is; whatever is
/// left of it goes when the mover is done, when the screen closes and at every lock, and with the folder at the next
/// launch (`EmergencyKitModel`, Z84). The Secret Key is hidden again whenever the app resigns active or the screen is
/// captured (`ScreenPrivacy`, Z95).
struct EmergencyKitView: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var model: EmergencyKitModel
    @State private var confirmed = false
    @State private var moving = false
    @State private var staged: URL?

    init(context: ScreenContext, privacy: ScreenPrivacy, kit: EmergencyKit?) {
        _model = State(initialValue: EmergencyKitModel(context: context, privacy: privacy, kit: kit))
    }

    var body: some View {
        Form {
            Section {
                Text(EmergencyKitText.title).font(.title2.bold())
                Text(EmergencyKitText.instructions).foregroundStyle(.secondary)
                Label(EmergencyKitModel.storageWarning, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .accessibilityIdentifier("kit.storageWarning")
            }
            if model.needsPassword {
                Section {
                    SecureField("Account password", text: $model.password)
                        .accessibilityIdentifier("kit.password")
                        .onSubmit { Task { await model.open() } }
                    Button("Show Emergency Kit") { Task { await model.open() } }
                        .disabled(model.password.isEmpty || model.isWorking)
                        .accessibilityIdentifier("kit.open")
                } footer: {
                    Text("Your account password is checked before the Secret Key is shown.")
                }
            } else if let kit = model.kit {
                Section("Secret Key") {
                    if model.showsSecretKey {
                        Text(kit.secretKey)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.disabled)
                            .accessibilityIdentifier("kit.secretKey")
                    } else {
                        Text(model.hiddenReason ?? "Hidden.").foregroundStyle(.secondary)
                        Button("Show Secret Key") { model.revealSecretKey() }
                            .accessibilityIdentifier("kit.reveal")
                    }
                }
                Section {
                    Button("Save Emergency Kit PDF…") { stageAndMove() }
                        .accessibilityIdentifier("kit.save")
                    Text(EmergencyKitText.unrecoverableWarning).font(.footnote)
                    if model.isOnboarding {
                        Toggle("I have saved or printed my Emergency Kit", isOn: $confirmed)
                            .accessibilityIdentifier("kit.confirmSaved")
                        Button("Continue") { Task { await app.confirmEmergencyKitSaved() } }
                            .disabled(!confirmed)
                            .accessibilityIdentifier("kit.continue")
                    } else if model.awaitsConfirmation {
                        // Not yet confirmed: after a quick unlock this is the only place to do it (Z131).
                        Toggle("I have saved or printed my Emergency Kit", isOn: $confirmed)
                            .accessibilityIdentifier("kit.settingsConfirmSaved")
                        Button("Confirm") { Task { await model.confirmSaved() } }
                            .disabled(!confirmed || model.isWorking)
                            .accessibilityIdentifier("kit.settingsConfirm")
                    }
                }
            }
            Section {
                if !model.isOnboarding {
                    Button("Done") { dismiss() }.accessibilityIdentifier("kit.done")
                }
                ErrorText(message: model.errorMessage ?? app.errorMessage)
            }
        }
        .formStyle(.grouped)
        .frame(maxWidth: 560)
        .overlay { if model.isWorking { ProgressView() } }
        .fileMover(isPresented: $moving, file: staged) { _ in
            staged = nil
            model.finishSaving()
        }
        .onChange(of: moving) { _, presented in
            // A mover dismissed without an answer leaves nothing behind either.
            guard !presented else { return }
            Task {
                await Task.yield()
                if staged != nil {
                    staged = nil
                    model.finishSaving()
                }
            }
        }
        .onDisappear {
            model.close()
            staged = nil
        }
    }

    private func stageAndMove() {
        #if os(iOS)
            let options: Data.WritingOptions = [.completeFileProtection]
        #else
            let options: Data.WritingOptions = []
        #endif
        do {
            staged = try model.stagePDF(options: options) { kit, url, options in
                try EmergencyKitDocument.write(kit, to: url, options: options)
            }
            moving = true
        } catch {
            model.errorMessage = "The Emergency Kit could not be created."
        }
    }
}
