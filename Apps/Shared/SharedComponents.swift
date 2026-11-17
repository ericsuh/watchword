import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI
import WatchwordPresentation

/// A safety number as twelve groups of five digits, three to a row, for two people to read to each other (PRD F4.2).
/// Monospaced and not selectable: it is compared, not copied.
struct SafetyNumberGrid: View {
    let groups: [String]

    var body: some View {
        Grid(horizontalSpacing: 16, verticalSpacing: 6) {
            ForEach(Array(stride(from: 0, to: groups.count, by: 3)), id: \.self) { start in
                GridRow {
                    ForEach(start..<min(start + 3, groups.count), id: \.self) { index in
                        Text(groups[index])
                    }
                }
            }
        }
        .font(.system(.title3, design: .monospaced))
        .textSelection(.disabled)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(groups.joined(separator: " "))
        .frame(maxWidth: .infinity)
        .padding(.vertical, 4)
    }
}

/// A QR code of `text`: a fingerprint code (`FingerprintCode.payload`), which is not a secret.
struct QRCodeView: View {
    let text: String

    var body: some View {
        if let image = Self.image(for: text) {
            Image(decorative: image, scale: 1)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .frame(maxWidth: 220, maxHeight: 220)
                .frame(maxWidth: .infinity)
                .accessibilityLabel("QR code of your fingerprint")
        }
    }

    static func image(for text: String) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)) else { return nil }
        return CIContext().createCGImage(output, from: output.extent)
    }
}

/// This account's safety number and QR code, for someone inviting this account to compare (PRD F4.2).
struct OwnFingerprintView: View {
    let fingerprint: OwnFingerprint

    var body: some View {
        Form {
            Section {
                Text(
                    "Someone inviting you to a shared vault compares this number with the one their device shows for "
                        + "you, in person or on a call. If any digit differs, they should not invite you."
                )
                .foregroundStyle(.secondary)
            }
            Section("Your safety number") {
                SafetyNumberGrid(groups: fingerprint.groups)
                    .accessibilityIdentifier(AccessibilityID.Vault.fingerprint)
            }
            Section("Your code") {
                QRCodeView(text: fingerprint.code)
                Text(fingerprint.code)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                Button("Copy Code") { Clipboard.copy(fingerprint.code) }
                Text("Your Watchword ID: \(fingerprint.accountID.uuidString)")
                    .font(.footnote).foregroundStyle(.secondary).textSelection(.enabled)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Your Safety Number")
        .closesSheet()
    }
}

/// A sheet asking for a vault's name: creating one, or renaming one.
struct VaultNameSheet: View {
    let title: String
    let action: String
    let fieldID: String
    let saveID: String
    let onSave: @MainActor (String) async -> Bool
    /// Clears the presenting state (see `ScreenSheet`).
    let close: @MainActor () -> Void
    @State private var name: String

    init(
        title: String, action: String, initial: String = "", fieldID: String, saveID: String,
        close: @escaping @MainActor () -> Void, onSave: @escaping @MainActor (String) async -> Bool
    ) {
        self.close = close
        self.title = title
        self.action = action
        self.fieldID = fieldID
        self.saveID = saveID
        self.onSave = onSave
        _name = State(initialValue: initial)
    }

    var body: some View {
        NavigationStack {
            Form {
                TextField("Name", text: $name)
                    .accessibilityIdentifier(fieldID)
                if let problem = VaultsModel.problem(withName: name), !name.isEmpty {
                    Text(problem).font(.footnote).foregroundStyle(.red)
                }
            }
            .formStyle(.grouped)
            .navigationTitle(title)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { close() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(action) {
                        let chosen = name
                        Task { if await onSave(chosen) { close() } }
                    }
                    .disabled(VaultsModel.problem(withName: name) != nil)
                    .accessibilityIdentifier(saveID)
                }
            }
        }
        #if os(macOS)
            .frame(minWidth: 380, minHeight: 180)
        #endif
    }
}

/// A line that says why something cannot be done here, or what to do about it.
struct Banner: View {
    let text: String
    var systemImage = "exclamationmark.triangle"

    var body: some View {
        Label(text, systemImage: systemImage)
            .font(.callout)
            .foregroundStyle(.orange)
    }
}

/// Closes the sheet an account screen was opened in, from that screen or anything pushed on it.
@MainActor
final class ScreenCloser {
    let close: @MainActor () -> Void

    init(close: @escaping @MainActor () -> Void) {
        self.close = close
    }
}

private struct ScreenCloserKey: EnvironmentKey {
    static let defaultValue: ScreenCloser? = nil
}

extension EnvironmentValues {
    var screenCloser: ScreenCloser? {
        get { self[ScreenCloserKey.self] }
        set { self[ScreenCloserKey.self] = newValue }
    }
}

/// An account screen in a sheet of its own over Settings, with a navigation stack for what it opens, and a Done button
/// on every screen in it (`closesSheet()`), so the whole sheet closes from wherever the person is.
///
/// It closes through `close`, which clears the presenting state, rather than through `dismiss`: on macOS a dismiss
/// action read inside a sheet that is itself over a sheet did not always close it.
struct ScreenSheet<Content: View>: View {
    let close: @MainActor () -> Void
    @ViewBuilder let content: () -> Content

    var body: some View {
        NavigationStack {
            content()
        }
        .environment(\.screenCloser, ScreenCloser(close: close))
        // Closed with Done: a swipe that scrolls past the top must not throw away an import being reviewed.
        .interactiveDismissDisabled()
        #if os(macOS)
            // Inside the 600-point window; the form scrolls, and Done is in the toolbar, always in view.
            .frame(minWidth: 540, minHeight: 520)
        #endif
    }
}

private struct CloseSheetButton: ViewModifier {
    @Environment(\.screenCloser) private var closer

    func body(content: Content) -> some View {
        content.toolbar {
            if let closer {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { closer.close() }
                        .accessibilityIdentifier(AccessibilityID.screenDone)
                }
            }
        }
    }
}

extension View {
    /// A Done button that closes the account screen's sheet; nothing outside one.
    func closesSheet() -> some View {
        modifier(CloseSheetButton())
    }
}
