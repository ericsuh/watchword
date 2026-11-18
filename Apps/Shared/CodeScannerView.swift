import SwiftUI
import WatchwordPresentation
import WatchwordSharing

#if os(iOS)
    import Vision
    import VisionKit

    /// The camera, reading one QR code from the other person's screen at a vault sharing code session (ADR 0010,
    /// Scanning). iPhone and iPad only: every device shows a code, and only these scan one.
    ///
    /// The live camera is the only source: `DataScannerViewController` reads what the camera sees, never the photo
    /// library or the pasteboard, because a code that arrived in a message names an account and proves nothing (review
    /// of the account screens, finding 2). The view decides nothing: it hands the text over once, bounded, to the screen
    /// model's `cameraScanned`, where the portable parsers (`ScannedSharingCode`, `FingerprintCode`) and the session
    /// check it. Drafted and not yet built on a Mac; the camera cannot be exercised by CI
    /// (docs/manual-tests/camera-scanning.md).
    struct CodeScannerView: View {
        let onScan: @MainActor (String) -> Void
        @Environment(\.dismiss) private var dismiss

        var body: some View {
            NavigationStack {
                Group {
                    if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                        LiveQRScanner { payload in
                            dismiss()
                            onScan(payload)
                        }
                        .ignoresSafeArea()
                        .accessibilityIdentifier(AccessibilityID.Scanner.view)
                    } else {
                        ContentUnavailableView(
                            "Scanning Is Not Available", systemImage: "camera",
                            description: Text(
                                "This device cannot use its camera here, or Watchword is not allowed to (Settings, "
                                    + "Privacy & Security, Camera). Type the code instead.")
                        )
                        .accessibilityIdentifier(AccessibilityID.Scanner.unavailable)
                    }
                }
                .navigationTitle("Scan Their Screen")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { dismiss() }
                            .accessibilityIdentifier(AccessibilityID.Scanner.cancel)
                    }
                }
            }
        }
    }

    /// `DataScannerViewController` for QR codes alone, delivering the first one it reads and then stopping.
    private struct LiveQRScanner: UIViewControllerRepresentable {
        let onScan: @MainActor (String) -> Void

        func makeCoordinator() -> Coordinator {
            Coordinator(onScan: onScan)
        }

        func makeUIViewController(context: Context) -> DataScannerViewController {
            let scanner = DataScannerViewController(
                recognizedDataTypes: [.barcode(symbologies: [.qr])], qualityLevel: .balanced,
                recognizesMultipleItems: false, isHighFrameRateTrackingEnabled: false, isPinchToZoomEnabled: true,
                isGuidanceEnabled: true, isHighlightingEnabled: true)
            scanner.delegate = context.coordinator
            return scanner
        }

        func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {
            // The first call to start scanning is what asks for the camera (NSCameraUsageDescription).
            if !scanner.isScanning, !context.coordinator.delivered { try? scanner.startScanning() }
        }

        static func dismantleUIViewController(_ scanner: DataScannerViewController, coordinator: Coordinator) {
            scanner.stopScanning()
        }

        @MainActor
        final class Coordinator: NSObject, DataScannerViewControllerDelegate {
            let onScan: @MainActor (String) -> Void
            private(set) var delivered = false

            init(onScan: @escaping @MainActor (String) -> Void) {
                self.onScan = onScan
            }

            func dataScanner(
                _ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem],
                allItems: [RecognizedItem]
            ) {
                guard !delivered else { return }
                for item in addedItems {
                    guard case .barcode(let barcode) = item, let payload = barcode.payloadStringValue,
                        // Longer than either code Watchword shows: not one of them, and not worth handing on.
                        payload.utf8.count <= ScannedSharingCode.payloadLength
                    else { continue }
                    delivered = true
                    dataScanner.stopScanning()
                    onScan(payload)
                    return
                }
            }
        }
    }
#endif

/// The control that scans the other person's screen: the camera on iPhone and iPad; nothing on a Mac, which shows
/// codes and does not scan them (ADR 0010). Under `--uitest` (Debug only) a stand-in reads the UI-test household
/// member's screen instead, as the file-picker stand-ins do, so XCUITests drive the same model entry point
/// (`cameraScanned`) the camera does.
struct ScanCodeButton: View {
    let title: String
    let accessibilityID: String
    /// What the household member's screen shows, for the stand-in.
    let uiTestPayload: @MainActor () async -> String?
    let onScan: @MainActor (String) async -> Void
    @Environment(AppModel.self) private var app
    @State private var scanning = false

    var body: some View {
        Group {
            #if os(iOS)
                Button {
                    scanning = true
                } label: {
                    Label(title, systemImage: "qrcode.viewfinder")
                }
                .accessibilityIdentifier(accessibilityID)
                .sheet(isPresented: $scanning) {
                    CodeScannerView { payload in Task { await onScan(payload) } }
                }
            #endif
            #if DEBUG
                if app.uiTestPeer != nil {
                    Button("Scan the household member's screen (UI test)") {
                        Task { if let payload = await uiTestPayload() { await onScan(payload) } }
                    }
                    .accessibilityIdentifier(AccessibilityID.Debug.scanMember)
                }
            #endif
        }
    }
}

/// Six or eight digits for two people to read to each other: large, monospaced, not selectable (they are read, not
/// copied), and spoken digit by digit by VoiceOver (`SharingCodeWording.spoken`).
struct SharingDigits: View {
    let code: String

    var body: some View {
        Text(code)
            .font(.system(.largeTitle, design: .monospaced).weight(.semibold))
            .textSelection(.disabled)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 4)
            .accessibilityLabel(SharingCodeWording.spoken(code))
    }
}
