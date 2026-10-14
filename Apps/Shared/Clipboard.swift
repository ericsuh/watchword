import Foundation

#if os(iOS)
    import UIKit
#else
    import AppKit
#endif

/// Copies with an expiry and without Universal Clipboard (PRD F5.6).
///
/// Whether the clipboard still holds our copy is decided by `changeCount`, never by reading it back: reading would show
/// the paste prompt on iOS whenever another app had copied something since.
@MainActor
enum Clipboard {
    static let lifetime: TimeInterval = 60
    private static var ourChangeCount: Int?

    static func copy(_ value: String) {
        #if os(iOS)
            UIPasteboard.general.setItems(
                [[UIPasteboard.typeAutomatic: value]],
                options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(lifetime)])
            ourChangeCount = UIPasteboard.general.changeCount
        #else
            let pasteboard = NSPasteboard.general
            pasteboard.clearContents()
            // `org.nspasteboard.ConcealedType` asks clipboard managers not to record it; `TransientType` asks them not
            // to keep it (nspasteboard.org conventions).
            pasteboard.declareTypes(
                [
                    .string, NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"),
                    NSPasteboard.PasteboardType("org.nspasteboard.TransientType"),
                ], owner: nil)
            pasteboard.setString(value, forType: .string)
            let changeCount = pasteboard.changeCount
            ourChangeCount = changeCount
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(lifetime))
                if NSPasteboard.general.changeCount == changeCount { NSPasteboard.general.clearContents() }
            }
        #endif
    }

    /// On lock, removes what we copied if nothing has been copied since.
    static func clearIfOurs() {
        guard let ourChangeCount else { return }
        #if os(iOS)
            if UIPasteboard.general.changeCount == ourChangeCount { UIPasteboard.general.items = [] }
        #else
            if NSPasteboard.general.changeCount == ourChangeCount { NSPasteboard.general.clearContents() }
        #endif
        self.ourChangeCount = nil
    }
}
