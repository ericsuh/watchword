import AuthenticationServices

#if os(iOS)
    import UIKit
#else
    import AppKit
#endif

/// The AutoFill extension shell (milestone 2). Requests are answered in milestone 5, through `AutoFillGate` and the
/// shared vault; until then every request is cancelled with an explanation, so the extension can never return a
/// credential. Keeping the target in the project from now means its entitlements and App Group wiring are built and
/// reviewed with the app's.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    static let explanation = "Watchword AutoFill is not available yet. Open the Watchword app to copy a password."

    override func viewDidLoad() {
        super.viewDidLoad()
        #if os(iOS)
            let label = UILabel()
            label.text = Self.explanation
            label.numberOfLines = 0
            label.textAlignment = .center
            let cancel = UIButton(
                type: .system, primaryAction: UIAction(title: "Cancel") { [weak self] _ in self?.cancel() })
            let stack = UIStackView(arrangedSubviews: [label, cancel])
            stack.axis = .vertical
            stack.spacing = 16
            stack.translatesAutoresizingMaskIntoConstraints = false
            view.backgroundColor = .systemBackground
            view.addSubview(stack)
            NSLayoutConstraint.activate([
                stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
                stack.leadingAnchor.constraint(equalTo: view.layoutMarginsGuide.leadingAnchor),
                stack.trailingAnchor.constraint(equalTo: view.layoutMarginsGuide.trailingAnchor),
            ])
        #endif
    }

    #if os(macOS)
        override func loadView() {
            let label = NSTextField(wrappingLabelWithString: Self.explanation)
            let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancelPressed))
            let stack = NSStackView(views: [label, cancel])
            stack.orientation = .vertical
            stack.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
            view = stack
        }

        @objc private func cancelPressed() {
            cancel()
        }
    #endif

    /// Never completes a request with a credential: there is no code path to `completeRequest` in this shell.
    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        extensionContext.cancelRequest(
            withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userInteractionRequired.rawValue))
    }

    private func cancel() {
        extensionContext.cancelRequest(
            withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue))
    }
}
