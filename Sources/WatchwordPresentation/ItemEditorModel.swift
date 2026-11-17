import Foundation
import Observation
import WatchwordKit
import WatchwordMatching
import WatchwordModel

/// What the editor asks before it adds one host that resembles a saved site, or that cannot be verified by eye
/// (PRD F11.7; docs/05-anti-phishing.md §3): the site as it resolves, what it resembles, and the item it would be
/// added to. Adding a host is the one way a refusal in the AutoFill extension ever becomes a fill, so the question
/// names both.
public struct HostConfirmationPrompt: Hashable, Sendable, Identifiable {
    public let host: MergeHost
    /// "Add amaz0n.com to “Amazon”?"
    public let title: String
    public let message: String
    public var id: String { host.host }

    public init(_ confirmation: HostConfirmation, scope: ServiceScope, itemTitle: String) {
        host = MergeHost(scope, resembling: confirmation.resembles)
        let name = itemTitle.isEmpty ? "this item" : "“\(itemTitle)”"
        title = "Add \(host.ascii) to \(name)?"
        var parts: [String] = []
        if confirmation.resembles.isEmpty {
            parts.append("\(host.ascii) cannot be told apart by eye from other addresses.")
        } else {
            parts.append(
                "\(host.ascii) looks like \(confirmation.resembles.joined(separator: ", ")) but is a different address."
            )
        }
        parts.append(
            "If you add it, AutoFill will offer \(name) and its password on \(host.ascii) (\(host.reach)). "
                + "Add it only if you are sure the address is \(name)'s own.")
        message = parts.joined(separator: " ")
    }
}

/// The item editor's Websites field and its save (PRD F11.2, F11.7; review finding Z61).
///
/// The session refuses a save that adds a look-alike host the person has not confirmed
/// (`VaultError.hostsNeedConfirmation`); this model turns that refusal into the questions the editor shows, one per
/// host, and saves again naming exactly the hosts that were asked about. It decides nothing: a view that skipped it
/// and called `save` would be refused all the same.
@MainActor
@Observable
public final class ItemEditorModel {
    /// The questions waiting for the person, with the draft they are about. Empty when nothing is waiting.
    public private(set) var prompts: [HostConfirmationPrompt] = []
    public private(set) var isWorking = false
    public var errorMessage: String?

    private let context: ScreenContext
    private var awaiting: Item?

    public init(context: ScreenContext) {
        self.context = context
    }

    public var isAwaitingConfirmation: Bool { !prompts.isEmpty }

    /// The scopes the Websites text stands for. A host the item already has keeps its scope as it is (reach and
    /// exclusions included); a new host is a new scope with the default reach, which the confirmation and the detail
    /// view both state. Order follows the text; a host named twice counts once.
    public nonisolated static func scopes(from text: String, keeping existing: [ServiceScope]) -> [ServiceScope] {
        let held = Dictionary(existing.map { ($0.host, $0) }, uniquingKeysWith: { first, _ in first })
        var seen = Set<String>()
        var scopes: [ServiceScope] = []
        for part in text.split(separator: ",") {
            let host = part.trimmingCharacters(in: .whitespaces)
            guard !host.isEmpty else { continue }
            let scope = held[ServiceScope.canonicalHost(host)] ?? ServiceScope(host: host)
            if seen.insert(scope.host).inserted { scopes.append(scope) }
        }
        return scopes
    }

    /// Saves `draft`. Returns the stored item, or `nil` when the save was refused: with `errorMessage` set, or,
    /// for look-alike hosts, with `prompts` set and nothing written.
    @discardableResult
    public func save(_ draft: Item) async -> Item? {
        await write(draft, confirming: [])
    }

    /// The person answered yes to every prompt: saves the same draft, naming exactly the hosts that were asked about.
    /// A host that needs confirmation and was not asked about (the vault changed meanwhile) is asked about now.
    @discardableResult
    public func confirmAndSave() async -> Item? {
        guard let draft = awaiting else { return nil }
        let confirmed = Set(prompts.map(\.host.host))
        return await write(draft, confirming: confirmed)
    }

    public func cancelConfirmation() {
        prompts = []
        awaiting = nil
    }

    private func write(_ draft: Item, confirming hosts: Set<String>) async -> Item? {
        isWorking = true
        defer { isWorking = false }
        context.recordActivity()
        do {
            let stored = try await context.session.save(draft, confirmingHosts: hosts)
            prompts = []
            awaiting = nil
            errorMessage = nil
            return stored
        } catch VaultError.hostsNeedConfirmation(let needed) {
            let scopes = Dictionary(draft.scopes.map { ($0.host, $0) }, uniquingKeysWith: { first, _ in first })
            prompts = needed.map {
                HostConfirmationPrompt(
                    $0, scope: scopes[$0.host] ?? ServiceScope(host: $0.host), itemTitle: draft.title)
            }
            awaiting = draft
            errorMessage = nil
            return nil
        } catch {
            if case VaultError.locked = error { context.didLock() }
            prompts = []
            awaiting = nil
            errorMessage = ErrorWording.message(for: error)
            return nil
        }
    }
}
