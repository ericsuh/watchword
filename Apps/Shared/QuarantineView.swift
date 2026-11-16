import SwiftUI
import WatchwordPresentation

/// What sync held aside rather than merge (PRD F7.7; review findings U5, Y37, S49): implausible versions, and in
/// shared vaults the writes that do not count. Keeping them costs nothing and needs no action; discarding one is the
/// person's choice, confirmed.
struct QuarantineView: View {
    @State private var model: QuarantineModel
    @State private var discarding: QuarantineRow?

    init(context: ScreenContext) {
        _model = State(initialValue: QuarantineModel(context: context))
    }

    var body: some View {
        Group {
            if !model.isSyncConfigured {
                ContentUnavailableView(
                    "Nothing held aside", systemImage: "tray",
                    description: Text("Sync between your devices is not available in this version yet."))
            } else if model.rows.isEmpty {
                ContentUnavailableView(
                    "Nothing held aside", systemImage: "tray",
                    description: Text("Changes sync could not trust would be kept here for you to review.")
                )
                .accessibilityIdentifier(AccessibilityID.Quarantine.empty)
            } else {
                Form {
                    Section {
                        Text(
                            "These changes arrived from sync and were not applied. Your items show the versions "
                                + "before them. Keep them for as long as you like; discard one only once you are sure "
                                + "you do not need it."
                        )
                        .foregroundStyle(.secondary)
                    }
                    ForEach(sections) { section in
                        Section(section.title) {
                            ForEach(section.rows) { entry in
                                row(entry, index: model.rows.firstIndex(of: entry) ?? 0)
                            }
                        }
                    }
                    ErrorText(message: model.errorMessage)
                }
                .formStyle(.grouped)
                .accessibilityIdentifier(AccessibilityID.Quarantine.list)
            }
        }
        .navigationTitle("Held-Aside Changes")
        .closesSheet()
        .overlay { if model.isWorking { ProgressView() } }
        .task { await model.load() }
        .confirmationDialog(
            "Discard this change?", isPresented: discardingBinding, titleVisibility: .visible
        ) {
            Button("Discard", role: .destructive) {
                if let entry = discarding { Task { await model.discard(entry) } }
            }
            .accessibilityIdentifier(AccessibilityID.Quarantine.discardConfirm)
            Button("Keep", role: .cancel) {}
        } message: {
            Text("It is removed from this device for good. The item stays as it is now.")
        }
    }

    private struct Bucket: Identifiable {
        let title: String
        let rows: [QuarantineRow]
        var id: String { title }
    }

    /// Shared vaults' held-aside writes first: S49 is why this screen exists.
    private var sections: [Bucket] {
        [
            Bucket(title: "Shared vaults", rows: model.rows.filter(\.isSharedVault)),
            Bucket(title: "Your vaults", rows: model.rows.filter { !$0.isSharedVault }),
        ].filter { !$0.rows.isEmpty }
    }

    private var discardingBinding: Binding<Bool> {
        Binding(get: { discarding != nil }, set: { if !$0 { discarding = nil } })
    }

    private func row(_ entry: QuarantineRow, index: Int) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(entry.subject).font(.headline)
            Text("\(entry.vaultName) · \(entry.summary)").font(.caption).foregroundStyle(.secondary)
            Text(entry.explanation).font(.footnote)
            Button("Discard…", role: .destructive) { discarding = entry }
                .buttonStyle(.borderless)
                .disabled(model.isWorking)
                .accessibilityIdentifier(AccessibilityID.Quarantine.discard(index))
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier(AccessibilityID.Quarantine.row(index))
    }
}
