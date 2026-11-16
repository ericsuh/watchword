import SwiftUI
import WatchwordPresentation

/// The security report (PRD F9.1–F9.3): breached passwords, with the source of a breach another device of the vault
/// reported (`ItemHygiene.breachSource`), reused and weak passwords and the other suggestions. The breach scan is
/// driven from here (`VaultSession.runHygieneStep()`); nothing is sent while the vault is locked. No password, or any
/// part of one, is shown.
struct HygieneReportView: View {
    @State private var model: HygieneModel

    init(context: ScreenContext, breachChecksAvailable: Bool) {
        _model = State(initialValue: HygieneModel(context: context, breachChecksAvailable: breachChecksAvailable))
    }

    var body: some View {
        Group {
            if !model.isAvailable {
                ContentUnavailableView(
                    "Security report unavailable", systemImage: "checkmark.shield",
                    description: Text("The security report is not available in this version yet.")
                )
                .accessibilityIdentifier(AccessibilityID.Hygiene.unavailable)
            } else {
                Form {
                    summary
                    ForEach(model.sections) { section in
                        Section {
                            ForEach(section.rows) { row in
                                rowView(row, kind: section.kind.rawValue)
                            }
                        } header: {
                            Text(section.title).accessibilityIdentifier(AccessibilityID.Hygiene.section(section.id))
                        } footer: {
                            Text(section.footer)
                        }
                    }
                    ErrorText(message: model.errorMessage)
                }
                .formStyle(.grouped)
                .accessibilityIdentifier(AccessibilityID.Hygiene.list)
            }
        }
        .navigationTitle("Security Report")
        .closesSheet()
        .task { await model.load() }
    }

    private var summary: some View {
        Section {
            if model.itemsNeedingAttention == 0 {
                Label("Nothing needs your attention.", systemImage: "checkmark.shield")
            } else {
                Label(
                    "\(model.itemsNeedingAttention) item(s) need your attention.", systemImage: "exclamationmark.shield"
                )
                .foregroundStyle(.orange)
            }
            if model.breachChecksAvailable {
                if model.itemsAwaitingBreachCheck > 0 {
                    Text("\(model.itemsAwaitingBreachCheck) item(s) not yet checked against known breaches.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Button(model.isScanning ? "Checking…" : "Check Now") { Task { await model.checkNow() } }
                    .disabled(model.isScanning || model.isWorking)
                    .accessibilityIdentifier(AccessibilityID.Hygiene.checkNow)
                if let status = model.scanStatus {
                    Text(status).font(.footnote).foregroundStyle(.secondary)
                        .accessibilityIdentifier(AccessibilityID.Hygiene.status)
                }
                if let next = model.nextCheckAt {
                    Text("Next check after \(next.formatted(date: .omitted, time: .shortened)).")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Text(
                    "Checks send the first five characters of each password's SHA-1 hash to Have I Been Pwned, never "
                        + "the password."
                )
                .font(.footnote).foregroundStyle(.secondary)
            } else {
                Text("Checking passwords against known breaches is not available in this version yet.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
    }

    private func rowView(_ row: HygieneRow, kind: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(row.title).font(.headline)
            Text(row.summary).font(.subheadline)
            Text(row.explanation).font(.footnote).foregroundStyle(.secondary)
            if let source = row.source {
                Label(source, systemImage: "arrow.triangle.2.circlepath").font(.caption).foregroundStyle(.orange)
            }
            if !row.sharedWith.isEmpty {
                Text("Also used by \(row.sharedWith.joined(separator: ", ")).").font(.caption).foregroundStyle(
                    .secondary)
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier(AccessibilityID.Hygiene.row(kind, row.title))
    }
}
