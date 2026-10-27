import SwiftUI
import WatchwordModel
import WatchwordSync

/// Values written on different devices at the same time, kept side by side until the person chooses (PRD F7.6). The
/// value the item shows is choice 0; each conflicting value follows. Choosing one discards the others (F7.7), so each
/// choice is an explicit button, and secrets stay hidden until shown.
struct ConflictSection: View {
    @Environment(AppModel.self) private var model
    let item: Item
    @State private var revealed: Set<ItemGroup> = []

    var body: some View {
        let conflicts = ItemMerge.conflicts(of: item).sorted { $0.key < $1.key }
        if !conflicts.isEmpty {
            Section {
                ForEach(conflicts, id: \.key) { group, values in
                    let name = Self.name(of: group, in: item, conflicts: values)
                    let choices = [ItemMerge.currentValue(of: group, in: item)].compactMap { $0 } + values.map(\.value)
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text(name).font(.headline)
                            Spacer()
                            if choices.contains(where: Self.isSecret) {
                                Button(revealed.contains(group) ? "Hide" : "Show") {
                                    model.recordActivity()
                                    if revealed.contains(group) {
                                        revealed.remove(group)
                                    } else {
                                        revealed.insert(group)
                                    }
                                }
                                .buttonStyle(.borderless)
                            }
                        }
                        ForEach(Array(choices.enumerated()), id: \.offset) { index, value in
                            HStack {
                                Text(Self.describe(value, revealed: revealed.contains(group)))
                                    .textSelection(.disabled)
                                    .accessibilityIdentifier("conflict.\(name).\(index).value")
                                Spacer()
                                Button(index == 0 ? "Keep shown" : "Keep this") {
                                    Task { await model.resolveConflict(item, group: group, choosing: value) }
                                }
                                .buttonStyle(.borderless)
                                .disabled(model.isWorking)
                                .accessibilityIdentifier("conflict.\(name).\(index)")
                            }
                        }
                    }
                }
            } header: {
                Label("Changed on more than one device", systemImage: "arrow.triangle.branch")
                    .accessibilityIdentifier("detail.conflicts")
            } footer: {
                Text("Choose the version to keep. The others are discarded.")
            }
        }
    }

    static func name(of group: ItemGroup, in item: Item, conflicts: [ConflictingValue]) -> String {
        if let id = group.fieldID {
            let fields =
                item.fields
                + conflicts.compactMap { conflict -> Field? in
                    if case .field(let field?) = conflict.value { return field }
                    return nil
                }
            return fields.first { $0.id == id }?.label ?? "Field"
        }
        switch group {
        case .title: return "Title"
        case .scopes: return "Websites"
        case .tags: return "Tags"
        case .archived: return "Archive"
        case .trashedAt: return "Trash"
        case .keptAfterDeletion: return "Kept after deletion"
        case .excludedFromSuggestions: return "AutoFill suggestions"
        case .fieldOrder: return "Field order"
        default: return group.rawValue
        }
    }

    static func isSecret(_ value: ItemGroupValue) -> Bool {
        if case .field(let field?) = value { return field.kind.isSecret }
        return false
    }

    static func describe(_ value: ItemGroupValue, revealed: Bool) -> String {
        switch value {
        case .title(let title): return title.isEmpty ? "Untitled" : title
        case .scopes(let scopes): return scopes.isEmpty ? "No websites" : scopes.map(\.host).joined(separator: ", ")
        case .tags(let tags): return tags.isEmpty ? "No tags" : tags.sorted().joined(separator: ", ")
        case .archived(let archived): return archived ? "Archived" : "Not archived"
        case .trashedAt(let date): return date == nil ? "Not in the Trash" : "In the Trash"
        case .keptAfterDeletion(let kept): return kept ? "Kept after a deletion elsewhere" : "Not kept"
        case .excludedFromSuggestions(let excluded): return excluded ? "Hidden from suggestions" : "Suggested"
        case .fieldOrder: return "A different field order"
        case .field(nil): return "Removed"
        case .field(let field?):
            return field.kind.isSecret && !revealed ? "••••••••" : field.value
        }
    }
}
