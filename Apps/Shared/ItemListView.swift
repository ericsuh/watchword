import SwiftUI
import WatchwordModel

struct ItemListView: View {
    @Environment(AppModel.self) private var model
    @State private var selection: Item.ID?
    @State private var editing: Item?
    @State private var showingSettings = false
    @State private var search = ""

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                if model.unreadableCount > 0 {
                    Label(
                        "\(model.unreadableCount) item(s) could not be read and were left untouched.",
                        systemImage: "exclamationmark.triangle"
                    )
                    .foregroundStyle(.orange)
                }
                ForEach(filtered) { item in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(item.title.isEmpty ? "Untitled" : item.title)
                            if let host = item.scopes.first?.host {
                                Text(host).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        if item.hasConflicts {
                            Spacer()
                            Image(systemName: "arrow.triangle.branch")
                                .foregroundStyle(.orange)
                                .accessibilityLabel("Changed on more than one device")
                        }
                    }
                    .tag(item.id)
                    .accessibilityIdentifier("items.row.\(item.title)")
                }
            }
            .searchable(text: $search)
            .navigationTitle("Watchword")
            .navigationSplitViewColumnWidth(min: 220, ideal: 260)
            .toolbar {
                ToolbarItem {
                    Button {
                        if let vaultID = model.personalVaultID {
                            editing = Item(vaultID: vaultID, title: "", scopes: [], fields: [])
                        }
                    } label: {
                        Label("New item", systemImage: "plus")
                    }
                    .accessibilityIdentifier("items.add")
                }
                #if os(iOS)
                    vaultItems
                #endif
            }
        } detail: {
            Group {
                if let item = model.items.first(where: { $0.id == selection }) {
                    ItemDetailView(item: item, onEdit: { editing = item })
                } else {
                    ContentUnavailableView("No item selected", systemImage: "key")
                        .accessibilityIdentifier("detail.empty")
                }
            }
            #if os(macOS)
                // The sidebar's share of a macOS toolbar is only as wide as the sidebar, so anything past the first
                // item there lands in the overflow menu. Settings and Lock go on the detail side, which has room.
                .toolbar { vaultItems }
            #endif
        }
        .onChange(of: selection) { model.recordActivity() }
        .onChange(of: search) { model.recordActivity() }
        .onChange(of: editing) { model.recordActivity() }
        .sheet(item: $editing) { item in
            ItemEditView(item: item)
        }
        .sheet(isPresented: $showingSettings) {
            SettingsView()
        }
    }

    @ToolbarContentBuilder private var vaultItems: some ToolbarContent {
        ToolbarItem {
            Button {
                showingSettings = true
            } label: {
                Label("Settings", systemImage: "gearshape")
            }
            .accessibilityIdentifier("items.settings")
        }
        ToolbarItem {
            Button {
                Task { await model.lock() }
            } label: {
                Label("Lock", systemImage: "lock")
            }
            .keyboardShortcut("l", modifiers: [.command, .control])
            .accessibilityIdentifier("items.lock")
        }
    }

    /// Search over title, hosts, usernames, tags and notes (PRD F2.3); secrets are not searched.
    private var filtered: [Item] {
        let query = search.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty else { return model.items }
        return model.items.filter { item in
            let haystack = [item.title, item.notes] + item.scopes.map(\.host) + item.loginNames + Array(item.tags)
            return haystack.contains { $0.localizedCaseInsensitiveContains(query) }
        }
    }
}
