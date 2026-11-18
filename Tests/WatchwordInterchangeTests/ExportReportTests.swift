import Foundation
import Testing
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordInterchange

/// An export may not leave something behind without saying so: the person deletes this app's copy on the strength of
/// the report (PRD F8.4, F7.7).
@Suite("Export reports")
struct ExportReportTests {
    private let onePUXOptions = OnePUX.ExportOptions(
        accountID: UUID(uuidString: "AAAAAAAA-0000-4000-8000-000000000001")!,
        vaultID: UUID(uuidString: "AAAAAAAA-0000-4000-8000-000000000002")!,
        createdAt: Date(timeIntervalSince1970: 1_700_000_000))
    private let cxfOptions = CredentialExchange.ExportOptions(
        exporterRelyingPartyID: "watchword.example", accountID: Fixtures.vaultID,
        timestamp: Date(timeIntervalSince1970: 1_700_000_000))

    private func exports(_ item: Item) -> [(format: String, text: String, warnings: [ExportWarning])] {
        let onePUX = OnePUX.exportDocument([item], options: onePUXOptions)
        let cxf = CredentialExchange.exportDocument([item], options: cxfOptions)
        let csv = PasswordCSV.exportApplePasswords([item])
        return [
            ("1PUX", String(decoding: onePUX.document, as: UTF8.self), onePUX.report.warnings),
            ("CXF", String(decoding: cxf.bytes, as: UTF8.self), cxf.report.warnings),
            ("CSV", String(decoding: csv.bytes, as: UTF8.self), csv.report.warnings),
        ]
    }

    /// Z87 (X4's export half): an item sync left in the trash is nobody's discard. Every exporter left it out with
    /// the person's trash's line, so a person migrating away was told they had thrown away an edit the never-lose-data
    /// rule had kept. Now only the person's own trash is left out; the other is written live, with a line of its own.
    @Test("only the person's own trash is left out; what sync left in the trash is exported live and says so")
    func syncTrash() {
        var kept = Item(
            vaultID: Fixtures.vaultID, title: "Kept by sync", scopes: [ServiceScope(host: "kept.example")],
            fields: [Field(kind: .password, label: "Password", value: "edit-made-elsewhere")])
        kept.trashedAt = Date(timeIntervalSince1970: 1_700_000_000)
        kept.keptAfterDeletion = true
        var discarded = kept
        discarded.id = UUID()
        discarded.title = "Thrown away"
        discarded.keptAfterDeletion = false
        #expect(!kept.isTrashedByPerson && discarded.isTrashedByPerson)
        for export in exports(kept) {
            #expect(export.text.contains("edit-made-elsewhere"), "\(export.format)")
            #expect(export.warnings.contains(.syncTrashExported(itemID: kept.id)), "\(export.format)")
            #expect(!export.warnings.contains(.trashedItemOmitted(itemID: kept.id)), "\(export.format)")
        }
        for export in exports(discarded) {
            #expect(!export.text.contains("edit-made-elsewhere"), "\(export.format)")
            #expect(export.warnings == [.trashedItemOmitted(itemID: discarded.id)], "\(export.format)")
        }
    }

    private func stamp(_ version: UInt64) -> GroupStamp {
        GroupStamp(
            revision: Revision(
                version: version, device: UUID(uuidString: "D0000000-0000-4000-8000-00000000000\(version)")!),
            seen: VersionVector())
    }

    @Test("A website the item is not scoped to is written as a field, never as a sign-in URL, and reported")
    func websiteNotScoped() throws {
        func website(_ url: String) -> Field {
            Field(
                kind: .url, label: "Website", value: url,
                meta: [InterchangeMeta.sourceType: InterchangeMeta.websiteType])
        }
        let item = Item(
            vaultID: Fixtures.vaultID, title: "Example", scopes: [ServiceScope(host: "example.com")],
            fields: [
                Field(kind: .password, label: "Password", value: "pw"),
                website("https://www.example.com/login"), website("https://example.org/login"),
                // No scope can come from this one, so it names no host an importer here would offer the item on:
                // it is written where it was found (PRD F8.1).
                website("ftp://example.com/files"),
                // A link, not a website: it was never among the sign-in URLs.
                Field(kind: .url, label: "Help", value: "https://help.example.net/"),
            ])
        for export in exports(item) {
            #expect(export.warnings.contains(.websiteNotScoped(itemID: item.id, count: 1)), "\(export.format)")
            #expect(export.text.contains("https://example.org/login"), "\(export.format)")
        }
        let onePUX = OnePUX.exportDocument([item], options: onePUXOptions)
        #expect(
            String(decoding: onePUX.document, as: UTF8.self).contains(
                #""urls":[{"label":"website","url":"https://www.example.com/login"},"#
                    + #"{"label":"website","url":"ftp://example.com/files"}]"#))
        let cxf = CredentialExchange.exportDocument([item], options: cxfOptions)
        #expect(
            String(decoding: cxf.bytes, as: UTF8.self).contains(
                #""urls":["https://www.example.com/login","ftp://example.com/files"]"#))
        let csv = try CSVReader.parse(PasswordCSV.exportApplePasswords([item]).bytes)
        #expect(csv.dropFirst().map { $0.fields[1] } == ["https://www.example.com/login", "ftp://example.com/files"])
        #expect(
            csv.dropFirst().allSatisfy {
                $0.fields[4] == "Website: https://example.org/login\nHelp: https://help.example.net/"
            })

        // An item with no scope has no sign-in URL to write, whatever `url` fields it holds.
        var unscoped = item
        unscoped.scopes = []
        unscoped.fields.removeAll { $0.value == "ftp://example.com/files" }
        let rows = try CSVReader.parse(PasswordCSV.exportApplePasswords([unscoped]).bytes)
        #expect(rows.count == 2 && rows[1].fields[1].isEmpty)
        #expect(
            exports(unscoped).allSatisfy { $0.warnings.contains(.websiteNotScoped(itemID: item.id, count: 2)) })
    }

    @Test("Values sync is keeping for the person to choose between are exported, labelled, and reported")
    func unresolvedValues() throws {
        let passwordID = UUID(uuidString: "F0000000-0000-4000-8000-000000000001")!
        let goneID = UUID(uuidString: "F0000000-0000-4000-8000-000000000002")!
        func password(_ value: String) -> ItemGroupValue {
            .field(Field(id: passwordID, kind: .password, label: "Password", value: value))
        }
        let item = Item(
            vaultID: Fixtures.vaultID, title: "Conflicted", scopes: [ServiceScope(host: "example.com")],
            fields: [
                Field(kind: .username, label: "Username", value: "wendy"),
                Field(id: passwordID, kind: .password, label: "Password", value: "shown-password"),
            ],
            conflicts: [
                .field(passwordID): [
                    ConflictingValue(stamp: stamp(2), value: password("CONCURRENT-PASSWORD")),
                    // The value already shown, and a removal, add nothing.
                    ConflictingValue(stamp: stamp(3), value: password("shown-password")),
                    ConflictingValue(stamp: stamp(4), value: .field(nil)),
                ],
                .title: [ConflictingValue(stamp: stamp(2), value: .title("Other title"))],
            ],
            retainedValues: [
                ConflictingValue(stamp: stamp(1), value: password("RETAINED-PASSWORD")),
                ConflictingValue(
                    stamp: stamp(1), value: .field(Field(id: goneID, kind: .pin, label: "", value: "RETAINED-PIN"))),
                ConflictingValue(stamp: stamp(1), value: .scopes([ServiceScope(host: "old.example")])),
            ])
        for export in exports(item) {
            for value in ["CONCURRENT-PASSWORD", "RETAINED-PASSWORD", "RETAINED-PIN"] {
                #expect(export.text.contains(value), "\(export.format) left out \(value)")
            }
            #expect(export.text.contains("Password (unresolved value)"), "\(export.format)")
            #expect(export.text.contains("pin (unresolved value)"), "\(export.format)")
            // A conflicting title or scope is not written as if it were the item's: it is counted.
            #expect(!export.text.contains("Other title"), "\(export.format)")
            #expect(!export.text.contains("old.example"), "\(export.format)")
            #expect(
                export.warnings == [
                    .unresolvedValuesAdded(itemID: item.id, count: 3),
                    .unresolvedValuesOmitted(itemID: item.id, count: 2),
                ], "\(export.format)")
        }

        // In the two structured formats they come back as concealed fields, whatever kind they were.
        var generator = SeededGenerator(seed: 3)
        let exported = OnePUX.exportDocument([item], options: onePUXOptions)
        let again = try OnePUX.importDocument(exported.document, into: Fixtures.vaultID, using: &generator)
        let kept = try #require(again.entries.first).item.fields.filter {
            $0.meta[InterchangeMeta.section] == "Unresolved values"
        }
        #expect(kept.map(\.value) == ["CONCURRENT-PASSWORD", "RETAINED-PASSWORD", "RETAINED-PIN"])
        #expect(kept.allSatisfy { $0.kind == .custom })
    }

    @Test("A scope limited to one host, or with hosts excluded, is reported: no format can say so")
    func scopeRestrictions() {
        let item = Item(
            vaultID: Fixtures.vaultID, title: "Scoped",
            scopes: [
                ServiceScope(host: "accounts.example.com", includeSubdomains: false),
                ServiceScope(host: "example.org", excludedHosts: ["evil.example.org"]),
                ServiceScope(host: "example.net"),
                // An address has no subdomains to include, so nothing is lost.
                ServiceScope(host: "192.168.1.1", includeSubdomains: false),
            ], fields: [Field(kind: .password, label: "Password", value: "pw")])
        for export in exports(item) {
            #expect(
                export.warnings == [
                    .scopeRestrictionOmitted(itemID: item.id, host: "accounts.example.com"),
                    .scopeRestrictionOmitted(itemID: item.id, host: "example.org"),
                ], "\(export.format)")
        }
    }

    @Test("History, the archived mark, tags and recovery-code marks are reported where a format leaves them out")
    func whatFormatsCannotHold() {
        var codes = Field(kind: .recoveryCodes, label: "Recovery codes", value: "aaaa\nbbbb")
        codes.markRecoveryCode(at: 0, used: true)
        func entry(_ fields: [Field]) -> ItemHistoryEntry {
            ItemHistoryEntry(replacedAt: Date(timeIntervalSince1970: 1_600_000_000), version: 1, fields: fields)
        }
        let item = Item(
            vaultID: Fixtures.vaultID, title: "Old", scopes: [ServiceScope(host: "example.com")],
            fields: [Field(kind: .password, label: "Password", value: "pw"), codes], tags: ["work"],
            archived: true,
            history: [
                entry([Field(kind: .password, label: "Password", value: "earlier")]),
                entry([
                    Field(kind: .password, label: "Password", value: "earliest"),
                    Field(kind: .pin, label: "PIN", value: "0000"),
                ]),
            ])
        let all = exports(item)
        let codeMarks = ExportWarning.fieldDetailOmitted(itemID: item.id, label: "Recovery codes")
        // 1PUX has an archived state, tags and earlier passwords; the earlier PIN has nowhere to go.
        #expect(all[0].warnings == [codeMarks, .historyOmitted(itemID: item.id, entries: 1)])
        #expect(all[0].text.contains(#""state":"archived""#))
        #expect(all[0].text.contains(#"{"value":"earlier","time":1600000000}"#))
        #expect(
            all[1].warnings == [
                codeMarks, .archivedStateOmitted(itemID: item.id), .historyOmitted(itemID: item.id, entries: 2),
            ])
        #expect(
            all[2].warnings == [
                codeMarks, .archivedStateOmitted(itemID: item.id), .tagsOmitted(itemID: item.id),
                .historyOmitted(itemID: item.id, entries: 2), .fieldsMovedToNotes(itemID: item.id, count: 1),
            ])
        // The fields this module's own imports annotate are not "detail left out".
        let annotated = Item(
            vaultID: Fixtures.vaultID, title: "Plain", scopes: [],
            fields: [
                Field(
                    kind: .custom, label: "PIN", value: "1",
                    meta: [
                        InterchangeMeta.section: "s", InterchangeMeta.sourceType: "concealed",
                        InterchangeMeta.sourceID: "pin", InterchangeMeta.category: "003",
                    ])
            ])
        #expect(OnePUX.exportDocument([annotated], options: onePUXOptions).report.warnings.isEmpty)
    }

    @Test("The export guides tell the person to read the report")
    func guides() {
        for id in [InterchangeGuide.ID.importInto1Password, .importIntoApplePasswords] {
            for route in InterchangeGuide.guide(id).routes {
                #expect(route.caveats.map(\.kind).contains(.exportReport), "\(route.id)")
            }
        }
        for id in [InterchangeGuide.ID.exportFrom1Password, .exportFromApplePasswords] {
            for route in InterchangeGuide.guide(id).routes {
                #expect(!route.caveats.map(\.kind).contains(.exportReport), "\(route.id)")
            }
        }
    }
}
