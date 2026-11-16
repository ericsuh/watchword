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

    private func stamp(_ version: UInt64) -> GroupStamp {
        GroupStamp(
            revision: Revision(
                version: version, device: UUID(uuidString: "D0000000-0000-4000-8000-00000000000\(version)")!),
            seen: VersionVector())
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
