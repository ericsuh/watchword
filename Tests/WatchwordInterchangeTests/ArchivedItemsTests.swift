import Foundation
import Testing
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordInterchange

@Suite("Items from an encrypted Watchword archive")
struct ArchivedItemsTests {
    static let sourceVault = UUID(uuidString: "5005CE00-0000-4000-8000-000000000001")!
    static let passwordID = UUID(uuidString: "F1E1D000-0000-4000-8000-000000000001")!

    static func archivedItem() -> Item {
        let password = Field(id: passwordID, kind: .password, label: "Password", value: "new-secret")
        return Item(
            id: UUID(uuidString: "17E40000-0000-4000-8000-000000000001")!, vaultID: sourceVault, title: "Bank",
            scopes: [
                ServiceScope(host: "bank.example", includeSubdomains: false),
                ServiceScope(host: "login.example.org", excludedHosts: ["ads.login.example.org"]),
            ],
            fields: [
                Field(kind: .username, label: "User", value: "wendy"), password,
                Field(kind: .totp, label: "Code", value: "not a code"),
            ],
            tags: ["money"], notes: "branch: high street", createdAt: Date(timeIntervalSince1970: 1_500_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_600_000_000), version: 42, archived: true,
            history: [
                ItemHistoryEntry(
                    replacedAt: Date(timeIntervalSince1970: 1_550_000_000), version: 7,
                    fields: [Field(id: passwordID, kind: .password, label: "Password", value: "old-secret")])
            ],
            excludedFromSuggestions: true,
            retainedValues: [
                ConflictingValue(
                    stamp: GroupStamp(revision: Revision(version: 9, device: UUID()), seen: VersionVector()),
                    value: .field(Field(id: passwordID, kind: .password, label: "Password", value: "other-secret")))
            ],
            clock: VersionVector([UUID(): 40]))
    }

    static func importing(_ entries: [ArchivedEntry], options: ImportOptions = ImportOptions()) throws -> ImportResult {
        var generator = SeededGenerator(seed: 3)
        return try ArchivedItems.importEntries(entries, into: Fixtures.vaultID, options: options, using: &generator)
    }

    @Test("keeps what a Watchword item holds, under new identities in the caller's vault")
    func fidelity() throws {
        let archived = Self.archivedItem()
        let result = try Self.importing([ArchivedEntry(.item(archived), container: "Personal")])
        let entry = try #require(result.entries.first)
        let item = entry.item
        #expect(result.report.format == .watchwordArchive)
        #expect(item.id != archived.id)
        #expect(item.vaultID == Fixtures.vaultID)
        #expect(entry.reference.container == "Personal")
        #expect(entry.state == .archived)
        #expect(item.title == "Bank" && item.notes == archived.notes && item.tags == ["money"])
        #expect(item.createdAt == archived.createdAt && item.modifiedAt == archived.modifiedAt)
        #expect(item.archived && item.excludedFromSuggestions)
        #expect(item.scopes == archived.scopes)
        // Field IDs are new, and the earlier version's password is still the same field as the current one.
        let password = try #require(item.fields.first { $0.kind == .password })
        #expect(password.id != Self.passwordID)
        #expect(item.history.count == 1)
        #expect(item.history[0].fields.map(\.id) == [password.id])
        #expect(item.history[0].fields[0].value == "old-secret")
        #expect(item.history[0].replacedAt == Date(timeIntervalSince1970: 1_550_000_000))
    }

    @Test("carries no sync metadata, and keeps what sync was holding as concealed fields, reported")
    func syncMetadata() throws {
        let result = try Self.importing([ArchivedEntry(.item(Self.archivedItem()))])
        let item = try #require(result.entries.first?.item)
        #expect(item.version == 0)
        #expect(item.clock.isEmpty && item.revisions.isEmpty && item.conflicts.isEmpty)
        #expect(item.retainedValues.isEmpty && item.noteLines.isEmpty && item.fieldOrder == nil)
        #expect(item.fields.contains { $0.kind == .custom && $0.value == "other-secret" })
        #expect(result.report.warnings.map(\.warning).contains(.unresolvedValuesKept(count: 1)))
    }

    @Test("a one-time password that is not one is kept as a concealed field and reported")
    func oneTimePassword() throws {
        let result = try Self.importing([ArchivedEntry(.item(Self.archivedItem()))])
        let item = try #require(result.entries.first?.item)
        #expect(!item.fields.contains { $0.kind == .totp })
        #expect(item.fields.contains { $0.kind == .custom && $0.value == "not a code" })
        #expect(
            result.report.warnings.contains {
                if case .unusableOneTimePassword = $0.warning { return true }
                return false
            })
    }

    @Test("scopes are checked again: a refused one is kept as a website, and none is widened")
    func scopes() throws {
        var archived = Self.archivedItem()
        archived.scopes = [
            ServiceScope(host: "com"), ServiceScope(host: "*.example.com"),
            ServiceScope(host: "192.0.2.1", includeSubdomains: true), ServiceScope(host: "ok.example"),
        ]
        let result = try Self.importing([ArchivedEntry(.item(archived))])
        let item = try #require(result.entries.first?.item)
        #expect(item.scopes.map(\.host) == ["192.0.2.1", "ok.example"])
        #expect(item.scopes[0].includeSubdomains == false)
        #expect(Set(item.fields.filter { $0.kind == .url }.map(\.value)) == ["com", "*.example.com"])
        let refused = result.report.warnings.compactMap { record -> String? in
            if case .scopeRefused(let url, _) = record.warning { return url }
            return nil
        }
        #expect(Set(refused) == ["com", "*.example.com"])
    }

    @Test("trashed items are skipped unless asked for; repeated and unreadable entries are listed")
    func skips() throws {
        var trashed = Self.archivedItem()
        trashed.id = UUID()
        trashed.trashedAt = Date(timeIntervalSince1970: 1_700_000_000)
        let archived = Self.archivedItem()
        let entries = [
            ArchivedEntry(.item(archived)), ArchivedEntry(.item(archived)), ArchivedEntry(.item(trashed)),
            ArchivedEntry(.unreadable),
        ]
        let result = try Self.importing(entries)
        #expect(result.entries.count == 1)
        #expect(
            result.report.skipped.map(\.reason) == [
                .duplicateIdentifier(archived.id.uuidString), .trashedAtSource, .malformed(path: "entry 4"),
            ])
        let withTrash = try Self.importing(
            [ArchivedEntry(.item(trashed))], options: ImportOptions(includesTrashed: true))
        #expect(withTrash.entries.first?.state == .trashed)
        #expect(withTrash.entries.first?.item.trashedAt == nil)
    }

    static func stamp(_ version: UInt64) -> GroupStamp {
        GroupStamp(revision: Revision(version: version, device: UUID()), seen: VersionVector())
    }

    /// Review finding X4: sync leaves items in the trash that nobody chose to discard. Restored as the source's
    /// trash, the 30-day purge would remove them as the person's; skipped, the report would call them the person's.
    /// They come back live, whatever `includesTrashed` says, and the report says why.
    @Test("an item sync left in the trash comes back live, not as the person's trash")
    func syncTrash() throws {
        var kept = Self.archivedItem()
        kept.archived = false
        kept.trashedAt = Date(timeIntervalSince1970: 1_700_000_000)
        kept.keptAfterDeletion = true
        var overRestore = Self.archivedItem()
        overRestore.id = UUID()
        overRestore.archived = false
        overRestore.trashedAt = Date(timeIntervalSince1970: 1_700_000_000)
        overRestore.conflicts = [.trashedAt: [ConflictingValue(stamp: Self.stamp(3), value: .trashedAt(nil))]]
        #expect(kept.isTrashed && !kept.isTrashedByPerson && !overRestore.isTrashedByPerson)
        for options in [ImportOptions(), ImportOptions(includesTrashed: true)] {
            let result = try Self.importing(
                [ArchivedEntry(.item(kept)), ArchivedEntry(.item(overRestore))], options: options)
            #expect(result.report.skipped.isEmpty)
            #expect(result.entries.map(\.state) == [.active, .active])
            #expect(result.entries.allSatisfy { $0.item.trashedAt == nil && !$0.item.keptAfterDeletion })
            #expect(result.report.warnings.filter { $0.warning == .restoredFromSyncTrash }.count == 2)
        }
    }

    /// Review finding X5: the archive is the backup that keeps everything, so what sync was holding beside a title,
    /// a set of scopes and the tags comes back as values the person can see, not as a count. A host comes back as
    /// text, never as a scope.
    @Test("another title, other hosts and other tags survive a restore as visible values")
    func unresolvedAttributes() throws {
        var archived = Self.archivedItem()
        archived.retainedValues = []
        archived.conflicts = [
            .title: [ConflictingValue(stamp: Self.stamp(5), value: .title("Bank – joint"))],
            .scopes: [
                ConflictingValue(
                    stamp: Self.stamp(6),
                    value: .scopes([ServiceScope(host: "bank.example"), ServiceScope(host: "joint.bank.example")]))
            ],
            .tags: [ConflictingValue(stamp: Self.stamp(7), value: .tags(["money", "shared", "joint"]))],
            .archived: [ConflictingValue(stamp: Self.stamp(8), value: .archived(false))],
        ]
        let result = try Self.importing([ArchivedEntry(.item(archived))])
        let item = try #require(result.entries.first?.item)
        let kept = item.fields.filter { $0.label.hasSuffix("(unresolved value)") }
        #expect(
            Set(kept.map { "\($0.kind.rawValue) \($0.label): \($0.value)" }) == [
                "custom Title (unresolved value): Bank – joint",
                "url Website (unresolved value): joint.bank.example",
                "custom Tags (unresolved value): joint, shared",
            ])
        #expect(kept.allSatisfy { $0.meta[InterchangeMeta.sourceType] == nil })
        #expect(item.title == "Bank" && item.scopes.map(\.host) == ["bank.example", "login.example.org"])
        let warnings = result.report.warnings.map(\.warning)
        #expect(warnings.contains(.unresolvedValuesKept(count: 3)))
        // Only the flag has no text form.
        #expect(warnings.contains(.unresolvedValuesOmitted(count: 1)))
    }

    @Test("timestamps no person could mean are dropped and reported")
    func implausibleDates() throws {
        var archived = Self.archivedItem()
        archived.createdAt = Date(timeIntervalSince1970: -5)
        archived.modifiedAt = Date(timeIntervalSince1970: 1e15)
        let result = try Self.importing([ArchivedEntry(.item(archived))])
        let item = try #require(result.entries.first?.item)
        #expect(item.createdAt == Date(timeIntervalSince1970: 0))
        #expect(result.report.warnings.map(\.warning).contains(.implausibleDate(label: "")))
    }

    @Test("the import's field budget counts history too")
    func budget() throws {
        let archived = Self.archivedItem()
        var generator = SeededGenerator(seed: 1)
        let limits = InterchangeLimits(maximumTotalFields: 8)
        #expect(throws: InterchangeError.self) {
            _ = try ArchivedItems.importEntries(
                [
                    ArchivedEntry(.item(archived)),
                    ArchivedEntry(
                        .item(
                            {
                                var i = archived
                                i.id = UUID()
                                return i
                            }())),
                ],
                into: Fixtures.vaultID, limits: limits, using: &generator)
        }
    }
}
