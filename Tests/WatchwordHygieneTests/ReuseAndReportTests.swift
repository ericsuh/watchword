import Foundation
import SecureMemory
import Testing
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordHygiene

enum HygieneFixtures {
    static let vault = UUID(uuidString: "11111111-0000-0000-0000-000000000000")!
    static let now = Date(timeIntervalSince1970: 1_800_000_000)
    static let year: TimeInterval = 365 * 24 * 60 * 60

    static func id(_ number: Int) -> UUID {
        ScanScheduleTests.id(number)
    }

    static func fieldID(_ item: Int, _ field: Int = 1) -> UUID {
        func padded(_ number: Int, _ width: Int) -> String {
            String(repeating: "0", count: width - String(number).count) + String(number)
        }
        return UUID(uuidString: "F0000000-0000-0000-\(padded(field, 4))-\(padded(item, 12))")!
    }

    /// The default password: strong, and different for every item, so a test opts in to reuse and weakness.
    static let unique = "\u{0}unique"

    static func strongPassword(_ number: Int) -> String {
        "Zr8@Wn4&x7#Vq9!mLp2$-\(number)"
    }

    static func reuseKey() throws -> ReuseKey {
        try ReuseKey(SecureBytes(copying: (0..<32).map { UInt8($0) }))
    }

    static func item(
        _ number: Int, title: String? = nil, password: String? = unique, host: String = "example.com",
        extra: [Field] = [], version: UInt64 = 1, createdAt: Date = now.addingTimeInterval(-86400),
        history: [ItemHistoryEntry] = [], trashedAt: Date? = nil, archived: Bool = false
    ) -> Item {
        var fields = [Field(id: fieldID(number, 0), kind: .username, label: "Username", value: "user\(number)")]
        if let password {
            let value = password == unique ? strongPassword(number) : password
            fields.append(Field(id: fieldID(number), kind: .password, label: "Password", value: value))
        }
        fields.append(contentsOf: extra)
        return Item(
            id: id(number), vaultID: vault, title: title ?? "Item \(number)", scopes: [ServiceScope(host: host)],
            fields: fields, createdAt: createdAt, modifiedAt: createdAt, version: version, archived: archived,
            trashedAt: trashedAt, history: history)
    }

    static func analyzer(_ policy: HygienePolicy = HygienePolicy()) -> ItemAnalyzer {
        ItemAnalyzer(estimator: StrengthEstimator(referenceYear: 2026), policy: policy)
    }

    static func report(
        _ items: [Item], ledger: ScanLedger = ScanLedger(), policy: HygienePolicy = HygienePolicy()
    ) throws -> HygieneReport {
        let key = try reuseKey()
        let analyses = items.map { analyzer(policy).analyse($0, reuseKey: key) }
        return HygieneReport.make(analyses: analyses, ledger: ledger, now: now, policy: policy)
    }

    static func scanned(_ item: Item, _ result: PwnedPasswordResult) -> ScanLedger.Entry {
        var results: [UUID: PwnedPasswordResult] = [:]
        for field in ItemAnalyzer.passwordFields(of: item) { results[field.id] = result }
        return ScanLedger.Entry(itemVersion: item.version, scannedAt: now.addingTimeInterval(-3600), results: results)
    }
}

@Suite("Password reuse")
struct ReuseIndexTests {
    @Test(
        "a reuse token is HMAC-SHA-256 of the password under the key, as Python's hmac computes it",
        arguments: zip(
            ["password", "pässwörd", "x7#Vq9!mLp2$Zr8@Wn4&"],
            [
                "efbcd5f31747b7a0b2be6b463f6040268b8455b05d3f19b1cbc89a634bd4973d",
                "c2d786a6125fad443fe25e59a477ece9ba1ba167b354453317f7ebf36c216f7a",
                "8c2e5be208ec70c3bb56f23ffc54fbde5c0f6a7af7689c803520ba8588ced826",
            ]))
    func knownAnswer(_ password: String, _ expected: String) throws {
        // key = bytes(range(32))
        #expect(try HygieneFixtures.reuseKey().token(forUTF8Of: password).bytes.hex == expected)
    }

    @Test("a different key gives unrelated tokens")
    func keyed() throws {
        let other = try ReuseKey(SecureBytes(copying: [UInt8](repeating: 9, count: 32)))
        #expect(
            try HygieneFixtures.reuseKey().token(forUTF8Of: "password") != other.token(forUTF8Of: "password"))
    }

    @Test("a key shorter than 32 bytes is refused")
    func shortKey() {
        #expect(throws: ReuseKeyError.tooShort) { try ReuseKey(SecureBytes(copying: [UInt8](repeating: 1, count: 31))) }
        #expect(throws: ReuseKeyError.tooShort) { try ReuseKey(SecureBytes(count: 0)) }
    }

    @Test("items sharing a password are grouped; an item alone is not")
    func groups() throws {
        let key = try HygieneFixtures.reuseKey()
        let shared = key.token(forUTF8Of: "shared-secret-1")
        var index = ReuseIndex()
        index.set([shared], for: HygieneFixtures.id(3))
        index.set([shared, key.token(forUTF8Of: "second-password-in-item")], for: HygieneFixtures.id(1))
        index.set([key.token(forUTF8Of: "another-Unique_9")], for: HygieneFixtures.id(2))
        #expect(index.items(sharing: shared, besides: HygieneFixtures.id(1)) == [HygieneFixtures.id(3)])
        #expect(index.items(sharing: shared) == [HygieneFixtures.id(1), HygieneFixtures.id(3)])
        #expect(index.reusedGroups == [[HygieneFixtures.id(1), HygieneFixtures.id(3)]])

        // Changing one item's password dissolves the group.
        index.set([key.token(forUTF8Of: "V3ry-Un1que+Phrase")], for: HygieneFixtures.id(3))
        #expect(index.reusedGroups.isEmpty)
        index.remove(HygieneFixtures.id(1))
        index.remove(HygieneFixtures.id(2))
        index.remove(HygieneFixtures.id(3))
        #expect(index.isEmpty)
    }

    @Test("the same password twice in one item is not reuse")
    func withinOneItem() throws {
        let item = HygieneFixtures.item(
            1, password: "shared-secret-1",
            extra: [Field(id: HygieneFixtures.fieldID(1, 2), kind: .password, label: "Old", value: "shared-secret-1")])
        let report = try HygieneFixtures.report([item])
        #expect(report.totals.itemsByKind[.reusedPassword] == nil)
    }

    @Test("tokens and the index print nothing")
    func redaction() throws {
        let key = try HygieneFixtures.reuseKey()
        let token = key.token(forUTF8Of: "password")
        var index = ReuseIndex()
        index.set([token], for: HygieneFixtures.id(1))
        let printed = "\(token) \(String(reflecting: token)) \(index) \(String(reflecting: index))"
        #expect(!printed.contains("efbc"))
        #expect(!printed.lowercased().contains(token.bytes.hex.prefix(8)))
        #expect(Mirror(reflecting: token).children.isEmpty)
        #expect(Mirror(reflecting: index).children.isEmpty)
    }
}

@Suite("Item checks")
struct ItemAnalysisTests {
    @Test("a password has been current since the item was created when history shows no other value")
    func ageFromCreation() throws {
        let created = HygieneFixtures.now.addingTimeInterval(-4 * HygieneFixtures.year)
        let item = HygieneFixtures.item(1, createdAt: created)
        let analysis = HygieneFixtures.analyzer().analyse(item, reuseKey: try HygieneFixtures.reuseKey())
        #expect(analysis.passwords.first?.currentSince == created)
    }

    @Test("a password has been current since the last time a different value was replaced")
    func ageFromHistory() throws {
        let created = HygieneFixtures.now.addingTimeInterval(-10 * HygieneFixtures.year)
        let changed = HygieneFixtures.now.addingTimeInterval(-2 * HygieneFixtures.year)
        let later = HygieneFixtures.now.addingTimeInterval(-1 * HygieneFixtures.year)
        func fields(_ password: String, user: String = "user1") -> [Field] {
            [
                Field(id: HygieneFixtures.fieldID(1, 0), kind: .username, label: "Username", value: user),
                Field(id: HygieneFixtures.fieldID(1), kind: .password, label: "Password", value: password),
            ]
        }
        let current = HygieneFixtures.strongPassword(1)
        // Newest first: a username edit a year ago (same password), the password change two years ago, and an
        // older state that already had today's password (it was changed away and back).
        let history = [
            ItemHistoryEntry(replacedAt: later, version: 3, fields: fields(current, user: "old-name")),
            ItemHistoryEntry(replacedAt: changed, version: 2, fields: fields("hunter2")),
            ItemHistoryEntry(replacedAt: created.addingTimeInterval(86400), version: 1, fields: fields(current)),
        ]
        let key = try HygieneFixtures.reuseKey()
        let item = HygieneFixtures.item(1, createdAt: created, history: history)
        #expect(HygieneFixtures.analyzer().analyse(item, reuseKey: key).passwords.first?.currentSince == changed)
        // The answer does not depend on the order a merge left the history in.
        let shuffled = HygieneFixtures.item(1, createdAt: created, history: history.reversed())
        #expect(HygieneFixtures.analyzer().analyse(shuffled, reuseKey: key).passwords.first?.currentSince == changed)
    }

    @Test("a field added after creation has been current since it was added")
    func ageOfAddedField() throws {
        let created = HygieneFixtures.now.addingTimeInterval(-5 * HygieneFixtures.year)
        let added = HygieneFixtures.now.addingTimeInterval(-86400)
        let before = [Field(id: HygieneFixtures.fieldID(1, 0), kind: .username, label: "Username", value: "user1")]
        let item = HygieneFixtures.item(
            1, createdAt: created, history: [ItemHistoryEntry(replacedAt: added, version: 1, fields: before)])
        let analysis = HygieneFixtures.analyzer().analyse(item, reuseKey: try HygieneFixtures.reuseKey())
        #expect(analysis.passwords.first?.currentSince == added)
    }

    @Test("an item without timestamps has no known age")
    func ageUnknown() throws {
        let item = HygieneFixtures.item(1, createdAt: Date(timeIntervalSince1970: 0))
        let analysis = HygieneFixtures.analyzer().analyse(item, reuseKey: try HygieneFixtures.reuseKey())
        #expect(analysis.passwords.first?.currentSince == nil)
        #expect(try HygieneFixtures.report([item]).totals.itemsByKind[.oldPassword] == nil)
    }

    @Test(
        "plain http addresses are insecure",
        arguments: [
            "http://example.com", "HTTP://Example.com/login", "  http://example.com/a?b#c\n", "http://192.168.1.1/",
            "http://user:pw@example.com:8080/", "http://[2001:db8::1]/", "http://localhost.example.com",
            "http://127.example.com",
        ])
    func insecure(_ url: String) {
        #expect(ItemAnalyzer.isInsecureURL(url))
    }

    @Test(
        "https, loopback and things that are not web addresses are not flagged",
        arguments: [
            "https://example.com", "example.com", "", "http://", "http:///path", "ftp://example.com",
            "http://localhost", "http://localhost:8080/admin", "http://app.localhost/", "http://127.0.0.1:3000",
            "http://[::1]:8080/", "httpx://example.com", "see http://example.com",
        ])
    func notInsecure(_ url: String) {
        #expect(!ItemAnalyzer.isInsecureURL(url))
    }

    @Test("empty passwords are not passwords, and other secret kinds are not checked as passwords")
    func whatCounts() throws {
        let item = HygieneFixtures.item(
            1, password: "",
            extra: [
                Field(kind: .pin, label: "PIN", value: "1234"),
                Field(kind: .apiKey, label: "Key", value: "password"),
                Field(kind: .securityQuestion, label: "Pet", value: "password"),
            ])
        let analysis = HygieneFixtures.analyzer().analyse(item, reuseKey: try HygieneFixtures.reuseKey())
        #expect(analysis.passwords.isEmpty)
        #expect(ItemAnalyzer.passwordFields(of: item).isEmpty)
    }

    @Test("an analysis says how many passwords it left out, and prints nothing about any of them")
    func passwordsNotAnalysed() throws {
        let fields = (1...20).map {
            Field(id: HygieneFixtures.fieldID(1, $0), kind: .password, label: "P", value: "dragon")
        }
        let empty = Field(id: HygieneFixtures.fieldID(1, 99), kind: .password, label: "Empty", value: "")
        let item = HygieneFixtures.item(1, title: "Secret title", password: nil, extra: fields + [empty])
        let analysis = HygieneFixtures.analyzer().analyse(item, reuseKey: try HygieneFixtures.reuseKey())
        #expect(analysis.passwords.count == ItemAnalyzer.maximumPasswordsPerItem)
        #expect(analysis.passwordsNotAnalysed == 4)
        #expect(
            HygieneFixtures.analyzer().analyse(HygieneFixtures.item(2), reuseKey: try HygieneFixtures.reuseKey())
                .passwordsNotAnalysed == 0)
        var printed = "\(analysis) \(String(reflecting: analysis)) \(analysis.passwords[0])"
        dump(analysis, to: &printed)
        dump(analysis.passwords[0], to: &printed)
        #expect(!printed.contains("Secret title"))
        #expect(!printed.contains("commonPassword"))
        #expect(!printed.contains("Log10"))
        #expect(printed.contains(item.id.uuidString))
    }

    @Test("an item with very many password fields is analysed up to the cap")
    func cappedFields() throws {
        let extra = (2..<500).map {
            Field(id: HygieneFixtures.fieldID(1, $0), kind: .password, label: "P\($0)", value: "unique-\($0)-Zq7!")
        }
        let item = HygieneFixtures.item(1, extra: extra)
        let analysis = HygieneFixtures.analyzer().analyse(item, reuseKey: try HygieneFixtures.reuseKey())
        #expect(analysis.passwords.count == ItemAnalyzer.maximumPasswordsPerItem)
    }

    @Test("the embedded site directory matches by whole labels, nearest entry first")
    func siteDirectory() {
        let directory = EmbeddedSiteDirectory()
        #expect(directory.capabilities(ofHost: "github.com") == [.oneTimeCodes, .passkeys])
        #expect(directory.capabilities(ofHost: "GIST.GitHub.com.") == [.oneTimeCodes, .passkeys])
        #expect(
            directory.capabilities(ofHost: "signin.aws.amazon.com") == EmbeddedSiteDirectory.table["aws.amazon.com"])
        #expect(directory.capabilities(ofHost: "app.slack.com") == [.oneTimeCodes])
        #expect(directory.capabilities(ofHost: "www.amazon.com").contains(.passkeys))
        for unknown in ["notgithub.com", "github.com.evil.example", "com", "", ".", "example.invalid"] {
            #expect(directory.capabilities(ofHost: unknown).isEmpty)
        }
        #expect(directory.capabilities(ofHost: String(repeating: "a.", count: 5000) + "github.com").isEmpty)
        #expect(NoSiteDirectory().capabilities(ofHost: "github.com").isEmpty)
        #expect(EmbeddedSiteDirectory.table.count > 200)
        #expect(EmbeddedSiteDirectory.table.keys.allSatisfy { $0 == $0.lowercased() && $0.contains(".") })
    }
}

@Suite("Hygiene report")
struct HygieneReportTests {
    @Test("a strong, unique, checked password with a passkey has no findings")
    func clean() throws {
        let item = HygieneFixtures.item(1, extra: [Field(kind: .passkey, label: "Passkey", value: "{}")])
        let ledger = ScanLedger(entries: [item.id: HygieneFixtures.scanned(item, .notFound)])
        let report = try HygieneFixtures.report([item], ledger: ledger)
        #expect(report.items.count == 1)
        #expect(report.items[0].findings.isEmpty)
        #expect(report.items[0].badges.isEmpty)
        #expect(report.items[0].severity == nil)
        #expect(report.items[0].breachStatus == .clear(checkedAt: HygieneFixtures.now.addingTimeInterval(-3600)))
        #expect(report.itemsNeedingAttention.isEmpty)
        #expect(report.totals.itemsNeedingAttention == 0)
        #expect(report.totals.itemsAwaitingBreachCheck == 0)
    }

    @Test("a breached password is critical, explained, and counted")
    func breached() throws {
        let item = HygieneFixtures.item(1)
        let ledger = ScanLedger(entries: [item.id: HygieneFixtures.scanned(item, .found(occurrences: 1234))])
        let report = try HygieneFixtures.report([item], ledger: ledger)
        let finding = try #require(report.items[0].findings.first)
        #expect(finding.kind == .breachedPassword)
        #expect(finding.severity == .critical)
        #expect(finding.fieldID == HygieneFixtures.fieldID(1))
        #expect(finding.detail == .breached(occurrences: 1234))
        #expect(finding.explanation.contains("1234 times"))
        #expect(report.items[0].breachStatus == .breached(checkedAt: HygieneFixtures.now.addingTimeInterval(-3600)))
        #expect(report.items[0].badges.first == HygieneBadge(kind: .breachedPassword, severity: .critical))
        #expect(report.totals.itemsByKind[.breachedPassword] == 1)
        #expect(report.totals.itemsBySeverity[.critical] == 1)
    }

    @Test("a breach result for an earlier version of the item does not count")
    func staleResult() throws {
        let item = HygieneFixtures.item(1, version: 5)
        let stale = ScanLedger.Entry(
            itemVersion: 4, scannedAt: HygieneFixtures.now,
            results: [HygieneFixtures.fieldID(1): .found(occurrences: 9)])
        let report = try HygieneFixtures.report([item], ledger: ScanLedger(entries: [item.id: stale]))
        #expect(report.items[0].breachStatus == .notChecked)
        #expect(report.totals.itemsByKind[.breachedPassword] == nil)
        #expect(report.totals.itemsAwaitingBreachCheck == 1)
        #expect(report.totals.oldestBreachCheck == nil)
    }

    @Test("reused passwords are flagged on every item that shares them, naming the others")
    func reused() throws {
        let items = [
            HygieneFixtures.item(1, password: "shared-secret-1"), HygieneFixtures.item(2, password: "shared-secret-1"),
            HygieneFixtures.item(3, password: "shared-secret-1"), HygieneFixtures.item(4, password: "another-Unique_9"),
        ]
        let report = try HygieneFixtures.report(items)
        #expect(report.totals.itemsByKind[.reusedPassword] == 3)
        let first = try #require(report.item(HygieneFixtures.id(1))?.findings.first { $0.kind == .reusedPassword })
        #expect(first.severity == .high)
        #expect(first.detail == .reused(sharedWith: [HygieneFixtures.id(2), HygieneFixtures.id(3)]))
        #expect(first.explanation.hasPrefix("2 other items"))
        #expect(report.item(HygieneFixtures.id(4))?.findings.contains { $0.kind == .reusedPassword } == false)
    }

    @Test("weak passwords are high, fair ones medium, and the explanation is the estimator's")
    func weak() throws {
        let report = try HygieneFixtures.report([
            HygieneFixtures.item(1, password: "password"), HygieneFixtures.item(2, password: "7410852963"),
        ])
        let weak = try #require(report.item(HygieneFixtures.id(1))?.findings.first { $0.kind == .weakPassword })
        #expect(weak.severity == .high)
        #expect(weak.summary == "Weak password")
        #expect(weak.detail == .weak(score: .veryWeak, weakness: .commonPassword))
        #expect(weak.explanation.hasPrefix(StrengthWeakness.commonPassword.explanation))
        let fair = try #require(report.item(HygieneFixtures.id(2))?.findings.first { $0.kind == .weakPassword })
        #expect(fair.severity == .medium)
        #expect(!weak.explanation.contains("password\""))
    }

    @Test("unchecked passwords beyond the cap make an item incomplete, not clear; a breach among the rest shows")
    func incomplete() throws {
        let extra = (2...18).map {
            Field(
                id: HygieneFixtures.fieldID(1, $0), kind: .password, label: "P",
                value: HygieneFixtures.strongPassword(200 + $0))
        }
        let item = HygieneFixtures.item(1, extra: extra)
        var ledger = ScanLedger(entries: [item.id: HygieneFixtures.scanned(item, .notFound)])
        var hygiene = try #require(try HygieneFixtures.report([item], ledger: ledger).item(item.id))
        #expect(hygiene.breachStatus == .incomplete(checkedAt: HygieneFixtures.now.addingTimeInterval(-3600)))
        let finding = try #require(hygiene.findings.first { $0.kind == .tooManyPasswords })
        #expect(finding.detail == .notAnalysed(passwords: 2))
        #expect(finding.explanation.contains("2 more passwords"))
        #expect(hygiene.severity == .low)

        // Not yet checked at all: still "not checked", which is the more urgent thing to say.
        hygiene = try #require(try HygieneFixtures.report([item]).item(item.id))
        #expect(hygiene.breachStatus == .notChecked)
        // One of the sixteen that were checked is breached: breached.
        ledger.entries[item.id]?.results[HygieneFixtures.fieldID(1, 3)] = .found(occurrences: 4)
        hygiene = try #require(try HygieneFixtures.report([item], ledger: ledger).item(item.id))
        #expect(hygiene.breachStatus == .breached(checkedAt: HygieneFixtures.now.addingTimeInterval(-3600)))
    }

    @Test("an old password is information, not an alarm")
    func old() throws {
        let item = HygieneFixtures.item(
            1, createdAt: HygieneFixtures.now.addingTimeInterval(-5.5 * HygieneFixtures.year))
        let report = try HygieneFixtures.report([item])
        let finding = try #require(report.items[0].findings.first { $0.kind == .oldPassword })
        #expect(finding.severity == .info)
        #expect(finding.explanation.contains("more than 5 years"))
        #expect(!report.items[0].badges.contains { $0.kind == .oldPassword })
        let off = try HygieneFixtures.report([item], policy: HygienePolicy(oldPasswordAge: nil))
        #expect(off.totals.itemsByKind[.oldPassword] == nil)
    }

    @Test("an http address is a low finding on its field")
    func insecureURL() throws {
        let field = Field(id: HygieneFixtures.fieldID(1, 7), kind: .url, label: "Website", value: "http://example.com")
        let report = try HygieneFixtures.report([HygieneFixtures.item(1, extra: [field])])
        let finding = try #require(report.items[0].findings.first { $0.kind == .insecureURL })
        #expect(finding.severity == .low)
        #expect(finding.fieldID == field.id)
    }

    @Test("without a site directory, a password-only item is noted and nothing is claimed about its site")
    func passwordOnlyByDefault() throws {
        let report = try HygieneFixtures.report([HygieneFixtures.item(1, host: "github.com")])
        let kinds = report.items[0].findings.map(\.kind)
        #expect(kinds.contains(.passwordOnly))
        #expect(!kinds.contains(.twoFactorAvailable))
        #expect(!kinds.contains(.passkeyAvailable))
        #expect(report.items[0].findings.first { $0.kind == .passwordOnly }?.severity == .info)
        #expect(report.itemsNeedingAttention.isEmpty)
    }

    @Test("with the directory, missing two-step verification and available passkeys are flagged where known")
    func directoryFindings() throws {
        let policy = HygienePolicy(siteDirectory: EmbeddedSiteDirectory())
        let totp = Field(kind: .totp, label: "Code", value: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")
        let passkey = Field(kind: .passkey, label: "Passkey", value: "{}")
        let report = try HygieneFixtures.report(
            [
                HygieneFixtures.item(1, host: "github.com"),
                HygieneFixtures.item(2, host: "github.com", extra: [totp]),
                HygieneFixtures.item(3, host: "github.com", extra: [passkey]),
                HygieneFixtures.item(4, host: "slack.com"),
                HygieneFixtures.item(5, host: "unknown.example"),
                HygieneFixtures.item(6, password: nil, host: "github.com"),
            ], policy: policy)
        func kinds(_ number: Int) -> Set<HygieneFindingKind> {
            Set(report.item(HygieneFixtures.id(number))?.findings.map(\.kind) ?? [])
        }
        #expect(kinds(1) == [.twoFactorAvailable, .passkeyAvailable])
        #expect(kinds(2) == [.passkeyAvailable])
        #expect(kinds(3).isEmpty)
        #expect(kinds(4) == [.twoFactorAvailable])
        #expect(kinds(5) == [.passwordOnly])
        #expect(kinds(6).isEmpty)
        #expect(report.item(HygieneFixtures.id(6))?.breachStatus == .notApplicable)
        #expect(report.item(HygieneFixtures.id(1))?.findings.first?.severity == .medium)
    }

    @Test("items are ordered worst first, then by title, then by ID; findings worst first")
    func ordering() throws {
        let breachedItem = HygieneFixtures.item(4, title: "zebra")
        let items = [
            HygieneFixtures.item(1, title: "Mango"),
            HygieneFixtures.item(2, title: "apple", password: "password"),
            HygieneFixtures.item(3, title: "Banana", password: "password"),
            breachedItem,
            HygieneFixtures.item(5, title: "apple", password: "qwerty"),
            HygieneFixtures.item(6, title: "cherry"),
        ]
        let ledger = ScanLedger(entries: [
            breachedItem.id: HygieneFixtures.scanned(breachedItem, .found(occurrences: 3))
        ])
        let report = try HygieneFixtures.report(items, ledger: ledger)
        #expect(report.items.map(\.title) == ["zebra", "apple", "apple", "Banana", "cherry", "Mango"])
        #expect(
            report.items.map(\.id).prefix(3) == [HygieneFixtures.id(4), HygieneFixtures.id(2), HygieneFixtures.id(5)])
        #expect(report.itemsNeedingAttention.map(\.title) == ["zebra", "apple", "apple", "Banana"])
        // Item 2: reused (high) and weak (high) before password-only (info); reuse sorts before weakness.
        #expect(
            report.item(HygieneFixtures.id(2))?.findings.map(\.kind) == [.reusedPassword, .weakPassword, .passwordOnly])
        #expect(
            report.badges(for: HygieneFixtures.id(2))
                == [
                    HygieneBadge(kind: .reusedPassword, severity: .high),
                    HygieneBadge(kind: .weakPassword, severity: .high),
                ])
        #expect(report.badges(for: UUID()).isEmpty)
    }

    @Test("the report does not depend on the order its inputs arrive in")
    func deterministic() throws {
        let items = (1...12).map {
            HygieneFixtures.item(
                $0, title: "Item \($0 % 4)", password: $0 % 3 == 0 ? "shared-secret-1" : "pw-\($0)-Zq7!x")
        }
        let reference = try HygieneFixtures.report(items)
        var generator = SeededGenerator(seed: 5)
        for _ in 0..<10 {
            #expect(try HygieneFixtures.report(items.shuffled(using: &generator)) == reference)
        }
    }

    @Test("totals add up")
    func totals() throws {
        let scannedItem = HygieneFixtures.item(1)
        let items = [
            scannedItem, HygieneFixtures.item(2, password: "password"), HygieneFixtures.item(3, password: nil),
            HygieneFixtures.item(4, password: HygieneFixtures.strongPassword(1), archived: true),
        ]
        let ledger = ScanLedger(
            entries: [scannedItem.id: HygieneFixtures.scanned(scannedItem, .notFound)],
            fullScanStartedAt: HygieneFixtures.now.addingTimeInterval(-7200), fullScanCompletedAt: nil)
        let report = try HygieneFixtures.report(items, ledger: ledger)
        #expect(report.generatedAt == HygieneFixtures.now)
        #expect(report.totals.items == 4)
        #expect(report.totals.passwords == 3)
        #expect(report.totals.itemsAwaitingBreachCheck == 2)
        #expect(report.totals.oldestBreachCheck == HygieneFixtures.now.addingTimeInterval(-3600))
        #expect(report.totals.fullScanInProgress)
        #expect(report.totals.lastFullScanCompletedAt == nil)
        // Items 1 and 4 share a password.
        #expect(report.totals.itemsByKind[.reusedPassword] == 2)
        #expect(report.totals.itemsNeedingAttention == 3)
        #expect(report.item(HygieneFixtures.id(4))?.isArchived == true)
    }

    @Test("no finding, summary or explanation contains a password")
    func noPasswordsInReport() throws {
        let passwords = ["hunter2", "shared-secret-1", "Tr0ub4dor&3", "qwerty", "p@ssw0rd"]
        let items =
            passwords.enumerated().map { HygieneFixtures.item($0.offset + 1, password: $0.element) }
            + [HygieneFixtures.item(9, password: "shared-secret-1")]
        var entries: [UUID: ScanLedger.Entry] = [:]
        for item in items { entries[item.id] = HygieneFixtures.scanned(item, .found(occurrences: 77)) }
        let report = try HygieneFixtures.report(items, ledger: ScanLedger(entries: entries))
        var dumped = ""
        dump(report, to: &dumped)
        for password in passwords {
            #expect(!dumped.contains(password))
        }
    }
}
