import Foundation
import SecureMemory
import Testing
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordHygiene

/// Synced breach-check results (owner decision 10; ADR 0005, amendment of 2026-11-16; docs/02-architecture.md §13.9):
/// the record's format and join, and how the engine weighs what other devices report.
@Suite("Synced scan results")
struct SyncedScanTests {
    static let deviceA = UUID(uuidString: "AAAAAAAA-0000-0000-0000-000000000001")!
    static let deviceB = UUID(uuidString: "BBBBBBBB-0000-0000-0000-000000000002")!
    static let keyID = UUID(uuidString: "4B000000-0000-0000-0000-000000000001")!
    static let now = HygieneFixtures.now
    static let week: TimeInterval = 7 * 24 * 60 * 60

    static func binding(_ seed: UInt8) -> ScanBinding {
        ScanBinding(bytes: [UInt8](repeating: seed, count: ScanBinding.length))!
    }

    static func observation(
        _ device: UUID, revision: UInt64, at: Date = now, results: [ScanBinding: UInt32] = [binding(1): 0]
    ) -> SyncedScanRecord.Observation {
        SyncedScanRecord.Observation(device: device, revision: revision, keyID: keyID, scannedAt: at, results: results)
    }

    static func record(_ observations: [SyncedScanRecord.Observation], version: UInt64 = 1000) -> SyncedScanRecord {
        SyncedScanRecord(
            itemID: HygieneFixtures.id(1), vaultID: HygieneFixtures.vault, version: version,
            observations: observations)
    }

    static func evidence(
        _ item: Item, _ result: PwnedPasswordResult, at: Date, device: UUID = deviceA
    ) -> SyncedScanEvidence {
        SyncedScanEvidence(
            itemID: item.id, itemVersion: item.version,
            fields: Dictionary(
                uniqueKeysWithValues: ItemAnalyzer.passwordFields(of: item).map {
                    ($0.id, [SyncedScanEvidence.Observation(device: device, scannedAt: at, result: result)])
                }))
    }

    // MARK: Bindings

    @Test(
        "a binding is HMAC-SHA-256 under its key of the label, the item ID and the password, as Python's hmac computes it",
        arguments: zip(
            ["hunter2", "pässwörd"],
            [
                "70d00ac4a66232e9451197acca443d375cb2f7f4adcdbbaa679e80701289b7bf",
                "2e9fa28ee3f6940a47d5cf1b559f094c3903dbcf1f51431e9759295b4cec52c3",
            ]))
    func bindingKnownAnswer(password: String, expected: String) throws {
        let key = try ScanBindingKey(SecureBytes(copying: (0..<32).map { UInt8($0) }))
        #expect(key.binding(item: HygieneFixtures.id(1), utf8Of: password).hex == expected)
    }

    @Test("a binding belongs to one password of one item under one key, and prints as redacted")
    func bindingScope() throws {
        let key = try ScanBindingKey(SecureBytes(copying: (0..<32).map { UInt8($0) }))
        let other = try ScanBindingKey(SecureBytes(copying: (0..<32).map { UInt8(255 - $0) }))
        let base = key.binding(item: HygieneFixtures.id(1), utf8Of: "hunter2")
        #expect(base == key.binding(item: HygieneFixtures.id(1), utf8Of: "hunter2"))
        #expect(base != key.binding(item: HygieneFixtures.id(2), utf8Of: "hunter2"))
        #expect(base != key.binding(item: HygieneFixtures.id(1), utf8Of: "hunter3"))
        #expect(base != other.binding(item: HygieneFixtures.id(1), utf8Of: "hunter2"))
        #expect("\(base)" == "ScanBinding(redacted)")
        #expect(throws: ScanBindingKeyError.tooShort) { try ScanBindingKey(SecureBytes(copying: [1, 2, 3])) }
    }

    // MARK: The record

    @Test("a record round-trips through its one canonical encoding and prints without results")
    func codec() throws {
        let record = Self.record([
            Self.observation(Self.deviceB, revision: 7, results: [Self.binding(2): 5, Self.binding(1): 0]),
            Self.observation(Self.deviceA, revision: 9, at: Self.now.addingTimeInterval(0.75)),
        ])
        let bytes = try record.encoded()
        let decoded = try SyncedScanRecord(decoding: bytes)
        #expect(decoded == record)
        #expect(try decoded.encoded() == bytes)
        #expect(!"\(record)".contains("5"))
        let reported = ScanLedger.Reported(occurrences: 31_337, reportedAt: Self.now)
        let observed = SyncedScanEvidence.Observation(
            device: Self.deviceA, scannedAt: Self.now, result: .found(occurrences: 31_337))
        for text in [
            "\(reported)", "\(observed)", String(reflecting: observed),
            "\(Self.observation(Self.deviceA, revision: 1, results: [Self.binding(1): 31_337]))",
        ] {
            #expect(!text.contains("31337"))
        }
        #expect(decoded.observations[Self.deviceA]?.scannedAt == Self.now)
    }

    @Test("a damaged, reordered, padded or over-full record does not decode")
    func codecRefuses() throws {
        let record = Self.record([
            Self.observation(Self.deviceA, revision: 7), Self.observation(Self.deviceB, revision: 8),
        ])
        let bytes = try record.encoded()
        #expect(throws: SyncedScanRecordError.malformed) { try SyncedScanRecord(decoding: bytes + [0]) }
        #expect(throws: SyncedScanRecordError.malformed) { try SyncedScanRecord(decoding: Array(bytes.dropLast())) }
        var badMagic = bytes
        badMagic[0] ^= 1
        #expect(throws: SyncedScanRecordError.malformed) { try SyncedScanRecord(decoding: badMagic) }
        // The two observations swapped: devices must ascend.
        let header = SyncedScanRecord.headerLength
        let length = SyncedScanRecord.observationHeaderLength + SyncedScanRecord.resultLength
        let swapped =
            Array(bytes[0..<header]) + Array(bytes[(header + length)...]) + Array(bytes[header..<(header + length)])
        #expect(throws: SyncedScanRecordError.malformed) { try SyncedScanRecord(decoding: swapped) }
        // An observation claiming a revision above the record's own version.
        let ahead = Self.record([Self.observation(Self.deviceA, revision: 9)], version: 9)
        var aheadBytes = try ahead.encoded()
        aheadBytes[37 + 7] = 8
        #expect(throws: SyncedScanRecordError.malformed) { try SyncedScanRecord(decoding: aheadBytes) }
        // More results than an item has checked passwords.
        var many: [ScanBinding: UInt32] = [:]
        for seed in 0..<UInt8(SyncedScanRecord.maximumResultsPerObservation + 1) { many[Self.binding(seed)] = 0 }
        #expect(throws: SyncedScanRecordError.tooLarge) {
            try Self.record([Self.observation(Self.deviceA, revision: 1, results: many)]).encoded()
        }
    }

    @Test("the join keeps each device's latest observation, whichever side it came from")
    func joinPerDevice() {
        let older = Self.record([Self.observation(Self.deviceA, revision: 3, results: [Self.binding(1): 9])])
        let newer = Self.record([
            Self.observation(Self.deviceA, revision: 5), Self.observation(Self.deviceB, revision: 4),
        ])
        let joined = older.joined(newer)
        #expect(joined.observations[Self.deviceA]?.revision == 5)
        #expect(joined.observations[Self.deviceB]?.revision == 4)
        #expect(joined.sameState(newer.joined(older)))
        #expect(joined.sameState(joined.joined(older)))
    }

    @Test("the join is commutative, associative and idempotent, and bounded, over random records")
    func joinLaws() {
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 0xC0FFEE))
        let devices = (0..<40).map { index in
            UUID(uuidString: "DE000000-0000-0000-0000-" + String(format: "%012d", index))!
        }
        func randomRecord() -> SyncedScanRecord {
            let count = Int(generator.next() % 20)
            return Self.record(
                (0..<count).map { _ in
                    Self.observation(
                        devices[Int(generator.next() % 40)], revision: 1 + generator.next() % 6,
                        results: [Self.binding(UInt8(generator.next() % 3)): UInt32(generator.next() % 2)])
                })
        }
        for _ in 0..<TestEnvironment.iterations(standard: 200, long: 5000) {
            let a = randomRecord()
            let b = randomRecord()
            let c = randomRecord()
            #expect(a.joined(b).sameState(b.joined(a)))
            #expect(a.joined(b).joined(c).sameState(a.joined(b.joined(c))))
            #expect(a.joined(a).sameState(a))
            #expect(a.joined(b).joined(c).observations.count <= SyncedScanRecord.maximumObservations)
        }
    }

    @Test("an erasure takes every observation its author can have seen, and keeps those written after it")
    func erasure() {
        let record = Self.record([
            Self.observation(Self.deviceA, revision: 5), Self.observation(Self.deviceB, revision: 12),
        ])
        #expect(record.settled(afterErasureAt: 12) == nil)
        let kept = record.settled(afterErasureAt: 6)
        #expect(kept?.observations.keys.sorted { $0.uuidString < $1.uuidString } == [Self.deviceB])
    }

    @Test("evidence holds only other devices' observations under keys this device can derive, matched by password")
    func matching() throws {
        let key = try ScanBindingKey(SecureBytes(copying: (0..<32).map { UInt8($0) }))
        defer { key.zeroise() }
        let item = HygieneFixtures.item(1, password: "hunter2")
        let current = key.binding(item: item.id, utf8Of: "hunter2")
        let stale = key.binding(item: item.id, utf8Of: "an-older-password")
        let unknownKey = UUID()
        let record = Self.record([
            Self.observation(Self.deviceA, revision: 3, results: [current: 0]),
            Self.observation(Self.deviceB, revision: 4, results: [stale: 9]),
            SyncedScanRecord.Observation(
                device: UUID(), revision: 5, keyID: unknownKey, scannedAt: Self.now, results: [current: 9]),
        ])
        let evidence = SyncedScanEvidence.matching(record, item: item, ownDevice: Self.deviceB) {
            $0 == Self.keyID ? key : nil
        }
        let field = HygieneFixtures.fieldID(1)
        #expect(evidence.fields[field] == [.init(device: Self.deviceA, scannedAt: Self.now, result: .notFound)])
        let asA = SyncedScanEvidence.matching(record, item: item, ownDevice: Self.deviceA) {
            $0 == Self.keyID ? key : nil
        }
        // B's result is about another password, and A's own observation is never read back.
        #expect(asA.fields.isEmpty)
    }

    // MARK: The engine

    @Test("a check another device synced stands in for this device's: nothing is asked, and it is shown as theirs")
    func remoteClearSkips() async throws {
        let rig = await EngineRig()
        let item = HygieneFixtures.item(1)
        let checked = Self.now.addingTimeInterval(-3600)
        try await rig.unlock([item], synced: [Self.evidence(item, .notFound, at: checked)])
        #expect(await rig.runUntilIdle([item]).isEmpty)
        #expect(await rig.http.requests.isEmpty)
        let entry = try await rig.engine.report(now: Self.now).item(item.id)
        #expect(entry?.breachStatus == .clear(checkedAt: checked))
        #expect(entry?.breachSource == .anotherDevice)
    }

    @Test("a synced check of an older password covers nothing: the changed password is checked here")
    func changedPasswordRechecked() async throws {
        let rig = await EngineRig(breached: ["hunter2": 5])
        let old = HygieneFixtures.item(1)
        var new = old
        new.fields[1].value = "hunter2"
        new.version = 2
        // The evidence was matched against version 1; the engine knows version 2.
        try await rig.unlock([new], synced: [Self.evidence(old, .notFound, at: Self.now)])
        #expect(try await rig.engine.updateSynced(Self.evidence(old, .notFound, at: Self.now), now: Self.now) == false)
        #expect(await rig.runUntilIdle([new]) == [.scanned(breachedPasswords: 1, networkRequests: 1)])
        #expect(try await rig.engine.report(now: Self.now).items[0].breachStatus == .breached(checkedAt: Self.now))
    }

    @Test("an edit that keeps the password keeps its result, here as well")
    func editKeepsResult() async throws {
        let rig = await EngineRig()
        var item = HygieneFixtures.item(1)
        try await rig.unlock([item])
        await rig.runUntilIdle([item])
        item.notes = "Renewed the plan."
        item.version = 2
        try await rig.engine.update(item)
        #expect(await rig.engine.next(now: Self.now) != .scan(item: item.id, reason: .changed))
        #expect(try await rig.engine.report(now: Self.now).items[0].breachStatus == .clear(checkedAt: Self.now))
    }

    @Test("a synced 'not found' never hides a breach this device found, however new or far ahead it is dated")
    func ownBreachSticks() async throws {
        let rig = await EngineRig(breached: ["hunter2": 5])
        let item = HygieneFixtures.item(1, password: "hunter2")
        try await rig.unlock([item])
        await rig.runUntilIdle([item])
        for at in [Self.now, Self.now.addingTimeInterval(10 * 365 * 86400)] {
            try await rig.engine.updateSynced(Self.evidence(item, .notFound, at: at), now: Self.now)
            let entry = try await rig.engine.report(now: Self.now).items[0]
            #expect(entry.breachStatus == .breached(checkedAt: Self.now))
            #expect(entry.breachSource == .thisDevice)
        }
    }

    @Test("a reported breach is shown, outlasts a later synced 'not found', and goes only with this device's own check")
    func reportedBreach() async throws {
        let rig = await EngineRig()
        let item = HygieneFixtures.item(1)
        let reportedAt = Self.now.addingTimeInterval(-60)
        try await rig.unlock([item], synced: [Self.evidence(item, .found(occurrences: 42), at: reportedAt)])
        var entry = try await rig.engine.report(now: Self.now).items[0]
        #expect(entry.breachStatus == .breached(checkedAt: reportedAt))
        #expect(entry.breachSource == .anotherDevice)
        #expect(entry.findings.first?.detail == .breached(occurrences: 42))
        #expect(entry.findings.first?.explanation.hasPrefix("Another device") == true)
        #expect(try await rig.engine.takeChangedLedger()?.reported[item.id]?.count == 1)

        // The same device, later, says it is clear: the report this device took in stands.
        try await rig.engine.updateSynced(Self.evidence(item, .notFound, at: Self.now), now: Self.now)
        entry = try await rig.engine.report(now: Self.now).items[0]
        #expect(entry.breachStatus == .breached(checkedAt: reportedAt))

        // This device's own check, which the server answers "not found", is the one thing that outranks it.
        await rig.clock.advance(by: 8 * 86400)
        let later = await rig.clock.now()
        #expect(await rig.engine.scan(item, now: later) == .scanned(breachedPasswords: 0, networkRequests: 1))
        entry = try await rig.engine.report(now: later).items[0]
        #expect(entry.breachStatus == .clear(checkedAt: later))
        #expect(try await rig.engine.ledger().reported.isEmpty)
    }

    @Test("a breach reported for a check older than this device's own clear one is not taken in")
    func olderReportIgnored() async throws {
        let rig = await EngineRig()
        let item = HygieneFixtures.item(1)
        try await rig.unlock([item])
        await rig.runUntilIdle([item])
        let older = Self.now.addingTimeInterval(-86400)
        try await rig.engine.updateSynced(Self.evidence(item, .found(occurrences: 3), at: older), now: Self.now)
        #expect(try await rig.engine.ledger().reported.isEmpty)
        #expect(try await rig.engine.report(now: Self.now).items[0].breachStatus == .clear(checkedAt: Self.now))
    }

    @Test("a synced time far ahead of the clock is ignored, and one just ahead counts as now")
    func futureTimes() async throws {
        let rig = await EngineRig()
        let item = HygieneFixtures.item(1)
        let farAhead = Self.now.addingTimeInterval(3600)
        try await rig.unlock([item], synced: [Self.evidence(item, .notFound, at: farAhead)])
        #expect(try await rig.engine.report(now: Self.now).items[0].breachStatus == .notChecked)
        #expect(await rig.engine.next(now: Self.now) == .scan(item: item.id, reason: .created))

        let justAhead = Self.now.addingTimeInterval(60)
        try await rig.engine.updateSynced(Self.evidence(item, .notFound, at: justAhead), now: Self.now)
        #expect(try await rig.engine.report(now: Self.now).items[0].breachStatus == .clear(checkedAt: Self.now))
    }

    @Test("a synced check postpones this device's own by at most an interval")
    func postponedByAnInterval() async throws {
        let rig = await EngineRig()
        let item = HygieneFixtures.item(1)
        try await rig.unlock([item], synced: [Self.evidence(item, .notFound, at: Self.now)])
        #expect(await rig.runUntilIdle([item]).isEmpty)
        await rig.clock.set(Self.now.addingTimeInterval(Self.week + 1))
        // Never checked here, so it is due as a new item once the synced check no longer covers it.
        #expect(await rig.engine.next(now: await rig.clock.now()) == .scan(item: item.id, reason: .created))
    }

    @Test("synced checks stand in for this device's own for at most the deferral limit, however fresh they keep coming")
    func deferralLimit() async throws {
        let rig = await EngineRig()
        let item = HygieneFixtures.item(1)
        try await rig.unlock([item])
        var now = Self.now
        var outcomes: [ScanOutcome] = []
        // Another device reports "not found" every day; this device checks itself once the limit has run out.
        for _ in 0..<40 {
            try await rig.engine.updateSynced(Self.evidence(item, .notFound, at: now), now: now)
            if case .scan(let id, _) = await rig.engine.next(now: now), id == item.id {
                outcomes.append(await rig.engine.scan(item, now: now))
                break
            }
            now = now.addingTimeInterval(86400)
            await rig.clock.set(now)
        }
        #expect(outcomes == [.scanned(breachedPasswords: 0, networkRequests: 1)])
        let elapsed = now.timeIntervalSince(Self.now)
        #expect(elapsed > ScanPolicy.standard.maximumSyncDeferral)
        #expect(elapsed <= ScanPolicy.standard.maximumSyncDeferral + 86400)
        #expect(try await rig.engine.ledger().deferred.isEmpty)
    }

    /// Review finding N1 (docs/06-adversarial-review.md §N): the item's password taken out and put back, or the item
    /// trashed and restored, used to make the engine forget the item's results and its deferral mark, so the limit
    /// started again each time.
    @Test(
        "the deferral limit holds when the password is taken out and put back, or the item trashed and restored",
        arguments: [false, true])
    func deferralLimitSurvivesRemoval(trash: Bool) async throws {
        let rig = await EngineRig()
        var item = HygieneFixtures.item(1)
        try await rig.unlock([item])
        var now = Self.now
        var checkedAt: Date?
        for day in 0..<60 {
            if day % 10 == 9 {
                // Away for a moment, then back: the same password, at a new version each time.
                var away = item
                away.version += 1
                if trash { away.trashedAt = now } else { away.fields.removeLast() }
                try await rig.engine.update(away)
                item.version = away.version + 1
                try await rig.engine.update(item)
            }
            try await rig.engine.updateSynced(Self.evidence(item, .notFound, at: now), now: now)
            if case .scan(let id, _) = await rig.engine.next(now: now), id == item.id {
                #expect(await rig.engine.scan(item, now: now) == .scanned(breachedPasswords: 0, networkRequests: 1))
                checkedAt = now
                break
            }
            now = now.addingTimeInterval(86400)
            await rig.clock.set(now)
        }
        let checked = try #require(checkedAt)
        #expect(checked.timeIntervalSince(Self.now) <= ScanPolicy.standard.maximumSyncDeferral + 86400)
    }

    /// Review finding N1 again: a breach this device found itself outlasts the password being taken out and put back,
    /// or a trash and restore, whatever another device syncs meanwhile.
    @Test(
        "a breach this device found outlasts the password's removal and return, and a trash and restore",
        arguments: [false, true])
    func ownBreachSurvivesRemoval(trash: Bool) async throws {
        let rig = await EngineRig(breached: ["hunter2": 5])
        var item = HygieneFixtures.item(1, password: "hunter2")
        try await rig.unlock([item])
        await rig.runUntilIdle([item])
        var away = item
        away.version = 2
        if trash { away.trashedAt = Self.now } else { away.fields.removeLast() }
        try await rig.engine.update(away)
        item.version = 3
        try await rig.engine.update(item)
        try await rig.engine.updateSynced(Self.evidence(item, .notFound, at: Self.now), now: Self.now)
        let entry = try await rig.engine.report(now: Self.now).items[0]
        #expect(entry.breachStatus == .breached(checkedAt: Self.now))
        #expect(entry.breachSource == .thisDevice)
    }

    /// Review finding N2: with the ledger's deferral marks full, an item that could not be marked was deferred from
    /// "now" at every pass, so the limit never ran out for it.
    @Test("an item that cannot be marked as deferring is not deferred at all")
    func deferralWithoutRoom() {
        var ledger = ScanLedger()
        for _ in 0..<ScanLedger.maximumEntries { ledger.deferred[UUID()] = Self.now.addingTimeInterval(-60) }
        var schedule = ScanSchedule(ledger: ledger)
        #expect(schedule.syncDeferral(of: HygieneFixtures.id(1), now: Self.now) == nil)
        #expect(!schedule.isDeferring(HygieneFixtures.id(1)))
    }

    /// Review finding N3: the ledger's binding key was `HMAC(reuse key, label)`, which is the reuse token of a password
    /// spelt like the label, so the two derivations were not separated.
    @Test("the ledger's binding key is no reuse token, whatever the password")
    func ledgerBindingKeyIsNoReuseToken() throws {
        let key = try ReuseKey(SecureBytes(copying: (0..<32).map { UInt8($0) }))
        defer { key.zeroise() }
        let label = String(decoding: ReuseKey.scanBindingLabel.filter { $0 < 0x80 }, as: UTF8.self)
        var token = key.token(forUTF8Of: label).bytes
        let asKey = try ScanBindingKey(SecureBytes(wiping: &token))
        defer { asKey.zeroise() }
        let item = HygieneFixtures.id(1)
        #expect(key.scanBinding(item: item, utf8Of: "hunter2") != asKey.binding(item: item, utf8Of: "hunter2"))
    }

    @Test("reports and deferrals survive the ledger's encoding, and a ledger without them decodes as before")
    func ledgerEncoding() throws {
        var ledger = ScanLedger()
        ledger.entries[HygieneFixtures.id(1)] = ScanLedger.Entry(
            itemVersion: 3, scannedAt: Self.now, results: [HygieneFixtures.fieldID(1): .notFound],
            bindings: [HygieneFixtures.fieldID(1): Self.binding(7)])
        ledger.reported[HygieneFixtures.id(1)] = [
            Self.binding(9): ScanLedger.Reported(occurrences: 12, reportedAt: Self.now)
        ]
        ledger.deferred[HygieneFixtures.id(2)] = Self.now
        let data = try JSONEncoder().encode(ledger)
        #expect(try JSONDecoder().decode(ScanLedger.self, from: data) == ledger)
        let empty = try JSONEncoder().encode(ScanLedger())
        #expect(String(decoding: empty, as: UTF8.self) == #"{"entries":[]}"#)
    }
}
