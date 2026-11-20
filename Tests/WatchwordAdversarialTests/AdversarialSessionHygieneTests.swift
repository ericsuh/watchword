import Foundation
import SecureMemory
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordHygiene
@testable import WatchwordKit

/// Milestone 6's session obligations for hygiene (docs/02-architecture.md §13.8, ADR 0005 and its amendment).
///
/// The adversaries, from docs/02-architecture.md §2 and §13.1:
/// - **A2 and A3, a thief holding the device while the vault is locked**, and **A8, malware reading or writing the
///   app's files**: read everything at rest and in a memory image taken after the lock, and can plant files. Must find
///   nothing derived from a password once `lock()` has run: no engine state, no reuse key, no prefix, no breach
///   result, in memory or in the device-local store; and a record planted from elsewhere must not be believed.
/// - **The service and the network path**, which choose when a response arrives: a response that comes back after the
///   lock must not be recorded anywhere.
/// - **Another device of the account, or another account on the same device** (A4 at its strongest: it holds the
///   account's keyset, as every device of the account does, a revoked one included, §7.8, and knows this device's ID,
///   which is on every row and stream the device writes): its sealed records must not open as this device's, so it
///   can neither read this device's ledger nor hand it one that says a breached password was checked and found clear.
///   What it lacks is this device's secret, in this device's Keychain (review finding L1).
@Suite("Adversarial: hygiene in the vault session", .tags(.adversarial))
struct AdversarialSessionHygieneTests {
    typealias Fixture = HygieneSessionFixture

    static func unlocked(seed: UInt64 = 31) async throws -> (Fixture, UUID) {
        let fixture = await Fixture(seed: seed)
        _ = try await fixture.session.createAccount(password: TestVault.password)
        return (fixture, try #require(await fixture.session.personalVaultID))
    }

    static func contains(_ haystack: [UInt8], _ needle: [UInt8]) -> Bool {
        guard needle.count <= haystack.count else { return false }
        return (0...(haystack.count - needle.count)).contains { Array(haystack[$0..<($0 + needle.count)]) == needle }
    }

    /// A3 and A8 after a lock: the engine holds nothing, the session's local key is gone, the cache answers nothing,
    /// and every byte at rest is ciphertext (no record magic, no ledger keys, no item ID, no prefix in hexadecimal).
    @Test("nothing password-derived survives lock(): engine state, the local key, the cache, the records at rest")
    func nothingSurvivesLock() async throws {
        let (fixture, vaultID) = try await Self.unlocked()
        let item = try await fixture.session.save(
            Fixture.login(vaultID, title: "Forum", host: "forum.example", password: "password"))
        try await fixture.scanUntilIdle()
        let prefix = try #require(PwnedRangePrefix("5BAA6"))
        #expect(await fixture.session.hygieneCachedRange(prefix, in: vaultID) != nil)
        let engine = try #require(await fixture.session.hygieneEngine)
        #expect(try await engine.items(using: "password") == [item.id])

        await fixture.session.lock()
        await fixture.session.hygieneSettled()
        #expect(await engine.isUnlocked == false)
        await #expect(throws: HygieneEngineError.locked) { try await engine.ledger() }
        await #expect(throws: HygieneEngineError.locked) { try await engine.items(using: "password") }
        await #expect(throws: HygieneEngineError.locked) { try await engine.report(now: Date()) }
        #expect(await fixture.session.hygieneRuntime?.localKey == nil)
        #expect(await fixture.session.hygieneRuntime?.known.isEmpty == true)
        #expect(await fixture.session.hygieneCachedRange(prefix, in: vaultID) == nil)

        let atRest = await fixture.local.contents
        #expect(atRest.count == 3, "one range, its index, the ledger")
        let needles = ["WWPR", "WWRI", "entries", "5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8", item.id.uuidString]
        for bytes in atRest.values {
            for needle in needles {
                #expect(!Self.contains(bytes, Array(needle.utf8)), "plaintext at rest")
            }
        }
        // The names on disk are keyed digests: none is derivable from the prefix without the key.
        #expect(!atRest.keys.contains { $0.uuidString.contains("5BAA6") })
    }

    /// The network path holds a response until after the lock (and a lock that lands while a range is on its way).
    /// Nothing may be recorded: no ledger entry, no cache record, nothing at rest changed; after the next unlock the
    /// item is still due and is asked for again.
    @Test("a scan in flight when lock() lands records nothing, in memory or at rest")
    func scanInFlightRecordsNothing() async throws {
        let (fixture, vaultID) = try await Self.unlocked()
        let item = try await fixture.session.save(
            Fixture.login(vaultID, title: "Forum", host: "forum.example", password: "password"))
        _ = try await fixture.session.hygieneReport()
        let before = await fixture.local.contents

        await fixture.http.hold()
        let session = fixture.session
        let step = Task { try await session.runHygieneStep() }
        await fixture.http.waitForHeldRequest()
        await session.lock()
        await session.hygieneSettled()
        await fixture.http.release()
        let result = try await step.value
        guard case .scanned(item.id, .interrupted) = result else {
            Issue.record("the interrupted scan reported \(result)")
            return
        }
        #expect(await fixture.local.contents == before, "nothing written at rest")

        try await session.unlock(password: TestVault.password)
        let report = try await session.hygieneReport()
        #expect(report.totals.itemsAwaitingBreachCheck == 1)
        #expect(await session.hygieneCachedRange(try #require(PwnedRangePrefix("5BAA6")), in: vaultID) == nil)
        let sent = await fixture.http.requests.count
        try await fixture.scanUntilIdle()
        #expect(await fixture.http.requests.count == sent + 1, "asked for again, not answered from a cache")
    }

    /// Another device of the same account holds the same keyset, and may claim this device's ID: without this
    /// device's secret, the device-local key it derives is a different key, under a different key ID, so a record
    /// sealed here neither opens there nor is accepted here from there. Nor does the secret alone, without the keyset.
    @Test(
        "a sealed local record does not open under another device's key, another account's, or one without the secret")
    func localKeyIsPerDevice() throws {
        let accountID = UUID()
        let keyset = Keyset.generate(accountID: accountID)
        let other = Keyset.generate(accountID: UUID())
        let thisDevice = UUID()
        var random = SeededGenerator(seed: 0x5EC7)
        let secret = SecureBytes(randomCount: DeviceLocalKeys.deviceSecretLength, using: &random)
        let otherSecret = SecureBytes(randomCount: DeviceLocalKeys.deviceSecretLength, using: &random)
        let here = try DeviceLocalKeys.deviceLocalKey(keyset: keyset, deviceSecret: secret, deviceID: thisDevice)
        let there = try DeviceLocalKeys.deviceLocalKey(keyset: keyset, deviceSecret: otherSecret, deviceID: UUID())
        let elsewhere = try DeviceLocalKeys.deviceLocalKey(keyset: other, deviceSecret: secret, deviceID: thisDevice)
        // Another device of the account, claiming this device's ID: everything but the secret.
        let claimant = try DeviceLocalKeys.deviceLocalKey(
            keyset: keyset, deviceSecret: otherSecret, deviceID: thisDevice)
        #expect(Set([here.keyID, there.keyID, elsewhere.keyID, claimant.keyID]).count == 4)
        // Derived again, the same key: the ledger survives a relaunch and a password change (the keyset is kept).
        #expect(
            try DeviceLocalKeys.deviceLocalKey(keyset: keyset, deviceSecret: secret, deviceID: thisDevice).keyID
                == here.keyID)
        #expect(throws: CryptoError.invalidKeyLength(16)) {
            try DeviceLocalKeys.deviceLocalKey(
                keyset: keyset, deviceSecret: secret.extracting(0..<16), deviceID: thisDevice)
        }
        let reuse = DeviceLocalKeys.hygieneReuseKey(keyset: keyset)
        #expect(reuse.unprotectedCopy() != keyset.symmetricKey.material.unprotectedCopy(), "never the raw key")

        let name = DeviceLocalKeys.recordName("scan-ledger", key: here)
        #expect(DeviceLocalKeys.recordName("scan-ledger", key: there) != name)
        #expect(DeviceLocalKeys.recordName("scan-ledger", key: claimant) != name)
        let sealed = try RecordCipher.seal(
            Array("{\"entries\":[]}".utf8),
            context: VaultSession.localContext(name: name, accountID: accountID, key: here), key: here)
        for key in [there, elsewhere, claimant] {
            // Under the other key's own context: the header names a different key.
            #expect(throws: (any Error).self) {
                try RecordCipher.open(
                    sealed, context: VaultSession.localContext(name: name, accountID: accountID, key: key), key: key)
            }
            // Under this key's context with the other key's bytes: authentication fails.
            let impostor = try EncryptionKey(keyID: here.keyID, material: key.material)
            #expect(throws: CryptoError.authenticationFailed) {
                try RecordCipher.open(
                    sealed, context: VaultSession.localContext(name: name, accountID: accountID, key: here),
                    key: impostor)
            }
        }
        // And moved to another name, it does not open under the right key either.
        #expect(throws: (any Error).self) {
            try RecordCipher.open(
                sealed,
                context: VaultSession.localContext(
                    name: DeviceLocalKeys.recordName("range-index", key: here), accountID: accountID, key: here),
                key: here)
        }
    }

    /// A3 or A8 takes a memory image straight after the lock, before anything else the session queued has run (an
    /// iOS process suspended as it enters the background): the engine must already hold nothing, and answer nothing.
    @Test("lock() drops the engine's reuse key and analyses before it returns, not in a task after it")
    func engineIsLockedWhenLockReturns() async throws {
        let (fixture, vaultID) = try await Self.unlocked()
        let item = try await fixture.session.save(
            Fixture.login(vaultID, title: "Forum", host: "forum.example", password: "password"))
        try await fixture.scanUntilIdle()
        #expect(try await fixture.session.itemsUsingPassword("password") == [item.id])
        for _ in 0..<20 {
            let probe = await fixture.session.lockThenProbeHygiene("password")
            #expect(probe.engineUnlocked == false, "the engine is still unlocked after lock() returned")
            #expect(probe.reuseAnswer == nil, "the engine still answers reuse queries after lock() returned")
            try await fixture.session.unlock(password: TestVault.password)
            #expect(try await fixture.session.itemsUsingPassword("password") == [item.id])
        }
    }

    /// A4 at its strongest, with A8's access to this device's files: another device of the account (a revoked one
    /// included: revocation does not take the keyset back, §7.8) holds the keyset and knows this device's ID, which
    /// is on every row and stream it writes. It must neither open this device's ledger nor plant one that says a
    /// breached password was checked and found clear.
    @Test("a keyset holder that knows this device's ID can neither read nor forge its sealed ledger")
    func ledgerForgedByAKeysetHolderIsIgnored() async throws {
        let (fixture, vaultID) = try await Self.unlocked()
        let session = fixture.session
        let item = try await session.save(
            Fixture.login(vaultID, title: "Forum", host: "forum.example", password: "password"))
        try await fixture.scanUntilIdle()
        let epoch = await session.lockEpoch
        let keyset = try #require(await session.keys?.keyset)
        let account = try #require(await session.account)
        // Which file is the ledger, the adversary can tell by its size; the test asks the session.
        let victimName = try #require(await session.localName("scan-ledger", since: epoch))
        let atRest = try #require(await fixture.local.contents[victimName])

        let forgingKey = try Self.forgingKey(keyset: keyset, deviceID: account.deviceID)
        let forgedName = DeviceLocalKeys.recordName("scan-ledger", key: forgingKey)
        for name in [victimName, forgedName] {
            #expect(throws: (any Error).self, "the adversary opened this device's ledger") {
                try RecordCipher.open(
                    atRest,
                    context: VaultSession.localContext(name: name, accountID: account.accountID, key: forgingKey),
                    key: forgingKey)
            }
        }

        let field = try #require(item.fields.first { $0.kind == .password }).id
        let now = await fixture.clock.now()
        let forged = ScanLedger(
            entries: [item.id: .init(itemVersion: item.version, scannedAt: now, results: [field: .notFound])],
            fullScanStartedAt: now, fullScanCompletedAt: now)
        let plaintext = try Array(JSONEncoder().encode(forged))
        for name in [victimName, forgedName] {
            let envelope = try RecordCipher.seal(
                plaintext,
                context: VaultSession.localContext(name: name, accountID: account.accountID, key: forgingKey),
                key: forgingKey)
            await fixture.local.write(envelope, as: name)
        }

        await session.lock()
        try await session.unlock(password: TestVault.password)
        let report = try await session.hygieneReport()
        #expect(report.totals.itemsAwaitingBreachCheck == 1, "the forged ledger was believed")
        try await fixture.scanUntilIdle()
        let after = try await session.hygieneReport()
        #expect(after.item(item.id)?.findings.contains { $0.kind == .breachedPassword } == true)
    }

    /// A8 keeps an older sealed ledger of this device's own and puts it back later (review finding L3, accepted): it
    /// opens, because it is this device's, but it is an authentic earlier reading, so every check it records is older
    /// than the one it replaces and the next weekly pass is due no later than it was. Here the pass the rolled-back
    /// ledger describes is over, so the item is due at once (after the rate limit, which is kept outside the ledger).
    @Test("an older ledger of this device's own, put back, defers no check")
    func rolledBackLedgerDefersNothing() async throws {
        let (fixture, vaultID) = try await Self.unlocked()
        let session = fixture.session
        let item = try await session.save(
            Fixture.login(vaultID, title: "Forum", host: "forum.example", password: "password"))
        try await fixture.scanUntilIdle()
        guard case .idle(let nextPass) = try await session.runHygieneStep() else {
            Issue.record("not idle after the first pass")
            return
        }
        let name = try #require(await session.localName("scan-ledger", since: await session.lockEpoch))
        let older = try #require(await fixture.local.contents[name])

        await fixture.clock.set(nextPass.addingTimeInterval(1))
        #expect(try await fixture.scanUntilIdle().count == 1, "the weekly pass checked the item again")
        guard case .idle = try await session.runHygieneStep() else {
            Issue.record("not idle after the second pass")
            return
        }
        await fixture.local.write(older, as: name)

        await session.lock()
        try await session.unlock(password: TestVault.password)
        var step = try await session.runHygieneStep()
        if case .wait(let until, .pacing) = step {
            // The rate limit since the second pass's request, which is not the ledger's to set: the item is due.
            await fixture.clock.set(until.addingTimeInterval(1))
            step = try await session.runHygieneStep()
        }
        guard case .scanned(item.id, .scanned) = step else {
            Issue.record("after the rollback the first step was \(step), not a check of the item")
            return
        }
    }

    /// The best the adversary of `ledgerForgedByAKeysetHolderIsIgnored` can do: everything it holds, the keyset and
    /// this device's ID, and a device secret of its own (it has no way to this device's Keychain).
    static func forgingKey(keyset: Keyset, deviceID: UUID) throws -> EncryptionKey {
        var random = SeededGenerator(seed: 0xF0F0)
        let ownSecret = SecureBytes(randomCount: DeviceLocalKeys.deviceSecretLength, using: &random)
        return try DeviceLocalKeys.deviceLocalKey(keyset: keyset, deviceSecret: ownSecret, deviceID: deviceID)
    }

    /// A4, a writing member of a shared vault with a client that reads the raw scan records (Z88). A check answered
    /// from the prefix cache costs no pacing token, so the victim's next item is scanned at once, and each item's
    /// `scannedAt` is published to every member: the gaps between them said which of A4's probe items hit a range the
    /// victim's device had cached for a password in some other vault, a confirmation oracle over passwords A4 cannot
    /// see. The cache is now partitioned by vault: a range fetched for one vault never answers another's check, so a
    /// probe in the shared vault always goes to the network, whatever the victim holds elsewhere.
    @Test("a range cached for one vault does not answer a check in another")
    func cachePartitionedByVault() async throws {
        let (fixture, personal) = try await Self.unlocked()
        let household = try await fixture.session.createVault(name: "Household")
        try await fixture.session.save(
            Fixture.login(personal, title: "Mine", host: "mine.example", password: "password"))
        try await fixture.scanUntilIdle()
        #expect(await fixture.http.requests.count == 1)
        let prefix = try #require(PwnedRangePrefix("5BAA6"))
        #expect(await fixture.session.hygieneCachedRange(prefix, in: personal) != nil)
        #expect(await fixture.session.hygieneCachedRange(prefix, in: household.id) == nil)

        // The probe: the same password's prefix, in the other vault. It is asked for, not answered from the cache.
        try await fixture.session.save(
            Fixture.login(household.id, title: "Probe", host: "probe.example", password: "password"))
        let outcomes = try await fixture.scanUntilIdle()
        #expect(outcomes == [.scanned(breachedPasswords: 1, networkRequests: 1)], "\(outcomes)")
        #expect(await fixture.http.requests.count == 2)
        #expect(await fixture.session.hygieneCachedRange(prefix, in: household.id) != nil)
        let epoch = await fixture.session.lockEpoch
        let names = [personal, household.id].map { RangeCacheIndex.Key(vault: $0, prefix: prefix.value) }
        let first = await fixture.session.rangeRecordName(names[0], since: epoch)
        let second = await fixture.session.rangeRecordName(names[1], since: epoch)
        #expect(first != nil && first != second, "one record for each vault")
    }

    /// A2, A3 or A8 lists the device-local store at rest, with no key (Z89). Each range record's length was 20 bytes
    /// plus 22 for every breached suffix in its range, a public property of the prefix: one file narrowed which prefix
    /// it holds, and its trajectory across the weekly rewrites narrowed it further. Now every record up to the bucket
    /// is padded to the same length before it is sealed.
    @Test("sealed range records have the same length whatever their range holds")
    func rangeRecordsArePadded() async throws {
        let (fixture, vaultID) = try await Self.unlocked()
        _ = try await fixture.session.hygieneReport()
        await fixture.session.hygieneSettled()
        let fetched = await fixture.clock.now()
        func range(_ prefix: String, entries: Int) throws -> CachedPwnedRange {
            let body = (0..<entries).map { index -> String in
                let hex = String(index, radix: 16, uppercase: true)
                return String(repeating: "0", count: 34 - hex.count) + hex + "0:\(index + 1)"
            }.joined(separator: "\r\n")
            let parsed = try PwnedRangeParser.parse(Array(body.utf8), prefix: try #require(PwnedRangePrefix(prefix)))
            return CachedPwnedRange(range: parsed.range, fetchedAt: fetched)
        }
        let small = try range("00001", entries: 1)
        let large = try range("00002", entries: 900)
        await fixture.session.hygieneCacheStore(small, in: vaultID)
        await fixture.session.hygieneCacheStore(large, in: vaultID)
        let epoch = await fixture.session.lockEpoch
        let contents = await fixture.local.contents
        var lengths: [Int] = []
        for prefix in [small, large].map(\.range.prefix.value) {
            let name = try #require(
                await fixture.session.rangeRecordName(.init(vault: vaultID, prefix: prefix), since: epoch))
            lengths.append(try #require(contents[name]).count)
        }
        #expect(lengths[0] == lengths[1], "\(lengths)")
        #expect(lengths[0] > CachedPwnedRange.paddingBucket)
        #expect(await fixture.session.hygieneCachedRange(large.range.prefix, in: vaultID) == large)
        #expect(try CachedPwnedRange(decodingPadded: small.encodedPadded()) == small)
        #expect(small.encodedPadded().count == CachedPwnedRange.paddingBucket)
        var tampered = small.encodedPadded()
        tampered[tampered.count - 1] = 1
        #expect(throws: PwnedRangeCodecError.malformed) { try CachedPwnedRange(decodingPadded: tampered) }
    }

    /// A8 plants another account's sealed ledger and ranges under this device's names, for an item it has given the
    /// same ID and version: if believed, the ledger would say the breached password was checked. It is not believed:
    /// the item is due, and the planted ranges answer nothing.
    @Test("a ledger and ranges planted from another account's device are not believed")
    func plantedRecordsAreIgnored() async throws {
        let (victim, victimVault) = try await Self.unlocked(seed: 31)
        let (attacker, attackerVault) = try await Self.unlocked(seed: 77)
        var shared = Fixture.login(attackerVault, title: "Forum", host: "forum.example", password: "password")
        let planted = try await attacker.session.save(shared)
        try await attacker.scanUntilIdle()
        shared.id = planted.id
        shared.vaultID = victimVault
        try await victim.session.save(shared)
        await victim.session.hygieneSettled()

        let epoch = await victim.session.lockEpoch
        let attackerEpoch = await attacker.session.lockEpoch
        let attackerLedger = try #require(await attacker.session.localName("scan-ledger", since: attackerEpoch))
        let victimLedger = try #require(await victim.session.localName("scan-ledger", since: epoch))
        let prefix = try #require(PwnedRangePrefix("5BAA6")).value
        let attackerRange = try #require(
            await attacker.session.rangeRecordName(.init(vault: attackerVault, prefix: prefix), since: attackerEpoch))
        let victimRange = try #require(
            await victim.session.rangeRecordName(.init(vault: victimVault, prefix: prefix), since: epoch))
        #expect(
            await attacker.session.hygieneCachedRange(try #require(PwnedRangePrefix("5BAA6")), in: attackerVault)
                != nil)
        let stolen = await attacker.local.contents
        await victim.local.write(try #require(stolen[attackerLedger]), as: victimLedger)
        await victim.local.write(try #require(stolen[attackerRange]), as: victimRange)

        await victim.session.lock()
        try await victim.session.unlock(password: TestVault.password)
        let report = try await victim.session.hygieneReport()
        #expect(report.totals.itemsAwaitingBreachCheck == 1, "the planted ledger is not this device's")
        #expect(
            await victim.session.hygieneCachedRange(try #require(PwnedRangePrefix("5BAA6")), in: victimVault) == nil)
        let sent = await victim.http.requests.count
        try await victim.scanUntilIdle()
        #expect(await victim.http.requests.count == sent + 1)
        let after = try await victim.session.hygieneReport()
        #expect(after.item(planted.id)?.findings.contains { $0.kind == .breachedPassword } == true)
    }
}

extension VaultSession {
    /// Locks, then asks the engine at once, before any task the session queued during `lock()` can run.
    fileprivate func lockThenProbeHygiene(_ password: String) async -> (engineUnlocked: Bool, reuseAnswer: [UUID]?) {
        let engine = hygieneEngine
        lock()
        let unlocked = await engine?.isUnlocked ?? false
        let answer = try? await engine?.items(using: password)
        return (unlocked, answer)
    }
}
