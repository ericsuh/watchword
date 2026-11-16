import Foundation
import SecureMemory
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordHygiene
import WatchwordModel
import WatchwordTestSupport

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
/// - **Another device of the account, or another account on the same device** (A4 at its strongest: it holds a
///   keyset): its sealed records must not open as this device's, so it can neither read this device's ledger nor
///   hand it one that says a breached password was checked and found clear.
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
        #expect(await fixture.session.hygieneCachedRange(prefix) != nil)
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
        #expect(await fixture.session.hygieneCachedRange(prefix) == nil)

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
        #expect(await session.hygieneCachedRange(try #require(PwnedRangePrefix("5BAA6"))) == nil)
        let sent = await fixture.http.requests.count
        try await fixture.scanUntilIdle()
        #expect(await fixture.http.requests.count == sent + 1, "asked for again, not answered from a cache")
    }

    /// Another device of the same account holds the same keyset: the device-local key it derives is a different
    /// key, under a different key ID, so a record sealed here neither opens there nor is accepted here from there.
    @Test("a sealed local record does not open under another device's key, or another account's")
    func localKeyIsPerDevice() throws {
        let accountID = UUID()
        let keyset = Keyset.generate(accountID: accountID)
        let other = Keyset.generate(accountID: UUID())
        let thisDevice = UUID()
        let here = DeviceLocalKeys.deviceLocalKey(keyset: keyset, deviceID: thisDevice)
        let there = DeviceLocalKeys.deviceLocalKey(keyset: keyset, deviceID: UUID())
        let elsewhere = DeviceLocalKeys.deviceLocalKey(keyset: other, deviceID: thisDevice)
        #expect(here.keyID != there.keyID && here.keyID != elsewhere.keyID)
        // Derived again, the same key: the ledger survives a relaunch and a password change (the keyset is kept).
        #expect(DeviceLocalKeys.deviceLocalKey(keyset: keyset, deviceID: thisDevice).keyID == here.keyID)
        let reuse = DeviceLocalKeys.hygieneReuseKey(keyset: keyset)
        #expect(reuse.unprotectedCopy() != keyset.symmetricKey.material.unprotectedCopy(), "never the raw key")

        let name = DeviceLocalKeys.recordName("scan-ledger", key: here)
        #expect(DeviceLocalKeys.recordName("scan-ledger", key: there) != name)
        let sealed = try RecordCipher.seal(
            Array("{\"entries\":[]}".utf8),
            context: VaultSession.localContext(name: name, accountID: accountID, key: here), key: here)
        for key in [there, elsewhere] {
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

        let epoch = await victim.session.lockEpoch
        let attackerEpoch = await attacker.session.lockEpoch
        let attackerLedger = try #require(await attacker.session.localName("scan-ledger", since: attackerEpoch))
        let victimLedger = try #require(await victim.session.localName("scan-ledger", since: epoch))
        let prefix = try #require(PwnedRangePrefix("5BAA6")).value
        let prefixBytes = [UInt8(prefix >> 16 & 0xFF), UInt8(prefix >> 8 & 0xFF), UInt8(prefix & 0xFF)]
        let attackerRange = try #require(
            await attacker.session.localName("range", prefixBytes, since: attackerEpoch))
        let victimRange = try #require(await victim.session.localName("range", prefixBytes, since: epoch))
        #expect(await attacker.session.hygieneCachedRange(try #require(PwnedRangePrefix("5BAA6"))) != nil)
        let stolen = await attacker.local.contents
        await victim.local.write(try #require(stolen[attackerLedger]), as: victimLedger)
        await victim.local.write(try #require(stolen[attackerRange]), as: victimRange)

        await victim.session.lock()
        try await victim.session.unlock(password: TestVault.password)
        let report = try await victim.session.hygieneReport()
        #expect(report.totals.itemsAwaitingBreachCheck == 1, "the planted ledger is not this device's")
        #expect(await victim.session.hygieneCachedRange(try #require(PwnedRangePrefix("5BAA6"))) == nil)
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
