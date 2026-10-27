import Foundation
import Testing
import WatchwordTestSupport

@testable import SecureMemory

@Suite("Secure bytes")
struct SecureBytesTests {
    @Test("holds exactly the bytes it was given")
    func copying() {
        let bytes = SecureBytes(copying: [1, 2, 3, 4, 5])
        #expect(bytes.count == 5)
        #expect(Array(bytes) == [1, 2, 3, 4, 5])
        #expect(bytes[4] == 5)
    }

    @Test("zeroise wipes the whole allocation and marks the buffer zeroised")
    func zeroiseWipes() {
        let bytes = SecureBytes(copying: [UInt8](repeating: 0xA5, count: 64))
        #expect(!bytes.storageIsAllZero())
        bytes.zeroise()
        #expect(bytes.isZeroised)
        #expect(bytes.storageIsAllZero())
        bytes.zeroise()
        #expect(bytes.storageIsAllZero(), "zeroise is idempotent")
    }

    @Test("deinit wipes storage before the memory is released")
    func deinitWipes() {
        let probe = ZeroisationProbe()
        do {
            let bytes = SecureBytes(copying: [UInt8](repeating: 0xFF, count: 32), zeroisationProbe: probe)
            #expect(!bytes.storageIsAllZero())
            #expect(probe.observedAllZeroAtRelease == nil)
        }
        #expect(probe.observedAllZeroAtRelease == true)
    }

    @Test(
        "storage is page-aligned and a whole number of pages, so mlock never shares a page",
        arguments: [0, 1, 32, SecureBytes.pageSize, SecureBytes.pageSize + 1])
    func pageIsolation(_ count: Int) {
        let bytes = SecureBytes(count: count)
        #expect(bytes.storageIsPageIsolated)
        #expect(bytes.count == count)
    }

    @Test("init(wiping:) clears the caller's array")
    func wipingArray() {
        var source: [UInt8] = [9, 8, 7, 6]
        let bytes = SecureBytes(wiping: &source)
        #expect(source == [0, 0, 0, 0])
        #expect(Array(bytes) == [9, 8, 7, 6])
    }

    @Test("init(wiping:) clears the caller's Data")
    func wipingData() {
        var source = Data([9, 8, 7, 6])
        let bytes = SecureBytes(wiping: &source)
        #expect(source == Data([0, 0, 0, 0]))
        #expect(Array(bytes) == [9, 8, 7, 6])
    }

    @Test("random bytes come from the injected generator, little-endian per word")
    func randomUsesInjectedGenerator() {
        var reference = SeededGenerator(seed: 42)
        let first = reference.next()
        let second = reference.next()
        let expected =
            (0..<8).map { UInt8(truncatingIfNeeded: first >> (8 * $0)) }
            + (0..<4).map { UInt8(truncatingIfNeeded: second >> (8 * $0)) }

        var generator = SeededGenerator(seed: 42)
        #expect(Array(SecureBytes(randomCount: 12, using: &generator)) == expected)

        var other = SeededGenerator(seed: 43)
        #expect(Array(SecureBytes(randomCount: 12, using: &other)) != expected)
    }

    @Test("concatenating and extracting preserve contents")
    func concatenateAndExtract() {
        let joined = SecureBytes.concatenating([
            SecureBytes(copying: [1, 2]), SecureBytes(count: 0), SecureBytes(copying: [3, 4, 5]),
        ])
        #expect(Array(joined) == [1, 2, 3, 4, 5])
        #expect(Array(joined.extracting(1..<4)) == [2, 3, 4])
        #expect(joined.extracting(2..<2).isEmpty)
    }

    @Test("constant-time equality compares contents, including the last byte")
    func constantTimeEquality() {
        let a = SecureBytes(copying: [1, 2, 3, 4])
        #expect(a.constantTimeEquals(a))
        #expect(a.constantTimeEquals(SecureBytes(copying: [1, 2, 3, 4])))
        #expect(!a.constantTimeEquals(SecureBytes(copying: [1, 2, 3, 5])))
        #expect(!a.constantTimeEquals(SecureBytes(copying: [1, 2, 3])))
    }

    @Test(
        "ConstantTime.equal agrees with ==",
        arguments: zip(
            [[UInt8](), [1], [1, 2, 3], [1, 2, 3], [0xFF, 0]],
            [[UInt8](), [1], [1, 2, 3], [1, 2, 4], [0xFF]]
        ))
    func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) {
        #expect(ConstantTime.equal(a, b) == (a == b))
    }

    @Test("printing, interpolation and dump never show the contents")
    func redacted() {
        let bytes = SecureBytes(copying: [0xDE, 0xAD, 0xBE, 0xEF])
        var dumped = ""
        dump(bytes, to: &dumped)
        for text in [bytes.description, bytes.debugDescription, "\(bytes)", String(reflecting: bytes), dumped] {
            for leak in ["dead", "beef", "222", "173", "190", "239"] {
                #expect(!text.lowercased().contains(leak), "contents leaked into: \(text)")
            }
        }
        #expect(bytes.description == "SecureBytes(4 bytes, redacted)")
    }
}

@Suite("Secure bytes: misuse traps and copy-out")
struct SecureBytesMisuseTests {
    @Test("unprotectedCopy is the named way out")
    func unprotectedCopy() {
        #expect(SecureBytes(copying: [7, 8, 9]).unprotectedCopy() == [7, 8, 9])
    }

    // Exit tests need Swift 6.2; on older toolchains the traps are covered by review only.
    #if compiler(>=6.2)
        @Test("reading after zeroise traps rather than returning zeros")
        func readAfterZeroiseTraps() async {
            await #expect(processExitsWith: .failure) {
                let bytes = SecureBytes(copying: [1, 2, 3])
                bytes.zeroise()
                _ = bytes[0]
            }
        }

        /// Review finding R7: the lock is recursive, so a same-thread zeroise inside a read must trap, not wipe.
        @Test("zeroising during a read on the same thread traps")
        func zeroiseDuringReadTraps() async {
            await #expect(processExitsWith: .failure) {
                let bytes = SecureBytes(copying: [1, 2, 3])
                bytes.withUnsafeBytes { _ in bytes.zeroise() }
            }
        }
    #endif
}

@Suite("Nonce ledger")
struct NonceLedgerTests {
    @Test("a nonce is fresh once, then reused; distinct nonces are independent")
    func claims() {
        let ledger = NonceLedger()
        let nonce = [UInt8](repeating: 0xAB, count: 12)
        #expect(ledger.claim(nonce) == .fresh)
        #expect(ledger.claim(nonce) == .reused)
        var other = nonce
        other[11] ^= 1
        #expect(ledger.claim(other) == .fresh)
        other[0] ^= 1
        #expect(ledger.claim(other) == .fresh, "every byte is part of the identity")
        #expect(ledger.count == 3)
    }

    @Test("concurrent claims of one nonce succeed exactly once")
    func concurrentClaims() async {
        let ledger = NonceLedger()
        let nonce = [UInt8](repeating: 1, count: 12)
        let fresh = await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<64 {
                group.addTask { ledger.claim(nonce) == .fresh }
            }
            return await group.reduce(0) { $0 + ($1 ? 1 : 0) }
        }
        #expect(fresh == 1)
    }
}

#if canImport(CryptoKit) || os(Linux)
    #if canImport(CryptoKit)
        import CryptoKit
    #else
        import Crypto
    #endif

    @Suite("Secure bytes: CryptoKit bridging")
    struct SecureBytesCryptoKitTests {
        @Test("SymmetricKey round-trips through SecureBytes")
        func symmetricKeyRoundTrip() {
            let key = SymmetricKey(data: Array(0..<32) as [UInt8])
            let secure = SecureBytes(copying: key)
            #expect(Array(secure) == Array(0..<32))
            #expect(secure.symmetricKey == key)
        }
    }
#endif

#if canImport(CommonCrypto) || os(Linux)
    @Suite("PBKDF2-HMAC-SHA256 known answers")
    struct PBKDF2Tests {
        /// RFC 7914 §11, cross-checked against Python's `hashlib.pbkdf2_hmac`.
        @Test(
            "matches the RFC 7914 vectors",
            arguments: [
                (
                    "passwd", "salt", UInt32(1),
                    "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
                        + "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
                ),
                (
                    "Password", "NaCl", UInt32(80_000),
                    "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
                        + "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
                ),
            ])
        func knownAnswers(_ password: String, _ salt: String, _ iterations: UInt32, _ expected: String) throws {
            let derived = try PBKDF2.sha256(
                password: SecureBytes(copying: Array(password.utf8)),
                salt: Array(salt.utf8),
                iterations: iterations,
                outputByteCount: 64
            )
            #expect(Array(derived) == [UInt8](hex: expected))
        }

        @Test("rejects zero iterations, an empty salt and an empty output")
        func invalidParameters() {
            let password = SecureBytes(copying: [1])
            #expect(throws: PBKDF2.Failure.invalidParameters) {
                try PBKDF2.sha256(password: password, salt: [1], iterations: 0, outputByteCount: 32)
            }
            #expect(throws: PBKDF2.Failure.invalidParameters) {
                try PBKDF2.sha256(password: password, salt: [], iterations: 1, outputByteCount: 32)
            }
            #expect(throws: PBKDF2.Failure.invalidParameters) {
                try PBKDF2.sha256(password: password, salt: [1], iterations: 1, outputByteCount: 0)
            }
        }
    }
#endif
