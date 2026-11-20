import Foundation
import Testing

@testable import SecureMemory

// Review finding Z126 (docs/06-adversarial-review.md): the copy a Keychain write hands the Security framework.
extension AdversarialCryptoTests {
    /// Threat: A8 with a memory image of the Mac after the vault locked, looking for the Local Unlock Key, the Secret
    /// Key or the device seed. The Keychain write made one `Data` from the secret, put it in the query dictionary
    /// (boxed, then bridged to `CFData` sharing its storage) and wiped it with `resetBytes` afterwards: if anything
    /// kept a reference past `SecItemAdd`, that wipe copied the buffer first and zeroed the copy, leaving the secret
    /// where it was. A reference type written through in place has no such escape: whoever kept the object sees the
    /// zeros. What the framework copies internally stays beyond reach (§11).
    @Test("a secret's mutable-data copy is zeroed in the object itself, whoever kept a reference to it")
    func mutableDataCopyIsZeroedWhereverRetained() {
        let secret = SecureBytes(copying: [UInt8](repeating: 0xA5, count: 48))
        var retained: NSMutableData?
        let seen = secret.withMutableDataCopy { data -> [UInt8] in
            retained = data
            return [UInt8](Data(referencing: data))
        }
        #expect(seen == [UInt8](repeating: 0xA5, count: 48))
        let kept = retained.map { [UInt8](Data(referencing: $0)) }
        #expect(kept == [UInt8](repeating: 0, count: 48), "the retained object still holds the secret")
        #expect(secret.unprotectedCopy() == [UInt8](repeating: 0xA5, count: 48), "the protected original is untouched")

        // The shape of the old wipe: a `Data` whose buffer another reference holds is copied before it is zeroed.
        var data = Data(repeating: 0xA5, count: 4)
        let other = data
        data.resetBytes(in: data.startIndex..<data.endIndex)
        #expect(other == Data(repeating: 0xA5, count: 4))
        // An empty secret gives an empty copy.
        #expect(SecureBytes(count: 0).withMutableDataCopy { $0.length } == 0)
    }
}
