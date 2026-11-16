import Foundation
import Testing
import WatchwordCrypto
import WatchwordTestSupport

@Suite("Forked generator")
struct ForkedGeneratorTests {
    /// Expected words from Python's `hmac` and `hashlib` (HMAC-SHA-256 of the little-endian counter under the four
    /// drawn words, little-endian), never from this code.
    @Test("words are HMAC-SHA-256 of a counter under four words drawn from the parent")
    func knownAnswer() {
        var parent = RepeatingGenerator(words: [
            0x0706_0504_0302_0100, 0x0F0E_0D0C_0B0A_0908, 0x1716_1514_1312_1110, 0x1F1E_1D1C_1B1A_1918,
        ])
        var fork = ForkedGenerator(forkingFrom: &parent)
        let expected: [UInt64] = [
            0x49FE_9740_B9D9_0C9F, 0x44B3_4289_2B8D_9129, 0x01C5_5DA3_6142_5739, 0x9988_E4D4_676C_F063,
            0x2299_7A3F_4E5D_343B, 0xA346_9C4F_7C2F_94D8, 0xF902_1CEB_4B68_0763, 0x1716_8EBE_2793_BA8D,
        ]
        #expect((0..<8).map { _ in fork.next() } == expected)
    }

    /// The reason it exists: a copy of a seeded generator replays the parent's own stream, so work given a copy would
    /// draw the identifiers the session draws next. A fork's stream is neither the parent's nor another fork's, and
    /// is as reproducible as the parent.
    @Test("a fork does not replay its parent or a sibling, and is reproducible under a seeded parent")
    func independentStreams() {
        var parent = SeededGenerator(seed: 77)
        var first = ForkedGenerator(forkingFrom: &parent)
        var second = ForkedGenerator(forkingFrom: &parent)
        let a = (0..<64).map { _ in first.next() }
        let b = (0..<64).map { _ in second.next() }
        let rest = (0..<64).map { _ in parent.next() }
        #expect(Set(a).isDisjoint(with: b) && Set(a).isDisjoint(with: rest) && Set(b).isDisjoint(with: rest))
        var again = SeededGenerator(seed: 77)
        var replay = ForkedGenerator(forkingFrom: &again)
        #expect((0..<64).map { _ in replay.next() } == a)
    }
}
