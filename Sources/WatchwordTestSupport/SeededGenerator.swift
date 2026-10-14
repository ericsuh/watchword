/// SplitMix64: deterministic generator for tests only. Never used in production code.
public struct SeededGenerator: RandomNumberGenerator, Sendable {
    private var state: UInt64

    public init(seed: UInt64) {
        state = seed
    }

    public mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// A broken generator that cycles through a fixed list of words: the fault the record sealer's nonce guard exists to
/// catch (docs/04-test-plan.md §6.1).
public struct RepeatingGenerator: RandomNumberGenerator, Sendable {
    private let words: [UInt64]
    private var index = 0

    public init(words: [UInt64]) {
        precondition(!words.isEmpty)
        self.words = words
    }

    public mutating func next() -> UInt64 {
        defer { index = (index + 1) % words.count }
        return words[index]
    }
}
