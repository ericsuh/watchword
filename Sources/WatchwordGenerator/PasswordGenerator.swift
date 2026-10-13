import Foundation

/// Generates passwords, passphrases and PINs from an injected random number generator.
///
/// Production code uses `SystemRandomNumberGenerator` (the OS CSPRNG). Tests inject a seeded
/// generator for determinism. All sampling goes through `Int.random(in:using:)`, which is
/// unbiased; constraints are enforced by rejection so the output stays uniform over the
/// accepted set (architecture §12).
public struct PasswordGenerator<RNG: RandomNumberGenerator> {
    public var rng: RNG
    /// Upper bound on rejection-sampling attempts before giving up (guards against pathological policies).
    public var maxAttempts: Int = 10_000

    public init(rng: RNG) {
        self.rng = rng
    }

    public mutating func generate(_ policy: RandomPasswordPolicy) throws -> String {
        try policy.validate()
        let alphabet = try policy.alphabet()
        let requiredClasses = policy.requireEachClass
            ? policy.classes.members.map { Set(policy.characters(in: $0)) }.filter { !$0.isEmpty }
            : []

        for _ in 0..<maxAttempts {
            var chars: [Character] = []
            chars.reserveCapacity(policy.length)
            while chars.count < policy.length {
                let ch = alphabet[Int.random(in: 0..<alphabet.count, using: &rng)]
                if policy.forbidRepeatedAdjacent, let last = chars.last, last == ch {
                    continue  // redraw; uniform over the allowed next characters
                }
                chars.append(ch)
            }
            let satisfied = requiredClasses.allSatisfy { cls in chars.contains { cls.contains($0) } }
            if satisfied {
                return String(chars)
            }
        }
        throw PasswordGenerationError.unsatisfiablePolicy
    }

    public mutating func generatePIN(digits: Int) throws -> String {
        guard (4...12).contains(digits) else { throw PasswordGenerationError.lengthOutOfRange(4...12) }
        var out = ""
        for _ in 0..<digits {
            out.append(String(Int.random(in: 0...9, using: &rng)))
        }
        return out
    }

    public mutating func generatePassphrase(_ policy: PassphrasePolicy, wordlist: [String]) throws -> String {
        guard PassphrasePolicy.wordCountRange.contains(policy.wordCount) else {
            throw PasswordGenerationError.lengthOutOfRange(PassphrasePolicy.wordCountRange)
        }
        guard !wordlist.isEmpty else { throw PasswordGenerationError.emptyWordlist }
        var words: [String] = []
        for _ in 0..<policy.wordCount {
            var word = wordlist[Int.random(in: 0..<wordlist.count, using: &rng)]
            if policy.capitalizeWords, let first = word.first {
                word = String(first).uppercased() + word.dropFirst()
            }
            words.append(word)
        }
        var phrase = words.joined(separator: policy.separator)
        if policy.appendDigit {
            phrase += String(Int.random(in: 0...9, using: &rng))
        }
        return phrase
    }
}

extension PasswordGenerator where RNG == SystemRandomNumberGenerator {
    public init() {
        self.init(rng: SystemRandomNumberGenerator())
    }
}
