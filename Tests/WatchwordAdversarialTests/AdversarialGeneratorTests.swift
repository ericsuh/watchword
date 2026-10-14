import Foundation
import Testing
@testable import WatchwordGenerator

@Suite("Adversarial: password generator", .tags(.adversarial))
struct AdversarialGeneratorTests {
    @Test("a degenerate RNG cannot make rejection sampling loop forever")
    func unsatisfiable() {
        struct Constant: RandomNumberGenerator {
            mutating func next() -> UInt64 { UInt64.max }
        }
        // A constant RNG always yields the same character, so "require each class" can never be
        // satisfied; the generator must give up after `maxAttempts` rather than spin.
        var generator = PasswordGenerator(rng: Constant())
        generator.maxAttempts = 100
        let policy = RandomPasswordPolicy(length: 8, classes: .all, requireEachClass: true)
        #expect(throws: PasswordGenerationError.unsatisfiablePolicy) { try generator.generate(policy) }
    }

    @Test("a one-character alphabet with no-repeat cannot produce a multi-character password")
    func oneCharacterAlphabet() {
        var generator = PasswordGenerator()
        let policy = RandomPasswordPolicy(
            length: 8, classes: .symbols, symbolSet: "!", requireEachClass: false, forbidRepeatedAdjacent: true)
        #expect(throws: PasswordGenerationError.unsatisfiablePolicy) { try generator.generate(policy) }
    }

    @Test("length outside the allowed range is rejected", arguments: [Int.min, -1, 0, 3, 129, Int.max])
    func badLength(_ length: Int) {
        var generator = PasswordGenerator()
        #expect(throws: PasswordGenerationError.lengthOutOfRange(RandomPasswordPolicy.lengthRange)) {
            try generator.generate(RandomPasswordPolicy(length: length))
        }
    }

    @Test("no character classes is rejected")
    func noClasses() {
        var generator = PasswordGenerator()
        #expect(throws: PasswordGenerationError.noCharacterClasses) {
            try generator.generate(RandomPasswordPolicy(length: 12, classes: []))
        }
    }

    @Test("symbols-only with an empty symbol set is rejected, not an empty alphabet crash")
    func emptySymbolSet() {
        var generator = PasswordGenerator()
        #expect(throws: PasswordGenerationError.noCharacterClasses) {
            try generator.generate(RandomPasswordPolicy(length: 12, classes: .symbols, symbolSet: ""))
        }
    }

    @Test("a biased RNG cannot make the generator emit characters outside the alphabet")
    func hostileRNG() throws {
        struct AllOnes: RandomNumberGenerator {
            mutating func next() -> UInt64 { UInt64.max }
        }
        var generator = PasswordGenerator(rng: AllOnes())
        let policy = RandomPasswordPolicy(length: 16, classes: .digits, requireEachClass: false)
        let password = try generator.generate(policy)
        #expect(password.allSatisfy { $0.isNumber })
    }

    @Test("entropy estimate never exceeds the unconstrained bound")
    func entropyBound() throws {
        let free = try Entropy.bits(for: RandomPasswordPolicy(length: 16, classes: .all, requireEachClass: false))
        for requireEach in [false, true] {
            for noRepeat in [false, true] {
                let policy = RandomPasswordPolicy(
                    length: 16, classes: .all, requireEachClass: requireEach, forbidRepeatedAdjacent: noRepeat)
                let bits = try Entropy.bits(for: policy)
                #expect(bits <= free + 1e-9)
                #expect(bits > 0)
            }
        }
    }
}
