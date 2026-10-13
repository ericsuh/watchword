import Foundation
import Testing
@testable import WatchwordGenerator

@Suite("Random password generation")
struct PasswordGeneratorTests {
    @Test("produces the requested length", arguments: [4, 8, 16, 20, 64, 128])
    func length(_ length: Int) throws {
        var generator = PasswordGenerator(rng: SeededGenerator(seed: 1))
        let password = try generator.generate(RandomPasswordPolicy(length: length))
        #expect(password.count == length)
    }

    static let classCombinations: [CharacterClasses] = [
        .lowercase,
        [.lowercase, .uppercase],
        [.digits],
        [.uppercase, .digits, .symbols],
        .all,
    ]

    @Test("uses only the selected classes", arguments: classCombinations)
    func classesRespected(_ classes: CharacterClasses) throws {
        var generator = PasswordGenerator(rng: SeededGenerator(seed: 2))
        let policy = RandomPasswordPolicy(length: 32, classes: classes, requireEachClass: false)
        let alphabet = Set(try policy.alphabet())
        for _ in 0..<50 {
            let password = try generator.generate(policy)
            #expect(password.allSatisfy { alphabet.contains($0) })
        }
    }

    @Test("requireEachClass guarantees every class appears")
    func requireEachClass() throws {
        var generator = PasswordGenerator(rng: SeededGenerator(seed: 3))
        let policy = RandomPasswordPolicy(length: 4, classes: .all, requireEachClass: true)
        for _ in 0..<200 {
            let password = try generator.generate(policy)
            #expect(password.contains { $0.isLowercase })
            #expect(password.contains { $0.isUppercase })
            #expect(password.contains { $0.isNumber })
            #expect(password.contains { policy.symbolSet.contains($0) })
        }
    }

    @Test("excludeAmbiguous removes l 1 I O 0 |")
    func excludeAmbiguous() throws {
        var generator = PasswordGenerator(rng: SeededGenerator(seed: 4))
        let policy = RandomPasswordPolicy(
            length: 128, classes: .all, symbolSet: "|!", excludeAmbiguous: true, requireEachClass: false)
        for _ in 0..<20 {
            let password = try generator.generate(policy)
            #expect(!password.contains { RandomPasswordPolicy.ambiguousCharacters.contains($0) })
        }
    }

    @Test("forbidRepeatedAdjacent never emits a doubled character")
    func noRepeats() throws {
        var generator = PasswordGenerator(rng: SeededGenerator(seed: 5))
        let policy = RandomPasswordPolicy(
            length: 64, classes: .digits, requireEachClass: false, forbidRepeatedAdjacent: true)
        for _ in 0..<100 {
            let password = Array(try generator.generate(policy))
            for i in 1..<password.count {
                #expect(password[i] != password[i - 1])
            }
        }
    }

    @Test("same seed gives same password; different seeds differ")
    func determinismOfInjectedRNG() throws {
        var a = PasswordGenerator(rng: SeededGenerator(seed: 42))
        var b = PasswordGenerator(rng: SeededGenerator(seed: 42))
        var c = PasswordGenerator(rng: SeededGenerator(seed: 43))
        let policy = RandomPasswordPolicy(length: 24)
        let fromA = try a.generate(policy)
        let fromB = try b.generate(policy)
        let fromC = try c.generate(policy)
        #expect(fromA == fromB)
        #expect(fromA != fromC)
    }

    @Test("system generator produces distinct passwords")
    func systemGenerator() throws {
        var generator = PasswordGenerator()
        let first = try generator.generate(RandomPasswordPolicy(length: 32))
        let second = try generator.generate(RandomPasswordPolicy(length: 32))
        #expect(first != second)
    }

    @Test("character distribution is roughly uniform (chi-square)")
    func uniformity() throws {
        var generator = PasswordGenerator(rng: SeededGenerator(seed: 6))
        let policy = RandomPasswordPolicy(length: 100, classes: .digits, requireEachClass: false)
        var counts = [Character: Int]()
        let samples = 2_000
        for _ in 0..<samples {
            for ch in try generator.generate(policy) {
                counts[ch, default: 0] += 1
            }
        }
        let total = Double(samples * policy.length)
        let expected = total / 10
        let chiSquare = counts.values.reduce(0.0) { $0 + pow(Double($1) - expected, 2) / expected }
        // 9 degrees of freedom; 27.88 is the 0.001 critical value.
        #expect(chiSquare < 27.88, "chi-square \(chiSquare) suggests bias")
        #expect(counts.count == 10)
    }
}

@Suite("Passphrases and PINs")
struct PassphraseTests {
    static let words = ["correct", "horse", "battery", "staple", "orbit", "velvet", "canyon", "quartz"]

    @Test("word count and separator are honoured", arguments: [3, 5, 10])
    func passphrase(_ count: Int) throws {
        var generator = PasswordGenerator(rng: SeededGenerator(seed: 7))
        let policy = PassphrasePolicy(wordCount: count, separator: ".")
        let phrase = try generator.generatePassphrase(policy, wordlist: Self.words)
        let parts = phrase.split(separator: ".")
        #expect(parts.count == count)
        #expect(parts.allSatisfy { Self.words.contains(String($0)) })
    }

    @Test("capitalisation and trailing digit")
    func decorations() throws {
        var generator = PasswordGenerator(rng: SeededGenerator(seed: 8))
        let policy = PassphrasePolicy(wordCount: 4, separator: "-", capitalizeWords: true, appendDigit: true)
        let phrase = try generator.generatePassphrase(policy, wordlist: Self.words)
        #expect(phrase.last?.isNumber == true)
        let parts = phrase.dropLast().split(separator: "-")
        #expect(parts.allSatisfy { $0.first?.isUppercase == true })
    }

    @Test("PIN digits", arguments: [4, 6, 12])
    func pin(_ digits: Int) throws {
        var generator = PasswordGenerator(rng: SeededGenerator(seed: 9))
        let pin = try generator.generatePIN(digits: digits)
        #expect(pin.count == digits)
        #expect(pin.allSatisfy(\.isNumber))
    }

    @Test("empty wordlist is an error")
    func emptyWordlist() {
        var generator = PasswordGenerator(rng: SeededGenerator(seed: 10))
        #expect(throws: PasswordGenerationError.emptyWordlist) {
            try generator.generatePassphrase(PassphrasePolicy(), wordlist: [])
        }
    }
}

@Suite("Entropy estimates")
struct EntropyTests {
    @Test("unconstrained random mode is length × log2(alphabet)")
    func unconstrained() throws {
        let policy = RandomPasswordPolicy(length: 20, classes: [.lowercase, .digits], requireEachClass: false)
        let bits = try Entropy.bits(for: policy)
        #expect(abs(bits - 20 * log2(36)) < 1e-9)
    }

    @Test("requiring each class lowers the estimate slightly, never raises it")
    func requireEachLowers() throws {
        let freePolicy = RandomPasswordPolicy(length: 12, classes: .all, requireEachClass: false)
        let constrainedPolicy = RandomPasswordPolicy(length: 12, classes: .all, requireEachClass: true)
        let free = try Entropy.bits(for: freePolicy)
        let constrained = try Entropy.bits(for: constrainedPolicy)
        #expect(constrained < free)
        #expect(free - constrained < 1.0)
    }

    @Test("passphrase entropy with EFF-sized list")
    func passphrase() {
        let bits = Entropy.bits(for: PassphrasePolicy(wordCount: 5), wordlistCount: 7776)
        #expect(abs(bits - 5 * log2(7776)) < 1e-9)
        #expect(bits > Entropy.warningThresholdBits)
    }

    @Test("PIN entropy")
    func pin() {
        #expect(abs(Entropy.bits(forPINDigits: 6) - 6 * log2(10)) < 1e-9)
    }
}
