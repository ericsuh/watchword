import Foundation
import Testing
import WatchwordGenerator
import WatchwordTestSupport

@testable import WatchwordAutoFill

@Suite("Site password rules")
struct PasswordRulesTests {
    @Test("parses the documented properties and classes")
    func parses() throws {
        let rules = try PasswordRules(
            parsing: "required: upper; required: lower; required: digit; allowed: [-().&@?'#,/\"+]; "
                + "max-consecutive: 2; minlength: 12; maxlength: 30;")
        #expect(rules.required == [PasswordRules.upper, PasswordRules.lower, PasswordRules.digit])
        #expect(rules.allowed == Set("-().&@?'#,/\"+"))
        #expect(rules.maxConsecutive == 2)
        #expect(rules.minLength == 12)
        #expect(rules.maxLength == 30)
    }

    @Test("a required property with several classes is satisfied by any of them")
    func requiredUnion() throws {
        let rules = try PasswordRules(parsing: "required: upper, digit; allowed: lower")
        #expect(rules.required == [PasswordRules.upper.union(PasswordRules.digit)])
        #expect(rules.isSatisfied(by: "abcD"))
        #expect(rules.isSatisfied(by: "abc4"))
        #expect(!rules.isSatisfied(by: "abcd"))
    }

    @Test("names are case-insensitive and whitespace is free")
    func lenientSpelling() throws {
        let rules = try PasswordRules(parsing: "  REQUIRED:Upper ;MinLength : 8;;  allowed:ascii-printable")
        #expect(rules.required == [PasswordRules.upper])
        #expect(rules.minLength == 8)
        #expect(rules.allowed == PasswordRules.printable)
    }

    @Test("a custom class may hold ], - and ; and the space is left out")
    func customClass() throws {
        #expect(try PasswordRules(parsing: "allowed: []-;:]").allowed == Set("]-;:"))
        #expect(try PasswordRules(parsing: "allowed: [a b]").allowed == Set("ab"))
        #expect(try PasswordRules(parsing: "required: [!]; allowed: lower").required == [Set("!")])
    }

    @Test("repeated length properties keep the stricter value")
    func repeatedLengths() throws {
        let rules = try PasswordRules(
            parsing: "minlength: 8; minlength: 14; maxlength: 40; maxlength: 32; max-consecutive: 3; max-consecutive: 2"
        )
        #expect(rules.minLength == 14)
        #expect(rules.maxLength == 32)
        #expect(rules.maxConsecutive == 2)
    }

    @Test("an empty string means no rules")
    func empty() throws {
        #expect(try PasswordRules(parsing: "") == PasswordRules())
        #expect(try PasswordRules(parsing: " ; ; ") == PasswordRules())
        #expect(PasswordRules().alphabet == PasswordRules.printable)
        #expect(!PasswordRules.printable.contains(" "))
        #expect(PasswordRules.printable.count == 94)
    }

    @Test(
        "anything outside the syntax is refused, not guessed at",
        arguments: [
            "required upper", "frobnicate: 3", "required: letters", "required: upper,", "required: , upper",
            "required: upper lower", "allowed: [abc", "allowed: [\u{00E9}]", "allowed: [\u{0007}]", "minlength: -1",
            "minlength: 0", "minlength: twelve", "minlength: 1e3", "maxlength: 99999999999999999999",
            "minlength: 1234567", "max-consecutive: 0", "minlength:", "required: upper; :",
        ])
    func malformed(_ text: String) {
        #expect(throws: PasswordRulesError.self) { try PasswordRules(parsing: text) }
    }

    @Test("an over-long rules string is refused before it is parsed")
    func tooLong() {
        let text = String(repeating: "allowed: lower; ", count: 200)
        #expect(throws: PasswordRulesError.tooLong) { try PasswordRules(parsing: text) }
    }

    @Test("a required property with no characters is unsatisfiable")
    func emptyRequired() {
        #expect(throws: PasswordRulesError.unsatisfiable) { try PasswordRules(parsing: "required: ;") }
        #expect(throws: PasswordRulesError.unsatisfiable) { try PasswordRules(parsing: "required: [ ]") }
    }

    // MARK: Mapping to the generator (PRD F3.1)

    @Test("no rules map to the default policy's shape")
    func defaultPolicy() throws {
        let policy = try PasswordRules().policy()
        #expect(policy.length == 20)
        #expect(policy.classes == .all)
        #expect(policy.requireEachClass)
        #expect(!policy.forbidRepeatedAdjacent)
        #expect(Set(policy.symbolSet) == PasswordRules.special)
    }

    @Test("whole classes map to classes and every other allowed character to the symbol set")
    func classMapping() throws {
        let policy = try PasswordRules(parsing: "required: lower; required: digit; allowed: [-_.]").policy()
        #expect(policy.classes == [.lowercase, .digits, .symbols])
        #expect(Set(policy.symbolSet) == Set("-_."))
        #expect(Set(try policy.alphabet()) == PasswordRules.lower.union(PasswordRules.digit).union(Set("-_.")))

        let partial = try PasswordRules(parsing: "allowed: [abc]; allowed: digit").policy()
        #expect(partial.classes == [.digits, .symbols])
        #expect(Set(partial.symbolSet) == Set("abc"))
    }

    @Test("the length moves inside the site's bounds")
    func lengthMapping() throws {
        #expect(try PasswordRules(parsing: "minlength: 32").policy().length == 32)
        #expect(try PasswordRules(parsing: "maxlength: 12").policy().length == 12)
        #expect(try PasswordRules(parsing: "minlength: 8; maxlength: 64").policy().length == 20)
        #expect(try PasswordRules(parsing: "minlength: 128").policy().length == 128)
        #expect(try PasswordRules(parsing: "maxlength: 4").policy().length == 4)
    }

    @Test(
        "rules the generator's own bounds cannot meet are refused",
        arguments: ["minlength: 129", "minlength: 999999", "maxlength: 3", "minlength: 30; maxlength: 20"])
    func unsatisfiableLengths(_ text: String) throws {
        let rules = try PasswordRules(parsing: text)
        #expect(throws: PasswordRulesError.unsatisfiable) { try rules.policy() }
    }

    @Test("any max-consecutive forbids adjacent repeats")
    func maxConsecutive() throws {
        #expect(try PasswordRules(parsing: "max-consecutive: 2").policy().forbidRepeatedAdjacent)
        let rules = try PasswordRules(parsing: "max-consecutive: 2; allowed: lower")
        #expect(rules.isSatisfied(by: "aabb"))
        #expect(!rules.isSatisfied(by: "aaab"))
    }

    @Test("isSatisfied checks alphabet, lengths and every required set")
    func satisfaction() throws {
        let rules = try PasswordRules(
            parsing: "required: upper; required: digit; allowed: lower; minlength: 6; maxlength: 8")
        #expect(rules.isSatisfied(by: "abcD12"))
        #expect(!rules.isSatisfied(by: "abcD1"))
        #expect(!rules.isSatisfied(by: "abcdD1234"))
        #expect(!rules.isSatisfied(by: "abcde1"))
        #expect(!rules.isSatisfied(by: "abcDEF"))
        #expect(!rules.isSatisfied(by: "abcD1!"))
        #expect(!rules.isSatisfied(by: "abcD1 "))
    }

    static let realWorldRules = [
        "",
        "minlength: 8; maxlength: 16; required: lower; required: upper; required: digit; allowed: [!#$%&*?@]",
        "minlength: 20; required: lower; required: upper; required: digit; required: [-];",
        "required: lower, upper; required: digit; max-consecutive: 2; minlength: 10; maxlength: 12",
        "allowed: digit; minlength: 6; maxlength: 6",
        "required: special; required: upper; minlength: 14",
        "required: [!]; required: [#]; allowed: lower; minlength: 24",
        "allowed: ascii-printable; minlength: 40; max-consecutive: 1",
    ]

    @Test("a generated password obeys the rules it was generated for", arguments: realWorldRules)
    func generatedPasswordsObey(_ text: String) async throws {
        let rules = try PasswordRules(parsing: text)
        for seed in 0..<UInt64(TestEnvironment.iterations(standard: 20, long: 400)) {
            let model = AutoFillHarness(seed: seed).model
            guard
                case .success(let generated) = await model.generatePassword(
                    for: GeneratePasswordRequest(passwordRules: text))
            else {
                Issue.record("no password for \(text) with seed \(seed)")
                continue
            }
            #expect(rules.isSatisfied(by: generated.password), "\(generated.password) breaks \(text)")
            #expect(try rules.policy() == generated.policy)
            #expect(generated.entropyBits == (try Entropy.bits(for: generated.policy)))
        }
    }
}
