import Foundation
import Testing
import WatchwordGenerator
import WatchwordTestSupport

@testable import WatchwordHygiene

/// PRD F9.3: the estimator on passwords everyone agrees are weak, on ones everyone agrees are strong, and on its
/// own bounds (docs/04-test-plan.md §6.6).
@Suite("Strength estimator")
struct StrengthEstimatorTests {
    static let estimator = StrengthEstimator(referenceYear: 2026)

    @Test(
        "passwords from every attacker's first page are very weak",
        arguments: [
            "password", "123456", "12345678", "qwerty", "abc123", "letmein", "iloveyou", "monkey", "dragon",
            "111111", "qwertyuiop", "1qaz2wsx", "football", "PASSWORD", "Password", "drowssap", "P@ssw0rd",
            "aaaaaaaaaaaa", "abcabcabcabc", "abcdefgh", "87654321", "a", "zz",
        ])
    func veryWeak(_ password: String) {
        let assessment = Self.estimator.assess(password)
        #expect(assessment.score == .veryWeak)
        #expect(assessment.weakness != nil)
    }

    @Test(
        "predictable variations are still weak",
        arguments: [
            "summer2019", "john1985", "01/02/1990", "19900102", "monkey123", "Sunshine!", "zxcvbnm,./",
            "asdfghjkl;'", "iloveyou2", "michael1", "Dragon99", "p4ssw0rd!", "kT9$",
        ])
    func weak(_ password: String) {
        let assessment = Self.estimator.assess(password)
        #expect(assessment.score <= .weak)
        #expect(assessment.weakness != nil)
        #expect(!assessment.explanation.isEmpty)
    }

    @Test(
        "long random strings and multi-word passphrases are very strong",
        arguments: [
            "x7#Vq9!mLp2$Zr8@Wn4&", "rWibMFACxAUGZmxhVncy", "correct horse battery staple",
            "abacus-zoom-unripe-rotting-yelp", "Kq2-vd9!-ZmP4-x7Lr", "8fGh#2kLm9$pQrS5tUv",
        ])
    func veryStrong(_ password: String) {
        let assessment = Self.estimator.assess(password)
        #expect(assessment.score == .veryStrong)
        #expect(assessment.weakness == nil)
        #expect(assessment.guessesLog10 > 10)
    }

    @Test("generated random passwords of twenty characters are always very strong")
    func generatedPasswords() throws {
        var generator = PasswordGenerator(rng: SeededGenerator(seed: TestEnvironment.seed(fallback: 0xC0FFEE)))
        for _ in 0..<TestEnvironment.iterations(standard: 200, long: 5000) {
            let password = try generator.generate(RandomPasswordPolicy(length: 20))
            #expect(Self.estimator.assess(password).score == .veryStrong)
        }
    }

    @Test("a passphrase of n EFF words costs about 7776^n guesses, and five words are very strong")
    func generatedPassphrases() throws {
        let words = EmbeddedWordLists.effLargeWordlist.split(separator: "\n").map(String.init)
        var generator = PasswordGenerator(rng: SeededGenerator(seed: TestEnvironment.seed(fallback: 42)))
        for _ in 0..<TestEnvironment.iterations(standard: 100, long: 2000) {
            let phrase = try generator.generatePassphrase(PassphrasePolicy(wordCount: 5), wordlist: words)
            let assessment = Self.estimator.assess(phrase)
            #expect(assessment.score == .veryStrong)
            // At least the entropy the generator itself reports (64.6 bits is 19.4 decimal digits); the search may
            // find a cheaper reading of some words but never one below the uniform cost of four of them.
            #expect(assessment.guessesLog10 > 4 * log10(7776.0))
        }
        let one = Self.estimator.assess("unripe")
        #expect(abs(one.guessesLog10 - log10(7776.0 + 1)) < 0.01)
        #expect(one.weakness == .dictionaryWord)
    }

    @Test("the embedded lists are what their headers say")
    func wordLists() {
        func lines(_ text: String) -> [String] { text.split(separator: "\n").map(String.init) }
        let eff = lines(EmbeddedWordLists.effLargeWordlist)
        #expect(eff.count == 7776)
        #expect(Set(eff).count == 7776)
        #expect(eff.first == "abacus")
        #expect(eff.last == "zoom")
        #expect(eff == eff.sorted())
        let passwords = lines(EmbeddedWordLists.commonPasswords)
        #expect(passwords.count == 10_000)
        #expect(Array(passwords.prefix(4)) == ["123456", "password", "12345678", "qwerty"])
        #expect(lines(EmbeddedWordLists.englishWords).count == 5000)
        #expect(lines(EmbeddedWordLists.surnames).count == 500)
        #expect(lines(EmbeddedWordLists.femaleNames).count == 300)
        #expect(lines(EmbeddedWordLists.maleNames).count == 300)
        for list in [passwords, lines(EmbeddedWordLists.englishWords), lines(EmbeddedWordLists.surnames), eff] {
            #expect(list.allSatisfy { $0 == $0.lowercased() && (3...32).contains($0.unicodeScalars.count) })
        }
        #expect(RankedDictionary.embedded.words["password"] == DictionaryHit(rank: 2, source: .commonPassword))
        #expect(RankedDictionary.embedded.words["abacus"]?.source == .passphraseWord)
        #expect(RankedDictionary.embedded.maximumWordLength <= 32)
    }

    @Test("each pattern is named for what it is")
    func weaknesses() {
        let cases: [(String, StrengthWeakness)] = [
            ("", .empty),
            ("password", .commonPassword),
            ("p4ssw0rd!", .commonPasswordVariation),
            ("drowssap", .commonPasswordVariation),
            ("unripe", .dictionaryWord),
            ("vndrmk", .tooShort),
            ("zxcvbnm,./", .keyboardPattern),
            ("aaaaaaaaaaaa", .repeatedCharacters),
            ("xkqxkqxkqxkq", .repeatedPattern),
            ("ghijklmn", .sequence),
            ("13/3/1997", .date),
            ("xq1987", .year),
            ("kT9$", .tooShort),
        ]
        for (password, expected) in cases {
            let assessment = Self.estimator.assess(password)
            #expect(assessment.weakness == expected, "\(password): \(String(describing: assessment.weakness))")
            #expect(assessment.explanation == expected.explanation)
        }
    }

    @Test("no explanation ever quotes the password")
    func explanationsDoNotQuote() {
        for password in ["hunter2hunter2", "Tr0ub4dor&3", "zxcvbnm,./", "mysecretword", "19900102"] {
            let assessment = Self.estimator.assess(password)
            #expect(!assessment.explanation.contains(password))
            #expect(!"\(assessment)".contains(password))
        }
        for weakness in StrengthWeakness.allCases {
            #expect(weakness.explanation.hasSuffix("."))
        }
    }

    @Test("a password built from the item's own title, username or site is caught")
    func personalInputs() {
        let plain = Self.estimator.assess("zyphrantha-vault")
        let personal = Self.estimator.assess(
            "zyphrantha-vault", personalInputs: ["Zyphrantha Bank", "j.smith@example.com", "zyphrantha.example"])
        #expect(personal.guessesLog10 < plain.guessesLog10 - 3)
        let username = Self.estimator.assess("jsmith99", personalInputs: ["j.smith@example.com"])
        #expect(username.score <= .weak)
        #expect(username.weakness == .personalInformation)
    }

    @Test("personal inputs are bounded")
    func personalInputsBounded() {
        let many = (0..<10_000).map { "input\($0)" }
        let dictionary = PersonalDictionary(many)
        #expect(dictionary.words.count <= PersonalDictionary.maximumInputs)
        let long = PersonalDictionary([String(repeating: "a", count: 1_000_000)])
        #expect(long.words.isEmpty)
        #expect(
            PersonalDictionary(["j.smith@example.com"]).words.keys.sorted()
                == ["com", "example", "examplecom", "jsmith", "smith"])
    }

    @Test("capitals and look-alike characters cost a little, not a lot")
    func variations() {
        let plain = Self.estimator.assess("sunshine").guessesLog10
        #expect(Self.estimator.assess("Sunshine").guessesLog10 > plain)
        #expect(Self.estimator.assess("Sunshine").guessesLog10 < plain + 1)
        #expect(Self.estimator.assess("sUnShInE").guessesLog10 > Self.estimator.assess("Sunshine").guessesLog10)
        #expect(Self.estimator.assess("5un5h1n3").guessesLog10 < plain + 2.5)
        #expect(Self.estimator.assess("5un5h1n3").weakness == .commonPasswordVariation)
    }

    @Test("years and dates near the reference year are the cheap ones")
    func referenceYear() {
        let near = StrengthEstimator(referenceYear: 2026).assess("xq-2020-vn").guessesLog10
        let far = StrengthEstimator(referenceYear: 2026).assess("xq-1905-vn").guessesLog10
        #expect(far > near)
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let date = calendar.date(from: DateComponents(year: 2031, month: 6, day: 1))!
        #expect(StrengthEstimator(now: date).referenceYear == 2031)
        #expect(StrengthEstimator(referenceYear: 12).referenceYear == 2000)
    }

    @Test("dates are read as zxcvbn reads them")
    func dates() {
        #expect(StrengthMatcher.dateYear(13, 3, 1997) == 1997)
        #expect(StrengthMatcher.dateYear(1997, 3, 13) == 1997)
        #expect(StrengthMatcher.dateYear(1, 2, 90) == 1990)
        #expect(StrengthMatcher.dateYear(1, 2, 26) == 2026)
        #expect(StrengthMatcher.dateYear(13, 13, 1997) == nil)
        #expect(StrengthMatcher.dateYear(1, 32, 1997) == nil)
        #expect(StrengthMatcher.dateYear(1, 2, 999) == nil)
        #expect(StrengthMatcher.dateYear(1, 2, 2051) == nil)
        #expect(StrengthMatcher.dateYear(0, 0, 2000) == nil)
    }

    @Test("the arithmetic helpers agree with the closed forms")
    func arithmetic() {
        #expect(StrengthMatcher.binomial(10, 3) == 120)
        #expect(StrengthMatcher.binomial(52, 5) == 2_598_960)
        #expect(StrengthMatcher.binomial(5, 0) == 1)
        #expect(StrengthMatcher.binomial(5, 6) == 0)
        #expect(StrengthMatcher.choices(4, upTo: 2) == 10)
        #expect(StrengthEstimator.score(guesses: 1) == .veryWeak)
        #expect(StrengthEstimator.score(guesses: 1e3 + 5) == .weak)
        #expect(StrengthEstimator.score(guesses: 1e6 + 5) == .fair)
        #expect(StrengthEstimator.score(guesses: 1e8 + 5) == .strong)
        #expect(StrengthEstimator.score(guesses: 1e10 + 5) == .veryStrong)
        #expect(StrengthEstimator.score(guesses: .infinity) == .veryStrong)
    }

    @Test("the keyboard graphs are a QWERTY keyboard and a keypad")
    func keyboards() {
        let qwerty = KeyboardGraph.qwerty
        #expect(qwerty.startingPositions == 94)
        #expect(qwerty.neighbours["q"]?.map { $0?.plain } == [nil, "1", "2", "w", "a", nil])
        #expect(qwerty.neighbours["Q"] == qwerty.neighbours["q"])
        #expect(qwerty.neighbours["g"]?.compactMap { $0?.plain } == ["f", "t", "y", "h", "b", "v"])
        // The published figure for this layout (zxcvbn's `calc_average_degree`) is about 4.6.
        #expect(abs(qwerty.averageDegree - 4.596) < 0.01)
        let keypad = KeyboardGraph.keypad
        #expect(keypad.startingPositions == 15)
        #expect(keypad.neighbours["5"]?.compactMap { $0?.plain } == ["4", "7", "8", "9", "6", "3", "2", "1"])
        #expect(abs(keypad.averageDegree - 5.0667) < 0.01)
    }

    @Test("only the first sixty-four characters are analysed, and the result says so")
    func truncation() {
        let sixtyFour = String(repeating: "a", count: 64)
        #expect(!Self.estimator.assess(sixtyFour).truncated)
        let longer = Self.estimator.assess(sixtyFour + "Zq7!")
        #expect(longer.truncated)
        #expect(longer.guessesLog10 == Self.estimator.assess(sixtyFour).guessesLog10)
    }

    @Test(
        "hostile passwords are assessed in bounded time",
        arguments: [
            String(repeating: "a", count: 10_000),
            String(repeating: "ab", count: 5_000),
            String(repeating: "1!|7", count: 2_500),
            String(repeating: "0123456789", count: 1_000),
            String(repeating: "password", count: 1_250),
            String(repeating: "qwertyuiop", count: 1_000),
            String(repeating: "1/1/1990", count: 1_250),
            String(repeating: "\u{0301}", count: 10_000),
            String(repeating: "🧑‍🤝‍🧑", count: 2_000),
            String(repeating: "aA1!bB2@", count: 125_000),
        ])
    func bounded(_ password: String) {
        let clock = ContinuousClock()
        var assessment: StrengthAssessment?
        let elapsed = clock.measure { assessment = Self.estimator.assess(password) }
        #expect(assessment?.truncated == true)
        // Milliseconds in practice; the bound is loose because CI machines are shared.
        #expect(elapsed < .seconds(2))
    }

    @Test("every 64-character string of pattern-dense material stays within the same bound")
    func boundedRandomised() {
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 99))
        let pieces = ["1", "!", "|", "7", "0", "a", "ab", "qwe", "123", "pass", "1990", "/", "aaa", "@", "$", "zxc"]
        let clock = ContinuousClock()
        var worst = Duration.zero
        for _ in 0..<TestEnvironment.iterations(standard: 50, long: 2000) {
            var password = ""
            while password.unicodeScalars.count < 64 {
                password += pieces[Int(generator.next() % UInt64(pieces.count))]
            }
            worst = max(worst, clock.measure { _ = Self.estimator.assess(password) })
        }
        #expect(worst < .seconds(2))
    }

    @Test("the cheapest cover prefers one pattern for the whole password to pieces")
    func cheapestCover() {
        let whole = StrengthMatch(start: 0, end: 7, pattern: .sequence, guesses: 32)
        let left = StrengthMatch(start: 0, end: 3, pattern: .sequence, guesses: 16)
        let right = StrengthMatch(start: 4, end: 7, pattern: .sequence, guesses: 16)
        let cover = StrengthEstimator.cheapestCover(length: 8, matches: [left, right, whole])
        #expect(cover.sequence == [whole])
        #expect(cover.guesses == 33)
        // With nothing matched, brute force: 10^n + 1.
        #expect(StrengthEstimator.cheapestCover(length: 3, matches: []).guesses == 1001)
        #expect(StrengthEstimator.cheapestCover(length: 0, matches: []).guesses == 1)
        // Matches outside the password are ignored, not trusted.
        let outside = StrengthMatch(start: 2, end: 9, pattern: .sequence, guesses: 1)
        #expect(StrengthEstimator.cheapestCover(length: 3, matches: [outside]).guesses == 1001)
    }
}
