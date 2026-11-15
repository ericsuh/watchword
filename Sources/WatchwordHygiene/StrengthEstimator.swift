import Foundation

/// How hard a password is to guess, on the five-step scale zxcvbn made familiar.
public enum StrengthScore: Int, Hashable, Sendable, Comparable, CaseIterable, Codable {
    /// Fewer than a thousand guesses: on every attacker's first page.
    case veryWeak = 0
    /// Fewer than a million: falls to an online attack that is not rate limited.
    case weak = 1
    /// Fewer than a hundred million: holds against a rate-limited online attack only.
    case fair = 2
    /// Fewer than ten billion: holds against an offline attack on a slow hash.
    case strong = 3
    /// More: holds against an offline attack on a fast hash for a long time.
    case veryStrong = 4

    public static func < (lhs: StrengthScore, rhs: StrengthScore) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

/// The most telling thing about a password that is not strong.
public enum StrengthWeakness: String, Hashable, Sendable, CaseIterable {
    case empty
    case commonPassword
    case commonPasswordVariation
    case dictionaryWord
    case name
    case personalInformation
    case keyboardPattern
    case repeatedCharacters
    case repeatedPattern
    case sequence
    case year
    case date
    case tooShort
    case predictable

    /// One plain sentence for the person (docs/02-architecture.md §13). It never quotes the password or any part
    /// of it.
    public var explanation: String {
        switch self {
        case .empty:
            return "There is no password."
        case .commonPassword:
            return "This is one of the most commonly used passwords, so it is among the first an attacker tries."
        case .commonPasswordVariation:
            return
                "This is a commonly used password with predictable changes, such as swapped characters, capitals "
                + "or added digits. Attackers try those variations too."
        case .dictionaryWord:
            return "This is built from ordinary words that guessing programs try early."
        case .name:
            return "This is built from a common name, which guessing programs try early."
        case .personalInformation:
            return
                "This contains the name of the site or the account's own username, the first things someone who "
                + "knows the account would try."
        case .keyboardPattern:
            return "This follows a pattern of neighbouring keys on the keyboard, which is easy to guess."
        case .repeatedCharacters:
            return "This repeats the same character, which adds almost nothing to guess."
        case .repeatedPattern:
            return "This repeats one short pattern, which is barely harder to guess than the pattern itself."
        case .sequence:
            return "This contains a sequence such as \"abc\" or \"6543\", which is easy to guess."
        case .year:
            return "This relies on a recent year, which is easy to guess."
        case .date:
            return "This relies on a date, which is easy to guess."
        case .tooShort:
            return "This is short enough to guess by trying every combination."
        case .predictable:
            return "This is made of predictable parts and would not take long to guess."
        }
    }
}

/// What the estimator says about one password.
///
/// **Not for a log.** For a password that is one entry of a public list, the exact estimate is that entry's rank,
/// which names the password; so the exact figure stays inside the module, `guessesMagnitude` is all a caller gets,
/// and printing, interpolating or reflecting an assessment shows the score and nothing else (PRD N5).
public struct StrengthAssessment: Hashable, Sendable {
    public let score: StrengthScore
    /// log10 of the estimated number of guesses an attacker needs. Internal: see the type's comment.
    let guessesLog10: Double
    /// `nil` when the password is strong or very strong.
    public let weakness: StrengthWeakness?
    /// One plain sentence: why it is weak, or that nothing predictable was found.
    public let explanation: String
    /// Whether the password was longer than `StrengthEstimator.maximumAnalysedLength`, so the estimate is of its
    /// beginning only.
    public let truncated: Bool

    /// The estimate as an order of magnitude: about `10^n` guesses, for a UI that wants to say more than the score.
    public var guessesMagnitude: Int {
        Int(min(max(guessesLog10.rounded(.down), 0), 400))
    }
}

extension StrengthAssessment: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "StrengthAssessment(score: \(score.rawValue), details withheld)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["score": score], displayStyle: .struct) }
}

/// A zxcvbn-class strength estimator (PRD F9.3, docs/02-architecture.md §13).
///
/// It asks how many guesses the cheapest known strategy needs: it finds every stretch of the password that a word
/// list, a keyboard walk, a repeat, a sequence, a year or a date explains (`StrengthMatcher`), then searches for the
/// cheapest way to cover the whole password with such stretches and brute force between them. That is an estimate of
/// what a guessing program does, not a count of character classes: `Tr0ub4dor&3` scores below four random words.
///
/// **Bounded.** Only the first `maximumAnalysedLength` scalars are analysed. Whatever follows can only add guesses,
/// so the estimate for a longer password is a lower bound, and the cost of an assessment has a fixed ceiling: a
/// ten-thousand-character password costs the same as a 64-character one.
///
/// The password is a `String` because item fields are (PRD SEC4). Nothing here keeps it, or any part of it, after
/// `assess` returns, and the result holds no characters from it.
public struct StrengthEstimator: Hashable, Sendable {
    public static let maximumAnalysedLength = 64

    /// The year dates and years are measured from: recent ones are the likely ones.
    public let referenceYear: Int

    public init(referenceYear: Int) {
        self.referenceYear = min(max(referenceYear, 2000), 2200)
    }

    /// The reference year is `now`'s, in UTC.
    public init(now: Date) {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0) ?? calendar.timeZone
        self.init(referenceYear: calendar.component(.year, from: now))
    }

    /// - Parameter personalInputs: words an attacker who knows the account would try first: the item's title, its
    ///   usernames, its site's name. At most 32 are read.
    public func assess(_ password: String, personalInputs: [String] = []) -> StrengthAssessment {
        var scalars: [Unicode.Scalar] = []
        scalars.reserveCapacity(Self.maximumAnalysedLength)
        var truncated = false
        for scalar in password.unicodeScalars {
            guard scalars.count < Self.maximumAnalysedLength else {
                truncated = true
                break
            }
            scalars.append(scalar)
        }
        guard !scalars.isEmpty else {
            return StrengthAssessment(
                score: .veryWeak, guessesLog10: 0, weakness: .empty, explanation: StrengthWeakness.empty.explanation,
                truncated: false)
        }
        let personal = PersonalDictionary(personalInputs)
        var matcher = StrengthMatcher(scalars, personal: personal, referenceYear: referenceYear, repeatDepth: 2)
        let matches = matcher.matchAll()
        let cheapest = Self.cheapestCover(length: scalars.count, matches: matches)
        let score = Self.score(guesses: cheapest.guesses)
        let weakness = score >= .strong ? nil : Self.weakness(cheapest.sequence, length: scalars.count)
        // Finite whatever the arithmetic did: the largest count a Double holds is the ceiling.
        let guesses = min(max(cheapest.guesses, 1), Double.greatestFiniteMagnitude)
        // "No pattern" is said only when none was found: a strong password built from recognisable parts is
        // strong because there are enough of them, and saying nothing was found would be false.
        let patterned = cheapest.sequence.contains { $0.pattern != .bruteForce }
        return StrengthAssessment(
            score: score, guessesLog10: guesses.isNaN ? 0 : log10(guesses), weakness: weakness,
            explanation: weakness?.explanation ?? (patterned ? Self.strongButPatterned : Self.nothingPredictable),
            truncated: truncated)
    }

    static let nothingPredictable = "No predictable pattern was found; this would take a long time to guess."
    static let strongButPatterned =
        "This is built from recognisable parts, such as words, dates or keyboard patterns, but there are enough of "
        + "them that it would still take a long time to guess."

    /// The estimate alone, for a repeated unit.
    static func guesses(
        for scalars: [Unicode.Scalar], personal: PersonalDictionary, referenceYear: Int, repeatDepth: Int
    ) -> Double {
        var matcher = StrengthMatcher(
            scalars, personal: personal, referenceYear: referenceYear, repeatDepth: repeatDepth)
        return cheapestCover(length: scalars.count, matches: matcher.matchAll()).guesses
    }

    static func score(guesses: Double) -> StrengthScore {
        // A small allowance, as zxcvbn makes, so a count that lands exactly on a power of ten falls below it.
        let allowance = 5.0
        if guesses < 1e3 + allowance { return .veryWeak }
        if guesses < 1e6 + allowance { return .weak }
        if guesses < 1e8 + allowance { return .fair }
        if guesses < 1e10 + allowance { return .strong }
        return .veryStrong
    }

    // MARK: The cheapest cover

    static let bruteForceCardinality = 10.0
    static let minimumGuessesForSingleCharacter = 10.0
    static let minimumGuessesForSeveralCharacters = 50.0

    /// The sequence of non-overlapping matches covering all `length` scalars that needs the fewest guesses, where a
    /// sequence of `k` matches with guess counts `g1…gk` needs `k! × g1 × … × gk`: the patterns can come in any
    /// order. A dynamic programme over the end position and the number of matches, as in the zxcvbn paper.
    ///
    /// **One deliberate difference from zxcvbn.** The paper adds `10000^(k-1)` to a sequence of `k` matches, for the
    /// shorter sequences an attacker is assumed to exhaust first. That term alone lifts any three cheap patterns to
    /// 10^8 guesses and any four to 10^12, so `Spring2026!` (a word, a year, a symbol: a few million guesses for a
    /// rule-based cracker) scored strong, and the search preferred "a word and eight random characters" to "two
    /// words and two symbols". Guessing programs order candidates by likelihood, not by the number of parts, so the
    /// term is left out: a password is as strong as its parts multiply out to, and no stronger. The factorial and
    /// the floor under each part still keep the search from preferring many small pieces.
    static func cheapestCover(length: Int, matches: [StrengthMatch]) -> (guesses: Double, sequence: [StrengthMatch]) {
        guard length > 0 else { return (1, []) }
        var endingAt = [[StrengthMatch]](repeating: [], count: length)
        for match in matches where match.start >= 0 && match.end < length && match.start <= match.end {
            endingAt[match.end].append(match)
        }
        struct Best {
            var match: StrengthMatch
            /// The product of the guess counts of this many matches ending here.
            var product: Double
            /// The whole estimate for the password up to here.
            var total: Double
        }
        // optimal[k][l]: the best sequence of exactly l matches covering scalars 0...k.
        var optimal = [[Int: Best]](repeating: [:], count: length)

        func adjusted(_ match: StrengthMatch) -> Double {
            // A match that is not the whole password is at least as costly as a guess at where it starts and ends.
            guard match.length < length else { return max(match.guesses, 1) }
            let floor = match.length == 1 ? minimumGuessesForSingleCharacter : minimumGuessesForSeveralCharacters
            return max(match.guesses, floor)
        }

        func consider(_ match: StrengthMatch, sequenceLength: Int) {
            var product = adjusted(match)
            if sequenceLength > 1 {
                guard match.start > 0, let previous = optimal[match.start - 1][sequenceLength - 1] else { return }
                product *= previous.product
            }
            let total = factorial(sequenceLength) * product
            // A sequence that is no shorter and no cheaper than one already found to this point cannot be part of
            // the answer.
            for (otherLength, other) in optimal[match.end] where otherLength <= sequenceLength {
                if other.total <= total { return }
            }
            optimal[match.end][sequenceLength] = Best(match: match, product: product, total: total)
        }

        func bruteForce(_ start: Int, _ end: Int) -> StrengthMatch {
            let count = Double(end - start + 1)
            var guesses = pow(bruteForceCardinality, count)
            if !guesses.isFinite { guesses = Double.greatestFiniteMagnitude }
            // One more than the floor for a submatch, so that a real pattern of the same length is preferred.
            let floor = (count == 1 ? minimumGuessesForSingleCharacter : minimumGuessesForSeveralCharacters) + 1
            return StrengthMatch(start: start, end: end, pattern: .bruteForce, guesses: max(guesses, floor))
        }

        for end in 0..<length {
            for match in endingAt[end] {
                if match.start == 0 {
                    consider(match, sequenceLength: 1)
                } else {
                    for sequenceLength in optimal[match.start - 1].keys.sorted() {
                        consider(match, sequenceLength: sequenceLength + 1)
                    }
                }
            }
            consider(bruteForce(0, end), sequenceLength: 1)
            for start in stride(from: 1, through: end, by: 1) {
                for (sequenceLength, previous) in optimal[start - 1].sorted(by: { $0.key < $1.key }) {
                    // Two stretches of brute force side by side are one stretch.
                    if previous.match.pattern == .bruteForce { continue }
                    consider(bruteForce(start, end), sequenceLength: sequenceLength + 1)
                }
            }
        }

        guard let last = optimal[length - 1].min(by: { ($0.value.total, $0.key) < ($1.value.total, $1.key) }) else {
            return (pow(bruteForceCardinality, Double(length)), [])
        }
        var sequence: [StrengthMatch] = []
        var end = length - 1
        var sequenceLength = last.key
        while end >= 0, sequenceLength >= 1, let best = optimal[end][sequenceLength] {
            sequence.append(best.match)
            end = best.match.start - 1
            sequenceLength -= 1
        }
        return (last.value.total, sequence.reversed())
    }

    private static func factorial(_ n: Int) -> Double {
        var result = 1.0
        for factor in stride(from: 2, through: n, by: 1) { result *= Double(factor) }
        return result
    }

    // MARK: Explaining

    /// The weakness to name: that of the longest pattern in the cheapest cover, since that is what the person should
    /// change first.
    static func weakness(_ sequence: [StrengthMatch], length: Int) -> StrengthWeakness {
        let patterns = sequence.filter { $0.pattern != .bruteForce }
        guard let longest = patterns.max(by: { ($0.length, -$0.start) < ($1.length, -$1.start) }) else {
            return length < 8 ? .tooShort : .predictable
        }
        let alone = sequence.count == 1
        switch longest.pattern {
        case .bruteForce:
            return .predictable
        case .dictionary(let source, _, let reversed, let substituted):
            switch source {
            case .personal: return .personalInformation
            case .commonPassword: return alone && !reversed && !substituted ? .commonPassword : .commonPasswordVariation
            case .name: return .name
            case .englishWord, .passphraseWord: return .dictionaryWord
            }
        case .keyboard:
            return .keyboardPattern
        case .repeated(let unitLength):
            return unitLength == 1 ? .repeatedCharacters : .repeatedPattern
        case .sequence:
            return .sequence
        case .year:
            return .year
        case .date:
            return .date
        }
    }
}
