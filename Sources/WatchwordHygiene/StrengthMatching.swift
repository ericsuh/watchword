import Foundation

/// A stretch of a password that some guessing strategy explains, with what that strategy would cost.
struct StrengthMatch: Sendable, Equatable {
    enum Pattern: Sendable, Equatable {
        /// Nothing cleverer than trying every character.
        case bruteForce
        case dictionary(source: DictionarySource, rank: Int, reversed: Bool, substituted: Bool)
        case keyboard(turns: Int)
        case repeated(unitLength: Int)
        case sequence
        case year
        case date
    }

    /// First and last scalar of the stretch, inclusive.
    var start: Int
    var end: Int
    var pattern: Pattern
    /// Guesses to produce this stretch by this strategy, before the allowances for it being part of a longer
    /// password.
    var guesses: Double

    var length: Int { end - start + 1 }
}

/// The pattern matchers of a zxcvbn-class estimator (PRD F9.3; Wheeler, "zxcvbn: Low-Budget Password Strength
/// Estimation", USENIX Security 2016, is the description this follows). Written here; no code is shared with any
/// implementation of it.
///
/// Every matcher is bounded by the length it is given, and `StrengthEstimator` never gives more than
/// `maximumAnalysedLength` scalars, so the worst case is a constant however long or hostile the password.
struct StrengthMatcher {
    let original: [Unicode.Scalar]
    let lower: [Unicode.Scalar]
    let personal: PersonalDictionary
    let referenceYear: Int
    /// How many times a repeated unit may itself be analysed for repeats; each level at most halves the length.
    let repeatDepth: Int

    /// The cheapest match found for each stretch. Only the cheapest can be part of the cheapest way to guess the whole
    /// password, so keeping one per stretch bounds the work that follows at `n(n+1)/2` matches.
    private(set) var best: [Int: StrengthMatch] = [:]

    init(_ scalars: [Unicode.Scalar], personal: PersonalDictionary, referenceYear: Int, repeatDepth: Int) {
        original = scalars
        lower = scalars.map(StrengthText.lowercased)
        self.personal = personal
        self.referenceYear = referenceYear
        self.repeatDepth = repeatDepth
    }

    var count: Int { original.count }

    mutating func matchAll() -> [StrengthMatch] {
        guard count > 0 else { return [] }
        matchDictionary()
        matchReversedDictionary()
        matchSubstitutedDictionary()
        for graph in KeyboardGraph.all { matchKeyboard(graph) }
        matchRepeats()
        matchSequences()
        matchYears()
        matchDates()
        return best.values.sorted { ($0.end, $0.start) < ($1.end, $1.start) }
    }

    private mutating func record(_ match: StrengthMatch) {
        let key = match.start * (count + 1) + match.end
        if let existing = best[key], existing.guesses <= match.guesses { return }
        best[key] = match
    }

    // MARK: Dictionary words

    /// How many times a word table was narrowed: the unit of work of the dictionary matchers, and what the tests
    /// bound, because it does not depend on the machine. At most two per scalar read (one per table).
    private(set) var dictionarySteps = 0

    /// The better of what the lists and the item's own words say about one stretch.
    private static func better(_ listed: DictionaryHit?, _ ownRank: Int?) -> DictionaryHit? {
        guard let ownRank else { return listed }
        let own = DictionaryHit(rank: ownRank, source: .personal)
        guard let listed, listed.rank < own.rank else { return own }
        return listed
    }

    /// Every stretch of `text` that is a known word, with its best rank.
    ///
    /// From each start the two tables are walked together, one scalar at a time, and the walk stops at the first
    /// scalar no word continues with. Nothing is built or hashed per stretch, so the cost is the same whatever script
    /// the password is in: at most `count × longest word × 2` steps, and for text that is not made of words, about
    /// two steps per scalar.
    private mutating func words(in text: [Unicode.Scalar]) -> [(start: Int, end: Int, hit: DictionaryHit)] {
        let listed = RankedDictionary.embedded.table
        let own = personal.table
        var found: [(start: Int, end: Int, hit: DictionaryHit)] = []
        for start in text.indices {
            var listedRange = listed.all
            var ownRange = own.all
            var depth = 0
            for end in start..<text.count {
                let scalar = text[end].value
                if !listedRange.isEmpty {
                    listedRange = listed.narrow(listedRange, depth: depth, by: scalar)
                    dictionarySteps += 1
                }
                if !ownRange.isEmpty {
                    ownRange = own.narrow(ownRange, depth: depth, by: scalar)
                    dictionarySteps += 1
                }
                depth += 1
                if listedRange.isEmpty && ownRange.isEmpty { break }
                guard depth >= PersonalDictionary.minimumLength else { continue }
                let hit = Self.better(
                    listed.value(in: listedRange, depth: depth), own.value(in: ownRange, depth: depth))
                if let hit { found.append((start, end, hit)) }
            }
        }
        return found
    }

    private mutating func matchDictionary() {
        for word in words(in: lower) {
            let guesses = Double(word.hit.rank) * capitalisationVariations(word.start, word.end)
            record(
                StrengthMatch(
                    start: word.start, end: word.end,
                    pattern: .dictionary(
                        source: word.hit.source, rank: word.hit.rank, reversed: false, substituted: false),
                    guesses: guesses))
        }
    }

    private mutating func matchReversedDictionary() {
        let reversed = Array(lower.reversed())
        for word in words(in: reversed) {
            // A palindrome is the same word forwards; it has been counted.
            let stretch = reversed[word.start...word.end]
            guard !stretch.elementsEqual(stretch.reversed()) else { continue }
            let from = count - 1 - word.end
            let to = count - 1 - word.start
            let guesses = Double(word.hit.rank) * capitalisationVariations(from, to) * 2
            record(
                StrengthMatch(
                    start: from, end: to,
                    pattern: .dictionary(
                        source: word.hit.source, rank: word.hit.rank, reversed: true, substituted: false),
                    guesses: guesses))
        }
    }

    /// The letters each look-alike character can stand for. Three are ambiguous, so at most eight readings of a
    /// password are tried.
    private static let lookAlikes: [Unicode.Scalar: [Unicode.Scalar]] = [
        "4": ["a"], "@": ["a"], "8": ["b"], "(": ["c"], "{": ["c"], "[": ["c"], "<": ["c"], "3": ["e"],
        "6": ["g"], "9": ["g"], "1": ["i", "l"], "!": ["i"], "|": ["i", "l"], "7": ["l", "t"], "0": ["o"],
        "$": ["s"], "5": ["s"], "+": ["t"], "%": ["x"], "2": ["z"],
    ]

    private mutating func matchSubstitutedDictionary() {
        var ambiguous: [Unicode.Scalar] = []
        var any = false
        for scalar in lower {
            guard let letters = Self.lookAlikes[scalar] else { continue }
            any = true
            if letters.count > 1, !ambiguous.contains(scalar) { ambiguous.append(scalar) }
        }
        guard any else { return }
        ambiguous.sort { $0.value < $1.value }
        for choice in 0..<(1 << ambiguous.count) {
            let translated = lower.map { scalar -> Unicode.Scalar in
                guard let letters = Self.lookAlikes[scalar] else { return scalar }
                guard letters.count > 1, let position = ambiguous.firstIndex(of: scalar) else { return letters[0] }
                return letters[(choice >> position) & 1]
            }
            for word in words(in: translated) {
                let (start, end) = (word.start, word.end)
                // Which look-alikes this word used, and how many ways the same word could have been disguised.
                var variations = 1.0
                var seen: [Unicode.Scalar] = []
                for index in start...end where translated[index] != lower[index] && !seen.contains(lower[index]) {
                    seen.append(lower[index])
                    let disguised = lower[start...end].filter { $0 == lower[index] }.count
                    let plain = lower[start...end].filter { $0 == translated[index] }.count
                    variations *= plain == 0 ? 2 : Self.choices(disguised + plain, upTo: min(disguised, plain))
                }
                guard !seen.isEmpty else { continue }
                let guesses = Double(word.hit.rank) * capitalisationVariations(start, end) * variations
                record(
                    StrengthMatch(
                        start: start, end: end,
                        pattern: .dictionary(
                            source: word.hit.source, rank: word.hit.rank, reversed: false, substituted: true),
                        guesses: guesses))
            }
        }
    }

    /// How many capitalisations of the word an attacker tries before this one: none for lower case, two for the
    /// conventions (first letter, last letter, all capitals), otherwise the number of ways to place that many
    /// capitals or fewer.
    private func capitalisationVariations(_ start: Int, _ end: Int) -> Double {
        let token = original[start...end]
        let upper = token.filter { $0.properties.isUppercase }.count
        guard upper > 0 else { return 1 }
        let lowerCount = token.filter { $0.properties.isLowercase }.count
        if lowerCount == 0 { return 2 }
        if upper == 1, original[start].properties.isUppercase || original[end].properties.isUppercase { return 2 }
        return Self.choices(upper + lowerCount, upTo: min(upper, lowerCount))
    }

    /// `C(n, 1) + C(n, 2) + … + C(n, k)`.
    static func choices(_ n: Int, upTo k: Int) -> Double {
        guard k >= 1 else { return 1 }
        var total = 0.0
        for chosen in 1...k { total += binomial(n, chosen) }
        return total
    }

    static func binomial(_ n: Int, _ k: Int) -> Double {
        guard k >= 0, k <= n else { return 0 }
        var result = 1.0
        var remaining = n
        for divisor in stride(from: 1, through: min(k, n - k), by: 1) {
            result = result * Double(remaining) / Double(divisor)
            remaining -= 1
        }
        return result
    }

    // MARK: Keyboard walks

    /// One maximal run of neighbouring keys.
    private struct KeyboardWalk {
        var start: Int
        var end: Int
        /// The direction of each step, as an index into the graph's fixed order of neighbours.
        var directions: [Int]
        var shifted: Int

        var length: Int { end - start + 1 }
    }

    private mutating func matchKeyboard(_ graph: KeyboardGraph) {
        var walks: [KeyboardWalk] = []
        var start = 0
        while start < count - 1 {
            var end = start + 1
            var directions: [Int] = []
            var shifted = isShifted(original[start], on: graph) ? 1 : 0
            while end < count, let around = graph.neighbours[original[end - 1]] {
                let wanted = original[end]
                var direction: Int?
                for (index, key) in around.enumerated() {
                    guard let key else { continue }
                    if key.plain == wanted {
                        direction = index
                        break
                    }
                    if key.shifted == wanted {
                        direction = index
                        shifted += 1
                        break
                    }
                }
                guard let direction else { break }
                directions.append(direction)
                end += 1
            }
            // Two adjacent keys are too common in ordinary words to count: a walk is three or more.
            if end - start > 2 {
                let walk = KeyboardWalk(start: start, end: end - 1, directions: directions, shifted: shifted)
                walks.append(walk)
                let turns = Self.effectiveTurns(directions)
                record(
                    StrengthMatch(
                        start: start, end: end - 1, pattern: .keyboard(turns: turns),
                        guesses: Self.keyboardGuesses(graph, length: walk.length, turns: turns, shifted: shifted)))
            }
            start = end
        }
        matchParallelWalks(walks, on: graph)
    }

    /// How many turns a walk is worth. Each change of direction is a turn, except that a walk whose directions
    /// repeat with a short period (a zigzag such as `2w3e4r5t`, down and back up again and again) is one shape
    /// repeated: it is worth the turns of one period, however long it goes on. Counting every turn of a zigzag made
    /// a ten-key zigzag cost more than ten random characters.
    static func effectiveTurns(_ directions: [Int]) -> Int {
        func turns(in steps: ArraySlice<Int>) -> Int {
            var turns = 0
            var last: Int?
            for direction in steps where direction != last {
                turns += 1
                last = direction
            }
            return turns
        }
        let all = turns(in: directions[...])
        guard directions.count >= 2 else { return all }
        for period in 1...min(4, directions.count / 2) {
            let periodic = (period..<directions.count).allSatisfy { directions[$0] == directions[$0 - period] }
            if periodic { return min(all, turns(in: directions.prefix(period))) }
        }
        return all
    }

    /// Walks of the same shape side by side: `1qaz2wsx3edc`, `rfvtgbyhn`, `!QAZ@WSX`. Each column is a walk of its
    /// own (the last key of one is not next to the first key of the next), and as separate patterns three of them
    /// multiply up to a strong password. They are one pattern: a walk, a direction to step in, and how many times.
    private mutating func matchParallelWalks(_ walks: [KeyboardWalk], on graph: KeyboardGraph) {
        var first = 0
        while first < walks.count {
            var last = first
            while last + 1 < walks.count, walks[last + 1].start == walks[last].end + 1,
                walks[last + 1].directions == walks[first].directions,
                isNeighbour(original[walks[last + 1].start], of: original[walks[last].start], on: graph)
            {
                last += 1
            }
            if last > first {
                let copies = last - first + 1
                let length = walks[first].length
                let total = walks[last].end - walks[first].start + 1
                let shifted = walks[first...last].reduce(0) { $0 + $1.shifted }
                let turns = Self.effectiveTurns(walks[first].directions)
                let guesses =
                    Self.keyboardGuesses(graph, length: length, turns: turns, shifted: 0) * graph.averageDegree
                    * Double(copies) * Self.shiftVariations(length: total, shifted: shifted)
                record(
                    StrengthMatch(
                        start: walks[first].start, end: walks[last].end, pattern: .keyboard(turns: turns + 1),
                        guesses: guesses))
            }
            first = last + 1
        }
    }

    private func isNeighbour(_ scalar: Unicode.Scalar, of other: Unicode.Scalar, on graph: KeyboardGraph) -> Bool {
        guard let around = graph.neighbours[other] else { return false }
        return around.contains { $0?.plain == scalar || ($0?.shifted != nil && $0?.shifted == scalar) }
    }

    private func isShifted(_ scalar: Unicode.Scalar, on graph: KeyboardGraph) -> Bool {
        graph.hasShift && Self.shiftedCharacters.contains(scalar)
    }

    private static let shiftedCharacters = Set("~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?".unicodeScalars)

    /// Walks of every length up to this one, with up to this many turns, from any starting key; then the ways to hold
    /// shift for some of it.
    static func keyboardGuesses(_ graph: KeyboardGraph, length: Int, turns: Int, shifted: Int) -> Double {
        var guesses = 0.0
        for walk in 2...max(2, length) {
            for turn in 1...max(1, min(turns, walk - 1)) {
                guesses +=
                    binomial(walk - 1, turn - 1) * graph.startingPositions * pow(graph.averageDegree, Double(turn))
            }
        }
        return guesses * shiftVariations(length: length, shifted: shifted)
    }

    /// The ways to hold shift for `shifted` of `length` keys: none if no key is shifted, two if all are.
    static func shiftVariations(length: Int, shifted: Int) -> Double {
        guard shifted > 0 else { return 1 }
        let plain = length - shifted
        return plain <= 0 ? 2 : choices(length, upTo: min(shifted, plain))
    }

    // MARK: Repeats

    private mutating func matchRepeats() {
        guard repeatDepth > 0 else { return }
        var position = 0
        while position < count - 1 {
            // The longest stretch starting here that is some unit two or more times over.
            var covered = 0
            for unit in 1...max(1, (count - position) / 2) {
                var copies = 1
                while position + (copies + 1) * unit <= count,
                    lower[(position + copies * unit)..<(position + (copies + 1) * unit)]
                        .elementsEqual(lower[position..<(position + unit)])
                {
                    copies += 1
                }
                if copies >= 2, copies * unit > covered { covered = copies * unit }
            }
            guard covered > 0 else {
                position += 1
                continue
            }
            // Its shortest period: "abababab" is "ab" four times, not "abab" twice.
            var unit = covered
            for candidate in 1...(covered / 2) where covered % candidate == 0 {
                let first = lower[position..<(position + candidate)]
                let periodic = stride(from: position, to: position + covered, by: candidate).allSatisfy {
                    lower[$0..<($0 + candidate)].elementsEqual(first)
                }
                if periodic {
                    unit = candidate
                    break
                }
            }
            let unitGuesses = StrengthEstimator.guesses(
                for: Array(original[position..<(position + unit)]), personal: personal, referenceYear: referenceYear,
                repeatDepth: repeatDepth - 1)
            record(
                StrengthMatch(
                    start: position, end: position + covered - 1, pattern: .repeated(unitLength: unit),
                    guesses: unitGuesses * Double(covered / unit)))
            position += covered
        }
    }

    // MARK: Sequences

    private mutating func matchSequences() {
        guard count > 1 else { return }
        var start = 0
        var lastDelta: Int?
        func delta(_ index: Int) -> Int { Int(original[index].value) - Int(original[index - 1].value) }
        for index in 1..<count {
            let step = delta(index)
            if lastDelta == nil { lastDelta = step }
            if step == lastDelta { continue }
            recordSequence(start, index - 1, lastDelta ?? 0)
            start = index - 1
            lastDelta = step
        }
        recordSequence(start, count - 1, lastDelta ?? 0)
    }

    private mutating func recordSequence(_ start: Int, _ end: Int, _ delta: Int) {
        // Three or more in step, or two that are neighbours; and a step small enough to be a pattern (abc, 2468).
        guard end - start > 1 || abs(delta) == 1, abs(delta) >= 1, abs(delta) <= 5 else { return }
        let first = original[start]
        var base: Double
        if "aAzZ019".unicodeScalars.contains(first) {
            // The obvious places to start.
            base = 4
        } else if StrengthText.isDigit(first) {
            base = 10
        } else {
            base = 26
        }
        if delta < 0 { base *= 2 }
        record(
            StrengthMatch(start: start, end: end, pattern: .sequence, guesses: base * Double(end - start + 1)))
    }

    // MARK: Years and dates

    static let minimumYearSpace = 20.0
    static let dateYears = 1000...2050

    private func yearGuesses(_ year: Int) -> Double {
        max(Double(abs(year - referenceYear)), Self.minimumYearSpace)
    }

    private func number(_ start: Int, _ end: Int) -> Int? {
        guard start <= end, end - start < 9 else { return nil }
        var value = 0
        for index in start...end {
            guard StrengthText.isDigit(original[index]) else { return nil }
            value = value * 10 + StrengthText.digitValue(original[index])
        }
        return value
    }

    private mutating func matchYears() {
        guard count >= 4 else { return }
        for start in 0...(count - 4) {
            guard let year = number(start, start + 3), (1900...2049).contains(year) else { continue }
            record(StrengthMatch(start: start, end: start + 3, pattern: .year, guesses: yearGuesses(year)))
        }
    }

    /// Where the two cuts can fall when a run of digits is read as a date without separators.
    private static let dateSplits: [Int: [(Int, Int)]] = [
        4: [(1, 2), (2, 3)],
        5: [(1, 3), (2, 3)],
        6: [(1, 2), (2, 4), (4, 5)],
        7: [(1, 3), (2, 3), (4, 5), (4, 6)],
        8: [(2, 4), (4, 6)],
    ]

    private mutating func matchDates() {
        var found: [StrengthMatch] = []
        // Runs of four to eight digits.
        for start in 0..<count {
            for length in 4...8 where start + length <= count {
                guard (start..<(start + length)).allSatisfy({ StrengthText.isDigit(original[$0]) }) else { break }
                var year: Int?
                for (first, second) in Self.dateSplits[length] ?? [] {
                    guard let a = number(start, start + first - 1),
                        let b = number(start + first, start + second - 1),
                        let c = number(start + second, start + length - 1),
                        let candidate = Self.dateYear(a, b, c)
                    else { continue }
                    // Of the readings that are dates, the one nearest the present is the one a person meant.
                    if year == nil || abs(candidate - referenceYear) < abs((year ?? 0) - referenceYear) {
                        year = candidate
                    }
                }
                if let year {
                    found.append(
                        StrengthMatch(
                            start: start, end: start + length - 1, pattern: .date, guesses: yearGuesses(year) * 365))
                }
            }
        }
        // day, separator, month, the same separator, year, in any plausible order.
        for start in 0..<count {
            for length in 6...10 where start + length <= count {
                let end = start + length - 1
                var separators: [Int] = []
                var valid = true
                for index in start...end where !StrengthText.isDigit(original[index]) {
                    if Self.isDateSeparator(original[index]) {
                        separators.append(index)
                    } else {
                        valid = false
                        break
                    }
                }
                guard valid, separators.count == 2, original[separators[0]] == original[separators[1]],
                    let a = number(start, separators[0] - 1), separators[0] - start <= 4,
                    let b = number(separators[0] + 1, separators[1] - 1), separators[1] - separators[0] - 1 <= 2,
                    let c = number(separators[1] + 1, end), end - separators[1] <= 4,
                    let year = Self.dateYear(a, b, c)
                else { continue }
                found.append(
                    StrengthMatch(start: start, end: end, pattern: .date, guesses: yearGuesses(year) * 365 * 4))
            }
        }
        // A date inside a longer date is the same guess; keep the longer.
        for match in found {
            let contained = found.contains { other in
                other != match && other.start <= match.start && other.end >= match.end
                    && other.length > match.length
            }
            if !contained { record(match) }
        }
    }

    private static func isDateSeparator(_ scalar: Unicode.Scalar) -> Bool {
        " /\\_.-".unicodeScalars.contains(scalar)
    }

    /// The year, if the three numbers can be read as a day, a month and a year in some order.
    static func dateYear(_ a: Int, _ b: Int, _ c: Int) -> Int? {
        let numbers = [a, b, c]
        // The middle number is a day or a month whichever way round.
        guard b >= 1, b <= 31 else { return nil }
        var over12 = 0
        var over31 = 0
        var under1 = 0
        for number in numbers {
            if (number > 99 && number < dateYears.lowerBound) || number > dateYears.upperBound { return nil }
            if number > 31 { over31 += 1 }
            if number > 12 { over12 += 1 }
            if number <= 0 { under1 += 1 }
        }
        guard over31 < 2, over12 < 3, under1 < 2 else { return nil }
        let readings = [(year: c, rest: (a, b)), (year: a, rest: (b, c))]
        for reading in readings where dateYears.contains(reading.year) {
            return isDayAndMonth(reading.rest.0, reading.rest.1) ? reading.year : nil
        }
        for reading in readings where isDayAndMonth(reading.rest.0, reading.rest.1) {
            // Two digits: this century up to fifty, the last one beyond.
            if reading.year > 99 { return reading.year }
            return reading.year > 50 ? reading.year + 1900 : reading.year + 2000
        }
        return nil
    }

    private static func isDayAndMonth(_ first: Int, _ second: Int) -> Bool {
        ((1...31).contains(first) && (1...12).contains(second))
            || ((1...31).contains(second) && (1...12).contains(first))
    }
}
