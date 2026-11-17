import Foundation

/// The word lists the strength estimator knows, embedded as Swift source so that the module carries no resource
/// files (CLAUDE.md, "No symlinks or non-Swift files under Sources/"). Each list's own file says where it came from
/// and under what licence; docs/02-architecture.md §13 lists them.
enum EmbeddedWordLists {}

/// Which list a matched word came from: it decides the explanation, not the arithmetic.
enum DictionarySource: UInt8, Sendable {
    case commonPassword = 0
    case englishWord = 1
    case name = 2
    /// The EFF large wordlist, from which passphrases are drawn.
    case passphraseWord = 3
    /// Something from the item itself: its title, a username, the site's name.
    case personal = 4
}

struct DictionaryHit: Sendable, Equatable {
    var rank: Int
    var source: DictionarySource
}

/// Words held as sorted arrays of scalar values, so that a stretch of a password is looked up by narrowing a range
/// of the table one scalar at a time, the way a trie is walked.
///
/// This is what bounds the estimator's work on hostile input. A stretch is abandoned at the first scalar no word
/// continues with, each step is two binary searches over integers, and nothing is hashed or built per stretch. An
/// earlier version made a `String` of every stretch and looked it up in a `String`-keyed dictionary; hashing a
/// non-ASCII `String` normalises it, which let a password of combining marks cost several hundred times an ordinary
/// one (review of milestone 6).
struct WordTable<Value: Sendable>: Sendable {
    /// Sorted lexicographically by scalar value; a word sorts before every longer word it begins.
    private let words: [[UInt32]]
    private let values: [Value]
    /// No word is longer than this many scalars.
    let maximumWordLength: Int

    /// - Parameter entries: distinct words. With a word listed twice, which value is kept is unspecified.
    init(_ entries: [(word: [UInt32], value: Value)]) {
        let sorted = entries.sorted { $0.word.lexicographicallyPrecedes($1.word) }
        words = sorted.map(\.word)
        values = sorted.map(\.value)
        maximumWordLength = words.reduce(0) { max($0, $1.count) }
    }

    var count: Int { words.count }

    /// Every word: the range to start narrowing from.
    var all: Range<Int> { 0..<words.count }

    /// Of the words in `range`, all of which begin with the same `depth` scalars, those whose next scalar is
    /// `scalar`.
    func narrow(_ range: Range<Int>, depth: Int, by scalar: UInt32) -> Range<Int> {
        // A word of exactly `depth` scalars has no next scalar and sorts first; it counts as less than any scalar.
        func next(_ index: Int) -> Int64 {
            let word = words[index]
            return depth < word.count ? Int64(word[depth]) : -1
        }
        let wanted = Int64(scalar)
        var low = range.lowerBound
        var high = range.upperBound
        while low < high {
            let middle = low + (high - low) / 2
            if next(middle) < wanted { low = middle + 1 } else { high = middle }
        }
        let first = low
        high = range.upperBound
        while low < high {
            let middle = low + (high - low) / 2
            if next(middle) <= wanted { low = middle + 1 } else { high = middle }
        }
        return first..<low
    }

    /// The value of the word that is exactly the `depth` scalars the words of `range` share, if that is a word.
    func value(in range: Range<Int>, depth: Int) -> Value? {
        guard !range.isEmpty, words[range.lowerBound].count == depth else { return nil }
        return values[range.lowerBound]
    }

    /// The value of `word`, for tests and for building: one walk of the table.
    func value(of word: some Sequence<UInt32>) -> Value? {
        var range = all
        var depth = 0
        for scalar in word {
            range = narrow(range, depth: depth, by: scalar)
            depth += 1
            if range.isEmpty { return nil }
        }
        return value(in: range, depth: depth)
    }
}

/// Every embedded list in one table: lower-cased word to its best (lowest) rank.
///
/// A rank is how many guesses an attacker working down that list needs to reach the word. For the frequency lists it
/// is the word's position. The EFF list is not a frequency list: a generated passphrase draws from it uniformly, so
/// every word in it costs the size of the list, which makes a passphrase of `n` words cost `7776^n`, the same number
/// `WatchwordGenerator`'s entropy estimate gives.
struct RankedDictionary: Sendable {
    let table: WordTable<DictionaryHit>

    /// No word is longer than this many scalars, so no longer stretch can be one.
    var maximumWordLength: Int { table.maximumWordLength }

    /// Built once, on first use: about 23,000 entries.
    static let embedded = RankedDictionary(lists: [
        (EmbeddedWordLists.commonPasswords, .commonPassword, nil),
        (EmbeddedWordLists.englishWords, .englishWord, nil),
        (EmbeddedWordLists.surnames, .name, nil),
        (EmbeddedWordLists.femaleNames, .name, nil),
        (EmbeddedWordLists.maleNames, .name, nil),
        (EmbeddedWordLists.effLargeWordlist, .passphraseWord, EmbeddedWordLists.effLargeWordlistCount),
    ])

    /// - Parameter lists: newline-separated words, best first; a non-`nil` rank applies to every word of that list.
    init(lists: [(text: String, source: DictionarySource, uniformRank: Int?)]) {
        var words: [Substring: DictionaryHit] = [:]
        for list in lists {
            var position = 0
            for line in list.text.split(separator: "\n", omittingEmptySubsequences: true) {
                position += 1
                let hit = DictionaryHit(rank: list.uniformRank ?? position, source: list.source)
                if let existing = words[line], existing.rank <= hit.rank { continue }
                words[line] = hit
            }
        }
        table = WordTable(words.map { (word: $0.key.unicodeScalars.map(\.value), value: $0.value) })
    }

    /// The best rank of `word`, which must already be lower case.
    func hit(for word: String) -> DictionaryHit? {
        table.value(of: word.unicodeScalars.lazy.map(\.value))
    }
}

extension EmbeddedWordLists {
    /// 6^5: five dice per word.
    static let effLargeWordlistCount = 7776
}

/// Words taken from the item a password belongs to. A password that contains its own site's name or its username is
/// the first thing an attacker who knows the account tries, so these rank ahead of every list.
struct PersonalDictionary: Sendable {
    static let maximumInputs = 32
    static let minimumLength = 3
    static let maximumLength = 32

    /// Word to rank: the order the words were found in, first is 1.
    let words: [String: Int]
    /// The same words, for looking up stretches of a password (`WordTable`).
    let table: WordTable<Int>

    /// Lower-cases each input and splits it at anything that is not a letter or a digit; keeps the pieces of a usable
    /// length, and also each run joined across `.`, `-` and `_` (`j.smith@example.com` gives `smith`, `example`,
    /// `com`, `jsmith` and `examplecom`). Bounded: at most `maximumInputs` inputs are read, each to its first 128
    /// scalars.
    init(_ inputs: [String]) {
        var words: [String: Int] = [:]
        var entries: [(word: [UInt32], value: Int)] = []
        func add(_ scalars: [Unicode.Scalar]) {
            guard (Self.minimumLength...Self.maximumLength).contains(scalars.count) else { return }
            var view = String.UnicodeScalarView()
            view.append(contentsOf: scalars)
            let word = String(view)
            // `String` equality is canonical equivalence, so two spellings of one word are one entry here and must
            // be one entry in the table: only the first spelling is kept.
            guard words[word] == nil else { return }
            words[word] = words.count + 1
            entries.append((scalars.map(\.value), words.count))
        }
        for input in inputs.prefix(Self.maximumInputs) {
            var piece: [Unicode.Scalar] = []
            var joined: [Unicode.Scalar] = []
            for scalar in input.unicodeScalars.prefix(128) {
                let lowered = StrengthText.lowercased(scalar)
                if lowered.properties.isAlphabetic || lowered.properties.numericType != nil {
                    piece.append(lowered)
                    joined.append(lowered)
                    continue
                }
                add(piece)
                piece.removeAll(keepingCapacity: true)
                if scalar != "." && scalar != "-" && scalar != "_" {
                    add(joined)
                    joined.removeAll(keepingCapacity: true)
                }
            }
            add(piece)
            add(joined)
        }
        self.words = words
        // Two spellings that `String` tells apart never share scalars, so the table's words are distinct.
        table = WordTable(entries)
    }
}

enum StrengthText {
    /// The scalar's lower-case form when that is a single scalar; otherwise the scalar itself, so positions in the
    /// lowered text are positions in the password.
    static func lowercased(_ scalar: Unicode.Scalar) -> Unicode.Scalar {
        if scalar.isASCII {
            return scalar.value >= 0x41 && scalar.value <= 0x5A ? Unicode.Scalar(UInt8(scalar.value + 0x20)) : scalar
        }
        let mapped = scalar.properties.lowercaseMapping.unicodeScalars
        guard let first = mapped.first, mapped.count == 1 else { return scalar }
        return first
    }

    static func isDigit(_ scalar: Unicode.Scalar) -> Bool {
        scalar.value >= 0x30 && scalar.value <= 0x39
    }

    static func digitValue(_ scalar: Unicode.Scalar) -> Int {
        Int(scalar.value) - 0x30
    }
}
