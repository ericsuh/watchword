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

/// Every embedded list in one table: lower-cased word to its best (lowest) rank.
///
/// A rank is how many guesses an attacker working down that list needs to reach the word. For the frequency lists it
/// is the word's position. The EFF list is not a frequency list: a generated passphrase draws from it uniformly, so
/// every word in it costs the size of the list, which makes a passphrase of `n` words cost `7776^n`, the same number
/// `WatchwordGenerator`'s entropy estimate gives.
struct RankedDictionary: Sendable {
    let words: [String: DictionaryHit]
    /// No word is longer than this many scalars, so no longer substring needs looking up.
    let maximumWordLength: Int

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
        var words: [String: DictionaryHit] = [:]
        var longest = 0
        for list in lists {
            var position = 0
            for line in list.text.split(separator: "\n", omittingEmptySubsequences: true) {
                position += 1
                let word = String(line)
                let hit = DictionaryHit(rank: list.uniformRank ?? position, source: list.source)
                if let existing = words[word], existing.rank <= hit.rank { continue }
                words[word] = hit
                longest = max(longest, word.unicodeScalars.count)
            }
        }
        self.words = words
        maximumWordLength = longest
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

    let words: [String: Int]

    /// Lower-cases each input and splits it at anything that is not a letter or a digit; keeps the pieces of a usable
    /// length, and also each run joined across `.`, `-` and `_` (`j.smith@example.com` gives `smith`, `example`,
    /// `com`, `jsmith` and `examplecom`). Bounded: at most `maximumInputs` inputs are read, each to its first 128
    /// scalars.
    init(_ inputs: [String]) {
        var words: [String: Int] = [:]
        func add(_ scalars: [Unicode.Scalar]) {
            guard (Self.minimumLength...Self.maximumLength).contains(scalars.count) else { return }
            var view = String.UnicodeScalarView()
            view.append(contentsOf: scalars)
            let word = String(view)
            if words[word] == nil { words[word] = words.count + 1 }
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
