import Foundation

/// Character classes the random generator can draw from.
public struct CharacterClasses: OptionSet, Sendable, Hashable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    public static let lowercase = CharacterClasses(rawValue: 1 << 0)
    public static let uppercase = CharacterClasses(rawValue: 1 << 1)
    public static let digits = CharacterClasses(rawValue: 1 << 2)
    public static let symbols = CharacterClasses(rawValue: 1 << 3)

    public static let all: CharacterClasses = [.lowercase, .uppercase, .digits, .symbols]

    /// The selected classes as individual values, in a stable order.
    public var members: [CharacterClasses] {
        [CharacterClasses.lowercase, .uppercase, .digits, .symbols].filter { contains($0) }
    }
}

public enum PasswordGenerationError: Error, Equatable, Sendable {
    case noCharacterClasses
    case lengthOutOfRange(ClosedRange<Int>)
    /// The policy cannot be satisfied (for example, require each of 4 classes in a 3-character password).
    case unsatisfiablePolicy
    case emptyWordlist
}

/// Knobs for random-character passwords (PRD F3.1).
public struct RandomPasswordPolicy: Sendable, Hashable {
    public static let lengthRange = 4...128
    public static let defaultSymbols = "!@#$%^&*()-_=+[]{};:,.<>?/"
    public static let ambiguousCharacters: Set<Character> = ["l", "1", "I", "O", "0", "|"]

    public var length: Int
    public var classes: CharacterClasses
    public var symbolSet: String
    public var excludeAmbiguous: Bool
    public var requireEachClass: Bool
    public var forbidRepeatedAdjacent: Bool

    public init(
        length: Int = 20,
        classes: CharacterClasses = .all,
        symbolSet: String = RandomPasswordPolicy.defaultSymbols,
        excludeAmbiguous: Bool = false,
        requireEachClass: Bool = true,
        forbidRepeatedAdjacent: Bool = false
    ) {
        self.length = length
        self.classes = classes
        self.symbolSet = symbolSet
        self.excludeAmbiguous = excludeAmbiguous
        self.requireEachClass = requireEachClass
        self.forbidRepeatedAdjacent = forbidRepeatedAdjacent
    }

    /// Characters available for one class under this policy.
    public func characters(in cls: CharacterClasses) -> [Character] {
        let raw: String
        switch cls {
        case .lowercase: raw = "abcdefghijklmnopqrstuvwxyz"
        case .uppercase: raw = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        case .digits: raw = "0123456789"
        case .symbols: raw = symbolSet
        default: raw = ""
        }
        var seen = Set<Character>()
        var out: [Character] = []
        for ch in raw where !seen.contains(ch) {
            if excludeAmbiguous && RandomPasswordPolicy.ambiguousCharacters.contains(ch) { continue }
            seen.insert(ch)
            out.append(ch)
        }
        return out
    }

    /// The full alphabet: the union of all selected classes, deduplicated, in a stable order.
    public func alphabet() throws -> [Character] {
        guard !classes.isEmpty else { throw PasswordGenerationError.noCharacterClasses }
        var seen = Set<Character>()
        var out: [Character] = []
        for cls in classes.members {
            for ch in characters(in: cls) where !seen.contains(ch) {
                seen.insert(ch)
                out.append(ch)
            }
        }
        guard !out.isEmpty else { throw PasswordGenerationError.noCharacterClasses }
        return out
    }

    /// Throws if the policy can never produce a password.
    public func validate() throws {
        guard RandomPasswordPolicy.lengthRange.contains(length) else {
            throw PasswordGenerationError.lengthOutOfRange(RandomPasswordPolicy.lengthRange)
        }
        let alphabet = try alphabet()
        let nonEmptyClasses = classes.members.filter { !characters(in: $0).isEmpty }
        guard !nonEmptyClasses.isEmpty else { throw PasswordGenerationError.noCharacterClasses }
        if requireEachClass && nonEmptyClasses.count > length {
            throw PasswordGenerationError.unsatisfiablePolicy
        }
        if forbidRepeatedAdjacent && alphabet.count < 2 && length > 1 {
            throw PasswordGenerationError.unsatisfiablePolicy
        }
    }
}

/// Knobs for memorable passphrases (PRD F3.2).
public struct PassphrasePolicy: Sendable, Hashable {
    public static let wordCountRange = 3...10

    public var wordCount: Int
    public var separator: String
    public var capitalizeWords: Bool
    public var appendDigit: Bool

    public init(wordCount: Int = 5, separator: String = "-", capitalizeWords: Bool = false, appendDigit: Bool = false) {
        self.wordCount = wordCount
        self.separator = separator
        self.capitalizeWords = capitalizeWords
        self.appendDigit = appendDigit
    }
}
