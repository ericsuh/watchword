import Foundation
import WatchwordGenerator

public enum PasswordRulesError: Error, Hashable, Sendable {
    case tooLong
    /// Not the password-rules syntax; the offending part is named.
    case malformed(String)
    case unknownProperty(String)
    case unknownCharacterClass(String)
    case numberOutOfRange(String)
    /// The rules contradict themselves or ask for something the generator will not produce: a minimum above the
    /// maximum, a length outside 4 to 128, a required class with no characters left.
    case unsatisfiable
}

/// A site's password rules, as a page declares them in the `passwordrules` attribute and the operating system passes
/// them to a generate-password request (PRD F3.1, F6.5; docs/02-architecture.md §12).
///
/// The syntax is Apple's: `required: upper; required: digit; allowed: [-_.]; minlength: 12; max-consecutive: 2`.
/// The string is written by the page, so the parser is bounded and strict (SEC9): a property or class it does not
/// know is an error rather than something to guess at, and nothing a page writes can make the generator produce a
/// password outside its own 4 to 128 character range.
public struct PasswordRules: Hashable, Sendable {
    public static let maximumLength = 2048
    /// Printable ASCII without the space, which enough sign-in forms trim or reject that generating one is a bug.
    static let printable = Set((0x21...0x7E).map { Character(UnicodeScalar(UInt8($0))) })
    static let lower = Set("abcdefghijklmnopqrstuvwxyz")
    static let upper = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    static let digit = Set("0123456789")
    static let special = printable.subtracting(lower).subtracting(upper).subtracting(digit)

    /// One set per `required` property: the password must contain a character from each.
    public var required: [Set<Character>]
    /// Characters named by `allowed` properties. The generator's alphabet is this plus every required set, or all
    /// printable ASCII when the rules name no characters at all.
    public var allowed: Set<Character>
    /// The longest run of one character the site accepts.
    public var maxConsecutive: Int?
    public var minLength: Int?
    public var maxLength: Int?

    public init(
        required: [Set<Character>] = [], allowed: Set<Character> = [], maxConsecutive: Int? = nil,
        minLength: Int? = nil,
        maxLength: Int? = nil
    ) {
        self.required = required
        self.allowed = allowed
        self.maxConsecutive = maxConsecutive
        self.minLength = minLength
        self.maxLength = maxLength
    }

    public init(parsing text: String) throws {
        guard text.utf8.count <= PasswordRules.maximumLength else { throw PasswordRulesError.tooLong }
        self.init()
        for rule in PasswordRules.splitRules(text) {
            guard let colon = rule.firstIndex(of: ":") else { throw PasswordRulesError.malformed(rule) }
            let name = rule[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = String(rule[rule.index(after: colon)...])
            switch name {
            case "required":
                let classes = try PasswordRules.parseClasses(value)
                guard !classes.isEmpty else { throw PasswordRulesError.unsatisfiable }
                required.append(classes)
            case "allowed":
                allowed.formUnion(try PasswordRules.parseClasses(value))
            case "max-consecutive":
                let number = try PasswordRules.parseNumber(value)
                maxConsecutive = min(maxConsecutive ?? number, number)
            case "minlength":
                let number = try PasswordRules.parseNumber(value)
                minLength = max(minLength ?? number, number)
            case "maxlength":
                let number = try PasswordRules.parseNumber(value)
                maxLength = min(maxLength ?? number, number)
            default:
                throw PasswordRulesError.unknownProperty(name)
            }
        }
    }

    /// Splits on `;` outside a `[…]` class, dropping empty rules (a trailing `;` is usual).
    private static func splitRules(_ text: String) -> [String] {
        var rules: [String] = []
        var current = ""
        var inClass = false
        var classStart = false
        for character in text {
            if inClass {
                // `]` closes the class unless it is the first character in it, where it stands for itself.
                if character == "]" && !classStart { inClass = false }
                classStart = false
                current.append(character)
            } else if character == ";" {
                rules.append(current)
                current = ""
            } else {
                if character == "[" {
                    inClass = true
                    classStart = true
                }
                current.append(character)
            }
        }
        rules.append(current)
        return rules.filter { !$0.allSatisfy(\.isWhitespace) }
    }

    /// A comma-separated list of class names and `[…]` classes; the union of their characters.
    private static func parseClasses(_ text: String) throws -> Set<Character> {
        var result = Set<Character>()
        var characters = Substring(text)
        var expectClass = true
        while true {
            characters = characters.drop(while: \.isWhitespace)
            guard let first = characters.first else { break }
            if first == "," {
                guard !expectClass else { throw PasswordRulesError.malformed(text) }
                expectClass = true
                characters = characters.dropFirst()
                continue
            }
            guard expectClass else { throw PasswordRulesError.malformed(text) }
            expectClass = false
            if first == "[" {
                var body = characters.dropFirst()
                var custom = Set<Character>()
                var isFirst = true
                var closed = false
                while let character = body.first {
                    body = body.dropFirst()
                    if character == "]" && !isFirst {
                        closed = true
                        break
                    }
                    isFirst = false
                    // A space in a class is tolerated and left out; anything else outside printable ASCII is not.
                    guard character == " " || printable.contains(character) else {
                        throw PasswordRulesError.malformed(text)
                    }
                    if character != " " { custom.insert(character) }
                }
                guard closed else { throw PasswordRulesError.malformed(text) }
                result.formUnion(custom)
                characters = body
            } else {
                let name = characters.prefix { $0.isLetter || $0 == "-" }
                guard !name.isEmpty else { throw PasswordRulesError.malformed(text) }
                characters = characters.dropFirst(name.count)
                switch name.lowercased() {
                case "lower": result.formUnion(lower)
                case "upper": result.formUnion(upper)
                case "digit": result.formUnion(digit)
                case "special": result.formUnion(special)
                // Only ASCII is ever generated, so `unicode` adds nothing beyond what `ascii-printable` does.
                case "ascii-printable", "unicode": result.formUnion(printable)
                default: throw PasswordRulesError.unknownCharacterClass(String(name))
                }
            }
        }
        guard !expectClass || result.isEmpty && text.allSatisfy(\.isWhitespace) else {
            throw PasswordRulesError.malformed(text)
        }
        return result
    }

    private static func parseNumber(_ text: String) throws -> Int {
        let digits = text.trimmingCharacters(in: .whitespaces)
        guard !digits.isEmpty, digits.utf8.count <= 6, digits.utf8.allSatisfy({ (0x30...0x39).contains($0) }),
            let number = Int(digits), number >= 1
        else { throw PasswordRulesError.numberOutOfRange(digits) }
        return number
    }

    /// The characters a password may be drawn from.
    public var alphabet: Set<Character> {
        if allowed.isEmpty && required.isEmpty { return PasswordRules.printable }
        return required.reduce(allowed) { $0.union($1) }
    }

    /// Whether `password` obeys every rule. The generator's output is checked with this before it is offered, so a
    /// mapping mistake cannot hand a site a password it will reject.
    public func isSatisfied(by password: String) -> Bool {
        let alphabet = alphabet
        guard password.allSatisfy(alphabet.contains) else { return false }
        if let minLength, password.count < minLength { return false }
        if let maxLength, password.count > maxLength { return false }
        guard required.allSatisfy({ set in password.contains(where: set.contains) }) else { return false }
        if let maxConsecutive {
            var run = 0
            var previous: Character?
            for character in password {
                run = character == previous ? run + 1 : 1
                if run > maxConsecutive { return false }
                previous = character
            }
        }
        return true
    }

    /// The generator policy for these rules, starting from `base` (PRD F3.1).
    ///
    /// The length is `base.length` moved inside the site's bounds, and must stay inside the generator's own. Whole
    /// classes the site allows are selected as classes; every other allowed character becomes the symbol set. Any
    /// `max-consecutive` forbids adjacent repeats altogether, which is stricter than asked and always accepted.
    public func policy(base: RandomPasswordPolicy = RandomPasswordPolicy()) throws -> RandomPasswordPolicy {
        if let minLength, let maxLength, minLength > maxLength { throw PasswordRulesError.unsatisfiable }
        var length = base.length
        if let minLength { length = max(length, minLength) }
        if let maxLength { length = min(length, maxLength) }
        guard RandomPasswordPolicy.lengthRange.contains(length) else { throw PasswordRulesError.unsatisfiable }

        var remaining = alphabet
        var classes: CharacterClasses = []
        for (cls, members) in [
            (CharacterClasses.lowercase, PasswordRules.lower), (.uppercase, PasswordRules.upper),
            (.digits, PasswordRules.digit),
        ] where members.isSubset(of: remaining) {
            classes.insert(cls)
            remaining.subtract(members)
        }
        if !remaining.isEmpty { classes.insert(.symbols) }
        guard !classes.isEmpty else { throw PasswordRulesError.unsatisfiable }

        let policy = RandomPasswordPolicy(
            length: length, classes: classes,
            symbolSet: String(remaining.sorted()),
            excludeAmbiguous: false, requireEachClass: true,
            forbidRepeatedAdjacent: maxConsecutive != nil || base.forbidRepeatedAdjacent)
        do {
            try policy.validate()
        } catch {
            throw PasswordRulesError.unsatisfiable
        }
        return policy
    }
}
