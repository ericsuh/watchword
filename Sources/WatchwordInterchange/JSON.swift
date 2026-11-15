import Foundation

/// A JSON value as this module reads and writes it. Objects keep their members in document order, so an export is
/// deterministic and an import can report what it saw in the order it saw it.
enum JSONValue: Hashable, Sendable {
    case null
    case bool(Bool)
    case integer(Int64)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object(JSONObject)

    var string: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    var integer: Int64? {
        if case .integer(let value) = self { return value }
        return nil
    }

    var bool: Bool? {
        if case .bool(let value) = self { return value }
        return nil
    }

    var array: [JSONValue]? {
        if case .array(let value) = self { return value }
        return nil
    }

    var object: JSONObject? {
        if case .object(let value) = self { return value }
        return nil
    }

    var isNull: Bool { self == .null }
}

struct JSONObject: Hashable, Sendable {
    struct Member: Hashable, Sendable {
        var key: String
        var value: JSONValue
    }

    var members: [Member] = []

    init(_ members: [(String, JSONValue)] = []) {
        self.members = members.map { Member(key: $0.0, value: $0.1) }
    }

    /// The value for `key`. Keys are unique: the reader refuses a repeated one. A scan of the members, so a caller
    /// looping over something a file sized must look a key up outside the loop.
    subscript(key: String) -> JSONValue? {
        members.first { $0.key == key }?.value
    }

    mutating func append(_ key: String, _ value: JSONValue) {
        members.append(Member(key: key, value: value))
    }

    /// Appends `value` under `key` unless it is `nil`.
    mutating func append(_ key: String, ifPresent value: JSONValue?) {
        if let value { append(key, value) }
    }

    func string(_ key: String) -> String? { self[key]?.string }
    func integer(_ key: String) -> Int64? { self[key]?.integer }
    func bool(_ key: String) -> Bool? { self[key]?.bool }
    func array(_ key: String) -> [JSONValue]? { self[key]?.array }
    func object(_ key: String) -> JSONObject? { self[key]?.object }
}

/// A strict, bounded JSON reader (RFC 8259) for import files (PRD SEC7, SEC9).
///
/// Foundation's `JSONSerialization` is not used: its behaviour differs between Apple platforms and Linux, it resolves
/// a repeated key by position, and it materialises the whole document. This reader behaves identically everywhere,
/// refuses what is ambiguous (repeated keys, lone surrogates, NUL), bounds its recursion, and can walk a document
/// without holding it: `readObject` and `readArray` visit members one at a time, `skipValue` checks a value's syntax
/// without allocating and reports where it lies, and `readValue` materialises only what the caller has already
/// measured. That is what keeps memory proportional to one item, not to a 100 MB document.
///
/// The bytes must already be valid UTF-8 (`UTF8Text.validatedRange`).
struct JSONReader {
    /// Keys longer than this are not remembered for the repeated-key check while walking: every key a format
    /// defines is far shorter, and remembering arbitrarily long unknown ones would be unbounded memory.
    private static let longestTrackedKey = 64

    let bytes: [UInt8]
    private(set) var position: Int
    let end: Int
    let limits: InterchangeLimits
    private var depth = 0

    init(bytes: [UInt8], range: Range<Int>, limits: InterchangeLimits) {
        self.bytes = bytes
        self.position = range.lowerBound
        self.end = range.upperBound
        self.limits = limits
    }

    private func failure(_ defect: JSONDefect) -> InterchangeError {
        .malformedJSON(defect, byteOffset: position)
    }

    private mutating func skipWhitespace() {
        while position < end {
            switch bytes[position] {
            case 0x20, 0x09, 0x0A, 0x0D: position += 1
            default: return
            }
        }
    }

    /// The next significant byte, without consuming it.
    private mutating func peek() throws -> UInt8 {
        skipWhitespace()
        guard position < end else { throw failure(.unexpectedEnd) }
        return bytes[position]
    }

    private mutating func expect(_ byte: UInt8) throws {
        guard try peek() == byte else { throw failure(.unexpectedCharacter) }
        position += 1
    }

    private mutating func enter() throws {
        depth += 1
        guard depth <= limits.maximumNestingDepth else { throw limits.exceeded(.nestingDepth) }
    }

    /// Throws unless only white space remains.
    mutating func finish() throws {
        skipWhitespace()
        guard position == end else { throw failure(.trailingData) }
    }

    /// Whether the next value is an object, an array or something else, without consuming it.
    mutating func nextIsObject() throws -> Bool { try peek() == UInt8(ascii: "{") }
    mutating func nextIsArray() throws -> Bool { try peek() == UInt8(ascii: "[") }

    // MARK: Walking

    /// Visits each member of the object that comes next. `body` consumes the member's value from the reader it is
    /// given, or leaves it, in which case it is checked and skipped. Throws `unexpectedStructure(path:)` if the next
    /// value is not an object.
    mutating func readObject(path: String, _ body: (String, inout JSONReader) throws -> Void) throws {
        guard try nextIsObject() else { throw InterchangeError.unexpectedStructure(path: path) }
        position += 1
        try enter()
        var seen = Set<String>()
        var count = 0
        if try peek() == UInt8(ascii: "}") {
            position += 1
        } else {
            while true {
                guard try peek() == UInt8(ascii: "\"") else { throw failure(.unexpectedCharacter) }
                let keyStart = position
                let key = try readString()
                count += 1
                guard count <= limits.maximumFieldsPerItem else { throw limits.exceeded(.fieldsPerItem) }
                if key.utf8.count <= JSONReader.longestTrackedKey, !seen.insert(key).inserted {
                    throw InterchangeError.malformedJSON(.duplicateKey, byteOffset: keyStart)
                }
                try expect(UInt8(ascii: ":"))
                skipWhitespace()
                let before = position
                try body(key, &self)
                if position == before {
                    _ = try skipValue()
                }
                let next = try peek()
                position += 1
                if next == UInt8(ascii: "}") { break }
                guard next == UInt8(ascii: ",") else {
                    position -= 1
                    throw failure(.unexpectedCharacter)
                }
            }
        }
        depth -= 1
    }

    /// Visits each element of the array that comes next; `body` consumes the element or leaves it to be skipped.
    mutating func readArray(path: String, _ body: (inout JSONReader) throws -> Void) throws {
        guard try nextIsArray() else { throw InterchangeError.unexpectedStructure(path: path) }
        position += 1
        try enter()
        if try peek() == UInt8(ascii: "]") {
            position += 1
        } else {
            while true {
                skipWhitespace()
                let before = position
                try body(&self)
                if position == before {
                    _ = try skipValue()
                }
                let next = try peek()
                position += 1
                if next == UInt8(ascii: "]") { break }
                guard next == UInt8(ascii: ",") else {
                    position -= 1
                    throw failure(.unexpectedCharacter)
                }
            }
        }
        depth -= 1
    }

    /// Checks the syntax of the next value and steps over it, allocating nothing. Returns where it lies.
    @discardableResult
    mutating func skipValue() throws -> Range<Int> {
        let first = try peek()
        let start = position
        switch first {
        case UInt8(ascii: "{"):
            position += 1
            try enter()
            if try peek() == UInt8(ascii: "}") {
                position += 1
            } else {
                while true {
                    guard try peek() == UInt8(ascii: "\"") else { throw failure(.unexpectedCharacter) }
                    try skipString()
                    try expect(UInt8(ascii: ":"))
                    try skipValue()
                    let next = try peek()
                    position += 1
                    if next == UInt8(ascii: "}") { break }
                    guard next == UInt8(ascii: ",") else {
                        position -= 1
                        throw failure(.unexpectedCharacter)
                    }
                }
            }
            depth -= 1
        case UInt8(ascii: "["):
            position += 1
            try enter()
            if try peek() == UInt8(ascii: "]") {
                position += 1
            } else {
                while true {
                    try skipValue()
                    let next = try peek()
                    position += 1
                    if next == UInt8(ascii: "]") { break }
                    guard next == UInt8(ascii: ",") else {
                        position -= 1
                        throw failure(.unexpectedCharacter)
                    }
                }
            }
            depth -= 1
        case UInt8(ascii: "\""):
            try skipString()
        default:
            _ = try readScalar()
        }
        return start..<position
    }

    /// Steps over the next value and, if it is no longer than one entry may be, materialises it. `nil` for a value
    /// over the limit: the caller skips that entry and carries on.
    mutating func readBoundedValue() throws -> JSONValue? {
        let span = try skipValue()
        guard span.count <= limits.maximumEntryBytes else { return nil }
        var inner = JSONReader(bytes: bytes, range: span, limits: limits)
        inner.depth = depth
        return try inner.readValue()
    }

    // MARK: Materialising

    /// Reads the next value whole. Callers bound what they hand this (`readBoundedValue`).
    mutating func readValue() throws -> JSONValue {
        switch try peek() {
        case UInt8(ascii: "{"):
            position += 1
            try enter()
            var object = JSONObject()
            var seen = Set<String>()
            if try peek() == UInt8(ascii: "}") {
                position += 1
            } else {
                while true {
                    guard try peek() == UInt8(ascii: "\"") else { throw failure(.unexpectedCharacter) }
                    let keyStart = position
                    let key = try readString()
                    guard seen.insert(key).inserted else {
                        throw InterchangeError.malformedJSON(.duplicateKey, byteOffset: keyStart)
                    }
                    try expect(UInt8(ascii: ":"))
                    object.append(key, try readValue())
                    let next = try peek()
                    position += 1
                    if next == UInt8(ascii: "}") { break }
                    guard next == UInt8(ascii: ",") else {
                        position -= 1
                        throw failure(.unexpectedCharacter)
                    }
                }
            }
            depth -= 1
            return .object(object)
        case UInt8(ascii: "["):
            position += 1
            try enter()
            var elements: [JSONValue] = []
            if try peek() == UInt8(ascii: "]") {
                position += 1
            } else {
                while true {
                    elements.append(try readValue())
                    let next = try peek()
                    position += 1
                    if next == UInt8(ascii: "]") { break }
                    guard next == UInt8(ascii: ",") else {
                        position -= 1
                        throw failure(.unexpectedCharacter)
                    }
                }
            }
            depth -= 1
            return .array(elements)
        case UInt8(ascii: "\""):
            return .string(try readString())
        default:
            return try readScalar()
        }
    }

    private mutating func readString() throws -> String {
        var buffer: [UInt8] = []
        try scanString(decoding: true, into: &buffer)
        return UTF8Text.string(buffer)
    }

    /// Checks a string token without decoding it.
    private mutating func skipString() throws {
        var unused: [UInt8] = []
        try scanString(decoding: false, into: &unused)
    }

    /// Reads a string token, decoding it into `buffer` if asked to. `position` is at the opening quote.
    private mutating func scanString(decoding: Bool, into buffer: inout [UInt8]) throws {
        position += 1
        while true {
            guard position < end else { throw failure(.unexpectedEnd) }
            let byte = bytes[position]
            switch byte {
            case UInt8(ascii: "\""):
                position += 1
                return
            case UInt8(ascii: "\\"):
                position += 1
                guard position < end else { throw failure(.unexpectedEnd) }
                let escape = bytes[position]
                position += 1
                let decoded: UInt8
                switch escape {
                case UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "/"): decoded = escape
                case UInt8(ascii: "b"): decoded = 0x08
                case UInt8(ascii: "f"): decoded = 0x0C
                case UInt8(ascii: "n"): decoded = 0x0A
                case UInt8(ascii: "r"): decoded = 0x0D
                case UInt8(ascii: "t"): decoded = 0x09
                case UInt8(ascii: "u"):
                    let scalar = try readEscapedScalar()
                    if decoding { buffer.append(contentsOf: Array(String(Character(scalar)).utf8)) }
                    continue
                default:
                    position -= 1
                    throw failure(.invalidEscape)
                }
                if decoding { buffer.append(decoded) }
            case 0x00...0x1F:
                throw failure(.controlCharacterInString)
            default:
                if decoding { buffer.append(byte) }
                position += 1
            }
        }
    }

    /// The scalar of a `\uXXXX` escape (or a surrogate pair of them); `position` is after the `u`.
    private mutating func readEscapedScalar() throws -> Unicode.Scalar {
        let first = try readHexQuad()
        var value = first
        if (0xD800...0xDBFF).contains(first) {
            guard end - position >= 2, bytes[position] == UInt8(ascii: "\\"), bytes[position + 1] == UInt8(ascii: "u")
            else { throw failure(.loneSurrogate) }
            position += 2
            let second = try readHexQuad()
            guard (0xDC00...0xDFFF).contains(second) else { throw failure(.loneSurrogate) }
            value = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
        } else if (0xDC00...0xDFFF).contains(first) {
            throw failure(.loneSurrogate)
        }
        guard value != 0 else { throw failure(.nulCharacter) }
        guard let scalar = Unicode.Scalar(value) else { throw failure(.invalidEscape) }
        return scalar
    }

    private mutating func readHexQuad() throws -> UInt32 {
        guard end - position >= 4 else { throw failure(.unexpectedEnd) }
        var value: UInt32 = 0
        for _ in 0..<4 {
            let byte = bytes[position]
            let digit: UInt32
            switch byte {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): digit = UInt32(byte - UInt8(ascii: "0"))
            case UInt8(ascii: "a")...UInt8(ascii: "f"): digit = UInt32(byte - UInt8(ascii: "a")) + 10
            case UInt8(ascii: "A")...UInt8(ascii: "F"): digit = UInt32(byte - UInt8(ascii: "A")) + 10
            default: throw failure(.invalidEscape)
            }
            value = value << 4 | digit
            position += 1
        }
        return value
    }

    /// `true`, `false`, `null` or a number.
    private mutating func readScalar() throws -> JSONValue {
        let first = try peek()
        switch first {
        case UInt8(ascii: "t"):
            try expectLiteral("true")
            return .bool(true)
        case UInt8(ascii: "f"):
            try expectLiteral("false")
            return .bool(false)
        case UInt8(ascii: "n"):
            try expectLiteral("null")
            return .null
        case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"):
            return try readNumber()
        default:
            throw failure(.unexpectedCharacter)
        }
    }

    private mutating func expectLiteral(_ literal: String) throws {
        let expected = Array(literal.utf8)
        guard end - position >= expected.count, bytes[position..<position + expected.count].elementsEqual(expected)
        else { throw failure(.unexpectedCharacter) }
        position += expected.count
    }

    private mutating func readNumber() throws -> JSONValue {
        let start = position
        func digits() -> Int {
            var count = 0
            while position < end, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[position]) {
                position += 1
                count += 1
            }
            return count
        }
        if bytes[position] == UInt8(ascii: "-") { position += 1 }
        let integerStart = position
        guard digits() > 0 else { throw failure(.invalidNumber) }
        // No leading zeros: `01` is not a number in JSON.
        if bytes[integerStart] == UInt8(ascii: "0"), position - integerStart > 1 {
            position = integerStart
            throw failure(.invalidNumber)
        }
        var integral = true
        if position < end, bytes[position] == UInt8(ascii: ".") {
            integral = false
            position += 1
            guard digits() > 0 else { throw failure(.invalidNumber) }
        }
        if position < end, bytes[position] == UInt8(ascii: "e") || bytes[position] == UInt8(ascii: "E") {
            integral = false
            position += 1
            if position < end, bytes[position] == UInt8(ascii: "+") || bytes[position] == UInt8(ascii: "-") {
                position += 1
            }
            guard digits() > 0 else { throw failure(.invalidNumber) }
        }
        let text = UTF8Text.string(bytes[start..<position])
        if integral, let value = Int64(text) {
            return .integer(value)
        }
        guard let value = Double(text), value.isFinite else {
            position = start
            throw failure(.invalidNumber)
        }
        return .double(value)
    }
}

/// Writes compact JSON, members in the order given. Strings are escaped as RFC 8259 requires and no further.
enum JSONWriter {
    static func encode(_ value: JSONValue) -> [UInt8] {
        var output: [UInt8] = []
        write(value, to: &output)
        return output
    }

    private static func write(_ value: JSONValue, to output: inout [UInt8]) {
        switch value {
        case .null:
            output.append(contentsOf: Array("null".utf8))
        case .bool(let flag):
            output.append(contentsOf: Array((flag ? "true" : "false").utf8))
        case .integer(let number):
            output.append(contentsOf: Array(String(number).utf8))
        case .double(let number):
            output.append(contentsOf: Array((number.isFinite ? String(number) : "null").utf8))
        case .string(let text):
            write(text, to: &output)
        case .array(let elements):
            output.append(UInt8(ascii: "["))
            for (index, element) in elements.enumerated() {
                if index > 0 { output.append(UInt8(ascii: ",")) }
                write(element, to: &output)
            }
            output.append(UInt8(ascii: "]"))
        case .object(let object):
            output.append(UInt8(ascii: "{"))
            for (index, member) in object.members.enumerated() {
                if index > 0 { output.append(UInt8(ascii: ",")) }
                write(member.key, to: &output)
                output.append(UInt8(ascii: ":"))
                write(member.value, to: &output)
            }
            output.append(UInt8(ascii: "}"))
        }
    }

    private static func write(_ text: String, to output: inout [UInt8]) {
        let hex = Array("0123456789abcdef".utf8)
        output.append(UInt8(ascii: "\""))
        for byte in text.utf8 {
            switch byte {
            case UInt8(ascii: "\""): output.append(contentsOf: [UInt8(ascii: "\\"), UInt8(ascii: "\"")])
            case UInt8(ascii: "\\"): output.append(contentsOf: [UInt8(ascii: "\\"), UInt8(ascii: "\\")])
            case 0x0A: output.append(contentsOf: [UInt8(ascii: "\\"), UInt8(ascii: "n")])
            case 0x0D: output.append(contentsOf: [UInt8(ascii: "\\"), UInt8(ascii: "r")])
            case 0x09: output.append(contentsOf: [UInt8(ascii: "\\"), UInt8(ascii: "t")])
            case 0x00...0x1F:
                output.append(contentsOf: Array("\\u00".utf8))
                output.append(hex[Int(byte >> 4)])
                output.append(hex[Int(byte & 0x0F)])
            default: output.append(byte)
            }
        }
        output.append(UInt8(ascii: "\""))
    }
}
