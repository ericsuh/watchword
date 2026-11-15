import Foundation
import Testing
import WatchwordTestSupport

@testable import WatchwordInterchange

@Suite("ZIP reader and writer")
struct ZIPArchiveTests {
    private let text = Array("The quick brown fox jumps over the lazy dog.".utf8)

    @Test("Reads stored and deflated members, checking size and CRC-32")
    func readsMembers() throws {
        let archive = try ZIPArchive(
            ZIPFixture([
                ZIPFixture.Member(name: "stored.txt", contents: text),
                ZIPFixture.Member(name: "deflated.txt", contents: text, data: DeflateFixture.stored(text)),
                ZIPFixture.Member(name: "dir/", contents: []),
                ZIPFixture.Member(name: "dir/empty", contents: []),
            ]).bytes())
        #expect(archive.entries.map(\.name) == ["stored.txt", "deflated.txt", "dir/", "dir/empty"])
        #expect(archive.entries.map(\.isDirectory) == [false, false, true, false])
        #expect(archive.entries.map(\.uncompressedSize) == [44, 44, 0, 0])
        #expect(try archive.contents(of: "stored.txt") == text)
        #expect(try archive.contents(of: "deflated.txt") == text)
        #expect(try archive.contents(of: "dir/empty").isEmpty)
        #expect(throws: InterchangeError.missingArchiveEntry("absent")) { try archive.contents(of: "absent") }
        // Names are matched exactly: no case folding, no path normalisation.
        #expect(throws: InterchangeError.missingArchiveEntry("Stored.txt")) { try archive.contents(of: "Stored.txt") }
    }

    /// Swift compares strings by canonical equivalence, under which the Kelvin sign equals `K`. A member is found by
    /// its bytes, so a look-alike name is not the member asked for.
    @Test("A member is looked up by the bytes of its name")
    func byteExactLookup() throws {
        let archive = try ZIPArchive(ZIPFixture([ZIPFixture.Member(name: "\u{212A}ey", contents: text)]).bytes())
        #expect("\u{212A}ey" == "Key")
        #expect(throws: InterchangeError.missingArchiveEntry("Key")) { try archive.contents(of: "Key") }
        #expect(try archive.contents(of: "\u{212A}ey") == text)
        // A directory is one by its last byte, not its last character.
        let marked = try ZIPArchive(ZIPFixture([ZIPFixture.Member(name: "dir/\u{301}", contents: text)]).bytes())
        #expect(marked.entries.map(\.isDirectory) == [false])
    }

    @Test("Reads archives with a comment, a data descriptor, and an empty directory")
    func variants() throws {
        let commented = ZIPFixture(
            [ZIPFixture.Member(name: "a", contents: text)], comment: Array("PK\u{5}\u{6} is not the end record".utf8))
        #expect(try ZIPArchive(commented.bytes()).contents(of: "a") == text)
        let streamed = ZIPFixture([
            ZIPFixture.Member(name: "a", contents: text, data: DeflateFixture.stored(text), usesDataDescriptor: true),
            ZIPFixture.Member(name: "b", contents: text, usesDataDescriptor: true),
        ])
        #expect(try ZIPArchive(streamed.bytes()).contents(of: "a") == text)
        #expect(try ZIPArchive(streamed.bytes()).contents(of: "b") == text)
        #expect(try ZIPArchive(ZIPFixture([]).bytes()).entries.isEmpty)
    }

    @Test("The writer's archives read back, here and in the fixture's terms")
    func writer() throws {
        let members = [
            ZIPWriter.Member(name: "export.attributes", contents: Array("{}".utf8)),
            ZIPWriter.Member(name: "export.data", contents: text),
            ZIPWriter.Member(name: "files/naïve name.txt", contents: []),
        ]
        let bytes = try ZIPWriter.archive(members)
        let archive = try ZIPArchive(bytes)
        #expect(archive.entries.map(\.name) == members.map(\.name))
        for member in members {
            #expect(try archive.contents(of: member.name) == member.contents)
        }
        // Byte-for-byte what an independent builder produces for the same members.
        let fixture = ZIPFixture(members.map { ZIPFixture.Member(name: $0.name, contents: $0.contents) }).bytes()
        #expect(bytes == fixture)
    }

    /// The archive for two members, pinned so a change to the writer is noticed. Python 3's `zipfile` (an
    /// independent reader) accepts exactly these bytes: `ZipFile(io.BytesIO(bytes)).testzip()` is `None`, it lists
    /// `a.txt` (stored, 5 bytes, UTF-8 names flag, 1980-01-01) and `b/`, and reads `a.txt` as `hello`.
    @Test("The writer's output is pinned")
    func writerKnownAnswer() throws {
        let bytes = try ZIPWriter.archive([
            ZIPWriter.Member(name: "a.txt", contents: Array("hello".utf8)),
            ZIPWriter.Member(name: "b/", contents: []),
        ])
        #expect(bytes.hex == ZIPArchiveTests.pinnedArchive)
    }

    static let pinnedArchive =
        "504b03041400000800000000210086a61036050000000500000005000000612e74787468656c6c6f"
        + "504b03041400000800000000210000000000000000000000000002000000622f"
        + "504b010214001400000800000000210086a610360500000005000000050000000000000000000000000000000000612e747874"
        + "504b0102140014000008000000002100000000000000000000000000020000000000000000000000000028000000622f"
        + "504b0506000000000200020063000000480000000000"

    @Test("The writer refuses what the reader would refuse")
    func writerRefusals() {
        #expect(throws: InterchangeError.forbiddenEntryName("../escape")) {
            try ZIPWriter.archive([ZIPWriter.Member(name: "../escape", contents: [])])
        }
        #expect(throws: InterchangeError.duplicateArchiveEntry("a")) {
            try ZIPWriter.archive([
                ZIPWriter.Member(name: "a", contents: []), ZIPWriter.Member(name: "a", contents: []),
            ])
        }
        #expect(throws: InterchangeError.limitExceeded(.inputBytes, limit: 64)) {
            try ZIPWriter.archive(
                [ZIPWriter.Member(name: "a", contents: [UInt8](repeating: 0, count: 100))],
                limits: InterchangeLimits(maximumInputBytes: 64))
        }
    }

    @Test(
        "Safe member names are accepted",
        arguments: ["export.data", "files/a.txt", "files/", "a/b/c", "a b", "naïve", "..a", "a..", "a.b.c", "...", "C"])
    func safeNames(_ name: String) throws {
        try ZIPArchive.validateEntryName(name)
    }
}

@Suite("Bounded JSON reader and writer")
struct JSONTests {
    private func parse(_ text: String, limits: InterchangeLimits = .standard) throws -> JSONValue {
        let bytes = Array(text.utf8)
        var reader = JSONReader(bytes: bytes, range: try UTF8Text.validatedRange(of: bytes), limits: limits)
        let value = try reader.readValue()
        try reader.finish()
        return value
    }

    private func skip(_ text: String) throws {
        let bytes = Array(text.utf8)
        var reader = JSONReader(bytes: bytes, range: 0..<bytes.count, limits: .standard)
        try reader.skipValue()
        try reader.finish()
    }

    @Test("Reads every kind of value")
    func values() throws {
        let value = try parse(#" {"a": [1, -2, 3.5, 1e3, true, false, null], "b": {"c": "d"}, "e": ""} "#)
        let object = try #require(value.object)
        #expect(object.members.map(\.key) == ["a", "b", "e"])
        #expect(
            object["a"]
                == .array([.integer(1), .integer(-2), .double(3.5), .double(1000), .bool(true), .bool(false), .null]))
        #expect(object.object("b")?.string("c") == "d")
        #expect(object.string("e") == "")
        #expect(try parse("9223372036854775807") == .integer(.max))
        #expect(try parse("9223372036854775808") == .double(9_223_372_036_854_775_808))
    }

    @Test("Decodes escapes, surrogate pairs included")
    func strings() throws {
        #expect(try parse(#""a\"b\\c\/d\b\f\n\r\t""#) == .string("a\"b\\c/d\u{8}\u{C}\n\r\t"))
        #expect(try parse(#""\u00e9\u65E5\ud83d\ude00""#) == .string("é日😀"))
        #expect(try parse("\"é日😀\"") == .string("é日😀"))
    }

    @Test(
        "Refuses what RFC 8259 does not allow, and what is ambiguous",
        arguments: [
            ("", JSONDefect.unexpectedEnd), ("{", .unexpectedEnd), ("[1,", .unexpectedEnd), ("\"abc", .unexpectedEnd),
            ("{a: 1}", .unexpectedCharacter), ("[1 2]", .unexpectedCharacter), ("[1,]", .unexpectedCharacter),
            ("{\"a\": 1,}", .unexpectedCharacter), ("{\"a\" 1}", .unexpectedCharacter), ("tru", .unexpectedCharacter),
            ("NaN", .unexpectedCharacter), ("'a'", .unexpectedCharacter), ("// c\n1", .unexpectedCharacter),
            ("01", .invalidNumber), ("-", .invalidNumber), ("1.", .invalidNumber), ("1e", .invalidNumber),
            ("1e999", .invalidNumber), ("-1e999", .invalidNumber),
            ("\"\\x\"", .invalidEscape), ("\"\\u12g4\"", .invalidEscape), ("\"\\ud800\"", .loneSurrogate),
            ("\"\\udc00\"", .loneSurrogate), ("\"\\ud800\\u0041\"", .loneSurrogate),
            ("\"\\u0000\"", .nulCharacter), ("\"a\nb\"", .controlCharacterInString),
            ("\"a\u{0}b\"", .controlCharacterInString),
            ("{\"a\": 1, \"a\": 2}", .duplicateKey), ("1 2", .trailingData), ("{} []", .trailingData),
        ])
    func malformed(_ text: String, _ defect: JSONDefect) {
        do {
            _ = try parse(text)
            Issue.record("accepted \(text)")
        } catch InterchangeError.malformedJSON(let found, _) {
            #expect(found == defect, "\(text)")
        } catch {
            Issue.record("\(text): \(error)")
        }
        // Stepping over a value applies the same grammar (but for repeated keys, which need memory to notice).
        if defect != .duplicateKey {
            #expect(throws: InterchangeError.self, "\(text)") { try skip(text) }
        }
    }

    @Test("Nesting is bounded, materialising and skipping alike")
    func depth() throws {
        let limits = InterchangeLimits(maximumNestingDepth: 8)
        let deepest = String(repeating: "[", count: 8) + String(repeating: "]", count: 8)
        #expect(try parse(deepest, limits: limits).array != nil)
        for open in ["[", "{\"a\":"] {
            let tooDeep = String(repeating: open, count: 9)
            #expect(throws: InterchangeError.limitExceeded(.nestingDepth, limit: 8)) {
                try parse(tooDeep, limits: limits)
            }
            let bytes = Array(tooDeep.utf8)
            var reader = JSONReader(bytes: bytes, range: 0..<bytes.count, limits: limits)
            #expect(throws: InterchangeError.limitExceeded(.nestingDepth, limit: 8)) { try reader.skipValue() }
        }
        // The standard limit holds against a document that is nothing but brackets.
        #expect(throws: InterchangeError.limitExceeded(.nestingDepth, limit: 64)) {
            try parse(String(repeating: "[", count: 100_000))
        }
    }

    @Test("Walking visits members in order and skips what the visitor leaves")
    func walking() throws {
        let bytes = Array(#"{"skip": {"deep": [1, {"x": null}]}, "take": [10, 20, 30], "last": "z"}"#.utf8)
        var reader = JSONReader(bytes: bytes, range: 0..<bytes.count, limits: .standard)
        var keys: [String] = []
        var taken: [JSONValue] = []
        try reader.readObject(path: "$") { key, reader in
            keys.append(key)
            guard key == "take" else { return }
            try reader.readArray(path: "take") { reader in
                let value = try reader.readValue()
                if value != .integer(20) { taken.append(value) }
            }
        }
        try reader.finish()
        #expect(keys == ["skip", "take", "last"])
        #expect(taken == [.integer(10), .integer(30)])
    }

    @Test("A value larger than one entry may be is measured and passed over, never built")
    func boundedValue() throws {
        let limits = InterchangeLimits(maximumEntryBytes: 32)
        let bytes = Array(#"[{"a": "small"}, {"a": "this one is much too large to be an entry"}, 7]"#.utf8)
        var reader = JSONReader(bytes: bytes, range: 0..<bytes.count, limits: limits)
        var seen: [JSONValue?] = []
        try reader.readArray(path: "$") { reader in
            seen.append(try reader.readBoundedValue())
        }
        #expect(seen == [.object(JSONObject([("a", .string("small"))])), nil, .integer(7)])
    }

    @Test("The writer escapes what it must and round-trips through the reader")
    func writer() throws {
        let value = JSONValue.object(
            JSONObject([
                ("text", .string("quote \" backslash \\ newline \n tab \t bell \u{7} é 日 😀 </script>")),
                ("numbers", .array([.integer(-5), .double(0.5), .double(.infinity)])),
                ("flags", .array([.bool(true), .null])),
            ]))
        let encoded = String(decoding: JSONWriter.encode(value), as: UTF8.self)
        #expect(
            encoded
                == #"{"text":"quote \" backslash \\ newline \n tab \t bell \u0007 é 日 😀 </script>","#
                + #""numbers":[-5,0.5,null],"flags":[true,null]}"#)
        let reread = try parse(encoded)
        #expect(reread.object?.string("text") == value.object?.string("text"))
    }

    @Test("Invalid UTF-8 is located, and a UTF-16 mark refused")
    func textEncoding() {
        #expect(throws: InterchangeError.invalidUTF8(byteOffset: 3)) {
            try UTF8Text.validatedRange(of: [0x61, 0x62, 0x63, 0xFF, 0x64])
        }
        // Overlong, surrogate, beyond U+10FFFF, truncated, stray continuation.
        for bytes: [UInt8] in [
            [0xC0, 0xAF], [0xE0, 0x80, 0xAF], [0xED, 0xA0, 0x80], [0xF4, 0x90, 0x80, 0x80], [0xE2, 0x82], [0x80],
        ] {
            #expect(throws: InterchangeError.invalidUTF8(byteOffset: 0)) { try UTF8Text.validatedRange(of: bytes) }
        }
        #expect(throws: InterchangeError.unsupportedTextEncoding) {
            try UTF8Text.validatedRange(of: [0xFF, 0xFE, 0x61, 0x00])
        }
        #expect(throws: InterchangeError.unsupportedTextEncoding) {
            try UTF8Text.validatedRange(of: [0xFE, 0xFF, 0x00, 0x61])
        }
    }

    @Test("The validator agrees with the standard library on random bytes")
    func validatorMatchesStandardLibrary() {
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 0x0F8))
        // Bytes weighted towards lead and continuation bytes, so multi-byte sequences actually form.
        let pool: [UInt8] = [
            0x41, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC0, 0xC2, 0xDF, 0xE0, 0xE1, 0xED, 0xEF, 0xF0, 0xF1, 0xF4,
            0xF5,
        ]
        for _ in 0..<TestEnvironment.iterations(standard: 5_000, long: 500_000) {
            let bytes = (0..<Int.random(in: 0...6, using: &generator)).map { _ in pool.randomElement(using: &generator)!
            }
            let valid = UTF8Text.firstInvalidOffset(in: bytes, range: 0..<bytes.count) == nil
            #expect(valid == (String(decoding: bytes, as: UTF8.self).utf8.elementsEqual(bytes)), "\(bytes)")
        }
    }
}
