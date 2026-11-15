import Foundation
import Testing
import WatchwordTestSupport

@testable import WatchwordInterchange

@Suite("DEFLATE inflater and CRC-32")
struct InflaterTests {
    @Test("Inflates streams written by zlib", arguments: DeflateVector.all)
    func inflatesZlibStreams(_ vector: DeflateVector) throws {
        let compressed = vector.compressed
        #expect(Int(compressed[0] >> 1) & 3 == vector.firstBlockType)
        // The ratio cap is per stream, and a thousand zeros compress far better than 100:1.
        let output = try Inflater.inflate(
            compressed, range: 0..<compressed.count, expectedLength: nil,
            limits: InterchangeLimits(maximumCompressionRatio: 100))
        #expect(output == vector.plaintext.bytes)
    }

    @Test("The vectors cover stored, fixed and dynamic blocks")
    func vectorsCoverEveryBlockType() {
        #expect(Set(DeflateVector.all.map(\.firstBlockType)) == [0, 1, 2])
    }

    @Test("CRC-32 agrees with zlib and with a bitwise implementation", arguments: DeflateVector.all)
    func checksum(_ vector: DeflateVector) {
        let bytes = vector.plaintext.bytes
        #expect(CRC32.checksum(bytes) == vector.crc32)
        #expect(CRC32.checksum(bytes) == ZIPFixture.crc32(bytes))
    }

    @Test("CRC-32 check value")
    func checksumCheckValue() {
        // The standard check value for CRC-32/ISO-HDLC.
        #expect(CRC32.checksum(Array("123456789".utf8)) == 0xCBF4_3926)
    }

    @Test("A declared length must be exact")
    func declaredLength() throws {
        let vector = try #require(DeflateVector.all.first { $0.name == "sentences/best" })
        let compressed = vector.compressed
        let length = vector.plaintext.bytes.count
        let limits = InterchangeLimits.standard
        #expect(
            try Inflater.inflate(compressed, range: 0..<compressed.count, expectedLength: length, limits: limits)
                == vector.plaintext.bytes)
        for wrong in [length - 1, length + 1, 0] {
            #expect(throws: InterchangeError.malformedDeflate(.lengthMismatch)) {
                try Inflater.inflate(compressed, range: 0..<compressed.count, expectedLength: wrong, limits: limits)
            }
        }
    }

    @Test("Inflates a sub-range, and refuses bytes after the final block")
    func rangeAndTrailingData() throws {
        let vector = try #require(DeflateVector.all.first { $0.name == "sentences/default" })
        let padded = [0xAA, 0xBB] + vector.compressed + [0xCC]
        let limits = InterchangeLimits.standard
        let output = try Inflater.inflate(
            padded, range: 2..<padded.count - 1, expectedLength: nil, limits: limits)
        #expect(output == vector.plaintext.bytes)
        #expect(throws: InterchangeError.malformedDeflate(.trailingData)) {
            try Inflater.inflate(padded, range: 2..<padded.count, expectedLength: nil, limits: limits)
        }
    }

    @Test("Stored streams written for export read back", arguments: [0, 1, 65_535, 65_536, 200_000])
    func storedStream(_ count: Int) throws {
        var generator = SeededGenerator(seed: UInt64(count))
        let bytes = (0..<count).map { _ in UInt8(truncatingIfNeeded: generator.next()) }
        let stream = Inflater.storedStream(bytes)
        #expect(stream == DeflateFixture.stored(bytes))
        #expect(try Inflater.inflate(stream) == bytes)
    }

    @Test("The hand-assembled zero stream inflates", arguments: [1, 2, 3, 4, 258, 259, 260, 261, 262, 1000, 70_000])
    func zeroFixture(_ count: Int) throws {
        let stream = DeflateFixture.zeros(count: count)
        let limits = InterchangeLimits(maximumCompressionRatio: 100)
        // Lift the ratio by padding the range arithmetic: inflate with an expected length the ratio permits.
        if count <= stream.count * 100 {
            #expect(try Inflater.inflate(stream, limits: limits) == [UInt8](repeating: 0, count: count))
        } else {
            #expect(throws: InterchangeError.limitExceeded(.compressionRatio, limit: 100)) {
                try Inflater.inflate(stream, limits: limits)
            }
        }
    }
}
