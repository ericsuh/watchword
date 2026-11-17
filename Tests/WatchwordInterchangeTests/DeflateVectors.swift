import Foundation
import Testing
import WatchwordTestSupport

/// Raw DEFLATE streams produced by Python's `zlib` (an independent implementation), with the CRC-32 of each
/// plaintext from `zlib.crc32`. Never regenerate these from `Inflater` or `CRC32` themselves.
///
/// Each stream is `zlib.compressobj(level, zlib.DEFLATED, -15, 9, strategy)` over the plaintext named, where:
///
/// - `stored` is level 0, `fastest` 1, `default` 6, `best` 9;
/// - `fixed`, `huffmanOnly` and `runLength` use `Z_FIXED` (level 9), `Z_HUFFMAN_ONLY` and `Z_RLE` (level 6);
/// - `flushed` is level 9 with a `Z_FULL_FLUSH` after every 97 bytes, and `storedFlushed` level 0 with one after
///   every 211, so the stream is many blocks, some of them empty stored blocks.
///
/// `firstBlockType` is bits 1 and 2 of the first byte (0 stored, 1 fixed Huffman, 2 dynamic Huffman): the set covers
/// all three.
struct DeflateVector: Sendable, CustomTestStringConvertible {
    enum Plaintext: Sendable {
        case empty, letter, zeros, sentences, ramp, noise

        /// The plaintext, rebuilt here the way the generating script built it.
        var bytes: [UInt8] {
            switch self {
            case .empty:
                return []
            case .letter:
                return Array("a".utf8)
            case .zeros:
                return [UInt8](repeating: 0, count: 1000)
            case .sentences:
                return (0..<40).flatMap { Array("\($0): Pack my box with five dozen liquor jugs.\n".utf8) }
            case .ramp:
                return (0..<3000).map { UInt8(truncatingIfNeeded: $0 * 31 + $0 / 7) }
            case .noise:
                var generator = SeededGenerator(seed: 42)
                return (0..<600).map { _ in UInt8(truncatingIfNeeded: generator.next()) }
            }
        }
    }

    let name: String
    let plaintext: Plaintext
    let firstBlockType: Int
    let crc32: UInt32
    let stream: String

    var testDescription: String { name }

    var compressed: [UInt8] { Array(Data(base64Encoded: stream)!) }

    static let all: [DeflateVector] = [
        DeflateVector(
            name: "empty/stored", plaintext: .empty, firstBlockType: 0, crc32: 0x00000000,
            stream: "AQAA//8="),
        DeflateVector(
            name: "empty/best", plaintext: .empty, firstBlockType: 1, crc32: 0x00000000,
            stream: "AwA="),
        DeflateVector(
            name: "empty/fixed", plaintext: .empty, firstBlockType: 1, crc32: 0x00000000,
            stream: "AwA="),
        DeflateVector(
            name: "letter/stored", plaintext: .letter, firstBlockType: 0, crc32: 0xE8B7BE43,
            stream: "AQEA/v9h"),
        DeflateVector(
            name: "letter/best", plaintext: .letter, firstBlockType: 1, crc32: 0xE8B7BE43,
            stream: "SwQA"),
        DeflateVector(
            name: "letter/fixed", plaintext: .letter, firstBlockType: 1, crc32: 0xE8B7BE43,
            stream: "SwQA"),
        DeflateVector(
            name: "zeros/default", plaintext: .zeros, firstBlockType: 1, crc32: 0x060B1780,
            stream: "Y2AYBaNgFAx3AAA="),
        DeflateVector(
            name: "zeros/best", plaintext: .zeros, firstBlockType: 1, crc32: 0x060B1780,
            stream: "Y2AYBaNgFAx3AAA="),
        DeflateVector(
            name: "zeros/fixed", plaintext: .zeros, firstBlockType: 1, crc32: 0x060B1780,
            stream: "Y2AYBaNgFAx3AAA="),
        DeflateVector(
            name: "zeros/huffmanOnly", plaintext: .zeros, firstBlockType: 2, crc32: 0x060B1780,
            stream: "BcGBAAAAAAAQ/9UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAg="),
        DeflateVector(
            name: "zeros/runLength", plaintext: .zeros, firstBlockType: 1, crc32: 0x060B1780,
            stream: "YxgFo2AUDHsAAA=="),
        DeflateVector(
            name: "sentences/stored", plaintext: .sentences, firstBlockType: 0, crc32: 0x29037056,
            stream: "Af4GAfkwOiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjE6IFBhY2sgbXkgYm94IHdpdGggZml2"
                + "ZSBkb3plbiBsaXF1b3IganVncy4KMjogUGFjayBteSBib3ggd2l0aCBmaXZlIGRvemVuIGxpcXVvciBqdWdzLgozOiBQYWNr"
                + "IG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjQ6IFBhY2sgbXkgYm94IHdpdGggZml2ZSBkb3plbiBsaXF1"
                + "b3IganVncy4KNTogUGFjayBteSBib3ggd2l0aCBmaXZlIGRvemVuIGxpcXVvciBqdWdzLgo2OiBQYWNrIG15IGJveCB3aXRo"
                + "IGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjc6IFBhY2sgbXkgYm94IHdpdGggZml2ZSBkb3plbiBsaXF1b3IganVncy4KODog"
                + "UGFjayBteSBib3ggd2l0aCBmaXZlIGRvemVuIGxpcXVvciBqdWdzLgo5OiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4g"
                + "bGlxdW9yIGp1Z3MuCjEwOiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjExOiBQYWNrIG15IGJv"
                + "eCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjEyOiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1"
                + "Z3MuCjEzOiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjE0OiBQYWNrIG15IGJveCB3aXRoIGZp"
                + "dmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjE1OiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjE2OiBQ"
                + "YWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjE3OiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4g"
                + "bGlxdW9yIGp1Z3MuCjE4OiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjE5OiBQYWNrIG15IGJv"
                + "eCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjIwOiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1"
                + "Z3MuCjIxOiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjIyOiBQYWNrIG15IGJveCB3aXRoIGZp"
                + "dmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjIzOiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjI0OiBQ"
                + "YWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjI1OiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4g"
                + "bGlxdW9yIGp1Z3MuCjI2OiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjI3OiBQYWNrIG15IGJv"
                + "eCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjI4OiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1"
                + "Z3MuCjI5OiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjMwOiBQYWNrIG15IGJveCB3aXRoIGZp"
                + "dmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjMxOiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjMyOiBQ"
                + "YWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjMzOiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4g"
                + "bGlxdW9yIGp1Z3MuCjM0OiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjM1OiBQYWNrIG15IGJv"
                + "eCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjM2OiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1"
                + "Z3MuCjM3OiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjM4OiBQYWNrIG15IGJveCB3aXRoIGZp"
                + "dmUgZG96ZW4gbGlxdW9yIGp1Z3MuCjM5OiBQYWNrIG15IGJveCB3aXRoIGZpdmUgZG96ZW4gbGlxdW9yIGp1Z3MuCg=="),
        DeflateVector(
            name: "sentences/default", plaintext: .sentences, firstBlockType: 2, crc32: 0x29037056,
            stream: "ldTJEcJAEEPRO1F0BJRbYo+CFAAbGLYpFgMmemL49397JTWrWG9257gOsa3f+JTXMfbl3UVbf90tLuXe10ec+sNzPErQCrQG"
                + "7QS0U9DOQDsH7QK0S2LRkJjIJaFLYpcEL4leEr4kfkkAkwiKCAptjwiKCIoIigiKCIoIigiKCJoImgga3ScRNBE0ETQRNBE0"
                + "ETQR/AM="),
        DeflateVector(
            name: "sentences/best", plaintext: .sentences, firstBlockType: 2, crc32: 0x29037056,
            stream: "ldTJEcJAEEPRO1F0BJRbYo+CFAAbGLYpFgMmemL49397JTWrWG9257gOsa3f+JTXMfbl3UVbf90tLuXe10ec+sNzPErQCrQG"
                + "7QS0U9DOQDsH7QK0S2LRkJjIJaFLYpcEL4leEr4kfkkAkwiKCAptjwiKCIoIigiKCIoIigiKCJoImgga3ScRNBE0ETQRNBE0"
                + "ETQR/AM="),
        DeflateVector(
            name: "sentences/fixed", plaintext: .sentences, firstBlockType: 1, crc32: 0x29037056,
            stream: "M7BSCEhMzlbIrVRIyq9QKM8syVBIyyxLVUjJr0rNU8jJLCzNL1LIKk0v1uMyJEGtEQlqjUlQa0KCWlMS1JqRoNacBLUWJKi1"
                + "JCUuDEhRTErMGZISdYakxJ0hKZFnSErsGZISfYakxJ8hKRFoSEoMGpESg0Yk5T1SYtCIlBg0IiUGjUiJQSNSYtCIlBg0IiUG"
                + "jUiJQWNSYtCYlBg0Jqn4JCUGjUmJQWNSYtCYlBg0JiUGjUmJQWNSYhAA"),
        DeflateVector(
            name: "sentences/huffmanOnly", plaintext: .sentences, firstBlockType: 2, crc32: 0x29037056,
            stream: "BcHRlaQgEEDRf6N4EXCmu3dnZonCFEBRS5Q6ioga/d77ZWldF1lvvF5UOSYGOQO9PiGxyFZ0Zy5jNs3L0roust54vahyTAxy"
                + "Bnp9QmKRrejOXMZsmreldV1kvfF6UeWYGOQM9PqExCJb0Z25jNk0H0vrush64/WiyjExyBno9QmJRbaiO3MZs2n+WFrXRdYb"
                + "rxdVjolBzkCvT0gsshXdmcuYTfPX0roust54vahyTAxyBnp9QmKRrejOXMZsmm9L67rIeuP1osoxMcgZ6PUJiUW2ojtzGbNp"
                + "fiyt6yLrjdeLKsfEIGeg1yckFtmK7sxlzKb5tbSui6w3Xi+qHBODnIFen5BYZCu6M5cxm+afpXVdZL3xelHlmBjkDPT6hMQi"
                + "W9GduYzZNK8vS+u6yHrj9aLKMTHIGej1CYlFtqI7cxmzaV4vS+u6yHrj9aLKMTHIGej1CYlFtqI7cxmzaV5vS+u6yHrj9aLK"
                + "MTHIGej1CYlFtqI7cxmzaV4fS+u6yHrj9aLKMTHIGej1CYlFtqI7cxmzaV5/LK3rIuuN14sqx8QgZ6DXJyQW2YruzGXMpnn9"
                + "tbSui6w3Xi+qHBODnIFen5BYZCu6M5cxm+b1bWldF1lvvF5UOSYGOQO9PiGxyFZ0Zy5jNs3rx9K6LrLeeL2ockwMcgZ6fUJi"
                + "ka3ozlzGbJrXr6V1XWS98XpR5ZgY5Az0+oTEIlvRnbmM2TSvf5bWdZH1xutFlWNikDPQ6xMSi2xFd+YyZtO8vyyt6yLrjdeL"
                + "KsfEIGeg1yckFtmK7sxlzKZ5vyyt6yLrjdeLKsfEIGeg1yckFtmK7sxlzKZ5vy2t6yLrjdeLKsfEIGeg1yckFtmK7sxlzKZ5"
                + "fyyt6yLrjdeLKsfEIGeg1yckFtmK7sxlzKZ5/7G0rousN14vqhwTg5yBXp+QWGQrujOXMZvm/dfSui6y3ni9qHJMDHIGen1C"
                + "YpGt6M5cxmya97eldV1kvfF6UeWYGOQM9PqExCJb0Z25jNk07x9L67rIeuP1osoxMcgZ6PUJiUW2ojtzGbNp3r+W1nWR9cbr"
                + "RZVjYpAz0OsTEotsRXfmMmbTvP9ZWtdF1huvF1WOiUHOQK9PSCyyFd2Zy5hN8/mytK6LrDdeL6ocE4OcgV6fkFhkK7ozlzGb"
                + "5vOytK6LrDdeL6ocE4OcgV6fkFhkK7ozlzGb5vO2tK6LrDdeL6ocE4OcgV6fkFhkK7ozlzGb5vOxtK6LrDdeL6ocE4OcgV6f"
                + "kFhkK7ozlzGb5vPH0roust54vahyTAxyBnp9QmKRrejOXMZsms9fS+u6yHrj9aLKMTHIGej1CYlFtqI7cxmzaT7fltZ1kfXG"
                + "60WVY2KQM9DrExKLbEV35jJm03x+LK3rIuuN14sqx8QgZ6DXJyQW2YruzGXMpvn8WlrXRdYbrxdVjolBzkCvT0gsshXdmcuY"
                + "TfP5Z2ldF1lvvF5UOSYGOQO9PiGxyFZ0Zy5jNs1/"),
        DeflateVector(
            name: "sentences/runLength", plaintext: .sentences, firstBlockType: 2, crc32: 0x29037056,
            stream: "BcHRlaQgEEDRf6N4EXCmu3dnZonCFEBRS5Q6ioga/d77ZWldF1lvvF5UOSYGOQO9PiGxyFZ0Zy5jNs3L0roust54vahyTAxy"
                + "Bnp9QmKRrejOXMZsmreldV1kvfF6UeWYGOQM9PqExCJb0Z25jNk0H0vrush64/WiyjExyBno9QmJRbaiO3MZs2n+WFrXRdYb"
                + "rxdVjolBzkCvT0gsshXdmcuYTfPX0roust54vahyTAxyBnp9QmKRrejOXMZsmm9L67rIeuP1osoxMcgZ6PUJiUW2ojtzGbNp"
                + "fiyt6yLrjdeLKsfEIGeg1yckFtmK7sxlzKb5tbSui6w3Xi+qHBODnIFen5BYZCu6M5cxm+afpXVdZL3xelHlmBjkDPT6hMQi"
                + "W9GduYzZNK8vS+u6yHrj9aLKMTHIGej1CYlFtqI7cxmzaV4vS+u6yHrj9aLKMTHIGej1CYlFtqI7cxmzaV5vS+u6yHrj9aLK"
                + "MTHIGej1CYlFtqI7cxmzaV4fS+u6yHrj9aLKMTHIGej1CYlFtqI7cxmzaV5/LK3rIuuN14sqx8QgZ6DXJyQW2YruzGXMpnn9"
                + "tbSui6w3Xi+qHBODnIFen5BYZCu6M5cxm+b1bWldF1lvvF5UOSYGOQO9PiGxyFZ0Zy5jNs3rx9K6LrLeeL2ockwMcgZ6fUJi"
                + "ka3ozlzGbJrXr6V1XWS98XpR5ZgY5Az0+oTEIlvRnbmM2TSvf5bWdZH1xutFlWNikDPQ6xMSi2xFd+YyZtO8vyyt6yLrjdeL"
                + "KsfEIGeg1yckFtmK7sxlzKZ5vyyt6yLrjdeLKsfEIGeg1yckFtmK7sxlzKZ5vy2t6yLrjdeLKsfEIGeg1yckFtmK7sxlzKZ5"
                + "fyyt6yLrjdeLKsfEIGeg1yckFtmK7sxlzKZ5/7G0rousN14vqhwTg5yBXp+QWGQrujOXMZvm/dfSui6y3ni9qHJMDHIGen1C"
                + "YpGt6M5cxmya97eldV1kvfF6UeWYGOQM9PqExCJb0Z25jNk07x9L67rIeuP1osoxMcgZ6PUJiUW2ojtzGbNp3r+W1nWR9cbr"
                + "RZVjYpAz0OsTEotsRXfmMmbTvP9ZWtdF1huvF1WOiUHOQK9PSCyyFd2Zy5hN8/mytK6LrDdeL6ocE4OcgV6fkFhkK7ozlzGb"
                + "5vOytK6LrDdeL6ocE4OcgV6fkFhkK7ozlzGb5vO2tK6LrDdeL6ocE4OcgV6fkFhkK7ozlzGb5vOxtK6LrDdeL6ocE4OcgV6f"
                + "kFhkK7ozlzGb5vPH0roust54vahyTAxyBnp9QmKRrejOXMZsms9fS+u6yHrj9aLKMTHIGej1CYlFtqI7cxmzaT7fltZ1kfXG"
                + "60WVY2KQM9DrExKLbEV35jJm03x+LK3rIuuN14sqx8QgZ6DXJyQW2YruzGXMpvn8WlrXRdYbrxdVjolBzkCvT0gsshXdmcuY"
                + "TfP5Z2ldF1lvvF5UOSYGOQO9PiGxyFZ0Zy5jNs1/"),
        DeflateVector(
            name: "sentences/flushed", plaintext: .sentences, firstBlockType: 1, crc32: 0x29037056,
            stream: "MrBSCEhMzlbIrVRIyq9QKM8syVBIyyxLVUjJr0rNU8jJLCzNL1LIKk0v1uMyJEGtEUwtAAAA//+qVEjKr1AozyzJUEjLLEtV"
                + "SMmvSs1TyMksLM0vUsgqTS/W4zK2UghITM5WyK0krNYEQy0AAAD//8pQSMssS1VIya9KzVPIySwszS9SyCpNL9bjMrVSCEhM"
                + "zlbIrVRIyq9QKM8sycCp1gy3WgAAAAD//6pKzVPIySwszS9SyCpNL9bjMrdSCEhMzlbIrVRIyq9QKM8syVBIyyxLVUjJr0JX"
                + "a0GEWgAAAAD//ypSyCpNL9bjsrRSCEhMzlbIrVRIyq9QKM8syVBIyyxLVUjJr0rNU8jJLCzNL4KqNTQgQTEAAAD//zI0tFII"
                + "SEzOVsitVEjKr1AozyzJUEjLLEtVSMmvSs1TyMksLM0vUsgqTS/W4zI0IkWxMVgxAAAA///KVsitVEjKr1AozyzJUEjLLEtV"
                + "SMmvSs1TyMksLM0vUsgqTS/W4zI0sVIISEzOJk6xKbJiAAAAAP//qlAozyzJUEjLLEtVSMmvSs1TyMksLM0vUsgqTS/W4zI0"
                + "s1IISEzOVsitVEjKryCg2ByLYgAAAAD//0rLLEtVSMmvSs1TyMksLM0vUsgqTS/W4zK0sFIISEzOVsitVEjKr1AozyzJUEjD"
                + "pdgSt2IAAAAA//+qSs1TyMksLM0vUsgqTS/W4zIysFIISEzOVsitVEjKr1AozyzJUEjLLEtVSMmvwlBsSFAxAAAA//8qzS9S"
                + "yCpNL9bjMjKyUghITM5WyK1USMqvUCjPLMlQSMssS1VIya9KzVPIySwsRSg2JlYxAAAA//8q1uMyMrFSCEhMzlbIrVRIyq9Q"
                + "KM8syVBIyyxLVUjJr0rNU8jJLCzNL1LIKk0vBio2JUWxmZUCAAAA//8KSEzOVsitVEjKr1AozyzJUEjLLEtVSMmvSs1TyMks"
                + "LM0vUsgqTS/W4zIyt1IIIFqxBVwxAAAA//9SSMqvUCjPLMlQSMssS1VIya9KzVPIySwszS9SyCpNL9bjMrK0UghITM5WyK1U"
                + "IKjY2ABdMQAAAP//KslQSMssS1VIya9KzVPIySwszS9SyCpNL9bjMja0UghITM5WyK1USMqvUCjPLMGj2AiHYgAAAAD//1JI"
                + "ya9KzVPIySwszS9SyCpNL9bjMja2UghITM5WyK1USMqvUCjPLMlQSMssS1XAptgEv2IAAAAA///KySwszS9SyCpNL9bjMja1"
                + "UghITM5WyK1USMqvUCjPLMlQSMssS1VIya9KzVPIQVFsRpRiAAAAAP//yipNL9bjMja3UghITM5WyK1USMqvUCjPLMlQSMss"
                + "S1VIya9KzVPIySwszS9SyIIotiBFMQAAAP//srRSCEhMzlbIrVRIyq9QKM8syVBIyyxLVUjJr0rNU8jJLCzNL1LIKk0v1uMC"
                + "AAAA//8DAA=="),
        DeflateVector(
            name: "ramp/default", plaintext: .ramp, firstBlockType: 2, crc32: 0xEA55B429,
            stream: "7dP3WogBHIbhjIZIQ6RBGjIaIg3RNBoyGiIN0TQaMhoiDdE0GjIaIg3RNBoiDZGGaBoNkYZIQzT4Xe8ROIDvBJ5/7uthEVW3"
                + "9L6W3/J7vrLpscjcNz955bc5h9991cu5TNfx7O2yzmni2ntPxxd9GBdZu9sz5mHDyNzVxm4XM2u/z5Y1OBic9uIru9RG24Cb"
                + "z9pZRNWtTl4voJLKzuNRVOJbud2FSn0zl+tRqfzzdAkqJTz5OEElryuPGqlkcuRSFpXkthwKoRLHkk12VOqYskiDSoXv/ghS"
                + "Kfr+20EquZ6/V0Ul/f3nkqkkuX6fL5UmF6wzp1LTr3mKVMp+/YObSqF3XnZTyf7MrRIqae45FUsloTW73Kk0NGeVIZWqv82S"
                + "plLK8y+sVPK78bSVShYnruZRSWnH0Qgq8azY6kSlnhlLdahU+mmqGJXiHr8fo5LH5Qf1VDI6fCGDSjKbDwRRiW3xBhsqtf1d"
                + "qEal/OZRASpF5tQNUMk5LL2SSroOgUlUEtey9qHSuLCqGZUahvkVqJRZ089FpeDUii4q2fonFlMJNM2joMmpA01YOmgcAkGj"
                + "ZQ0aYVXQDPODpqYfNKkVoPFPBI2lN2iUTUHDKw+aXk7QlHWCJr4INJ4xoDF2A42sAWjYpUDTzgKaghbQROWCxiUcNHqOoJHQ"
                + "Bs2ECGgaR0CTVQuakDTQ2AWARsMKNIIqoBnkA01VH2iSy0HjmwAacy/QKJqAhlsONN0coCnpAE1sIWjco0Fj6AoaaX3QsEqC"
                + "pnUSNHlNoInIBo1TKGh07EEjpgmaMSHQ1A+BJqMaNEEpoLHxA42aBWgElEAzwAOayh7QJJWCxicONGYeoFEwAg2XDGi62EBT"
                + "3MbC/Mf8x/zH/Mf8x/zH/Mf895///QM="),
        DeflateVector(
            name: "ramp/best", plaintext: .ramp, firstBlockType: 2, crc32: 0xEA55B429,
            stream: "7dP3WogBHIbhjIZIQ6RBGjIaIg3RNBoyGiIN0TQaMhoiDdE0GjIaIg3RNBoiDZGGaBoNkYZIQzT4Xe8ROIDvBJ5/7uthEVW3"
                + "9L6W3/J7vrLpscjcNz955bc5h9991cu5TNfx7O2yzmni2ntPxxd9GBdZu9sz5mHDyNzVxm4XM2u/z5Y1OBic9uIru9RG24Cb"
                + "z9pZRNWtTl4voJLKzuNRVOJbud2FSn0zl+tRqfzzdAkqJTz5OEElryuPGqlkcuRSFpXkthwKoRLHkk12VOqYskiDSoXv/ghS"
                + "Kfr+20EquZ6/V0Ul/f3nkqkkuX6fL5UmF6wzp1LTr3mKVMp+/YObSqF3XnZTyf7MrRIqae45FUsloTW73Kk0NGeVIZWqv82S"
                + "plLK8y+sVPK78bSVShYnruZRSWnH0Qgq8azY6kSlnhlLdahU+mmqGJXiHr8fo5LH5Qf1VDI6fCGDSjKbDwRRiW3xBhsqtf1d"
                + "qEal/OZRASpF5tQNUMk5LL2SSroOgUlUEtey9qHSuLCqGZUahvkVqJRZ089FpeDUii4q2fonFlMJNM2joMmpA01YOmgcAkGj"
                + "ZQ0aYVXQDPODpqYfNKkVoPFPBI2lN2iUTUHDKw+aXk7QlHWCJr4INJ4xoDF2A42sAWjYpUDTzgKaghbQROWCxiUcNHqOoJHQ"
                + "Bs2ECGgaR0CTVQuakDTQ2AWARsMKNIIqoBnkA01VH2iSy0HjmwAacy/QKJqAhlsONN0coCnpAE1sIWjco0Fj6AoaaX3QsEqC"
                + "pnUSNHlNoInIBo1TKGh07EEjpgmaMSHQ1A+BJqMaNEEpoLHxA42aBWgElEAzwAOayh7QJJWCxicONGYeoFEwAg2XDGi62EBT"
                + "3MbC/Mf8x/zH/Mf8x/zH/Mf895///QM="),
        DeflateVector(
            name: "ramp/fixed", plaintext: .ramp, firstBlockType: 1, crc32: 0xEA55B429,
            stream: "Y5C3i62ZvevWTwnzsNIpWy5/EjTwz+tbe+Y1l6ZHRvuyo0+YlZwSG+bvu/tHxjqqcsb2a99ETYKLJm648J5P1ye7a9XJF+xq"
                + "riktiw89ZJC3i6udsxtokkV42VSgSUKGAflAk95wa3kCTTr2lEUZaNKC/ff+Ak2qmrnjOtCkkOJJG4Em6fnmdANN4lB3SwWa"
                + "9IhRwR5o0p7bvySBJk3beuUz0KSC/nVngSZ5ZXYsB5qk4pzUCDTpn6xNNNCkG9/FTIEmbbr4gR9oUs/qUy+BJqW1LjkMNMkh"
                + "vm4u0CQpy4hyoElfhI0CgSade8ujDTRpxfFnrECTmhYeuA80KaZ61k6gSWahJZOBJgno++UCTXrFqeEONOnIYyZFoEnz9t75"
                + "DTSpYvq2q0CTggonrAeapOOd1Qk0iU3VJRlo0oP/crZAk3bd/CEONGnK5ksfgSbl9a45DTTJI71tKdAkJceEeqBJf6StIoEm"
                + "XfsqYgw0acP5d7xAk7pWnngONCmledFBoEngqLn5Axw1my+Bo6Z3DThq0tvAUeOYAI4aaStw1HwVAUfN+XfgqFl5Ahw1zYvA"
                + "URNbA44a8zBw1AgagKPmNRc4ao4+AUfN/H3gqKmcAY6a4CJw1Oj6gKOGXQ0cNQ8ZwFGz+xY4aqZuAUdNfh84ajwzwFGj7ASO"
                + "mr8y4Ki5/g0cNRsvgKOmexU4alJbwFFjHweOGkkLcNR8FgJHzdk34KhZfgwcNY0LwFETXQWOGtMQcNTw64Gj5iUHOGoOPwJH"
                + "zdw94KgpnwaOmsACcNRoe4GjhlUFHDX3/4GjZucNcNRM3gSOmtwecNS4p4GjRtEBHDW/pcBRc/ULOGrWnwNHTecKcNQkN4Gj"
                + "xjYGHDXiZuCo+SgAjprTr8BRs/QIOGrq54GjJrICHDXGQeCo4dUBR81zNnDUHHzAMJr/RvPfaP4bzX+j+W80/43mv9H8R2T+"
                + "AwA="),
        DeflateVector(
            name: "noise/stored", plaintext: .noise, firstBlockType: 0, crc32: 0xF1F821F5,
            stream: "AVgCp/2VA1KU8gZdpNWuv77mt9zydR0HYOiZ1ZFQETUfB0N1Xp3eVUMRQUCEIjmMETPKqtdu70EIJFs1SwG6sLoWhkaqvrNU"
                + "Fr1mylvybAKdL048G/3dhMNT+lr0AloXx3PQHnV3DMuYej8AYlpfYrhD1On2nh3ZTVAieWNO9jZODS9sCQVm9/wB1a3Ort59"
                + "/HqSWKV/wlmwEtWrX2+LHIk6AZPted6yXDnLw0MpXz0qGnUYKlQQRe9552l1LammkSR3qLhFDjjHGfHW9Rh9/v3QUULy0Suj"
                + "EdOL4eg8lQv8x3hWEa7lR4p90oxNa8AqqsD4dHgTle9wC4ERvxr0U6zUT4zuw18+6MCSePh7NMOi+XQJJRq3hEiNgUQNCBpQ"
                + "bTJRTesBwDin29wQg5x+Bohv2X8c4UGVxx7OwENkFjHitpcAF4Sor0eJUfsPdNmUnciFGt1ypI1m8kaEzw64mpj4kYNfVuL+"
                + "Jhwp9ZLLD0w7gDpMonk7YJX/KwSbjVKK8CtTAqgH2i9dbwSynzVkwPuXhCvYhmTouxAgz/aKUIxjiLfRoPJBOxpMOJRftr6i"
                + "eRECaVQ8CNHBXRCyhZT/ptepqWrTqcS2ax08ORu44LOg2qrvjqhZlvgT+HQxEiM1pLJnBeKqdEzFHZJlbyO9L5WI6s7J06rO"
                + "JX8T4FGzuSodNtefvoBKnNw8cdY7oCWl5M860l/ZXqZKVmITuB7qd8xcYUluIHhok+IR2p3xfHdv8ZvsdC3Mlj5iKELOyDgo"
                + "i+k252UjV8uLNaJnw3WhkyeOnsVlED+y9rMUxZw="),
        DeflateVector(
            name: "noise/default", plaintext: .noise, firstBlockType: 0, crc32: 0xF1F821F5,
            stream: "AVgCp/2VA1KU8gZdpNWuv77mt9zydR0HYOiZ1ZFQETUfB0N1Xp3eVUMRQUCEIjmMETPKqtdu70EIJFs1SwG6sLoWhkaqvrNU"
                + "Fr1mylvybAKdL048G/3dhMNT+lr0AloXx3PQHnV3DMuYej8AYlpfYrhD1On2nh3ZTVAieWNO9jZODS9sCQVm9/wB1a3Ort59"
                + "/HqSWKV/wlmwEtWrX2+LHIk6AZPted6yXDnLw0MpXz0qGnUYKlQQRe9552l1LammkSR3qLhFDjjHGfHW9Rh9/v3QUULy0Suj"
                + "EdOL4eg8lQv8x3hWEa7lR4p90oxNa8AqqsD4dHgTle9wC4ERvxr0U6zUT4zuw18+6MCSePh7NMOi+XQJJRq3hEiNgUQNCBpQ"
                + "bTJRTesBwDin29wQg5x+Bohv2X8c4UGVxx7OwENkFjHitpcAF4Sor0eJUfsPdNmUnciFGt1ypI1m8kaEzw64mpj4kYNfVuL+"
                + "Jhwp9ZLLD0w7gDpMonk7YJX/KwSbjVKK8CtTAqgH2i9dbwSynzVkwPuXhCvYhmTouxAgz/aKUIxjiLfRoPJBOxpMOJRftr6i"
                + "eRECaVQ8CNHBXRCyhZT/ptepqWrTqcS2ax08ORu44LOg2qrvjqhZlvgT+HQxEiM1pLJnBeKqdEzFHZJlbyO9L5WI6s7J06rO"
                + "JX8T4FGzuSodNtefvoBKnNw8cdY7oCWl5M860l/ZXqZKVmITuB7qd8xcYUluIHhok+IR2p3xfHdv8ZvsdC3Mlj5iKELOyDgo"
                + "i+k252UjV8uLNaJnw3WhkyeOnsVlED+y9rMUxZw="),
        DeflateVector(
            name: "noise/fixed", plaintext: .noise, firstBlockType: 0, crc32: 0xF1F821F5,
            stream: "AVgCp/2VA1KU8gZdpNWuv77mt9zydR0HYOiZ1ZFQETUfB0N1Xp3eVUMRQUCEIjmMETPKqtdu70EIJFs1SwG6sLoWhkaqvrNU"
                + "Fr1mylvybAKdL048G/3dhMNT+lr0AloXx3PQHnV3DMuYej8AYlpfYrhD1On2nh3ZTVAieWNO9jZODS9sCQVm9/wB1a3Ort59"
                + "/HqSWKV/wlmwEtWrX2+LHIk6AZPted6yXDnLw0MpXz0qGnUYKlQQRe9552l1LammkSR3qLhFDjjHGfHW9Rh9/v3QUULy0Suj"
                + "EdOL4eg8lQv8x3hWEa7lR4p90oxNa8AqqsD4dHgTle9wC4ERvxr0U6zUT4zuw18+6MCSePh7NMOi+XQJJRq3hEiNgUQNCBpQ"
                + "bTJRTesBwDin29wQg5x+Bohv2X8c4UGVxx7OwENkFjHitpcAF4Sor0eJUfsPdNmUnciFGt1ypI1m8kaEzw64mpj4kYNfVuL+"
                + "Jhwp9ZLLD0w7gDpMonk7YJX/KwSbjVKK8CtTAqgH2i9dbwSynzVkwPuXhCvYhmTouxAgz/aKUIxjiLfRoPJBOxpMOJRftr6i"
                + "eRECaVQ8CNHBXRCyhZT/ptepqWrTqcS2ax08ORu44LOg2qrvjqhZlvgT+HQxEiM1pLJnBeKqdEzFHZJlbyO9L5WI6s7J06rO"
                + "JX8T4FGzuSodNtefvoBKnNw8cdY7oCWl5M860l/ZXqZKVmITuB7qd8xcYUluIHhok+IR2p3xfHdv8ZvsdC3Mlj5iKELOyDgo"
                + "i+k252UjV8uLNaJnw3WhkyeOnsVlED+y9rMUxZw="),
    ]
}
