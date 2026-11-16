#if !WATCHWORD_LIBFUZZER
    import Foundation
    import WatchwordEnvelope
    import WatchwordSync

    /// The harness without libFuzzer: replays inputs through a target, and mutates a corpus blindly.
    ///
    /// Two uses. Reproducing a finding needs no sanitiser build: `WatchwordFuzz replay <target> <file>` runs the one
    /// input and traps where libFuzzer did. And a toolchain with no libFuzzer runtime can still exercise every target:
    /// `mutate` is no substitute for coverage guidance, but it replays the whole corpus and tries a seeded stream of
    /// mutations of it, which is what `mise run fuzz` falls back to.
    @main
    enum Replay {
        static func main() {
            let arguments = Array(CommandLine.arguments.dropFirst())
            do {
                switch arguments.first {
                case "list":
                    for target in FuzzTarget.allCases {
                        print(target.rawValue)
                    }
                case "replay":
                    guard arguments.count >= 3 else { throw Usage() }
                    let target = try target(arguments[1])
                    let inputs = try files(under: Array(arguments[2...]))
                    for (path, bytes) in inputs {
                        print(path)
                        target.run(bytes)
                    }
                    print("\(target.rawValue): replayed \(inputs.count) inputs")
                case "mutate":
                    guard arguments.count >= 5, let runs = Int(arguments[2]), let seed = UInt64(arguments[3]) else {
                        throw Usage()
                    }
                    let target = try target(arguments[1])
                    let corpus = try files(under: Array(arguments[4...])).map(\.bytes)
                    for bytes in corpus {
                        target.run(bytes)
                    }
                    var mutator = Mutator(seed: seed, corpus: corpus)
                    for _ in 0..<runs {
                        target.run(mutator.next())
                    }
                    print("\(target.rawValue): replayed \(corpus.count) inputs, then \(runs) mutations (seed \(seed))")
                case "seeds":
                    guard arguments.count == 2 else { throw Usage() }
                    try writeSeeds(to: URL(fileURLWithPath: arguments[1], isDirectory: true))
                default:
                    throw Usage()
                }
            } catch {
                FileHandle.standardError.write(
                    Data(
                        """
                        \(error)
                        usage: WatchwordFuzz list
                               WatchwordFuzz replay <target> <file or directory>...
                               WatchwordFuzz mutate <target> <runs> <seed> <file or directory>...
                               WatchwordFuzz seeds <corpus directory>

                        """.utf8))
                exit(2)
            }
        }

        struct Usage: Error, CustomStringConvertible {
            var description: String { "bad arguments" }
        }

        struct UnknownTarget: Error, CustomStringConvertible {
            var name: String
            var description: String { "no target named \(name)" }
        }

        private static func target(_ name: String) throws -> FuzzTarget {
            guard let target = FuzzTarget(rawValue: name) else { throw UnknownTarget(name: name) }
            return target
        }

        /// The files named, and the files directly inside the directories named, in a stable order.
        private static func files(under paths: [String]) throws -> [(path: String, bytes: [UInt8])] {
            var found: [(String, [UInt8])] = []
            for path in paths {
                var isDirectory: ObjCBool = false
                guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory) else { continue }
                let names =
                    isDirectory.boolValue
                    ? try FileManager.default.contentsOfDirectory(atPath: path).sorted().map { path + "/" + $0 }
                    : [path]
                for name in names {
                    var isNested: ObjCBool = false
                    guard FileManager.default.fileExists(atPath: name, isDirectory: &isNested), !isNested.boolValue
                    else { continue }
                    found.append((name, Array(try Data(contentsOf: URL(fileURLWithPath: name)))))
                }
            }
            return found
        }

        /// Writes one valid input for each binary format into `<directory>/<target>/`, built with the formats' own
        /// writers, so a run starts from inputs that get past the first checks. The text formats' seeds are written by
        /// hand and committed beside them.
        private static func writeSeeds(to directory: URL) throws {
            let context = FuzzTarget.envelopeContext
            let header = try EnvelopeHeader(
                kind: context.kind, keyID: context.keyID, nonce: [UInt8](0..<12), aad: context.canonicalAAD())
            let envelope = try Envelope(header: header, ciphertext: [UInt8](repeating: 0xAB, count: 48)).serialized()
            let author = UUID(uuid: (3, 3, 3, 3, 3, 3, 0x43, 3, 0x83, 3, 3, 3, 3, 3, 3, 3))
            // A deletion names no key.
            let zero = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
            let payload = SyncPayload(
                kind: .segment, vaultID: context.vaultID, author: author, number: 1, vector: [author: 2],
                entries: [
                    SyncEntry(
                        recordID: context.recordID, kind: .item, keyID: context.keyID, version: 7, device: author,
                        envelope: envelope),
                    SyncEntry(
                        recordID: author, kind: .item, keyID: zero, version: 2, device: author,
                        envelope: nil, erasure: [1, 2, 3]),
                ]
            ).encoded()
            let signed = SignedObject(signature: [UInt8](repeating: 0x5A, count: 64), envelope: envelope).serialized()
            // For `amplify`: a format byte, a two-byte repeat count, and the unit that is repeated.
            func recipe(_ format: UInt8, _ count: UInt16, _ unit: String) -> [UInt8] {
                [format, UInt8(count >> 8), UInt8(count & 0xFF)] + Array(unit.utf8)
            }
            let login =
                #"{"categoryUuid":"001","overview":{"title":"t","url":"https://example.com"},"details":{"loginFields":"#
                + #"[{"designation":"username","value":"u"},{"designation":"password","value":"p"}],"notesPlain":"n"}}"#
            let credential =
                #"{"title":"t","scope":{"urls":["https://example.com/x"]},"credentials":[{"type":"basic-auth","#
                + #""username":{"fieldType":"string","value":"u"},"password":{"fieldType":"concealed-string","#
                + #""value":"p"}},{"type":"note","content":{"fieldType":"string","value":"n"}}]}"#
            let seeds: [(FuzzTarget, String, [UInt8])] = [
                (.envelope, "item-envelope", envelope), (.syncPayload, "segment", payload),
                (.signedObject, "signed-envelope", signed),
                (.amplify, "csv-rows", recipe(0, 64, "t,https://example.com/login,u,p,n,GEZDGNBVGY3TQOJQ,a,b,c,d")),
                (.amplify, "csv-short-cells", recipe(0, .max, "a,a,a,a,a,a,a,a,a,a")),
                (.amplify, "1pux-items", recipe(1, 64, login)),
                (.amplify, "1pux-urls-repeated", recipe(2, .max, "https://a.bc")),
                (.amplify, "1pux-urls-refused", recipe(2, 4_096, "intranet")),
                (.amplify, "1pux-fields", recipe(3, .max, #"{"value":{"string":"a"}}"#)),
                (
                    .amplify, "1pux-fields-typed",
                    recipe(3, 256, #"{"title":"t","id":"i","value":{"totp":"GEZDGNBVGY3TQOJQ"}}"#)
                ),
                (.amplify, "cxf-items", recipe(4, 64, credential)),
            ]
            for (target, name, bytes) in seeds {
                let folder = directory.appendingPathComponent(target.rawValue, isDirectory: true)
                try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
                try Data(bytes).write(to: folder.appendingPathComponent(name))
                print("wrote \(target.rawValue)/\(name) (\(bytes.count) bytes)")
            }
        }
    }

    /// Blind mutations of a corpus: truncation, repetition, removal, splicing and byte changes, biased towards the
    /// bytes that carry structure in the formats under test.
    struct Mutator {
        private static let interesting: [UInt8] = [
            0x00, 0x22, 0x2C, 0x0A, 0x0D, 0x5B, 0x5D, 0x7B, 0x7D, 0x5C, 0xFF, 0x80, 0x50, 0x4B, 0x3A, 0x2F, 0x25, 0x40,
        ]

        private var generator: FuzzGenerator
        private let corpus: [[UInt8]]

        init(seed: UInt64, corpus: [[UInt8]]) {
            generator = FuzzGenerator(seed: seed)
            self.corpus = corpus.isEmpty ? [[]] : corpus
        }

        mutating func next() -> [UInt8] {
            var bytes = corpus.randomElement(using: &generator)!
            for _ in 0..<Int.random(in: 1...3, using: &generator) {
                switch Int.random(in: 0..<7, using: &generator) {
                case 0:
                    bytes = Array(bytes[..<Int.random(in: 0...bytes.count, using: &generator)])
                case 1 where !bytes.isEmpty:
                    let start = Int.random(in: 0..<bytes.count, using: &generator)
                    let end = min(bytes.count, start + Int.random(in: 1...64, using: &generator))
                    bytes.insert(contentsOf: bytes[start..<end], at: Int.random(in: 0...bytes.count, using: &generator))
                case 2 where !bytes.isEmpty:
                    let start = Int.random(in: 0..<bytes.count, using: &generator)
                    bytes.removeSubrange(start..<min(bytes.count, start + Int.random(in: 1...16, using: &generator)))
                case 3:
                    let other = corpus.randomElement(using: &generator)!
                    let cut = Int.random(in: 0...bytes.count, using: &generator)
                    bytes = Array(bytes[..<cut]) + other[Int.random(in: 0...other.count, using: &generator)...]
                case 4:
                    bytes.insert(
                        Mutator.interesting.randomElement(using: &generator)!,
                        at: Int.random(in: 0...bytes.count, using: &generator))
                default:
                    guard !bytes.isEmpty else { continue }
                    bytes[Int.random(in: bytes.indices, using: &generator)] =
                        Bool.random(using: &generator)
                        ? Mutator.interesting.randomElement(using: &generator)!
                        : UInt8.random(in: 0...255, using: &generator)
                }
            }
            return bytes
        }
    }
#endif
