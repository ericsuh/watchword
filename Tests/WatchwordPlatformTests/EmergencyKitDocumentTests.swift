#if canImport(PDFKit) && canImport(CoreImage)
    import CoreImage
    import Foundation
    import PDFKit
    import Testing
    import WatchwordKit
    import WatchwordPlatform

    @Suite("Emergency Kit PDF")
    struct EmergencyKitDocumentTests {
        static let kit = EmergencyKit(
            accountID: UUID(uuidString: "6F1C2A3B-4D5E-4F60-8172-839405A6B7C8")!,
            secretKey: "WW-A3K9QZ-7MPRT-XC4WN-B8HJD-2FGVS-K7",
            createdAt: Date(timeIntervalSince1970: 1_800_000_000))

        @Test("one page carrying the account ID, the Secret Key and the unrecoverable-loss warning")
        func content() throws {
            let document = try #require(PDFDocument(data: try EmergencyKitDocument.pdf(for: Self.kit)))
            #expect(document.pageCount == 1)
            let text = try #require(document.string)
            #expect(text.contains(Self.kit.secretKey))
            #expect(text.contains(Self.kit.accountID.uuidString))
            #expect(text.contains("cannot recover your account"))
        }

        /// Z84: the app writes the kit itself, into its swept staging folder, and the page says where not to keep it.
        @Test("write puts the same page at the URL given, which says not to keep it in a synced folder")
        func written() throws {
            let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: folder) }
            let url = folder.appendingPathComponent("Kit.pdf")
            try EmergencyKitDocument.write(Self.kit, to: url, options: [.withoutOverwriting])
            let document = try #require(PDFDocument(url: url))
            let text = try #require(document.string)
            #expect(text.contains(Self.kit.secretKey))
            #expect(text.split(whereSeparator: \.isWhitespace).joined(separator: " ").contains("iCloud Drive"))
            #expect(throws: (any Error).self) {
                try EmergencyKitDocument.write(Self.kit, to: url, options: [.withoutOverwriting])
            }
        }

        @Test("the QR code decodes to the setup code")
        func qrCode() throws {
            let image = CIImage(cgImage: try EmergencyKitDocumentProbe.qrImage(for: Self.kit))
                .transformed(by: CGAffineTransform(scaleX: 8, y: 8))
            let detector = try #require(
                CIDetector(
                    ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]))
            let messages = detector.features(in: image).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
            #expect(messages == [Self.kit.setupCode])
        }

        @Test("the Secret Key is not in the document metadata")
        func metadata() throws {
            let document = try #require(PDFDocument(data: try EmergencyKitDocument.pdf(for: Self.kit)))
            let attributes = document.documentAttributes ?? [:]
            #expect(attributes[PDFDocumentAttribute.titleAttribute] as? String == EmergencyKitText.title)
            for value in attributes.values {
                #expect(!"\(value)".contains(Self.kit.secretKey))
            }
        }
    }

    enum EmergencyKitDocumentProbe {
        static func qrImage(for kit: EmergencyKit) throws -> CGImage {
            try EmergencyKitDocument.qrCode(kit.setupCode)
        }
    }
#endif
