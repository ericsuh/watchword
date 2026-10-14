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
