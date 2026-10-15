#if canImport(CoreGraphics) && canImport(CoreText) && canImport(CoreImage)
    import CoreGraphics
    import CoreImage
    import CoreImage.CIFilterBuiltins
    import CoreText
    import Foundation
    import SecureMemory
    import WatchwordKit

    public enum EmergencyKitDocumentError: Error, Equatable, Sendable {
        case renderingFailed
    }

    /// Renders the Emergency Kit as a one-page PDF (PRD F5.1, F10.2), with Core Graphics and Core Text so the same code
    /// runs on iOS and macOS.
    ///
    /// The PDF is returned as `Data` and never written by this type: the caller hands it straight to the share sheet or
    /// save panel, so the Secret Key does not land in the app's container, its caches or a temporary directory. The
    /// document metadata carries only a title; the Secret Key appears in the page content and the QR code, nowhere else.
    public enum EmergencyKitDocument {
        /// US Letter in points; also prints within A4's printable area.
        static let pageSize = CGSize(width: 612, height: 792)
        static let margin: CGFloat = 54

        public static func pdf(for kit: EmergencyKit) throws -> Data {
            let data = NSMutableData()
            let mediaBox = CGRect(origin: .zero, size: pageSize)
            let info = [kCGPDFContextTitle as String: EmergencyKitText.title] as CFDictionary
            guard let consumer = CGDataConsumer(data: data as CFMutableData),
                let context = CoreGraphicsBridge.pdfContext(consumer: consumer, auxiliaryInfo: info)
            else { throw EmergencyKitDocumentError.renderingFailed }

            context.beginPDFPage([kCGPDFContextMediaBox as String: mediaBox.dictionaryRepresentation] as CFDictionary)
            let width = pageSize.width - 2 * margin
            var top = pageSize.height - margin

            top = draw(EmergencyKitText.title, font: font("Helvetica-Bold", 24), in: context, top: top, width: width)
            top = draw(
                EmergencyKitText.instructions, font: font("Helvetica", 11), in: context, top: top - 12, width: width)
            top = draw("Account ID", font: font("Helvetica-Bold", 10), in: context, top: top - 18, width: width)
            top = draw(
                kit.accountID.uuidString, font: font("Menlo-Regular", 11), in: context, top: top - 2, width: width)
            top = draw("Secret Key", font: font("Helvetica-Bold", 10), in: context, top: top - 14, width: width)
            top = draw(kit.secretKey, font: font("Menlo-Bold", 16), in: context, top: top - 2, width: width)
            top = draw(
                EmergencyKitText.passwordLine, font: font("Helvetica", 10), in: context, top: top - 18, width: width)
            context.setStrokeColor(CGColor(gray: 0.6, alpha: 1))
            context.stroke(CGRect(x: margin, y: top - 34, width: width, height: 28))
            top -= 50

            let qrSide: CGFloat = 170
            let qr = try qrCode(kit.setupCode)
            context.interpolationQuality = .none
            context.draw(qr, in: CGRect(x: margin, y: top - qrSide, width: qrSide, height: qrSide))
            _ = draw(
                "Scan this code with Watchword on a new device to enter your Secret Key. It does not contain your "
                    + "account password.",
                font: font("Helvetica", 10), in: context, top: top, width: width - qrSide - 18,
                left: margin + qrSide + 18)
            top -= qrSide + 24

            _ = draw(
                EmergencyKitText.unrecoverableWarning, font: font("Helvetica-Bold", 11), in: context, top: top,
                width: width)
            context.endPDFPage()
            context.closePDF()
            return data as Data
        }

        private static func font(_ name: String, _ size: CGFloat) -> CTFont {
            CTFontCreateWithName(name as CFString, size, nil)
        }

        /// Draws wrapped text whose first line starts at `top`; returns the y coordinate below it.
        private static func draw(
            _ text: String, font: CTFont, in context: CGContext, top: CGFloat, width: CGFloat, left: CGFloat = margin
        ) -> CGFloat {
            let attributed = NSAttributedString(
                string: text,
                attributes: [
                    NSAttributedString.Key(kCTFontAttributeName as String): font,
                    NSAttributedString.Key(kCTForegroundColorAttributeName as String): CGColor(gray: 0, alpha: 1),
                ])
            let framesetter = CTFramesetterCreateWithAttributedString(attributed)
            let size = CTFramesetterSuggestFrameSizeWithConstraints(
                framesetter, CFRange(location: 0, length: 0), nil,
                CGSize(width: width, height: .greatestFiniteMagnitude), nil)
            let height = ceil(size.height)
            let path = CGMutablePath()
            path.addRect(CGRect(x: left, y: top - height, width: width, height: height))
            CTFrameDraw(CTFramesetterCreateFrame(framesetter, CFRange(location: 0, length: 0), path, nil), context)
            return top - height
        }

        /// The setup code as a QR image, error-correction level M, one CGImage pixel per module.
        public static func qrCode(_ payload: String) throws -> CGImage {
            let filter = CIFilter.qrCodeGenerator()
            filter.message = Data(payload.utf8)
            filter.correctionLevel = "M"
            guard let image = filter.outputImage,
                let cgImage = CIContext(options: [.useSoftwareRenderer: true]).createCGImage(image, from: image.extent)
            else { throw EmergencyKitDocumentError.renderingFailed }
            return cgImage
        }
    }
#endif
