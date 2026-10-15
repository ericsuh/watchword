#if canImport(CoreGraphics)
    import CoreGraphics

    /// `CGContext(consumer:mediaBox:_:)`, whose media box parameter is an `UnsafePointer<CGRect>` even when `nil` is
    /// passed, so ADR 0001 puts the call here. `WatchwordPlatform.EmergencyKitDocument` uses it to render the Emergency
    /// Kit; the page size is set per page through `kCGPDFContextMediaBox`, so no pointer is ever passed.
    public enum CoreGraphicsBridge {
        public static func pdfContext(consumer: CGDataConsumer, auxiliaryInfo: CFDictionary?) -> CGContext? {
            unsafe (CGContext(consumer: consumer, mediaBox: nil, auxiliaryInfo))
        }
    }
#endif
