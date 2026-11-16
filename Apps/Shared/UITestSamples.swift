#if DEBUG
    /// The file the import UI test and the screenshot tour import (`--uitest` launches only), so neither has to drive
    /// the system's file picker: Apple Passwords' header, an entry that duplicates the tour's Library item from a `www`
    /// host with a password and a URL of its own, and one new item. The same file is
    /// `Tests/WatchwordPresentationTests`' `sampleCSV`, where the duplicate review is tested against a real session.
    enum UITestSamples {
        static let importCSV = """
            Title,URL,Username,Password,Notes,OTPAuth
            Library,https://www.citylibrary.org/login,pat,imported-Library-9!,From the old app,
            Garden club,https://gardenclub.org/,pat@example.com,imported-Garden-4!,,
            """
    }
#endif
