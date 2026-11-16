#if canImport(Darwin)
    import Foundation

    /// Where the ciphertext store lives (docs/02-architecture.md §3, §6): the App Group container shared by the app and
    /// the AutoFill extension.
    public enum AppContainer {
        public static let databaseName = "Watchword.sqlite"

        /// `<App Group container>/Library/Application Support/Watchword/Watchword.sqlite`.
        ///
        /// Returns `nil` when the App Group is not available (an unsigned build without the entitlement). There is
        /// deliberately no fallback to the app's own container: the extension could not see a store there, and a silent
        /// split between two stores is worse than an error the person can report.
        public static func databaseURL(appGroup: String) -> URL? {
            FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
                .appendingPathComponent("Library/Application Support/Watchword", isDirectory: true)
                .appendingPathComponent(databaseName, isDirectory: false)
        }

        /// `<App Group container>/Library/Application Support/Watchword/DeviceLocal`: this device's sealed, unsynced
        /// records (the scan ledger and the prefix cache, §13.8), for `FileDeviceLocalStore`. Beside the database, so
        /// erasing the account's files reaches both; never in a folder a sync provider or a backup reads. `nil` without
        /// the App Group, as for the database.
        public static func deviceLocalStoreURL(appGroup: String) -> URL? {
            deviceLocalStore(appGroup: appGroup)?.directory
        }

        /// The device-local store at `deviceLocalStoreURL`, with the container as its trusted ancestor, so a link
        /// planted anywhere below the container is refused.
        public static func deviceLocalStore(appGroup: String) -> FileDeviceLocalStore? {
            guard let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
            else { return nil }
            return FileDeviceLocalStore(
                ancestor: container, components: ["Library", "Application Support", "Watchword", "DeviceLocal"])
        }
    }
#endif
