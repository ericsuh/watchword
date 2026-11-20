import Foundation
import Testing
import WatchwordKit
import WatchwordPresentation
import WatchwordTestSupport

/// The one folder the app writes files into for the system's file mover (Z80): what a process that died with the
/// mover up leaves behind is removed by the sweep the app runs at launch, unlock, lock and termination, which does not
/// depend on the state of the model that staged it.
@Suite("Screen models: staged files")
@MainActor
struct StagingTests {
    func temporaryRoot() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    }

    func exportStaged(in staging: StagingFolder, vault: TestVault) async throws -> URL {
        let model = ExportModel(context: ContextProbe().context(vault.session), staging: staging)
        await model.load()
        model.kind = .applePasswordsCSV
        model.password = TestVault.password
        await model.export()
        return try model.stage(options: [])
        // The model goes here without `finishSaving` or `discardFile`: what a killed process leaves.
    }

    /// The reproduction of interchange #5 and network #2: the export model was the only thing that knew where its
    /// copy was, so a process that died with the file mover up left every exported password in the temporary
    /// directory, and no later launch looked for it.
    @Test("a plaintext export left by a process that died is removed by the next launch's sweep")
    func launchSweep() async throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let vault = TestVault()
        try await vault.createAccount()
        let personal = try #require(await vault.session.personalVaultID)
        _ = try await vault.session.save(
            login(personal, "Library", host: "citylibrary.org", username: "pat", password: "x7#Vq9!mLp2$Zr8@Wn4&"))
        let staging = StagingFolder(temporaryDirectory: root)
        let staged = try await exportStaged(in: staging, vault: vault)
        #expect(FileManager.default.fileExists(atPath: staged.path))
        // An export staged by a build from before the folder, directly in the temporary directory.
        let earlier = root.appendingPathComponent("Export-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: earlier, withIntermediateDirectories: true)
        try Data("Title,Password\nBank,hunter2\n".utf8).write(to: earlier.appendingPathComponent("old.csv"))
        let unrelated = root.appendingPathComponent("unrelated.txt")
        try Data("kept".utf8).write(to: unrelated)

        // The next launch: a new process, which knows only the folder's fixed place.
        StagingFolder(temporaryDirectory: root).sweep()
        #expect(!FileManager.default.fileExists(atPath: staged.path))
        #expect(!FileManager.default.fileExists(atPath: staging.url.path))
        #expect(!FileManager.default.fileExists(atPath: earlier.path), "an earlier build's leftover is removed")
        #expect(FileManager.default.fileExists(atPath: unrelated.path), "the sweep removes only what is staged")
    }

    @Test("a lock sweeps the folder even when the model that staged a file is gone")
    func lockSweep() async throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let vault = TestVault()
        try await vault.createAccount()
        let locks = await LockSignal.watching(vault.session)
        defer { locks.stop() }
        let staging = StagingFolder(temporaryDirectory: root)
        let sweeper = StagingSweeper(folder: staging, locks: locks)
        let staged = try await exportStaged(in: staging, vault: vault)
        #expect(!staging.stagedFiles().isEmpty)
        await vault.session.lock()
        for _ in 0..<1000 where !staging.stagedFiles().isEmpty { await Task.yield() }
        #expect(!FileManager.default.fileExists(atPath: staged.path))
        _ = sweeper
    }

    /// The review of Z80 (Z99): `start()` runs once per window, and swept on every call, so opening a second window
    /// (Cmd-N, a second iPad window) deleted the file a first window's save sheet was presenting, and the save
    /// failed. The launch sweep is the first start's only; a lock still sweeps.
    @Test("a second window's start does not remove a file another window is saving")
    func secondWindowKeepsTheStagedFile() async throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let staging = StagingFolder(temporaryDirectory: root)
        let leftover = try staging.stage(named: "left.csv") { try Data("old".utf8).write(to: $0) }
        let sweeper = StagingSweeper(folder: staging)
        sweeper.launched()
        #expect(
            !FileManager.default.fileExists(atPath: leftover.path), "the first start sweeps what a dead process left")
        let presenting = try staging.stage(named: "Export.csv") { try Data("rows".utf8).write(to: $0) }
        sweeper.launched()
        #expect(FileManager.default.fileExists(atPath: presenting.path), "the second window's start removed it")
        sweeper.dropOnLock()
        #expect(!FileManager.default.fileExists(atPath: presenting.path))
    }

    /// The review of Z80 (Z129): `stage` created its folder with intermediate directories under a path it trusted. A8,
    /// or anyone who can write to the per-user temporary directory of an unsandboxed build (`app:test macos`, CI),
    /// makes `Watchword Staging` a symbolic link to a folder of their choosing, and the next export's plaintext was
    /// written through it. And the sweep of earlier builds' `Export-*` folders removed any other program's folder of
    /// that name in the temporary directory. Now a staging folder that is not a real directory is replaced before
    /// anything is written, and only an `Export-<UUID>` folder holding one regular file is swept.
    @Test("a staging folder replaced by a link is not written through, and the earlier sweep removes only its own")
    func stagingFolderIsNotALink() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let manager = FileManager.default
        try manager.createDirectory(at: root, withIntermediateDirectories: true)
        let elsewhere = root.appendingPathComponent("elsewhere", isDirectory: true)
        try manager.createDirectory(at: elsewhere, withIntermediateDirectories: true)
        let staging = StagingFolder(temporaryDirectory: root)
        try manager.createSymbolicLink(at: staging.url, withDestinationURL: elsewhere)

        let staged = try staging.stage(named: "Export.csv") { try Data("Title,Password\n".utf8).write(to: $0) }
        #expect(try manager.contentsOfDirectory(atPath: elsewhere.path).isEmpty, "written through the link")
        let type = try manager.attributesOfItem(atPath: staging.url.path)[.type] as? FileAttributeType
        #expect(type == .typeDirectory)
        #expect(manager.fileExists(atPath: staged.path))

        // The earlier builds' folders: only `Export-<UUID>` holding one regular file is theirs.
        let ours = root.appendingPathComponent("Export-\(UUID().uuidString)", isDirectory: true)
        try manager.createDirectory(at: ours, withIntermediateDirectories: true)
        try Data("old".utf8).write(to: ours.appendingPathComponent("old.csv"))
        let named = root.appendingPathComponent("Export-reports", isDirectory: true)
        try manager.createDirectory(at: named, withIntermediateDirectories: true)
        try Data("kept".utf8).write(to: named.appendingPathComponent("q3.pdf"))
        let fuller = root.appendingPathComponent("Export-\(UUID().uuidString)", isDirectory: true)
        try manager.createDirectory(at: fuller, withIntermediateDirectories: true)
        try Data("a".utf8).write(to: fuller.appendingPathComponent("a.txt"))
        try Data("b".utf8).write(to: fuller.appendingPathComponent("b.txt"))
        staging.sweep()
        #expect(!manager.fileExists(atPath: ours.path))
        #expect(manager.fileExists(atPath: named.path), "another program's Export- folder was removed")
        #expect(manager.fileExists(atPath: fuller.path), "a folder no earlier build wrote was removed")
        #expect(manager.fileExists(atPath: elsewhere.path))
    }

    @Test("each staged file has a folder of its own, a name cannot leave it, and removal touches nothing else")
    func layout() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let staging = StagingFolder(temporaryDirectory: root)
        let first = try staging.stage(named: "../../escape.pdf") { try Data("one".utf8).write(to: $0) }
        let second = try staging.stage(named: "Kit.pdf") { try Data("two".utf8).write(to: $0) }
        #expect(first.lastPathComponent == "..-..-escape.pdf")
        #expect(first.deletingLastPathComponent() != second.deletingLastPathComponent())
        #expect(Set(staging.stagedFiles().map(\.lastPathComponent)) == ["..-..-escape.pdf", "Kit.pdf"])
        let outside = root.appendingPathComponent("outside.txt")
        try Data("kept".utf8).write(to: outside)
        staging.remove(outside)
        #expect(FileManager.default.fileExists(atPath: outside.path))
        staging.remove(first)
        #expect(staging.stagedFiles().map(\.lastPathComponent) == ["Kit.pdf"])
        struct Failed: Error {}
        #expect(throws: Failed.self) { _ = try staging.stage(named: "half.csv") { _ in throw Failed() } }
        #expect(staging.stagedFiles().map(\.lastPathComponent) == ["Kit.pdf"], "a failed write leaves nothing")
    }
}
