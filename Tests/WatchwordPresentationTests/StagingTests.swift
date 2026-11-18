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
        #expect(!FileManager.default.fileExists(atPath: earlier.path), "an earlier build's leftover stays")
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
