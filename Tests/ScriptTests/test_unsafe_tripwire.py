""".github/scripts/assert-unsafe-confined.sh (`mise run audit:unsafe`), its test-hook check: the `package` members that
let a test play an adversary or leave a check out (`playModifiedClient` and the state it sets, `enrol(…,
assigningDeviceID:)`, `MemberKeyCheck.unchecked(in:)` and `MemberKeyCheck`'s initialiser) are visible to every target
of the package, so the compiler would let a shipped one call them. The script allows each on the lines that define or
apply it, matched whole and counted, and under Sources/WatchwordTestSupport only (review of round 7,
docs/06-adversarial-review.md Z168; the evasions of round 8, Z172; a copy of an allowed line, round 9, Z178). Run
as it is, in a scratch tree of Swift files, and once on the repository as it stands."""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support  # noqa: E402

SCRIPT = os.path.join(support.ROOT, ".github", "scripts", "assert-unsafe-confined.sh")

# The defining and applying lines the script allows, each in its own file, as the repository holds them.
DEFINITIONS = {
    "Sources/WatchwordKit/VaultSession.swift": (
        "public actor VaultSession {\n"
        "    /// For tests (`playModifiedClient()`).\n"
        "    var playsModifiedClient = false\n"
        "}\n"
    ),
    "Sources/WatchwordKit/VaultSession+Sharing.swift": (
        "extension VaultSession {\n"
        "    func thisDeviceCommits() -> Bool {\n"
        "        if playsModifiedClient { return true }\n"
        "        return false\n"
        "    }\n"
        "    package func playModifiedClient(_ playing: Bool = true) {\n"
        "        playsModifiedClient = playing\n"
        "    }\n"
        "}\n"
    ),
    "Sources/WatchwordKit/VaultSession+Sync.swift": (
        "extension VaultSession {\n"
        "    func verifyOwn(_ location: Location) -> Bool {\n"
        "        if sharing.vaults[location.vaultID] != nil, !playsModifiedClient,\n"
        "            true\n"
        "        { return false }\n"
        "        return true\n"
        "    }\n"
        "}\n"
    ),
    "Sources/WatchwordKit/VaultSession+Account.swift": (
        "extension VaultSession {\n"
        "    public func enrol(as identity: DeviceIdentity?) async throws {\n"
        "        try await enrol(\n"
        "            password: password, secretKey: secretKey, accountID: accountID, assigningDeviceID: identity?.id)\n"
        "    }\n"
        "    package func enrol(password: String, secretKey text: String, accountID: UUID?, assigningDeviceID: UUID?)\n"
        "        async throws\n"
        "    {\n"
        "        if let assigningDeviceID {\n"
        "            deviceID = assigningDeviceID\n"
        "        }\n"
        "    }\n"
        "}\n"
    ),
    "Sources/WatchwordSharing/MemberKeyCheck.swift": (
        "extension MemberKeyCheck {\n"
        "    package static func unchecked(in ledger: MembershipLedger) -> MemberKeyCheck {\n"
        "        MemberKeyCheck(vaultID: ledger.vaultID, head: ledger.state.hash, substituted: [], unverified: [])\n"
        "    }\n"
        "    static func check(_ ledger: MembershipLedger) -> MemberKeyCheck {\n"
        "        return MemberKeyCheck(\n"
        "            vaultID: ledger.vaultID, head: ledger.state.hash, substituted: [], unverified: [])\n"
        "    }\n"
        "}\n"
    ),
    "Sources/WatchwordTestSupport/Fixtures.swift": (
        "func fixture(_ session: VaultSession, ledger: MembershipLedger) async throws {\n"
        "    await session.playModifiedClient()\n"
        "    try await session.enrol(password: \"\", secretKey: \"\", accountID: nil, assigningDeviceID: UUID())\n"
        "    _ = MemberKeyCheck\n"
        "        .unchecked(in: ledger)\n"
        "}\n"
    ),
}

CALLS = {
    "playModifiedClient": "        await session.playModifiedClient()\n",
    "playsModifiedClient": "        session.playsModifiedClient = true\n",
    "assigningDeviceID": "        try await session.enrol(assigningDeviceID: named)\n",
    "unchecked(in:)": "        let check = MemberKeyCheck.unchecked( in : ledger)\n",
    "MemberKeyCheck.init": "        let check = MemberKeyCheck(vaultID: id, head: head, substituted: [], unverified: [])\n",
}

# Ways round the patterns of round 7 (review of round 8): each is refused at the line given.
EVASIONS = {
    "the call split over lines": ("        let check = MemberKeyCheck\n            .unchecked(in: ledger)\n", 3),
    "the argument on the next line": ("        let check = MemberKeyCheck.unchecked(\n            in: ledger)\n", 2),
    "a backticked name": ("        let check = MemberKeyCheck.`unchecked`(in: ledger)\n", 2),
    "a backticked hook": ("        await session.`playModifiedClient`()\n", 2),
    "an unapplied reference": ("        let make = MemberKeyCheck.unchecked\n", 2),
    "an unapplied reference by implicit member": ("        let make: (MembershipLedger) -> MemberKeyCheck = .unchecked\n", 2),
    "a bare call in an extension": ("        unchecked(in: ledger)\n", 2),
    "the initialiser by name": ("        let check = MemberKeyCheck.init(vaultID: id, head: h, substituted: [], unverified: [])\n", 2),
    "the initialiser unapplied": ("        let make = MemberKeyCheck.init\n", 2),
}


class TestHookTripwireTests(support.ScriptTestCase):
    def setUp(self):
        super().setUp()
        for directory in ("Sources", "Tests", "Apps"):
            os.makedirs(self.path(directory), exist_ok=True)
        for relative, text in DEFINITIONS.items():
            self.write(relative, text)
        support.git(self.scratch, "init", "-q")

    def run_script(self):
        return self.run_process(["bash", SCRIPT])

    def assert_passes(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("test hooks only in tests", result.stdout)

    def assert_refused(self, expected):
        result = self.run_script()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("A test hook (", result.stdout)
        self.assertIn(expected, result.stdout)

    def caller(self, call):
        return "func caller() async throws {\n" + call + "}\n"

    def test_the_definitions_and_test_support_pass(self):
        self.assert_passes()

    def test_the_repository_as_it_stands_passes(self):
        result = subprocess.run(
            ["bash", SCRIPT], cwd=support.ROOT, capture_output=True, text=True, check=False,
            env={**os.environ, "LC_ALL": "C"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_each_hook_in_a_shipped_target_is_refused(self):
        for name, call in CALLS.items():
            with self.subTest(hook=name):
                target = self.write("Sources/WatchwordPlatform/Adapter.swift", self.caller(call))
                self.assert_refused("Sources/WatchwordPlatform/Adapter.swift:2:")
                os.remove(target)

    def test_a_hook_in_another_file_of_its_own_module_is_refused(self):
        self.write("Sources/WatchwordKit/VaultSession+Vaults.swift", self.caller(CALLS["playModifiedClient"]))
        self.assert_refused("Sources/WatchwordKit/VaultSession+Vaults.swift:2:")

    def test_a_new_line_in_a_defining_file_is_refused(self):
        # The file that defines a hook is not allowed as a whole: only the lines that define or apply it.
        for relative, line, hook in (
            ("Sources/WatchwordKit/VaultSession+Sharing.swift", "playsModifiedClient = true", "playsModifiedClient"),
            ("Sources/WatchwordKit/VaultSession+Sync.swift", "await playModifiedClient()", "playModifiedClient"),
            ("Sources/WatchwordSharing/MemberKeyCheck.swift", "let check = Self.unchecked(in: ledger)",
             "MemberKeyCheck.unchecked"),
            ("Sources/WatchwordSharing/MemberKeyCheck.swift",
             "MemberKeyCheck(vaultID: other, head: head, substituted: [], unverified: [])", "MemberKeyCheck.init"),
        ):
            with self.subTest(file=relative, hook=hook):
                original = DEFINITIONS[relative]
                self.write(relative, original + "func added() {\n    " + line + "\n}\n")
                try:
                    self.assert_refused("(" + hook + ")")
                    self.assert_refused(relative + ":" + str(original.count("\n") + 2) + ":")
                finally:
                    self.write(relative, original)

    def test_a_copy_of_an_allowed_line_in_its_file_is_refused(self):
        # Each allowed line is counted (review of round 9, Z178): a copy of it elsewhere in the defining file is a new
        # use of the hook, whatever its text.
        for relative, line, hook in (
            ("Sources/WatchwordKit/VaultSession+Sharing.swift", "playsModifiedClient = playing", "playsModifiedClient"),
            ("Sources/WatchwordKit/VaultSession+Sync.swift",
             "if sharing.vaults[location.vaultID] != nil, !playsModifiedClient,", "playsModifiedClient"),
            ("Sources/WatchwordKit/VaultSession+Account.swift", "deviceID = assigningDeviceID", "assigningDeviceID"),
            ("Sources/WatchwordSharing/MemberKeyCheck.swift", "return MemberKeyCheck(", "MemberKeyCheck.init"),
        ):
            with self.subTest(file=relative, hook=hook):
                original = DEFINITIONS[relative]
                self.write(relative, original + "func added() {\n    " + line + "\n}\n")
                try:
                    self.assert_refused("(" + hook + ")")
                    self.assert_refused(relative + ":" + str(original.count("\n") + 2) + ":")
                finally:
                    self.write(relative, original)

    def test_each_evasion_is_refused(self):
        for name, (call, line) in EVASIONS.items():
            with self.subTest(evasion=name):
                target = self.write("Sources/WatchwordSharing/Rotation.swift", self.caller(call))
                self.assert_refused("Sources/WatchwordSharing/Rotation.swift:" + str(line) + ":")
                os.remove(target)

    def test_other_uses_of_the_word_unchecked_pass(self):
        self.write(
            "Sources/WatchwordSharing/Membership.swift",
            "public struct WriteCut {\n"
            "    public static let nothing = WriteCut(unchecked: [])\n"
            "    init(unchecked bytes: [UInt8]) {}\n"
            "}\n"
            "func hosts(_ concern: Concern) -> [String] {\n"
            "    var unchecked: [String] = []\n"
            "    if !concern.uncheckedHosts.isEmpty { unchecked.append(\"host\") }\n"
            "    return unchecked\n"
            "}\n",
        )
        self.write("Sources/SecureMemory/Buffer.swift", "final class Buffer: @unchecked Sendable {}\n")
        self.assert_passes()

    def test_a_hook_in_the_apps_is_refused(self):
        self.write("Apps/Shared/Settings.swift", self.caller(CALLS["assigningDeviceID"]))
        self.assert_refused("Apps/Shared/Settings.swift:2:")

    def test_a_hook_named_in_a_comment_or_inside_a_longer_name_passes(self):
        self.write(
            "Sources/WatchwordPresentation/Model.swift",
            "/// Tests call `playModifiedClient()` and `MemberKeyCheck.unchecked(in:)`; nothing here does.\n"
            "    // enrol(assigningDeviceID:) is for tests.\n"
            "let replayModifiedClientCount = 0\n"
            "let assigningDeviceIDs: [UUID] = []\n",
        )
        self.assert_passes()


if __name__ == "__main__":
    unittest.main()
