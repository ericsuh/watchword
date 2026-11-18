""".github/scripts/assert-unsafe-confined.sh (`mise run audit:unsafe`), its test-hook check: the `package` members that
let a test play an adversary or leave a check out (`playModifiedClient`, `enrol(…, assigningDeviceID:)`,
`MemberKeyCheck.unchecked(in:)`) are visible to every target of the package, so the compiler would let a shipped one
call them. The script allows each in the file that defines it and under Sources/WatchwordTestSupport only (review of
round 7, docs/06-adversarial-review.md Z168). Run as it is, in a scratch tree of Swift files, and once on the
repository as it stands."""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support  # noqa: E402

SCRIPT = os.path.join(support.ROOT, ".github", "scripts", "assert-unsafe-confined.sh")

DEFINITIONS = {
    "Sources/WatchwordKit/VaultSession+Sharing.swift": (
        "extension VaultSession {\n"
        "    package func playModifiedClient(_ playing: Bool = true) {\n"
        "        playsModifiedClient = playing\n"
        "    }\n"
        "}\n"
    ),
    "Sources/WatchwordKit/VaultSession+Account.swift": (
        "extension VaultSession {\n"
        "    public func enrol(as identity: DeviceIdentity?) async throws {\n"
        "        try await enrol(assigningDeviceID: identity?.id)\n"
        "    }\n"
        "    package func enrol(assigningDeviceID: UUID?) async throws {}\n"
        "}\n"
    ),
    "Sources/WatchwordSharing/MemberKeyCheck.swift": (
        "extension MemberKeyCheck {\n"
        "    package static func unchecked(in ledger: MembershipLedger) -> MemberKeyCheck { fatalError() }\n"
        "}\n"
    ),
    "Sources/WatchwordTestSupport/Fixtures.swift": (
        "func fixture(_ session: VaultSession, ledger: MembershipLedger) async throws {\n"
        "    await session.playModifiedClient()\n"
        "    try await session.enrol(assigningDeviceID: UUID())\n"
        "    _ = MemberKeyCheck\n"
        "        .unchecked(in: ledger)\n"
        "}\n"
    ),
}

CALLS = {
    "playModifiedClient": "        await session.playModifiedClient()\n",
    "assigningDeviceID": "        try await session.enrol(assigningDeviceID: named)\n",
    "unchecked(in:)": "        let check = MemberKeyCheck.unchecked( in : ledger)\n",
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
        self.assertIn("A test hook named outside", result.stdout)
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
