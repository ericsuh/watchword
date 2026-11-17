"""mise-tasks/app/diagnose-attachments.py against made-up `xcresulttool export attachments` directories.

What is at stake: when a UI test fails in CI, the element tree its helpers attach is the only account of why, and the
job log is the only place a reader without Xcode can see it. The helper must print every text attachment, skip
pictures, stay within its caps, and take nothing in the export on trust (it is a test run's output)."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support  # noqa: E402

HELPER = os.path.join(support.ROOT, "mise-tasks", "app", "diagnose-attachments.py")


class DiagnoseAttachmentsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.export = self.directory.name

    def tearDown(self):
        self.directory.cleanup()

    def write(self, name, data):
        with open(os.path.join(self.export, name), "wb") as handle:
            handle.write(data)

    def manifest(self, attachments, test="VaultSharingTests/testCreateRenameShareAndInvite()"):
        with open(os.path.join(self.export, "manifest.json"), "w", encoding="utf-8") as handle:
            json.dump([{"testIdentifier": test, "attachments": attachments}], handle)

    def run_helper(self):
        result = subprocess.run(
            [sys.executable, "-I", HELPER, self.export, "macOS"], capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_text_attachments_are_printed_and_pictures_skipped(self):
        self.write("tree.txt", b"=== UI-test diagnostics: reveal vaults.add\ntarget vaults.add: frame {{1, 2}, {3, 4}}\n")
        self.write("screen.png", support.png(2, 2, lambda x, y: (x, y, 0)))
        self.manifest(
            [
                {"exportedFileName": "tree.txt", "suggestedHumanReadableName": "element tree: reveal vaults.add.txt"},
                {"exportedFileName": "screen.png", "suggestedHumanReadableName": "screen: reveal vaults.add.png"},
            ]
        )
        output = self.run_helper()
        self.assertIn("::group::macOS: VaultSharingTests/testCreateRenameShareAndInvite(): element tree", output)
        self.assertIn("target vaults.add: frame {{1, 2}, {3, 4}}", output)
        self.assertNotIn("PNG", output)

    def test_one_long_attachment_is_cut(self):
        self.write("tree.txt", "".join(f"line {n}\n" for n in range(1000)).encode())
        self.manifest([{"exportedFileName": "tree.txt", "suggestedHumanReadableName": "element tree.txt"}])
        output = self.run_helper()
        self.assertIn("line 299\n", output)
        self.assertNotIn("line 300\n", output)

    def test_names_outside_the_export_and_missing_files_are_ignored(self):
        outside = os.path.join(os.path.dirname(self.export), "outside.txt")
        self.manifest(
            [
                {"exportedFileName": "../outside.txt", "suggestedHumanReadableName": "escape.txt"},
                {"exportedFileName": "missing.txt", "suggestedHumanReadableName": "missing.txt"},
            ]
        )
        self.assertFalse(os.path.exists(outside))
        self.assertIn("no text attachments", self.run_helper())

    def test_an_unreadable_manifest_prints_nothing_and_succeeds(self):
        self.write("manifest.json", b"{not json")
        self.assertIn("no text attachments", self.run_helper())


if __name__ == "__main__":
    unittest.main()
