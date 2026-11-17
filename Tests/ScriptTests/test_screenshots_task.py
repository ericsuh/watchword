"""mise-tasks/app/screenshots, run with stand-ins for `mise run app:test`, `xcrun xcresulttool` and `sips`.

The task is what a capture job and a person both run. What it writes where a set goes, what it tells the job summary
and what it announces to the comment job must be true of a failed capture as much as of a good one."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support  # noqa: E402

THREE = [("01-onboarding", "Choosing the password"), ("02-emergency-kit", "The kit"), ("03-item-list-empty", "Empty")]

# `mise run app:test <os> --only-testing=… --results <dir>`: leaves a result bundle, notes the appearance it was asked
# for, and exits as $STUB_TOUR_EXIT says.
FAKE_MISE = r'''#!/usr/bin/env python3
import os, sys
arguments = sys.argv[1:]
assert arguments[:2] == ["run", "app:test"], arguments
results = arguments[arguments.index("--results") + 1]
os.makedirs(os.path.join(results, "iOS.xcresult" if arguments[2] == "ios" else "macOS.xcresult"), exist_ok=True)
with open(os.environ["STUB_LOG"], "a") as log:
    appearance = os.environ.get("TEST_RUNNER_WATCHWORD_SCREENSHOT_APPEARANCE", "")
    log.write(" ".join(arguments) + " appearance=" + appearance + "\n")
sys.exit(int(os.environ.get("STUB_TOUR_EXIT", "0")))
'''

# `xcrun xcresulttool export attachments --path <bundle> --output-path <dir>`: copies $STUB_EXPORT there.
FAKE_XCRUN = r'''#!/usr/bin/env python3
import os, shutil, sys
arguments = sys.argv[1:]
assert arguments[:3] == ["xcresulttool", "export", "attachments"], arguments
shutil.copytree(os.environ["STUB_EXPORT"], arguments[arguments.index("--output-path") + 1])
'''


class ScreenshotsTaskTests(support.ScriptTestCase):
    def setUp(self):
        super().setUp()
        self.install("sips", support.FAKE_SIPS)
        self.install("mise", FAKE_MISE)
        self.install("xcrun", FAKE_XCRUN)

    def task(self, export, platform="macos", appearance="light", tour_exit=0, previews="false"):
        """Runs the task as mise would: its arguments arrive as `usage_` variables."""
        for name in ("output.txt", "summary.md", "stub.log"):
            self.write(name, "")
        result = self.run_process(
            ["bash", support.TASK],
            usage_platform=platform, usage_appearance=appearance, usage_device="iphone",
            usage_output="Screenshots", usage_results="TestResults/Screenshots", usage_source="Commit 0123.",
            usage_previews=previews, STUB_EXPORT=export, STUB_TOUR_EXIT=str(tour_exit),
            STUB_LOG=self.path("stub.log"), GITHUB_OUTPUT=self.path("output.txt"),
            GITHUB_STEP_SUMMARY=self.path("summary.md"),
        )  # fmt: skip
        outputs = dict(line.split("=", 1) for line in self.read("output.txt").splitlines())
        return result, outputs

    def complete(self):
        pictures = [(name, ".png", support.screen(shade=number * 20)) for number, (name, _) in enumerate(THREE)]
        return self.export("export", pictures + [support.index_attachment(*THREE)])

    def test_complete_capture_writes_the_set_the_sheet_and_the_outputs(self):
        result, outputs = self.task(self.complete())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            outputs,
            {
                "set": "macos",
                "directory": "Screenshots/macos",
                "sheet": "Screenshots/watchword-screens-macos.png",
                "incomplete": "Screenshots/macos-incomplete",
                "screens_macos": "01-onboarding,02-emergency-kit,03-item-list-empty",
            },
        )
        self.assertTrue(os.path.isfile(self.path("Screenshots", "macos", "03-item-list-empty.png")))
        with open(self.path("Screenshots", "watchword-screens-macos.png"), "rb") as handle:
            self.assertEqual(support.decode_png(handle.read())[0], 24 + 3 * 84)
        self.assertFalse(os.path.exists(self.path("Screenshots", "macos-incomplete")))
        self.assertIn("3 screens, in the order the tour meets them.", self.read("summary.md"))
        # Nothing the task writes is a page: the one file that opens on its own is a picture.
        self.assertEqual([name for name in os.listdir(self.path("Screenshots")) if name.endswith(".html")], [])

    def test_the_tour_is_told_the_appearance_both_ways(self):
        """The task's half of a finding: the set called light was whatever the machine was set to, because only
        `dark` was acted on. The tour is handed the appearance either way (and, in Screens.swift, passes it on)."""
        export = self.complete()
        self.task(export)
        self.assertIn("appearance=light", self.read("stub.log"))
        # These pictures are light, so they are not a dark set, and are not passed off as one.
        result, outputs = self.task(export, appearance="dark")
        self.assertEqual(result.returncode, 1)
        self.assertIn("appearance=dark", self.read("stub.log"))
        self.assertIn("asked for in the dark appearance, but its pictures are light", result.stdout)
        self.assertEqual(outputs["set"], "macos-dark")
        self.assertEqual(outputs["sheet"], "Screenshots/watchword-screens-macos-dark.png")
        self.assertNotIn("screens_macos", outputs)
        dark = [(name, ".png", support.screen(shade=n * 20, dark=True)) for n, (name, _) in enumerate(THREE)]
        result, outputs = self.task(self.export("dark", dark + [support.index_attachment(*THREE)]), appearance="dark")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(os.path.isfile(self.path("Screenshots", "macos-dark", "01-onboarding.png")))

    def test_failed_tour_leaves_its_pictures_where_no_set_goes_and_says_so(self):
        """Finding: the task said it was "extracting what it captured before that" and then wrote nothing, so a
        step that failed on the runner left a cloud session with no picture of where the tour had got to."""
        export = self.export(
            "export",
            [
                ("01-onboarding", ".png", support.screen()),
                ("02-emergency-kit", ".png", support.screen(shade=80)),
                ("Screenshot at failure", ".png", support.screen(shade=160)),
            ],
        )
        result, outputs = self.task(export, tour_exit=65, previews="true")
        self.assertEqual(result.returncode, 1)
        self.assertIn("what it captured goes to Screenshots/macos-incomplete", result.stdout)
        self.assertNotIn("screens_macos", outputs)
        self.assertFalse(os.path.exists(self.path("Screenshots", "macos")))
        self.assertFalse(os.path.exists(self.path("Screenshots", "watchword-screens-macos.png")))
        self.assertEqual(
            sorted(os.listdir(self.path("Screenshots", "macos-incomplete"))),
            ["01-onboarding.png", "02-emergency-kit.png", "failure-1.png", "index.html", "index.md"],
        )
        self.assertIn("::group::failure-1 (text preview)", result.stdout)
        summary = self.read("summary.md")
        self.assertTrue(summary.startswith("### The screenshots of macOS are missing or incomplete"), summary)
        self.assertIn("### Incomplete: Watchword screens: macOS", summary)
        self.assertNotIn("screens, in the order the tour meets them", summary)

    def test_set_with_a_missing_picture_is_not_summarised_or_announced_as_a_set(self):
        """Finding: with one listed screen missing, the job summary and both artifacts showed "2 screens" as if
        that were the tour's result."""
        pictures = [("01-onboarding", ".png", support.screen()), ("03-item-list-empty", ".png", support.screen())]
        result, outputs = self.task(self.export("export", pictures + [support.index_attachment(*THREE)]))
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("screens_macos", outputs)
        self.assertFalse(os.path.exists(self.path("Screenshots", "macos")))
        self.assertFalse(os.path.exists(self.path("Screenshots", "watchword-screens-macos.png")))
        summary = self.read("summary.md")
        self.assertTrue(summary.startswith("### The screenshots of macOS are missing or incomplete"), summary)
        self.assertIn("02-emergency-kit", summary)
        self.assertNotIn("screens, in the order the tour meets them", summary)

    def test_tour_that_failed_after_listing_its_screens_is_still_not_a_set(self):
        result, outputs = self.task(self.complete(), tour_exit=65)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("screens_macos", outputs)
        self.assertFalse(os.path.exists(self.path("Screenshots", "macos")))
        self.assertTrue(os.path.isdir(self.path("Screenshots", "macos-incomplete")))

    def test_both_platforms_run_even_if_the_first_fails(self):
        result, outputs = self.task(self.complete(), platform="all")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("screens_ios", outputs)
        self.assertIn("screens_macos", outputs)
        self.assertTrue(os.path.isfile(self.path("Screenshots", "watchword-screens-ios.png")))


if __name__ == "__main__":
    unittest.main()
