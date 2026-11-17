"""mise-tasks/app/diagnose-summary.py, and the end of the app:diagnose task, against made-up result summaries and logs.

What is at stake: an iOS UI test that runs out of time leaves no element tree, and its job log is tens of thousands of
lines. The last lines of the log must say which tests failed, why, and the last steps each reached, and the very last
line must be the summary, even when a summary or a log is missing, malformed or hostile (it is a test run's output)."""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support  # noqa: E402

HELPER = os.path.join(support.ROOT, "mise-tasks", "app", "diagnose-summary.py")
DIAGNOSE = os.path.join(support.ROOT, "mise-tasks", "app", "diagnose")

SHARING = "VaultSharingTests/testCreateRenameShareAndInvite()"


def summary(passed=0, failed=0, failures=(), result=None):
    """What `xcresulttool get test-results summary --compact` prints, reduced to the fields the helper reads."""
    return {
        "title": "Test - Watchword-iOS",
        "result": result or ("Failed" if failed else "Passed"),
        "totalTestCount": passed + failed,
        "passedTests": passed,
        "failedTests": failed,
        "skippedTests": 0,
        "testFailures": [
            {
                "testName": identifier.split("/")[-1],
                "targetName": "WatchwordUITests",
                "failureText": text,
                "testIdentifier": number,
                "testIdentifierString": identifier,
            }
            for number, (identifier, text) in enumerate(failures)
        ],
    }


def step(time, test, name):
    """A line as `XCTestCase.step` prints it; `test` is XCTestCase.name, `-[Class method]` on Apple platforms."""
    return f"STEP 2026-11-17T10:{time}Z [{test}] {name}\n"


class DiagnoseSummaryTests(support.ScriptTestCase):
    def setUp(self):
        super().setUp()
        self.work = self.path("work")
        os.makedirs(self.work)

    def bundle(self, name, report=None, logs=None):
        if report is not None:
            self.write(os.path.join("work", name + ".summary.json"), json.dumps(report))
        os.makedirs(os.path.join(self.work, name + ".logs"), exist_ok=True)
        for file, text in (logs or {}).items():
            self.write(os.path.join("work", name + ".logs", file), text)

    def run_helper(self):
        result = self.run_process([sys.executable, "-I", HELPER, self.work])
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def test_failed_tests_get_their_messages_and_last_thirty_steps_and_the_summary_is_last(self):
        steps = "".join(step(f"{n // 60:02d}:{n % 60:02d}", "-[VaultSharingTests testCreateRenameShareAndInvite]",
                             f"step {n}") for n in range(40))  # fmt: skip
        other = step("59:00", "-[DeviceRevocationTests testPasswordChangedElsewhereThenRevokeThatDevice]", "launch")
        self.bundle(
            "iOS",
            summary(passed=5, failed=1, failures=[(SHARING, "Test exceeded execution time allowance of 10 minutes")]),
            {"xcodebuild.log": "Test Suite 'All tests' started\n" + steps + other + "** TEST FAILED **\n"},
        )
        lines = self.run_helper()
        self.assertEqual(lines[-1], f"UI-test summary: 5 passed, 1 failed: {SHARING}")
        self.assertIn(f"--- iOS: {SHARING} failed", lines)
        self.assertIn("failure: Test exceeded execution time allowance of 10 minutes", lines)
        shown = [line for line in lines if line.startswith("  STEP ")]
        self.assertEqual(len(shown), 30)
        self.assertTrue(shown[0].endswith("] step 10") and shown[-1].endswith("] step 39"), shown)
        self.assertNotIn("launch", "\n".join(shown), "another test's step was shown")

    def test_a_line_in_both_logs_is_shown_once_in_time_order(self):
        test = "-[ImportExportTests testExportReportALockAndARestore]"
        late, early = step("05:00", test, "restore"), step("01:00", test, "export")
        identifier = "ImportExportTests/testExportReportALockAndARestore()"
        self.bundle(
            "iOS",
            summary(passed=1, failed=1, failures=[(identifier, "first"), (identifier, "second\nline two")]),
            {"xcodebuild.log": late + early, "runner-1.txt": "noise " + early + late},
        )
        lines = self.run_helper()
        shown = [line for line in lines if line.startswith("  STEP ")]
        self.assertEqual([line.split("] ")[-1] for line in shown], ["export", "restore"])
        self.assertEqual([line for line in lines if line.startswith("failure:")],
                         ["failure: first", "failure: second", "failure: line two"])  # fmt: skip
        self.assertEqual(lines.count(f"--- iOS: {identifier} failed"), 1, "one heading per test")

    def test_the_same_method_name_in_another_class_is_not_this_tests(self):
        self.bundle(
            "macOS",
            summary(failed=1, failures=[("QuarantineTests/testShare()", "boom")]),
            {"xcodebuild.log": step("00:00", "-[VaultSharingTests testShare]", "not mine")
             + step("00:01", "-[QuarantineTests testShare]", "mine")},
        )  # fmt: skip
        shown = [line for line in self.run_helper() if line.startswith("  STEP ")]
        self.assertEqual([line.split("] ")[-1] for line in shown], ["mine"])

    def test_a_test_without_steps_says_so(self):
        self.bundle("iOS", summary(failed=1, failures=[("SyncConflictTests/testRename()", "no")]), {})
        lines = self.run_helper()
        self.assertIn("no STEP lines for this test (it prints none, or it stopped before its first)", lines)
        self.assertEqual(lines[-1], "UI-test summary: 0 passed, 1 failed: SyncConflictTests/testRename()")

    def test_counts_and_names_add_up_across_bundles(self):
        self.bundle("iOS", summary(passed=3, failed=1, failures=[("ATests/testA()", "x")]))
        self.bundle("macOS", summary(passed=4))
        self.assertEqual(self.run_helper()[-1], "UI-test summary: 7 passed, 1 failed: iOS: ATests/testA()")

    def test_a_passing_run_still_ends_in_the_summary(self):
        self.bundle("macOS", summary(passed=8))
        self.assertEqual(self.run_helper()[-1], "UI-test summary: 8 passed, 0 failed: none")

    def test_a_run_that_failed_outside_any_test_is_noted(self):
        self.bundle("iOS", summary(passed=2, result="Failed"))
        self.assertEqual(
            self.run_helper()[-1],
            "UI-test summary: 2 passed, 0 failed: none (a run failed outside any test (see the runner logs above))",
        )

    def test_missing_and_malformed_summaries_are_reported_not_trusted(self):
        self.bundle("iOS", logs={"xcodebuild.log": "STEP"})
        self.write(os.path.join("work", "macOS.summary.json"), "[1, 2")
        hostile = {"passedTests": "9", "failedTests": -3, "testFailures": [7, {"failureText": 1}]}
        self.write(os.path.join("work", "tvOS.summary.json"), json.dumps(hostile))
        lines = self.run_helper()
        self.assertTrue(lines[-1].startswith("UI-test summary: 0 passed, 0 failed: tvOS: a test"), lines[-1])
        self.assertIn("no readable summary for iOS, macOS", lines[-1])

    def test_an_empty_work_directory(self):
        self.assertEqual(self.run_helper()[-1], "UI-test summary: 0 passed, 0 failed: none (no result bundle was read)")

    def test_links_are_not_followed_and_long_lines_are_cut(self):
        outside = self.write("outside.log", step("00:00", "-[ATests testA]", "from outside"))
        self.bundle("iOS", summary(failed=1, failures=[("ATests/testA()", "y" * 2000)]),
                    {"xcodebuild.log": step("00:01", "-[ATests testA]", "z" * 2000)})  # fmt: skip
        os.symlink(outside, os.path.join(self.work, "iOS.logs", "linked.log"))
        os.symlink(os.path.dirname(outside), os.path.join(self.work, "iOS.logs", "linked"))
        lines = self.run_helper()
        self.assertNotIn("from outside", "\n".join(lines))
        self.assertTrue(all(len(line) < 700 for line in lines), max(len(line) for line in lines))


# `xcrun xcresulttool …` as app:diagnose calls it: the summary from $STUB_SUMMARY, the diagnostics from
# $STUB_DIAGNOSTICS, and an export of attachments with nothing in it.
FAKE_XCRUN = r'''#!/usr/bin/env python3
import os, shutil, sys
arguments = sys.argv[1:]
output = arguments[arguments.index("--output-path") + 1] if "--output-path" in arguments else None
if arguments[:4] == ["xcresulttool", "get", "test-results", "summary"]:
    with open(os.environ["STUB_SUMMARY"]) as handle:
        sys.stdout.write(handle.read())
elif arguments[:3] == ["xcresulttool", "export", "diagnostics"]:
    shutil.copytree(os.environ["STUB_DIAGNOSTICS"], output, dirs_exist_ok=True)
elif arguments[:3] == ["xcresulttool", "export", "attachments"]:
    os.makedirs(output, exist_ok=True)
    with open(os.path.join(output, "manifest.json"), "w") as handle:
        handle.write("[]")
else:
    sys.exit("unexpected: " + " ".join(arguments))
'''


class DiagnoseTaskTests(support.ScriptTestCase):
    def test_the_last_lines_are_the_steps_of_the_failed_test_and_the_summary(self):
        self.install("xcrun", FAKE_XCRUN)
        os.makedirs(self.path("TestResults", "iOS.xcresult"))
        test = "-[ScreenshotTourTests testTourOfEveryScreen]"
        identifier = "ScreenshotTourTests/testTourOfEveryScreen()"
        self.write("TestResults/iOS.log", step("00:00", test, "launch") + "lots of build output\n")
        self.write("summary.json", json.dumps(summary(failed=1, failures=[(identifier, "timed out")])))
        runner = os.path.join("diagnostics", "WatchwordUITests-Runner", "StandardOutputAndStandardError-1.txt")
        self.write(runner, step("03:00", test, "tourVaultsAndSharing"))
        result = self.run_process(
            ["bash", DIAGNOSE], usage_results="TestResults", STUB_SUMMARY=self.path("summary.json"),
            STUB_DIAGNOSTICS=self.path("diagnostics"),
        )  # fmt: skip
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(lines[-1], f"UI-test summary: 0 passed, 1 failed: {identifier}")
        tail = lines[lines.index(f"--- iOS: {identifier} failed") :]
        self.assertEqual([line.split("] ")[-1] for line in tail if line.startswith("  STEP ")],
                         ["launch", "tourVaultsAndSharing"])  # fmt: skip

    def test_no_bundles_still_ends_in_the_summary(self):
        os.makedirs(self.path("TestResults"))
        result = self.run_process(["bash", DIAGNOSE], usage_results="TestResults")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.splitlines()[-1].startswith("UI-test summary: 0 passed, 0 failed: none"))


if __name__ == "__main__":
    unittest.main()
