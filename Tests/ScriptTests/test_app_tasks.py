"""mise-tasks/app/build, test, test-keychain and release, run as they are with a stand-in `xcodebuild`.

Two things these tasks decide that no Swift test can reach (docs/06-adversarial-review.md Z102, Z111):

- Which swift-crypto an app is built from. The pin in the root Package.resolved covers `swift build`; xcodebuild
  resolves the generated project's local package for itself and writes a Package.resolved of its own inside the
  project. The tasks have Xcode resolve first and refuse to build unless that file pins the allowed commits.
- That a Release build holds none of the Debug-only UI-test switch. Every scheme and CI leg built Debug, so nothing
  ever compiled Release, let alone looked inside it.

None of this has run on a Mac. What is tested here is what the tasks do with what xcodebuild leaves; where Xcode
leaves it is from its documented behaviour."""

import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support  # noqa: E402

TASKS = os.path.join(support.ROOT, "mise-tasks", "app")
RESOLVED = os.path.join("Apps", "Watchword.xcodeproj", "project.xcworkspace", "xcshareddata", "swiftpm", "Package.resolved")

# xcodebuild: appends its arguments to $STUB_LOG. `-resolvePackageDependencies` writes $STUB_RESOLVED (if set) where
# Xcode keeps the project's Package.resolved; any other invocation writes $STUB_REWRITTEN there (if set), as a build
# that resolved again would, and, for a build with `-derivedDataPath`, lays down the products $STUB_PRODUCTS describes
# ({"relative path under Build/Products": "contents"}). Exits as $STUB_EXIT says for anything but the resolution.
FAKE_XCODEBUILD = r'''#!/usr/bin/env python3
import json, os, shutil, sys
arguments = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(arguments) + "\n")
resolved = os.path.join("Apps", "Watchword.xcodeproj", "project.xcworkspace", "xcshareddata", "swiftpm", "Package.resolved")
resolving = "-resolvePackageDependencies" in arguments
source = os.environ.get("STUB_RESOLVED" if resolving else "STUB_REWRITTEN", "")
if source:
    os.makedirs(os.path.dirname(resolved), exist_ok=True)
    shutil.copy(source, resolved)
if resolving:
    sys.exit(int(os.environ.get("STUB_RESOLVE_EXIT", "0")))
if "-derivedDataPath" in arguments and os.environ.get("STUB_PRODUCTS"):
    root = os.path.join(arguments[arguments.index("-derivedDataPath") + 1], "Build", "Products")
    platform = "ios" if "Watchword-iOS" in arguments else "macos"
    for relative, contents in json.loads(os.environ["STUB_PRODUCTS"])[platform].items():
        target = os.path.join(root, relative)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as handle:
            handle.write(contents.encode("latin-1"))
sys.exit(int(os.environ.get("STUB_EXIT", "0")))
'''


class AppTaskTestCase(support.ScriptTestCase):
    def setUp(self):
        super().setUp()
        self.install("xcodebuild", FAKE_XCODEBUILD)
        self.write("stub.log", "")
        os.makedirs(self.path("Apps", "Watchword.xcodeproj"))

    def pins(self, edit=None):
        """A Package.resolved as Xcode would write it: the committed pins, with edit applied."""
        with open(os.path.join(support.ROOT, "Package.resolved"), encoding="utf-8") as handle:
            document = json.load(handle)
        if edit:
            edit(document)
        return self.write(f"pins-{len(os.listdir(self.scratch))}.json", json.dumps(document))

    def task(self, name, **environment):
        environment.setdefault("STUB_RESOLVED", self.pins())
        return self.run_process(["bash", os.path.join(TASKS, name)], STUB_LOG=self.path("stub.log"), **environment)

    def calls(self):
        return [json.loads(line) for line in self.read("stub.log").splitlines()]

    def actions(self):
        """What each xcodebuild call was for: its first argument."""
        return [call[0] for call in self.calls()]


def moved_tag(document):
    """The 4.5.2 tag points somewhere else: same package, another commit."""
    next(pin for pin in document["pins"] if pin["identity"] == "swift-crypto")["state"]["revision"] = "f" * 40


def newer_asn1(document):
    """A new swift-asn1 release inside swift-crypto's range, which an unpinned resolution takes."""
    state = next(pin for pin in document["pins"] if pin["identity"] == "swift-asn1")["state"]
    state["revision"], state["version"] = "a" * 40, "1.9.0"


def another_package(document):
    document["pins"].append({"identity": "swift-extra", "kind": "remoteSourceControl", "state": {"revision": "b" * 40}})


class ResolvedPackagesTests(AppTaskTestCase):
    def build(self, **environment):
        return self.task("build", usage_platform="macos", usage_configuration="Debug", **environment)

    def test_the_pinned_commits_build(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies", "build"])
        self.assertEqual(self.calls()[0], ["-resolvePackageDependencies", "-project", "Apps/Watchword.xcodeproj"])
        self.assertEqual(result.stdout.count("pins the allowed swift-crypto commits and nothing else"), 2)

    def test_both_apps_are_built_after_one_resolution(self):
        result = self.task("build", usage_platform="all", usage_configuration="Debug")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies", "build", "build"])

    def test_nothing_is_built_from_any_other_resolution(self):
        """Finding: a re-pointed 4.5.2 tag, or a new swift-asn1, left every package gate green and was compiled into
        the app by the next `app:build` or `app:test`."""
        for edit in (moved_tag, newer_asn1, another_package):
            with self.subTest(case=edit.__name__):
                self.write("stub.log", "")
                result = self.build(STUB_RESOLVED=self.pins(edit))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(self.actions(), ["-resolvePackageDependencies"])
                self.assertIn("expected exactly", result.stdout)
                self.assertIn("::error::Before building, Xcode's own Package.resolved does not pin", result.stdout)

    def test_no_record_of_the_resolution_is_a_failure(self):
        result = self.build(STUB_RESOLVED="")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies"])
        self.assertIn("is missing", result.stdout)

    def test_a_failed_resolution_stops_the_task(self):
        result = self.build(STUB_RESOLVE_EXIT="74")
        self.assertEqual(result.returncode, 74, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies"])

    def test_a_build_that_resolved_again_is_caught_afterwards(self):
        result = self.build(STUB_REWRITTEN=self.pins(moved_tag))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies", "build"])
        self.assertIn("::error::After building, Xcode's own Package.resolved does not pin", result.stdout)

    def test_the_tests_do_not_run_on_another_resolution(self):
        result = self.task("test", usage_platform="macos", STUB_RESOLVED=self.pins(moved_tag))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies"])

    def test_passing_tests_do_not_excuse_another_resolution(self):
        result = self.task("test", usage_platform="macos")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies", "test"])
        self.write("stub.log", "")
        result = self.task("test", usage_platform="macos", STUB_REWRITTEN=self.pins(newer_asn1))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies", "test"])
        self.assertIn("::error::App tests failed: packages(not the pinned commits)", result.stdout)

    def test_failing_tests_still_fail_on_the_pinned_commits(self):
        result = self.task("test", usage_platform="macos", STUB_EXIT="65")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("::error::App tests failed: macOS", result.stdout)

    def test_the_keychain_run_is_held_to_the_same_commits(self):
        result = self.task("test-keychain", usage_team="ABCDE12345")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies", "test"])
        self.write("stub.log", "")
        result = self.task("test-keychain", usage_team="ABCDE12345", STUB_RESOLVED=self.pins(moved_tag))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies"])

    def test_every_task_that_runs_xcodebuild_checks(self):
        """A new app task that builds must source packages.sh too, or it builds whatever Xcode resolved."""
        for name in sorted(os.listdir(TASKS)):
            path = os.path.join(TASKS, name)
            if not os.access(path, os.X_OK) or name.endswith(".py"):
                continue
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            # A line that is the command itself, after `if` or an environment assignment, not one that mentions it.
            if re.search(r"^\s*(if\s+)?([A-Z_]+=\S+\s+)*xcodebuild\s", text, re.MULTILINE):
                with self.subTest(task=name):
                    self.assertIn('source "$(dirname "${BASH_SOURCE[0]}")/packages.sh"', text)
                    self.assertIn("resolve_packages\n", text)
                    self.assertIn("check_resolved_packages ", text)


if __name__ == "__main__":
    unittest.main()
