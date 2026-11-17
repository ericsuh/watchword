"""mise-tasks/app/build, test, test-keychain and release, run as they are with a stand-in `xcodebuild`.

Two things these tasks decide that no Swift test can reach (docs/06-adversarial-review.md Z102, Z105):

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
import shutil
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


MARKERS = ["--uitest", "WATCHWORD_UITEST_PASSWORD", "UI test: another device", "Lock now (UI test)"]
MACOS_APP = "Release/Watchword.app/Contents/MacOS/Watchword"
MACOS_EXTENSION = "Release/Watchword.app/Contents/PlugIns/AutoFillExtension-macOS.appex/Contents/MacOS/AutoFillExtension-macOS"
IOS_APP = "Release-iphonesimulator/Watchword.app/Watchword"
IOS_EXTENSION = "Release-iphonesimulator/Watchword.app/PlugIns/AutoFillExtension-iOS.appex/AutoFillExtension-iOS"
# What a binary looks like to a search for text: strings between runs of other bytes.
CLEAN = "\xcf\xfa\xed\xfe\x00\x00Account password\x00Unlock\x00\x01\x02"


class ReleaseBuildTests(AppTaskTestCase):
    def setUp(self):
        super().setUp()
        # The markers are checked against the sources, so the task reads the repository's own.
        shutil.copytree(os.path.join(support.ROOT, "Apps", "Shared"), self.path("Apps", "Shared"))

    def products(self, **changes):
        files = {"macos": {MACOS_APP: CLEAN, MACOS_EXTENSION: CLEAN}, "ios": {IOS_APP: CLEAN, IOS_EXTENSION: CLEAN}}
        for platform, platform_changes in changes.items():
            for path, contents in platform_changes.items():
                if contents is None:
                    del files[platform][path]
                else:
                    files[platform][path] = contents
        return json.dumps(files)

    def release(self, platform="macos", products=None, **environment):
        environment.setdefault("STUB_PRODUCTS", products or self.products())
        return self.task("release", usage_platform=platform, usage_derived_data="derived", **environment)

    def test_a_release_build_without_the_markers_passes(self):
        result = self.release()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies", "build"])
        build = self.calls()[1]
        self.assertEqual(build[build.index("-configuration") + 1], "Release")
        self.assertEqual(build[build.index("-derivedDataPath") + 1], "derived/macos")
        self.assertEqual(build[build.index("-scheme") + 1], "Watchword-macOS")
        self.assertIn("Release build of macOS: none of the 4 Debug-only markers", result.stdout)

    def test_both_apps_are_built_and_read(self):
        result = self.release(platform="all")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies", "build", "build"])
        self.assertIn("Release build of iOS: none of", result.stdout)
        self.assertIn("Release build of macOS: none of", result.stdout)

    def test_the_markers_the_task_reads_for_are_the_finding_s(self):
        with open(os.path.join(TASKS, "release"), encoding="utf-8") as handle:
            text = handle.read()
        for marker in MARKERS:
            self.assertIn(f'  "{marker}"\n', text)

    def test_a_debug_only_string_in_the_app_fails(self):
        """Finding: nothing would have noticed a Release build that carried the `--uitest` switch."""
        for marker in MARKERS + ["--uitest-appearance="]:
            with self.subTest(marker=marker):
                binary = CLEAN + marker + "\x00\x07"
                result = self.release(products=self.products(macos={MACOS_APP: binary}))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("::error::The Release build of macOS contains", result.stdout)
                self.assertIn("derived/macos/Build/Products/" + MACOS_APP, result.stdout)
                self.assertIn("::error::Release builds failed inspection: macOS", result.stdout)

    def test_the_embedded_extension_is_read_too(self):
        binary = CLEAN + "WATCHWORD_UITEST_PASSWORD\x00"
        result = self.release(platform="ios", products=self.products(ios={IOS_EXTENSION: binary}))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("derived/ios/Build/Products/" + IOS_EXTENSION, result.stdout)

    def test_one_platform_s_failure_does_not_hide_the_other_s(self):
        binary = CLEAN + "UI test: another device\x00"
        products = self.products(ios={IOS_APP: binary}, macos={MACOS_APP: binary})
        result = self.release(platform="all", products=products)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("::error::Release builds failed inspection: iOS macOS", result.stdout)

    def test_a_product_that_is_not_there_is_a_failure(self):
        for name, products in (
            ("no app", self.products(macos={MACOS_APP: None, MACOS_EXTENSION: None})),
            ("no extension in it", self.products(macos={MACOS_EXTENSION: None})),
            ("two apps", self.products(macos={"Debug/Watchword.app/Contents/MacOS/Watchword": CLEAN})),
        ):
            with self.subTest(case=name):
                result = self.release(products=products)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("::error::", result.stdout)
                self.assertNotIn("none of the 4 Debug-only markers", result.stdout)

    def test_an_earlier_product_is_not_what_is_read(self):
        stale = self.path("derived", "macos", "Build", "Products", "Release", "Watchword.app", "Contents", "MacOS")
        os.makedirs(stale)
        with open(os.path.join(stale, "Leftover"), "w", encoding="utf-8") as handle:
            handle.write("--uitest")
        result = self.release()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_marker_that_left_the_sources_makes_the_list_stale(self):
        """Renaming the Settings section must not turn the search for its old name into a pass."""
        path = self.path("Apps", "Shared", "SettingsView.swift")
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn('Section("UI test: another device")', text)
        self.write(os.path.join("Apps", "Shared", "SettingsView.swift"), text.replace("UI test: another device", "Peer"))
        result = self.release()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('"UI test: another device" is no longer in Apps/Shared', result.stdout)
        self.assertEqual(self.actions(), [])

    def test_a_release_only_build_error_fails_the_task(self):
        result = self.release(STUB_EXIT="65")
        self.assertEqual(result.returncode, 65, result.stdout + result.stderr)

    def test_release_is_built_from_the_pinned_commits_only(self):
        result = self.release(STUB_RESOLVED=self.pins(moved_tag))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies"])

    def test_the_markers_are_compiled_for_debug_only(self):
        """Each marker is a string in the app's code, and its every use there is inside `#if DEBUG`: what makes its
        absence from a Release build the evidence, and a marker that only a comment still mentions a stale one."""
        directory = os.path.join(support.ROOT, "Apps", "Shared")
        compiled = set()
        for name in sorted(os.listdir(directory)):
            with open(os.path.join(directory, name), encoding="utf-8") as handle:
                depth, debug = 0, []
                for number, line in enumerate(handle.read().splitlines(), 1):
                    stripped = line.strip()
                    if stripped.startswith("#if"):
                        depth += 1
                        if stripped == "#if DEBUG":
                            debug.append(depth)
                    elif stripped.startswith("#else") or stripped.startswith("#elseif"):
                        if debug and debug[-1] == depth:
                            debug.pop()
                    elif stripped.startswith("#endif"):
                        if debug and debug[-1] == depth:
                            debug.pop()
                        depth -= 1
                    elif not stripped.startswith("//"):
                        for marker in MARKERS:
                            if f'"{marker}' in line:
                                self.assertTrue(debug, f"{name}:{number} is compiled for Release")
                                compiled.add(marker)
        self.assertEqual(compiled, set(MARKERS))

    def test_the_gate_is_a_required_job(self):
        with open(os.path.join(support.ROOT, ".github", "workflows", "ci.yml"), encoding="utf-8") as handle:
            workflow = handle.read()
        job = workflow[workflow.index("\n  release-build:\n") : workflow.index("\n  required:\n")]
        self.assertIn('run: mise run app:release "$PLATFORM"', job)
        self.assertIn("      contents: read\n", job)
        self.assertIn("          persist-credentials: false\n", job)
        self.assertNotIn("continue-on-error", job)
        for platform in ("macos", "ios"):
            self.assertIn(f"            platform: {platform}\n", job)
        needs = next(line for line in workflow.splitlines() if line.strip().startswith("needs: [package-tests"))
        self.assertIn("release-build", needs)


if __name__ == "__main__":
    unittest.main()
