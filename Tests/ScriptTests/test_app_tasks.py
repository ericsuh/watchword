"""mise-tasks/app/build, test, test-keychain and release, run as they are with a stand-in `xcodebuild`.

Two things these tasks decide that no Swift test can reach (docs/06-adversarial-review.md Z102, Z105):

- Which swift-crypto an app is built from. The pin in the root Package.resolved covers `swift build`; xcodebuild
  resolves the generated project's local package for itself, and writes no Package.resolved of its own for it (the
  first Mac run looked). So the tasks give every xcodebuild call one `-clonedSourcePackagesDirPath`, have Xcode
  resolve first, and refuse to build unless the git working copies it left there are the allowed packages at the
  allowed commits, unchanged. The stand-in checks packages out with real git, so the real `git` calls are what is
  tested.
- That a Release build holds none of the Debug-only UI-test switch. Every scheme and CI leg built Debug, so nothing
  ever compiled Release, let alone looked inside it.

None of this has passed on a Mac. What is tested here is what the tasks do with what xcodebuild leaves; that Xcode
leaves clean working copies in that directory is from its documented behaviour.

The tasks run from a scratch copy of `mise-tasks/app` and `.github/scripts`, identical but for the one line of
assert-no-dependencies.sh that names the allowed commits: a made-up repository cannot be given swift-crypto's real
commit ID, so that line names the stand-in repositories' (support.pinned_tripwire)."""

import json
import os
import re
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support  # noqa: E402

TASKS = os.path.join(support.ROOT, "mise-tasks", "app")
PICK_SIMULATOR = os.path.join(support.ROOT, ".github", "scripts", "pick-simulator.sh")
DIRECTORY_ARGUMENT = '"${package_arguments[@]}"'


def xcodebuild_commands(text):
    """The xcodebuild command lines in a shell script, each with its continuation lines joined: a line that is the
    command itself (after `if`, a `!` or an environment assignment), not one that mentions it."""
    joined = re.sub(r"\s*\\\n\s*", " ", text)
    return [line.strip() for line in joined.splitlines() if re.match(r"\s*(if\s+)?(!\s+)?([A-Z_]+=\S+\s+)*xcodebuild\s", line)]


class AppTaskTestCase(support.ScriptTestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = tempfile.mkdtemp(prefix="watchword-script-test-packages-")
        cls.addClassCleanup(shutil.rmtree, cls.upstream, ignore_errors=True)
        cls.sources = support.PackageSources(cls.upstream)

    def setUp(self):
        super().setUp()
        self.install("xcodebuild", support.FAKE_XCODEBUILD)
        self.install("xcrun", "#!/bin/sh\nexit 0\n")
        self.write("stub.log", "")
        os.makedirs(self.path("Apps", "Watchword.xcodeproj"))
        shutil.copytree(TASKS, self.path("mise-tasks", "app"))
        os.makedirs(self.path(".github", "scripts"))
        shutil.copy(PICK_SIMULATOR, self.path(".github", "scripts", "pick-simulator.sh"))
        self.tripwire = support.pinned_tripwire(self, self.sources)
        # Where the tasks tell xcodebuild to put packages. bash works out $PWD for itself, links resolved.
        self.packages = os.path.join(os.path.realpath(self.scratch), ".build", "app-source-packages")

    def task(self, name, **environment):
        environment.setdefault("STUB_CHECKOUTS", self.sources.plan())
        command = ["bash", self.path("mise-tasks", "app", name)]
        return self.run_process(command, STUB_LOG=self.path("stub.log"), **environment)

    def calls(self):
        return [json.loads(line) for line in self.read("stub.log").splitlines()]

    def actions(self):
        """What each xcodebuild call was for: its first argument."""
        return [call[0] for call in self.calls()]

    def assert_every_call_was_given_the_directory(self):
        calls = self.calls()
        self.assertTrue(calls)
        for call in calls:
            self.assertIn("-clonedSourcePackagesDirPath", call, call)
            self.assertEqual(call[call.index("-clonedSourcePackagesDirPath") + 1], self.packages, call)


class ResolvedPackagesTests(AppTaskTestCase):
    def build(self, **environment):
        return self.task("build", usage_platform="macos", usage_configuration="Debug", **environment)

    def assert_stopped_before_building(self, result, expected):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies"])
        self.assertIn(expected, result.stdout)
        self.assertIn("::error::Before building, the package sources xcodebuild checked out are not", result.stdout)

    def test_the_pinned_commits_build(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies", "build"])
        self.assertEqual(self.calls()[0][:3], ["-resolvePackageDependencies", "-project", "Apps/Watchword.xcodeproj"])
        self.assert_every_call_was_given_the_directory()
        # One line a package, with its commit, before the build and again after it.
        for name in ("swift-crypto", "swift-asn1"):
            self.assertEqual(result.stdout.count(f"{name} {self.sources.commits[name][0]} (clean checkout"), 2)
        self.assertNotIn("::error", result.stdout)

    def test_both_apps_are_built_after_one_resolution(self):
        result = self.task("build", usage_platform="all", usage_configuration="Debug")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies", "build", "build"])
        self.assert_every_call_was_given_the_directory()

    def test_nothing_is_built_from_any_other_commit(self):
        """Finding: a re-pointed 4.5.2 tag, or a new swift-asn1, left every package gate green and was compiled into
        the app by the next `app:build` or `app:test`."""
        sources = self.sources
        cases = {
            "a moved tag": (sources.plan(swift_crypto=sources.at("swift-crypto", 1)), "swift-crypto: checked out at"),
            "a newer swift-asn1": (sources.plan(swift_asn1=sources.at("swift-asn1", 1)), "swift-asn1: checked out at"),
            "another package": (sources.plan(swift_extra=sources.at("swift-extra")), "swift-extra: a package that is not"),
            "a package missing": (sources.plan(swift_asn1=None), "swift-asn1: not checked out"),
            "no packages": ("{}", "swift-crypto: not checked out"),
        }
        for name, (plan, expected) in cases.items():
            with self.subTest(case=name):
                self.write("stub.log", "")
                self.assert_stopped_before_building(self.build(STUB_CHECKOUTS=plan), expected)

    def test_a_stray_file_beside_the_checkouts_is_not_a_package(self):
        os.makedirs(os.path.join(self.packages, "checkouts"))
        with open(os.path.join(self.packages, "checkouts", ".DS_Store"), "w", encoding="utf-8") as handle:
            handle.write("left by a file browser")
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_no_checkouts_at_all_is_a_failure(self):
        """What the first Mac run would have looked like had it been this check: nothing where the task looked."""
        result = self.build(STUB_CHECKOUTS="")
        self.assert_stopped_before_building(result, "checkouts is not a directory")

    def test_a_checkout_that_was_changed_is_refused(self):
        sources = self.sources
        cases = {
            "a tracked file edited": sources.at("swift-crypto", edit="let backdoor = true\n"),
            "a file added": sources.at("swift-crypto", add="Extra.swift"),
        }
        for name, how in cases.items():
            with self.subTest(case=name):
                self.write("stub.log", "")
                result = self.build(STUB_CHECKOUTS=sources.plan(swift_crypto=how))
                self.assert_stopped_before_building(result, "swift-crypto: the checkout differs from commit")

    def test_a_directory_that_is_no_working_copy_is_refused(self):
        """Sources dropped where a checkout belongs. The task's directory is inside this repository on a runner, so
        git must not be let to find *that* repository and answer for it: here the scratch directory is one too."""
        support.git(self.scratch, "init", "-q")
        support.git(self.scratch, "commit", "-q", "--allow-empty", "-m", "the repository the tasks run in")
        elsewhere = self.path("elsewhere")
        support.git(self.scratch, "clone", "-q", self.sources.repositories["swift-crypto"], elsewhere)
        support.git(elsewhere, "checkout", "-q", "--detach", self.sources.commits["swift-crypto"][0])
        for name, how in (("a plain directory", {"plain": True}), ("a symbolic link", {"link": elsewhere})):
            with self.subTest(case=name):
                self.write("stub.log", "")
                result = self.build(STUB_CHECKOUTS=self.sources.plan(swift_crypto=how))
                self.assert_stopped_before_building(result, "is not a git working copy of its own")

    def test_a_failure_says_what_was_there(self):
        """Nothing in a cloud session can run Xcode, so one failed CI run has to show what Xcode left."""
        moved = self.sources.commits["swift-crypto"][1]
        result = self.build(STUB_CHECKOUTS=self.sources.plan(swift_crypto=self.sources.at("swift-crypto", 1)))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        output = result.stdout
        self.assertIn(f"::error::swift-crypto: checked out at {moved}, expected {self.sources.commits['swift-crypto'][0]}", output)
        self.assertIn("::group::What xcodebuild left in the source packages directory", output)
        self.assertIn(f"$ ls -la {self.packages}\n", output)
        self.assertIn(f"$ ls -la {os.path.join(self.packages, 'checkouts')}\n", output)
        self.assertIn("workspace-state.json", output)
        self.assertIn(f"swift-crypto: git rev-parse HEAD: {moved}; changed files: 0", output)
        self.assertIn(f"swift-asn1: git rev-parse HEAD: {self.sources.commits['swift-asn1'][0]}; changed files: 0", output)
        self.assertIn(f'workspace-state.json: swift-crypto remoteSourceControl', output)
        self.assertIn(f'"revision": "{moved}"', output)
        self.assertIn("::endgroup::", output)

    def test_a_failed_resolution_stops_the_task(self):
        result = self.build(STUB_RESOLVE_EXIT="74")
        self.assertEqual(result.returncode, 74, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies"])

    def test_a_build_that_resolved_again_is_caught_afterwards(self):
        moved = self.sources.plan(swift_crypto=self.sources.at("swift-crypto", 1))
        result = self.build(STUB_REBUILT=moved)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies", "build"])
        self.assertIn("::error::After building, the package sources xcodebuild checked out are not", result.stdout)

    def test_a_resolution_that_was_not_given_the_directory_proves_nothing(self):
        """Without the argument Xcode checks packages out under its own DerivedData, which nothing reads. The pinned
        commits being there is no evidence, and the task must not take it for any."""
        packages = self.path("mise-tasks", "app", "packages.sh")
        with open(packages, encoding="utf-8") as handle:
            text = handle.read()
        resolve = f"-project Apps/Watchword.xcodeproj {DIRECTORY_ARGUMENT}\n"
        self.assertEqual(text.count(resolve), 1)
        self.write(os.path.join("mise-tasks", "app", "packages.sh"), text.replace(resolve, "-project Apps/Watchword.xcodeproj\n"))
        result = self.build()
        self.assert_stopped_before_building(result, "checkouts is not a directory")
        derived = self.path("Library", "Developer", "Xcode", "DerivedData", "Watchword-stand-in", "SourcePackages")
        self.assertTrue(os.path.isdir(os.path.join(derived, "checkouts", "swift-crypto", ".git")))

    def test_every_xcodebuild_call_of_every_task_is_given_the_directory(self):
        """A call without it compiles from Xcode's own checkouts, whatever the ones that were read say."""
        runs = {
            "build": {"usage_platform": "all", "usage_configuration": "Debug"},
            "test": {"usage_platform": "all"},
            "test (with results)": {"usage_platform": "macos", "usage_results": "TestResults"},
            "test (a chosen simulator)": {"usage_platform": "ios", "usage_simulator": "0000-UDID"},
            "test-keychain": {"usage_team": "ABCDE12345"},
            "release": {"usage_platform": "all", "usage_derived_data": "derived"},
        }
        shutil.copytree(os.path.join(support.ROOT, "Apps", "Shared"), self.path("Apps", "Shared"))
        seen = set()
        for name, environment in runs.items():
            with self.subTest(run=name):
                self.write("stub.log", "")
                self.task(name.split(" ")[0], **environment)
                self.assert_every_call_was_given_the_directory()
                seen.update(self.actions())
        self.assertEqual(
            seen,
            {"-resolvePackageDependencies", "-showdestinations", "build", "build-for-testing", "test", "test-without-building"},
        )

    def test_no_xcodebuild_command_in_the_repository_s_scripts_lacks_the_directory(self):
        """The same, read from the scripts: a call on a path the runs above do not take cannot slip through."""
        scripts = [os.path.join(TASKS, name) for name in sorted(os.listdir(TASKS)) if not name.endswith(".py")]
        scripts.append(PICK_SIMULATOR)
        found = {}
        for path in scripts:
            with open(path, encoding="utf-8") as handle:
                commands = xcodebuild_commands(handle.read())
            for command in commands:
                self.assertIn(DIRECTORY_ARGUMENT, command, f"{os.path.relpath(path, support.ROOT)}: {command}")
            if commands:
                found[os.path.basename(path)] = len(commands)
        expected = {"build": 1, "packages.sh": 1, "pick-simulator.sh": 1, "release": 1, "test": 3, "test-keychain": 1}
        self.assertEqual(found, expected)

    def test_the_reading_of_the_scripts_sees_a_call_without_it(self):
        """The check above is only as good as its eye for a command line."""
        with open(os.path.join(TASKS, "test"), encoding="utf-8") as handle:
            text = handle.read()
        self.assertEqual(len(xcodebuild_commands(text)), 3)
        stripped = xcodebuild_commands(text.replace(DIRECTORY_ARGUMENT + " ", ""))
        self.assertEqual(len(stripped), 3)
        self.assertTrue(all(DIRECTORY_ARGUMENT not in command for command in stripped))
        sample = 'if ! FOO=1 xcodebuild build \\\n    -scheme X; then\n  echo "xcodebuild failed"\nfi\n# xcodebuild test\n'
        self.assertEqual(xcodebuild_commands(sample), ["if ! FOO=1 xcodebuild build -scheme X; then"])

    def test_the_tests_do_not_run_on_another_commit(self):
        moved = self.sources.plan(swift_crypto=self.sources.at("swift-crypto", 1))
        result = self.task("test", usage_platform="macos", STUB_CHECKOUTS=moved)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies"])

    def test_passing_tests_do_not_excuse_another_commit(self):
        result = self.task("test", usage_platform="macos")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies", "test"])
        self.write("stub.log", "")
        newer = self.sources.plan(swift_asn1=self.sources.at("swift-asn1", 1))
        result = self.task("test", usage_platform="macos", STUB_REBUILT=newer)
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
        moved = self.sources.plan(swift_crypto=self.sources.at("swift-crypto", 1))
        result = self.task("test-keychain", usage_team="ABCDE12345", STUB_CHECKOUTS=moved)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.actions(), ["-resolvePackageDependencies"])

    def test_the_directory_is_build_output(self):
        """Ignored by git and removed by `mise run clean`, like the rest of `.build`."""
        with open(os.path.join(TASKS, "packages.sh"), encoding="utf-8") as handle:
            self.assertIn('\nsource_packages="$PWD/.build/app-source-packages"\n', handle.read())
        with open(os.path.join(support.ROOT, "mise-tasks", "clean"), encoding="utf-8") as handle:
            self.assertIn("\nrm -rf .build ", handle.read())
        with open(os.path.join(support.ROOT, ".gitignore"), encoding="utf-8") as handle:
            self.assertIn("\n.build/\n", handle.read())

    def test_the_repository_s_own_script_holds_the_real_commits(self):
        """The scratch copy differs from the repository's script in one line. The repository's, unchanged, refuses
        these stand-ins, and names the commits `Package.resolved` pins as the ones it wants."""
        with open(os.path.join(support.ROOT, "Package.resolved"), encoding="utf-8") as handle:
            pins = {pin["identity"]: pin["state"]["revision"] for pin in json.load(handle)["pins"]}
        self.build()
        script = os.path.join(support.ROOT, ".github", "scripts", "assert-no-dependencies.sh")
        result = self.run_process(["bash", script, "--checkouts", self.packages])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for name, commit in pins.items():
            self.assertIn(f"::error::{name}: checked out at {self.sources.commits[name][0]}, expected {commit}", result.stdout)
        self.assertEqual(sorted(pins), ["swift-asn1", "swift-crypto"])


MARKERS = ["--uitest", "WATCHWORD_UITEST_PASSWORD", "UI test: another device", "Lock now (UI test)"]
MACOS_APP = "Release/Watchword.app/Contents/MacOS/Watchword"
MACOS_EXTENSION = "Release/Watchword.app/Contents/PlugIns/AutoFillExtension-macOS.appex/Contents/MacOS/AutoFillExtension-macOS"
IOS_APP = "Release-iphonesimulator/Watchword.app/Watchword"
IOS_EXTENSION = "Release-iphonesimulator/Watchword.app/PlugIns/AutoFillExtension-iOS.appex/AutoFillExtension-iOS"
# What a binary looks like to a search for text: strings between runs of other bytes.
CONTROL = "Watchword cannot reach its shared storage"
# What a binary looks like to a search for text: strings between runs of other bytes. BARE is one in which the search
# finds nothing it knows, the control included; CLEAN is the app as it should be.
BARE = "\xcf\xfa\xed\xfe\x00\x00Account password\x00Unlock\x00\x01\x02"
CLEAN = BARE + CONTROL + ". This build is missing its App Group entitlement.\x00"


class ReleaseBuildTests(AppTaskTestCase):
    def setUp(self):
        super().setUp()
        # The markers are checked against the sources, so the task reads the repository's own.
        shutil.copytree(os.path.join(support.ROOT, "Apps", "Shared"), self.path("Apps", "Shared"))

    def products(self, **changes):
        files = {"macos": {MACOS_APP: CLEAN, MACOS_EXTENSION: BARE}, "ios": {IOS_APP: CLEAN, IOS_EXTENSION: BARE}}
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

    def test_a_binary_the_search_cannot_read_proves_nothing(self):
        """Found by the review of this change: the markers' absence is evidence only if this search can see such a
        literal in this binary at all (a compressed or encrypted executable, a literal built in registers). So the
        app must show one that is always compiled in, found the same way."""
        result = self.release(products=self.products(macos={MACOS_APP: BARE}))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f'::error::The Release build of macOS does not contain "{CONTROL}"', result.stdout)
        self.assertNotIn("none of the 4 Debug-only markers", result.stdout)
        # The control is the app's, not the extension's: finding it only there is not finding it in the app.
        result = self.release(products=self.products(macos={MACOS_APP: BARE, MACOS_EXTENSION: CLEAN}))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_the_control_is_a_literal_the_app_always_compiles(self):
        """Long enough to be stored as bytes (over 15), in code outside `#if DEBUG`, and the one the task names."""
        self.assertGreater(len(CONTROL.encode()), 15)
        with open(os.path.join(TASKS, "release"), encoding="utf-8") as handle:
            self.assertIn(f'\ncontrol="{CONTROL}"\n', handle.read())
        with open(os.path.join(support.ROOT, "Apps", "Shared", "AppEnvironment.swift"), encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        depth = 0
        found = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#if"):
                depth += 1
            elif stripped.startswith("#endif"):
                depth -= 1
            elif f'"{CONTROL}' in line and not stripped.startswith("//"):
                found.append(depth)
        self.assertEqual(found, [0])

    def test_a_control_that_left_the_sources_makes_the_check_stale(self):
        path = os.path.join("Apps", "Shared", "AppEnvironment.swift")
        with open(self.path(path), encoding="utf-8") as handle:
            text = handle.read()
        self.write(path, text.replace(CONTROL, "Watchword cannot open its storage"))
        result = self.release()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f'"{CONTROL}" is no longer in Apps/Shared', result.stdout)
        self.assertEqual(self.actions(), [])

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
        moved = self.sources.plan(swift_crypto=self.sources.at("swift-crypto", 1))
        result = self.release(STUB_CHECKOUTS=moved)
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
