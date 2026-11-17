"""The two smaller audit helpers: mise-tasks/test/adversarial-suites.sh, which `test` and `test:adversarial` source to
check that every adversarial area's suite ran, and mise-tasks/audit/mise-pins.

The suite check was `grep -F <name>` anywhere in the log, so one area's name inside another's ("sync log" in "sync
log, item metadata"), in a test's display name, or on the line that says a suite was skipped all counted as that area
having run (docs/06-adversarial-review.md Z105)."""

import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support  # noqa: E402

SUITES = os.path.join(support.ROOT, "mise-tasks", "test", "adversarial-suites.sh")
SUITE_LIST = os.path.join(support.ROOT, "mise-tasks", "test", "adversarial-suites.txt")
MISE_PINS = os.path.join(support.ROOT, "mise-tasks", "audit", "mise-pins")


def areas():
    """[(area, only on Apple platforms)] as adversarial-suites.txt lists them."""
    listed = []
    with open(SUITE_LIST, encoding="utf-8") as handle:
        for line in handle.read().splitlines():
            if line and not line.startswith("#"):
                listed.append((line[len("darwin: ") :], True) if line.startswith("darwin: ") else (line, False))
    return listed


def passed(area):
    return f'✔ Suite "Adversarial: {area}" passed after 0.123 seconds.'


class AdversarialSuitesTests(support.ScriptTestCase):
    def check(self, lines, system="Linux"):
        """Runs check_adversarial_suites on a log of these lines, on a machine whose `uname -s` says system."""
        self.install("uname", f"#!/bin/sh\necho {system}\n")
        log = self.write("test.log", "\n".join(lines) + "\n")
        return self.run_process(["bash", "-c", 'source "$1" && check_adversarial_suites "$2"', "check", SUITES, log])

    def full_log(self, without=(), darwin=True):
        lines = ['◇ Test run started.', '◇ Suite "Adversarial: sync log" started.']
        lines += [passed(area) for area, apple in areas() if area not in without and (darwin or not apple)]
        return lines + ["✔ Test run with 900 tests in 30 suites passed after 9.000 seconds."]

    def test_the_list_names_real_suites(self):
        """Every listed area is the display name of a suite in the adversarial target, less its "Adversarial: "."""
        sources = ""
        directory = os.path.join(support.ROOT, "Tests", "WatchwordAdversarialTests")
        for name in sorted(os.listdir(directory)):
            if name.endswith(".swift"):
                with open(os.path.join(directory, name), encoding="utf-8") as handle:
                    sources += handle.read()
        self.assertGreater(len(areas()), 20)
        for area, _ in areas():
            with self.subTest(area=area):
                self.assertIn(f'@Suite("Adversarial: {area}"', sources)

    def test_a_log_with_every_suite_passes(self):
        result = self.check(self.full_log(), system="Darwin")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")

    def test_apple_only_suites_are_required_on_macos_and_reported_elsewhere(self):
        result = self.check(self.full_log(darwin=False), system="Linux")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("not required on Linux (Apple platforms only): Keychain item protection", result.stdout)
        result = self.check(self.full_log(darwin=False), system="Darwin")
        self.assertEqual(result.returncode, 1)
        self.assertIn("::error::Adversarial suite missing: Keychain item protection", result.stdout)

    def test_one_area_s_name_inside_another_s_is_not_that_area(self):
        """Finding: deleting the "sync log" suite passed, because "sync log, item metadata" still ran."""
        result = self.check(self.full_log(without=("sync log",)))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("::error::"), 1, result.stdout)
        self.assertIn("::error::Adversarial suite missing: sync log\n", result.stdout)

    def test_a_skipped_started_or_failed_suite_has_not_run(self):
        for line in (
            '➜ Suite "Adversarial: crypto core" skipped.',
            '➜ Suite "Adversarial: crypto core" skipped: "not today"',
            '◇ Suite "Adversarial: crypto core" started.',
            '✘ Suite "Adversarial: crypto core" failed after 0.2 seconds with 1 issue.',
        ):
            with self.subTest(line=line):
                result = self.check(self.full_log(without=("crypto core",)) + [line])
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("::error::Adversarial suite missing: crypto core\n", result.stdout)

    def test_the_name_in_a_test_s_title_or_output_is_not_the_suite(self):
        for line in (
            '✔ Test "crypto core" passed after 0.001 seconds.',
            '✔ Test "Suite "Adversarial: crypto core" passed after 0.1 seconds." passed after 0.001 seconds.',
            'note: Suite "Adversarial: crypto core" passed after 0.1 seconds.',
            '✔ Suite "Adversarial: crypto core, more" passed after 0.1 seconds.',
            '✔ Suite "Not Adversarial: crypto core" passed after 0.1 seconds.',
            '✔ Suite "Adversarial: crypto core" passed after lunch.',
        ):
            with self.subTest(line=line):
                result = self.check(self.full_log(without=("crypto core",)) + [line])
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("::error::Adversarial suite missing: crypto core\n", result.stdout)

    def test_the_line_is_recognised_as_each_toolchain_writes_it(self):
        """Swift Testing's symbol differs by platform and terminal, and a run with known issues or warnings says so
        after the time; colour codes appear when the output is a terminal."""
        for line in (
            '✔ Suite "Adversarial: crypto core" passed after 12.5 seconds.',
            '\U0010079b Suite "Adversarial: crypto core" passed after 0.004 seconds.',
            '\x1b[32m✔\x1b[0m Suite "Adversarial: crypto core" passed after 0.004 seconds.',
            '✔ Suite "Adversarial: crypto core" passed after 0.004 seconds with 1 known issue.',
            'Suite "Adversarial: crypto core" passed after 3 seconds',
        ):
            with self.subTest(line=line):
                result = self.check(self.full_log(without=("crypto core",)) + [line])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class MisePinsTests(support.ScriptTestCase):
    """audit:mise-pins compares the mise release that CI installs with the one a cloud session installs."""

    def audit(self, edit_cloud=None, edit_ci=None):
        for name, edit in (("install-mise.sh", edit_ci), ("cloud-setup.sh", edit_cloud)):
            with open(os.path.join(support.ROOT, ".github", "scripts", name), encoding="utf-8") as handle:
                text = handle.read()
            self.write(os.path.join(".github", "scripts", name), edit(text) if edit else text)
        return self.run_process(["bash", MISE_PINS])

    def test_the_repository_s_two_pins_agree(self):
        result = self.audit()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("pin the same mise release", result.stdout)

    def test_a_bump_of_one_script_only_fails(self):
        result = self.audit(edit_cloud=lambda text: text.replace('readonly MISE_VERSION="', 'readonly MISE_VERSION="9', 1))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("MISE_VERSION", result.stdout)
        result = self.audit(edit_ci=lambda text: text.replace('MISE_SHA256_LINUX_X64="', 'MISE_SHA256_LINUX_X64="0', 1))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("MISE_SHA256", result.stdout)

    def test_a_pin_that_is_gone_fails(self):
        result = self.audit(edit_cloud=lambda text: text.replace("readonly MISE_SHA256=", "MISE_SHA256=", 1))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("<missing>", result.stdout)

    def test_both_audits_gate_pull_requests(self):
        """Finding: audit:actions ran nightly only and audit:mise-pins in no workflow at all, so `Required checks`
        was green on a pull request that broke either. Both are steps of ci.yml's lint job, which `required` needs."""
        with open(os.path.join(support.ROOT, ".github", "workflows", "ci.yml"), encoding="utf-8") as handle:
            workflow = handle.read()
        lint = workflow[workflow.index("\n  lint:\n") : workflow.index("\n  app-tests:\n")]
        for task in ("audit:actions", "audit:mise-pins", "test:scripts"):
            with self.subTest(task=task):
                self.assertIn(f"        run: mise run {task}\n", lint)
        needs = next(line for line in workflow.splitlines() if line.strip().startswith("needs: [package-tests"))
        self.assertIn(" lint,", needs)


if __name__ == "__main__":
    unittest.main()
