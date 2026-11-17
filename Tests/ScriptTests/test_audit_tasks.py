"""The two smaller audit helpers: mise-tasks/test/adversarial-suites.sh, which `test` and `test:adversarial` source to
check that every adversarial area's suite ran, and mise-tasks/audit/mise-pins.

The suite check was `grep -F <name>` anywhere in the log, so one area's name inside another's ("sync log" in "sync
log, item metadata"), in a test's display name, or on the line that says a suite was skipped all counted as that area
having run (docs/06-adversarial-review.md Z104)."""

import os
import shutil
import subprocess
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
        for line, expected in (
            ('➜ Suite "Adversarial: crypto core" skipped.', "skipped or failed"),
            ('➜ Suite "Adversarial: crypto core" skipped: "not today"', "skipped or failed"),
            ('◇ Suite "Adversarial: crypto core" started.', "missing"),
            ('✘ Suite "Adversarial: crypto core" failed after 0.2 seconds with 1 issue.', "skipped or failed"),
        ):
            with self.subTest(line=line):
                result = self.check(self.full_log(without=("crypto core",)) + [line])
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(f"::error::Adversarial suite {expected}: crypto core\n", result.stdout)

    def test_a_pass_beside_a_skip_or_a_failure_is_not_a_pass(self):
        """Found by the review of this change: a suite reported skipped, with a line elsewhere in the log that reads
        as its pass (a test's title with a line break in it, or a line a test printed), still counted as run."""
        skipped = '➜ Suite "Adversarial: crypto core" skipped.'
        cases = {
            "a title with a line break": [
                skipped,
                '✔ Test "a title',
                '✔ Suite "Adversarial: crypto core" passed after 0.001 seconds." passed after 0.001 seconds.',
            ],
            "a printed line": [skipped, 'Suite "Adversarial: crypto core" passed after 0.001 seconds.'],
            "a skip after the real pass": [passed("crypto core"), skipped],
            "a failure beside a pass": [
                passed("crypto core"),
                '✘ Suite "Adversarial: crypto core" failed after 0.2 seconds with 1 issue.',
            ],
            "a skip quoted in other output": [passed("crypto core"), f"note: {skipped}"],
        }
        for name, lines in cases.items():
            with self.subTest(case=name):
                result = self.check(self.full_log(without=("crypto core",)) + lines)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("::error::Adversarial suite skipped or failed: crypto core\n", result.stdout)

    def test_a_suite_reported_passed_twice_is_not_trusted(self):
        """One of the two lines is not Swift Testing's, and the check cannot tell which."""
        for extra in (passed("crypto core"), 'printed: Suite "Adversarial: crypto core" passed after 1 seconds.'):
            with self.subTest(extra=extra):
                result = self.check(self.full_log() + [extra], system="Darwin")
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("::error::Adversarial suite reported as passed more than once: crypto core\n", result.stdout)

    def test_the_result_symbol_is_not_a_letter_in_any_locale(self):
        """Found by the review of this change: a byte-oriented awk classes the bytes of `✔` by the caller's locale,
        and in a Latin-1 locale its first byte is a letter, so every genuine pass was reported missing. The check
        reads the log as bytes whatever the locale."""
        locale = self.latin1_locale()
        if locale is None:
            self.skipTest("no Latin-1 locale here, and none could be generated")
        self.install("uname", "#!/bin/sh\necho Darwin\n")
        log = self.write("test.log", "\n".join(self.full_log()) + "\n")
        command = ["bash", "-c", 'source "$1" && check_adversarial_suites "$2"', "check", SUITES, log]
        result = self.run_process(command, **locale)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def latin1_locale(self):
        """Environment variables that select a locale in which bytes above 0x7F are letters, or None."""
        if shutil.which("localedef"):
            directory = self.path("locales")
            os.makedirs(directory, exist_ok=True)
            name = "en_US.ISO-8859-1"
            command = ["localedef", "-i", "en_US", "-f", "ISO-8859-1", os.path.join(directory, name)]
            subprocess.run(command, capture_output=True, check=False)
            if os.path.isdir(os.path.join(directory, name)):
                return {"LOCPATH": directory, "LC_ALL": name}
        if shutil.which("locale"):
            listed = subprocess.run(["locale", "-a"], capture_output=True, text=True, check=False).stdout.split()
            for name in ("en_US.ISO8859-1", "en_US.ISO-8859-1", "en_US.iso88591"):
                if name in listed:
                    return {"LC_ALL": name}
        return None

    def test_awk_is_run_in_the_c_locale_whatever_the_caller_s(self):
        """The same, where no such locale exists to try: what awk is given."""
        real = shutil.which("awk")
        self.install("awk", f'#!/bin/sh\necho "LC_ALL=$LC_ALL" >> "$AWK_LOG"\nexec {real} "$@"\n')
        self.write("awk.log", "")
        self.install("uname", "#!/bin/sh\necho Linux\n")
        log = self.write("test.log", "\n".join(self.full_log(darwin=False)) + "\n")
        command = ["bash", "-c", 'source "$1" && check_adversarial_suites "$2" && no_skipped_tests "$2"', "check", SUITES, log]
        result = self.run_process(command, LC_ALL="en_US.UTF-8", LANG="en_US.UTF-8", AWK_LOG=self.path("awk.log"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        runs = self.read("awk.log").splitlines()
        self.assertGreater(len(runs), 10)
        self.assertEqual(set(runs), {"LC_ALL=C"})

    def skipped_tests(self, lines):
        log = self.write("test.log", "\n".join(self.full_log(darwin=False) + lines) + "\n")
        return self.run_process(["bash", "-c", 'source "$1" && no_skipped_tests "$2"', "check", SUITES, log])

    def test_a_skipped_test_fails_the_adversarial_run(self):
        """A suite whose every test is disabled is still reported as passed; the tests it did not run are not."""
        for line in (
            '➜ Test "a forged segment is refused" skipped.',
            '➜ Test "a forged segment is refused" skipped: "flaky on the runner"',
            "➜ Test forgedSegment() skipped.",
            '\x1b[33m➜\x1b[0m Test forgedSegment() skipped: "later"',
        ):
            with self.subTest(line=line):
                result = self.skipped_tests([line])
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("::error::An adversarial test was skipped", result.stdout)
                self.assertIn("forged", result.stdout)

    def test_a_test_that_is_about_skipping_is_not_a_skipped_test(self):
        result = self.skipped_tests(
            [
                '◇ Test "An oversized item is skipped and listed; its neighbours are imported" started.',
                '✔ Test "An oversized item is skipped and listed; its neighbours are imported" passed after 1.2 seconds.',
                '✔ Test "a malformed vault entry in an archive is listed as skipped" passed after 0.8 seconds.',
                '✔ Test "an entry is listed as skipped: with its reason" passed after 0.8 seconds.',
                "the importer says: 3 entries skipped.",
            ]
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_the_adversarial_task_checks_for_skipped_tests(self):
        with open(os.path.join(support.ROOT, "mise-tasks", "test", "adversarial"), encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn('\ncheck_adversarial_suites "$log"\nno_skipped_tests "$log"\n', text)

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
