"""mise-tasks/audit/actions, run as it is in scratch directories holding made-up workflows.

The audit is the control behind "every action is pinned to a commit SHA" (docs/07-supply-chain.md §3.1). It was a
`grep` for one spelling of `uses:`, and YAML has several: an end-to-end audit (docs/06-adversarial-review.md Z105)
wrote each of the spellings below and none was reported. Each is a test here, with the two cases the grep got wrong
the other way: a correctly pinned value in quotes, and the word in a script or a comment."""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support  # noqa: E402

TASK = os.path.join(support.ROOT, "mise-tasks", "audit", "actions")
SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"

WORKFLOW = """\
name: Example
on:
  pull_request:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: First
        run: echo first
{steps}
"""


class AuditActionsTests(support.ScriptTestCase):
    def audit(self, steps, name="example.yml", text=None):
        self.write(os.path.join(".github", "workflows", name), text or WORKFLOW.format(steps=steps))
        return self.run_process(["bash", TASK])

    def assert_refused(self, steps, **options):
        result = self.audit(steps, **options)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("::error", result.stdout)
        return result.stdout

    def assert_passes(self, steps, **options):
        result = self.audit(steps, **options)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("All actions pinned", result.stdout)

    def test_the_repository_s_own_workflows_pass(self):
        result = subprocess.run(
            ["bash", TASK], cwd=support.ROOT, env=self.environment, capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_pinned_actions_pass_with_or_without_a_comment_or_quotes(self):
        self.assert_passes(f"      - uses: actions/checkout@{SHA}")
        self.assert_passes(f"      - uses: actions/checkout@{SHA} # v7.0.1\n        with:\n          fetch-depth: 1")
        # The grep reported these two as unpinned: it kept the quotes.
        self.assert_passes(f'      - uses: "actions/checkout@{SHA}"')
        self.assert_passes(f"      - uses: 'actions/checkout@{SHA}' # v7.0.1")
        self.assert_passes(f"      - name: In a subdirectory\n        uses: github/codeql-action/init@{SHA}")

    def test_a_tag_branch_or_short_sha_is_refused(self):
        for reference in ("v4", "main", SHA[:7], SHA.upper(), SHA + "0"):
            with self.subTest(reference=reference):
                output = self.assert_refused(f"      - uses: actions/checkout@{reference}")
                self.assertIn("is not pinned to a 40-hex commit SHA", output)
        self.assert_refused("      - uses: actions/checkout")
        self.assert_refused("      - uses: docker://alpine:3.20")
        self.assert_refused("      - uses: ./.github/actions/local")

    def test_spellings_the_grep_did_not_read_are_refused(self):
        """Each of these is a `uses:` to GitHub and none was matched by `^\\s*-?\\s*uses:\\s*\\S+`."""
        spellings = {
            "a double-quoted key": '      - "uses": actions/checkout@v4',
            "a single-quoted key": "      - 'uses': x/y@main",
            "a flow mapping": "      - {uses: actions/setup-node@v4}",
            "a space before the colon": "      - uses : actions/cache@v4",
            "the value on the next line": "      - uses:\n          actions/cache@v4",
            "a quoted value on the next line": '      - uses:\n          "actions/cache@v4"',
            "a folded value": "      - uses: >-\n          actions/cache@v4",
            "an escaped key": '      - "us\\u0065s": actions/cache@v4',
            "an explicit key": "      - ? uses\n        : actions/cache@v4",
            "a tagged value": "      - uses: !!str actions/cache@v4",
            "an anchored step": "      - &step\n        uses: actions/cache@v4\n      - *step",
            "a merge key": "      - <<: {uses: actions/cache@v4}",
            "a capital letter": "      - Uses: actions/cache@v4",
            "a multi-line flow mapping": "      - {\n        uses: actions/cache@v4\n        }",
            "a second document": f"      - uses: actions/checkout@{SHA}\n---\nuses: actions/cache@v4",
        }
        for name, steps in spellings.items():
            with self.subTest(spelling=name):
                self.assert_refused(steps)

    def test_a_pinned_spelling_outside_the_subset_is_refused_too(self):
        """The reader does not guess: what it cannot read fails the audit even when a person can see it is pinned,
        and the message says which line."""
        output = self.assert_refused(f"      - {{uses: actions/checkout@{SHA}}}")
        self.assertIn("example.yml:12", output)
        self.assertIn("reads a subset of YAML", output)

    def test_a_second_uses_key_cannot_hide_behind_the_first(self):
        output = self.assert_refused(f"      - uses: actions/checkout@{SHA}\n        uses: actions/cache@v4")
        self.assertIn("appears twice", output)

    def test_a_line_separator_cannot_end_a_comment(self):
        """A YAML 1.1 parser starts a new line at U+2028 or U+0085, so a key can follow a comment on what an editor
        and a grep show as one line."""
        for separator in (" ", "\u0085", "\r"):
            with self.subTest(separator=repr(separator)):
                steps = f"      - name: Two\n        # a note{separator}        uses: actions/cache@v4\n        run: echo"
                self.assertIn("is not permitted", self.assert_refused(steps))

    def test_a_reusable_workflow_must_be_pinned(self):
        text = "name: Example\non:\n  pull_request:\njobs:\n  call:\n    uses: octo/repo/.github/workflows/build.yml@{}\n"
        self.assert_refused("", text=text.format("main"))
        self.assert_passes("", text=text.format(SHA))

    def test_the_word_in_a_script_a_name_or_a_comment_is_not_an_action(self):
        steps = "\n".join(
            [
                "      # this job uses: actions/cache@v4, once it is pinned",
                "      - name: Say what the job uses",
                "        run: |",
                "          echo 'uses: actions/cache@v4'",
                "          uses: actions/cache@v4",
                "      - name: Folded",
                "        run: >-",
                "          echo",
                "          uses: actions/cache@v4",
            ]
        )
        self.assert_passes(steps)

    def test_every_workflow_file_is_read(self):
        self.write(os.path.join(".github", "workflows", "good.yml"), WORKFLOW.format(steps=""))
        output = self.assert_refused("      - uses: actions/cache@v4", name="other.yaml")
        self.assertIn("other.yaml", output)
        self.assertNotIn("good.yml", output)

    def test_a_composite_action_in_the_repository_is_read(self):
        self.write(os.path.join(".github", "workflows", "good.yml"), WORKFLOW.format(steps=""))
        self.write(
            os.path.join(".github", "actions", "setup", "action.yml"),
            'name: Setup\nruns:\n  using: composite\n  steps:\n    - uses: actions/cache@v4\n',
        )
        result = self.run_process(["bash", TASK])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("action.yml", result.stdout)

    def test_no_workflows_is_a_failure_not_a_pass(self):
        """The grep printed "All actions pinned" when it was run where there was nothing to read."""
        result = self.run_process(["bash", TASK])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("nothing was audited", result.stdout)


if __name__ == "__main__":
    unittest.main()
