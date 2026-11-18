"""The inline script of ci.yml's `Required checks` job, run as it is in the file against a stand-in `gh`.

`Required checks` is the one check branch protection names, so what it lets through is what can merge. It judged
`needs.*.result`, and a matrix job's result turned out not to be its legs' together: in run 44175108735 the Xcode 16.4
leg of the package tests was cancelled by the platform after 33 minutes without a runner, having run no step, the
matrix job's result was still `success`, and the gate went green (docs/06-adversarial-review.md Z119). The step tested
here asks the API for every job of the run attempt instead, and holds them to a list of the jobs it expects."""

import json
import os
import re
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support  # noqa: E402

CI = os.path.join(support.ROOT, ".github", "workflows", "ci.yml")
AUDIT = os.path.join(support.ROOT, ".github", "scripts", "yaml-audit.py")
STEP = "Fail unless every job of this run succeeded"
REPO = "ericsuh/watchword"
LISTING = f"repos/{REPO}/actions/runs/44175108735/attempts/1/jobs?per_page=100"
CANCELLED_LEG = "Package tests (Xcode 16.4 / macOS 15)"


def workflow():
    """ci.yml as the repository's own YAML reader reads it."""
    done = subprocess.run([sys.executable, "-I", AUDIT, "dump", CI], capture_output=True, text=True, check=True)
    return json.loads(done.stdout)


def job_names(job):
    """A job's names as GitHub reports them: its `name:` with each matrix leg's values filled in."""
    legs = job.get("strategy", {}).get("matrix", {}).get("include")
    if not legs:
        assert "${{" not in job["name"], job["name"]
        return [job["name"]]
    names = []
    for leg in legs:
        name = re.sub(r"\$\{\{ *matrix\.([a-z_]+) *\}\}", lambda match: leg[match.group(1)], job["name"])
        assert "${{" not in name, name
        names.append(name)
    return names


class RequiredChecksTests(support.ScriptTestCase):
    def setUp(self):
        super().setUp()
        self.install("gh", support.FAKE_GH)
        self.script = self.write("step.sh", support.workflow_script(STEP, CI))
        self.job = workflow()["jobs"]["required"]
        self.step = next(step for step in self.job["steps"] if step.get("name") == STEP)
        self.expected = self.step["env"]["EXPECTED"].splitlines()
        self.own = self.step["env"]["SELF"]

    def jobs(self, **changes):
        """The run's jobs as the API lists them when all is well: every expected job completed and successful, and
        this one still running. changes: {name: (status, conclusion)}, or None to leave a job out."""
        listed = {name: ("completed", "success") for name in self.expected}
        listed[self.own] = ("in_progress", None)
        for name, state in changes.items():
            if state is None:
                del listed[name]
            else:
                listed[name] = state
        return [
            {"name": name, "status": status, "conclusion": conclusion} for name, (status, conclusion) in listed.items()
        ]

    def page(self, jobs):
        return {"total_count": len(jobs), "jobs": jobs}

    def run_step(self, responses, **environment):
        self.write("gh/responses.json", json.dumps(responses))
        self.write("gh/calls.jsonl", "")
        values = {"REPO": REPO, "RUN_ID": "44175108735", "RUN_ATTEMPT": "1", "SELF": self.own}
        values["EXPECTED"] = self.step["env"]["EXPECTED"]
        values.update(environment)
        return self.run_process(["bash", self.script], GH_STUB=self.path("gh"), GH_TOKEN="not-a-token", **values)

    def check(self, jobs, **environment):
        return self.run_step({LISTING: self.page(jobs)}, **environment)

    def calls(self):
        return [json.loads(line) for line in self.read("gh", "calls.jsonl").splitlines()]

    def assert_fails(self, result, *expected):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for text in expected:
            self.assertIn(text, result.stdout)

    def test_every_job_successful_passes(self):
        result = self.check(self.jobs())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("::error", result.stdout)
        for name in self.expected:
            self.assertIn(name + "\n", result.stdout)
        self.assertEqual(self.calls(), [{"method": "GET", "path": LISTING, "body": None, "paginate": True}])

    def test_a_leg_cancelled_before_it_ran_fails_the_gate(self):
        """What happened: the leg's own conclusion is `cancelled`, whatever `needs.package-tests.result` says. The
        step does not read `needs` at all."""
        result = self.check(self.jobs(**{CANCELLED_LEG: ("completed", "cancelled")}))
        expected = f'::error::Job "{CANCELLED_LEG}" did not succeed: status completed, conclusion cancelled'
        self.assert_fails(result, expected)
        self.assertEqual(result.stdout.count("did not succeed"), 1)
        with open(self.script, encoding="utf-8") as handle:
            self.assertNotIn("needs.", handle.read())
        self.assertEqual(self.step["if"], "always()")

    def test_a_job_that_failed_or_was_skipped_fails_the_gate(self):
        for conclusion in ("failure", "skipped", "timed_out", "neutral", "action_required", "startup_failure"):
            with self.subTest(conclusion=conclusion):
                result = self.check(self.jobs(**{"App tests (macOS)": ("completed", conclusion)}))
                expected = f'Job "App tests (macOS)" did not succeed: status completed, conclusion {conclusion}'
                self.assert_fails(result, expected)

    def test_a_job_that_has_not_finished_fails_the_gate_without_waiting(self):
        # Every status the REST description lists but `completed`.
        for status in ("queued", "in_progress", "waiting", "requested", "pending"):
            with self.subTest(status=status):
                result = self.check(self.jobs(**{"Release build (macOS)": (status, None)}))
                expected = f'Job "Release build (macOS)" did not succeed: status {status}, conclusion none'
                self.assert_fails(result, expected)

    def test_every_job_that_did_not_succeed_is_named(self):
        changes = {CANCELLED_LEG: ("completed", "cancelled"), "Strict memory safety": ("completed", "failure")}
        result = self.check(self.jobs(**changes))
        self.assert_fails(
            result, f'Job "{CANCELLED_LEG}" did not succeed', 'Job "Strict memory safety" did not succeed'
        )

    def test_the_job_itself_is_set_aside_and_must_be_there(self):
        """It is in the listing, still running; that must not fail it. But a listing without it is not this run's."""
        result = self.check(self.jobs(**{self.own: None}))
        self.assert_fails(result, f'Expected this job ("{self.own}") once among the run\'s jobs and found it 0 times')
        twice = self.jobs() + [{"name": self.own, "status": "completed", "conclusion": "success"}]
        self.assert_fails(self.check(twice), "found it 2 times")

    def test_an_empty_listing_fails(self):
        self.assert_fails(self.check([]), "the listing is empty or is not this run's")
        self.assert_fails(self.run_step({LISTING: {}}))

    def test_a_request_that_fails_fails_the_gate(self):
        result = self.run_step({})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("completed and succeeded", result.stdout)
        self.assertIn("HTTP 404", result.stderr)

    def test_a_second_page_is_read(self):
        """More jobs than a page holds: the failure on the second page counts, and so does the success."""
        jobs = self.jobs()
        pages = [self.page(jobs[:5]), self.page(jobs[5:])]
        result = self.run_step({LISTING: pages})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.calls()[0]["paginate"])
        jobs[-2]["conclusion"] = "cancelled"
        result = self.run_step({LISTING: [self.page(jobs[:5]), self.page(jobs[5:])]})
        self.assert_fails(result, f'Job "{jobs[-2]["name"]}" did not succeed: status completed, conclusion cancelled')
        # Only the first page arriving is a listing with jobs missing.
        result = self.run_step({LISTING: self.page(self.jobs()[:5])})
        self.assert_fails(result, "a leg that was never created has not passed")

    def test_a_leg_that_was_never_created_fails_the_gate(self):
        """A mistyped matrix entry makes no job, so no job fails: only the list of what should be there shows it."""
        result = self.check(self.jobs(**{"App tests (iOS simulator, tour)": None}))
        expected = 'Expected job "App tests (iOS simulator, tour)" once among the run\'s jobs and found it 0 times'
        self.assert_fails(result, expected)

    def test_a_job_the_gate_does_not_know_fails_it(self):
        result = self.check(self.jobs(**{"A new job": ("completed", "success")}))
        self.assert_fails(result, '::error::Job "A new job" is not one this gate expects')
        twice = self.jobs() + [{"name": CANCELLED_LEG, "status": "completed", "conclusion": "success"}]
        expected = f'Expected job "{CANCELLED_LEG}" once among the run\'s jobs and found it 2 times'
        self.assert_fails(self.check(twice), expected)

    def test_one_name_inside_another_is_not_that_job(self):
        jobs = self.jobs(**{"App tests (macOS)": None, "App tests (macOS) again": ("completed", "success")})
        unknown = 'Job "App tests (macOS) again" is not one this gate expects'
        self.assert_fails(self.check(jobs), unknown, 'Expected job "App tests (macOS)" once')

    def test_values_that_are_not_what_they_should_be_check_nothing(self):
        values = (("RUN_ID", "1; echo"), ("RUN_ATTEMPT", ""), ("REPO", "ericsuh/watchword/../other"), ("RUN_ID", ""))
        for name, value in values:
            with self.subTest(variable=name, value=value):
                result = self.check(self.jobs(), **{name: value})
                self.assert_fails(result, "nothing was checked")
                self.assertEqual(self.calls(), [])

    def test_a_later_attempt_asks_for_its_own_jobs(self):
        """A re-run of failed jobs, as attempt 2 of run 44175108735 went: every job listed under the new attempt,
        those carried over as well as the one run again, so it passes."""
        listing = LISTING.replace("/attempts/1/", "/attempts/2/")
        result = self.run_step({listing: self.page(self.jobs())}, RUN_ATTEMPT="2")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls()[0]["path"], listing)

    def test_a_later_attempt_that_lists_only_what_it_ran_fails_closed(self):
        """GitHub's REST description does not say that a later attempt lists the jobs it carried over. If one ever
        listed only the leg it ran again, the gate must go red, not judge the re-run leg alone."""
        listing = LISTING.replace("/attempts/1/", "/attempts/2/")
        rerun = [job for job in self.jobs() if job["name"] in (CANCELLED_LEG, self.own)]
        result = self.run_step({listing: self.page(rerun)}, RUN_ATTEMPT="2")
        self.assert_fails(result, 'Expected job "Adversarial security tests" once among the run\'s jobs and found it 0')
        self.assertNotIn(f'Expected job "{CANCELLED_LEG}"', result.stdout)

    def test_the_list_of_expected_jobs_is_the_workflow_s_jobs(self):
        """EXPECTED is written by hand beside the jobs it names. If a job or a matrix leg is added, renamed or removed
        and the list is not, the gate would fail every run, or worse, not expect a job that should block."""
        jobs = workflow()["jobs"]
        others = {key: job for key, job in jobs.items() if key != "required"}
        names = [name for job in others.values() for name in job_names(job)]
        self.assertEqual(len(names), len(set(names)), "two jobs have the same name")
        self.assertEqual(sorted(self.expected), sorted(names))
        self.assertEqual(len(self.expected), len(set(self.expected)))
        self.assertTrue(all(name == name.strip() and name for name in self.expected))
        self.assertEqual(self.own, self.job["name"])
        self.assertNotIn(self.own, names)

    def test_the_gate_waits_for_every_job(self):
        jobs = workflow()["jobs"]
        self.assertEqual(sorted(self.job["needs"]), sorted(key for key in jobs if key != "required"))
        self.assertEqual(self.job["if"], "always()")

    def test_the_job_has_only_the_token_it_needs_and_takes_values_through_env(self):
        self.assertEqual(self.job["permissions"], {"contents": "read", "actions": "read"})
        self.assertFalse(any("uses" in step for step in self.job["steps"]), "the gate checks nothing out")
        with open(self.script, encoding="utf-8") as handle:
            self.assertNotIn("${{", handle.read())
        env = self.step["env"]
        self.assertEqual(env["GH_TOKEN"], "${{ github.token }}")
        self.assertEqual(env["REPO"], "${{ github.repository }}")
        self.assertEqual(env["RUN_ID"], "${{ github.run_id }}")
        self.assertEqual(env["RUN_ATTEMPT"], "${{ github.run_attempt }}")
        # No other job of the workflow reads run metadata.
        for key, job in workflow()["jobs"].items():
            if key != "required":
                self.assertEqual(job["permissions"], {"contents": "read"}, key)


if __name__ == "__main__":
    unittest.main()
