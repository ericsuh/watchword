"""The two inline scripts of .github/workflows/screenshots.yml, run as they are in the file against a stand-in `gh`.

`decide` chooses whether a pull request gets a capture, which costs two macOS runners. `comment` is the one job
with a token that can write: it runs after a job that executed the pull request's code, so everything that job hands
it is hostile input, and so is every other comment on the pull request."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support  # noqa: E402

REPO = "ericsuh/watchword"
SHA = "0123456789abcdef0123456789abcdef01234567"
RUN = "https://github.com/ericsuh/watchword/actions/runs/777"
MARKER = "<!-- watchword-screenshots -->"
IOS = "01-onboarding,02-emergency-kit"
MACOS = "01-onboarding"


class WorkflowScriptTestCase(support.ScriptTestCase):
    step = None

    def setUp(self):
        super().setUp()
        self.install("gh", support.FAKE_GH)
        self.install("curl", support.FAKE_CURL)
        self.script = self.write("step.sh", support.workflow_script(self.step))
        self.responses = {}
        self.redirects = {}

    def run_step(self, **environment):
        self.write("gh/responses.json", json.dumps(self.responses))
        self.write("gh/redirects.json", json.dumps(self.redirects))
        if os.path.exists(self.path("gh", "calls.jsonl")):
            os.remove(self.path("gh", "calls.jsonl"))
        self.write("output.txt", "")
        return self.run_process(
            ["bash", self.script],
            GH_STUB=self.path("gh"),
            GH_TOKEN="not-a-token",
            GITHUB_OUTPUT=self.path("output.txt"),
            **environment,
        )

    def calls(self):
        if not os.path.exists(self.path("gh", "calls.jsonl")):
            return []
        return [json.loads(line) for line in self.read("gh", "calls.jsonl").splitlines()]


class DecideTests(WorkflowScriptTestCase):
    step = "Decide whether to capture, and whether a comment can be posted"

    def decide(self, message=None, **overrides):
        if message is not None:
            self.responses[f"repos/{REPO}/commits/{SHA}"] = {"commit": {"message": message}}
        environment = {
            "EVENT": "pull_request", "ACTION": "synchronize", "REPO": REPO, "LABEL": "", "LABELLED": "false",
            "PR_NUMBER": "21", "HEAD_SHA": SHA, "HEAD_REPO": REPO,
        }  # fmt: skip
        environment.update(overrides)
        result = self.run_step(**environment)
        outputs = dict(line.split("=", 1) for line in self.read("output.txt").splitlines())
        return result, outputs

    def test_adding_the_label_captures(self):
        result, outputs = self.decide(ACTION="labeled", LABEL="screenshots", LABELLED="true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outputs, {"capture": "true", "comment": "true", "pull_request": "21", "head": SHA})
        self.assertEqual(self.calls(), [], "the label needs no API call")

    def test_label_spelled_with_a_capital_captures_too(self):
        """Finding: the job's `if:` accepts `Screenshots` (expressions ignore case) and the script did not, so the
        documented trigger ran and did nothing."""
        _, outputs = self.decide(ACTION="labeled", LABEL="Screenshots", LABELLED="true")
        self.assertEqual(outputs["capture"], "true")

    def test_another_label_does_not_capture_even_on_a_labelled_pull_request(self):
        _, outputs = self.decide(ACTION="labeled", LABEL="bug", LABELLED="true")
        self.assertEqual(outputs["capture"], "false")

    def test_push_to_a_labelled_pull_request_captures(self):
        _, outputs = self.decide(LABELLED="true")
        self.assertEqual(outputs["capture"], "true")

    def test_marker_line_in_the_head_commit_captures_on_a_same_repository_branch(self):
        _, outputs = self.decide(message="Redraw the item list\n\n[screenshots]\n\nCo-Authored-By: x <x@example.com>")
        self.assertEqual((outputs["capture"], outputs["comment"]), ("true", "true"))

    def test_marker_mentioned_in_prose_does_not_capture(self):
        """Finding: a commit that only described the feature ("when a message contains [screenshots]") started two
        macOS jobs, because the marker was matched anywhere in the message."""
        for message in (
            "Add screenshots.yml\n\nIt runs when a head commit's message contains [screenshots].",
            "fix [screenshots]",
            "[screenshots] please",
            "  [screenshots]",
            "Revert \"x\"\n\n> [screenshots]",
            "[Screenshots]",
            "no marker at all",
        ):
            with self.subTest(message=message):
                result, outputs = self.decide(message=message)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(outputs["capture"], "false")

    def test_fork_cannot_start_a_capture_with_a_commit_message(self):
        """Finding: the marker checked no permission. A fork's author, with no access to the repository, could put
        it in every commit and take two macOS runners per push. A fork captures only through the label, which
        needs triage access; the marker is honoured only where pushing already needs write access."""
        result, outputs = self.decide(message="x\n\n[screenshots]", HEAD_REPO="evil/watchword")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((outputs["capture"], outputs["comment"]), ("false", "false"))
        self.assertEqual(self.calls(), [], "a fork's commit message is not even fetched")

    def test_labelled_fork_captures_without_a_comment(self):
        _, outputs = self.decide(ACTION="labeled", LABEL="screenshots", LABELLED="true", HEAD_REPO="evil/watchword")
        self.assertEqual((outputs["capture"], outputs["comment"]), ("true", "false"))

    def test_dispatch_attaches_only_to_an_open_pull_request_of_this_repository_at_that_commit(self):
        pull = f"repos/{REPO}/pulls/21"
        dispatch = {"EVENT": "workflow_dispatch", "ACTION": "", "HEAD_REPO": ""}
        self.responses[pull] = {"state": "open", "head": {"sha": SHA, "repo": {"full_name": REPO}}}
        _, outputs = self.decide(**dispatch)
        self.assertEqual((outputs["capture"], outputs["comment"]), ("true", "true"))
        for state, sha, repository in (("closed", SHA, REPO), ("open", "f" * 40, REPO), ("open", SHA, "evil/fork")):
            with self.subTest(state=state, sha=sha, repository=repository):
                self.responses[pull] = {"state": state, "head": {"sha": sha, "repo": {"full_name": repository}}}
                result, outputs = self.decide(**dispatch)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(outputs, {})
        for number in ("21/../../issues/1", "0", "-1", "21 22", "abc"):
            with self.subTest(number=number):
                result, outputs = self.decide(PR_NUMBER=number, **dispatch)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.calls(), [])
        _, outputs = self.decide(PR_NUMBER="", **dispatch)
        self.assertEqual((outputs["capture"], outputs["comment"]), ("true", "false"))


class CommentTests(WorkflowScriptTestCase):
    step = "Create or update the screenshots comment"
    comments = f"repos/{REPO}/issues/21/comments"
    artifacts = f"repos/{REPO}/actions/runs/777/artifacts"

    def setUp(self):
        super().setUp()
        self.responses[self.comments] = [[]]
        self.responses[self.artifacts] = [
            {
                "artifacts": [
                    {"id": 501, "name": "screenshots-ios"},
                    {"id": 502, "name": "watchword-screens-ios.png"},
                    {"id": 503, "name": "screenshots-macos"},
                ]
            },
            {"artifacts": [{"id": 504, "name": "watchword-screens-macos.png"}]},
        ]
        for identifier in (502, 504, 606, 701):
            self.serve(identifier, "image/png")

    def serve(self, identifier, content_type, name="sheet.png"):
        """Where the API says artifact identifier is served from: GitHub's storage, with the type in `rsct`."""
        address = f"https://api.github.com/repos/{REPO}/actions/artifacts/{identifier}/zip"
        self.redirects[address] = (
            f"https://results.blob.core.windows.test/artifacts/{identifier}?rscd=inline%3B+filename%3D%22{name}%22"
            f"&rsct={content_type.replace('/', '%2F').replace('+', '%2B')}&se=2026-11-15T23%3A55%3A22Z&sig=SIGNATURE"
        )

    def comment(self, **overrides):
        environment = {
            "REPO": REPO, "SERVER": "https://github.com", "API": "https://api.github.com", "RUN_ID": "777",
            "EVENT": "pull_request",
            "APPEARANCE": "", "DEVICE": "", "PR_NUMBER": "21", "HEAD_SHA": SHA,
            "SCREENS_IOS": IOS, "SCREENS_MACOS": MACOS,
        }  # fmt: skip
        environment.update(overrides)
        return self.run_step(**environment)

    def writes(self):
        return [call for call in self.calls() if call["method"] not in ("GET", "REDIRECT")]

    def posted(self):
        writes = self.writes()
        self.assertEqual(len(writes), 1, writes)
        return writes[0]

    def sticky(self, identifier, login="github-actions[bot]", body=None):
        if body is None:
            body = f"{MARKER}\n### Screenshots\n\nOf `{'a' * 40}`, merged with the base branch as CI tests it. "
            body += "Captured by [this run](https://github.com/ericsuh/watchword/actions/runs/5).\n\n- old"
        return {"id": identifier, "user": {"login": login}, "body": body}

    def test_first_comment_is_created_with_links_to_this_runs_artifacts(self):
        result = self.comment()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        call = self.posted()
        self.assertEqual((call["method"], call["path"]), ("POST", self.comments))
        body = call["body"]
        self.assertTrue(body.startswith(f"{MARKER}\n### Screenshots\n\nOf `{SHA}`, merged with the base branch"))
        self.assertIn(f"Captured by [this run]({RUN}).", body)
        self.assertIn(f"- **iOS simulator:** 2 screens. [contact sheet]({RUN}/artifacts/502), one PNG", body)
        self.assertIn(f"[every screen]({RUN}/artifacts/501), full size, zipped", body)
        self.assertIn(f"- **macOS:** 1 screen. [contact sheet]({RUN}/artifacts/504)", body)
        self.assertIn("  - `02-emergency-kit`", body)

    def test_comment_says_what_is_behind_the_links_and_expects_no_sign_in(self):
        """Finding: the comment said the pictures were "behind the links (sign-in needed)", priming the reader for a
        login prompt on a page the pull request's build controls."""
        self.comment()
        body = self.posted()["body"]
        self.assertNotIn("sign-in needed", body)
        self.assertIn("files this pull request's build produced", body)
        self.assertIn("blob.core.windows.net", body)
        self.assertIn("should ever ask for a password", body)

    def test_links_come_from_this_runs_artifact_list_not_from_the_capture_job(self):
        """Finding: the job linked whatever all-digit artifact id the job that ran the pull request's code reported,
        and the link opened an HTML page inline. Now ids reported by that job are not read at all: an artifact is
        linked only if this run has one under the exact name the upload steps use, and the unzipped one is a PNG."""
        self.responses[self.artifacts] = [
            {
                "artifacts": [
                    {"id": 601, "name": "watchword-screens-ios.html"},
                    {"id": 602, "name": "watchword-screens-ios.png.html"},
                    {"id": 603, "name": "evil watchword-screens-ios.png"},
                    {"id": 604, "name": "screenshots-ios-dark"},
                    {"id": 605, "name": "watchword-screens-macos.png"},
                    {"id": 606, "name": "watchword-screens-macos.png"},
                ]
            }
        ]
        result = self.comment(SHEET_IOS="999", IMAGES_IOS="998", SHEET_MACOS="997", IMAGES_MACOS="996")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        body = self.posted()["body"]
        self.assertIn("- **iOS simulator:** 2 screens. No artifact was uploaded.", body)
        # The newest of a re-run's two.
        self.assertIn(f"- **macOS:** 1 screen. [contact sheet]({RUN}/artifacts/606), one PNG of them all\n", body)
        for identifier in ("601", "602", "603", "604", "605", "999", "998", "997", "996"):
            self.assertNotIn(f"artifacts/{identifier}", body)

    def test_contact_sheet_is_linked_only_if_github_will_serve_it_as_a_png(self):
        """The rest of the same finding. An unzipped artifact is served inline as the type its uploader declared,
        and the uploader is the job that ran the pull request's code: it can give an HTML page the sheet's name.
        The job asks GitHub what it will serve the artifact as, and links it only if that is image/png."""
        for served in ("text/html", "image/svg+xml", "image/pngx", "application/octet-stream", None):
            with self.subTest(served=served):
                self.redirects.clear()
                self.serve(504, "image/png")
                if served:
                    self.serve(502, served, name="watchword-screens-ios.png")
                result = self.comment()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                body = self.posted()["body"]
                self.assertIn(f"- **iOS simulator:** 2 screens. [every screen]({RUN}/artifacts/501), full size", body)
                self.assertNotIn("artifacts/502", body)
                self.assertIn(f"[contact sheet]({RUN}/artifacts/504)", body)
                self.assertIn("contact sheet (artifact 502) is not served as image/png", result.stderr)
        # A type that only appears somewhere else in the address does not count.
        self.redirects.clear()
        address = f"https://api.github.com/repos/{REPO}/actions/artifacts/502/zip"
        self.redirects[address] = "https://blob.test/a?xrsct=image%2Fpng&rsct=text%2Fhtml&name=rsct=image%2Fpng.html"
        self.comment()
        self.assertNotIn("artifacts/502", self.posted()["body"])

    def test_the_signed_address_is_neither_followed_nor_shown(self):
        result = self.comment()
        self.assertNotIn("SIGNATURE", result.stdout + result.stderr + self.posted()["body"])
        asked = [call["path"] for call in self.calls() if call["method"] == "REDIRECT"]
        self.assertEqual(asked, [f"https://api.github.com/repos/{REPO}/actions/artifacts/{n}/zip" for n in (502, 504)])

    def test_dark_and_ipad_sets_are_looked_up_under_their_own_names(self):
        self.responses[self.artifacts] = [
            {
                "artifacts": [
                    {"id": 701, "name": "watchword-screens-ios-ipad-dark.png"},
                    {"id": 702, "name": "screenshots-macos-dark"},
                    {"id": 703, "name": "watchword-screens-ios.png"},
                ]
            }
        ]
        self.comment(EVENT="workflow_dispatch", APPEARANCE="dark", DEVICE="ipad")
        body = self.posted()["body"]
        self.assertIn(f"Of `{SHA}`. Captured by [this run]({RUN}), dispatched by hand.", body)
        self.assertIn(f"[contact sheet]({RUN}/artifacts/701)", body)
        self.assertIn(f"[every screen]({RUN}/artifacts/702)", body)
        self.assertNotIn("artifacts/703", body)

    def test_names_the_tour_could_not_have_produced_are_not_posted(self):
        """Finding: the list was bounded only by its total length, so one "name" could be thousands of characters
        of the build's choosing, posted by the repository's bot. A name is now at most `NN-` and 40 characters, and
        a list at most 99 names, which is what `Screens.capture` can produce."""
        many = ",".join(f"{number % 100:02d}-screen-{number}" for number in range(100))
        hostile = (
            "00-security-notice-" + "-".join(["your-session-expired"] * 250),
            "01-" + "a" * 41,
            many,
            "01-a,",
            ",01-a",
            "01-a,,02-b",
            "01-a\n02-b",
            "01-a\n",
            "01-a`",
            "01-a](https://evil.example)",
            "01-<img src=x>",
            "01-a b",
            "01-A",
            "1-a",
            "01-a--b",
            "01-a-",
            "@ericsuh",
            "",
        )
        for screens in hostile:
            with self.subTest(screens=screens[:60]):
                result = self.comment(SCREENS_IOS=screens)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                body = self.posted()["body"]
                self.assertIn(f"- **iOS simulator:** the capture failed or is incomplete. The [run]({RUN}) says", body)
                self.assertNotIn("evil", body)
                self.assertNotIn("session-expired", body)
                self.assertIn("- **macOS:** 1 screen.", body)
        ninety_nine = ",".join(f"{number:02d}-" + "a" * 40 for number in range(1, 100))
        self.comment(SCREENS_IOS=ninety_nine)
        self.assertIn("- **iOS simulator:** 99 screens.", self.posted()["body"])

    def test_its_own_earlier_comment_is_updated_not_duplicated(self):
        other = {"id": 41, "user": {"login": "ericsuh"}, "body": "Looks good"}
        self.responses[self.comments] = [[other], [self.sticky(42)]]
        result = self.comment()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        call = self.posted()
        self.assertEqual((call["method"], call["path"]), ("PATCH", f"repos/{REPO}/issues/comments/42"))
        # What it wrote is recognised as its own the next time.
        self.responses[self.comments] = [[self.sticky(42, body=call["body"])]]
        self.comment(EVENT="workflow_dispatch")
        call = self.posted()
        self.assertEqual((call["method"], call["path"]), ("PATCH", f"repos/{REPO}/issues/comments/42"))
        self.responses[self.comments] = [[self.sticky(42, body=call["body"])]]
        self.comment()
        self.assertEqual(self.posted()["method"], "PATCH")

    def test_another_bot_comment_that_begins_with_the_marker_is_left_alone(self):
        """Finding: the comment to overwrite was "the first by github-actions[bot] that starts with the marker".
        claude-pr.yml's reviews have that author too, and their text is model output a pull request can steer: a
        review made to begin with the marker would be erased, findings and all. The match is now the whole header
        this job writes, and anything less is not this job's comment."""
        review = f"{MARKER}\n## Review\n\n🔴 This change leaks the vault key to the log."
        lookalikes = [
            self.sticky(50, body=review),
            self.sticky(51, body=f"{MARKER}\n### Screenshots\n\nOf `{SHA}`. No run here."),
            self.sticky(52, body=f"{MARKER}\n### Screenshots\n\nOf `{SHA}`. Captured by [this run](https://x.test/1)."),
            self.sticky(53, body=f"{MARKER}\n### Screenshots\n\nOf `{SHA}`. Captured by [this run]({RUN[:-3]}x))."),
            self.sticky(54, body=f"intro\n{MARKER}\n### Screenshots\n\nOf `{SHA}`. Captured by [this run]({RUN})."),
            self.sticky(55, body=f"{MARKER}\n### Screenshots\n\nOf `nothing`. Captured by [this run]({RUN})."),
            self.sticky(56, body=MARKER),
        ]
        self.responses[self.comments] = [lookalikes]
        result = self.comment()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        call = self.posted()
        self.assertEqual((call["method"], call["path"]), ("POST", self.comments))

    def test_someone_elses_comment_with_the_whole_header_is_left_alone(self):
        self.responses[self.comments] = [[self.sticky(60, login="mallory"), self.sticky(61, login="github-actions")]]
        self.comment()
        self.assertEqual(self.posted()["method"], "POST")

    def test_two_comments_with_the_header_stop_the_job(self):
        self.responses[self.comments] = [[self.sticky(70)], [self.sticky(71)]]
        result = self.comment()
        self.assertEqual(result.returncode, 1)
        self.assertIn("More than one comment", result.stdout)
        self.assertEqual(self.writes(), [])

    def test_values_that_are_not_what_they_should_be_stop_the_job_before_any_call(self):
        for override in (
            {"PR_NUMBER": "21/../../pulls/1"}, {"PR_NUMBER": ""}, {"PR_NUMBER": "0"},
            {"HEAD_SHA": "main"}, {"HEAD_SHA": SHA.upper()}, {"HEAD_SHA": SHA + "0"},
            {"RUN_ID": "7/../7"}, {"RUN_ID": "9" * 21}, {"RUN_ID": ""},
        ):  # fmt: skip
            with self.subTest(override=override):
                result = self.comment(**override)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.calls(), [])

    def test_failed_capture_is_reported_as_failed(self):
        self.comment(SCREENS_IOS="", SCREENS_MACOS="")
        body = self.posted()["body"]
        self.assertEqual(body.count("the capture failed or is incomplete"), 2)
        self.assertNotIn("/artifacts/", body)


class WorkflowFileTests(unittest.TestCase):
    """What the file itself must keep saying, read as text: there is no YAML parser to rely on here."""

    def setUp(self):
        with open(support.WORKFLOW, encoding="utf-8") as handle:
            self.text = handle.read()
        self.jobs = {}
        name = None
        for line in self.text.split("jobs:\n", 1)[1].split("\n"):
            if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
                name = line.strip()[:-1]
                self.jobs[name] = []
            elif name:
                self.jobs[name].append(line)

    def keys(self, job, key):
        """The lines nested under `key:` at the job's top level."""
        lines, found, inside = self.jobs[job], [], False
        for line in lines:
            if line.startswith(f"    {key}:"):
                inside = True
            elif inside and line.strip() and not line.startswith("      "):
                break
            elif inside and line.strip() and not line.strip().startswith("#"):
                found.append(line.strip())
        return found

    def test_job_names_are_fixed_text(self):
        """Finding: `name: Capture (${{ matrix.name }})` showed unexpanded on every pull request that skipped it."""
        for job, lines in self.jobs.items():
            names = [line.strip() for line in lines if line.startswith("    name:")]
            self.assertEqual(len(names), 1, job)
            self.assertNotIn("${{", names[0], job)

    def test_only_the_comment_job_can_write_and_only_comments(self):
        self.assertEqual(self.keys("decide", "permissions"), ["contents: read"])
        self.assertEqual(self.keys("capture", "permissions"), ["contents: read"])
        self.assertEqual(self.keys("comment", "permissions"), ["pull-requests: write", "actions: read"])
        code = [line for line in self.text.split("\n") if not line.strip().startswith("#")]
        self.assertEqual([line.strip() for line in code if ": write" in line], ["pull-requests: write"])
        self.assertIn("\npermissions:\n  contents: read\n", self.text)
        self.assertNotIn("pull_request_target", self.text.split("jobs:\n", 1)[1])
        self.assertNotIn("issue_comment", self.text.split("jobs:\n", 1)[1])

    def test_the_comment_job_runs_nothing_from_the_pull_request(self):
        comment = "\n".join(self.jobs["comment"])
        self.assertNotIn("uses:", comment, "no checkout, no artifact download, no action at all")
        # All it takes from the job that ran the pull request's code is the two lists of names.
        taken = sorted(set(part.split("}}")[0].strip() for part in comment.split("needs.capture.outputs.")[1:]))
        self.assertEqual(taken, ["screens_ios", "screens_macos"])
        self.assertEqual(self.keys("capture", "outputs"), [
            "screens_ios: ${{ steps.capture.outputs.screens_ios }}",
            "screens_macos: ${{ steps.capture.outputs.screens_macos }}",
        ])  # fmt: skip

    def test_no_expression_is_expanded_inside_a_script(self):
        for step in (DecideTests.step, CommentTests.step):
            self.assertNotIn("${{", support.workflow_script(step), step)

    def test_checkout_keeps_no_credentials_and_actions_are_pinned(self):
        self.assertEqual(self.text.count("uses: actions/checkout@"), self.text.count("persist-credentials: false"))
        for line in self.text.split("\n"):
            if "uses:" in line:
                self.assertRegex(line.strip(), r"^(- )?uses: actions/[a-z-]+@[0-9a-f]{40} # v[0-9.]+$")


if __name__ == "__main__":
    unittest.main()
