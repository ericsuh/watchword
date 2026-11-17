"""Prints the end of app:diagnose: each failed test's failure messages and last STEP lines, then one summary line
(data, not a task).

Usage: python3 -I diagnose-summary.py <work directory>

app:diagnose fills the work directory, for each result bundle <name>:
  <name>.summary.json   `xcresulttool get test-results summary --compact`, if it could be read
  <name>.logs/          text files to search for STEP lines: app:test's copy of xcodebuild's output, and the test
                        runner's standard output from the bundle's diagnostics

A UI test prints `STEP <ISO 8601 time> [<test name>] <step>` before each step of a long flow (Apps/UITests/Shared,
`XCTestCase.step`). A test that ran out of time, or whose app stopped answering, has no other account of where it was,
so the last STEP_LINES of a failed test's lines are printed under its failure messages. The same line can be in both
xcodebuild's output and the runner's, so each is printed once, in time order. The last line printed is always
`UI-test summary: N passed, N failed: <names>`. Everything read is a test run's output, so files are capped, links are
not followed, and the helper never fails: the job has already failed.
"""

import json
import os
import re
import sys

STEP_LINES = 30
MESSAGE_LINES = 20
LINE_CHARACTERS = 500
MAX_LOG_BYTES = 256 << 20
MAX_SUMMARY_BYTES = 8 << 20

# XCTestCase.name is `-[Class method]` on Apple platforms, brackets and all, inside the line's own brackets.
STEP = re.compile(r"STEP (\d{4}-\d\d-\d\dT\S+) \[(-\[[^\]\n]*\]|[^\]\n]*)\] ([^\n]*)")


def clip(text):
    return text if len(text) <= LINE_CHARACTERS else text[:LINE_CHARACTERS] + "…"


def readable_file(path, limit):
    try:
        return not os.path.islink(path) and os.path.isfile(path) and os.path.getsize(path) <= limit
    except OSError:
        return False


def load_summary(path):
    """The summary's dict, or None when it is missing, too large or not a JSON object."""
    if not readable_file(path, MAX_SUMMARY_BYTES):
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            summary = json.load(handle)
    except (OSError, ValueError):
        return None
    return summary if isinstance(summary, dict) else None


def count(summary, key):
    value = summary.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def test_words(name):
    """The class and method a test name carries, as a set of words: `-[VaultSharingTests testShare]` (what
    XCTestCase.name is), `VaultSharingTests/testShare()` (xcresulttool's identifier) and `testShare()` all give
    their words without punctuation, so a STEP line's name and a failure's can be compared."""
    return {word for word in re.split(r"[^A-Za-z0-9_]+", name) if word}


def failures(summary):
    """[(test identifier, method words, [messages])] in the order the summary lists them, one entry per test."""
    found = {}
    for failure in summary.get("testFailures") or []:
        if not isinstance(failure, dict):
            continue
        name = failure.get("testIdentifierString") or failure.get("testName")
        if not isinstance(name, str) or not name:
            name = "a test"
        text = failure.get("failureText")
        method = failure.get("testName")
        words = test_words(name) | (test_words(method) if isinstance(method, str) else set())
        entry = found.setdefault(name, (words, []))
        if isinstance(text, str) and text:
            entry[1].append(text)
    return [(name, words, messages) for name, (words, messages) in found.items()]


def step_lines(directory):
    """{(time, test name, step)} from every plain file in directory, not following links."""
    steps = set()
    if not os.path.isdir(directory) or os.path.islink(directory):
        return steps
    for root, directories, files in os.walk(directory):
        directories[:] = [name for name in directories if not os.path.islink(os.path.join(root, name))]
        for file in files:
            path = os.path.join(root, file)
            if not readable_file(path, MAX_LOG_BYTES):
                continue
            try:
                with open(path, "rb") as handle:
                    for raw in handle:
                        if b"STEP " not in raw:
                            continue
                        line = raw.decode("utf-8", errors="replace")
                        for match in STEP.finditer(line):
                            steps.add((match.group(1), match.group(2), clip(match.group(3).rstrip())))
            except OSError:
                continue
    return steps


def steps_of(steps, words):
    """The STEP lines of the failed test whose words are `words`: the same test method, and, where the line names a
    class, one the failure names too (two classes can each have a `testShare`)."""
    methods = {word for word in words if word.startswith("test")}
    if not methods:
        return []
    others = words - methods
    mine = []
    for step in steps:
        named = test_words(step[1])
        named_methods = {word for word in named if word.startswith("test")}
        named_others = named - named_methods
        if named_methods == methods and (not named_others or named_others & others):
            mine.append(step)
    return sorted(mine)


def main(arguments):
    if len(arguments) != 1:
        print("usage: diagnose-summary.py <work directory>")
        return 0
    work = arguments[0]
    try:
        entries = os.listdir(work)
    except OSError:
        entries = []
    names = sorted(
        {entry[: -len(".summary.json")] for entry in entries if entry.endswith(".summary.json")}
        | {entry[: -len(".logs")] for entry in entries if entry.endswith(".logs")}
    )

    passed = failed = 0
    failed_names = []
    unread = []
    run_failed = False
    print("::group::UI-test steps of the failed tests")
    for bundle in names:
        summary = load_summary(os.path.join(work, bundle + ".summary.json"))
        if summary is None:
            unread.append(bundle)
            continue
        passed += count(summary, "passedTests")
        failed += count(summary, "failedTests")
        listed = failures(summary)
        if summary.get("result") == "Failed" and count(summary, "failedTests") == 0:
            run_failed = True
        steps = step_lines(os.path.join(work, bundle + ".logs")) if listed else set()
        for name, words, messages in listed:
            failed_names.append(name if len(names) == 1 else f"{bundle}: {name}")
            print(f"--- {bundle}: {name} failed")
            for message in messages[:MESSAGE_LINES]:
                for line in message.splitlines()[:MESSAGE_LINES] or [""]:
                    print(f"failure: {clip(line)}")
            if len(messages) > MESSAGE_LINES:
                print(f"failure: … and {len(messages) - MESSAGE_LINES} more")
            mine = steps_of(steps, words)
            if mine:
                shown = mine[-STEP_LINES:]
                print(f"last {len(shown)} of its {len(mine)} STEP lines:")
                for time, test, text in shown:
                    print(f"  STEP {time} [{test}] {text}")
            else:
                print("no STEP lines for this test (it prints none, or it stopped before its first)")
    print("::endgroup::")

    line = f"UI-test summary: {passed} passed, {failed} failed: {', '.join(failed_names) if failed_names else 'none'}"
    notes = []
    if run_failed:
        notes.append("a run failed outside any test (see the runner logs above)")
    if unread:
        notes.append(f"no readable summary for {', '.join(unread)}")
    if not names:
        notes.append("no result bundle was read")
    print(line + (f" ({'; '.join(notes)})" if notes else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
