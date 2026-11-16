"""Prints the text attachments `xcresulttool export attachments` wrote, for app:diagnose (data, not a task).

Usage: python3 -I diagnose-attachments.py <export directory> <bundle name>

Reads the export's manifest.json and prints every attachment that is text (a .txt name, or bytes that decode as
UTF-8 without NUL), one GitHub Actions group each, under its test's name. Each is cut to PER_ATTACHMENT lines and
the whole to TOTAL lines, so a runaway tree cannot bury the rest of the log. Never fails: the job has already failed.
"""

import json
import os
import sys

PER_ATTACHMENT = 300
TOTAL = 3000
MAX_BYTES = 2 << 20


def text_of(path):
    """The file's text, or None if it is not text (an image, a binary) or too large to be worth reading."""
    try:
        if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) > MAX_BYTES:
            return None
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def entries(export_dir):
    """[(test name, attachment name, path)] from the manifest, keeping only plain files inside export_dir."""
    try:
        with open(os.path.join(export_dir, "manifest.json"), encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, ValueError):
        return []
    found = []
    for test in manifest if isinstance(manifest, list) else []:
        if not isinstance(test, dict):
            continue
        test_name = test.get("testIdentifier") or test.get("testName") or "a test"
        for attachment in test.get("attachments", []) or []:
            if not isinstance(attachment, dict):
                continue
            exported = attachment.get("exportedFileName")
            if not isinstance(exported, str) or os.path.basename(exported) != exported or exported in ("", ".", ".."):
                continue
            name = attachment.get("suggestedHumanReadableName") or exported
            found.append((str(test_name), str(name), os.path.join(export_dir, exported)))
    return found


def main(arguments):
    if len(arguments) != 2:
        print("usage: diagnose-attachments.py <export directory> <bundle name>")
        return 0
    export_dir, bundle = arguments
    printed = 0
    shown = 0
    for test_name, name, path in entries(export_dir):
        if printed >= TOTAL:
            print(f"::warning::{bundle}: more text attachments not shown (over {TOTAL} lines)")
            break
        if name.lower().endswith((".png", ".jpg", ".jpeg", ".heic")):
            continue
        text = text_of(path)
        if text is None:
            continue
        lines = text.splitlines()
        budget = min(PER_ATTACHMENT, TOTAL - printed)
        print(f"::group::{bundle}: {test_name}: {name} ({len(lines)} lines, first {min(budget, len(lines))} shown)")
        for line in lines[:budget]:
            print(line)
        print("::endgroup::")
        printed += min(budget, len(lines))
        shown += 1
    if shown == 0:
        print(f"{bundle}: no text attachments in the failed tests")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
