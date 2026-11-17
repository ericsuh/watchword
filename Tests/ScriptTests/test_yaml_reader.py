""".github/scripts/yaml-audit.py's reader of YAML: what it takes, what it refuses, and that it reads what a full parser
reads.

Every YAML audit (`audit:actions`, the `Apps/project.yml` allowlist) trusts this reader to see the document as GitHub
or XcodeGen will. It reads a small subset and refuses the rest, so the two things to hold are that nothing outside the
subset is accepted, and that what is accepted means what it says. The second is checked against PyYAML where PyYAML
is installed (it is not part of Xcode's python3, so that test skips on the CI runners and runs in cloud sessions)."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support  # noqa: E402

AUDIT = os.path.join(support.ROOT, ".github", "scripts", "yaml-audit.py")
WORKFLOWS = os.path.join(support.ROOT, ".github", "workflows")


def audited_files():
    files = [os.path.join(WORKFLOWS, name) for name in sorted(os.listdir(WORKFLOWS)) if name.endswith((".yml", ".yaml"))]
    return files + [os.path.join(support.ROOT, "Apps", "project.yml")]


class YAMLReaderTests(support.ScriptTestCase):
    def dump(self, text=None, path=None):
        """(the document as the reader reads it, or None if refused; what it printed)."""
        if text is not None:
            path = self.write("document.yml", text.encode("utf-8"))
        result = self.run_process([sys.executable, "-I", AUDIT, "dump", path])
        if result.returncode != 0:
            self.assertIn("::error", result.stdout, result.stderr)
            return None, result.stdout
        return json.loads(result.stdout), result.stdout

    def test_the_subset_reads_as_written(self):
        document, _ = self.dump(
            "\n".join(
                [
                    "# a comment",
                    "name: Example  # trailing",
                    "on:",
                    "  pull_request:",
                    "  push:",
                    "    branches: [main, 'release/1', \"x:y\"]",
                    "empty: {}",
                    "none: []",
                    "quoted: 'it''s'",
                    "dash: --flag \"value\"",
                    "jobs:",
                    "  build:",
                    "    steps:",
                    "      - uses: a/b@c # pin",
                    "        with:",
                    "          key: value",
                    "      - name: Script",
                    "        run: |",
                    "          echo one",
                    "",
                    "          uses: not a key",
                    "      - plain entry",
                    "    if: >-",
                    "      a &&",
                    "      b",
                    "",
                ]
            )
        )
        self.assertEqual(
            document,
            {
                "name": "Example",
                "on": {"pull_request": None, "push": {"branches": ["main", "release/1", "x:y"]}},
                "empty": {},
                "none": [],
                "quoted": "it's",
                "dash": '--flag "value"',
                "jobs": {
                    "build": {
                        "steps": [
                            {"uses": "a/b@c", "with": {"key": "value"}},
                            {"name": "Script", "run": "echo one\n\nuses: not a key\n"},
                            "plain entry",
                        ],
                        "if": "a && b",
                    }
                },
            },
        )

    def test_everything_outside_the_subset_is_refused(self):
        cases = {
            "a flow mapping": "a: {b: c}\n",
            "a flow mapping in a sequence": "a: [{b: c}]\n",
            "a nested flow sequence": "a: [[b]]\n",
            "a flow sequence over two lines": "a: [b,\n  c]\n",
            "a quoted key": '"a": b\n',
            "a key with a space": "a b: c\n",
            "an explicit key": "? a\n: b\n",
            "an anchor": "a: &x b\n",
            "an alias": "a: *x\n",
            "a tag": "a: !!str b\n",
            "a merge key": "<<: {a: b}\n",
            "a duplicate key": "a: 1\na: 2\n",
            "a plain value over two lines": "a: b\n  c\n",
            "a value on the next line": "a:\n  b\n",
            "a quoted value over two lines": 'a: "b\n  c"\n',
            "an escape": 'a: "b\\n"\n',
            "a mapping in a plain value": "a: b: c\n",
            "a document marker": "---\na: b\n",
            "a second document": "a: b\n---\nc: d\n",
            "a directive": "%YAML 1.2\na: b\n",
            "a tab": "a:\tb\n",
            "a tab in indentation": "a:\n\tb: c\n",
            "a carriage return": "a: b\r\nc: d\n",
            "a line separator": "a: b # x\u2028c: d\n",
            "a next-line character": "a: b # x\u0085c: d\n",
            "a bidirectional override": "a: b \u202e# c\n",
            "a byte-order mark": "\ufeffa: b\n",
            "a sequence beside its key": "a:\n- b\n",
            "a sequence in a sequence entry": "- - a\n",
            "an empty entry": "a:\n  -\n  - b\n",
            "deeper indentation with no owner": "a: b\n    c: d\n",
            "a block scalar with an indentation indicator": "a: |2\n    b\n",
            "a kept block scalar": "a: |+\n  b\n",
            "text after a quoted value": "a: 'b' c\n",
            "text after a flow sequence": "a: [b] c\n",
            "an empty document": "# nothing\n",
            "a scalar document": "just text\n",
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                document, output = self.dump(text)
                self.assertIsNone(document, output)
                self.assertIn("document.yml:", output)

    def test_bytes_that_are_not_utf8_are_refused(self):
        path = self.write("document.yml", b"a: \xff\n")
        document, _ = self.dump(path=path)
        self.assertIsNone(document)

    def test_the_audited_files_are_inside_the_subset(self):
        for path in audited_files():
            with self.subTest(file=os.path.relpath(path, support.ROOT)):
                document, output = self.dump(path=path)
                self.assertIsInstance(document, dict, output)

    def test_the_reader_agrees_with_a_full_parser_on_every_audited_file(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML is not installed (it is not part of Xcode's python3)")

        def normal(node):
            # Scalars compare as text: a full parser's types (`on` as true, `6.0` as a number) are not this reader's
            # business. An absent value is the empty string to both.
            if isinstance(node, dict):
                return {key: normal(value) for key, value in node.items()}
            if isinstance(node, list):
                return [normal(value) for value in node]
            return "" if node is None else node

        for path in audited_files():
            with self.subTest(file=os.path.relpath(path, support.ROOT)):
                document, output = self.dump(path=path)
                with open(path, encoding="utf-8") as handle:
                    expected = yaml.load(handle.read(), Loader=yaml.BaseLoader)
                self.assertEqual(normal(document), normal(expected), output[:200])


if __name__ == "__main__":
    unittest.main()
