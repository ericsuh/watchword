#!/usr/bin/env python3
"""Audits of the repository's YAML that read it as a parser would, not as lines of text.

    yaml-audit.py actions [<directory>]   every `uses:` under .github/ is pinned to a 40-hex commit SHA
    yaml-audit.py app-spec <project.yml>  the XcodeGen spec holds nothing but what is allowed below
    yaml-audit.py dump <file>             the document as JSON, for the script tests

Both audits used to be `grep`s, and a grep reads spellings: `- {uses: a/b@v1}`, `"uses": a/b@v1`, a value on the next
line, a flow-style remote package or a quoted `"NO"` all passed (docs/06-adversarial-review.md Z103, Z104). The runners
promise no YAML library (Xcode's python3 is the standard library alone), so this file reads a small subset of YAML
itself and refuses everything outside it. That is the point of it, not a limitation to be worked round: a file this
does not understand fails the audit, so nothing can be hidden in a construct it skipped. The subset is what the
workflows and Apps/project.yml use:

  - block mappings with plain keys (letters, digits, `_`, `.`, `-`), and block sequences nested under a key;
  - scalars on one line: plain, 'single-quoted', "double-quoted" without escapes; literal and folded block scalars;
  - flow sequences of scalars on one line, and the empty mapping `{}`;
  - comments and blank lines.

Refused, with the file and line: quoted or escaped keys, flow mappings, anchors, aliases, tags, merge keys, explicit
keys, document markers, multi-line plain or quoted scalars, a value on the line after its key, duplicate keys, tabs,
and control, bidirectional or Unicode line-separator characters (a YAML 1.1 parser starts a new line at U+2028, so a
comment could end there and a key begin). Where a real parser is at hand, Tests/ScriptTests compares this reader's
result with PyYAML's for every file audited.

Standard library only, Python 3.9 syntax.
"""

import json
import os
import re
import sys


class Refused(Exception):
    """The document is outside the subset, or breaks an audit's rule."""


KEY = re.compile(r"([A-Za-z_][A-Za-z0-9_.-]*):(?: +(.*))?$")
BLOCK_HEADER = re.compile(r"([|>])(-?)(?: +#.*)?$")
AFTER_VALUE = re.compile(r"(?: +#.*)?$")
FLOW_PLAIN = re.compile(r"[A-Za-z0-9_.$/][A-Za-z0-9_.$()/@+=~-]*")
# What may not begin a plain scalar: YAML's indicators. A value that starts with one is a construct this reader does
# not read (an alias, a tag, a flow mapping, an explicit key), not text.
INDICATORS = "-?:,[]{}#&*!|>'\"%@`"
FORBIDDEN_CHARACTERS = {0x7F, 0x85, 0x2028, 0x2029, 0xFEFF} | set(range(0x80, 0xA0))
FORBIDDEN_CHARACTERS |= set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F}


def indent_of(line):
    return len(line) - len(line.lstrip(" "))


class Reader:
    def __init__(self, text, name):
        self.name = name
        for number, line in enumerate(text.split("\n"), 1):
            for character in line:
                code = ord(character)
                if (code < 0x20 and character != "\t") or code in FORBIDDEN_CHARACTERS:
                    raise Refused(f"{name}:{number}: character U+{code:04X} is not permitted")
        self.lines = text.split("\n")
        self.index = 0

    def refuse(self, message, index=None):
        number = (self.index if index is None else index) + 1
        raise Refused(f"{self.name}:{number}: {message}")

    def skip(self):
        """Moves past blank lines and comment lines."""
        while self.index < len(self.lines):
            line = self.lines[self.index]
            if "\t" in line:
                self.refuse("a tab outside a block scalar")
            stripped = line.strip(" ")
            if stripped and not stripped.startswith("#"):
                return
            self.index += 1

    def at_end(self):
        self.skip()
        return self.index >= len(self.lines)

    def document(self):
        if self.at_end():
            self.refuse("the document is empty")
        if indent_of(self.lines[self.index]) != 0:
            self.refuse("the document does not start in the first column")
        result = self.node(0)
        if not self.at_end():
            self.refuse("unexpected content after the document")
        return result

    def node(self, indent):
        content = self.lines[self.index][indent:].rstrip(" ")
        if content.startswith("- ") or content == "-":
            return self.sequence(indent)
        if KEY.match(content):
            return self.mapping(indent)
        return self.refuse("expected `key: value` or `- entry` (a scalar may not start on the line after its key)")

    def mapping(self, indent):
        result = {}
        while not self.at_end():
            line = self.lines[self.index]
            if indent_of(line) < indent:
                break
            if indent_of(line) > indent:
                self.refuse("unexpected indentation")
            match = KEY.match(line[indent:].rstrip(" "))
            if not match:
                self.refuse("expected `key: value` with a plain key")
            key = match.group(1)
            if key in result:
                self.refuse(f"the key `{key}` appears twice")
            self.index += 1
            result[key] = self.value(match.group(2) or "", indent)
        return result

    def sequence(self, indent):
        result = []
        while not self.at_end():
            line = self.lines[self.index]
            if indent_of(line) < indent:
                break
            if indent_of(line) > indent:
                self.refuse("unexpected indentation")
            content = line[indent:].rstrip(" ")
            if not content.startswith("- "):
                self.refuse("expected `- entry`")
            rest = content[2:].lstrip(" ")
            inner = indent + len(content) - len(rest)
            if rest == "" or rest.startswith("#"):
                self.refuse("an empty sequence entry")
            if rest.startswith("- ") or rest == "-":
                self.refuse("a sequence directly inside a sequence entry")
            if KEY.match(rest):
                # `- key: value`: a mapping whose first key is on the entry's line, indented to where the key starts.
                self.lines[self.index] = " " * inner + rest
                result.append(self.mapping(inner))
            else:
                self.index += 1
                result.append(self.value(rest, indent))
        return result

    def value(self, rest, indent):
        """The value whose text after `key:` or `- ` is rest; the line itself is already consumed."""
        rest = rest.strip(" ")
        if rest == "" or rest.startswith("#"):
            if not self.at_end() and indent_of(self.lines[self.index]) > indent:
                return self.node(indent_of(self.lines[self.index]))
            return None
        if rest[0] in "|>":
            return self.block_scalar(rest, indent)
        result = self.inline(rest)
        if not self.at_end() and indent_of(self.lines[self.index]) > indent:
            self.refuse("a value that continues on the next line")
        return result

    def inline(self, text):
        index = self.index - 1
        if text[0] in "\"'":
            result, end = self.quoted(text, 0, index)
        elif text[0] == "[":
            result, end = self.flow_sequence(text, index)
        elif text.startswith("{}"):
            result, end = {}, 2
        else:
            return self.plain(text, index)
        if not AFTER_VALUE.match(text[end:].rstrip(" ")):
            self.refuse("unexpected text after a value", index)
        return result

    def plain(self, text, index):
        comment = text.find(" #")
        if comment >= 0:
            text = text[:comment].rstrip(" ")
        # `-x` is text (`--allowedTools …`); `- x` would be a sequence entry, and never reaches here.
        if text[0] in INDICATORS and not (text[0] == "-" and len(text) > 1 and text[1] != " "):
            self.refuse(f"a value that starts with `{text[0]}` (an alias, tag, flow mapping or other indicator)", index)
        if ": " in text or text.endswith(":"):
            self.refuse("a plain value that contains `: `", index)
        return text

    def quoted(self, text, start, index):
        quote = text[start]
        position = start + 1
        result = []
        while position < len(text):
            character = text[position]
            if character == quote:
                if quote == "'" and text[position + 1 : position + 2] == "'":
                    result.append("'")
                    position += 2
                    continue
                return "".join(result), position + 1
            if quote == '"' and character == "\\":
                self.refuse("an escape in a double-quoted value", index)
            result.append(character)
            position += 1
        return self.refuse("a quoted value that does not end on its line", index)

    def flow_sequence(self, text, index):
        result = []
        position = 1
        while True:
            while text[position : position + 1] == " ":
                position += 1
            if text[position : position + 1] == "]" and not result:
                return result, position + 1
            if text[position : position + 1] in ("'", '"') and position < len(text):
                item, position = self.quoted(text, position, index)
            else:
                match = FLOW_PLAIN.match(text, position)
                if not match:
                    self.refuse("a flow sequence may hold only plain or quoted scalars, on one line", index)
                item, position = match.group(0), match.end()
            result.append(item)
            while text[position : position + 1] == " ":
                position += 1
            if text[position : position + 1] == "]":
                return result, position + 1
            if text[position : position + 1] != ",":
                self.refuse("a flow sequence may hold only plain or quoted scalars, on one line", index)
            position += 1

    def block_scalar(self, header, indent):
        match = BLOCK_HEADER.match(header)
        if not match:
            self.refuse("a block scalar header other than `|`, `|-`, `>` or `>-`", self.index - 1)
        style, strip = match.group(1), match.group(2) == "-"
        lines, width, blank = [], None, 0
        # A line of nothing but spaces that is longer than the scalar's indentation is refused: before the first line
        # of text a full parser rejects it, and after it the extra spaces are content this reader would drop.
        longer = "a whitespace-only line longer than its block scalar's indentation"
        while self.index < len(self.lines):
            line = self.lines[self.index]
            if line.strip(" \t") == "":
                if "\t" in line:
                    self.refuse("a tab on an otherwise blank line")
                if width is None:
                    blank = max(blank, len(line))
                elif len(line) > width:
                    self.refuse(longer)
                lines.append("")
            else:
                if width is None:
                    if indent_of(line) <= indent:
                        break
                    width = indent_of(line)
                    if blank > width:
                        self.refuse(longer)
                elif indent_of(line) < width:
                    break
                lines.append(line[width:])
            self.index += 1
        while lines and lines[-1] == "":
            lines.pop()
        if style == "|":
            text = "\n".join(lines)
        else:
            text, previous, blanks = "", None, 0
            for line in lines:
                if line == "":
                    blanks += 1
                    continue
                if previous is None:
                    text = "\n" * blanks + line
                else:
                    kept = previous.startswith(" ") or line.startswith(" ")
                    text += ("\n" * (blanks + (1 if kept else 0)) if blanks or kept else " ") + line
                previous, blanks = line, 0
        return text if strip or not text else text + "\n"


def load(path):
    with open(path, encoding="utf-8", newline="") as handle:
        text = handle.read()
    return Reader(text, path).document()


# ----------------------------------------------------------------------------------------------------- actions

# `owner/repository[/path]@<40 hex>`. The owner is a GitHub account name, so it starts with a letter or digit: a value
# that starts with `.` is not an action in someone's repository but a path in the checkout, and GitHub reads the whole
# of it as that path, an `@…` ending included. `./ci/build@<40 hex>` matched an earlier form of this pattern with `.`
# as the owner (docs/06-adversarial-review.md Z109). No local action is allowed at all: a composite action's manifest
# in the checkout is the pull request's own file, it may sit anywhere, and nothing here would read its `uses:`.
PINNED = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:/[A-Za-z0-9_.-]+)+@[0-9a-f]{40}")


def pinned(value):
    """Whether value names an action or reusable workflow in a repository at a full commit ID."""
    if not isinstance(value, str) or not PINNED.fullmatch(value):
        return False
    return not any(part in (".", "..") for part in value.split("@")[0].split("/"))


def uses_values(node, where):
    """Every value under a key spelled `uses` in any letter case, at any depth, with where it is."""
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{where}.{key}" if where else key
            if key.lower() == "uses":
                yield here, value
            else:
                yield from uses_values(value, here)
    elif isinstance(node, list):
        for number, value in enumerate(node):
            yield from uses_values(value, f"{where}[{number}]")


def workflow_files(root):
    """Workflows, and the manifests of composite actions kept in the repository: the files whose `uses:` GitHub runs."""
    found = []
    for directory, _, names in sorted(os.walk(root)):
        for name in sorted(names):
            path = os.path.join(directory, name)
            relative = os.path.relpath(path, root).split(os.sep)
            # Any letter case: whether GitHub would load `X.YML` is not this audit's to guess.
            if not name.lower().endswith((".yml", ".yaml")):
                continue
            if relative[0] == "workflows" or name.lower() in ("action.yml", "action.yaml"):
                found.append(path)
    return found


def audit_actions(root):
    problems = []
    files = workflow_files(root)
    if not files:
        problems.append(f"::error::No workflow files under {root}: nothing was audited")
    for path in files:
        try:
            document = load(path)
        except (Refused, UnicodeDecodeError) as refusal:
            problems.append(f"::error file={path}::{refusal} (yaml-audit.py reads a subset of YAML and refuses the rest)")
            continue
        for where, value in uses_values(document, ""):
            if not pinned(value):
                shown = value if isinstance(value, str) else json.dumps(value)
                local = isinstance(value, str) and value.startswith(".")
                reason = ": it is a path in the checkout, and local actions are not permitted" if local else ""
                problems.append(f"::error file={path}::{where}: `{shown}` is not pinned to a 40-hex commit SHA{reason}")
    return problems, f"All actions pinned to commit SHAs ({len(files)} files)."


# ---------------------------------------------------------------------------------------------------- app spec
#
# Everything below is an allowlist: a key, target type, dependency kind or build setting that is not named here fails
# the audit, so adding one to Apps/project.yml means adding it here, in the same pull request, where a reviewer sees
# it. What the lists leave out on purpose: remote packages and any local package but the repository's own; build
# scripts and rules, plugins, legacy and aggregate targets, scheme actions and the generation-time commands (each runs
# shell); `include`, `configFiles` and `fileGroups` (files no check reads); prebuilt frameworks and SDK dependencies;
# compiler, linker and compilation-condition settings; per-configuration settings (so nothing can define DEBUG for
# Release); and source paths that leave Apps/.

ROOT_KEYS = {"name", "options", "settings", "packages", "targetTemplates", "targets", "schemes"}
OPTION_KEYS = {"bundleIdPrefix", "deploymentTarget", "createIntermediateGroups", "generateEmptyDirectories"}
TARGET_KEYS = {"type", "platform", "templates", "sources", "dependencies", "settings", "info", "entitlements"}
TARGET_TYPES = {"application", "app-extension", "bundle.ui-testing", "bundle.unit-test"}
PLATFORMS = {"iOS", "macOS"}
# The one file compiled from outside Apps/: the Keychain adapter's tests, hosted by an entitled app (project.yml says
# why). It is Swift under Tests/, which the other tripwires read.
OUTSIDE_SOURCES = {"../Tests/WatchwordPlatformTests/SystemKeychainStoreTests.swift"}
# Settings that are the project's alone, with the value each must have. A target may not set them at all, so none can
# be relaxed for one target; and each must be present, because a setting that is merely absent is off.
REQUIRED_PROJECT_SETTINGS = {
    "SWIFT_VERSION": {"6.0", "6"},
    "SWIFT_STRICT_CONCURRENCY": {"complete"},
    "SWIFT_STRICT_MEMORY_SAFETY": {"YES"},
    "SWIFT_TREAT_WARNINGS_AS_ERRORS": {"YES"},
    "ENABLE_USER_SCRIPT_SANDBOXING": {"YES"},
}
PROJECT_SETTINGS = {"MARKETING_VERSION", "CURRENT_PROJECT_VERSION", "DEAD_CODE_STRIPPING"}
PROJECT_SETTING_PREFIXES = ("WATCHWORD_",)
TARGET_SETTINGS = {
    "PRODUCT_NAME",
    "PRODUCT_BUNDLE_IDENTIFIER",
    "GENERATE_INFOPLIST_FILE",
    "TARGETED_DEVICE_FAMILY",
    "ENABLE_HARDENED_RUNTIME",
    "TEST_TARGET_NAME",
    "TEST_HOST",
    "BUNDLE_LOADER",
}
TARGET_SETTING_PREFIXES = ("INFOPLIST_KEY_",)
SCHEME_KEYS = {"build", "run", "test"}
BUILD_ACTIONS = {"run", "test", "profile", "analyze", "archive"}
CONFIGURATIONS = {"Debug", "Release"}
# A relative path of ordinary names: no `..`, no `.`, nothing hidden, not absolute, no `~` or variable.
PATH = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*")
# The package's own modules. XcodeGen would accept any product name the package graph can supply, swift-crypto's
# `Crypto` and `CryptoExtras` (BoringSSL) among them, so the name is held to the repository's.
PRODUCT = re.compile(r"SecureMemory|Watchword[A-Za-z0-9]*")


def one_of(value, allowed):
    """Whether value is a string in allowed (a list or mapping where a name belongs is not, and is not hashable)."""
    return isinstance(value, str) and value in allowed


class SpecAudit:
    def __init__(self, path):
        self.path = path
        self.problems = []

    def problem(self, message):
        self.problems.append(f"::error file={self.path}::{message}")

    def mapping(self, node, where, allowed=None):
        """node if it is a mapping with no key outside allowed, else an empty mapping and a problem."""
        if not isinstance(node, dict):
            self.problem(f"{where} must be a mapping")
            return {}
        if allowed is not None:
            for key in node:
                if key not in allowed:
                    self.problem(f"{where}.{key} is not permitted in the app project (allowed: {', '.join(sorted(allowed))})")
        return node

    def strings(self, node, where):
        if isinstance(node, list) and all(isinstance(item, str) for item in node):
            return node
        self.problem(f"{where} must be a list of strings")
        return []

    def no_expansion(self, node, where):
        """XcodeGen replaces `${NAME}` with an environment variable while it reads the spec, so a value written that
        way is one this audit has not seen. `$(NAME)` is Xcode's own build-setting reference and is fine."""
        if isinstance(node, dict):
            for key, value in node.items():
                self.no_expansion(value, f"{where}.{key}" if where else key)
        elif isinstance(node, list):
            for number, value in enumerate(node):
                self.no_expansion(value, f"{where}[{number}]")
        elif isinstance(node, str) and "${" in node:
            self.problem(f"{where}: `${{…}}` is expanded from the environment when the project is generated")

    def inside_apps(self, value, where):
        if not isinstance(value, str) or not PATH.fullmatch(value):
            self.problem(f"{where}: `{value}` must be a path inside Apps/ (no `..`, not absolute)")

    def settings(self, node, where, exact, prefixes, required=None):
        base = self.mapping(self.mapping(node, where, {"base"}).get("base", {}), f"{where}.base")
        for key, value in base.items():
            if required and key in required:
                if not one_of(value, required[key]):
                    wanted = " or ".join(sorted(required[key]))
                    self.problem(f"{where}.base.{key} must be {wanted}, not `{value}`")
            elif key not in exact and not key.startswith(prefixes):
                self.problem(f"{where}.base.{key} is not a build setting the app project may set")
            elif not isinstance(value, str):
                self.problem(f"{where}.base.{key} must be a single value")
        for key in required or {}:
            if key not in base:
                self.problem(f"{where}.base.{key} is required (a setting that is absent is off)")

    def target(self, node, where, target_names, template_names, template):
        node = self.mapping(node, where, TARGET_KEYS)
        if "type" in node and not one_of(node["type"], TARGET_TYPES):
            self.problem(f"{where}.type `{node['type']}` is not permitted (allowed: {', '.join(sorted(TARGET_TYPES))})")
        if "platform" in node and not one_of(node["platform"], PLATFORMS):
            self.problem(f"{where}.platform `{node['platform']}` is not permitted")
        if not template and "type" not in node and not node.get("templates"):
            self.problem(f"{where} has neither a type nor a template")
        for name in self.strings(node.get("templates", []), f"{where}.templates"):
            if template or name not in template_names:
                self.problem(f"{where}.templates: `{name}` is not a target template of this spec")
        sources = node.get("sources", [])
        if not isinstance(sources, list):
            self.problem(f"{where}.sources must be a list")
            sources = []
        for number, source in enumerate(sources):
            here = f"{where}.sources[{number}]"
            if isinstance(source, dict):
                source = self.mapping(source, here, {"path", "excludes"})
                self.strings(source.get("excludes", []), f"{here}.excludes")
                source = source.get("path")
            if not one_of(source, OUTSIDE_SOURCES):
                self.inside_apps(source, here)
        dependencies = node.get("dependencies", [])
        if not isinstance(dependencies, list):
            self.problem(f"{where}.dependencies must be a list")
            dependencies = []
        for number, dependency in enumerate(dependencies):
            here = f"{where}.dependencies[{number}]"
            dependency = self.mapping(dependency, here)
            if set(dependency) in ({"target"}, {"target", "embed"}):
                if not one_of(dependency["target"], target_names):
                    self.problem(f"{here}.target `{dependency['target']}` is not a target of this spec")
                if not one_of(dependency.get("embed", "true"), ("true", "false")):
                    self.problem(f"{here}.embed must be true or false")
            elif set(dependency) == {"package", "product"}:
                product = dependency["product"]
                if dependency["package"] != "Watchword":
                    self.problem(f"{here}.package: only the repository's own package, Watchword, may be linked")
                if not isinstance(product, str) or not PRODUCT.fullmatch(product) or product == "WatchwordTestSupport":
                    self.problem(
                        f"{here}.product `{product}` is not a product an app may link (SecureMemory or a Watchword "
                        "module; never swift-crypto's own products, and never WatchwordTestSupport)"
                    )
            else:
                self.problem(
                    f"{here} must be `target:` (with `embed:`) or `package: Watchword` with `product:`; frameworks, "
                    "SDKs, Carthage and bundles are not permitted"
                )
        if "settings" in node:
            self.settings(node["settings"], f"{where}.settings", TARGET_SETTINGS, TARGET_SETTING_PREFIXES)
        for key in ("info", "entitlements"):
            if key in node:
                generated = self.mapping(node[key], f"{where}.{key}", {"path", "properties"})
                self.inside_apps(generated.get("path"), f"{where}.{key}.path")
                self.mapping(generated.get("properties", {}), f"{where}.{key}.properties")

    def scheme(self, node, where, target_names):
        node = self.mapping(node, where, SCHEME_KEYS)
        build = self.mapping(node.get("build", {}), f"{where}.build", {"targets"})
        for name, actions in self.mapping(build.get("targets", {}), f"{where}.build.targets").items():
            if name not in target_names:
                self.problem(f"{where}.build.targets.{name} is not a target of this spec")
            if actions != "all" and not (isinstance(actions, list) and all(one_of(a, BUILD_ACTIONS) for a in actions)):
                self.problem(f"{where}.build.targets.{name} must be `all` or a list of build actions")
        for action, allowed in (("run", {"config"}), ("test", {"config", "targets"})):
            if action not in node:
                continue
            settings = self.mapping(node[action], f"{where}.{action}", allowed)
            if not one_of(settings.get("config", "Debug"), CONFIGURATIONS):
                self.problem(f"{where}.{action}.config must be Debug or Release")
            for name in self.strings(settings.get("targets", []), f"{where}.{action}.targets"):
                if name not in target_names:
                    self.problem(f"{where}.{action}.targets: `{name}` is not a target of this spec")

    def audit(self, document):
        document = self.mapping(document, "the spec", ROOT_KEYS)
        self.no_expansion(document, "")
        if not isinstance(document.get("name"), str):
            self.problem("name must be a string")
        options = self.mapping(document.get("options", {}), "options", OPTION_KEYS)
        for platform, version in self.mapping(options.get("deploymentTarget", {}), "options.deploymentTarget").items():
            if platform not in PLATFORMS or not isinstance(version, str):
                self.problem(f"options.deploymentTarget.{platform} is not permitted")
        for key in OPTION_KEYS - {"deploymentTarget"}:
            if key in options and not isinstance(options[key], str):
                self.problem(f"options.{key} must be a single value")
        self.settings(
            document.get("settings"), "settings", PROJECT_SETTINGS, PROJECT_SETTING_PREFIXES, REQUIRED_PROJECT_SETTINGS
        )
        if document.get("packages") != {"Watchword": {"path": ".."}}:
            self.problem(
                "packages must be exactly `Watchword: {path: ..}` in block style: the repository's own package and no "
                "other, local or remote (a new dependency needs an ADR; docs/07-supply-chain.md)"
            )
        templates = self.mapping(document.get("targetTemplates", {}), "targetTemplates")
        targets = self.mapping(document.get("targets", {}), "targets")
        if not targets:
            self.problem("targets is empty")
        for name, template in templates.items():
            self.target(template, f"targetTemplates.{name}", set(targets), set(templates), True)
        for name, target in targets.items():
            self.target(target, f"targets.{name}", set(targets), set(templates), False)
        for name, scheme in self.mapping(document.get("schemes", {}), "schemes").items():
            self.scheme(scheme, f"schemes.{name}", set(targets))
        return self.problems


def audit_app_spec(path):
    try:
        document = load(path)
    except (Refused, UnicodeDecodeError) as refusal:
        return [f"::error file={path}::{refusal} (yaml-audit.py reads a subset of YAML and refuses the rest)"], ""
    return SpecAudit(path).audit(document), f"{path}: nothing beyond what yaml-audit.py allows."


def main(arguments):
    if len(arguments) == 2 and arguments[0] == "dump":
        try:
            json.dump(load(arguments[1]), sys.stdout)
        except (Refused, UnicodeDecodeError) as refusal:
            print(f"::error file={arguments[1]}::{refusal}")
            return 1
        return 0
    if arguments[:1] == ["actions"] and len(arguments) <= 2:
        problems, summary = audit_actions(arguments[1] if len(arguments) == 2 else ".github")
    elif len(arguments) == 2 and arguments[0] == "app-spec":
        problems, summary = audit_app_spec(arguments[1])
    else:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    for problem in problems:
        print(problem)
    if problems:
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
