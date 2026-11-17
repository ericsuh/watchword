"""What the script tests share: the repository's paths, made-up pictures and exports, and stand-ins for the tools the
scripts call (`gh`, `sips`, `mise`, `xcrun`), so everything runs on any machine with python3, bash and jq."""

import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import textwrap
import unittest
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "screenshots.yml")
INDEX_HELPER = os.path.join(ROOT, "mise-tasks", "app", "screenshots-index.py")
TASK = os.path.join(ROOT, "mise-tasks", "app", "screenshots")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def png(width, height, pixel):
    """An 8-bit RGB PNG whose pixel at (x, y) is pixel(x, y), written the simplest way a PNG can be."""

    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))

    rows = b"".join(b"\x00" + b"".join(bytes(pixel(x, y)) for x in range(width)) for y in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return PNG_SIGNATURE + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")


def decode_png(data):
    """(width, height, rows of RGB bytes) of a PNG written as `png` writes one: 8-bit RGB, no filtering."""
    assert data[:8] == PNG_SIGNATURE, "not a PNG"
    position, width, height, packed = 8, 0, 0, b""
    while position < len(data):
        (length,) = struct.unpack_from(">I", data, position)
        kind, body = data[position + 4 : position + 8], data[position + 8 : position + 8 + length]
        (checksum,) = struct.unpack_from(">I", data, position + 8 + length)
        assert checksum == zlib.crc32(kind + body), f"bad checksum in {kind}"
        if kind == b"IHDR":
            width, height, depth, colour, _, _, interlace = struct.unpack(">IIBBBBB", body)
            assert (depth, colour, interlace) == (8, 2, 0), "not 8-bit RGB"
        elif kind == b"IDAT":
            packed += body
        position += 12 + length
    raw = zlib.decompress(packed)
    stride = 1 + width * 3
    assert len(raw) == stride * height, "the pixel data is not the size the header says"
    rows = []
    for y in range(height):
        assert raw[y * stride] == 0, "a filtered row"
        rows.append(raw[y * stride + 1 : (y + 1) * stride])
    return width, height, rows


def screen(width=60, height=120, shade=0, dark=False):
    """A picture with something drawn in it, so a thumbnail of it is not one flat colour: light like a light
    interface, or dark like a dark one. Its top left pixel is (base + shade, base, base)."""
    base = 10 if dark else 200
    return png(width, height, lambda x, y: (base + (x + shade) % 50, base + y % 50, base))


def blank(width=60, height=120):
    return png(width, height, lambda x, y: (255, 255, 255))


# `sips -s format bmp -z <height> <width> <source> --out <target>`, as screenshots-index.py calls it: resamples a
# PNG written by `png` above (nearest pixel) into a bottom-up 24-bit BMP.
FAKE_SIPS = r'''#!/usr/bin/env python3
import struct, sys, zlib
arguments = sys.argv[1:]
assert arguments[:3] == ["-s", "format", "bmp"] and arguments[3] == "-z" and arguments[7] == "--out", arguments
height, width, source, target = int(arguments[4]), int(arguments[5]), arguments[6], arguments[8]
data = open(source, "rb").read()
if data[:8] != b"\x89PNG\r\n\x1a\n":
    sys.exit(1)
position, packed = 8, b""
while position < len(data):
    (length,) = struct.unpack_from(">I", data, position)
    kind, body = data[position + 4 : position + 8], data[position + 8 : position + 8 + length]
    if kind == b"IHDR":
        source_width, source_height = struct.unpack_from(">II", body)
    elif kind == b"IDAT":
        packed += body
    position += 12 + length
raw = zlib.decompress(packed)
stride = 1 + source_width * 3
padding = b"\x00" * (-(width * 3) % 4)
rows = []
for y in range(height - 1, -1, -1):
    start = (y * source_height // height) * stride + 1
    row = b""
    for x in range(width):
        offset = start + (x * source_width // width) * 3
        red, green, blue = raw[offset : offset + 3]
        row += bytes((blue, green, red))
    rows.append(row + padding)
pixels = b"".join(rows)
header = b"BM" + struct.pack("<IHHI", 54 + len(pixels), 0, 0, 54)
header += struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, len(pixels), 2835, 2835, 0, 0)
open(target, "wb").write(header + pixels)
'''

# `gh api [--paginate] [--method M] <path> [-F body=@file] [--jq expression]`: answers from $GH_STUB/responses.json
# (path -> JSON, or a list of pages), applies --jq with the real jq, and records every call in $GH_STUB/calls.jsonl.
FAKE_GH = r'''#!/usr/bin/env python3
import json, os, subprocess, sys
home = os.environ["GH_STUB"]
arguments = sys.argv[1:]
assert arguments[0] == "api", arguments
method, path, expression, body, paginate, rest = "GET", None, None, None, False, arguments[1:]
while rest:
    word = rest.pop(0)
    if word == "--paginate":
        paginate = True
    elif word == "--method":
        method = rest.pop(0)
    elif word == "--jq":
        expression = rest.pop(0)
    elif word == "-F":
        field = rest.pop(0)
        assert field.startswith("body=@"), field
        body = open(field[len("body=@"):], encoding="utf-8").read()
    else:
        assert path is None and not word.startswith("-"), arguments
        path = word
with open(os.path.join(home, "calls.jsonl"), "a", encoding="utf-8") as log:
    log.write(json.dumps({"method": method, "path": path, "body": body, "paginate": paginate}) + "\n")
responses = json.load(open(os.path.join(home, "responses.json"), encoding="utf-8"))
if method != "GET":
    answer = [{"html_url": "https://github.test/comment"}]
elif path not in responses:
    sys.stderr.write(f"gh: no such thing as {path} (HTTP 404)\n")
    sys.exit(1)
else:
    answer = responses[path] if isinstance(responses[path], list) and paginate else [responses[path]]
text = "".join(json.dumps(page) for page in answer)
if expression is None:
    sys.stdout.write(text)
else:
    sys.exit(subprocess.run(["jq", "-r", expression], input=text, text=True).returncode)
'''


# `curl … -w '%{redirect_url}' … <address>`, as screenshots.yml's comment job asks where an artifact is served from:
# prints what $GH_STUB/redirects.json has for the address, follows nothing, and records the call.
FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, sys
home = os.environ["GH_STUB"]
arguments = sys.argv[1:]
assert "%{redirect_url}" in arguments and "-L" not in arguments and "--location" not in arguments, arguments
address = arguments[-1]
with open(os.path.join(home, "calls.jsonl"), "a", encoding="utf-8") as log:
    log.write(json.dumps({"method": "REDIRECT", "path": address, "body": None, "paginate": False}) + "\n")
redirects = json.load(open(os.path.join(home, "redirects.json"), encoding="utf-8"))
if address not in redirects:
    sys.exit(22)
sys.stdout.write(redirects[address])
'''


def workflow_script(step_name):
    """The `run: |` block of the step so named in screenshots.yml, as the runner would hand it to bash."""
    with open(WORKFLOW, encoding="utf-8") as handle:
        lines = handle.read().split("\n")
    start = next(index for index, line in enumerate(lines) if line.strip() == f"- name: {step_name}")
    run = next(index for index in range(start, len(lines)) if lines[index].strip() == "run: |")
    indent = len(lines[run]) - len(lines[run].lstrip())
    body = []
    for line in lines[run + 1 :]:
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        body.append(line)
    return textwrap.dedent("\n".join(body)) + "\n"


class ScriptTestCase(unittest.TestCase):
    """A scratch directory with a `bin` of stand-in tools that comes first on PATH."""

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix="watchword-script-test-")
        self.addCleanup(shutil.rmtree, self.scratch, ignore_errors=True)
        self.bin = os.path.join(self.scratch, "bin")
        os.mkdir(self.bin)
        self.environment = {
            "PATH": self.bin + os.pathsep + os.environ["PATH"],
            "HOME": self.scratch,
            "LC_ALL": "C",
        }
        # What macOS's `python3` and other Xcode-provided tools need to find themselves.
        for name in ("DEVELOPER_DIR", "TMPDIR"):
            if name in os.environ:
                self.environment[name] = os.environ[name]

    def path(self, *parts):
        return os.path.join(self.scratch, *parts)

    def install(self, name, text):
        """Puts an executable stand-in called name on PATH."""
        target = os.path.join(self.bin, name)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(text.replace("#!/usr/bin/env python3", "#!" + sys.executable, 1))
        os.chmod(target, os.stat(target).st_mode | stat.S_IXUSR)
        return target

    def write(self, relative, data):
        target = self.path(relative)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb" if isinstance(data, bytes) else "w") as handle:
            handle.write(data)
        return target

    def read(self, *parts):
        with open(self.path(*parts), encoding="utf-8") as handle:
            return handle.read()

    def export(self, name, attachments):
        """A directory as `xcresulttool export attachments` writes one. attachments: [(label, extension, bytes)],
        in the order they were attached."""
        directory = self.path(name)
        os.makedirs(directory)
        listed = []
        for number, (label, extension, data) in enumerate(attachments):
            unique = f"00000000-0000-0000-0000-{number:012d}"
            exported = f"{unique}{extension}"
            with open(os.path.join(directory, exported), "wb") as handle:
                handle.write(data)
            listed.append(
                {
                    "exportedFileName": exported,
                    "suggestedHumanReadableName": f"{label}_0_{unique}{extension}",
                    "timestamp": 1000.0 + number,
                }
            )
        with open(os.path.join(directory, "manifest.json"), "w", encoding="utf-8") as handle:
            json.dump([{"testIdentifier": "ScreenshotTourTests/testTour()", "attachments": listed}], handle)
        return directory

    def run_process(self, command, **environment):
        return subprocess.run(
            command,
            cwd=self.scratch,
            env={**self.environment, **environment},
            capture_output=True,
            text=True,
            check=False,
        )


def index_attachment(*screens):
    """The tour's `screens-index` attachment for screens [(name, caption)]."""
    return ("screens-index", ".txt", "".join(f"{name}\t{caption}\n" for name, caption in screens).encode())
