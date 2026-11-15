# Turns the attachments `xcrun xcresulttool export attachments` wrote for one screenshot-tour run into a directory of
# named PNGs with an index. Run by `app:screenshots` (not a task: mise runs only executable files); standard library
# only, plus macOS's `sips` for the blank check and the text previews, which are skipped where it is missing.
#
#   <output>/<NN-name>.png   one per screen, numbered in the order the tour captured them
#   <output>/index.md        the list, which the task also appends to a GitHub job summary
#   <output>/index.html      a contact sheet whose images are the files beside it
#   <standalone>             the same sheet with the images embedded, so the one file opens anywhere
#
# The tour says what to expect: its `screens-index` attachment lists every screen it captured, `name<TAB>caption`
# per line. Exit 1 if that list is absent (the tour did not finish), if a listed screen has no PNG, or if a PNG is
# not a PNG or is one flat colour. Everything in the export comes from a test run, so it is treated as input, not
# as trusted text: names must match NAME before they become file names, captions are length-limited and escaped,
# and nothing is read outside the export directory.
import argparse
import base64
import html
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

NAME = re.compile(r"[0-9]{2}-[a-z0-9]+(?:-[a-z0-9]+)*")
INDEX_LABEL = "screens-index"
# xcresulttool names an exported attachment `<name>_<n>_<UUID>.<ext>`.
SUGGESTED = re.compile(r"(?P<label>.+)_[0-9]+_[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_SCREENS = 200
MAX_INDEX_BYTES = 64 * 1024
MAX_PNG_BYTES = 64 * 1024 * 1024
RAMP = " .:-=+*#%@"


def fail(message):
    print(f"::error::{message}")
    sys.exit(1)


def one_line(text, limit):
    """Printable, single-line, length-limited: what a caption or a source description may contribute."""
    cleaned = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(cleaned.split())[:limit]


def markdown_text(text):
    """Text for a Markdown table cell or heading: no markup of its own, whatever the run put in it."""
    return re.sub(r"([\\`*_\[\]()|#~])", r"\\\1", html.escape(text, quote=False))


def load_manifest(export_dir):
    """[(label, extension, path, timestamp)] for every exported attachment that is a plain file in export_dir."""
    path = os.path.join(export_dir, "manifest.json")
    try:
        with open(path, encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, ValueError) as error:
        fail(f"cannot read {path}: {error}")
    found = []
    tests = manifest if isinstance(manifest, list) else []
    for test in tests:
        attachments = test.get("attachments", []) if isinstance(test, dict) else []
        for attachment in attachments if isinstance(attachments, list) else []:
            if not isinstance(attachment, dict):
                continue
            exported = attachment.get("exportedFileName")
            suggested = attachment.get("suggestedHumanReadableName")
            if not isinstance(exported, str) or not isinstance(suggested, str):
                continue
            if os.path.basename(exported) != exported or exported in ("", ".", ".."):
                continue
            file_path = os.path.join(export_dir, exported)
            if os.path.islink(file_path) or not os.path.isfile(file_path):
                continue
            stem, extension = os.path.splitext(suggested)
            match = SUGGESTED.fullmatch(stem)
            label = match.group("label") if match else stem
            timestamp = attachment.get("timestamp")
            found.append((label, extension.lower(), file_path, timestamp if isinstance(timestamp, (int, float)) else 0))
    return found


def expected_screens(attachments):
    """[(name, caption)] from the tour's index attachment; the longest one if several tours attached theirs."""
    indexes = [path for label, _, path, _ in attachments if label == INDEX_LABEL]
    if not indexes:
        fail(
            "the result bundle has no screens-index attachment: the screenshot tour did not finish, "
            "so the set would be incomplete (its failure is in the xcodebuild output above)"
        )
    best = []
    for path in indexes:
        if os.path.getsize(path) > MAX_INDEX_BYTES:
            fail(f"the screens index is larger than {MAX_INDEX_BYTES} bytes")
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = [line.rstrip("\r\n") for line in handle if line.strip()]
        if len(lines) > len(best):
            best = lines
    if not best or len(best) > MAX_SCREENS:
        fail(f"the screens index lists {len(best)} screens; expected between 1 and {MAX_SCREENS}")
    screens, seen = [], set()
    for line in best:
        name, _, caption = line.partition("\t")
        if not NAME.fullmatch(name) or len(name) > 64 or name in seen:
            fail(f"the screens index has an unusable or repeated name: {name!r}")
        seen.add(name)
        screens.append((name, one_line(caption, 200)))
    return screens


def png_size(path):
    """(width, height) from the IHDR chunk, or None if the file is not a PNG."""
    try:
        with open(path, "rb") as handle:
            header = handle.read(24)
    except OSError:
        return None
    if len(header) < 24 or header[:8] != PNG_SIGNATURE or header[12:16] != b"IHDR":
        return None
    width, height = struct.unpack(">II", header[16:24])
    if not (0 < width <= 20000 and 0 < height <= 20000):
        return None
    return width, height


def read_bmp(path):
    """Rows of 0-255 luminance, top row first, from an uncompressed 24- or 32-bit BMP; None for anything else."""
    with open(path, "rb") as handle:
        data = handle.read(1 << 20)
    if len(data) < 54 or data[:2] != b"BM":
        return None
    offset, header_size, width, height, _, bits, compression = struct.unpack_from("<IIiiHHI", data, 10)
    if header_size < 40 or bits not in (24, 32) or compression not in (0, 3) or width <= 0 or height == 0:
        return None
    step = bits // 8
    stride = (width * step + 3) & ~3
    count = abs(height)
    if count > 400 or width > 400 or offset + stride * count > len(data):
        return None
    rows = []
    for index in range(count):
        start = offset + stride * index
        row = [
            (114 * data[start + x * step] + 587 * data[start + x * step + 1] + 299 * data[start + x * step + 2]) // 1000
            for x in range(width)
        ]
        rows.append(row)
    if height > 0:
        rows.reverse()  # a positive height means the bottom row is stored first
    return rows


def luminance_grid(path, size):
    """A coarse grid of the picture's luminance, by way of sips; None where sips is missing or says no."""
    if shutil.which("sips") is None:
        return None
    width, height = size
    columns = 72 if width >= height else 40
    # A character cell is about twice as tall as it is wide.
    rows = max(4, min(100, round(columns * height / width / 2)))
    with tempfile.TemporaryDirectory() as scratch:
        thumbnail = os.path.join(scratch, "thumbnail.bmp")
        result = subprocess.run(
            ["sips", "-s", "format", "bmp", "-z", str(rows), str(columns), path, "--out", thumbnail],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0 or not os.path.isfile(thumbnail):
            return None
        try:
            return read_bmp(thumbnail)
        except (OSError, struct.error):
            return None


def preview(grid):
    """The grid as text: blank where the picture is its commonest shade, denser the further a cell is from it."""
    counts = {}
    for row in grid:
        for value in row:
            counts[value] = counts.get(value, 0) + 1
    background = max(counts, key=counts.get)
    lines = []
    for row in grid:
        # Shades within a few steps of the background stay blank; the square root keeps faint things visible.
        distances = (max(0, abs(value - background) - 4) for value in row)
        cells = (min(len(RAMP) - 1, int((distance / 255) ** 0.5 * len(RAMP))) for distance in distances)
        lines.append("".join(RAMP[cell] for cell in cells).rstrip())
    return lines


def sheet(title, source, screens, image_source, linked):
    """The contact sheet. No script, no remote reference; every string from the run is escaped."""
    figures = []
    for name, caption, (width, height), _ in screens:
        address = html.escape(image_source(name), quote=True)
        image = f'<img src="{address}" width="{width}" height="{height}" alt="{html.escape(name, quote=True)}">'
        if linked:  # to the full-size file beside the sheet; an embedded image has nowhere to link to
            image = f'<a href="{address}">{image}</a>'
        figures.append(
            f"<figure>{image}<figcaption><code>{html.escape(name)}</code>{html.escape(caption)}</figcaption></figure>"
        )
    return f"""<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
  body {{ font: 14px/1.4 -apple-system, system-ui, sans-serif; margin: 24px; background: #e9e9ec; color: #1c1c1e; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  p {{ margin: 0 0 20px; color: #55555a; }}
  main {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 24px; align-items: start; }}
  figure {{ margin: 0; }}
  img {{ display: block; width: 100%; height: auto; border: 1px solid #c4c4c8; background: #fff; }}
  figcaption {{ margin-top: 6px; color: #55555a; }}
  code {{ display: block; color: #1c1c1e; font-weight: 600; }}
</style>
<h1>{html.escape(title)}</h1>
<p>{len(screens)} screens, in the order the tour meets them. {html.escape(source)}</p>
<main>
{chr(10).join(figures)}
</main>
</html>
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attachments", required=True, help="directory xcresulttool exported the attachments to")
    parser.add_argument("--output", required=True, help="directory to (re)create with the PNGs and the index")
    parser.add_argument("--title", required=True)
    parser.add_argument("--source", default="", help="what the screens are of, such as a commit")
    parser.add_argument("--standalone", help="also write the contact sheet with embedded images to this file")
    parser.add_argument("--previews", action="store_true", help="print a coarse text rendering of each screen")
    parser.add_argument("--names", help="write the screen names, comma-separated, to this file")
    arguments = parser.parse_args()

    title = one_line(arguments.title, 120)
    source = one_line(arguments.source, 200)
    attachments = load_manifest(arguments.attachments)
    expected = expected_screens(attachments)

    shutil.rmtree(arguments.output, ignore_errors=True)
    os.makedirs(arguments.output)

    screens, problems, have_sips = [], [], True
    for name, caption in expected:
        candidates = [a for a in attachments if a[0] == name and a[1] == ".png"]
        if not candidates:
            problems.append(f"{name}: listed by the tour, but the result bundle has no PNG of that name")
            continue
        source_path = max(candidates, key=lambda a: a[3])[2]
        size = png_size(source_path)
        byte_count = os.path.getsize(source_path)
        if size is None or byte_count > MAX_PNG_BYTES:
            problems.append(f"{name}: not a PNG of a plausible size ({byte_count} bytes)")
            continue
        destination = os.path.join(arguments.output, f"{name}.png")
        shutil.copyfile(source_path, destination)
        grid = luminance_grid(destination, size)
        note = ""
        if grid is None:
            have_sips = False
        else:
            values = [value for row in grid for value in row]
            note = f", brightness {sum(values) / len(values) / 255:.2f}"
            if max(values) - min(values) < 8:
                problems.append(f"{name}: the picture is one flat colour, so nothing was drawn when it was taken")
        print(f"{name}  {size[0]}x{size[1]}  {byte_count // 1024} KB{note}")
        if arguments.previews and grid is not None:
            print(f"::group::{name} (text preview)")
            print("\n".join(preview(grid)))
            print("::endgroup::")
        screens.append((name, caption, size, destination))

    if not have_sips:
        print("::warning::sips is unavailable, so the pictures were not checked for being blank")

    rows = "\n".join(
        f"| {index} | `{name}` | {markdown_text(caption)} | {size[0]} × {size[1]} |"
        for index, (name, caption, size, _) in enumerate(screens, start=1)
    )
    with open(os.path.join(arguments.output, "index.md"), "w", encoding="utf-8") as handle:
        handle.write(
            f"### {markdown_text(title)}\n\n"
            f"{len(screens)} screens, in the order the tour meets them. {markdown_text(source)}\n\n"
            f"| # | Screen | Shows | Pixels |\n| --- | --- | --- | --- |\n{rows}\n"
        )
    with open(os.path.join(arguments.output, "index.html"), "w", encoding="utf-8") as handle:
        handle.write(sheet(title, source, screens, lambda name: f"{name}.png", linked=True))
    if arguments.standalone:
        embedded = {}
        for name, _, _, path in screens:
            with open(path, "rb") as handle:
                embedded[name] = "data:image/png;base64," + base64.b64encode(handle.read()).decode("ascii")
        with open(arguments.standalone, "w", encoding="utf-8") as handle:
            handle.write(sheet(title, source, screens, embedded.__getitem__, linked=False))
    if arguments.names:
        with open(arguments.names, "w", encoding="utf-8") as handle:
            handle.write(",".join(name for name, _, _, _ in screens) + "\n")

    if problems:
        for problem in problems:
            print(f"::error::{problem}")
        sys.exit(1)
    print(f"{len(screens)} screens written to {arguments.output}")


if __name__ == "__main__":
    main()
