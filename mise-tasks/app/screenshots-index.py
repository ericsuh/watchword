# Turns the attachments `xcrun xcresulttool export attachments` wrote for one screenshot-tour run into a directory of
# named PNGs with an index. Run by `app:screenshots` (not a task: mise runs only executable files); standard library
# only, plus macOS's `sips` for the blank check, the text previews and the one-picture contact sheet, which are
# skipped where it is missing. `mise run test:scripts` runs it against made-up exports (Tests/ScriptTests).
#
# A complete set goes to <output>:
#   <output>/<NN-name>.png   one per screen, numbered in the order the tour captured them
#   <output>/index.md        the list, which the task also appends to a GitHub job summary
#   <output>/index.html      a contact sheet whose images are the files beside it
#   <standalone>             every screen in one PNG, each under its name: the one file that opens anywhere
#   <names>                  the screen names, comma-separated, for screenshots.yml's comment
#
# The tour says what to expect: its `screens-index` attachment lists every screen it captured, `name<TAB>caption`
# per line. A set is complete only if that list is present, every screen on it has a PNG that is a PNG and is not
# one flat colour, and the pictures are in the appearance (light or dark) the set was asked for, if one was. Anything
# less is never written to <output>, so nothing that looks like a set can be an
# incomplete one. It goes to <incomplete> instead, for whoever has to work out what went wrong: the pictures there
# are, an index.md and index.html that begin by saying what is missing and keep the tour's own numbering, and, when
# the tour stopped part way, XCUITest's own screenshots of the failure. The exit status is then 1.
#
# Everything in the export comes from a test run, so it is treated as input, not as trusted text: names must match
# NAME before they become file names, captions are length-limited and escaped, and nothing is read outside the
# export directory.
import argparse
import html
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

# `NN-` and at most 40 characters of lower-case words joined by hyphens: what `Screens.capture` accepts, and what
# screenshots.yml's comment job checks again.
NAME = re.compile(r"[0-9]{2}-(?=[a-z0-9-]{1,40}\Z)[a-z0-9]+(?:-[a-z0-9]+)*")
INDEX_LABEL = "screens-index"
# xcresulttool names an exported attachment `<name>_<n>_<UUID>.<ext>`.
SUGGESTED = re.compile(r"(?P<label>.+)_[0-9]+_[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_SCREENS = 99
MAX_FAILURE_PICTURES = 6
MAX_INDEX_BYTES = 64 * 1024
MAX_PNG_BYTES = 64 * 1024 * 1024
MAX_BMP_BYTES = 16 * 1024 * 1024
RAMP = " .:-=+*#%@"

# The contact sheet: thumbnails this wide, in as many columns as fit SHEET_WIDTH, on the HTML sheet's colours.
PORTRAIT_TILE, LANDSCAPE_TILE, SHEET_WIDTH, SHEET_GAP = 420, 840, 2600, 24
MAX_SHEET_PIXELS = 48 * 1000 * 1000
BACKGROUND, BORDER, INK = b"\xe9\xe9\xec", b"\xc4\xc4\xc8", b"\x1c\x1c\x1e"
# A 5-by-7 face for exactly the characters a screen name may hold, so a tile can carry its name without a font
# file or a drawing library: seven rows per glyph, two hex digits each, the low five bits left to right.
GLYPHS = {
    "0": "0e11131519110e", "1": "040c040404040e", "2": "0e11010204081f", "3": "1f02040201110e",
    "4": "02060a121f0202", "5": "1f101e0101110e", "6": "0608101e11110e", "7": "1f010204080808",
    "8": "0e11110e11110e", "9": "0e11110f01020c", "a": "00000e010f110f", "b": "1010161911111e",
    "c": "00000e1010110e", "d": "01010d1311110f", "e": "00000e111f100e", "f": "0609081c080808",
    "g": "000f11110f010e", "h": "10101619111111", "i": "04000c0404040e", "j": "0200060202120c",
    "k": "10101214181412", "l": "0c04040404040e", "m": "00001a15151111", "n": "00001619111111",
    "o": "00000e1111110e", "p": "001e11111e1010", "q": "000f11110f0101", "r": "00001619101010",
    "s": "00000f100e011e", "t": "08081c08080906", "u": "0000111111130d", "v": "00001111110a04",
    "w": "0000111115150a", "x": "0000110a040a11", "y": "001111110f010e", "z": "00001f0204081f",
    "-": "0000001f000000",
}


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


def listed_screens(attachments):
    """[(name, caption)] from the tour's index attachment, the longest one if several tours attached theirs; None
    if there is no index, which is a tour that stopped part way. An index that cannot be used is a hard failure."""
    indexes = [path for label, _, path, _ in attachments if label == INDEX_LABEL]
    if not indexes:
        return None
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
        if not NAME.fullmatch(name) or name in seen:
            fail(f"the screens index has an unusable or repeated name: {name!r}")
        seen.add(name)
        screens.append((name, one_line(caption, 200)))
    return screens


def png_size(path):
    """(width, height) from the IHDR chunk, or None if the file is not a PNG of a plausible size."""
    try:
        if os.path.getsize(path) > MAX_PNG_BYTES:
            return None
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
    """(width, height, rows) from an uncompressed 24- or 32-bit BMP, each row `width` RGB triples as bytes, top row
    first; None for anything else. Transparent pixels (a Mac window's rounded corners) are put on white."""
    try:
        if os.path.getsize(path) > MAX_BMP_BYTES:
            return None
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    if len(data) < 54 or data[:2] != b"BM":
        return None
    offset, header_size, width, height, _, bits, compression = struct.unpack_from("<IIiiHHI", data, 10)
    if header_size < 40 or bits not in (24, 32) or compression not in (0, 3) or width <= 0 or height == 0:
        return None
    step = bits // 8
    red, green, blue, alpha = 2, 1, 0, 3  # the order an uncompressed BMP stores a pixel in
    if compression == 3:  # the header says which byte is which
        if len(data) < 66:
            return None
        places = {0x000000FF: 0, 0x0000FF00: 1, 0x00FF0000: 2, 0xFF000000: 3}
        masks = struct.unpack_from("<III", data, 54)
        if any(mask not in places for mask in masks) or len(set(masks)) != 3:
            return None
        red, green, blue = (places[mask] for mask in masks)
        alpha = ({0, 1, 2, 3} - {red, green, blue}).pop()
        if max(red, green, blue) >= step:
            return None
    stride = (width * step + 3) & ~3
    count = abs(height)
    if width > 4096 or count > 16384 or offset < 54 or offset + stride * count > len(data):
        return None
    lines = [data[offset + stride * index : offset + stride * index + width * step] for index in range(count)]
    # The fourth byte is transparency only if something in the picture uses it.
    see_through = step == 4 and any(max(line[alpha::4]) > 0 for line in lines)
    rows = []
    for line in lines:
        row = bytearray(width * 3)
        row[0::3], row[1::3], row[2::3] = line[red::step], line[green::step], line[blue::step]
        if see_through and min(line[alpha::4]) < 255:
            for x, opacity in enumerate(line[alpha::4]):
                if opacity < 255:
                    for channel in range(3):
                        value = row[x * 3 + channel]
                        row[x * 3 + channel] = (value * opacity + 255 * (255 - opacity)) // 255
        rows.append(bytes(row))
    if height > 0:
        rows.reverse()  # a positive height means the bottom row is stored first
    return width, count, rows


def thumbnail(path, width, height):
    """The picture resampled to width by height, as read_bmp gives it, by way of sips; None where sips is missing
    or says no."""
    if shutil.which("sips") is None:
        return None
    with tempfile.TemporaryDirectory() as scratch:
        target = os.path.join(scratch, "thumbnail.bmp")
        result = subprocess.run(
            ["sips", "-s", "format", "bmp", "-z", str(height), str(width), path, "--out", target],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0 or not os.path.isfile(target):
            return None
        try:
            found = read_bmp(target)
        except (OSError, struct.error, ValueError):
            return None
    if found is None or (found[0], found[1]) != (width, height):
        return None
    return found


def luminance_grid(path, size):
    """A coarse grid of the picture's luminance, 0 to 255; None where it could not be made."""
    width, height = size
    columns = 72 if width >= height else 40
    # A character cell is about twice as tall as it is wide.
    found = thumbnail(path, columns, max(4, min(100, round(columns * height / width / 2))))
    if found is None:
        return None
    return [
        [(299 * row[x] + 587 * row[x + 1] + 114 * row[x + 2]) // 1000 for x in range(0, len(row), 3)]
        for row in found[2]
    ]


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


def png_bytes(width, rows):
    """An 8-bit RGB PNG of rows, each `width` RGB triples."""

    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))

    scanlines = b"".join(b"\x00" + bytes(row) for row in rows)  # filter 0: each row as it is
    header = struct.pack(">IIBBBBB", width, len(rows), 8, 2, 0, 0, 0)
    return PNG_SIGNATURE + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(scanlines, 6)) + chunk(b"IEND", b"")


def draw_name(canvas, left, top, name, room):
    """Writes a screen name on the canvas at twice the face's size, or at its own size if that is all there is
    room for; a name too long even for that is cut."""
    scale = 2 if len(name) * 6 * 2 <= room else 1
    for index, character in enumerate(name[: max(1, room // (6 * scale))]):
        glyph = bytes.fromhex(GLYPHS.get(character, GLYPHS["-"]))
        for row, bits in enumerate(glyph):
            for column in range(5):
                if bits >> (4 - column) & 1:
                    x = left + (index * 6 + column) * scale
                    for y in range(top + row * scale, top + (row + 1) * scale):
                        canvas[y][x * 3 : (x + scale) * 3] = INK * scale


def contact_sheet(tiles):
    """Every tile (name, width, height, rows) on one canvas, in rows of equal columns, each over its name. Returns
    (width, rows) for png_bytes, or None if the sheet would be implausibly large."""
    cell = max(width for _, width, _, _ in tiles)
    columns = max(1, min(len(tiles), (SHEET_WIDTH - SHEET_GAP) // (cell + SHEET_GAP)))
    label = 7 * 2 + 14  # the name, at twice the face's size, and the space around it
    bands = [tiles[start : start + columns] for start in range(0, len(tiles), columns)]
    sheet_width = SHEET_GAP + columns * (cell + SHEET_GAP)
    sheet_height = SHEET_GAP + sum(max(height for _, _, height, _ in band) + label + SHEET_GAP for band in bands)
    if sheet_width * sheet_height > MAX_SHEET_PIXELS:
        return None
    canvas = [bytearray(BACKGROUND * sheet_width) for _ in range(sheet_height)]
    top = SHEET_GAP
    for band in bands:
        for column, (name, width, height, rows) in enumerate(band):
            left = SHEET_GAP + column * (cell + SHEET_GAP)
            for y in (top - 1, top + height):
                canvas[y][(left - 1) * 3 : (left + width + 1) * 3] = BORDER * (width + 2)
            for y, row in enumerate(rows, start=top):
                canvas[y][(left - 1) * 3 : (left + width + 1) * 3] = BORDER + row + BORDER
            draw_name(canvas, left, top + height + 8, name, cell)
        top += max(height for _, _, height, _ in band) + label + SHEET_GAP
    return sheet_width, canvas


def write_contact_sheet(path, screens):
    """Writes the one-picture contact sheet of screens [(name, source path, (width, height))]; False if a thumbnail
    could not be made (no sips) or the sheet would be too large."""
    tiles = []
    for name, source, (width, height) in screens:
        tile_width = min(width, LANDSCAPE_TILE if width >= height else PORTRAIT_TILE)
        found = thumbnail(source, tile_width, max(1, round(tile_width * height / width)))
        if found is None:
            return False
        tiles.append((name, *found))
    sheet = contact_sheet(tiles)
    if sheet is None:
        return False
    with open(path, "wb") as handle:
        handle.write(png_bytes(*sheet))
    return True


def page(title, source, entries, problems):
    """The HTML contact sheet over the files beside it. No script, no remote reference; every string from the run
    is escaped. An incomplete set says so before anything else."""
    figures = []
    for entry in entries:
        name, caption = html.escape(entry["name"]), html.escape(entry["caption"])
        if entry["size"] is None:
            picture = '<div class="absent">no picture</div>'
        else:
            address = html.escape(entry["file"], quote=True)
            width, height = entry["size"]
            picture = f'<a href="{address}"><img src="{address}" width="{width}" height="{height}" alt="{name}"></a>'
        note = f'<strong>{html.escape(entry["problem"])}</strong>' if entry["problem"] else ""
        figures.append(f"<figure>{picture}<figcaption><code>{name}</code>{caption}{note}</figcaption></figure>")
    pictured = sum(1 for entry in entries if entry["size"] is not None)
    if problems:
        items = "".join(f"<li>{html.escape(problem)}</li>" for problem in problems)
        heading = f"Incomplete: {html.escape(title)}"
        summary = (
            f'<div class="incomplete"><p>This set is incomplete, so it is not a record of the app\'s screens. '
            f"It holds {pictured} pictures.</p><ul>{items}</ul></div>"
        )
    else:
        heading = html.escape(title)
        summary = ""
    count = "" if problems else f"{pictured} screens, in the order the tour meets them. "
    return f"""<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{heading}</title>
<style>
  body {{ font: 14px/1.4 -apple-system, system-ui, sans-serif; margin: 24px; background: #e9e9ec; color: #1c1c1e; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  p {{ margin: 0 0 20px; color: #55555a; }}
  main {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 24px; align-items: start; }}
  figure {{ margin: 0; }}
  img {{ display: block; width: 100%; height: auto; border: 1px solid #c4c4c8; background: #fff; }}
  figcaption {{ margin-top: 6px; color: #55555a; }}
  code, strong {{ display: block; color: #1c1c1e; font-weight: 600; }}
  .incomplete {{ border: 3px solid #b3261e; background: #fff; padding: 12px 16px; margin: 0 0 20px; }}
  .incomplete p, .incomplete li, strong {{ color: #b3261e; font-weight: 600; margin: 0; }}
  .absent {{ border: 1px dashed #b3261e; padding: 60px 0; text-align: center; color: #b3261e; }}
</style>
<h1>{heading}</h1>
{summary}<p>{count}{html.escape(source)}</p>
<main>
{chr(10).join(figures)}
</main>
</html>
"""


def listing(title, source, entries, problems):
    """index.md: the table of screens, under a heading that says first if the set is incomplete."""
    if not problems:
        rows = "\n".join(
            f"| {entry['position']} | `{entry['name']}` | {markdown_text(entry['caption'])} "
            f"| {entry['size'][0]} × {entry['size'][1]} |"
            for entry in entries
        )
        return (
            f"### {markdown_text(title)}\n\n"
            f"{len(entries)} screens, in the order the tour meets them. {markdown_text(source)}\n\n"
            f"| # | Screen | Shows | Pixels |\n| --- | --- | --- | --- |\n{rows}\n"
        )
    rows = "\n".join(
        f"| {entry['position']} | `{entry['name']}` | {markdown_text(entry['caption'])} "
        f"| {'%d × %d' % entry['size'] if entry['size'] else 'no picture'} "
        f"| {'**' + markdown_text(entry['problem']) + '**' if entry['problem'] else ''} |"
        for entry in entries
    )
    reasons = "\n".join(f"- {markdown_text(problem)}" for problem in problems)
    return (
        f"### Incomplete: {markdown_text(title)}\n\n"
        f"**This set is incomplete, so it is not a record of the app's screens.** {markdown_text(source)}\n\n"
        f"{reasons}\n\n"
        f"| # | Screen | Shows | Pixels | Problem |\n| --- | --- | --- | --- | --- |\n{rows}\n"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attachments", required=True, help="directory xcresulttool exported the attachments to")
    parser.add_argument("--output", required=True, help="directory to (re)create with a complete set")
    parser.add_argument("--incomplete", help="directory to (re)create with what there is of an incomplete set")
    parser.add_argument("--title", required=True)
    parser.add_argument("--source", default="", help="what the screens are of, such as a commit")
    parser.add_argument("--standalone", help="also write a complete set's one-picture contact sheet to this PNG")
    parser.add_argument("--previews", action="store_true", help="print a coarse text rendering of each screen")
    parser.add_argument("--names", help="write a complete set's screen names, comma-separated, to this file")
    parser.add_argument("--tour-failed", action="store_true", help="the tour's run failed: no set is complete")
    parser.add_argument("--appearance", choices=["light", "dark"], help="the appearance the set was asked for")
    arguments = parser.parse_args()

    title = one_line(arguments.title, 120)
    source = one_line(arguments.source, 200)
    attachments = load_manifest(arguments.attachments)
    pictures = [attachment for attachment in attachments if attachment[1] == ".png"]

    # Nothing an earlier run wrote may stand in for this one's.
    for stale in (arguments.output, arguments.incomplete):
        if stale:
            shutil.rmtree(stale, ignore_errors=True)
    for stale in (arguments.standalone, arguments.names):
        if stale and os.path.lexists(stale):
            os.remove(stale)

    problems, extras = [], []
    listed = listed_screens(attachments)
    finished = listed is not None
    if finished and arguments.tour_failed:
        problems.append("the tour's run failed although it listed its screens; the failure is in the xcodebuild output")
    if not finished:
        problems.append(
            "the tour did not finish (the result bundle has no screens-index attachment), so these are only the "
            "screens it captured before it stopped; its failure is in the xcodebuild output"
        )
        captured = sorted({label for label, _, _, _ in pictures if NAME.fullmatch(label)})
        listed = [(name, "") for name in captured[:MAX_SCREENS]]
        # XCUITest's own pictures of the moment it failed, oldest first.
        others = sorted((p for p in pictures if not NAME.fullmatch(p[0])), key=lambda p: p[3])
        extras = [(f"failure-{n}", one_line(p[0], 120), p[2]) for n, p in enumerate(others[-MAX_FAILURE_PICTURES:], 1)]

    entries, have_sips, brightness = [], True, []
    for position, (name, caption) in enumerate(listed, start=1):
        entry = {"position": position, "name": name, "caption": caption, "file": f"{name}.png"}
        entry.update(size=None, source=None, problem=None, grid=None)
        entries.append(entry)
        candidates = [picture for picture in pictures if picture[0] == name]
        if not candidates:
            entry["problem"] = "listed by the tour, but the result bundle has no PNG of that name"
            continue
        candidate = max(candidates, key=lambda picture: picture[3])[2]
        size = png_size(candidate)
        if size is None:
            entry["problem"] = f"not a PNG of a plausible size ({os.path.getsize(candidate)} bytes)"
            continue
        entry.update(size=size, source=candidate, grid=luminance_grid(candidate, size))
        note = ""
        if entry["grid"] is None:
            have_sips = False
        else:
            values = [value for row in entry["grid"] for value in row]
            brightness.append(sum(values) / len(values) / 255)
            note = f", brightness {brightness[-1]:.2f}"
            if max(values) - min(values) < 8:
                entry["problem"] = "the picture is one flat colour, so nothing was drawn when it was taken"
        print(f"{name}  {size[0]}x{size[1]}  {os.path.getsize(candidate) // 1024} KB{note}")
    problems += [f"{entry['name']}: {entry['problem']}" for entry in entries if entry["problem"]]
    # A light interface is mostly light and a dark one mostly dark, so the middle picture of the set tells them
    # apart: a set that follows the machine's appearance instead of the one asked for is not the set it is named.
    if arguments.appearance and brightness:
        middle = sorted(brightness)[len(brightness) // 2]
        if (middle < 0.5) != (arguments.appearance == "dark"):
            problems.append(
                f"the set was asked for in the {arguments.appearance} appearance, but its pictures are "
                f"{'dark' if middle < 0.5 else 'light'} (brightness {middle:.2f}): the app followed the machine's"
            )
    last_captured = [entry for entry in entries if entry["grid"] is not None][-1:]
    failures = []
    for name, caption, candidate in extras:
        size = png_size(candidate)
        if size is not None:
            entry = {"position": "–", "name": name, "caption": caption, "file": f"{name}.png", "problem": None}
            entry.update(size=size, source=candidate, grid=luminance_grid(candidate, size))
            failures.append(entry)
    entries += failures

    if not have_sips:
        print("::warning::sips is unavailable, so the pictures were not checked for being blank")
    if arguments.previews:
        # Of a tour that stopped, the last screen it captured and the failure are what there is to read.
        for entry in entries if finished else last_captured + failures:
            if entry["grid"] is not None:
                print(f"::group::{entry['name']} (text preview)")
                print("\n".join(preview(entry["grid"])))
                print("::endgroup::")

    directory = arguments.incomplete if problems else arguments.output
    if directory:
        os.makedirs(directory)
        for entry in entries:
            if entry["source"] is not None:
                shutil.copyfile(entry["source"], os.path.join(directory, entry["file"]))
        with open(os.path.join(directory, "index.md"), "w", encoding="utf-8") as handle:
            handle.write(listing(title, source, entries, problems))
        with open(os.path.join(directory, "index.html"), "w", encoding="utf-8") as handle:
            handle.write(page(title, source, entries, problems))

    if problems:
        for problem in problems:
            print(f"::error::{problem}")
        if directory:
            print(f"The set is incomplete; what there is of it is in {directory}")
        sys.exit(1)

    if arguments.standalone:
        screens = [(entry["name"], entry["source"], entry["size"]) for entry in entries]
        if not write_contact_sheet(arguments.standalone, screens):
            print("::warning::no one-picture contact sheet was written (sips is unavailable, or it would be too large)")
    if arguments.names:
        with open(arguments.names, "w", encoding="utf-8") as handle:
            handle.write(",".join(entry["name"] for entry in entries) + "\n")
    print(f"{len(entries)} screens written to {arguments.output}")


if __name__ == "__main__":
    main()
