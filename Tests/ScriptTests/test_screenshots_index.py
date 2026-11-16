"""mise-tasks/app/screenshots-index.py against made-up `xcresulttool export attachments` directories.

What is at stake: a set of pictures that a person audits by eye must be what it says it is. A set with a screen
missing, blank or not a picture must never be written where a complete set goes, and everything in the export is the
output of a test run, so names and captions are input to be checked, not text to be trusted."""

import importlib.util
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support  # noqa: E402

THREE = [("01-onboarding", "Choosing the password"), ("02-emergency-kit", "The kit"), ("03-item-list-empty", "Empty")]


def helper_module():
    spec = importlib.util.spec_from_file_location("screenshots_index", support.INDEX_HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ScreenshotsIndexTests(support.ScriptTestCase):
    def setUp(self):
        super().setUp()
        self.install("sips", support.FAKE_SIPS)

    def index(self, export, *extra):
        return self.run_process(
            [
                sys.executable, support.INDEX_HELPER,
                "--attachments", export,
                "--output", self.path("Screenshots", "ios"),
                "--incomplete", self.path("Screenshots", "ios-incomplete"),
                "--standalone", self.path("Screenshots", "watchword-screens-ios.png"),
                "--names", self.path("names.txt"),
                "--title", "Watchword screens: iOS simulator",
                "--source", "Commit 0123.",
                *extra,
            ]
        )  # fmt: skip

    def pictures(self, screens):
        return [(name, ".png", support.screen(shade=number * 20)) for number, (name, _) in enumerate(screens)]

    def test_complete_set_is_written_with_index_sheet_and_names(self):
        export = self.export("export", self.pictures(THREE) + [support.index_attachment(*THREE)])
        result = self.index(export)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            sorted(os.listdir(self.path("Screenshots", "ios"))),
            ["01-onboarding.png", "02-emergency-kit.png", "03-item-list-empty.png", "index.html", "index.md"],
        )
        self.assertFalse(os.path.exists(self.path("Screenshots", "ios-incomplete")))
        self.assertEqual(self.read("names.txt"), "01-onboarding,02-emergency-kit,03-item-list-empty\n")
        listing = self.read("Screenshots", "ios", "index.md")
        self.assertIn("3 screens, in the order the tour meets them.", listing)
        self.assertIn("| 2 | `02-emergency-kit` | The kit | 60 × 120 |", listing)
        self.assertNotIn("ncomplete", listing)

    def test_contact_sheet_is_one_png_holding_every_screen_under_its_name(self):
        export = self.export("export", self.pictures(THREE) + [support.index_attachment(*THREE)])
        result = self.index(export, "--previews")
        self.assertEqual(result.returncode, 0)
        self.assertIn(f"contact sheet  {24 + 3 * 84}x{24 + 120 + 28 + 24}  ", result.stdout)
        self.assertIn("::group::contact sheet (text preview)", result.stdout)
        with open(self.path("Screenshots", "watchword-screens-ios.png"), "rb") as handle:
            width, height, rows = support.decode_png(handle.read())
        # Three 60-pixel tiles and four 24-pixel gaps; one band of tile, name and gap under the top margin.
        self.assertEqual((width, height), (24 + 3 * 84, 24 + 120 + 28 + 24))
        # The first tile is the first screen, pixel for pixel, from its top left corner.
        self.assertEqual(rows[24][24 * 3 : 24 * 3 + 6], bytes((200, 200, 200, 201, 200, 200)))
        # The second screen's pattern starts 20 higher, one tile and one gap to the right.
        self.assertEqual(rows[24][(24 + 84) * 3 : (24 + 84) * 3 + 3], bytes((220, 200, 200)))
        # Under each tile, ink: the name is drawn there.
        ink = bytes((0x1C, 0x1C, 0x1E))
        band = b"".join(row[24 * 3 : (24 + 60) * 3] for row in rows[24 + 120 + 8 : 24 + 120 + 8 + 14])
        self.assertIn(ink, [band[i : i + 3] for i in range(0, len(band), 3)])

    def test_missing_picture_is_never_written_as_a_set(self):
        """Finding: a listed screen without a PNG used to leave `<set>/index.md` saying "2 screens", renumbered."""
        pictures = [picture for picture in self.pictures(THREE) if picture[0] != "02-emergency-kit"]
        export = self.export("export", pictures + [support.index_attachment(*THREE)])
        result = self.index(export)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("::error::02-emergency-kit: listed by the tour", result.stdout)
        self.assertFalse(os.path.exists(self.path("Screenshots", "ios")), "an incomplete set where a set goes")
        self.assertFalse(os.path.exists(self.path("Screenshots", "watchword-screens-ios.png")))
        self.assertFalse(os.path.exists(self.path("names.txt")), "an incomplete set was announced")
        listing = self.read("Screenshots", "ios-incomplete", "index.md")
        self.assertTrue(listing.startswith("### Incomplete: "), listing)
        self.assertIn("**This set is incomplete", listing)
        self.assertNotIn("screens, in the order the tour meets them", listing)
        # The tour's own numbering is kept, with the hole in it.
        self.assertIn("| 2 | `02-emergency-kit` | The kit | no picture | **listed by the tour", listing)
        self.assertIn("| 3 | `03-item-list-empty` | Empty | 60 × 120 |", listing)
        page = self.read("Screenshots", "ios-incomplete", "index.html")
        self.assertIn("<h1>Incomplete: ", page)
        self.assertIn("This set is incomplete", page)
        self.assertEqual(page.count("<img "), 2)

    def test_blank_and_invalid_pictures_make_the_set_incomplete(self):
        pictures = self.pictures(THREE)
        pictures[0] = ("01-onboarding", ".png", support.blank())
        pictures[2] = ("03-item-list-empty", ".png", b"<html>not a picture</html>")
        export = self.export("export", pictures + [support.index_attachment(*THREE)])
        result = self.index(export)
        self.assertEqual(result.returncode, 1)
        self.assertIn("::error::01-onboarding: the picture is one flat colour", result.stdout)
        self.assertIn("::error::03-item-list-empty: not a PNG of a plausible size", result.stdout)
        self.assertFalse(os.path.exists(self.path("Screenshots", "ios")))
        listing = self.read("Screenshots", "ios-incomplete", "index.md")
        self.assertIn("| 1 | `01-onboarding` | Choosing the password | 60 × 120 | **the picture is one flat", listing)
        self.assertFalse(os.path.exists(self.path("Screenshots", "ios-incomplete", "03-item-list-empty.png")))

    def test_tour_that_stopped_part_way_leaves_what_it_captured_under_another_name(self):
        """Finding: with no index attachment nothing was written at all, so a failed step left no picture to read."""
        attachments = self.pictures(THREE[:2]) + [
            ("Screenshot of the failure", ".png", support.screen(shade=200)),
            ("Debug description", ".txt", b"Attributes: Application"),
        ]
        result = self.index(self.export("export", attachments), "--previews")
        self.assertEqual(result.returncode, 1)
        self.assertIn("::error::the tour did not finish", result.stdout)
        self.assertFalse(os.path.exists(self.path("Screenshots", "ios")))
        self.assertFalse(os.path.exists(self.path("names.txt")))
        self.assertEqual(
            sorted(os.listdir(self.path("Screenshots", "ios-incomplete"))),
            ["01-onboarding.png", "02-emergency-kit.png", "failure-1.png", "index.html", "index.md"],
        )
        listing = self.read("Screenshots", "ios-incomplete", "index.md")
        self.assertTrue(listing.startswith("### Incomplete: "))
        self.assertIn("the tour did not finish", listing)
        self.assertIn("| – | `failure-1` | Screenshot of the failure |", listing)
        # The log shows the last screen reached and the failure, which is what there is to go on.
        self.assertNotIn("::group::01-onboarding", result.stdout)
        self.assertIn("::group::02-emergency-kit (text preview)", result.stdout)
        self.assertIn("::group::failure-1 (text preview)", result.stdout)

    def test_failed_tour_is_incomplete_even_if_it_listed_every_screen(self):
        export = self.export("export", self.pictures(THREE) + [support.index_attachment(*THREE)])
        result = self.index(export, "--tour-failed")
        self.assertEqual(result.returncode, 1)
        self.assertFalse(os.path.exists(self.path("Screenshots", "ios")))
        self.assertFalse(os.path.exists(self.path("names.txt")))
        self.assertIn("the tour's run failed", self.read("Screenshots", "ios-incomplete", "index.md"))

    def test_set_in_the_wrong_appearance_is_not_the_set_it_is_named(self):
        """Finding: the default set is named light, but the app was only ever told to be dark, so on a machine in
        Dark Mode `Screenshots/macos` held dark pictures. The app is now told either way, and a set whose pictures
        are not in the appearance asked for is refused."""
        dark = [(name, ".png", support.screen(shade=n * 20, dark=True)) for n, (name, _) in enumerate(THREE)]
        light = self.pictures(THREE)
        cases = (("a", dark, "light", False), ("b", dark, "dark", True), ("c", light, "dark", False))
        for name, pictures, asked, accepted in cases + (("d", light, "light", True),):
            with self.subTest(pictures="dark" if pictures is dark else "light", asked=asked):
                export = self.export(name, pictures + [support.index_attachment(*THREE)])
                result = self.index(export, "--appearance", asked)
                self.assertEqual(result.returncode, 0 if accepted else 1, result.stdout)
                self.assertEqual(os.path.isdir(self.path("Screenshots", "ios")), accepted)
                if not accepted:
                    self.assertIn(f"::error::the set was asked for in the {asked} appearance", result.stdout)
                    self.assertIn("the set was asked for", self.read("Screenshots", "ios-incomplete", "index.md"))

    def test_an_earlier_runs_set_does_not_survive_a_failed_one(self):
        export = self.export("export", self.pictures(THREE) + [support.index_attachment(*THREE)])
        self.assertEqual(self.index(export).returncode, 0)
        failed = self.export("failed", self.pictures(THREE[:1]))
        self.assertEqual(self.index(failed).returncode, 1)
        self.assertFalse(os.path.exists(self.path("Screenshots", "ios")))
        self.assertFalse(os.path.exists(self.path("Screenshots", "watchword-screens-ios.png")))
        self.assertFalse(os.path.exists(self.path("names.txt")))
        self.assertEqual(self.index(export).returncode, 0)
        self.assertFalse(os.path.exists(self.path("Screenshots", "ios-incomplete")))

    def test_names_the_tour_could_not_have_produced_are_refused(self):
        """A name becomes a file name, a line of a comment and a job output. `Screens.capture` allows `NN-` and 40
        characters of lower-case words, and at most 99 screens; the helper and the comment job hold to the same."""
        for name in (
            "../../etc/passwd", "01-Onboarding", "1-onboarding", "01-on--boarding", "01-onboarding-", "01-",
            "01-" + "a" * 41, "01-a b", "01-a\\b", "01-a.png",
        ):  # fmt: skip
            with self.subTest(name=name):
                export = self.export(f"export-{abs(hash(name))}", [support.index_attachment((name, ""))])
                result = self.index(export)
                self.assertEqual(result.returncode, 1)
                self.assertIn("unusable or repeated name", result.stdout)
                self.assertFalse(os.path.exists(self.path("Screenshots")))
        longest = "01-" + "a" * 40
        export = self.export("longest", [(longest, ".png", support.screen()), support.index_attachment((longest, ""))])
        self.assertEqual(self.index(export).returncode, 0)

    def test_more_screens_than_a_tour_can_capture_are_refused(self):
        hundred = [(f"{number % 100:02d}-screen-{number}", "") for number in range(100)]
        result = self.index(self.export("export", [support.index_attachment(*hundred)]))
        self.assertEqual(result.returncode, 1)
        self.assertIn("lists 100 screens", result.stdout)

    def test_captions_cannot_carry_markup(self):
        screens = [("01-onboarding", '<script>alert(1)</script> [x](http://evil) | `code` "quoted"')]
        export = self.export("export", self.pictures(screens) + [support.index_attachment(*screens)])
        self.assertEqual(self.index(export).returncode, 0)
        page = self.read("Screenshots", "ios", "index.html")
        self.assertNotIn("<script", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("default-src 'none'", page)
        listing = self.read("Screenshots", "ios", "index.md")
        self.assertNotIn("<script", listing)
        self.assertNotIn("[x](http", listing)
        self.assertNotIn(" | `code`", listing)

    def test_attachments_outside_the_export_are_not_read(self):
        outside = self.write("outside.png", support.screen())
        export = self.export("export", [support.index_attachment(*THREE[:1])])
        os.symlink(outside, os.path.join(export, "link.png"))
        manifest = [
            {
                "attachments": [
                    {"exportedFileName": "../outside.png", "suggestedHumanReadableName": "01-onboarding.png"},
                    {"exportedFileName": "link.png", "suggestedHumanReadableName": "01-onboarding.png"},
                    {"exportedFileName": "00000000-0000-0000-0000-000000000000.txt",
                     "suggestedHumanReadableName": "screens-index.txt"},
                ]
            }
        ]  # fmt: skip
        import json

        with open(os.path.join(export, "manifest.json"), "w", encoding="utf-8") as handle:
            json.dump(manifest, handle)
        result = self.index(export)
        self.assertEqual(result.returncode, 1)
        self.assertIn("01-onboarding: listed by the tour, but the result bundle has no PNG", result.stdout)

    def test_without_sips_the_set_is_written_and_the_missing_checks_are_said(self):
        os.remove(os.path.join(self.bin, "sips"))
        export = self.export("export", self.pictures(THREE) + [support.index_attachment(*THREE)])
        result = self.run_process(
            [sys.executable, support.INDEX_HELPER, "--attachments", export, "--output", self.path("out"),
             "--standalone", self.path("sheet.png"), "--title", "t"],
            PATH=self.bin,
        )  # fmt: skip
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("::warning::sips is unavailable", result.stdout)
        self.assertIn("::warning::no one-picture contact sheet", result.stdout)
        self.assertFalse(os.path.exists(self.path("sheet.png")))


class BitmapTests(support.ScriptTestCase):
    """The reader of what sips writes. A wrong guess about byte order would tint every thumbnail."""

    def bitmap(self, bits, compression, pixels, width, height, masks=b""):
        offset = 54 + len(masks)
        header = b"BM" + struct.pack("<IHHI", offset + len(pixels), 0, 0, offset)
        header += struct.pack("<IiiHHIIiiII", 40, width, height, 1, bits, compression, len(pixels), 0, 0, 0, 0)
        return self.write("picture.bmp", header + masks + pixels)

    def test_24_bit_rows_are_bottom_up_blue_first_and_padded(self):
        # Two rows of one pixel, stored bottom row first, each padded to four bytes.
        path = self.bitmap(24, 0, bytes((3, 2, 1, 0)) + bytes((30, 20, 10, 0)), 1, 2)
        self.assertEqual(helper_module().read_bmp(path), (1, 2, [bytes((10, 20, 30)), bytes((1, 2, 3))]))

    def test_top_down_32_bit_with_masks_and_transparency(self):
        # Masks say red is the first byte; the second pixel is fully transparent, so it is drawn on white.
        masks = struct.pack("<III", 0x000000FF, 0x0000FF00, 0x00FF0000)
        path = self.bitmap(32, 3, bytes((10, 20, 30, 255)) + bytes((0, 0, 0, 0)), 2, -1, masks)
        self.assertEqual(helper_module().read_bmp(path), (2, 1, [bytes((10, 20, 30, 255, 255, 255))]))

    def test_an_unused_fourth_byte_is_not_transparency(self):
        path = self.bitmap(32, 0, bytes((3, 2, 1, 0)), 1, 1)
        self.assertEqual(helper_module().read_bmp(path), (1, 1, [bytes((1, 2, 3))]))

    def test_truncated_compressed_or_oversized_bitmaps_are_refused(self):
        module = helper_module()
        self.assertIsNone(module.read_bmp(self.bitmap(24, 0, bytes(4), 1, 2)))  # one row short
        self.assertIsNone(module.read_bmp(self.bitmap(24, 1, bytes(8), 1, 2)))  # run-length encoded
        self.assertIsNone(module.read_bmp(self.bitmap(8, 0, bytes(8), 1, 2)))  # palette
        self.assertIsNone(module.read_bmp(self.bitmap(24, 0, bytes(8), 5000, 1)))  # wider than any thumbnail
        self.assertIsNone(module.read_bmp(self.write("short.bmp", b"BM")))


if __name__ == "__main__":
    unittest.main()
