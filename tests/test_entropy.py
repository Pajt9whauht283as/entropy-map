"""Tests: python -m unittest discover -s tests -v"""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from entropymap import binformats, png, report, scan, strings  # noqa: E402
from entropymap.carve import carve as carve_files  # noqa: E402


def _minimal_pe() -> bytes:
    blob = bytearray(0x400)
    blob[0:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, 0x40)
    blob[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HH", blob, 0x44, 0x8664, 1)        # machine, sections
    struct.pack_into("<H", blob, 0x44 + 16, 0)            # optional header size
    table = 0x44 + 20
    name = b".text\x00\x00\x00"
    blob[table:table + 8] = name
    struct.pack_into("<IIII", blob, table + 8, 0x100, 0x1000, 0x100, 0x200)
    struct.pack_into("<I", blob, table + 36, 0x60000020)
    blob[0x200:0x300] = bytes(range(256))
    return bytes(blob)


class TestEntropy(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(scan.shannon(b""), 0.0)

    def test_zeros(self):
        self.assertEqual(scan.shannon(b"\x00" * 4096), 0.0)

    def test_uniform(self):
        self.assertAlmostEqual(scan.shannon(bytes(range(256))), 8.0, places=6)

    def test_half(self):
        value = scan.shannon(b"\x00" * 2048 + b"\xff" * 2048)
        self.assertAlmostEqual(value, 1.0, places=6)

    def test_chi_square(self):
        self.assertLess(scan.chi_square(bytes(range(256))), 1.0)
        self.assertGreater(scan.chi_square(b"\x00" * 256), 1000)


class TestProfile(unittest.TestCase):
    def test_regions_and_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sample.bin")
            with open(path, "wb") as fh:
                fh.write(b"\x00" * 65536)
                fh.write(os.urandom(65536))
            profile = scan.analyze(path, window=4096, step=1024)
            self.assertEqual(profile.size, 131072)
            self.assertGreater(len(profile.windows), 10)
            regions = profile.regions(threshold=7.0)
            self.assertTrue(regions, "random half should register as high entropy")
            self.assertTrue(any(start >= 60000 for start, _, _ in regions))
            self.assertTrue(profile.gaps(), "zero half should register as a gap")

    def test_classify(self):
        with tempfile.TemporaryDirectory() as tmp:
            text = os.path.join(tmp, "a.txt")
            with open(text, "wb") as fh:
                fh.write(b"hello world\n" * 500)
            self.assertIn(scan.classify(scan.analyze(text)), ("text", "code / structured data"))


class TestPng(unittest.TestCase):
    def test_roundtrip_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x.png")
            pixels = [bytearray((10, 20, 30) * 32) for _ in range(16)]
            png.write_rgb(path, 32, 16, pixels)
            self.assertEqual(png.read_header(path), (32, 16, 8))
            with open(path, "rb") as fh:
                data = fh.read()
            self.assertTrue(data.startswith(png.PNG_SIG))
            self.assertIn(b"IHDR", data)
            self.assertTrue(data.endswith(b"IEND\xaeB`\x82"))

    def test_colormap_bounds(self):
        self.assertEqual(len(png.colormap(0.0)), 3)
        self.assertEqual(len(png.colormap(1.0)), 3)
        self.assertNotEqual(png.colormap(0.0), png.colormap(1.0))


class TestBinformats(unittest.TestCase):
    def test_pe_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "tiny.exe")
            with open(path, "wb") as fh:
                fh.write(_minimal_pe())
            self.assertEqual(binformats.detect(path), "PE")
            found = binformats.sections(path)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].name, ".text")
            self.assertEqual(found[0].offset, 0x200)
            self.assertEqual(found[0].size, 0x100)
            self.assertGreater(found[0].entropy, 7.9)

    def test_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x.bin")
            with open(path, "wb") as fh:
                fh.write(b"just text\n")
            self.assertEqual(binformats.detect(path), "unknown")
            self.assertEqual(binformats.sections(path), [])


class TestCarve(unittest.TestCase):
    def test_png_inside_blob(self):
        with tempfile.TemporaryDirectory() as tmp:
            inner = os.path.join(tmp, "inner.png")
            png.write_rgb(inner, 8, 8, [bytearray((200, 40, 40) * 8) for _ in range(8)])
            with open(inner, "rb") as fh:
                png_bytes = fh.read()
            blob = os.urandom(500) + png_bytes + os.urandom(500)
            path = os.path.join(tmp, "dump.bin")
            with open(path, "wb") as fh:
                fh.write(blob)
            found = carve_files(path)
            png_hits = [item for item in found if item.extension == "png"]
            self.assertEqual(len(png_hits), 1)
            self.assertEqual(png_hits[0].offset, 500)
            self.assertEqual(png_hits[0].size, len(png_bytes))

    def test_no_false_positive_mz(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "code.bin")
            with open(path, "wb") as fh:
                fh.write(b"MZ" + b"\x00" * 200)      # no PE header behind it
            self.assertEqual(carve_files(path), [])


class TestStrings(unittest.TestCase):
    def test_ascii_and_utf16(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "s.bin")
            with open(path, "wb") as fh:
                fh.write(b"\x00\x01hello world\x00")
                fh.write("wide string".encode("utf-16-le"))
                fh.write(b"\x00https://example.com/api\x00")
            found = strings.extract(path, minimum=4)
            texts = [item.text for item in found]
            self.assertIn("hello world", texts)
            self.assertIn("wide string", texts)
            self.assertTrue(any("example.com" in text for text in texts))

    def test_interesting_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "s.bin")
            with open(path, "wb") as fh:
                fh.write(b"nothing to see\x00https://x.tld/a\x00plain text\x00")
            found = strings.interesting(strings.extract(path))
            self.assertEqual(len(found), 1)
            self.assertIn("https://", found[0].text)


class TestReport(unittest.TestCase):
    def test_render_dimensions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.bin")
            with open(path, "wb") as fh:
                fh.write(b"\x00" * 2048 + b"\x01" * 2048)
            profile = scan.analyze(path, window=1024, step=512)
            width, height, pixels = report.render(profile, None, None, width=200, height=60)
            self.assertEqual(width, 200)
            self.assertEqual(height, 84)
            self.assertEqual(len(pixels), 84)
            self.assertEqual(len(pixels[0]), 600)

    def test_save(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "r.bin")
            with open(src, "wb") as fh:
                fh.write(os.urandom(4096))
            profile = scan.analyze(src)
            out = os.path.join(tmp, "map.png")
            report.save(out, profile, width=128, height=64)
            self.assertTrue(os.path.exists(out))
            self.assertEqual(png.read_header(out)[0], 128)


if __name__ == "__main__":
    unittest.main()
