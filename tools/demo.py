#!/usr/bin/env python3
"""Build the README screenshots from a synthetic sample, so they are reproducible."""

from __future__ import annotations

import os
import random
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from entropymap import png, report, scan  # noqa: E402
from entropymap.carve import carve as carve_files  # noqa: E402


def build_sample(path: str) -> None:
    rng = random.Random(7)
    text = (b"# synthetic sample for entropy-map\n"
            b"header, version, license, config keys and other structured text\n") * 120
    packed = bytes(rng.getrandbits(8) for _ in range(48 * 1024))
    zeros = b"\x00" * 8192
    inner = os.path.join(tempfile.gettempdir(), "entropy-demo-inner.png")
    png.write_rgb(inner, 16, 16, [bytearray((90, 200, 120) * 16) for _ in range(16)])
    with open(inner, "rb") as fh:
        embedded = fh.read()
    body = text + packed + embedded + zeros + text
    with open(path, "wb") as fh:
        fh.write(body)


def main() -> int:
    docs = os.path.join(ROOT, "docs")
    os.makedirs(docs, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        sample = os.path.join(tmp, "demo.bin")
        build_sample(sample)
        profile = scan.analyze(sample, window=2048, step=512)
        carved = carve_files(sample)
        out = os.path.join(docs, "demo.png")
        report.save(out, profile, None, carved, width=1100, height=170)
        print("wrote", out, "regions", len(profile.regions()), "carved", len(carved))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
