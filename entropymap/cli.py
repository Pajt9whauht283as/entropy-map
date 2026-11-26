"""Command line: entropy analysis, sections, carving and strings."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

from . import binformats, report, scan
from .carve import carve as carve_files
from .strings import extract as extract_strings, interesting as interesting_strings

VERSION = "1.0.0"

COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _paint(code: str, text: str) -> str:
    return "\x1b[%sm%s\x1b[0m" % (code, text) if COLOR else text


def bold(text: str) -> str:
    return _paint("1", text)


def dim(text: str) -> str:
    return _paint("2", text)


def cyan(text: str) -> str:
    return _paint("36", text)


def yellow(text: str) -> str:
    return _paint("33", text)


def red(text: str) -> str:
    return _paint("31", text)


def green(text: str) -> str:
    return _paint("32", text)


def human_bytes(value: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(value) < 1024:
            return "%.0f %s" % (value, unit)
        value /= 1024.0
    return "%.1f TB" % value


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _visible(text: str) -> int:
    return len(_ANSI.sub("", text))


def _pad(text: str, width: int, align_right: bool) -> str:
    fill = " " * max(width - _visible(text), 0)
    return fill + text if align_right else text + fill


def table(headers, rows, right=()):
    widths = [_visible(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], _visible(cell))
    head = "  ".join(_pad(h, widths[i], False) for i, h in enumerate(headers))
    print("  " + dim(head))
    print("  " + dim("  ".join("─" * width for width in widths)))
    for row in rows:
        cells = [_pad(cell, widths[i], i in right) for i, cell in enumerate(row)]
        print("  " + "  ".join(cells))


def _bar(ratio: float, cells: int = 20) -> str:
    filled = int(round(ratio * cells))
    return "#" * filled + dim("." * (cells - filled))


# ------------------------------------------------------------------ commands

def cmd_analyze(args) -> int:
    if not os.path.isfile(args.path):
        print(red("not a file: %s") % args.path, file=sys.stderr)
        return 2
    profile = scan.analyze(args.path, window=args.window, step=args.step)
    kind = binformats.detect(args.path)
    sections = binformats.sections(args.path) if kind in ("PE", "ELF") else []
    carved = carve_files(args.path) if args.carve else []
    strings_found = extract_strings(args.path) if args.strings else []

    print()
    print(cyan("┌─ ") + bold(os.path.basename(args.path)))
    print("    %-11s %s" % (dim("size"), human_bytes(profile.size)))
    print("    %-11s %s" % (dim("container"), kind))
    print("    %-11s %s" % (dim("class"), scan.classify(profile)))
    print("    %-11s %.2f bits/byte  peak %.2f" % (dim("entropy"), profile.average, profile.peak))
    print("    %-11s %d windows of %s, step %s" % (
        dim("grid"), len(profile.windows), human_bytes(profile.window), human_bytes(profile.step)))

    high = profile.regions(threshold=args.threshold)
    if high:
        print()
        print("  " + bold("high-entropy regions") + dim("  (packed / compressed / encrypted)"))
        rows = []
        for start, end, peak in high[:12]:
            ratio = min(peak / 8.0, 1.0)
            rows.append(["0x%08x" % start, human_bytes(end - start), "%.2f" % peak, _bar(ratio)])
        table(["offset", "length", "peak", "ratio"], rows, right=(1, 2))
    gaps = profile.gaps()
    if gaps:
        print()
        print("  " + bold("near-empty regions") + dim("  (padding, sparse tables)"))
        rows = [["0x%08x" % start, human_bytes(end - start)] for start, end in gaps[:8]]
        table(["offset", "length"], rows, right=(1,))

    if sections:
        print()
        print("  " + bold("%s sections" % kind))
        rows = []
        for section in sections:
            rows.append([
                section.name,
                "0x%08x" % section.offset,
                human_bytes(section.size),
                "%.2f" % section.entropy,
                _bar(min(section.entropy / 8.0, 1.0), 10),
                section.flags,
            ])
        table(["section", "offset", "size", "entropy", "ratio", "flags"], rows, right=(1, 2, 3))
        packed = binformats.highest_entropy(sections)
        if packed:
            print("  " + yellow("! ") + "high entropy in "
                  + ", ".join("%s (%.2f)" % (s.name, s.entropy) for s in packed[:4]))

    if carved:
        print()
        print("  " + bold("embedded objects"))
        rows = []
        for item in carved[:20]:
            rows.append(["0x%08x" % item.offset,
                         item.kind,
                         human_bytes(item.size or 0) if item.size else "?",
                         item.extension])
        table(["offset", "type", "size", "ext"], rows, right=(0, 2))

    if strings_found:
        print()
        print("  " + bold("strings") + dim("  %d extracted, %d interesting"
                                           % (len(strings_found), len(interesting_strings(strings_found)))))
        for item in interesting_strings(strings_found)[:15]:
            print("    " + dim("0x%08x" % item.offset) + "  " + item.text[:100])

    png_path = None
    if not args.no_png:
        png_path = args.png or (os.path.splitext(os.path.basename(args.path))[0] + ".entropy.png")
        report.save(png_path, profile, sections, carved, width=args.width, height=args.height)
        print()
        print("  " + green("+ ") + "image written to " + png_path)

    if args.json:
        print(json.dumps({
            "path": profile.path,
            "size": profile.size,
            "container": kind,
            "class": scan.classify(profile),
            "average_entropy": round(profile.average, 4),
            "peak_entropy": round(profile.peak, 4),
            "window": profile.window,
            "step": profile.step,
            "high_entropy": [{"offset": s, "length": e - s, "peak": round(p, 4)}
                             for s, e, p in high],
            "gaps": [{"offset": s, "length": e - s} for s, e in gaps],
            "sections": [{"name": s.name, "offset": s.offset, "size": s.size,
                          "entropy": round(s.entropy, 4), "flags": s.flags} for s in sections],
            "carved": [{"offset": c.offset, "kind": c.kind, "size": c.size,
                        "extension": c.extension} for c in carved],
            "strings": len(strings_found),
            "image": png_path,
        }, indent=2))
    return 0


def cmd_sections(args) -> int:
    kind = binformats.detect(args.path)
    found = binformats.sections(args.path)
    if not found:
        print(yellow("no PE or ELF sections found (%s)" % kind))
        return 1
    print()
    print(cyan("┌─ ") + bold("%s sections: %s" % (kind, os.path.basename(args.path))))
    rows = [[s.name, "0x%08x" % s.offset, human_bytes(s.size), "%.3f" % s.entropy, s.flags]
            for s in found]
    table(["section", "offset", "size", "entropy", "flags"], rows, right=(1, 2, 3))
    return 0


def cmd_carve(args) -> int:
    found = carve_files(args.path)
    if not found:
        print(yellow("no embedded signatures found"))
        return 1
    rows = [["0x%08x" % c.offset, c.kind, human_bytes(c.size or 0), c.extension] for c in found]
    table(["offset", "type", "size", "ext"], rows, right=(0, 2))
    return 0


def cmd_strings(args) -> int:
    found = extract_strings(args.path, minimum=args.min, limit=args.limit)
    if args.interesting:
        found = interesting_strings(found, limit=args.limit)
    for item in found:
        print("0x%08x  %s" % (item.offset, item.text))
    return 0


# ------------------------------------------------------------------ parser

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="entropy-map",
        description="Visual entropy analysis of binaries and archives: packers, blobs, sections.",
        epilog="examples:\n"
               "  main.py analyze suspicious.exe\n"
               "  main.py analyze pack.zip --strings --json\n"
               "  main.py sections client.dll\n"
               "  main.py carve dump.bin\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="entropy-map " + VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("analyze", help="full profile plus rendered map")
    p.add_argument("path")
    p.add_argument("--window", type=int, default=scan.DEFAULT_WINDOW)
    p.add_argument("--step", type=int)
    p.add_argument("--width", type=int, default=1600)
    p.add_argument("--height", type=int, default=180)
    p.add_argument("--threshold", type=float, default=7.2)
    p.add_argument("--png", metavar="FILE")
    p.add_argument("--no-png", action="store_true")
    p.add_argument("--no-carve", dest="carve", action="store_false")
    p.add_argument("--strings", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_analyze, carve=True, strings=False)

    p = sub.add_parser("sections", help="PE / ELF section table with entropy")
    p.add_argument("path")
    p.set_defaults(func=cmd_sections)

    p = sub.add_parser("carve", help="find embedded files by signature")
    p.add_argument("path")
    p.set_defaults(func=cmd_carve)

    p = sub.add_parser("strings", help="extract printable strings")
    p.add_argument("path")
    p.add_argument("--min", type=int, default=4)
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--interesting", action="store_true")
    p.set_defaults(func=cmd_strings)

    return parser


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(red("missing file: %s") % exc.filename, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print()
        return 130
