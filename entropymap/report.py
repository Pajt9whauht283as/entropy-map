"""Rendering: entropy area chart with section band, carved markers and gridlines."""

from __future__ import annotations

from . import png
from .binformats import Section
from .carve import Carved
from .scan import Profile

BACKGROUND = (13, 17, 28)
GRID = (32, 38, 52)
BAND_EMPTY = (24, 28, 38)
MARKER = (250, 250, 250)
LABEL = (90, 100, 120)

SECTION_PALETTE = [
    (58, 74, 122), (72, 110, 92), (110, 78, 122), (122, 100, 62),
    (62, 112, 122), (100, 62, 78), (86, 96, 132), (96, 118, 68),
]


def _sample(windows, columns: int) -> list[float]:
    if not windows:
        return [0.0] * columns
    if len(windows) <= columns:
        step = len(windows) / columns
        return [windows[min(int(index * step), len(windows) - 1)].entropy for index in range(columns)]
    step = len(windows) / columns
    out = []
    for index in range(columns):
        start = int(index * step)
        end = max(int((index + 1) * step), start + 1)
        chunk = windows[start:end]
        out.append(max(window.entropy for window in chunk))
    return out


def render(
    profile: Profile,
    sections: list[Section] | None = None,
    carved: list[Carved] | None = None,
    width: int = 1600,
    height: int = 180,
    band: int = 24,
) -> tuple[int, int, list[bytearray]]:
    width = max(64, width)
    height = max(48, height)
    total_height = band + height
    pixels = [bytearray(BACKGROUND * width) for _ in range(total_height)]

    values = _sample(profile.windows, width)
    size = profile.size or 1

    # section band
    for row in range(band):
        line = pixels[row]
        for x in range(width):
            line[x * 3:x * 3 + 3] = bytes(BAND_EMPTY)
    if sections:
        for index, section in enumerate(sections):
            start = int(section.offset / size * width)
            end = int((section.offset + section.size) / size * width)
            if end <= start:
                end = min(start + 1, width)
            color = SECTION_PALETTE[index % len(SECTION_PALETTE)]
            for row in range(band - 6, band):
                line = pixels[row]
                for x in range(start, min(end, width)):
                    line[x * 3:x * 3 + 3] = bytes(color)
            for row in range(0, band - 6):
                line = pixels[row]
                for x in range(start, min(end, width)):
                    current = line[x * 3:x * 3 + 3]
                    line[x * 3:x * 3 + 3] = bytes(png.blend(tuple(current), color, 0.18))
            if start < width:
                for row in range(band):
                    line = pixels[row]
                    line[start * 3:start * 3 + 3] = bytes((10, 12, 18))

    # area chart
    for x, entropy in enumerate(values):
        ratio = min(entropy / 8.0, 1.0)
        top = band + height - 1 - int(ratio * (height - 1))
        color = png.colormap(ratio)
        for y in range(top, band + height):
            depth = (y - top) / max(height - 1, 1)
            shade = png.blend(color, BACKGROUND, depth * 0.75)
            line = pixels[y]
            line[x * 3:x * 3 + 3] = bytes(shade)
        line = pixels[top]
        line[x * 3:x * 3 + 3] = bytes(color)

    # gridlines at 2/4/6 bits, drawn over the fill so they stay readable
    for bits in (2, 4, 6):
        y = band + height - 1 - int(bits / 8 * (height - 1))
        line = pixels[y]
        for x in range(width):
            current = tuple(line[x * 3:x * 3 + 3])
            line[x * 3:x * 3 + 3] = bytes(png.blend(current, (150, 165, 190), 0.28))

    # carved markers
    for item in carved or []:
        x = int(item.offset / size * width)
        if not 0 <= x < width:
            continue
        for row in range(band, band + 8):
            line = pixels[row]
            line[x * 3:x * 3 + 3] = bytes(MARKER)

    return width, total_height, pixels


def save(path: str, profile: Profile, sections=None, carved=None, width: int = 1600,
         height: int = 180) -> str:
    w, h, pixels = render(profile, sections, carved, width=width, height=height)
    png.write_rgb(path, w, h, pixels)
    return path
