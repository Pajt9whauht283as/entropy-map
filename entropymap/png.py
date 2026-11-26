"""Minimal PNG writer: 8-bit RGB, no third-party dependencies."""

from __future__ import annotations

import struct
import zlib

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def _chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def write_rgb(path: str, width: int, height: int, pixels: list[bytearray]) -> None:
    """pixels: height rows, each row width*3 bytes."""
    if len(pixels) != height:
        raise ValueError("expected %d rows, got %d" % (height, len(pixels)))
    raw = bytearray()
    for row in pixels:
        if len(row) != width * 3:
            raise ValueError("row width mismatch")
        raw.append(0)
        raw.extend(row)
    payload = (
        PNG_SIG
        + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + _chunk(b"IEND", b"")
    )
    with open(path, "wb") as fh:
        fh.write(payload)


def read_header(path: str) -> tuple[int, int, int]:
    """Return (width, height, bit depth) for tests and quick checks."""
    with open(path, "rb") as fh:
        data = fh.read(33)
    if not data.startswith(PNG_SIG):
        raise ValueError("not a PNG")
    if data[12:16] != b"IHDR":
        raise ValueError("missing IHDR")
    width, height, depth = struct.unpack(">IIB", data[16:25])
    return width, height, depth


# t = 0.0 -> cold, 1.0 -> hot
_STOPS = [
    (0.00, (13, 17, 28)),
    (0.18, (26, 62, 122)),
    (0.38, (32, 150, 190)),
    (0.55, (52, 194, 120)),
    (0.72, (228, 196, 62)),
    (0.86, (226, 108, 52)),
    (1.00, (232, 64, 64)),
]


def colormap(t: float) -> tuple[int, int, int]:
    value = min(max(t, 0.0), 1.0)
    for (left, c0), (right, c1) in zip(_STOPS, _STOPS[1:]):
        if value <= right:
            span = right - left
            ratio = (value - left) / span if span else 0.0
            return tuple(int(a + (b - a) * ratio) for a, b in zip(c0, c1))
    return _STOPS[-1][1]


def scale_to_rgb(value: float, maximum: float) -> tuple[int, int, int]:
    return colormap(value / maximum if maximum else 0.0)


def blend(a: tuple[int, int, int], b: tuple[int, int, int], ratio: float) -> tuple[int, int, int]:
    ratio = min(max(ratio, 0.0), 1.0)
    return tuple(int(x + (y - x) * ratio) for x, y in zip(a, b))
