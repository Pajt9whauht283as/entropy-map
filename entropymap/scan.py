"""Shannon entropy over sliding windows, plus byte-class statistics."""

from __future__ import annotations

import math
import os
from collections import Counter
from dataclasses import dataclass, field

DEFAULT_WINDOW = 4096
MAX_COLUMNS = 2048
SAMPLE_BYTES = 2048


def shannon(data: bytes) -> float:
    """Entropy in bits per byte, 0.0 .. 8.0."""
    if not data:
        return 0.0
    total = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def shannon_sampled(data: bytes, limit: int = SAMPLE_BYTES) -> float:
    """Entropy over an evenly strided sample: C-speed slicing, same shape."""
    if len(data) <= limit:
        return shannon(data)
    stride = max(len(data) // limit, 1)
    return shannon(data[::stride])


def chi_square(data: bytes) -> float:
    """Uniformity test: near 0 for random-looking data, huge for structured."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    expected = len(data) / 256.0
    return sum((count - expected) ** 2 / expected for count in counts)


@dataclass
class Window:
    offset: int
    length: int
    entropy: float
    printable: float
    zeros: float

    @property
    def end(self) -> int:
        return self.offset + self.length


@dataclass
class Profile:
    path: str
    size: int
    window: int
    step: int
    windows: list[Window] = field(default_factory=list)

    @property
    def average(self) -> float:
        if not self.windows:
            return 0.0
        return sum(w.entropy for w in self.windows) / len(self.windows)

    @property
    def peak(self) -> float:
        return max((w.entropy for w in self.windows), default=0.0)

    def regions(self, threshold: float = 7.2, minimum_span: int = 3) -> list[tuple[int, int, float]]:
        """Contiguous runs of high-entropy windows: compression, encryption or packing."""
        regions: list[tuple[int, int, float]] = []
        start = None
        peak = 0.0
        for window in self.windows:
            if window.entropy >= threshold:
                if start is None:
                    start = window.offset
                    peak = window.entropy
                peak = max(peak, window.entropy)
            elif start is not None:
                if window.offset - start >= minimum_span * self.step:
                    regions.append((start, window.offset, peak))
                start = None
        if start is not None:
            regions.append((start, self.windows[-1].end, peak))
        return regions

    def gaps(self, threshold: float = 0.5, minimum_span: int = 4) -> list[tuple[int, int]]:
        """Runs of near-zero entropy: padding, sparse tables, empty space."""
        out: list[tuple[int, int]] = []
        start = None
        for window in self.windows:
            if window.entropy <= threshold:
                if start is None:
                    start = window.offset
            elif start is not None:
                if window.offset - start >= minimum_span * self.step:
                    out.append((start, window.offset))
                start = None
        if start is not None:
            out.append((start, self.windows[-1].end))
        return out


_PRINTABLE = bytes(1 if 32 <= value < 127 or value in (9, 10, 13) else 0
                     for value in range(256))


def _stats(chunk: bytes) -> tuple[float, float]:
    total = len(chunk) or 1
    return sum(chunk.translate(_PRINTABLE)) / total, chunk.count(0) / total


def analyze(
    path: str,
    window: int = DEFAULT_WINDOW,
    step: int | None = None,
    max_windows: int = 8192,
) -> Profile:
    size = os.path.getsize(path)
    if step is None:
        step = max(window // 4, 256)
    # keep the grid bounded for huge files: switch to non-overlapping tiles so the
    # whole scan reads each byte once instead of re-reading overlaps
    if size and (size // step) > max_windows:
        step = max(step, -(-size // max_windows))
        window = step

    profile = Profile(path=path, size=size, window=window, step=step)
    if size == 0:
        return profile

    with open(path, "rb") as fh:
        offset = 0
        while offset < size:
            fh.seek(offset)
            chunk = fh.read(window)
            if not chunk:
                break
            printable, zeros = _stats(chunk)
            profile.windows.append(Window(
                offset=offset,
                length=len(chunk),
                entropy=shannon_sampled(chunk),
                printable=printable,
                zeros=zeros,
            ))
            if offset + len(chunk) >= size:
                break
            offset += step
    return profile


def classify(profile: Profile) -> str:
    if not profile.windows:
        return "empty"
    average = profile.average
    printable = sum(w.printable for w in profile.windows) / len(profile.windows)
    if average < 1.0:
        return "sparse / mostly zero"
    if average < 4.0 and printable > 0.8:
        return "text"
    if average < 6.5:
        return "code / structured data"
    if average >= 7.2:
        return "packed, compressed or encrypted"
    return "mixed"
