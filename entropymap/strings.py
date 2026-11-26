"""String extraction: ASCII and UTF-16LE runs."""

from __future__ import annotations

import re
from dataclasses import dataclass

ASCII_RUN = re.compile(rb"[\x20-\x7e\t]{4,}")
UTF16_RUN = re.compile(rb"(?:[\x20-\x7e\t]\x00){4,}")


@dataclass
class String:
    offset: int
    text: str
    encoding: str


def extract(path: str, minimum: int = 4, limit: int = 4096) -> list[String]:
    with open(path, "rb") as fh:
        blob = fh.read()
    out: list[String] = []
    for match in ASCII_RUN.finditer(blob):
        text = match.group().decode("ascii", "replace")
        if len(text) >= minimum:
            out.append(String(match.start(), text, "ascii"))
            if len(out) >= limit:
                return out
    for match in UTF16_RUN.finditer(blob):
        start = match.start()
        raw = match.group()
        # an ASCII run followed by a NUL produces one bogus leading character
        if start and 32 <= blob[start - 1] < 127:
            raw = raw[2:]
            start += 2
        if start % 2:
            continue
        text = raw.decode("utf-16-le", "replace").rstrip("\x00")
        if len(text) >= minimum:
            out.append(String(start, text, "utf16"))
            if len(out) >= limit:
                return out
    out.sort(key=lambda item: item.offset)
    return out


def interesting(strings_: list[String], limit: int = 40) -> list[String]:
    """Heuristic shortlist: URLs, paths, keys, commands."""
    markers = (
        "http://", "https://", "ftp://", "\\\\", "/etc/", "/proc/", ".dll", ".exe",
        "cmd.exe", "powershell", "HKEY_", "SOFTWARE\\", "token", "password", "passwd",
        "api_key", "apikey", "secret", "license", "hwid", "discord", "telegram",
    )
    hits = [item for item in strings_
            if any(marker.lower() in item.text.lower() for marker in markers)]
    return hits[:limit]
