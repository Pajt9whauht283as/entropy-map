"""Signature carving: find files embedded inside files."""

from __future__ import annotations

import struct
from dataclasses import dataclass

MAX_SCAN = 64 << 20


@dataclass
class Carved:
    kind: str
    offset: int
    size: int | None
    extension: str

    @property
    def end(self) -> int | None:
        return None if self.size is None else self.offset + self.size


SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG image", "png"),
    (b"\xff\xd8\xff", "JPEG image", "jpg"),
    (b"GIF87a", "GIF image", "gif"),
    (b"GIF89a", "GIF image", "gif"),
    (b"PK\x03\x04", "ZIP archive", "zip"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "7z"),
    (b"Rar!\x1a\x07\x00", "RAR archive (v4)", "rar"),
    (b"Rar!\x1a\x07\x01\x00", "RAR5 archive", "rar"),
    (b"\x1f\x8b\x08", "gzip stream", "gz"),
    (b"BZh9", "bzip2 stream", "bz2"),
    (b"\xfd7zXZ\x00", "xz stream", "xz"),
    (b"%PDF-", "PDF document", "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file", "ole"),
    (b"SQLite format 3\x00", "SQLite database", "sqlite"),
    (b"MZ", "PE executable", "exe"),
    (b"\x7fELF", "ELF binary", "elf"),
    (b"dex\n", "Dalvik executable", "dex"),
    (b"ustar", "tar header", "tar"),
]


def _png_size(blob: bytes, offset: int) -> int | None:
    pos = offset + 8
    while pos + 8 <= len(blob):
        length = struct.unpack_from(">I", blob, pos)[0]
        kind = blob[pos + 4:pos + 8]
        pos += 12 + length
        if kind == b"IEND":
            return pos - offset
        if length > len(blob):
            return None
    return None


def _zip_size(blob: bytes, offset: int) -> int | None:
    end = blob.find(b"PK\x05\x06", offset)
    if end < 0 or end + 22 > len(blob):
        return None
    comment = struct.unpack_from("<H", blob, end + 20)[0]
    return end + 22 + comment - offset


def _jpeg_size(blob: bytes, offset: int) -> int | None:
    end = blob.find(b"\xff\xd9", offset + 2)
    return None if end < 0 else end + 2 - offset


_SIZE_RESOLVERS = {
    "png": _png_size,
    "zip": _zip_size,
    "jpg": _jpeg_size,
}


def _valid_pe(blob: bytes, offset: int) -> bool:
    if offset + 0x40 > len(blob):
        return False
    e_lfanew = struct.unpack_from("<I", blob, offset + 0x3C)[0]
    if e_lfanew <= 0 or offset + e_lfanew + 4 > len(blob):
        return False
    return blob[offset + e_lfanew:offset + e_lfanew + 4] == b"PE\x00\x00"


def _valid_elf(blob: bytes, offset: int) -> bool:
    if offset + 6 > len(blob):
        return False
    return blob[offset + 4] in (1, 2) and blob[offset + 5] in (1, 2)


def _valid_gzip(blob: bytes, offset: int) -> bool:
    return offset + 3 <= len(blob) and blob[offset + 3] & 0xE0 == 0


def _valid_tar(blob: bytes, offset: int) -> bool:
    return blob[offset + 257:offset + 262] == b"ustar"


def _valid_7z(blob: bytes, offset: int) -> bool:
    return offset + 32 <= len(blob)


def _valid_dex(blob: bytes, offset: int) -> bool:
    return blob[offset + 4:offset + 7].isdigit()


def _valid_sqlite(blob: bytes, offset: int) -> bool:
    return blob[offset + 16:offset + 18] == b"\x01\x00"


VALIDATORS = {
    "exe": _valid_pe,
    "elf": _valid_elf,
    "gz": _valid_gzip,
    "tar": _valid_tar,
    "7z": _valid_7z,
    "dex": _valid_dex,
    "sqlite": _valid_sqlite,
}


def _acceptable(kind: str, blob: bytes, offset: int) -> bool:
    resolver = _SIZE_RESOLVERS.get(kind)
    if resolver is not None and resolver(blob, offset) is None:
        return False
    validator = VALIDATORS.get(kind)
    if validator is not None:
        try:
            return validator(blob, offset)
        except (struct.error, IndexError):
            return False
    return True


def _resolve(kind: str, blob: bytes, offset: int) -> int | None:
    resolver = _SIZE_RESOLVERS.get(kind)
    if resolver is None:
        return None
    try:
        return resolver(blob, offset)
    except (struct.error, IndexError):
        return None


def carve(path: str, limit: int = MAX_SCAN) -> list[Carved]:
    with open(path, "rb") as fh:
        blob = fh.read(limit)
    found: list[Carved] = []
    seen: set[tuple[int, str]] = set()
    for magic, label, extension in SIGNATURES:
        start = 0
        while True:
            offset = blob.find(magic, start)
            if offset < 0:
                break
            start = offset + 1
            key = (offset, extension)
            if key in seen:
                continue
            seen.add(key)
            if offset == 0:
                continue          # the container is not an embedded object
            if not _acceptable(extension, blob, offset):
                continue
            found.append(Carved(kind=label, offset=offset, size=_resolve(extension, blob, offset),
                                extension=extension))
    found.sort(key=lambda item: item.offset)

    # carriers with unknown sizes inherit the distance to the next hit
    for index, item in enumerate(found):
        if item.size is None:
            end = found[index + 1].offset if index + 1 < len(found) else len(blob)
            item.size = max(end - item.offset, 0)
    return found
