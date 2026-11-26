"""Container metadata: PE sections, ELF sections, Mach-O basics."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .scan import shannon

PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce": ("Mach-O 32 BE", ">"),
    b"\xce\xfa\xed\xfe": ("Mach-O 32 LE", "<"),
    b"\xfe\xed\xfa\xcf": ("Mach-O 64 BE", ">"),
    b"\xcf\xfa\xed\xfe": ("Mach-O 64 LE", "<"),
    b"\xca\xfe\xba\xbe": ("Mach-O universal", ">"),
}

PE_CHARACTERISTICS = {
    0x00000020: "code",
    0x00000040: "initialized data",
    0x00000080: "uninitialized data",
    0x02000000: "discardable",
    0x20000000: "executable",
    0x40000000: "readable",
    0x80000000: "writable",
}


@dataclass
class Section:
    name: str
    offset: int
    size: int
    virtual_address: int = 0
    flags: str = ""
    entropy: float = 0.0
    kind: str = ""


def detect(path: str) -> str:
    with open(path, "rb") as fh:
        head = fh.read(16)
    if head.startswith(ELF_MAGIC):
        return "ELF"
    if head[:4] in MACHO_MAGICS:
        return MACHO_MAGICS[head[:4]][0]
    if head.startswith(PE_MAGIC):
        return "PE"
    return "unknown"


def _entropy_at(path: str, offset: int, size: int, cap: int = 1 << 20) -> float:
    if size <= 0:
        return 0.0
    with open(path, "rb") as fh:
        fh.seek(offset)
        data = fh.read(min(size, cap))
    return shannon(data)


def pe_sections(path: str) -> list[Section]:
    with open(path, "rb") as fh:
        blob = fh.read()
    if not blob.startswith(PE_MAGIC) or len(blob) < 0x40:
        return []
    pe_offset = struct.unpack_from("<I", blob, 0x3C)[0]
    if blob[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        return []
    coff = pe_offset + 4
    machine, count = struct.unpack_from("<HH", blob, coff)
    optional_size = struct.unpack_from("<H", blob, coff + 16)[0]
    table = coff + 20 + optional_size
    sections: list[Section] = []
    for index in range(count):
        base = table + index * 40
        if base + 40 > len(blob):
            break
        raw_name = blob[base:base + 8].rstrip(b"\x00")
        name = raw_name.decode("latin-1", "replace")
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", blob, base + 8)
        characteristics = struct.unpack_from("<I", blob, base + 36)[0]
        flags = ", ".join(label for bit, label in PE_CHARACTERISTICS.items() if characteristics & bit)
        size = raw_size or virtual_size
        sections.append(Section(
            name=name or "(unnamed)",
            offset=raw_ptr,
            size=size,
            virtual_address=virtual_address,
            flags=flags,
            entropy=_entropy_at(path, raw_ptr, size),
            kind="pe",
        ))
    return sections


def elf_sections(path: str) -> list[Section]:
    with open(path, "rb") as fh:
        blob = fh.read()
    if not blob.startswith(ELF_MAGIC) or len(blob) < 0x34:
        return []
    is64 = blob[4] == 2
    endian = "<" if blob[5] == 1 else ">"
    if is64:
        shoff = struct.unpack_from(endian + "Q", blob, 0x28)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", blob, 0x3A)
        fmt = endian + "IIQQQQIIQQ"
    else:
        shoff = struct.unpack_from(endian + "I", blob, 0x20)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", blob, 0x2E)
        fmt = endian + "IIIIIIIIII"
    if not shoff or not shnum or shentsize < struct.calcsize(fmt):
        return []

    raw_headers = []
    for index in range(shnum):
        base = shoff + index * shentsize
        if base + struct.calcsize(fmt) > len(blob):
            return []
        raw_headers.append(struct.unpack_from(fmt, blob, base))

    names_blob = b""
    if shstrndx < len(raw_headers):
        names_offset, names_size = raw_headers[shstrndx][4], raw_headers[shstrndx][5]
        names_blob = blob[names_offset:names_offset + names_size]

    sections: list[Section] = []
    for header in raw_headers:
        name_offset, sh_type, sh_flags, sh_addr, sh_offset, sh_size = header[:6]
        name = ""
        if names_blob and name_offset < len(names_blob):
            end = names_blob.find(b"\x00", name_offset)
            name = names_blob[name_offset:end if end >= 0 else len(names_blob)].decode("latin-1", "replace")
        if sh_type == 8:          # SHT_NOBITS has no file payload
            entropy = 0.0
        else:
            entropy = _entropy_at(path, sh_offset, sh_size)
        label = []
        if sh_flags & 0x4:
            label.append("exec")
        if sh_flags & 0x2:
            label.append("alloc")
        if sh_flags & 0x1:
            label.append("write")
        sections.append(Section(
            name=name or "(unnamed)",
            offset=sh_offset,
            size=sh_size,
            virtual_address=sh_addr,
            flags=", ".join(label),
            entropy=entropy,
            kind="elf",
        ))
    return sections


def sections(path: str) -> list[Section]:
    kind = detect(path)
    if kind == "PE":
        return pe_sections(path)
    if kind == "ELF":
        return elf_sections(path)
    return []


def highest_entropy(sections_: list[Section], threshold: float = 7.4) -> list[Section]:
    return [section for section in sections_ if section.entropy >= threshold and section.size > 4096]
