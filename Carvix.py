#!/usr/bin/env python3
"""
Focused Task Manager minidump carver for Java client artifacts.

Carves:
  * JAR-like ZIP runs that contain Java entries and bundled assets
  * loose PNG/GIF/JPEG/WebP assets
  * PE DLL candidates, with Windows/Microsoft module noise filtered by default

The JAR path intentionally rebuilds a clean archive from local ZIP headers instead
of dumping arbitrary byte ranges. That avoids most of the noisy binwalk behavior.
"""

from __future__ import annotations

import argparse
import binascii
import csv
import io
import hashlib
import json
import os
import re
import struct
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterable
from zipfile import ZIP_DEFLATED, ZIP_STORED, BadZipFile, ZipFile, ZipInfo


LOCAL_ZIP = b"PK\x03\x04"
CENTRAL_ZIP = b"PK\x01\x02"
EOCD_ZIP = b"PK\x05\x06"
PNG_SIG = b"\x89PNG\r\n\x1a\n"
GIF87 = b"GIF87a"
GIF89 = b"GIF89a"
JPEG_SIG = b"\xff\xd8\xff"
WEBP_SIG = b"RIFF"
MZ_SIG = b"MZ"

ASSET_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ogg",
    ".wav",
    ".json",
    ".mcmeta",
    ".fsh",
    ".vsh",
    ".glsl",
    ".ttf",
    ".otf",
    ".properties",
    ".lang",
}
JAVA_HINT_EXTS = {".class", ".kotlin_module"}
JAVA_HINT_FILES = {
    "META-INF/MANIFEST.MF",
    "fabric.mod.json",
    "forge.mod.json",
    "META-INF/mods.toml",
    "plugin.yml",
    "bungee.yml",
}
WINDOWS_PATH_MARKERS = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "\\windows\\microsoft.net\\",
)
MICROSOFT_MARKERS = (
    "microsoft corporation",
    "microsoft windows",
    "windows operating system",
)
NTFS_RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}
THIRD_PARTY_DLL_MARKERS = (
    "vape",
    "minecraft",
    "net/minecraft",
    "jni_getcreatedjavavms",
    "java/lang/classloader",
    "lwjgl",
)
COMMON_IMPORT_DLLS = {
    "advapi32.dll",
    "bcrypt.dll",
    "combase.dll",
    "crypt32.dll",
    "gdi32.dll",
    "gdi32full.dll",
    "imm32.dll",
    "java.dll",
    "jvm.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "msvcrt.dll",
    "ntdll.dll",
    "ole32.dll",
    "oleaut32.dll",
    "rpcrt4.dll",
    "sechost.dll",
    "shell32.dll",
    "ucrtbase.dll",
    "user32.dll",
    "winhttp.dll",
    "winmm.dll",
    "ws2_32.dll",
}


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def iter_sig(f: BinaryIO, sig: bytes, chunk_size: int = 8 * 1024 * 1024) -> Iterable[int]:
    overlap = len(sig) - 1
    base = 0
    prev = b""
    while True:
        chunk = f.read(chunk_size)
        if not chunk:
            return
        buf = prev + chunk
        pos = buf.find(sig)
        while pos != -1:
            yield base - len(prev) + pos
            pos = buf.find(sig, pos + 1)
        keep = min(overlap, len(buf))
        prev = buf[-keep:]
        base += len(chunk)


def read_at(f: BinaryIO, off: int, size: int) -> bytes:
    f.seek(off)
    return f.read(size)


def safe_name(name: str) -> str:
    name = name.replace("\\", "/").strip("/")
    name = re.sub(r"[^A-Za-z0-9._/\-+@()[\] ]+", "_", name)
    parts = [p for p in name.split("/") if p not in ("", ".", "..")]
    return "/".join(parts) or "unnamed"


def safe_artifact_stem(name: str, fallback: str) -> str:
    name = Path(name).name if name else fallback
    name = re.sub(r"\.(jar|dll|exe)$", "", name, flags=re.I)
    name = re.sub(r"[^A-Za-z0-9._+\- @()[\]]+", "_", name).strip(" ._")
    return name[:80] or fallback


def ntfs_component(name: str) -> str:
    name = re.sub(r'[<>:"|?*\x00-\x1f]+', "_", name).strip()
    name = name.rstrip(" .")
    if not name or name in (".", ".."):
        name = "unnamed"
    stem = name.split(".", 1)[0].lower()
    if stem in NTFS_RESERVED_NAMES:
        name = "_" + name
    if len(name) > 140:
        suffix = "".join(Path(name).suffixes)
        keep = max(20, 140 - len(suffix) - 13)
        digest = hashlib.sha1(name.encode("utf-8", "ignore")).hexdigest()[:10]
        name = f"{name[:keep]}_{digest}{suffix}"
    return name


def ntfs_safe_relpath(zip_name: str, used: set[str]) -> Path:
    raw_parts = zip_name.replace("\\", "/").strip("/").split("/")
    parts = [ntfs_component(p) for p in raw_parts if p not in ("", ".", "..")]
    if not parts:
        parts = ["unnamed"]
    candidate = parts[:]
    key = "/".join(candidate).casefold()
    if key not in used:
        used.add(key)
        return Path(*candidate)

    base = Path(candidate[-1]).stem or "unnamed"
    suffix = "".join(Path(candidate[-1]).suffixes)
    parent = candidate[:-1]
    n = 2
    while True:
        candidate = parent + [ntfs_component(f"{base}_dup{n:03d}{suffix}")]
        key = "/".join(candidate).casefold()
        if key not in used:
            used.add(key)
            return Path(*candidate)
        n += 1


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class ZipEntry:
    name: str
    method: int
    flags: int
    crc: int
    comp_size: int
    uncomp_size: int
    header_offset: int
    data_offset: int
    end_offset: int
    data: bytes = b""


@dataclass
class JarCandidate:
    start: int
    end: int
    entries: list[ZipEntry] = field(default_factory=list)
    class_count: int = 0
    asset_count: int = 0
    java_hint_count: int = 0
    score: int = 0
    name_hint: str = ""
    ntfs_collision_count: int = 0
    ntfs_collision_examples: list[str] = field(default_factory=list)
    sha256: str = ""
    output: str = ""
    reason: str = ""


@dataclass
class PeCandidate:
    offset: int
    size_of_image: int
    machine: int
    sections: int
    image_base: int
    characteristics: int = 0
    is_dll: bool = False
    module_path: str = ""
    name_hint: str = ""
    third_party_hints: list[str] = field(default_factory=list)
    extraction_mode: str = ""
    pe_score: int = 0
    is_windows_noise: bool = False
    sha256: str = ""
    output: str = ""
    reason: str = ""


def parse_minidump_modules(blob: bytes) -> tuple[list[dict], list[dict]]:
    modules: list[dict] = []
    memory_ranges: list[dict] = []
    if len(blob) < 32 or blob[:4] != b"MDMP":
        return modules, memory_ranges

    streams = u32(blob, 8)
    directory_rva = u32(blob, 12)
    for i in range(streams):
        doff = directory_rva + i * 12
        if doff + 12 > len(blob):
            break
        stype, dsize, rva = struct.unpack_from("<III", blob, doff)
        if rva + dsize > len(blob):
            continue
        if stype == 4 and dsize >= 4:
            count = u32(blob, rva)
            moff = rva + 4
            for _ in range(count):
                if moff + 108 > len(blob):
                    break
                base = u64(blob, moff)
                size = u32(blob, moff + 8)
                name_rva = u32(blob, moff + 20)
                name = ""
                if 0 <= name_rva <= len(blob) - 4:
                    nbytes = min(u32(blob, name_rva), len(blob) - name_rva - 4)
                    raw = blob[name_rva + 4 : name_rva + 4 + nbytes]
                    try:
                        name = raw.decode("utf-16le", "replace").rstrip("\x00")
                    except UnicodeDecodeError:
                        name = ""
                modules.append({"base": base, "size": size, "path": name})
                moff += 108
        elif stype == 5 and dsize >= 4:
            count = u32(blob, rva)
            roff = rva + 4
            for _ in range(count):
                if roff + 16 > len(blob):
                    break
                start = u64(blob, roff)
                size = u32(blob, roff + 8)
                data_rva = u32(blob, roff + 12)
                memory_ranges.append({"start": start, "size": size, "rva": data_rva})
                roff += 16
        elif stype == 9 and dsize >= 16:
            count = u64(blob, rva)
            base_rva = u64(blob, rva + 8)
            roff = rva + 16
            cur_rva = base_rva
            for _ in range(count):
                if roff + 16 > len(blob):
                    break
                start = u64(blob, roff)
                size = u64(blob, roff + 8)
                if size <= 0x7FFFFFFF:
                    memory_ranges.append({"start": start, "size": int(size), "rva": int(cur_rva)})
                cur_rva += size
                roff += 16
    return modules, memory_ranges


def module_for_file_offset(offset: int, modules: list[dict], ranges: list[dict]) -> dict | None:
    va = None
    for r in ranges:
        if r["rva"] <= offset < r["rva"] + r["size"]:
            va = r["start"] + (offset - r["rva"])
            break
    if va is None:
        return None
    for m in modules:
        if m["base"] <= va < m["base"] + m["size"]:
            return m
    return None


def printable_text(blob: bytes) -> str:
    ascii_text = blob.decode("latin1", "ignore")
    utf16_text = blob.decode("utf-16le", "ignore")
    return ascii_text + "\n" + utf16_text


def infer_pe_identity(path: str, blob: bytes) -> tuple[str, list[str]]:
    text = printable_text(blob[: min(len(blob), 3 * 1024 * 1024)])
    lower = text.lower()
    hints = [marker for marker in THIRD_PARTY_DLL_MARKERS if marker in lower]
    if path:
        name = Path(path).name
        if name:
            return name, hints

    dll_names = re.findall(r"(?i)\b[A-Z0-9][A-Z0-9_.+\- @()]{2,80}\.(?:dll|exe)\b", text)
    cleaned = []
    for name in dll_names:
        base = re.sub(r"\s+", " ", name).strip(" .")
        if not base:
            continue
        cleaned.append(base)
    preferred = [
        name
        for name in cleaned
        if name.lower() not in COMMON_IMPORT_DLLS and not name.lower().startswith(("api-ms-", "ext-ms-"))
    ]
    if hints and preferred:
        return preferred[0], hints
    if preferred:
        return preferred[0], hints
    return "", hints


def looks_windows_noise(path: str, blob: bytes, third_party_hints: list[str]) -> tuple[bool, str]:
    text = path.lower()
    if any(marker in text for marker in WINDOWS_PATH_MARKERS):
        return True, "module path is under Windows system directories"
    if third_party_hints:
        return False, "third-party markers: " + ", ".join(third_party_hints[:6])
    sample_text = printable_text(blob[: min(len(blob), 2 * 1024 * 1024)]).lower()
    if any(marker in sample_text for marker in MICROSOFT_MARKERS):
        return True, "version strings identify Microsoft/Windows"
    return False, ""


def parse_zip_run(blob: bytes, start: int, max_entries: int, max_size: int) -> JarCandidate | None:
    off = start
    entries: list[ZipEntry] = []
    seen_names: set[str] = set()
    limit = min(len(blob), start + max_size)

    while off + 30 <= limit and blob[off : off + 4] == LOCAL_ZIP and len(entries) < max_entries:
        try:
            flags = u16(blob, off + 6)
            method = u16(blob, off + 8)
            crc = u32(blob, off + 14)
            csize = u32(blob, off + 18)
            usize = u32(blob, off + 22)
            nlen = u16(blob, off + 26)
            xlen = u16(blob, off + 28)
        except struct.error:
            break
        if nlen <= 0 or nlen > 4096 or xlen > 65535:
            break
        name_start = off + 30
        data_start = name_start + nlen + xlen
        if data_start > limit:
            break
        raw_name = blob[name_start : name_start + nlen]
        try:
            name = raw_name.decode("utf-8" if flags & 0x800 else "cp437", "replace")
        except LookupError:
            name = raw_name.decode("latin1", "replace")
        name = safe_name(name)
        if not name or name in seen_names or "\x00" in name:
            break
        if method not in (0, 8):
            break

        if flags & 0x08 or csize == 0xFFFFFFFF or usize == 0xFFFFFFFF:
            # Data descriptors require the central directory or a stronger stream parser.
            break
        if csize > max_size or data_start + csize > limit:
            break
        data_end = data_start + csize
        data = blob[data_start:data_end]
        if method == 8:
            try:
                zlib.decompress(data, -15)
            except zlib.error:
                break
        elif usize != csize:
            break

        entries.append(
            ZipEntry(
                name=name,
                method=method,
                flags=flags,
                crc=crc,
                comp_size=csize,
                uncomp_size=usize,
                header_offset=off,
                data_offset=data_start,
                end_offset=data_end,
                data=data,
            )
        )
        seen_names.add(name)
        off = data_end
        if off + 4 <= limit and blob[off : off + 4] not in (LOCAL_ZIP, CENTRAL_ZIP, EOCD_ZIP):
            break
        if off + 4 <= limit and blob[off : off + 4] in (CENTRAL_ZIP, EOCD_ZIP):
            break

    if not entries:
        return None

    names = [e.name for e in entries]
    lowered = [n.lower() for n in names]
    class_count = sum(1 for n in lowered if Path(n).suffix == ".class")
    asset_count = sum(1 for n in lowered if Path(n).suffix in ASSET_EXTS or n.startswith(("assets/", "resources/")))
    java_hint_count = class_count + sum(1 for n in names if n in JAVA_HINT_FILES)
    score = java_hint_count * 4 + asset_count * 2 + min(len(entries), 20)
    cand = JarCandidate(start=start, end=entries[-1].end_offset, entries=entries)
    cand.class_count = class_count
    cand.asset_count = asset_count
    cand.java_hint_count = java_hint_count
    cand.score = score
    if len(entries) < 2:
        cand.reason = "too few ZIP entries"
    elif java_hint_count == 0:
        cand.reason = "no Java/class/mod metadata entries"
    elif asset_count == 0:
        cand.reason = "no bundled asset entries"
    return cand


def rebuild_jar(cand: JarCandidate, out_path: Path) -> str:
    with ZipFile(out_path, "w") as zf:
        for entry in cand.entries:
            if entry.method == 8:
                payload = zlib.decompress(entry.data, -15)
                compress_type = ZIP_DEFLATED
            else:
                payload = entry.data
                compress_type = ZIP_STORED
            zi = ZipInfo(entry.name)
            zi.compress_type = compress_type
            zf.writestr(zi, payload)
    digest = hashlib.sha256(out_path.read_bytes()).hexdigest()
    return digest


def parse_eocd_zip(blob: bytes, eocd_off: int) -> tuple[int, int, list[str]] | None:
    if eocd_off + 22 > len(blob):
        return None
    try:
        disk, cd_disk, disk_entries, total_entries, cd_size, cd_off, comment = struct.unpack_from("<HHHHIIH", blob, eocd_off + 4)
    except struct.error:
        return None
    if disk != 0 or cd_disk != 0 or total_entries == 0 or total_entries == 0xFFFF:
        return None
    end = eocd_off + 22 + comment
    start = eocd_off - cd_size - cd_off
    if start < 0 or end > len(blob) or start >= eocd_off:
        return None
    if blob[start : start + 4] != LOCAL_ZIP:
        return None
    raw = blob[start:end]
    try:
        with ZipFile(io.BytesIO(raw)) as zf:
            names = zf.namelist()
            bad = zf.testzip()
            if bad is not None:
                return None
    except (BadZipFile, RuntimeError, OSError, zlib.error):
        return None
    return start, end, names


def jar_name_stats(names: list[str]) -> tuple[int, int, int, int]:
    lowered = [n.lower() for n in names]
    class_count = sum(1 for n in lowered if Path(n).suffix == ".class")
    asset_count = sum(1 for n in lowered if Path(n).suffix in ASSET_EXTS or n.startswith(("assets/", "resources/")))
    java_hint_count = class_count + sum(1 for n in names if n in JAVA_HINT_FILES)
    score = java_hint_count * 4 + asset_count * 2 + min(len(names), 20)
    return class_count, asset_count, java_hint_count, score


def infer_jar_name(names: list[str], class_count: int, asset_count: int) -> str:
    lowered = [n.lower() for n in names]
    if any(n.startswith("resources/textures/") for n in lowered):
        base = "java_resources"
    elif any(n.startswith("assets/") for n in lowered):
        base = "java_assets"
    else:
        packages = [n.split("/", 1)[0] for n in names if n.endswith(".class") and "/" in n]
        if packages:
            base = f"java_{packages[0]}"
        else:
            base = "java_archive"
    return safe_artifact_stem(f"{base}_classes{class_count}_assets{asset_count}", "java_archive")


def ntfs_collision_info(names: list[str]) -> tuple[int, list[str]]:
    seen: dict[str, str] = {}
    examples: list[str] = []
    collisions = 0
    for name in names:
        used: set[str] = set()
        rel = ntfs_safe_relpath(name, used)
        key = str(rel).replace("\\", "/").casefold()
        if key in seen:
            collisions += 1
            if len(examples) < 20:
                examples.append(f"{seen[key]} <-> {name}")
        else:
            seen[key] = name
    return collisions, examples


def parse_pe(blob: bytes, off: int) -> PeCandidate | None:
    if off + 0x100 > len(blob) or blob[off : off + 2] != MZ_SIG:
        return None
    try:
        peoff = u32(blob, off + 0x3C)
    except struct.error:
        return None
    if peoff < 0x40 or peoff > 0x1000 or off + peoff + 0x108 > len(blob):
        return None
    if blob[off + peoff : off + peoff + 4] != b"PE\x00\x00":
        return None
    machine = u16(blob, off + peoff + 4)
    sections = u16(blob, off + peoff + 6)
    characteristics = u16(blob, off + peoff + 22)
    opt_size = u16(blob, off + peoff + 20)
    if sections <= 0 or sections > 96 or opt_size < 0x60:
        return None
    opt = off + peoff + 24
    magic = u16(blob, opt)
    if magic == 0x10B:
        image_base = u32(blob, opt + 28)
        size_of_image = u32(blob, opt + 56)
    elif magic == 0x20B:
        image_base = u64(blob, opt + 24)
        size_of_image = u32(blob, opt + 56)
    else:
        return None
    size_headers = u32(blob, opt + 60)
    if size_of_image < 0x1000 or size_of_image > 512 * 1024 * 1024 or off + min(size_of_image, 0x1000) > len(blob):
        return None
    sec_table = opt + opt_size
    if sec_table + sections * 40 > len(blob):
        return None
    if size_headers <= 0 or size_headers > size_of_image:
        size_headers = min(0x1000, size_of_image)
    return PeCandidate(off, size_of_image, machine, sections, image_base, characteristics, bool(characteristics & 0x2000))


def pe_section_rows(blob: bytes, off: int, cand: PeCandidate) -> list[dict]:
    peoff = u32(blob, off + 0x3C)
    opt_size = u16(blob, off + peoff + 20)
    opt = off + peoff + 24
    sec_table = opt + opt_size
    rows = []
    for i in range(cand.sections):
        so = sec_table + i * 40
        rows.append(
            {
                "name": blob[so : so + 8].split(b"\x00", 1)[0].decode("ascii", "ignore"),
                "vsize": u32(blob, so + 8),
                "va": u32(blob, so + 12),
                "raw_size": u32(blob, so + 16),
                "raw_ptr": u32(blob, so + 20),
            }
        )
    return rows


def pe_file_size_from_headers(blob: bytes, off: int, cand: PeCandidate) -> int:
    peoff = u32(blob, off + 0x3C)
    opt = off + peoff + 24
    size_headers = u32(blob, opt + 60)
    max_file_size = max(size_headers, 0x400)
    for row in pe_section_rows(blob, off, cand):
        raw_ptr = row["raw_ptr"]
        raw_size = row["raw_size"]
        if raw_ptr and raw_size:
            max_file_size = max(max_file_size, raw_ptr + raw_size)
    return min(max_file_size, 512 * 1024 * 1024)


def carve_raw_pe(blob: bytes, cand: PeCandidate) -> bytes:
    size = min(pe_file_size_from_headers(blob, cand.offset, cand), len(blob) - cand.offset)
    return blob[cand.offset : cand.offset + size]


def reconstruct_pe(blob: bytes, cand: PeCandidate) -> bytes:
    off = cand.offset
    peoff = u32(blob, off + 0x3C)
    opt = off + peoff + 24
    size_headers = min(u32(blob, opt + 60), cand.size_of_image, len(blob) - off)
    sections = pe_section_rows(blob, off, cand)
    max_file_size = pe_file_size_from_headers(blob, off, cand)
    out = bytearray(max_file_size)
    out[:size_headers] = blob[off : off + size_headers]
    for row in sections:
        va = row["va"]
        vsize = row["vsize"]
        raw_size = row["raw_size"]
        raw_ptr = row["raw_ptr"]
        if not raw_size or not raw_ptr or va >= cand.size_of_image:
            continue
        take = min(raw_size, vsize if vsize else raw_size, cand.size_of_image - va, len(blob) - (off + va))
        if take > 0 and raw_ptr + take <= len(out):
            out[raw_ptr : raw_ptr + take] = blob[off + va : off + va + take]
    return bytes(out)


def pe_score(data: bytes) -> int:
    try:
        if len(data) < 0x100 or data[:2] != MZ_SIG:
            return -1000
        peoff = u32(data, 0x3C)
        if peoff < 0x40 or peoff + 0x108 > len(data) or data[peoff : peoff + 4] != b"PE\x00\x00":
            return -1000
        sections = u16(data, peoff + 6)
        opt_size = u16(data, peoff + 20)
        opt = peoff + 24
        magic = u16(data, opt)
        if magic not in (0x10B, 0x20B) or sections <= 0 or sections > 96:
            return -1000
        size_image = u32(data, opt + 56)
        size_headers = u32(data, opt + 60)
        number_rva_and_sizes = u32(data, opt + (92 if magic == 0x10B else 108))
        data_dir = opt + (96 if magic == 0x10B else 112)
        sec_table = opt + opt_size
        if size_headers > len(data) or sec_table + sections * 40 > len(data):
            return -1000
        rows = []
        score = 20
        for i in range(sections):
            so = sec_table + i * 40
            name = data[so : so + 8].split(b"\x00", 1)[0]
            vsize = u32(data, so + 8)
            va = u32(data, so + 12)
            raw_size = u32(data, so + 16)
            raw_ptr = u32(data, so + 20)
            rows.append((va, max(vsize, raw_size), raw_ptr, raw_size))
            if name and all(32 <= c < 127 for c in name):
                score += 2
            if raw_size and raw_ptr + raw_size <= len(data):
                score += 3
                sample = data[raw_ptr : raw_ptr + min(raw_size, 512)]
                if any(sample):
                    score += 2
            elif raw_size:
                score -= 40

        def rva_to_off(rva: int) -> int | None:
            for va, span, raw_ptr, raw_size in rows:
                if raw_ptr and va <= rva < va + span:
                    delta = rva - va
                    if delta < raw_size:
                        return raw_ptr + delta
            if rva < size_headers:
                return rva
            return None

        if number_rva_and_sizes > 1 and data_dir + 16 <= len(data):
            imp_rva, imp_size = u32(data, data_dir + 8), u32(data, data_dir + 12)
            if imp_rva and imp_size:
                imp_off = rva_to_off(imp_rva)
                if imp_off is None or imp_off + 20 > len(data):
                    score -= 60
                else:
                    good_imports = 0
                    for i in range(64):
                        desc = imp_off + i * 20
                        if desc + 20 > len(data):
                            break
                        vals = struct.unpack_from("<IIIII", data, desc)
                        if vals == (0, 0, 0, 0, 0):
                            break
                        name_off = rva_to_off(vals[3])
                        if name_off is not None and name_off < len(data):
                            end = data.find(b"\x00", name_off, min(len(data), name_off + 260))
                            dll_name = data[name_off:end].lower() if end != -1 else b""
                            if dll_name.endswith(b".dll"):
                                good_imports += 1
                    score += min(good_imports, 12) * 8
                    if good_imports == 0:
                        score -= 20
        if number_rva_and_sizes > 0 and data_dir + 8 <= len(data):
            exp_rva = u32(data, data_dir)
            if exp_rva:
                exp_off = rva_to_off(exp_rva)
                if exp_off is not None and exp_off + 40 <= len(data):
                    score += 10
        return score
    except (struct.error, ValueError):
        return -1000


def best_pe_bytes(blob: bytes, cand: PeCandidate, prefer_mapped: bool) -> tuple[bytes, str, int]:
    mapped = reconstruct_pe(blob, cand)
    raw = carve_raw_pe(blob, cand)
    mapped_score = pe_score(mapped)
    raw_score = pe_score(raw)
    if prefer_mapped:
        mapped_score += 15
    if raw_score > mapped_score:
        return raw, "raw", raw_score
    return mapped, "mapped", mapped_score


def carve_png(blob: bytes, off: int) -> bytes | None:
    end = blob.find(b"IEND\xaeB`\x82", off + len(PNG_SIG))
    if end == -1:
        return None
    end += 8
    if end - off < 32 or end - off > 64 * 1024 * 1024:
        return None
    return blob[off:end]


def carve_jpeg(blob: bytes, off: int) -> bytes | None:
    end = blob.find(b"\xff\xd9", off + 3)
    if end == -1:
        return None
    end += 2
    if end - off < 32 or end - off > 64 * 1024 * 1024:
        return None
    return blob[off:end]


def carve_webp(blob: bytes, off: int) -> bytes | None:
    if off + 12 > len(blob) or blob[off + 8 : off + 12] != b"WEBP":
        return None
    size = u32(blob, off + 4) + 8
    if size < 20 or size > 64 * 1024 * 1024 or off + size > len(blob):
        return None
    return blob[off : off + size]


def carve_gif(blob: bytes, off: int) -> bytes | None:
    end = blob.find(b"\x00\x3b", off + 13)
    if end == -1:
        end = blob.find(b"\x3b", off + 13)
    if end == -1:
        return None
    end += 1
    if end - off < 16 or end - off > 64 * 1024 * 1024:
        return None
    return blob[off:end]


def write_report(out_dir: Path, jars: list[JarCandidate], dlls: list[PeCandidate], assets: list[dict]) -> None:
    report = {
        "jars": [cand.__dict__ | {"entries": [e.name for e in cand.entries[:200]]} for cand in jars],
        "dlls": [cand.__dict__ for cand in dlls],
        "assets": assets,
    }
    (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    with (out_dir / "report.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["type", "offset_hex", "output", "sha256", "details"])
        for cand in jars:
            writer.writerow(
                [
                    "jar",
                    f"0x{cand.start:x}",
                    cand.output,
                    cand.sha256,
                    f"entries={len(cand.entries)} classes={cand.class_count} assets={cand.asset_count} score={cand.score}",
                ]
            )
        for cand in dlls:
            writer.writerow(
                [
                    "dll",
                    f"0x{cand.offset:x}",
                    cand.output,
                    cand.sha256,
                    f"image=0x{cand.size_of_image:x} machine=0x{cand.machine:x} path={cand.module_path}",
                ]
            )
        for asset in assets:
            writer.writerow(["asset", f"0x{asset['offset']:x}", asset["output"], asset["sha256"], asset["kind"]])


def extract_assets_from_jar(jar_path: Path, asset_dir: Path, jar_label: str, assets: list[dict]) -> None:
    used_paths: set[str] = set()
    with ZipFile(jar_path) as zf:
        for info in zf.infolist():
            name = safe_name(info.filename)
            suffix = Path(name.lower()).suffix
            if suffix not in ASSET_EXTS and not name.lower().startswith(("assets/", "resources/")):
                continue
            if info.is_dir() or info.file_size > 64 * 1024 * 1024:
                continue
            data = zf.read(info)
            digest = sha256_bytes(data)
            rel = Path(jar_label) / ntfs_safe_relpath(name, used_paths)
            out_path = asset_dir / rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(data)
            assets.append(
                {
                    "kind": f"jar:{suffix.lstrip('.') or 'asset'}",
                    "offset": 0,
                    "size": len(data),
                    "sha256": digest,
                    "output": str(out_path),
                    "source": str(jar_path),
                    "original_name": info.filename,
                }
            )


def extract_all_entries_from_jar(jar_path: Path, entries_dir: Path, jar_label: str) -> dict:
    root = entries_dir / jar_label
    used_paths: set[str] = set()
    mapping = []
    collisions = 0
    with ZipFile(jar_path) as zf:
        for info in zf.infolist():
            if info.is_dir() or info.file_size > 256 * 1024 * 1024:
                continue
            original = safe_name(info.filename)
            rel = ntfs_safe_relpath(original, used_paths)
            if str(rel).replace("\\", "/") != original:
                collisions += 1
            out_path = root / rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            data = zf.read(info)
            out_path.write_bytes(data)
            mapping.append(
                {
                    "original_name": info.filename,
                    "output": str(out_path),
                    "size": len(data),
                    "sha256": sha256_bytes(data),
                }
            )
    root.mkdir(parents=True, exist_ok=True)
    map_path = root / "extraction_map.json"
    map_path.write_text(json.dumps(mapping, indent=2), encoding="utf-8")
    return {"files": len(mapping), "renamed_for_ntfs": collisions, "map": str(map_path)}


def jar_output_path(jar_dir: Path, index: int, name_hint: str, offset: int, digest: str = "") -> Path:
    stem = safe_artifact_stem(name_hint, "java_archive")
    hash_part = f"_{digest[:8]}" if digest else ""
    return jar_dir / f"jar_{index:03d}_{stem}_off_{offset:08x}{hash_part}.jar"


def unique_output_path(path: Path) -> Path:
    if not path.exists():
        return path
    n = 2
    while True:
        candidate = path.with_name(f"{path.stem}_dup{n:03d}{path.suffix}")
        if not candidate.exists():
            return candidate
        n += 1


def pe_output_path(dll_dir: Path, index: int, cand: PeCandidate, digest: str) -> Path:
    raw_name = cand.name_hint or (Path(cand.module_path).name if cand.module_path else "")
    stem = safe_artifact_stem(raw_name, "anonymous_pe")
    suffix = ".dll" if cand.is_dll else ".exe"
    if raw_name.lower().endswith((".dll", ".exe")):
        suffix = Path(raw_name).suffix.lower()
    return dll_dir / f"{'dll' if cand.is_dll else 'pe'}_{index:03d}_{stem}_off_{cand.offset:08x}_{digest[:8]}{suffix}"


def carve(args: argparse.Namespace) -> int:
    dump = Path(args.dump)
    out_dir = Path(args.out)
    jar_dir = out_dir / "jars"
    dll_dir = out_dir / "dlls"
    asset_dir = out_dir / "assets"
    entries_dir = out_dir / "jar_entries"
    for d in (jar_dir, dll_dir, asset_dir):
        d.mkdir(parents=True, exist_ok=True)
    if args.extract_all_jar_entries:
        entries_dir.mkdir(parents=True, exist_ok=True)

    blob = dump.read_bytes()
    modules, ranges = parse_minidump_modules(blob)
    print(f"[+] loaded {dump} ({len(blob):,} bytes)")
    if modules:
        print(f"[+] minidump modules: {len(modules):,}; memory ranges: {len(ranges):,}")

    jars: list[JarCandidate] = []
    rejected_jars: list[JarCandidate] = []
    assets: list[dict] = []
    seen_jar_hashes: set[str] = set()
    covered_zip_ranges: list[tuple[int, int]] = []

    eocd_offsets = [m.start() for m in re.finditer(re.escape(EOCD_ZIP), blob)]
    print(f"[+] ZIP EOCD signatures: {len(eocd_offsets):,}")
    for eocd_off in eocd_offsets:
        parsed = parse_eocd_zip(blob, eocd_off)
        if not parsed:
            continue
        start, end, names = parsed
        class_count, asset_count, java_hint_count, score = jar_name_stats(names)
        cand = JarCandidate(start=start, end=end)
        cand.class_count = class_count
        cand.asset_count = asset_count
        cand.java_hint_count = java_hint_count
        cand.score = score
        cand.name_hint = infer_jar_name(names, class_count, asset_count)
        cand.ntfs_collision_count, cand.ntfs_collision_examples = ntfs_collision_info(names)
        if len(names) < 2:
            cand.reason = "too few ZIP entries"
        elif java_hint_count == 0:
            cand.reason = "no Java/class/mod metadata entries"
        elif asset_count == 0:
            cand.reason = "no bundled asset entries"
        if cand.reason:
            rejected_jars.append(cand)
            continue
        raw = blob[start:end]
        digest = sha256_bytes(raw)
        if digest in seen_jar_hashes:
            cand.reason = "duplicate EOCD-backed archive"
            rejected_jars.append(cand)
            covered_zip_ranges.append((start, end))
            continue
        seen_jar_hashes.add(digest)
        out_path = unique_output_path(jar_output_path(jar_dir, len(jars), cand.name_hint, start, digest))
        out_path.write_bytes(raw)
        cand.sha256 = digest
        cand.output = str(out_path)
        cand.entries = [ZipEntry(name=n, method=0, flags=0, crc=0, comp_size=0, uncomp_size=0, header_offset=0, data_offset=0, end_offset=0) for n in names[:500]]
        if not args.no_jar_assets:
            extract_assets_from_jar(out_path, asset_dir, out_path.stem, assets)
        if args.extract_all_jar_entries:
            extract_all_entries_from_jar(out_path, entries_dir, out_path.stem)
        jars.append(cand)
        covered_zip_ranges.append((start, end))

    zip_offsets = [m.start() for m in re.finditer(re.escape(LOCAL_ZIP), blob)]
    print(f"[+] ZIP local-header signatures: {len(zip_offsets):,}")
    for off in zip_offsets:
        if any(start <= off < end for start, end in covered_zip_ranges):
            continue
        cand = parse_zip_run(blob, off, args.max_zip_entries, args.max_zip_size)
        if not cand:
            continue
        covered_zip_ranges.append((cand.start, cand.end))
        if cand.reason:
            rejected_jars.append(cand)
            continue
        cand.name_hint = infer_jar_name([entry.name for entry in cand.entries], cand.class_count, cand.asset_count)
        cand.ntfs_collision_count, cand.ntfs_collision_examples = ntfs_collision_info([entry.name for entry in cand.entries])
        out_path = unique_output_path(jar_output_path(jar_dir, len(jars), cand.name_hint, cand.start))
        try:
            digest = rebuild_jar(cand, out_path)
        except Exception as exc:
            cand.reason = f"rebuild failed: {exc}"
            rejected_jars.append(cand)
            if out_path.exists():
                out_path.unlink()
            continue
        if digest in seen_jar_hashes:
            out_path.unlink()
            cand.reason = "duplicate rebuilt archive"
            rejected_jars.append(cand)
            continue
        seen_jar_hashes.add(digest)
        final_path = unique_output_path(jar_output_path(jar_dir, len(jars), cand.name_hint, cand.start, digest))
        if final_path != out_path:
            out_path.replace(final_path)
            out_path = final_path
        cand.sha256 = digest
        cand.output = str(out_path)
        if not args.no_jar_assets:
            extract_assets_from_jar(out_path, asset_dir, out_path.stem, assets)
        if args.extract_all_jar_entries:
            extract_all_entries_from_jar(out_path, entries_dir, out_path.stem)
        jars.append(cand)

    dlls: list[PeCandidate] = []
    rejected_dlls: list[PeCandidate] = []
    seen_dll_hashes: set[str] = set()
    seen_dll_identities: set[tuple[str, int, int]] = set()
    mz_offsets = [m.start() for m in re.finditer(re.escape(MZ_SIG), blob)]
    print(f"[+] MZ signatures: {len(mz_offsets):,}")
    for off in mz_offsets:
        cand = parse_pe(blob, off)
        if not cand:
            continue
        module = module_for_file_offset(off, modules, ranges)
        if module:
            cand.module_path = module.get("path", "")
        if not cand.is_dll and not args.all_pe:
            cand.reason = "PE image is not a DLL"
            rejected_dlls.append(cand)
            continue
        raw_image = blob[off : min(len(blob), off + cand.size_of_image)]
        cand.name_hint, cand.third_party_hints = infer_pe_identity(cand.module_path, raw_image)
        cand.is_windows_noise, cand.reason = looks_windows_noise(cand.module_path, raw_image, cand.third_party_hints)
        if cand.is_windows_noise and not args.keep_windows_dlls:
            rejected_dlls.append(cand)
            continue
        identity_name = (cand.name_hint or Path(cand.module_path).name or "").lower()
        if identity_name and cand.third_party_hints and not cand.module_path:
            identity = (identity_name, cand.size_of_image, cand.machine)
            if identity in seen_dll_identities:
                cand.reason = "duplicate anonymous third-party DLL image"
                rejected_dlls.append(cand)
                continue
            seen_dll_identities.add(identity)
        pe_file, cand.extraction_mode, cand.pe_score = best_pe_bytes(blob, cand, prefer_mapped=module is not None)
        if cand.pe_score < args.min_pe_score:
            cand.reason = f"reconstructed PE failed structural score ({cand.pe_score} < {args.min_pe_score})"
            rejected_dlls.append(cand)
            continue
        digest = sha256_bytes(pe_file)
        if digest in seen_dll_hashes:
            cand.reason = "duplicate PE"
            rejected_dlls.append(cand)
            continue
        seen_dll_hashes.add(digest)
        out_path = unique_output_path(pe_output_path(dll_dir, len(dlls), cand, digest))
        out_path.write_bytes(pe_file)
        cand.sha256 = digest
        cand.output = str(out_path)
        dlls.append(cand)

    if args.loose_assets:
        asset_specs = [
            ("png", PNG_SIG, carve_png),
            ("jpg", JPEG_SIG, carve_jpeg),
            ("gif", GIF87, carve_gif),
            ("gif", GIF89, carve_gif),
            ("webp", WEBP_SIG, carve_webp),
        ]
        seen_assets: set[str] = set()
        for kind, sig, fn in asset_specs:
            for match in re.finditer(re.escape(sig), blob):
                off = match.start()
                data = fn(blob, off)
                if not data:
                    continue
                digest = sha256_bytes(data)
                if digest in seen_assets:
                    continue
                seen_assets.add(digest)
                out_path = asset_dir / f"{kind}_{len(assets):04d}_off_{off:08x}.{kind}"
                out_path.write_bytes(data)
                assets.append({"kind": kind, "offset": off, "size": len(data), "sha256": digest, "output": str(out_path)})

    if args.keep_rejects:
        (out_dir / "rejected_jars.json").write_text(
            json.dumps(
                [
                    {
                        "offset": cand.start,
                        "end": cand.end,
                        "entries": len(cand.entries),
                        "class_count": cand.class_count,
                        "asset_count": cand.asset_count,
                        "reason": cand.reason,
                    }
                    for cand in rejected_jars
                ],
                indent=2,
            ),
            encoding="utf-8",
        )
        (out_dir / "rejected_dlls.json").write_text(
            json.dumps([cand.__dict__ for cand in rejected_dlls], indent=2), encoding="utf-8"
        )

    write_report(out_dir, jars, dlls, assets)
    print(f"[+] carved JARs: {len(jars)}")
    print(f"[+] carved DLLs: {len(dlls)} ({len(rejected_dlls)} Windows/noise/dupe candidates skipped)")
    print(f"[+] carved/extracted assets: {len(assets)}")
    print(f"[+] report: {out_dir / 'report.json'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Carve useful JAR/assets/DLL artifacts from a Windows Task Manager minidump.")
    parser.add_argument("dump", help="Input .dmp file")
    parser.add_argument("-o", "--out", default="carved", help="Output directory")
    parser.add_argument("--all-pe", action="store_true", help="Carve non-DLL PE images too, such as the dumped process EXE")
    parser.add_argument("--min-pe-score", type=int, default=0, help="Reject reconstructed PE files below this structural score")
    parser.add_argument("--keep-windows-dlls", action="store_true", help="Also output Microsoft/Windows system DLLs")
    parser.add_argument("--no-jar-assets", action="store_true", help="Do not extract asset files from recovered JARs")
    parser.add_argument("--extract-all-jar-entries", action="store_true", help="Extract every JAR entry with NTFS-safe collision handling and an extraction map")
    parser.add_argument("--loose-assets", action="store_true", help="Carve loose PNG/JPEG/GIF/WebP blobs outside rebuilt JARs")
    parser.add_argument("--keep-rejects", action="store_true", help="Write JSON files explaining rejected candidates")
    parser.add_argument("--max-zip-size", type=int, default=128 * 1024 * 1024, help="Maximum bytes to scan for one ZIP/JAR run")
    parser.add_argument("--max-zip-entries", type=int, default=20000, help="Maximum local headers to consume for one ZIP/JAR run")
    args = parser.parse_args(argv)
    return carve(args)


if __name__ == "__main__":
    raise SystemExit(main())
