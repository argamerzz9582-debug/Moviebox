"""Deep static triage for packed / repacked Android APKs (own-code implementation).

``apk_analyzer`` answers *what is this APK and what does it claim to do*; this
module answers the harder question an RE workflow actually needs: **is the code
I can see the real code?** It does that with three evidence passes:

1. **DEX table accounting** - parse the header + ``map_list`` and compare the
   byte span the tables describe against the file size. A DEX whose tables end
   at 26 KiB inside a 61 MiB file is a shell, not code. This is measured, not
   guessed, and it is the cheapest reliable unpacking indicator.
2. **Packer fingerprinting** - artifact names, class prefixes and embedded
   strings matched against a signature table (iJiami, 360 Jiagu, Legu, Bangcle,
   ...), each hit reported with its evidence and a confidence label.
3. **Payload classification** - every non-code asset is sampled, hashed,
   entropy-scored and classified (ELF / packed ELF / numeric-tag container /
   high-entropy ciphertext), so hidden natives and encrypted overlays surface.

Parsing rules that matter (learned the hard way, kept here so they are not
re-derived): ``uleb128`` lengths in ``string_data_item`` are the *UTF-16 unit*
count, not a byte count; ``proto_ids``/``field_ids``/``method_ids`` may have
offsets that point into missing tables; ``map_list`` is the only trustworthy
inventory of what a stripped DEX really contains. Nothing here executes or
even runs a disassembler over APK bytes, and every string from the APK is
handled as untrusted data, never as an instruction.

Usage::

    from rex.adapters.apk_deep import analyze_deep, write_deep_report
    report = analyze_deep(Path("movie.apk"))
    write_deep_report(report, Path("out/"))
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

MAX_LIST = 80
MAX_STRINGS = 300_000
MAX_BLOB_SAMPLE = 4 * 1024 * 1024
#: Assets above this entropy are treated as ciphertext / compressed payload.
HIGH_ENTROPY = 7.5
#: Sample size used when looking for embedded markers inside a large asset.
MARKER_WINDOW = 8 * 1024 * 1024

DEX_MAGIC = re.compile(rb"dex\n(\d{3})\x00")

URL_IN_STRING = re.compile(r"https?://[^\s\"'<>]{4,200}")
HOST_IN_STRING = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|cn|tv|cc|me|in|co)$")
HEADER_IN_STRING = re.compile(r"^(?:X|x)-[A-Za-z][A-Za-z0-9-]{1,40}$")
ENDPOINT_IN_STRING = re.compile(r"^/[A-Za-z0-9][A-Za-z0-9/_.\-{}]{3,120}$")

#: DEX ``map_list`` item types (Dalvik executables spec, ``map_item``).
MAP_TYPES: Dict[int, str] = {
    0x0000: "header_item",
    0x0001: "string_id_item",
    0x0002: "type_id_item",
    0x0003: "proto_id_item",
    0x0004: "field_id_item",
    0x0005: "method_id_item",
    0x0006: "class_def_item",
    0x0007: "call_site_id_item",
    0x0008: "method_handle_item",
    0x1000: "map_list",
    0x1001: "type_list",
    0x1002: "annotation_set_ref_list",
    0x1003: "annotation_set_item",
    0x2000: "class_data_item",
    0x2001: "code_item",
    0x2002: "string_data_item",
    0x2003: "debug_info_item",
    0x2004: "annotation_item",
    0x2005: "encoded_array_item",
    0x2006: "annotations_directory_item",
}

#: Packer fingerprints: label -> (entry-name markers, class/string markers).
#: A signature needs at least one entry-name hit to be considered *structural*.
PACKER_SIGNATURES: Sequence[Tuple[str, Tuple[str, ...], Tuple[str, ...]]] = (
    ("iJiami (爱加密)", ("assets/hx.classes", "assets/hx.code", "assets/hx.cer", "libhxpatch.so",
                         "assets/labresencscfg"),
     ("com/ijiami", "hxreborn/ijiami", "ijiami SecLLVM", "ijiami.dat")),
    ("360 Jiagu (梆梆/加固)", ("libjiagu.so", "libjiagu_art.so", "assets/libjiagu.so"),
     ("com/qihoo/util", "StubApp", "com.qihoo360")),
    ("Tencent Legu (乐固)", ("libshella.so", "libshellx.so", "assets/0OO00l111l1l"),
     ("com/tencent/StubShell", "com/tencent/legu")),
    ("Bangcle / SecNeo", ("libsecexe.so", "libsecmain.so", "libsecshell.so"),
     ("com/secneo/apkwrapper", "SecShell")),
    ("Baidu Protect", ("libbaiduprotect.so",), ("com/baidu/protect", "BaiduProtect")),
    ("Alibaba Mobile Security", ("libmobisec.so", "libzuma.so"), ("com/ali/mobisecenhance",)),
    ("UPX (native only)", (), ("$Info: This file is packed with the UPX", "UPX!")),
)

#: Community patch frameworks that ship their own DEX into the APK assets.
PATCH_FRAMEWORKS: Sequence[Tuple[str, Tuple[str, ...]]] = (
    ("hxreborn/morphe MovieBox patch", ("hxreborn/moviebox", "hx/AppPatch", "hx/source/MovieBoxSource")),
    ("ReVanced-style patch", ("app/revanced/", "revanced")),
    ("Morphe patch runtime", ("app/morphe/", "morphe-patches")),
)


# --------------------------------------------------------------------------- #
# data model
# --------------------------------------------------------------------------- #
@dataclass
class Evidence:
    """A single claim plus the method that produced it."""

    name: str
    detail: str
    confidence: str
    tool: str


@dataclass
class DexIndex:
    """Structural index of one ``classes*.dex`` payload."""

    name: str
    size: int
    version: int = 0
    map_items: List[Dict[str, Any]] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    table_end: int = 0
    parsed: bool = True
    error: str = ""

    @property
    def dark_bytes(self) -> int:
        """Bytes the DEX tables do not describe - payload space for a packer."""
        if not self.parsed:
            return 0
        return max(0, self.size - self.table_end)

    @property
    def dark_ratio(self) -> float:
        return (self.dark_bytes / self.size) if self.size else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "size": self.size,
            "version": self.version,
            "parsed": self.parsed,
            "error": self.error,
            "classes": len(self.classes),
            "strings": len(self.strings),
            "table_end": self.table_end,
            "dark_bytes": self.dark_bytes,
            "dark_ratio": round(self.dark_ratio, 4),
            "map_items": self.map_items,
            "class_list": self.classes[:MAX_LIST],
        }


@dataclass
class BlobInfo:
    """A non-code asset with its classification."""

    path: str
    size: int
    entropy: float
    kind: str
    detail: str
    sha256: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "entropy": round(self.entropy, 3),
            "kind": self.kind,
            "detail": self.detail,
            "sha256": self.sha256,
        }


@dataclass
class DeepReport:
    """Result of a deep static triage run."""

    apk: str
    sha256: str
    size: int
    entries: int
    packers: List[Dict[str, Any]] = field(default_factory=list)
    patch_frameworks: List[Dict[str, Any]] = field(default_factory=list)
    dexes: List[DexIndex] = field(default_factory=list)
    blobs: List[BlobInfo] = field(default_factory=list)
    clusters: Dict[str, List[str]] = field(default_factory=dict)
    findings: List[Evidence] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "apk": self.apk,
            "sha256": self.sha256,
            "size": self.size,
            "entries": self.entries,
            "packers": self.packers,
            "patch_frameworks": self.patch_frameworks,
            "dexes": [d.to_dict() for d in self.dexes],
            "blobs": [b.to_dict() for b in self.blobs],
            "clusters": self.clusters,
            "findings": [f.__dict__ for f in self.findings],
            "limitations": self.limitations,
        }


# --------------------------------------------------------------------------- #
# DEX parsing
# --------------------------------------------------------------------------- #
def _uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """Decode an unsigned LEB128 value; returns ``(value, next_offset)``."""
    result = 0
    shift = 0
    for i in range(5):
        byte = data[offset + i]
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset + i + 1
        shift += 7
    raise ValueError("uleb128 longer than 5 bytes")


def _read_string(data: bytes, offset: int) -> str:
    """Read a ``string_data_item`` (uleb128 UTF-16 length + MUTF-8 bytes)."""
    _, start = _uleb128(data, offset)
    end = data.index(b"\x00", start)
    raw = data[start:end]
    # MUTF-8 differs from UTF-8 only for surrogates; replacement keeps it total.
    return raw.decode("utf-8", errors="replace")


def parse_dex_index(data: bytes, name: str = "classes.dex") -> DexIndex:
    """Index one DEX: version, map table, class descriptors, string pool.

    Never raises for malformed input - the failure is recorded on the index so
    a damaged/encrypted DEX shows up as evidence rather than an exception.
    """
    index = DexIndex(name=name, size=len(data))
    match = DEX_MAGIC.match(data)
    if not match:
        index.parsed = False
        index.error = "not a DEX (bad magic)"
        return index
    try:
        index.version = int(match.group(1))
        if len(data) < 0x70:
            raise ValueError("truncated header")
        map_off = struct.unpack_from("<I", data, 0x34)[0]
        string_ids_size, string_ids_off = struct.unpack_from("<II", data, 0x38)
        type_ids_size, type_ids_off = struct.unpack_from("<II", data, 0x40)
        class_defs_size, class_defs_off = struct.unpack_from("<II", data, 0x60)

        # --- map_list: the authoritative inventory of a (possibly stripped) DEX
        entries: List[Tuple[int, int, int]] = []
        if map_off and map_off + 4 <= len(data):
            count = struct.unpack_from("<I", data, map_off)[0]
            for i in range(min(count, 64)):
                base = map_off + 4 + i * 12
                if base + 12 > len(data):
                    break
                item_type, _, item_count, item_off = struct.unpack_from("<HHII", data, base)
                entries.append((item_type, item_count, item_off))
            starts = sorted({off for _, _, off in entries if off})
            for item_type, item_count, item_off in entries:
                # A variable-length table ends where the next table begins.
                nxt = next((s for s in starts if s > item_off), len(data))
                span = _item_size(item_type, item_count, data, item_off, nxt)
                index.map_items.append(
                    {
                        "type": MAP_TYPES.get(item_type, f"0x{item_type:04x}"),
                        "count": item_count,
                        "offset": item_off,
                        "end": item_off + span,
                    }
                )
            if index.map_items:
                index.table_end = max(m["end"] for m in index.map_items)

        # --- strings (bounded; a packer shell has very few)
        for i in range(min(string_ids_size, MAX_STRINGS)):
            try:
                off = struct.unpack_from("<I", data, string_ids_off + i * 4)[0]
                index.strings.append(_read_string(data, off))
            except (struct.error, ValueError, IndexError):
                break

        # --- classes (class_def_item.class_idx -> type_id.descriptor_idx -> string)
        for i in range(min(class_defs_size, MAX_STRINGS)):
            try:
                pos = class_defs_off + i * 32
                class_idx = struct.unpack_from("<I", data, pos)[0]
                if class_idx >= type_ids_size:
                    continue
                string_idx = struct.unpack_from("<I", data, type_ids_off + class_idx * 4)[0]
                if string_idx < len(index.strings):
                    index.classes.append(index.strings[string_idx])
            except struct.error:
                break
    except (struct.error, ValueError, IndexError, KeyError) as exc:  # pragma: no cover - defensive
        index.parsed = False
        index.error = f"{type(exc).__name__}: {exc}"
    return index


def _item_size(item_type: int, count: int, data: bytes, offset: int, next_start: int) -> int:
    """Best-effort byte span of one map entry, used for the dark-byte estimate.

    Fixed-size items are exact. Variable-length items (``string_data_item``,
    ``code_item``, ``class_data_item``, ...) carry no length prefix, so they are
    measured from their start up to ``next_start`` - the following table, or EOF
    for the last one. Measuring them to EOF unconditionally would swallow the
    packer's payload and hide the very signal this module looks for.
    """
    fixed = {0x0000: 0x70, 0x0001: 4, 0x0002: 4, 0x0003: 12, 0x0004: 8, 0x0005: 8,
             0x0006: 32, 0x0007: 4, 0x0008: 8, 0x1000: 4 + 12 * count, 0x1002: 4, 0x1003: 4}
    if item_type in fixed:
        return fixed[item_type]
    return max(0, next_start - offset) if offset else 0


# --------------------------------------------------------------------------- #
# packer / patch fingerprinting
# --------------------------------------------------------------------------- #
def detect_packers(entry_names: Iterable[str], corpus: str) -> List[Dict[str, Any]]:
    """Match packer signatures; structural (file) hits outrank string-only hits."""
    names = set(entry_names)
    hits: List[Dict[str, Any]] = []
    for label, name_markers, text_markers in PACKER_SIGNATURES:
        name_hits = [m for m in name_markers if m in names]
        text_hits = [m for m in text_markers if m in corpus]
        if not name_hits and not text_hits:
            continue
        total = len(name_hits) + len(text_hits)
        if len(name_hits) >= 2 or (name_hits and total >= 3):
            confidence = "Confirmed"
        elif name_hits or total >= 2:
            confidence = "Strongly supported"
        else:
            confidence = "Possible"
        hits.append(
            {
                "packer": label,
                "confidence": confidence,
                "file_markers": name_hits[:MAX_LIST],
                "string_markers": text_hits[:MAX_LIST],
            }
        )
    hits.sort(key=lambda h: {"Confirmed": 0, "Strongly supported": 1, "Possible": 2}[h["confidence"]])
    return hits


def detect_patch_frameworks(class_names: Iterable[str], corpus: str) -> List[Dict[str, Any]]:
    """Identify community patch runtimes riding inside the APK."""
    classes = list(class_names)
    joined = "\n".join(classes)
    found: List[Dict[str, Any]] = []
    for label, markers in PATCH_FRAMEWORKS:
        hits = [m for m in markers if m in corpus or m.replace("/", ".") in corpus or m in joined]
        if not hits:
            continue
        found.append(
            {
                "framework": label,
                "confidence": "Confirmed" if len(hits) >= 2 else "Strongly supported",
                "markers": hits,
            }
        )
    return found


def cluster_strings(strings: Iterable[str]) -> Dict[str, List[str]]:
    """Group string-pool entries into the buckets an RE report actually cites."""
    buckets: Dict[str, List[str]] = {
        "urls": [], "hosts": [], "endpoints": [], "custom_headers": [], "api_paths": [],
    }
    seen: Dict[str, set] = {k: set() for k in buckets}
    for value in strings:
        if not value or len(value) > 300:
            continue
        for url in URL_IN_STRING.findall(value)[:3]:
            if url not in seen["urls"]:
                seen["urls"].add(url)
                buckets["urls"].append(url)
        if HOST_IN_STRING.match(value) and value not in seen["hosts"]:
            seen["hosts"].add(value)
            buckets["hosts"].append(value)
        if HEADER_IN_STRING.match(value) and value not in seen["custom_headers"]:
            seen["custom_headers"].add(value)
            buckets["custom_headers"].append(value)
        if ENDPOINT_IN_STRING.match(value) and value not in seen["endpoints"]:
            seen["endpoints"].add(value)
            buckets["endpoints"].append(value)
        if "/" in value and not value.startswith(("/", "L")) and re.match(r"^[a-z][\w-]*/[\w/.-]+$", value):
            if value not in seen["api_paths"]:
                seen["api_paths"].add(value)
                buckets["api_paths"].append(value)
    return {k: sorted(v)[:MAX_LIST] for k, v in buckets.items() if v}


# --------------------------------------------------------------------------- #
# asset classification
# --------------------------------------------------------------------------- #
def _entropy(sample: bytes) -> float:
    if not sample:
        return 0.0
    counts = Counter(sample)
    length = len(sample)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def classify_blob(name: str, data: bytes) -> BlobInfo:
    """Classify one asset: ELF, packed ELF, tagged container, ciphertext or text."""
    sample = data[:MAX_BLOB_SAMPLE]
    window = data[:MARKER_WINDOW]
    entropy = _entropy(sample)
    sha = hashlib.sha256(data).hexdigest()
    kind = "data"
    detail = ""
    head = data[:64]

    if head[:4] == b"\x7fELF":
        bits = "64" if len(head) > 4 and head[4] == 2 else "32"
        machine = int.from_bytes(head[18:20], "little") if len(head) >= 20 else 0
        arch = {0x28: "arm", 0xB7: "aarch64", 0x3E: "x86-64", 0x03: "x86"}.get(machine, f"machine={machine}")
        kind = "elf"
        detail = f"ELF{bits} {arch}"
        if b"UPX!" in window or b"UPX executable packer" in window:
            kind = "elf-packed"
            detail += ", UPX-packed"
        if "ijiami" in window[:MARKER_WINDOW].lower().decode("latin-1", "ignore"):
            detail += ", iJiami-hardened"
        if not name.startswith("lib/"):
            detail += ", stored outside lib/ (hidden native)"
    elif head[:4] == b"pro\x00" or head[:4] == b"pro.":
        # ART baseline/startup profile: legitimately high-entropy, not evidence.
        kind = "art-profile"
        detail = "ART baseline profile"
    elif head[:2] == b"PK":
        # A container magic outranks entropy: high entropy here just means the
        # nested entries are compressed, which is expected and not evidence.
        kind = "zip"
        detail = f"nested ZIP archive, entropy {entropy:.2f}"
    elif entropy >= HIGH_ENTROPY and len(data) > 4096:
        kind = "ciphertext-or-compressed"
        ascii_tag = "".join(chr(c) if 32 <= c < 127 else "." for c in head[:8])
        detail = f"entropy {entropy:.2f}, header {ascii_tag!r}"
    elif head[:1] in (b"{", b"[") or head.lstrip()[:1] in (b"{", b"["):
        kind = "json"
        detail = "JSON text"
    else:
        ascii_tag = "".join(chr(c) if 32 <= c < 127 else "." for c in head[:12])
        if sum(1 for c in sample[:4096] if 32 <= c < 127 or c in (9, 10, 13)) > len(sample[:4096]) * 0.9:
            kind = "text"
            detail = f"text, header {ascii_tag!r}"
        else:
            kind = "binary"
            detail = f"binary, header {ascii_tag!r}"
    return BlobInfo(path=name, size=len(data), entropy=entropy, kind=kind, detail=detail, sha256=sha)


def scan_blobs(zf: zipfile.ZipFile) -> List[BlobInfo]:
    """Classify assets that are *not* ordinary resources (skip images/fonts)."""
    skip = (".png", ".jpg", ".jpeg", ".webp", ".gif", ".ttf", ".otf", ".xml", ".json", ".html", ".js")
    results: List[BlobInfo] = []
    for info in zf.infolist():
        name = info.filename
        if info.is_dir() or not name.startswith("assets/"):
            continue
        if name.lower().endswith(skip) or name.startswith("assets/dexopt/"):
            continue  # dexopt/ holds ART profiles, not app payload
        try:
            data = zf.read(name)
        except (RuntimeError, zipfile.BadZipFile, KeyError):
            continue
        if len(data) < 512:  # tiny config stubs are listed by name only
            results.append(BlobInfo(path=name, size=len(data), entropy=_entropy(data),
                                    kind="small-config", detail="under 512 B, listed for completeness",
                                    sha256=hashlib.sha256(data).hexdigest()))
            continue
        results.append(classify_blob(name, data))
    results.sort(key=lambda b: b.size, reverse=True)
    return results


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #
def _verdict(report: DeepReport) -> None:
    """Derive the packing verdict + limitations from the collected evidence."""
    shells = [d for d in report.dexes if d.size > 1024 * 1024 and len(d.classes) < 50]
    if shells:
        for dex in shells:
            report.findings.append(
                Evidence(
                    name="dex-shell-detected",
                    detail=(
                        f"{dex.name}: {dex.size / 1048576:.1f} MiB file, only {len(dex.classes)} class definition(s) "
                        f"and {len(dex.strings)} string(s); DEX tables cover {dex.table_end / 1024:.0f} KiB "
                        f"({dex.dark_ratio:.1%} of the file unddescribed)"
                    ),
                    confidence="Confirmed",
                    tool="apk_deep.parse_dex_index + map_list accounting",
                )
            )
    confirmed = [p for p in report.packers if p["confidence"] == "Confirmed"]
    if confirmed:
        report.findings.append(
            Evidence(
                name="packer-identified",
                detail="; ".join(
                    f"{p['packer']} (files: {', '.join(p['file_markers'][:4]) or 'n/a'})" for p in confirmed
                ),
                confidence="Confirmed",
                tool="apk_deep.detect_packers",
            )
        )
    for framework in report.patch_frameworks:
        report.findings.append(
            Evidence(
                name="patch-framework",
                detail=f"{framework['framework']} markers: {', '.join(framework['markers'][:5])}",
                confidence=framework["confidence"],
                tool="apk_deep.detect_patch_frameworks",
            )
        )
    hidden = [b for b in report.blobs if b.kind in ("elf", "elf-packed") and not b.path.startswith("lib/")]
    if hidden:
        report.findings.append(
            Evidence(
                name="native-code-outside-lib",
                detail=f"{len(hidden)} ELF payload(s) in assets/: " + ", ".join(b.path for b in hidden[:6]),
                confidence="Confirmed",
                tool="apk_deep.classify_blob",
            )
        )
    opaque = [b for b in report.blobs if b.kind == "ciphertext-or-compressed"]
    if opaque:
        total = sum(b.size for b in opaque)
        report.findings.append(
            Evidence(
                name="encrypted-overlays",
                detail=f"{len(opaque)} high-entropy asset(s), {total / 1048576:.1f} MiB total: "
                       + ", ".join(f"{b.path} ({b.detail})" for b in opaque[:5]),
                confidence="Strongly supported",
                tool="apk_deep.classify_blob",
            )
        )
    if shells or confirmed:
        report.limitations.append(
            "Static analysis cannot recover the runtime-decrypted code: the real classes are materialised in "
            "memory by the packer after JNI_OnLoad, so class/method coverage from disk is a lower bound."
        )
        report.limitations.append(
            "Unpacking was not performed. A safe next step is a dynamic run on an isolated emulator "
            "(frida spawn-gating + memory DEX dump), which requires executing the sample."
        )
    report.limitations.append("Blob classification uses entropy and magic bytes; it does not prove encryption.")
    report.limitations.append("The DEX map table is trusted for table extents; forged map entries would skew the dark-byte ratio.")


def analyze_deep(apk: Path) -> DeepReport:
    """Run the deep triage pass over an APK and return a :class:`DeepReport`."""
    apk = Path(apk)
    digest = hashlib.sha256()
    with apk.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    report = DeepReport(apk=str(apk), sha256=digest.hexdigest(), size=apk.stat().st_size, entries=0)

    with zipfile.ZipFile(apk) as zf:
        names = zf.namelist()
        report.entries = len(names)

        dex_names = sorted(n for n in names if n.endswith(".dex"))
        corpus_parts: List[str] = []
        all_classes: List[str] = []
        all_strings: List[str] = []
        for dex_name in dex_names:
            try:
                data = zf.read(dex_name)
            except (RuntimeError, zipfile.BadZipFile):
                report.limitations.append(f"{dex_name} could not be decompressed (corrupt or oversized).")
                continue
            index = parse_dex_index(data, dex_name)
            report.dexes.append(index)
            all_classes.extend(index.classes)
            all_strings.extend(index.strings)
            corpus_parts.append("\n".join(index.strings))
            corpus_parts.append("\n".join(index.classes))

        report.blobs = scan_blobs(zf)

    corpus = "\n".join(corpus_parts + [b.path for b in report.blobs])
    report.packers = detect_packers(names, corpus)
    report.patch_frameworks = detect_patch_frameworks(all_classes, corpus)
    report.clusters = cluster_strings(all_strings)
    _verdict(report)
    return report


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #
def render_markdown(report: DeepReport) -> str:
    """Render a deep report as reviewable Markdown (bounded, evidence-first)."""
    lines: List[str] = []
    add = lines.append

    add("# Deep APK triage")
    add("")
    add(f"- **File**: `{report.apk}`")
    add(f"- **SHA-256**: `{report.sha256}`")
    add(f"- **Size**: {report.size:,} B ({report.size / 1048576:.1f} MiB)")
    add(f"- **ZIP entries**: {report.entries:,}")
    add("")

    add("## 1. Findings")
    add("")
    if report.findings:
        add("| Finding | Confidence | Evidence | Tool |")
        add("| --- | --- | --- | --- |")
        for item in report.findings:
            detail = item.detail.replace("|", "\\|")
            add(f"| `{item.name}` | {item.confidence} | {detail} | `{item.tool}` |")
    else:
        add("_No packing or patching indicators found._")
    add("")

    add("## 2. DEX table accounting")
    add("")
    add("| DEX | Size | Classes | Strings | Tables end | Undescribed | Share |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for dex in report.dexes:
        add(
            f"| `{dex.name}` | {dex.size:,} B | {len(dex.classes)} | {len(dex.strings)} | "
            f"{dex.table_end:,} B | {dex.dark_bytes:,} B | {dex.dark_ratio:.1%} |"
        )
    add("")
    for dex in report.dexes:
        if not dex.map_items:
            continue
        add(f"<details><summary>{dex.name} map_list</summary>")
        add("")
        add("| Type | Count | Offset |")
        add("| --- | ---: | ---: |")
        for item in dex.map_items:
            add(f"| {item['type']} | {item['count']:,} | {item['offset']:,} |")
        add("")
        add("</details>")
        add("")

    add("## 3. Packer / patch fingerprints")
    add("")
    if report.packers:
        for packer in report.packers:
            add(f"### {packer['packer']} - {packer['confidence']}")
            if packer["file_markers"]:
                add(f"- File markers: {', '.join(f'`{m}`' for m in packer['file_markers'])}")
            if packer["string_markers"]:
                add(f"- Text markers: {', '.join(f'`{m}`' for m in packer['string_markers'])}")
            add("")
    else:
        add("_No known packer signature matched._")
        add("")
    for framework in report.patch_frameworks:
        add(f"- **Patch runtime**: {framework['framework']} ({framework['confidence']}) - "
            + ", ".join(f"`{m}`" for m in framework["markers"]))
    if report.patch_frameworks:
        add("")

    add("## 4. Classes by package")
    add("")
    packages: Counter = Counter()
    for dex in report.dexes:
        for cls in dex.classes:
            packages["/".join(cls.strip("L;").split("/")[:2])] += 1
    for pkg, count in packages.most_common(30):
        add(f"- `{pkg}` - {count}")
    add("")

    if report.clusters:
        add("## 5. String clusters")
        add("")
        titles = {
            "urls": "URLs", "hosts": "Hosts", "endpoints": "Endpoints",
            "custom_headers": "Custom headers", "api_paths": "API paths",
        }
        for key, values in report.clusters.items():
            add(f"**{titles.get(key, key)}** ({len(values)})")
            add("")
            for value in values:
                add(f"- `{value}`")
            add("")

    add("## 6. Assets by classification")
    add("")
    add("| Asset | Size | Entropy | Kind | Detail |")
    add("| --- | ---: | ---: | --- | --- |")
    for blob in report.blobs[:MAX_LIST]:
        add(f"| `{blob.path}` | {blob.size:,} B | {blob.entropy:.2f} | {blob.kind} | {blob.detail} |")
    add("")

    add("## 7. Limitations")
    add("")
    for note in report.limitations:
        add(f"- {note}")
    add("")
    return "\n".join(lines)


def write_deep_report(report: DeepReport, out_dir: Path) -> Dict[str, str]:
    """Write ``deep_report.md`` + ``deep_report.json``; returns the paths written."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / "deep_report.md"
    json_path = out_dir / "deep_report.json"
    md_path.write_text(render_markdown(report), encoding="utf-8")
    json_path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return {"markdown": str(md_path), "json": str(json_path)}
