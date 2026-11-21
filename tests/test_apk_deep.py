"""Tests for :mod:`rex.adapters.apk_deep` (packed-APK deep triage).

The fixtures build real, minimal DEX containers and real ZIP APKs so the module
is exercised against bytes rather than mocks. No sample from the internet is
used and nothing is executed.
"""
from __future__ import annotations

import io
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from rex.adapters.apk_deep import (
    analyze_deep,
    classify_blob,
    cluster_strings,
    detect_packers,
    detect_patch_frameworks,
    parse_dex_index,
    render_markdown,
    write_deep_report,
)


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _string_item(text: str) -> bytes:
    """string_data_item: uleb128(utf16 units) + MUTF-8 + NUL."""
    body = text.encode("utf-8")
    return _uleb(len(text)) + body + b"\x00"


def build_dex(strings=("Lcom/demo/Real;", "Lcom/demo/Shell;"), payload=b"", class_count=None):
    """Build a structurally valid DEX with a real map_list.

    ``payload`` is appended after the tables - exactly how a packer shell hides
    its encrypted classes. Tables are laid out sequentially:
    header(0x70) | string_ids | type_ids | class_defs | string_data | map_list | payload.
    """
    strings = list(strings)
    string_ids_size = len(strings)
    type_ids = list(strings)
    n_classes = class_count if class_count is not None else len(strings)

    header_size = 0x70
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4 * string_ids_size
    class_defs_off = type_ids_off + 4 * len(type_ids)
    string_data_off = class_defs_off + 32 * n_classes
    map_off = string_data_off + sum(len(_string_item(s)) for s in strings)
    payload_off = map_off + 4 + 12 * 6
    total = payload_off + len(payload)

    data = bytearray(total)
    # header
    data[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", data, 0x20, total)             # file_size
    struct.pack_into("<I", data, 0x24, header_size)       # header_size
    struct.pack_into("<I", data, 0x34, map_off)           # map_off
    struct.pack_into("<II", data, 0x38, string_ids_size, string_ids_off)
    struct.pack_into("<II", data, 0x40, len(type_ids), type_ids_off)
    struct.pack_into("<II", data, 0x60, n_classes, class_defs_off)
    data[0x70 - 8:0x70] = b"\x00" * 8

    # string data first (we need offsets for string_ids)
    cursor = string_data_off
    offsets = []
    for text in strings:
        item = _string_item(text)
        data[cursor:cursor + len(item)] = item
        offsets.append(cursor)
        cursor += len(item)

    for i, off in enumerate(offsets):
        struct.pack_into("<I", data, string_ids_off + 4 * i, off)
    for i in range(len(type_ids)):
        struct.pack_into("<I", data, type_ids_off + 4 * i, i)   # descriptor_idx = string index
    for i in range(n_classes):
        struct.pack_into("<I", data, class_defs_off + 32 * i, i)  # class_idx

    # map_list: header, string_id, type_id, class_def, string_data, map_list
    entries = [
        (0x0000, 1, 0),
        (0x0001, string_ids_size, string_ids_off),
        (0x0002, len(type_ids), type_ids_off),
        (0x0006, n_classes, class_defs_off),
        (0x2002, string_ids_size, string_data_off),
        (0x1000, 1, map_off),
    ]
    struct.pack_into("<I", data, map_off, len(entries))
    for i, (item_type, count, off) in enumerate(entries):
        struct.pack_into("<HHII", data, map_off + 4 + 12 * i, item_type, 0, count, off)

    data[payload_off:] = payload
    return bytes(data)


def build_apk(path: Path, dex_payload=b"", assets=None, extra_entries=None):
    """Write a minimal APK (ZIP) with manifest, classes.dex and given assets."""
    assets = assets or {}
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 60)
        zf.writestr("classes.dex", build_dex(payload=dex_payload))
        for name, blob in assets.items():
            zf.writestr(name, blob)
        for name, blob in (extra_entries or {}).items():
            zf.writestr(name, blob)
    return path


class DexIndexTests(unittest.TestCase):
    def test_parses_classes_and_strings(self):
        index = parse_dex_index(build_dex(), "classes.dex")
        self.assertTrue(index.parsed, index.error)
        self.assertEqual(index.version, 35)
        self.assertIn("Lcom/demo/Real;", index.classes)
        self.assertEqual(len(index.strings), 2)

    def test_table_end_and_dark_bytes(self):
        payload = b"\xde\xad\xbe\xef" * 4096
        index = parse_dex_index(build_dex(payload=payload), "classes.dex")
        self.assertGreater(index.table_end, 0)
        self.assertGreaterEqual(index.dark_bytes, len(payload))

    def test_map_list_is_declared(self):
        index = parse_dex_index(build_dex(), "classes.dex")
        types = {item["type"] for item in index.map_items}
        self.assertIn("map_list", types)
        self.assertIn("class_def_item", types)

    def test_rejects_non_dex(self):
        index = parse_dex_index(b"PK\x03\x04not a dex", "fake.dex")
        self.assertFalse(index.parsed)
        self.assertIn("bad magic", index.error)

    def test_handles_truncated_header(self):
        index = parse_dex_index(b"dex\n035\x00", "short.dex")
        self.assertFalse(index.parsed)
        self.assertTrue(index.error)

    def test_uleb_string_length_is_utf16_units(self):
        # 200-char ASCII name -> uleb128 of 200 (0xC8 0x01), not 200 bytes.
        name = "L" + "a" * 197 + ";"
        index = parse_dex_index(build_dex(strings=(name,)), "classes.dex")
        self.assertIn(name, index.classes)


class PackerDetectionTests(unittest.TestCase):
    def test_ijiami_confirmed_from_file_markers(self):
        names = ["assets/hx.classes", "assets/hx.code", "assets/hx.cer", "libhxpatch.so"]
        hits = detect_packers(names, "")
        self.assertTrue(hits)
        self.assertEqual(hits[0]["packer"], "iJiami (爱加密)")
        self.assertEqual(hits[0]["confidence"], "Confirmed")

    def test_string_only_match_is_possible(self):
        hits = detect_packers([], "com/qihoo/util present in pool")
        self.assertEqual(hits[0]["packer"], "360 Jiagu (梆梆/加固)")
        self.assertEqual(hits[0]["confidence"], "Possible")

    def test_no_false_positive_on_clean_apk(self):
        self.assertEqual(detect_packers(["classes.dex", "lib/arm64-v8a/libfoo.so"], "Lcom/app/Main;"), [])

    def test_patch_framework_detected(self):
        found = detect_patch_frameworks(["Lhx/AppPatch;"], "hxreborn/moviebox hx/source/MovieBoxSource")
        self.assertTrue(found)
        self.assertEqual(found[0]["confidence"], "Confirmed")


class BlobTests(unittest.TestCase):
    def test_elf_not_in_lib_flagged_hidden(self):
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 2
        header[18:20] = struct.pack("<H", 0xB7)
        info = classify_blob("assets/x/libhidden.so", bytes(header) + b"\x00" * 2048)
        self.assertEqual(info.kind, "elf")
        self.assertIn("aarch64", info.detail)
        self.assertIn("hidden native", info.detail)

    def test_upx_packed_elf(self):
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        info = classify_blob("assets/x.so", bytes(header) + b"UPX! padding " * 64)
        self.assertEqual(info.kind, "elf-packed")

    def test_zip_magic_outranks_entropy(self):
        import zipfile as _z
        buffer = io.BytesIO()
        with _z.ZipFile(buffer, "w", _z.ZIP_DEFLATED) as zf:
            zf.writestr("a.bin", bytes(range(256)) * 40)
        info = classify_blob("assets/bundle.zip", buffer.getvalue())
        self.assertEqual(info.kind, "zip")
        self.assertIn("nested ZIP", info.detail)

    def test_art_profile_is_not_ciphertext(self):
        import os
        info = classify_blob("assets/dexopt/baseline.prof", b"pro.010." + os.urandom(8192))
        self.assertEqual(info.kind, "art-profile")

    def test_high_entropy_is_ciphertext(self):
        import os
        info = classify_blob("assets/blob", os.urandom(8192))
        self.assertEqual(info.kind, "ciphertext-or-compressed")

    def test_text_and_json(self):
        self.assertEqual(classify_blob("assets/a.txt", b"hello world\n" * 100).kind, "text")
        self.assertEqual(classify_blob("assets/a.cfg", b'{"k": 1}\n' * 100).kind, "json")

    def test_sha256_is_stable(self):
        a = classify_blob("assets/a", b"x" * 1000)
        b = classify_blob("assets/a", b"x" * 1000)
        self.assertEqual(a.sha256, b.sha256)
        self.assertEqual(len(a.sha256), 64)


class ClusterTests(unittest.TestCase):
    def test_buckets(self):
        clusters = cluster_strings([
            "https://api.example.com/v1/play",
            "api.example.com",
            "X-Client-Build",
            "/subject-api/play-info/v2",
            "wefeed-mobile-bff/subject-api/resource",
        ])
        self.assertIn("https://api.example.com/v1/play", clusters["urls"])
        self.assertIn("api.example.com", clusters["hosts"])
        self.assertIn("X-Client-Build", clusters["custom_headers"])
        self.assertIn("/subject-api/play-info/v2", clusters["endpoints"])
        self.assertTrue(any("wefeed-mobile-bff" in p for p in clusters["api_paths"]))

    def test_deduplicates(self):
        clusters = cluster_strings(["X-Ab", "X-Ab", "X-Ab"])
        self.assertEqual(clusters["custom_headers"], ["X-Ab"])


class AnalyzeDeepTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _packed_apk(self):
        assets = {
            "assets/hx.classes": b"com.x.Y\n" * 40,
            "assets/hx.code": b"\x00" * 600,
            "assets/hx.cer": b"\x00" * 900,
            "assets/LYouKWv/arm64-v8a/libhidden.so": b"\x7fELF" + b"\x02" + b"\x00" * 3000,
            "assets/opaque": bytes(range(256)) * 40,
            "assets/logo.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 100,
        }
        return build_apk(self.dir / "packed.apk", dex_payload=b"\xAA" * 1_500_000, assets=assets)

    def test_detects_shell_packer_and_hidden_native(self):
        report = analyze_deep(self._packed_apk())
        names = {f.name for f in report.findings}
        self.assertIn("dex-shell-detected", names)
        self.assertIn("packer-identified", names)
        self.assertIn("native-code-outside-lib", names)
        self.assertIn("encrypted-overlays", names)
        self.assertEqual(report.packers[0]["packer"], "iJiami (爱加密)")
        self.assertGreater(report.dexes[0].dark_ratio, 0.9)

    def test_images_are_not_classified_as_blobs(self):
        report = analyze_deep(self._packed_apk())
        self.assertNotIn("assets/logo.png", {b.path for b in report.blobs})

    def test_clean_apk_has_no_packer_findings(self):
        path = build_apk(self.dir / "clean.apk")
        report = analyze_deep(path)
        self.assertEqual(report.packers, [])
        self.assertNotIn("dex-shell-detected", {f.name for f in report.findings})
        self.assertTrue(any("map table" in note for note in report.limitations))

    def test_report_round_trip(self):
        report = analyze_deep(self._packed_apk())
        paths = write_deep_report(report, self.dir / "out")
        self.assertTrue(Path(paths["markdown"]).is_file())
        self.assertTrue(Path(paths["json"]).is_file())
        import json
        blob = json.loads(Path(paths["json"]).read_text())
        self.assertEqual(blob["sha256"], report.sha256)
        self.assertIn("Deep APK triage", Path(paths["markdown"]).read_text())

    def test_markdown_escapes_pipes(self):
        report = analyze_deep(self._packed_apk())
        report.findings[0].detail += " | injected | column"
        self.assertIn("\\|", render_markdown(report))

    def test_empty_zip_does_not_crash(self):
        path = self.dir / "empty.apk"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"\x00" * 8)
        report = analyze_deep(path)
        self.assertEqual(report.dexes, [])
        self.assertEqual(report.findings, [])


if __name__ == "__main__":
    unittest.main()
