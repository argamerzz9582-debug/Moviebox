"""Tests for the APK reverse-engineering pipeline (rex apk / apk_analyzer)."""

import io
import json
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from rex.adapters import apk_analyzer, apk_pipeline

REPO_ROOT = Path(__file__).resolve().parent.parent


def _xml_string_pool(strings):
    """Android AXML string pool chunk (UTF-8 strings, no style spans)."""
    data = b""
    offsets = []
    for text in strings:
        raw = text.encode("utf-16-le")
        offsets.append(len(data))
        data += struct.pack("<H", len(text)) + raw + b"\x00\x00"
        while len(data) % 4:
            data += b"\x00"
    header_size = 28
    strings_start = header_size + 4 * len(offsets)
    chunk_size = strings_start + len(data)
    # ResStringPool_header: chunk(8) + stringCount(4) + styleCount(4) + flags(4)
    #                        + stringsStart(4) + stylesStart(4) = 28 bytes
    chunk = struct.pack("<HHII", 0x0001, header_size, chunk_size, len(strings))
    chunk += struct.pack("<IIII", 0, 0, strings_start, 0)
    assert len(chunk) == header_size, (len(chunk), header_size)
    chunk += b"".join(struct.pack("<I", o) for o in offsets)
    return chunk + data


def _build_apk(path: Path, package="com.rex.demo", label="RexDemo", activity=".Main",
               permissions=("android.permission.INTERNET",), extra_entries=None) -> Path:
    """Assemble a small but structurally valid APK (AXML manifest + DEX + assets)."""
    strings = [
        "versionCode", "versionName", "minSdkVersion", "targetSdkVersion", "package",
        "android", "http://schemas.android.com/apk/res/android", "1", "1.0",
        "manifest", "uses-sdk", "uses-permission", "application", "activity",
        "name", "exported", "intent-filter", "action", "true", "false",
        "android.intent.action.MAIN", "android.intent.category.LAUNCHER",
        package, label, activity, "android:name", "android:exported", "android:versionCode",
        "android:versionName", "android:minSdkVersion", "android:targetSdkVersion", "LAUNCHER",
    ]
    for extra in permissions:
        if extra not in strings:
            strings.append(extra)
    idx = {value: i for i, value in enumerate(strings)}

    NS = 0xFFFFFFFF

    def attr(name, raw, value_type=0x03, data=None):
        """Attribute chunk: android-namespaced name + string/boolean/int value."""
        if data is None:
            data = idx[raw] if value_type == 0x03 else 0xFFFFFFFF
        raw_value = idx[raw] if value_type == 0x03 else 0xFFFFFFFF
        return struct.pack("<IIIHBBI", idx["android"], idx[name], raw_value, 8, 0,
                           value_type, data)

    def start(name, attrs=b"", attr_count=0):
        body = struct.pack("<IIHHHHHH", NS, idx[name], 20, 20, attr_count, 0, 0, 0) + attrs
        # NOTE: android:name style attributes carry the namespace of the *attribute*;
        # element names stay in the empty namespace (NS above).
        node = struct.pack("<HHIII", 0x0102, 16, 16 + len(body), 1, NS)
        return node + body

    def end(name):
        body = struct.pack("<II", NS, idx[name])
        node = struct.pack("<HHIII", 0x0103, 16, 16 + len(body), 1, NS)
        return node + body

    manifest_attrs = (attr("versionCode", "1", 0x10, 1)
                      + attr("versionName", "1.0")
                      + attr("package", package))
    body = start("manifest", manifest_attrs, 3)
    body += start("uses-sdk", attr("minSdkVersion", "21", 0x10, 21)
                  + attr("targetSdkVersion", "34", 0x10, 34), 2)
    body += end("uses-sdk")
    for perm in permissions:
        body += start("uses-permission", attr("name", perm), 1)
        body += end("uses-permission")
    body += start("application", attr("name", label), 1)
    activity_attrs = attr("name", activity) + attr("exported", "true", 0x12, 0xFFFFFFFF)
    body += start("activity", activity_attrs, 2)
    body += start("intent-filter", b"", 0)
    body += start("action", attr("name", "android.intent.action.MAIN"), 1)
    body += end("action")
    body += end("intent-filter")
    body += end("activity")
    body += end("application")
    body += end("manifest")

    pool = _xml_string_pool(strings)
    xml = struct.pack("<HHI", 0x0003, 8, 8 + len(pool) + len(body)) + pool + body

    dex = b"dex\n035\x00" + b"\x00" * 104
    dex += b"http://cdn.example-cdn.net/api/v1/license\x00"
    dex += b"10.20.30.40\x00" + b"admin@example.com\x00" + b"Lokhttp3/Request$Builder;\x00"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", xml)
        zf.writestr("classes.dex", dex)
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n")
        zf.writestr("res/layout/main.xml", "<LinearLayout/>")
        zf.writestr("assets/config.json", '{"api":"https://api.example-cdn.net/v2"}')
        zf.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELF" + b"\x00" * 60)
        for name, data in (extra_entries or {}).items():
            zf.writestr(name, data)
    return path


class TestApkPipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.apk = _build_apk(self.dir / "RexDemo_v1.0_Mod.apk")

    def tearDown(self):
        self.tmp.cleanup()

    def test_validation_accepts_a_well_formed_apk(self):
        result = apk_pipeline.validate_apk(self.apk)
        self.assertTrue(result["valid"], result["detail"])
        self.assertEqual(result["dex_files"], ["classes.dex"])

    def test_validation_rejects_non_zip_and_zip_without_manifest(self):
        bogus = self.dir / "not-an.apk"
        bogus.write_bytes(b"\x7fELF not a zip")
        self.assertFalse(apk_pipeline.validate_apk(bogus)["valid"])
        no_manifest = self.dir / "no_manifest.apk"
        with zipfile.ZipFile(no_manifest, "w") as zf:
            zf.writestr("classes.dex", b"dex\n035\x00")
        result = apk_pipeline.validate_apk(no_manifest)
        self.assertFalse(result["valid"])
        self.assertIn("AndroidManifest", result["detail"])

    def test_structure_and_indicators_are_extracted(self):
        report = apk_analyzer.analyze_apk(self.apk)
        ident = report.identity
        self.assertEqual(len(ident["sha256"]), 64)
        self.assertIn("classes.dex", ident["dex_files"])
        self.assertEqual(len(report.native_libs), 1)
        self.assertEqual(report.native_libs[0]["abi"], "arm64-v8a")
        self.assertIn("http://cdn.example-cdn.net/api/v1/license", report.indicators["urls"])
        self.assertIn("10.20.30.40", report.indicators["ipv4"])
        self.assertIn("admin@example.com", report.indicators["emails"])

    def test_mod_labelling_is_flagged(self):
        report = apk_analyzer.analyze_apk(self.apk)
        self.assertIn("mod-labelled-build", report.mod_analysis["strong_signals"])
        self.assertEqual(report.mod_analysis["verdict"], "modified-or-repacked build")

    def test_cleanly_named_build_without_signals_is_not_flagged_as_modded(self):
        clean = _build_apk(self.dir / "RexDemo_v1.0.apk")
        report = apk_analyzer.analyze_apk(clean)
        self.assertNotIn("mod-labelled-build", report.mod_analysis["strong_signals"])
        self.assertNotEqual(report.mod_analysis["verdict"], "modified-or-repacked build")

    def test_markdown_and_json_are_written_and_bounded(self):
        result = apk_pipeline.run_pipeline(self.apk, self.dir / "out")
        self.assertTrue(result["analyzed"])
        md = Path(result["paths"]["markdown"]).read_text(encoding="utf-8")
        payload = json.loads(Path(result["paths"]["json"]).read_text(encoding="utf-8"))
        self.assertIn("Reverse-engineering report", md)
        self.assertIn("## 8. Modified-build assessment", md)
        self.assertLess(len(md), 200_000)
        self.assertEqual(payload["identity"]["package"] or "", payload["identity"]["package"] or "")
        self.assertTrue(payload["findings"])

    def test_report_contains_no_raw_binary_dump(self):
        result = apk_pipeline.run_pipeline(self.apk, self.dir / "out2")
        md = Path(result["paths"]["markdown"]).read_text(encoding="utf-8")
        self.assertNotIn("\x00", md)
        self.assertLess(md.count("\n"), 4000)

    def test_cli_analyze_and_json(self):
        from rex.cli import main
        out = self.dir / "cli_out"
        with redirect_stdout(io.StringIO()) as captured:
            code = main(["apk", "analyze", str(self.apk), "--out", str(out)])
        self.assertEqual(code, 0)
        self.assertIn("Mod verdict", captured.getvalue())
        with redirect_stdout(io.StringIO()) as captured_json:
            code = main(["apk", "analyze", str(self.apk), "--out", str(out), "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(captured_json.getvalue())
        self.assertTrue(payload["analyzed"])
        self.assertIn("identity", payload["report"])

    def test_cli_validate_rejects_garbage(self):
        from rex.cli import main
        bogus = self.dir / "garbage.apk"
        bogus.write_text("nope")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["apk", "validate", str(bogus), "--json"]), 1)

    def test_drive_listing_reports_unavailable_without_gcloud(self):
        with mock.patch.object(apk_pipeline, "_find_gcloud", return_value=None):
            result = apk_pipeline.list_drive_files()
        self.assertFalse(result["available"])
        self.assertIn("gcloud", result["detail"])

    def test_fetch_rejects_non_https(self):
        result = apk_pipeline.fetch_from_url("http://example.com/a.apk", self.dir / "a.apk")
        self.assertFalse(result["ok"])
        self.assertIn("https", result["detail"])


if __name__ == "__main__":
    unittest.main()
