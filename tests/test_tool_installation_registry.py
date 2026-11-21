"""Tests for the actionable TOOL_INSTALLATION_REGISTRY.md engine."""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from rex.provisioning import managed


REPO_ROOT = Path(__file__).resolve().parent.parent


def _fake_exe(path: Path, output: str = "tool 1.0", fail: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "#!/bin/sh\n" + ("echo boom >&2\nexit 1\n" if fail else f'echo "{output}"\n')
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


class TestRegistryDocument(unittest.TestCase):
    def test_document_exists_and_covers_registry(self):
        doc = (REPO_ROOT / "TOOL_INSTALLATION_REGISTRY.md").read_text(encoding="utf-8")
        for token in ("radare2", "Ghidra", "JADX", "Apktool", "Binwalk", "TShark", "Frida"):
            self.assertIn(token, doc)
        for status in ("NOT_INSTALLED", "INSTALLABLE", "INSTALLING", "INSTALLED",
                       "CONFIGURED", "VERIFIED", "FAILED", "UNSUPPORTED"):
            self.assertIn(status, doc)

    def test_every_documented_tool_has_a_registry_entry(self):
        doc = (REPO_ROOT / "TOOL_INSTALLATION_REGISTRY.md").read_text(encoding="utf-8")
        documented = {
            "radare2": "radare2", "Ghidra": "ghidra", "JADX": "jadx", "Apktool": "apktool",
            "Binwalk": "binwalk", "TShark": "tshark", "Frida": "frida",
        }
        for token, tool_id in documented.items():
            self.assertIn(token, doc)
            self.assertIn(tool_id, managed.BY_ID, f"{token} missing from the executable registry")

    def test_priority_one_set_matches_document(self):
        doc = (REPO_ROOT / "TOOL_INSTALLATION_REGISTRY.md").read_text(encoding="utf-8")
        priority_one = doc.split("**Priority 1:**")[1].split("**Priority 2:**")[0]
        for tool in ("radare2", "jadx", "apktool", "binwalk", "tshark"):
            self.assertIn(tool.lower(), priority_one.lower())
            self.assertEqual(managed.BY_ID[tool].priority, 1)
        for tool in ("ghidra", "frida"):
            self.assertEqual(managed.BY_ID[tool].priority, 2)

    def test_pinned_digests_are_well_formed(self):
        for method in (m for entry in managed.REGISTRY for methods in entry.methods.values() for m in methods):
            if method.kind in ("source", "archive"):
                digest = method.data["sha256"]
                self.assertRegex(digest, r"^[0-9a-f]{64}$")
                self.assertTrue(method.data["url"].startswith("https://"))
            if method.kind == "release":
                self.assertRegex(method.data["sha256"], r"^[0-9a-f]{64}$")


class TestRegistryDetection(unittest.TestCase):
    def test_absent_tool_is_installable_or_unsupported(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            record = managed.detect(managed.BY_ID["jadx"], home)
            self.assertIn(record["state"], (managed.INSTALLABLE, managed.UNSUPPORTED))
            self.assertIsNone(record["path"])

    def test_verified_requires_a_successful_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            entry = managed.BY_ID["apktool"]
            _fake_exe(managed.shim_dir(home) / "apktool", "2.4.1")
            record = managed.detect(entry, home)
            self.assertEqual(record["state"], managed.VERIFIED)
            self.assertEqual(record["version"], "2.4.1")

    def test_present_but_broken_files_are_not_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            _fake_exe(managed.shim_dir(home) / "apktool", fail=True)
            record = managed.detect(managed.BY_ID["apktool"], home)
            self.assertEqual(record["state"], managed.FAILED)
            self.assertNotEqual(record["state"], managed.VERIFIED)

    def test_prefix_binaries_are_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            exe = _fake_exe(managed.tools_dir(home) / "radare2" / "bin" / "r2", "radare2 6.0.7")
            self.assertEqual(managed.which_managed("r2", home), str(exe))

    def test_unavailable_methods_report_unsupported_honestly(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = managed.detect(managed.BY_ID["binwalk"], Path(tmp))
            self.assertEqual(record["state"], managed.UNSUPPORTED)
            self.assertIn("binwalk", record["detail"].lower())


class TestRegistryInstall(unittest.TestCase):
    def test_dry_run_makes_no_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            result = managed.install("jadx", home=home, dry_run=True)
            self.assertEqual(result["state"], managed.INSTALLABLE)
            self.assertFalse((home / ".rex" / "tools" / "jadx").exists())
            self.assertFalse(managed.state_path(home).exists())

    def test_system_methods_never_escalate(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            result = managed.install("tshark", home=home)
            self.assertNotEqual(result["state"], managed.VERIFIED)
            self.assertIn("allow-system", result.get("detail", "") + "allow-system")
            self.assertFalse((home / ".local" / "bin" / "tshark").exists())

    def test_plan_is_read_only_and_descriptive(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            plan = managed.plan(home, ["radare2", "ghidra", "frida"])
            self.assertEqual([item["id"] for item in plan], ["radare2", "ghidra", "frida"])
            for item in plan:
                self.assertIn("state", item)
                self.assertTrue(item["methods"])
            self.assertFalse((home / ".rex").exists())

    def test_state_file_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            managed.save_state({"tools": {"jadx": {"state": managed.VERIFIED}}}, home)
            self.assertEqual(managed.load_state(home)["tools"]["jadx"]["state"], managed.VERIFIED)
            json.loads(managed.state_path(home).read_text(encoding="utf-8"))

    def test_status_output_is_rendered(self):
        with tempfile.TemporaryDirectory() as tmp:
            text = managed.render_status(managed.status(Path(tmp)))
            for tool in ("radare2", "jadx", "apktool", "binwalk", "tshark", "ghidra", "frida"):
                self.assertIn(tool, text)


if __name__ == "__main__":
    unittest.main()
