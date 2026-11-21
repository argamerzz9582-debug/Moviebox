import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
from rex.cli import main as cli_main  # noqa: E402
from rex.config import RexConfig  # noqa: E402
from rex.ingestion.url_fetcher import SsrfSecurityError, inspect_remote_url, validate_public_url  # noqa: E402
from rex.orchestrator.engine import AnalysisOrchestrator  # noqa: E402
from rex.workspace.manager import WorkspaceManager  # noqa: E402


class TestSecurityOrchestratorCli(unittest.TestCase):
    def test_ssrf_blocks_localhost_private_and_bad_schemes(self):
        for bad in [
            "http://127.0.0.1:8080/admin",
            "http://localhost/secret",
            "http://169.254.169.254/latest/meta-data/",
            "http://192.168.1.1/",
            "http://10.0.0.5/",
            "file:///etc/passwd",
            "ftp://example.com/file.bin",
        ]:
            with self.assertRaises(SsrfSecurityError, msg=f"Failed to block {bad}"):
                validate_public_url(bad)

        # DNS rebinding / internal IP resolution simulation
        with self.assertRaises(SsrfSecurityError):
            validate_public_url("https://evil.example.com/payload", resolver=lambda _: ["10.1.2.3"])

        # Public URL in offline mode succeeds without making network calls
        res = inspect_remote_url(
            "https://github.com/argamerzz9582-debug/ZyroxLauncher",
            offline_mode=True,
            resolver=lambda _: ["140.82.121.4"],
        )
        self.assertEqual(res.status, "skipped_offline")
        self.assertEqual(res.platform, "github")

    def test_zip_slip_traversal_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            evil_zip = d / "evil.zip"
            with zipfile.ZipFile(evil_zip, "w") as zf:
                zf.writestr("../escape.txt", "malicious")
            with self.assertRaises(ValueError):
                WorkspaceManager.safe_extract_zip(evil_zip, d / "out")


    def test_zip_windows_backslash_traversal_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            evil_zip = d / "windows_traversal.zip"
            with zipfile.ZipFile(evil_zip, "w") as zf:
                zf.writestr(r"..\..\escape.txt", "malicious")
            with self.assertRaises(ValueError):
                WorkspaceManager.safe_extract_zip(evil_zip, d / "out")

    def test_workspace_symlink_escape_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            workspaces = base / "workspaces"
            outside = base / "outside"
            workspaces.mkdir()
            outside.mkdir()
            link = workspaces / "linked-run"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks unavailable on this platform")
            manager = WorkspaceManager(workspaces)
            with self.assertRaises(FileNotFoundError):
                manager.get_run("linked-run")

    def test_repository_validator_checks_missing_files(self):
        import importlib.util
        validator_path = REPO_ROOT / "scripts" / "validate_repo.py"
        spec = importlib.util.spec_from_file_location("rex_validate_repo", validator_path)
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        original_root = validator.REPO_ROOT
        try:
            with tempfile.TemporaryDirectory() as tmp:
                validator.REPO_ROOT = Path(tmp)
                rc = validator.validate()
                self.assertEqual(rc, 1)
        finally:
            validator.REPO_ROOT = original_root

    def test_orchestrator_end_to_end_and_cli_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            sample_jar = fake_home / "TestPlugin.jar"
            with zipfile.ZipFile(sample_jar, "w") as zf:
                zf.writestr("plugin.yml", "name: TestPlugin\nversion: 1.0\nmain: com.test.Main\n")

            cfg = RexConfig.load(repo_root=REPO_ROOT, home=fake_home, offline_mode=True)
            orch = AnalysisOrchestrator(cfg)
            result = orch.execute(str(sample_jar), mode="full", allow_dynamic=False)

            self.assertEqual(result["classification"]["primary_type"], "minecraft_bukkit_plugin")
            self.assertTrue(Path(result["reports"]["markdown"]).exists())
            self.assertTrue(Path(result["reports"]["json"]).exists())

            # Dynamic analysis must be Skipped by default when allow_dynamic=False
            task_states = {t["task_id"]: t["state"] for t in result["tasks"]}
            self.assertEqual(task_states["task_dynamic"], "Skipped")

            # Verify CLI commands return exit code 0
            rc_doc = cli_main(["--home", str(fake_home), "--json", "doctor"])
            self.assertEqual(rc_doc, 0)
            rc_mc = cli_main(["--home", str(fake_home), "--json", "minecraft", "inspect", str(sample_jar)])
            self.assertEqual(rc_mc, 0)
            rc_ws = cli_main(["--home", str(fake_home), "--json", "workspace", "list"])
            self.assertEqual(rc_ws, 0)


if __name__ == "__main__":
    unittest.main()
