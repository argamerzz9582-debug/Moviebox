import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
import install as rex_install  # noqa: E402


class TestInstaller(unittest.TestCase):
    def test_detect_environment_keys(self):
        env = rex_install.detect_environment()
        for key in ("os", "arch", "pkg_mgr", "is_termux", "is_root"):
            self.assertIn(key, env)

    def test_json_merge_backup_and_uninstall_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            claude_dir = fake_home / ".claude"
            claude_dir.mkdir(parents=True)
            claude_cfg = fake_home / ".claude.json"
            original_cfg = {
                "theme": "dark",
                "mcpServers": {
                    "user-existing-server": {"command": "node", "args": ["my-server.js"]}
                },
            }
            claude_cfg.write_text(json.dumps(original_cfg, indent=2), encoding="utf-8")

            state = rex_install.run_install(
                profile="core",
                agent="claude",
                dry_run=False,
                home=fake_home,
                skip_venv=True,
                repo_root=REPO_ROOT,
            )

            self.assertEqual(state["agent"], "claude")
            self.assertGreaterEqual(len(state["installed_skills"]), 11)
            self.assertTrue((claude_dir / "skills" / "rex-minecraft" / "SKILL.md").exists())
            self.assertIsNotNone(state["backup_file"])

            merged = json.loads(claude_cfg.read_text(encoding="utf-8"))
            self.assertIn("user-existing-server", merged["mcpServers"])

            rex_install.uninstall_rex(fake_home, dry_run=False)
            restored = json.loads(claude_cfg.read_text(encoding="utf-8"))
            self.assertEqual(restored, original_cfg)
            self.assertFalse((claude_dir / "skills" / "rex-minecraft").exists())

    def test_toml_merge_codex(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            codex_dir = fake_home / ".codex"
            codex_dir.mkdir(parents=True)
            cfg = codex_dir / "config.toml"
            cfg.write_text('model = "gpt-5"\n', encoding="utf-8")

            rex_install.run_install(
                profile="core",
                agent="codex",
                dry_run=False,
                home=fake_home,
                skip_venv=True,
                repo_root=REPO_ROOT,
            )

            text = cfg.read_text(encoding="utf-8")
            self.assertIn('model = "gpt-5"', text)
            self.assertIn("# >>> REX MCP SERVERS >>>", text)
            self.assertIn("# <<< REX MCP SERVERS <<<", text)

    def test_dry_run_makes_no_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            rex_install.run_install(
                profile="minecraft",
                agent="generic",
                dry_run=True,
                home=fake_home,
                skip_venv=True,
                repo_root=REPO_ROOT,
            )
            self.assertFalse((fake_home / ".rex").exists())


if __name__ == "__main__":
    unittest.main()
