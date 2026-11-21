import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import install as rex_install  # noqa: E402
import validate_repo  # noqa: E402
from rex.registry.tool_registry import ToolRegistry, ToolStatus  # noqa: E402
from rex.skills.loader import SkillRegistry  # noqa: E402


class TestPresetsAndSkills(unittest.TestCase):
    def test_prerequisite_gating_skips_missing_binaries(self):
        registry = rex_install.load_registry(REPO_ROOT)

        def fake_which(binary_name):
            return "/usr/bin/python3" if binary_name == "python3" else None

        eligible, skipped = rex_install.evaluate_mcp_gates(registry, which_fn=fake_which)
        eligible_ids = {s["id"] for s in eligible}
        skipped_map = {s["id"]: missing for s, missing in skipped}

        self.assertIn("hex-binary-mcp", eligible_ids)
        self.assertIn("ghidra-mcp", skipped_map)
        self.assertIn("jadx-mcp", skipped_map)
        self.assertIn("radare2-mcp", skipped_map)

    def test_tool_registry_status_distinction(self):
        reg = ToolRegistry(which_fn=lambda b: "/usr/bin/python3" if b == "python3" else None, run_health_checks=False)
        tools = {t.id: t for t in reg.inspect_all()}
        self.assertEqual(tools["python3"].status, ToolStatus.INSTALLED.value)
        self.assertEqual(tools["ghidra"].status, ToolStatus.NOT_DETECTED.value)

    def test_skill_loader_and_routing(self):
        sreg = SkillRegistry(REPO_ROOT)
        specs = sreg.discover()
        self.assertEqual(len(specs), 11)
        self.assertTrue(all(s.valid for s in specs))
        routed = [s.name for s in sreg.route_for_target(["rex-minecraft"])]
        self.assertEqual(routed, ["rex-master", "rex-minecraft", "rex-evidence-report"])

    def test_repo_validator_passes(self):
        self.assertEqual(validate_repo.validate(), 0)


if __name__ == "__main__":
    unittest.main()
