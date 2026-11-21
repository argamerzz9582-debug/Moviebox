#!/usr/bin/env python3
"""REX Repository Validator — Verifies JSON registry schema, templates, and SKILL.md frontmatter."""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
from rex.skills.loader import SkillRegistry  # noqa: E402

REQUIRED_SERVER_KEYS = {
    "id", "name", "category", "upstream", "description",
    "targets", "platforms", "license", "verification_status",
    "profile", "required_binaries", "template", "risk_tier", "mcp_config",
}


def validate() -> int:
    errors = []

    for fname in ["AGENTS.md", "CLAUDE.md", "README.md", "LICENSE", "SECURITY.md", "install.py",
                  "pyproject.toml", "TOOL_INSTALLATION_REGISTRY.md"]:
        if not (REPO_ROOT / fname).exists():
            errors.append(f"Missing required root file: {fname}")

    reg_path = REPO_ROOT / "mcp-presets" / "registry.json"
    reg = {}
    if not reg_path.exists():
        errors.append("Missing mcp-presets/registry.json")
    else:
        try:
            reg = json.loads(reg_path.read_text(encoding="utf-8"))
            servers = reg.get("servers", [])
            if not servers:
                errors.append("registry.json has no servers")
            seen_ids = set()
            for srv in servers:
                missing_keys = REQUIRED_SERVER_KEYS - set(srv.keys())
                if missing_keys:
                    errors.append(f"Server {srv.get('id', '?')} missing keys: {sorted(missing_keys)}")
                sid = srv.get("id")
                if sid in seen_ids:
                    errors.append(f"Duplicate server id: {sid}")
                seen_ids.add(sid)
                tpl_path = REPO_ROOT / "mcp-presets" / srv.get("template", "")
                if not tpl_path.exists():
                    errors.append(f"Missing MCP template file: {tpl_path}")
                else:
                    json.loads(tpl_path.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"Invalid registry.json: {exc}")

    specs = SkillRegistry(REPO_ROOT).discover()
    if len(specs) < 11:
        errors.append(f"Expected at least 11 skills (including rex-minecraft), found {len(specs)}")
    for spec in specs:
        if not spec.valid:
            errors.append(f"Skill {spec.name} invalid: {spec.errors}")

    for kfile in ["tool-cheatsheets.md", "magic-bytes.md", "decompiler-pitfalls.md", "minecraft-artifacts.md"]:
        if not (REPO_ROOT / "knowledge" / kfile).exists():
            errors.append(f"Missing knowledge guide: knowledge/{kfile}")

    if errors:
        print("VALIDATION FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1

    from rex.adapters import apk_analyzer, apk_deep, apk_pipeline  # noqa: F401  (import-time sanity)
    from rex.provisioning import managed

    for tool in ("radare2", "jadx", "apktool", "binwalk", "tshark", "ghidra", "frida"):
        if tool not in managed.BY_ID:
            errors.append(f"TOOL_INSTALLATION_REGISTRY.md tool not actionable in rex/provisioning/managed.py: {tool}")
    if errors:
        print("VALIDATION FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"VALIDATION PASSED: {len(specs)} skills, {len(reg['servers'])} MCP presets, "
          f"4 knowledge guides, {len(managed.REGISTRY)} registry tools verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(validate())
