"""Skill Loader, Metadata Validator, and Multi-Skill Target Router."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List


REQUIRED_FRONTMATTER_KEYS = {"name", "description", "triggers", "tools_required"}


@dataclass
class SkillSpec:
    name: str
    description: str
    triggers: List[str]
    tools_required: List[str]
    path: Path
    valid: bool = True
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "triggers": self.triggers,
            "tools_required": self.tools_required,
            "path": str(self.path),
            "valid": self.valid,
            "errors": self.errors,
        }


def parse_frontmatter(text: str) -> Dict[str, str]:
    if not text.startswith("---\n"):
        return {}
    parts = text.split("---\n", 2)
    if len(parts) < 3:
        return {}
    fm: Dict[str, str] = {}
    for line in parts[1].splitlines():
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            fm[k.strip()] = v.strip()
    return fm


class SkillRegistry:
    def __init__(self, repo_root: Path):
        self.skills_dir = repo_root / "skills"

    def discover(self) -> List[SkillSpec]:
        if not self.skills_dir.exists():
            return []
        specs: List[SkillSpec] = []
        for skill_md in sorted(self.skills_dir.glob("*/SKILL.md")):
            text = skill_md.read_text(encoding="utf-8")
            fm = parse_frontmatter(text)
            errors: List[str] = []
            for req in REQUIRED_FRONTMATTER_KEYS:
                if req not in fm or not fm[req]:
                    errors.append(f"Missing frontmatter key: {req}")
            if len(text) < 350:
                errors.append("Skill content is unexpectedly short")

            triggers = [t.strip() for t in fm.get("triggers", "").split(",") if t.strip()]
            tools = [t.strip() for t in fm.get("tools_required", "").split(",") if t.strip()]
            specs.append(
                SkillSpec(
                    name=fm.get("name", skill_md.parent.name),
                    description=fm.get("description", ""),
                    triggers=triggers,
                    tools_required=tools,
                    path=skill_md,
                    valid=len(errors) == 0,
                    errors=errors,
                )
            )
        return specs

    def route_for_target(self, recommended_names: List[str]) -> List[SkillSpec]:
        all_skills = {s.name: s for s in self.discover() if s.valid}
        routed: List[SkillSpec] = []
        for name in ["rex-master", *recommended_names, "rex-evidence-report"]:
            if name in all_skills and all_skills[name] not in routed:
                routed.append(all_skills[name])
        return routed
