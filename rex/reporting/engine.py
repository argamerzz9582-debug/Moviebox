"""Evidence Ledger and Dual Markdown + JSON Report Generator."""

import json
from dataclasses import dataclass
from typing import Any, Dict, List

from rex.config import redact_sensitive_text
from rex.workspace.manager import WorkspaceRun


VALID_CONFIDENCE = {"Confirmed", "Strongly supported", "Probable", "Unverified", "Contradicted"}


@dataclass
class EvidenceFinding:
    id: str
    claim: str
    evidence: str
    location: str
    tool: str
    confidence: str = "Probable"
    alternatives: str = ""
    limitations: str = ""

    def to_dict(self) -> Dict[str, Any]:
        conf = self.confidence if self.confidence in VALID_CONFIDENCE else "Unverified"
        return {
            "id": self.id,
            "claim": redact_sensitive_text(self.claim),
            "evidence": redact_sensitive_text(self.evidence),
            "location": self.location,
            "tool": self.tool,
            "confidence": conf,
            "alternatives": self.alternatives,
            "limitations": self.limitations,
        }


class ReportEngine:
    @staticmethod
    def render_markdown(payload: Dict[str, Any]) -> str:
        cls = payload.get("classification", {})
        tasks = payload.get("tasks", [])
        findings = payload.get("findings", [])
        limitations = payload.get("limitations", [])
        tools = payload.get("tools", [])
        installed_tools = [t["id"] for t in tools if t.get("status") in ("installed", "healthy", "verified")]
        missing_tools = [t["id"] for t in tools if t.get("status") == "not_detected"]

        lines: List[str] = [
            f"# REX Analysis Report — `{payload.get('run_id')}`",
            "",
            "## 1. Executive Summary",
            f"- **Target:** `{payload.get('target')}`",
            f"- **Primary Classification:** `{cls.get('primary_type')}` (Confidence: **{cls.get('confidence')}**)",
            f"- **Analysis Mode:** `{payload.get('mode')}`",
            f"- **Routed Skills:** {', '.join(payload.get('routed_skills', [])) or 'none'}",
            "",
            "## 2. Target Identity & Metadata",
            f"- **Target Kind:** {cls.get('target_kind')}",
            f"- **Architecture:** {cls.get('architecture') or 'N/A'}",
            f"- **Subtypes:** {', '.join(cls.get('subtypes', [])) or 'none'}",
        ]
        for k, v in cls.get("metadata", {}).items():
            lines.append(f"- **{k}:** `{v}`")

        lines.extend([
            "",
            "## 3. Tools Used & Availability",
            f"- **Available / Installed Tools:** {', '.join(installed_tools) if installed_tools else 'Python stdlib core only'}",
            f"- **Not Detected Tools:** {', '.join(missing_tools) if missing_tools else 'none'}",
            "",
            "## 4. Orchestrator Task Execution",
            "| Task ID | Title | State | Summary |",
            "|---|---|---|---|",
        ])
        for t in tasks:
            lines.append(f"| `{t['task_id']}` | {t['title']} | **{t['state']}** | {redact_sensitive_text(t.get('summary', ''))} |")

        lines.extend([
            "",
            "## 5. Evidence-Backed Findings",
            "| ID | Claim | Location | Tool | Confidence |",
            "|---|---|---|---|---|",
        ])
        for f in findings:
            lines.append(f"| `{f['id']}` | {f['claim']} | `{f['location']}` | `{f['tool']}` | **{f['confidence']}** |")

        lines.extend(["", "### Detailed Evidence"])
        for f in findings:
            lines.append(f"- **{f['id']} ({f['confidence']}):** {f['evidence']}")

        lines.extend(["", "## 6. Limitations & Unknowns"])
        if limitations:
            for lim in limitations:
                lines.append(f"- {lim}")
        else:
            lines.append("- Analysis bounded to static inspection scope.")

        lines.extend(["", "## 7. Suggested Next Steps"])
        for step in cls.get("next_steps", ["Inspect generated artifacts inside workspace directory."]):
            lines.append(f"- {step}")

        return "\n".join(lines) + "\n"

    @classmethod
    def write_reports(cls, run: WorkspaceRun, payload: Dict[str, Any]) -> Dict[str, str]:
        json_path = run.reports_dir / "report.json"
        md_path = run.reports_dir / "report.md"

        sanitized_json = redact_sensitive_text(json.dumps(payload, indent=2) + "\n")
        json_path.write_text(sanitized_json, encoding="utf-8")

        md_text = cls.render_markdown(payload)
        md_path.write_text(md_text, encoding="utf-8")

        return {"json": str(json_path), "markdown": str(md_path)}
