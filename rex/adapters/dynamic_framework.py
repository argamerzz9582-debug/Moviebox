"""Controlled Dynamic Analysis Framework — Disabled by default, opt-in with explicit approval."""

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class DynamicPlan:
    enabled: bool
    approved: bool
    isolation_required: bool
    selected_engines: List[str]
    warnings: List[str]

    def to_dict(self) -> Dict:
        return {
            "enabled": self.enabled,
            "approved": self.approved,
            "isolation_required": self.isolation_required,
            "selected_engines": self.selected_engines,
            "warnings": self.warnings,
        }


def prepare_dynamic_analysis(
    target_type: str,
    allow_dynamic: bool = False,
    explicit_approval: bool = False,
) -> DynamicPlan:
    """Validates opt-in flags and safety gates before any runtime observation can occur."""
    if not allow_dynamic or not explicit_approval:
        return DynamicPlan(
            enabled=False,
            approved=False,
            isolation_required=True,
            selected_engines=[],
            warnings=[
                "Dynamic analysis is DISABLED by default.",
                "To enable runtime observation, re-run with '--mode full --allow-dynamic' and explicit user approval inside an isolated VM/container/emulator.",
            ],
        )

    engine_map = {
        "android_apk": ["frida-observation", "adb-logcat"],
        "elf_binary": ["strace-trace", "ltrace-trace", "gdb-isolated"],
        "pe_executable": ["sandbox-monitor"],
        "remote_url": ["playwright-browser-observation"],
    }
    engines = engine_map.get(target_type, ["isolated-process-observer"])
    return DynamicPlan(
        enabled=True,
        approved=True,
        isolation_required=True,
        selected_engines=engines,
        warnings=[
            "Execute ONLY inside an isolated environment (e.g., docker run --network none --cap-drop ALL --read-only or dedicated Android emulator).",
            "Never run untrusted binaries or JARs directly on a production host.",
        ],
    )
