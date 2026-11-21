"""Analysis Orchestrator — Coordinates plans, task states, dependencies, failures, and evidence."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from rex.adapters.dynamic_framework import prepare_dynamic_analysis
from rex.adapters.static_adapters import ADAPTER_REGISTRY, AdapterResult
from rex.config import RexConfig
from rex.detectors.target_detector import TargetClassification, detect_target
from rex.ingestion.url_fetcher import inspect_remote_url
from rex.registry.tool_registry import ToolRegistry
from rex.provisioning.engine import Provisioner
from rex.reporting.engine import EvidenceFinding, ReportEngine
from rex.skills.loader import SkillRegistry
from rex.workspace.manager import WorkspaceManager


class TaskState(str, Enum):
    PENDING = "Pending"
    RUNNING = "Running"
    COMPLETED = "Completed"
    FAILED = "Failed"
    SKIPPED = "Skipped"
    BLOCKED = "Blocked"
    CANCELLED = "Cancelled"


@dataclass
class OrchestratorTask:
    task_id: str
    title: str
    adapter: str
    depends_on: List[str] = field(default_factory=list)
    state: str = TaskState.PENDING.value
    summary: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "title": self.title,
            "adapter": self.adapter,
            "depends_on": self.depends_on,
            "state": self.state,
            "summary": self.summary,
            "error": self.error,
        }


class AnalysisOrchestrator:
    def __init__(self, config: RexConfig):
        self.config = config
        self.ws_manager = WorkspaceManager(config.workspaces_dir)
        self.tool_registry = ToolRegistry(venv_python=config.venv_python, run_health_checks=False)
        self.skill_registry = SkillRegistry(config.repo_root)

    def build_plan(self, classification: TargetClassification, mode: str) -> List[OrchestratorTask]:
        tasks: List[OrchestratorTask] = []
        if classification.target_kind == "url":
            tasks.append(OrchestratorTask("task_url_ingest", "Validate & inspect remote URL metadata", "url_ingestion"))
            return tasks

        tasks.append(OrchestratorTask("task_general", "General target metadata, hash, entropy & strings", "general"))

        if mode in ("deep", "full"):
            for adapter_name in classification.recommended_adapters:
                if adapter_name == "general":
                    continue
                tasks.append(
                    OrchestratorTask(
                        task_id=f"task_{adapter_name}",
                        title=f"Domain static analysis ({adapter_name})",
                        adapter=adapter_name,
                        depends_on=["task_general"],
                    )
                )

        if mode == "full":
            tasks.append(
                OrchestratorTask(
                    task_id="task_dynamic",
                    title="Controlled dynamic observation gate",
                    adapter="dynamic",
                    depends_on=["task_general"],
                )
            )
        return tasks

    def execute(
        self,
        target_str: str,
        mode: str = "quick",
        allow_dynamic: bool = False,
        explicit_approval: bool = False,
        cancel_check: Optional[Callable[[], bool]] = None,
        install_missing: bool = False,
    ) -> Dict[str, Any]:
        if mode not in ("quick", "deep", "full"):
            raise ValueError(f"Unsupported analysis mode: {mode!r}. Use quick, deep, or full.")

        classification = detect_target(target_str)
        is_url = classification.target_kind == "url"
        target_path = None if is_url else Path(target_str).resolve()
        label = classification.primary_type if is_url else target_path.name

        run = self.ws_manager.create_run(
            label=label,
            source_path=target_path if (target_path and target_path.is_file()) else None,
            source_url=target_str if is_url else None,
        )

        routed_skills = self.skill_registry.route_for_target(classification.recommended_skills)
        tools_snapshot = [t.to_dict() for t in self.tool_registry.inspect_all()]
        tasks = self.build_plan(classification, mode=mode)

        provisioning = []
        executable_paths = {}
        if install_missing and not is_url and mode in ("deep", "full"):
            # Only tools used by existing adapters; system installs remain disabled.
            needed = {"jvm": ["jadx", "vineflower"], "android": ["jadx", "apktool"],
                      "native": ["radare2"], "firmware": ["binwalk"],
                      "network": ["tshark"]}
            requested = [tool for task in tasks for tool in needed.get(task.adapter, [])]
            if requested:
                engine = Provisioner(self.config.rex_home.parent, offline=self.config.offline_mode)
                try:
                    plan = engine.plan(requested)
                    provisioning = engine.install(plan)
                except (OSError, ValueError, RuntimeError) as exc:
                    provisioning = [{"state": "failed", "detail": str(exc)}]
                tools_snapshot = [t.to_dict() for t in self.tool_registry.inspect_all()]
        # Managed binaries are passed explicitly, never added to process PATH.
        if not is_url and mode in ("deep", "full"):
            engine = Provisioner(self.config.rex_home.parent, offline=self.config.offline_mode)
            for name in ("jadx", "vineflower"):
                if (engine.root / name).is_dir():
                    verified = engine.inspect(name)
                    if verified.get("state") == "verified" and verified.get("path"):
                        executable_paths[name] = verified["path"]

        findings: List[EvidenceFinding] = [
            EvidenceFinding(
                id="REX-001",
                claim=f"Target classified as {classification.primary_type}",
                evidence="; ".join(classification.evidence),
                location=target_str,
                tool="rex.detectors.target_detector",
                confidence=classification.confidence,
                limitations="Classification is based on magic bytes and structural headers.",
            )
        ]
        all_limitations: List[str] = []
        adapter_outputs: Dict[str, Any] = {}
        completed_ids = set()
        failed_ids = set()

        for task in tasks:
            if cancel_check and cancel_check():
                task.state = TaskState.CANCELLED.value
                task.summary = "Cancelled before execution."
                continue

            if any(dep in failed_ids for dep in task.depends_on):
                task.state = TaskState.BLOCKED.value
                task.summary = f"Blocked due to failed dependency: {task.depends_on}"
                continue

            task.state = TaskState.RUNNING.value

            try:
                if task.adapter == "url_ingestion":
                    url_res = inspect_remote_url(
                        target_str,
                        offline_mode=self.config.offline_mode,
                        timeout_sec=self.config.request_timeout_sec,
                        max_bytes=self.config.max_download_bytes,
                        github_token=self.config.secrets.get("GITHUB_TOKEN"),
                    )
                    adapter_outputs[task.adapter] = url_res.to_dict()
                    all_limitations.extend(url_res.limitations)
                    if url_res.status == "skipped_offline":
                        task.state = TaskState.SKIPPED.value
                        task.summary = "Skipped remote fetch in offline mode."
                    elif url_res.status == "completed":
                        task.state = TaskState.COMPLETED.value
                        task.summary = f"Fetched {url_res.platform} metadata."
                        completed_ids.add(task.task_id)
                        findings.append(
                            EvidenceFinding(
                                id=f"REX-{len(findings)+1:03d}",
                                claim=f"Remote {url_res.platform} metadata retrieved",
                                evidence="; ".join(url_res.evidence),
                                location=target_str,
                                tool="rex.ingestion.url_fetcher",
                                confidence="Confirmed",
                            )
                        )
                    else:
                        task.state = TaskState.FAILED.value
                        task.error = "; ".join(url_res.limitations)
                        failed_ids.add(task.task_id)

                elif task.adapter == "dynamic":
                    dyn_plan = prepare_dynamic_analysis(
                        classification.primary_type,
                        allow_dynamic=allow_dynamic,
                        explicit_approval=explicit_approval,
                    )
                    adapter_outputs["dynamic"] = dyn_plan.to_dict()
                    all_limitations.extend(dyn_plan.warnings)
                    if not dyn_plan.enabled:
                        task.state = TaskState.SKIPPED.value
                        task.summary = "Dynamic analysis disabled by default (opt-in + approval required)."
                    else:
                        task.state = TaskState.COMPLETED.value
                        task.summary = f"Dynamic observation plan prepared: {', '.join(dyn_plan.selected_engines)}"
                        completed_ids.add(task.task_id)

                else:
                    adapter_impl = ADAPTER_REGISTRY.get(task.adapter)
                    if not adapter_impl or target_path is None:
                        task.state = TaskState.SKIPPED.value
                        task.summary = f"No adapter implementation for {task.adapter}"
                        continue

                    res: AdapterResult = adapter_impl.run(target_path, run, deep=(mode in ("deep", "full")), tools=executable_paths)
                    adapter_outputs[task.adapter] = res.to_dict()
                    all_limitations.extend(res.limitations)
                    task.state = TaskState.COMPLETED.value
                    task.summary = res.summary
                    completed_ids.add(task.task_id)
                    if res.evidence:
                        findings.append(
                            EvidenceFinding(
                                id=f"REX-{len(findings)+1:03d}",
                                claim=res.summary,
                                evidence="; ".join(res.evidence[:4]),
                                location=str(target_path),
                                tool=f"rex.adapters.{task.adapter}",
                                confidence="Confirmed" if task.adapter in ("general", "minecraft") else "Strongly supported",
                                limitations="; ".join(res.limitations) if res.limitations else "Static inspection scope",
                            )
                        )
            except Exception as exc:
                task.state = TaskState.FAILED.value
                task.error = str(exc)
                task.summary = f"Adapter failed: {exc}"
                failed_ids.add(task.task_id)

        payload = {
            "run_id": run.run_id,
            "workspace_dir": str(run.root),
            "target": target_str,
            "mode": mode,
            "classification": classification.to_dict(),
            "routed_skills": [s.name for s in routed_skills],
            "tasks": [t.to_dict() for t in tasks],
            "tools": tools_snapshot,
            "provisioning": provisioning,
            "adapter_outputs": adapter_outputs,
            "findings": [f.to_dict() for f in findings],
            "limitations": list(dict.fromkeys(all_limitations)),
        }

        report_paths = ReportEngine.write_reports(run, payload)
        payload["reports"] = report_paths
        run.record_metadata({"mode": mode, "primary_type": classification.primary_type, "reports": report_paths})
        return payload
