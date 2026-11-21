#!/usr/bin/env python3
"""REX Command-Line Interface (`rex` / `python3 -m rex.cli`)."""

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

from rex.config import RexConfig, configure_logging
from rex.detectors.target_detector import detect_target
from rex.ingestion.url_fetcher import inspect_remote_url
from rex.minecraft.analyzer import inspect_minecraft_artifact
from rex.orchestrator.engine import AnalysisOrchestrator
from rex.registry.tool_registry import ToolRegistry
from rex.provisioning.engine import Provisioner, PROFILES, environment
from rex.provisioning import managed as registry_engine
from rex.adapters import apk_pipeline
from rex.mcp.health import verify_server
from rex.skills.loader import SkillRegistry
from rex.workspace.manager import WorkspaceManager

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
import install as rex_install  # noqa: E402


def _emit(data, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, indent=2))
    elif isinstance(data, str):
        print(data)
    else:
        print(json.dumps(data, indent=2))


def cmd_doctor(args: argparse.Namespace, cfg: RexConfig) -> int:
    env = rex_install.detect_environment()
    agent = rex_install.detect_agent(cfg.rex_home.parent)
    tools = ToolRegistry(venv_python=cfg.venv_python, run_health_checks=True).inspect_all()
    reg = rex_install.load_registry(cfg.repo_root)
    eligible, skipped = rex_install.evaluate_mcp_gates(reg)
    skills = SkillRegistry(cfg.repo_root).discover()

    summary = {
        "environment": env,
        "detected_agent": agent,
        "offline_mode": cfg.offline_mode,
        "venv_ready": bool(cfg.venv_python),
        "skills_valid": sum(1 for s in skills if s.valid),
        "skills_total": len(skills),
        "tools": [t.to_dict() for t in tools],
        "mcps_eligible_unverified": [s["id"] for s in eligible],
        "provisioning_environment": environment(cfg.rex_home.parent),
        "mcps_skipped": [{"id": s["id"], "missing": m} for s, m in skipped],
    }

    if args.fix:
        provisioner = Provisioner(cfg.rex_home.parent, offline=cfg.offline_mode)
        plan = provisioner.plan(profile="core")
        summary["fix_plan"] = plan
        summary["fix_results"] = provisioner.install(plan, dry_run=args.dry_run)
    if args.json:
        _emit(summary, True)
        return 0

    if args.fix:
        print("Provisioning plan and results: " + json.dumps({"plan": summary["fix_plan"], "results": summary["fix_results"]}, indent=2))
    print("=" * 66)
    print("REX DOCTOR — SYSTEM, TOOL REGISTRY & MCP DIAGNOSTICS")
    print("=" * 66)
    print(f"OS / Arch        : {env['os']} / {env['arch']} (pkg_mgr={env['pkg_mgr'] or 'none'})")
    print(f"Detected Agent   : {agent}")
    print(f"Offline Mode     : {cfg.offline_mode}")
    print(f"Python Venv      : {'READY' if cfg.venv_python else 'NOT INSTALLED'}")
    print(f"Skills Validated : {summary['skills_valid']}/{summary['skills_total']}")
    print("\n--- Tool Registry Statuses ---")
    for t in tools:
        ver_str = f" ({t.version})" if t.version else ""
        print(f"  {t.id:<18} : {t.status:<18}{ver_str}")
    print("\n--- MCP Servers ---")
    for s in eligible:
        print(f"  [ELIGIBLE, NOT VERIFIED]  {s['id']}")
    for s, m in skipped:
        print(f"  [SKIPPED] {s['id']} (missing: {', '.join(m)})")
    print("=" * 66)
    return 0


def cmd_tools(args: argparse.Namespace, cfg: RexConfig) -> int:
    engine = Provisioner(cfg.rex_home.parent, getattr(args, "install_dir", None), cfg.offline_mode)
    action = args.tools_action
    if action in ("list", "check", "missing", "verify"):
        records = engine.plan(ids=list(engine.specs))
        if action == "missing":
            records = [r for r in records if r["current"]["state"] != "verified"]
        _emit(records, args.json)
        return 0
    if action == "uninstall":
        if not args.tool_id:
            raise ValueError("Specify a tool to uninstall")
        _emit(engine.uninstall(args.tool_id, args.dry_run), args.json)
        return 0
    if action == "install":
        plan = engine.plan([args.tool_id] if args.tool_id else None, args.profile)
        # Explicit consent is mandatory for any system package manager.
        if not args.json:
            print("Installation plan:", file=sys.stderr)
            print(json.dumps(plan, indent=2), file=sys.stderr)
        results = engine.install(plan, dry_run=args.dry_run, allow_system=args.allow_system)
        _emit({"plan": plan, "results": results}, args.json)
        return 1 if not args.dry_run and any(r["state"] in ("failed", "blocked", "unsupported", "skipped") for r in results) else 0
    return 1



def cmd_provision(args: argparse.Namespace, cfg: RexConfig) -> int:
    """Review a dependency plan or explicitly approve its execution."""
    if not args.tools and not args.profile:
        raise ValueError("Select tool IDs or a profile")
    # Archive uses the binary names; the central registry uses qualified IDs.
    aliases = {"readelf": "binutils-readelf", "objdump": "binutils-objdump"}
    ids = [aliases.get(tool, tool) for tool in args.tools]
    engine = Provisioner(cfg.rex_home.parent, args.install_dir, cfg.offline_mode)
    plan = engine.plan(ids=ids, profile=args.profile)
    if args.provision_action == "plan":
        _emit({"environment": engine.env, "items": plan}, args.json)
        return 0
    if not args.yes and not args.dry_run:
        _emit({"plan": plan, "results": [{"tool": p["tool"], "state": "approval_required"} for p in plan]}, args.json)
        return 1
    if not args.json:
        print("Installation plan: " + json.dumps(plan, indent=2), file=sys.stderr)
    results = engine.install(plan, dry_run=args.dry_run, allow_system=args.yes and args.allow_system)
    _emit({"plan": plan, "results": results}, args.json)
    return 1 if not args.dry_run and any(r["state"] in ("failed", "blocked", "unsupported", "skipped") for r in results) else 0

def cmd_registry(args: argparse.Namespace, cfg: RexConfig) -> int:
    """Actionable installation registry (TOOL_INSTALLATION_REGISTRY.md).

    READ REGISTRY -> OFFICIAL REPOSITORY -> INSTALL -> CONFIGURE -> VERIFY.
    """
    home = cfg.rex_home.parent
    action = args.registry_action

    def log(message: str) -> None:
        if not args.json:
            print(message, file=sys.stderr)

    if action == "list":
        records = registry_engine.status(home)
        if args.json:
            _emit(records, True)
            return 0
        print(registry_engine.render_status(records))
        print("\nRegistry source: TOOL_INSTALLATION_REGISTRY.md "
              f"({len(registry_engine.REGISTRY)} tools, priority 1 then 2)")
        return 0
    if action == "plan":
        ids = args.tools or None
        _emit(registry_engine.plan(home, ids), args.json)
        return 0
    if action in ("install", "ensure"):
        if args.priority:
            targets = registry_engine.DEFAULT_PRIORITY.get(args.priority, [])
        elif args.tools:
            targets = list(args.tools)
        else:
            raise ValueError("Select tool IDs, --priority 1|2, or --all")
        if args.all:
            targets = [entry.id for entry in registry_engine.REGISTRY]
        results = []
        for tool in targets:
            result = registry_engine.install(tool, home=home, dry_run=args.dry_run,
                                            allow_system=args.allow_system, force=args.force, log=log)
            results.append(result)
            if not args.json:
                state = result.get("state")
                print(f"[{state:<13}] {tool:<10} {(result.get('version') or result.get('detail') or '')[:90]}")
            if action == "ensure" and result.get("state") == registry_engine.VERIFIED and not args.dry_run:
                continue
        _emit({"results": results}, args.json) if args.json else None
        if args.dry_run:
            return 0
        return 1 if any(r.get("state") not in (registry_engine.VERIFIED, "already verified") for r in results) else 0
    if action == "retry":
        # Verify CONFIGURED tools whose probe failed earlier and re-install if needed.
        results = []
        for tool in args.tools or [entry.id for entry in registry_engine.REGISTRY]:
            record = registry_engine.detect(registry_engine.BY_ID[tool], home)
            if record["state"] != registry_engine.VERIFIED:
                record = registry_engine.install(tool, home=home, dry_run=args.dry_run,
                                                 allow_system=args.allow_system, log=log)
            results.append(record)
        _emit({"results": results}, args.json) if args.json else print(registry_engine.render_status(results))
        return 0
    return 1


def cmd_apk(args: argparse.Namespace, cfg: RexConfig) -> int:
    """Android APK reverse engineering: local file, Drive file ID, or direct URL."""
    action = args.apk_action
    out_dir = Path(args.out).expanduser() if getattr(args, "out", None) else None

    if action == "drive":
        listing = apk_pipeline.list_drive_files(
            query=getattr(args, "query", None) or "name contains 'MovieBox'",
            limit=getattr(args, "limit", 25) or 25)
        _emit(listing, args.json)
        return 0 if listing.get("available") else 1

    if action == "validate":
        result = apk_pipeline.validate_apk(Path(args.target).expanduser())
        _emit(result, args.json) if args.json else print(json.dumps(result, indent=2))
        return 0 if result["valid"] else 1

    source = Path(args.target).expanduser() if args.target else None
    if getattr(args, "url", None):
        staging = out_dir or Path(tempfile.gettempdir()) / "rex-apk" / "download"
        fetched = apk_pipeline.fetch_from_url(args.url, staging / "download.apk")
        if not fetched.get("ok"):
            _emit({"error": fetched.get("detail")}, True) if args.json else print(
                f"[REX ERROR] download failed: {fetched.get('detail')}", file=sys.stderr)
            return 1
        source = Path(fetched["path"])
    if not source or not source.is_file():
        raise ValueError("Provide an APK path, --url, or use `rex apk drive --query ...`")

    target_dir = out_dir or (cfg.workspaces_dir / f"apk_{source.stem[:40]}")
    result = apk_pipeline.run_pipeline(source, target_dir)
    if args.json:
        _emit(result, True)
        return 0 if result.get("analyzed") else 1
    if not result.get("analyzed"):
        print(f"[REX] validation failed: {result['validation']['detail']}", file=sys.stderr)
        return 1
    report = result["report"]
    ident = report["identity"]
    print(f"APK          : {ident.get('name')}")
    print(f"SHA-256      : {ident.get('sha256')}")
    print(f"Package      : {ident.get('package')} v{ident.get('version_name')} ({ident.get('version_code')})")
    print(f"Size         : {ident.get('size_bytes', 0)/1048576:.1f} MiB, {len(ident.get('dex_files') or [])} DEX")
    print(f"Signing      : {', '.join(report['signing'].get('schemes') or []) or 'none'}")
    print(f"Classes      : {report['bytecode'].get('classes', 0):,}, methods {report['bytecode'].get('methods', 0):,}")
    print(f"Permissions  : {report['permissions'].get('count', 0)} "
          f"({len(report['permissions'].get('risk') or [])} flagged)")
    print(f"Mod verdict  : {report['mod_analysis'].get('verdict')}")
    print("Findings     :")
    for finding in report["findings"]:
        print(f"  - {finding['id']} ({finding['confidence']}): {finding['claim']}")
    print(f"Markdown     : {result['paths']['markdown']}")
    print(f"JSON         : {result['paths']['json']}")
    return 0


def cmd_skills(args: argparse.Namespace, cfg: RexConfig) -> int:
    specs = [s.to_dict() for s in SkillRegistry(cfg.repo_root).discover()]
    if args.json:
        _emit(specs, True)
    else:
        for s in specs:
            flag = "VALID" if s["valid"] else "INVALID"
            print(f"{s['name']:<22} | {flag:<7} | {s['description']}")
    return 0


def cmd_mcp(args: argparse.Namespace, cfg: RexConfig) -> int:
    reg = rex_install.load_registry(cfg.repo_root)
    eligible, skipped = rex_install.evaluate_mcp_gates(reg)
    if args.mcp_action == "verify":
        server = next((s for s in reg.get("servers", []) if s["id"] == args.server_id), None)
        if not server:
            raise ValueError("Specify a known MCP server ID")
        if cfg.offline_mode:
            result = {"state": "UNSUPPORTED", "detail": "MCP process checks are disabled in offline mode"}
        else:
            result = verify_server(server)
        _emit({"server": server["id"], **result}, args.json)
        return 0 if result["state"] == "VERIFIED" else 1
    out = {
        "eligible_unverified": [s["id"] for s in eligible],
        "skipped": [{"id": s["id"], "missing_binaries": m, "profile": s.get("profile")} for s, m in skipped],
    }
    if args.json:
        _emit(out, True)
    else:
        for s in eligible:
            print(f"[ELIGIBLE, NOT VERIFIED]  {s['id']:<16} — {s['description']}")
        for s, m in skipped:
            print(f"[SKIPPED] {s['id']:<16} — missing {', '.join(m)}")
    return 0


def cmd_target(args: argparse.Namespace, cfg: RexConfig) -> int:
    cls = detect_target(args.target)
    payload = cls.to_dict()
    if args.json:
        _emit(payload, True)
    else:
        print(f"Target       : {args.target}")
        print(f"Kind         : {cls.target_kind}")
        print(f"Primary Type : {cls.primary_type} ({cls.confidence})")
        print(f"Architecture : {cls.architecture or 'N/A'}")
        print(f"Skills       : {', '.join(cls.recommended_skills)}")
        print("Evidence     :")
        for ev in cls.evidence:
            print(f"  - {ev}")
    return 0


def cmd_analyze(args: argparse.Namespace, cfg: RexConfig) -> int:
    orch = AnalysisOrchestrator(cfg)
    result = orch.execute(
        args.target,
        mode=args.mode,
        allow_dynamic=args.allow_dynamic,
        explicit_approval=args.allow_dynamic,
        install_missing=args.install_missing,
    )
    if args.json:
        _emit(result, True)
    else:
        print(f"Run ID       : {result['run_id']}")
        print(f"Workspace    : {result['workspace_dir']}")
        print(f"Target Type  : {result['classification']['primary_type']} ({result['classification']['confidence']})")
        print(f"Markdown Rpt : {result['reports']['markdown']}")
        print(f"JSON Report  : {result['reports']['json']}")
        print("Tasks:")
        for t in result["tasks"]:
            print(f"  - [{t['state']}] {t['task_id']}: {t['summary']}")
    return 0


def cmd_url_or_github(args: argparse.Namespace, cfg: RexConfig) -> int:
    res = inspect_remote_url(
        args.url,
        offline_mode=cfg.offline_mode,
        timeout_sec=cfg.request_timeout_sec,
        max_bytes=cfg.max_download_bytes,
        github_token=cfg.secrets.get("GITHUB_TOKEN"),
    )
    payload = res.to_dict()
    if args.json:
        _emit(payload, True)
    else:
        print(f"URL      : {res.url}")
        print(f"Platform : {res.platform}")
        print(f"Status   : {res.status}")
        for k, v in res.metadata.items():
            print(f"  {k}: {v}")
        for lim in res.limitations:
            print(f"Note: {lim}")
    return 0 if res.status in ("completed", "skipped_offline") else 1


def cmd_minecraft(args: argparse.Namespace, cfg: RexConfig) -> int:
    target = args.target
    if target.startswith(("http://", "https://")):
        return cmd_url_or_github(argparse.Namespace(url=target, json=args.json), cfg)
    data = inspect_minecraft_artifact(Path(target))
    if args.json:
        _emit(data, True)
    else:
        print(f"Artifact      : {data['artifact']}")
        print(f"Platform Type : {data['platform_type']}")
        print(f"Classes       : {data['class_count']}")
        print(f"Metadata      : {json.dumps(data['metadata'])}")
        print(f"Entrypoints   : {', '.join(data['entrypoints']) or 'none'}")
        print(f"Mixins        : {', '.join(data['mixins']) or 'none'}")
        print(f"Commands      : {len(data['commands'])}")
        print(f"Permissions   : {len(data['permissions'])}")
    return 0


def cmd_workspace(args: argparse.Namespace, cfg: RexConfig) -> int:
    wm = WorkspaceManager(cfg.workspaces_dir)
    runs = wm.list_runs()
    if args.json:
        _emit(runs, True)
    else:
        if not runs:
            print("No workspace runs found.")
        for r in runs:
            print(f"{r.get('run_id')} | type={r.get('primary_type', 'unknown')} | mode={r.get('mode', '-')}")
    return 0


def cmd_report(args: argparse.Namespace, cfg: RexConfig) -> int:
    wm = WorkspaceManager(cfg.workspaces_dir)
    run = wm.get_run(args.run_id)
    target_file = run.reports_dir / ("report.json" if args.format == "json" else "report.md")
    if not target_file.exists():
        print(f"Report file not found: {target_file}", file=sys.stderr)
        return 1
    print(target_file.read_text(encoding="utf-8"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rex", description="REX — Reverse Engineering Expert CLI")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    parser.add_argument("--offline", action="store_true", help="Disable outbound network calls")
    parser.add_argument("--home", type=Path, default=None, help="Override home directory")

    sub = parser.add_subparsers(dest="command", required=True)

    p_doctor = sub.add_parser("doctor", help="Inspect OS, tools, skills, and MCP eligibility")
    p_doctor.add_argument("--fix", action="store_true", help="Provision missing core user-level dependencies")
    p_doctor.add_argument("--dry-run", action="store_true")
    p_doctor.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    p_setup = sub.add_parser("setup", help="Provision tools for a profile")
    p_setup.add_argument("--profile", choices=[*PROFILES, "full"], default="core")
    p_setup.add_argument("--dry-run", action="store_true")
    p_setup.add_argument("--allow-system", action="store_true", help="Permit system package manager changes without escalation")
    p_setup.add_argument("--install-dir", type=Path)
    p_setup.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    p_setup.set_defaults(tools_action="install", tool_id="")

    p_tools = sub.add_parser("tools", help="Inspect and provision registered RE tools")
    p_tools.add_argument("tools_action", choices=["list", "check", "missing", "verify", "install", "uninstall"])
    p_tools.add_argument("tool_id", nargs="?", default="")
    p_tools.add_argument("--dry-run", action="store_true")
    p_tools.add_argument("--profile", choices=[*PROFILES, "full"])
    p_tools.add_argument("--install-dir", type=Path, help="Managed tool directory")
    p_tools.add_argument("--allow-system", action="store_true", help="Permit system package manager changes; never escalates privileges")
    p_tools.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    p_tools.add_argument("--offline", action="store_true", default=argparse.SUPPRESS)

    p_provision = sub.add_parser("provision", help="Plan or provision registered analysis tools")
    p_provision.add_argument("provision_action", choices=["plan", "install"])
    p_provision.add_argument("tools", nargs="*", help="Tool IDs to provision")
    p_provision.add_argument("--profile", choices=[*PROFILES, "full"])
    p_provision.add_argument("--yes", action="store_true", help="Confirm installation")
    p_provision.add_argument("--allow-system", action="store_true", help="Permit system changes with --yes; no privilege escalation")
    p_provision.add_argument("--dry-run", action="store_true")
    p_provision.add_argument("--install-dir", type=Path)
    p_provision.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    p_provision.add_argument("--offline", action="store_true", default=argparse.SUPPRESS)

    p_apk = sub.add_parser("apk", help="Android APK reverse engineering (local, Drive ID, or URL)")
    p_apk.add_argument("apk_action", choices=["analyze", "validate", "drive"],
                       help="analyze=full static report, validate=structure only, drive=list Drive candidates")
    p_apk.add_argument("target", nargs="?", help="Path to the .apk file")
    p_apk.add_argument("--url", help="HTTPS URL that returns the APK bytes directly")
    p_apk.add_argument("--out", help="Output directory for the report")
    p_apk.add_argument("--query", default="name contains 'MovieBox'", help="Drive search query for `drive`")
    p_apk.add_argument("--limit", type=int, default=25, help="Max Drive results")
    p_apk.add_argument("--json", action="store_true", default=argparse.SUPPRESS)

    p_registry = sub.add_parser("registry", help="Actionable tool installation registry (TOOL_INSTALLATION_REGISTRY.md)")
    p_registry.add_argument("registry_action", choices=["list", "plan", "install", "ensure", "retry"],
                            help="list=honest states, plan=preview, install/ensure=install+verify, retry=re-verify")
    p_registry.add_argument("tools", nargs="*", help="Registry tool IDs (radare2, jadx, apktool, binwalk, tshark, ghidra, frida, java)")
    p_registry.add_argument("--priority", type=int, choices=[1, 2], help="Install priority 1 or 2 from the registry")
    p_registry.add_argument("--all", action="store_true", help="Install every registry tool")
    p_registry.add_argument("--dry-run", action="store_true")
    p_registry.add_argument("--allow-system", action="store_true", help="Permit system package changes; never escalates privileges")
    p_registry.add_argument("--force", action="store_true", help="Reinstall even when already verified")
    p_registry.add_argument("--json", action="store_true", default=argparse.SUPPRESS)

    p_skills = sub.add_parser("skills", help="List and validate REX skills")
    p_skills.add_argument("skills_action", choices=["list"], default="list", nargs="?")

    p_mcp = sub.add_parser("mcp", help="List active and prerequisite-skipped MCP presets")
    p_mcp.add_argument("mcp_action", choices=["list", "verify"], default="list", nargs="?")
    p_mcp.add_argument("server_id", nargs="?")
    p_mcp.add_argument("--json", action="store_true", default=argparse.SUPPRESS)

    p_target = sub.add_parser("target", help="Classify target using magic bytes and structure")
    p_target.add_argument("target_action", choices=["inspect"])
    p_target.add_argument("target")

    p_analyze = sub.add_parser("analyze", help="Run quick, deep, or full reverse-engineering workflow")
    p_analyze.add_argument("target")
    p_analyze.add_argument("--mode", choices=["quick", "deep", "full"], default="quick")
    p_analyze.add_argument("--install-missing", action="store_true", help="Attempt safe non-system provisioning before analysis")
    p_analyze.add_argument("--allow-dynamic", action="store_true", help="Explicitly opt into controlled dynamic analysis")

    p_url = sub.add_parser("url", help="Safely validate and inspect public URL metadata")
    p_url.add_argument("url_action", choices=["inspect"])
    p_url.add_argument("url")

    p_gh = sub.add_parser("github", help="Inspect public GitHub repository metadata")
    p_gh.add_argument("gh_action", choices=["inspect"])
    p_gh.add_argument("url")

    p_mc = sub.add_parser("minecraft", help="Minecraft Intelligence Pack artifact inspection")
    p_mc.add_argument("mc_action", choices=["inspect"])
    p_mc.add_argument("target")

    p_ws = sub.add_parser("workspace", help="List analysis workspace runs")
    p_ws.add_argument("ws_action", choices=["list"])

    p_rep = sub.add_parser("report", help="Print Markdown or JSON report for a workspace run")
    p_rep.add_argument("run_id")
    p_rep.add_argument("--format", choices=["markdown", "json"], default="markdown")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    configure_logging()
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = RexConfig.load(repo_root=REPO_ROOT, home=args.home, offline_mode=True if args.offline else None)

    try:
        if args.command == "doctor":
            return cmd_doctor(args, cfg)
        if args.command in ("tools", "setup"):
            return cmd_tools(args, cfg)
        if args.command == "provision":
            return cmd_provision(args, cfg)
        if args.command == "apk":
            return cmd_apk(args, cfg)
        if args.command == "registry":
            return cmd_registry(args, cfg)
        if args.command == "skills":
            return cmd_skills(args, cfg)
        if args.command == "mcp":
            return cmd_mcp(args, cfg)
        if args.command == "target":
            return cmd_target(args, cfg)
        if args.command == "analyze":
            return cmd_analyze(args, cfg)
        if args.command in ("url", "github"):
            return cmd_url_or_github(args, cfg)
        if args.command == "minecraft":
            return cmd_minecraft(args, cfg)
        if args.command == "workspace":
            return cmd_workspace(args, cfg)
        if args.command == "report":
            return cmd_report(args, cfg)
    except Exception as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}, indent=2))
        else:
            print(f"[REX ERROR] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
