#!/usr/bin/env python3
"""
REX — Reverse Engineering Expert Auto-Installer
Zero-dependency Python 3.9+ stdlib bootstrapper for AI coding agents.
"""

import argparse
import datetime
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent
CORE_PYTHON_LIBS = [
    "lief",
    "pefile",
    "pyelftools",
    "capstone",
    "keystone-engine",
    "scapy",
]

PROFILE_PACKAGES: Dict[str, Dict[str, List[str]]] = {
    "android": {
        "apt": ["apktool", "android-tools-adb", "default-jre-headless"],
        "brew": ["jadx", "apktool", "android-platform-tools"],
        "pkg": ["apktool", "android-tools", "openjdk-17"],
        "winget": ["Skylot.Jadx", "Google.PlatformTools"],
        "pacman": ["jadx", "android-tools"],
    },
    "native": {
        "apt": ["radare2", "binutils", "gdb", "file"],
        "brew": ["radare2", "rizin", "binutils"],
        "pkg": ["radare2", "binutils", "gdb", "file"],
        "winget": ["Radare.Radare2"],
        "pacman": ["radare2", "rizin", "binutils", "gdb"],
    },
    "web": {
        "npm": ["js-beautify", "source-map-explorer"],
    },
    "firmware": {
        "apt": ["binwalk", "squashfs-tools", "mtd-utils"],
        "brew": ["binwalk", "squashfs"],
        "pkg": ["binwalk", "squashfs-tools"],
        "pacman": ["binwalk", "squashfs-tools", "mtd-utils"],
    },
    "minecraft": {
        "apt": ["default-jdk-headless", "unzip"],
        "brew": ["openjdk", "jadx"],
        "pkg": ["openjdk-17", "unzip"],
        "pacman": ["jdk-openjdk", "jadx"],
        "winget": ["EclipseAdoptium.Temurin.21.JDK", "Skylot.Jadx"],
    },
}


def detect_environment() -> Dict[str, Optional[str]]:
    sys_name = platform.system().lower()
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        arch = "x86_64"
    elif machine in ("arm64", "aarch64"):
        arch = "aarch64"
    else:
        arch = machine

    is_termux = bool(os.environ.get("TERMUX_VERSION")) or "com.termux" in os.environ.get("PREFIX", "")
    os_id = "termux" if is_termux else ("darwin" if sys_name == "darwin" else ("windows" if sys_name == "windows" else "linux"))

    pkg_mgr = None
    candidates = ["pkg", "apt", "brew", "pacman", "winget", "choco"] if is_termux else ["apt", "brew", "pacman", "winget", "choco", "pkg"]
    for pm in candidates:
        if shutil.which(pm):
            pkg_mgr = pm
            break

    is_root = False
    if hasattr(os, "geteuid"):
        is_root = os.geteuid() == 0

    return {
        "os": os_id,
        "arch": arch,
        "pkg_mgr": pkg_mgr,
        "is_termux": str(is_termux).lower(),
        "is_root": str(is_root).lower(),
    }


def get_agent_paths(agent: str, home: Path) -> Dict[str, Path]:
    mapping = {
        "claude": {
            "skills_dir": home / ".claude" / "skills",
            "config_file": home / ".claude.json",
            "format": "json",
        },
        "codex": {
            "skills_dir": home / ".codex" / "skills",
            "config_file": home / ".codex" / "config.toml",
            "format": "toml",
        },
        "opencode": {
            "skills_dir": home / ".config" / "opencode" / "skills",
            "config_file": home / ".config" / "opencode" / "opencode.json",
            "format": "json",
        },
        "cursor": {
            "skills_dir": home / ".cursor" / "rules",
            "config_file": home / ".cursor" / "mcp.json",
            "format": "json",
        },
        "generic": {
            "skills_dir": home / ".rex" / "installed" / "skills",
            "config_file": home / ".rex" / "installed" / "mcp.json",
            "format": "json",
        },
    }
    return mapping[agent]


def detect_agent(home: Path) -> str:
    if (home / ".claude").exists() or (home / ".claude.json").exists():
        return "claude"
    if (home / ".codex").exists():
        return "codex"
    if (home / ".config" / "opencode").exists():
        return "opencode"
    if (home / ".cursor").exists():
        return "cursor"
    return "generic"


def load_registry(repo_root: Path = REPO_ROOT) -> Dict:
    reg_path = repo_root / "mcp-presets" / "registry.json"
    return json.loads(reg_path.read_text(encoding="utf-8"))


def evaluate_mcp_gates(registry: Dict, which_fn=shutil.which) -> Tuple[List[Dict], List[Tuple[Dict, List[str]]]]:
    eligible = []
    skipped = []
    for server in registry.get("servers", []):
        missing = [b for b in server.get("required_binaries", []) if not which_fn(b)]
        if missing:
            skipped.append((server, missing))
        else:
            eligible.append(server)
    return eligible, skipped


def backup_file(target: Path, backup_dir: Path, dry_run: bool = False) -> Optional[Path]:
    if not target.exists():
        return None
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"{ts}_{target.name}"
    if dry_run:
        print(f"[DRY-RUN] Backup {target} -> {backup_path}")
        return backup_path
    backup_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(target, backup_path)
    return backup_path


def atomic_write_text(target: Path, content: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".rex_tmp_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_name, target)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise


def merge_json_mcp_config(config_file: Path, servers: List[Dict], dry_run: bool = False) -> List[str]:
    if config_file.exists():
        raw = config_file.read_text(encoding="utf-8").strip()
        data = json.loads(raw) if raw else {}
    else:
        data = {}

    if not isinstance(data, dict):
        raise ValueError(f"Config file {config_file} does not contain a JSON object.")

    mcp_servers = data.setdefault("mcpServers", {})
    if not isinstance(mcp_servers, dict):
        raise ValueError(f"'mcpServers' in {config_file} must be a JSON object.")

    added_ids = []
    for srv in servers:
        mcp_servers[srv["id"]] = srv["mcp_config"]
        added_ids.append(srv["id"])

    serialized = json.dumps(data, indent=2) + "\n"
    json.loads(serialized)

    if dry_run:
        print(f"[DRY-RUN] Would merge {len(added_ids)} MCP servers into {config_file}: {added_ids}")
    else:
        atomic_write_text(config_file, serialized)
    return added_ids


def merge_toml_mcp_config(config_file: Path, servers: List[Dict], dry_run: bool = False) -> List[str]:
    existing = config_file.read_text(encoding="utf-8") if config_file.exists() else ""
    start_marker = "# >>> REX MCP SERVERS >>>"
    end_marker = "# <<< REX MCP SERVERS <<<"

    if start_marker in existing and end_marker in existing:
        before = existing.split(start_marker)[0].rstrip()
        after = existing.split(end_marker)[-1].lstrip()
        base_text = (before + "\n\n" + after).strip()
    else:
        base_text = existing.strip()

    blocks = [start_marker]
    added_ids = []
    for srv in servers:
        sid = srv["id"]
        cfg = srv["mcp_config"]
        cmd = cfg["command"].replace('"', '\\"')
        args_toml = ", ".join(f'"{a.replace(chr(34), chr(92) + chr(34))}"' for a in cfg.get("args", []))
        blocks.append(f'[mcp_servers."{sid}"]')
        blocks.append(f'command = "{cmd}"')
        blocks.append(f"args = [{args_toml}]")
        blocks.append("")
        added_ids.append(sid)
    blocks.append(end_marker)

    new_content = (base_text + "\n\n" if base_text else "") + "\n".join(blocks) + "\n"
    if dry_run:
        print(f"[DRY-RUN] Would merge {len(added_ids)} MCP servers into {config_file}: {added_ids}")
    else:
        atomic_write_text(config_file, new_content)
    return added_ids


def install_skills(skills_dest: Path, repo_root: Path = REPO_ROOT, dry_run: bool = False) -> List[str]:
    installed = []
    skills_src = repo_root / "skills"
    knowledge_src = repo_root / "knowledge"

    for skill_dir in sorted(skills_src.iterdir()):
        if not skill_dir.is_dir() or not (skill_dir / "SKILL.md").exists():
            continue
        dest_dir = skills_dest / skill_dir.name
        if dry_run:
            print(f"[DRY-RUN] Copy skill {skill_dir.name} -> {dest_dir}")
        else:
            if dest_dir.exists():
                shutil.rmtree(dest_dir)
            shutil.copytree(skill_dir, dest_dir)
        installed.append(skill_dir.name)

    knowledge_dest = skills_dest.parent / "rex-knowledge"
    if knowledge_src.exists():
        if dry_run:
            print(f"[DRY-RUN] Copy knowledge -> {knowledge_dest}")
        else:
            if knowledge_dest.exists():
                shutil.rmtree(knowledge_dest)
            shutil.copytree(knowledge_src, knowledge_dest)
    return installed


def setup_core_venv(rex_home: Path, dry_run: bool = False) -> Path:
    venv_dir = rex_home / "venv"
    if dry_run:
        print(f"[DRY-RUN] Create Python venv at {venv_dir} and install: {', '.join(CORE_PYTHON_LIBS)}")
        return venv_dir
    if not venv_dir.exists():
        print(f"[REX] Creating isolated Python venv at {venv_dir}...")
        subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=False)
    pip_bin = venv_dir / ("Scripts" if os.name == "nt" else "bin") / ("pip.exe" if os.name == "nt" else "pip")
    if pip_bin.exists():
        print(f"[REX] Installing lightweight Python RE libraries into {venv_dir}...")
        subprocess.run([str(pip_bin), "install", "--quiet", "--disable-pip-version-check", *CORE_PYTHON_LIBS], check=False)
    else:
        print("[REX] Warning: pip not found inside venv; skipping Python RE library install.")
    return venv_dir


def install_profile_packages(profile: str, env: Dict[str, Optional[str]], dry_run: bool = False) -> None:
    profiles = ["android", "native", "web", "firmware", "minecraft"] if profile == "full" else ([profile] if profile != "core" else [])
    if not profiles:
        return

    pkg_mgr = env.get("pkg_mgr")
    use_sudo = env["os"] == "linux" and env["is_root"] != "true" and bool(shutil.which("sudo"))

    for prof in profiles:
        spec = PROFILE_PACKAGES.get(prof, {})
        if "npm" in spec and shutil.which("npm"):
            cmd = ["npm", "install", "-g", *spec["npm"]]
            if dry_run:
                print(f"[DRY-RUN] Run: {' '.join(cmd)}")
            else:
                print(f"[REX] Installing {prof} npm utilities...")
                subprocess.run(cmd, check=False)
        if pkg_mgr and pkg_mgr in spec:
            pkgs = spec[pkg_mgr]
            if pkg_mgr == "apt":
                cmd = (["sudo"] if use_sudo else []) + ["apt-get", "install", "-y", *pkgs]
            elif pkg_mgr == "brew":
                cmd = ["brew", "install", *pkgs]
            elif pkg_mgr == "pkg":
                cmd = ["pkg", "install", "-y", *pkgs]
            elif pkg_mgr == "pacman":
                cmd = (["sudo"] if use_sudo else []) + ["pacman", "-S", "--noconfirm", *pkgs]
            elif pkg_mgr == "winget":
                for p in pkgs:
                    wcmd = ["winget", "install", "--silent", "--accept-package-agreements", "--accept-source-agreements", p]
                    if dry_run:
                        print(f"[DRY-RUN] Run: {' '.join(wcmd)}")
                    else:
                        subprocess.run(wcmd, check=False)
                continue
            else:
                continue
            if dry_run:
                print(f"[DRY-RUN] Run: {' '.join(cmd)}")
            else:
                print(f"[REX] Installing {prof} packages via {pkg_mgr}: {', '.join(pkgs)}")
                subprocess.run(cmd, check=False)


def uninstall_rex(home: Path, dry_run: bool = False) -> None:
    rex_home = home / ".rex"
    state_file = rex_home / "state.json"
    if not state_file.exists():
        print("[REX] No installation state found at ~/.rex/state.json. Nothing to uninstall.")
        return

    state = json.loads(state_file.read_text(encoding="utf-8"))
    skills_dir = Path(state["skills_dir"])
    for skill_name in state.get("installed_skills", []):
        target = skills_dir / skill_name
        if target.exists():
            if dry_run:
                print(f"[DRY-RUN] Remove skill directory {target}")
            else:
                shutil.rmtree(target)

    knowledge_dir = skills_dir.parent / "rex-knowledge"
    if knowledge_dir.exists():
        if dry_run:
            print(f"[DRY-RUN] Remove knowledge directory {knowledge_dir}")
        else:
            shutil.rmtree(knowledge_dir)

    config_file = Path(state["config_file"])
    backup_path = state.get("backup_file")
    if backup_path and Path(backup_path).exists():
        if dry_run:
            print(f"[DRY-RUN] Restore {config_file} from backup {backup_path}")
        else:
            shutil.copy2(backup_path, config_file)
            print(f"[REX] Restored original config: {config_file}")
    elif config_file.exists() and state.get("config_created_by_rex"):
        if dry_run:
            print(f"[DRY-RUN] Remove REX-created config {config_file}")
        else:
            config_file.unlink()

    if not dry_run:
        state_file.unlink(missing_ok=True)
        print("[REX] Uninstall complete.")


def run_install(
    profile: str = "core",
    agent: str = "auto",
    dry_run: bool = False,
    home: Optional[Path] = None,
    skip_venv: bool = False,
    repo_root: Path = REPO_ROOT,
) -> Dict:
    home_dir = home or Path.home()
    rex_home = home_dir / ".rex"
    backup_dir = rex_home / "backups"
    env = detect_environment()
    resolved_agent = detect_agent(home_dir) if agent == "auto" else agent
    paths = get_agent_paths(resolved_agent, home_dir)

    print(f"[REX] OS={env['os']} Arch={env['arch']} PkgMgr={env['pkg_mgr']} Agent={resolved_agent} Profile={profile}")

    installed_skills = install_skills(paths["skills_dir"], repo_root=repo_root, dry_run=dry_run)

    if not skip_venv:
        setup_core_venv(rex_home, dry_run=dry_run)

    if dry_run:
        install_profile_packages(profile, env, dry_run=True)
    elif profile != "core":
        print("[REX] System packages not installed by bootstrap. Use rex tools install --profile " + profile + " --allow-system after reviewing the plan.")

    registry = load_registry(repo_root=repo_root)
    eligible, skipped = evaluate_mcp_gates(registry)

    config_file = paths["config_file"]
    existed_before = config_file.exists()
    backup_path = backup_file(config_file, backup_dir, dry_run=dry_run)

    if paths["format"] == "toml":
        added_mcps = merge_toml_mcp_config(config_file, eligible, dry_run=dry_run)
    else:
        added_mcps = merge_json_mcp_config(config_file, eligible, dry_run=dry_run)

    for srv, missing in skipped:
        print(
            f"[REX] SKIPPED {srv['id']} — missing binaries: {', '.join(missing)}. "
            f"Run 'python3 install.py --profile {srv.get('profile', 'full')}' to enable."
        )

    state = {
        "installed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "agent": resolved_agent,
        "profile": profile,
        "skills_dir": str(paths["skills_dir"]),
        "installed_skills": installed_skills,
        "config_file": str(config_file),
        "backup_file": str(backup_path) if backup_path else None,
        "config_created_by_rex": not existed_before,
        "active_mcps": added_mcps,
        "skipped_mcps": [s["id"] for s, _ in skipped],
    }

    if not dry_run:
        rex_home.mkdir(parents=True, exist_ok=True)
        atomic_write_text(rex_home / "state.json", json.dumps(state, indent=2) + "\n")
        print(f"[REX] Installation complete! Active skills: {len(installed_skills)}, Configured MCPs (not connectivity verified): {len(added_mcps)}, Skipped MCPs: {len(skipped)}")
    else:
        print("[REX] Dry-run complete. No files were modified.")

    return state


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="REX — Reverse Engineering Expert Auto-Installer")
    parser.add_argument("--auto", action="store_true", help="Non-interactive instant core setup")
    parser.add_argument("--profile", choices=["core", "full", "android", "native", "web", "firmware", "minecraft"], default="core")
    parser.add_argument("--agent", choices=["auto", "claude", "codex", "opencode", "cursor", "generic"], default="auto")
    parser.add_argument("--dry-run", action="store_true", help="Preview planned actions without modifying disk")
    parser.add_argument("--uninstall", action="store_true", help="Remove REX skills and restore backed-up configs")
    parser.add_argument("--skip-venv", action="store_true", help="Skip creating ~/.rex/venv (useful in offline/CI environments)")
    parser.add_argument("--home", type=Path, default=None, help="Override home directory (primarily for testing)")

    args = parser.parse_args(argv)
    if args.uninstall:
        uninstall_rex(args.home or Path.home(), dry_run=args.dry_run)
        return 0

    run_install(
        profile=args.profile,
        agent=args.agent,
        dry_run=args.dry_run,
        home=args.home,
        skip_venv=args.skip_venv,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
