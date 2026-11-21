"""Dependency planning and restricted installers for REX's central registry.

Only the static registry controls executable arguments. Never execute install
hints or invoke a shell; system changes require explicit permission.
"""
import json
import hashlib
import os
import platform
import re
import tempfile
import zipfile
import shutil
import subprocess
import sys
import time
from pathlib import Path

from rex.registry.tool_registry import DEFAULT_TOOLS, ToolRegistry
from rex.provisioning.releases import download, extract_zip

PROFILES = {
    "core": ["python3", "lief", "pefile", "pyelftools", "capstone", "keystone", "scapy"],
    "android": ["jadx", "apktool"],
    "native": ["ghidra", "radare2", "binutils-readelf", "binutils-objdump"],
    "jvm": ["java", "javap", "jadx", "vineflower", "cfr"],
    "web": ["node"], "firmware": ["binwalk"],
    "minecraft": ["java", "javap", "jadx", "vineflower", "cfr"],
}
MANAGERS = {
    "linux": ("apt-get", "dnf", "yum", "pacman", "apk", "brew"),
    "darwin": ("brew",), "windows": ("winget", "choco", "scoop"),
    "termux": ("pkg",),
}


def environment(home):
    termux = bool(os.environ.get("TERMUX_VERSION")) or "com.termux" in os.environ.get("PREFIX", "")
    system = "termux" if termux else platform.system().lower()
    machine = platform.machine().lower()
    arch = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    paths = {x: shutil.which(x) for x in ("apt", "apt-get", "dnf", "yum", "pacman", "apk", "brew", "pkg", "winget", "choco", "scoop", "java", "node", "npm", "git", "python3")}
    existing = Path(home).resolve()
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    disk = shutil.disk_usage(existing)
    return {"os": system, "os_version": platform.platform(), "arch": arch,
            "package_managers": [m for m in MANAGERS.get(system, ()) if paths[m]],
            "executables": paths, "python": sys.version.split()[0],
            "disk_free_bytes": disk.free, "path": os.environ.get("PATH", ""),
            "is_root": os.geteuid() == 0 if hasattr(os, "geteuid") else None,
            "venv": str(Path(home) / ".rex" / "venv")}


class Provisioner:
    def __init__(self, home, tools_dir=None, offline=False):
        self.home = Path(home)
        self.root = Path(tools_dir).expanduser().resolve() if tools_dir else (self.home / ".rex" / "tools").resolve()
        self.offline = offline
        self.specs = {x["id"]: x for x in DEFAULT_TOOLS}
        self.env = environment(home)

    def python(self, tool):
        return self.root / tool / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    def inspect(self, tool):
        spec = self.specs[tool]
        # Managed environments are isolated per tool, and take precedence.
        py = self.python(tool)
        if py.is_file() and spec.get("pip_pin"):
            try:
                if spec["binary"]:
                    binary = py.parent / (spec["binary"] + (".exe" if os.name == "nt" else ""))
                    cmd = [str(binary), *spec["version_args"]]
                else:
                    cmd = [str(py), "-c", "import importlib; importlib.import_module(%r)" % spec["python_module"]]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
                if result.returncode == 0:
                    return {"state": "verified", "path": str(binary if spec["binary"] else py), "version": (result.stdout or result.stderr).strip()[:200]}
                return {"state": "failed", "detail": "managed installation failed verification"}
            except (OSError, subprocess.SubprocessError) as exc:
                return {"state": "failed", "detail": str(exc)}
        release = spec.get("release")
        if release:
            dest = self.root / tool
            if dest.is_symlink():
                return {"state": "failed", "detail": "managed directory is a symlink"}
            entry = dest / release["entry"]
            if entry.is_file():
                try:
                    metadata = json.loads((dest / "metadata.json").read_text(encoding="utf-8"))
                    if (metadata.get("tool") != tool or metadata.get("sha256") != release["sha256"] or
                            dest.resolve() not in entry.resolve().parents):
                        raise ValueError("invalid managed release metadata or path")
                    if release["format"] == "jar":
                        with entry.open("rb") as stream:
                            digest = hashlib.sha256()
                            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                                digest.update(chunk)
                        if digest.hexdigest() != release["sha256"]:
                            raise ValueError("managed JAR checksum mismatch")
                except (OSError, ValueError, TypeError) as exc:
                    return {"state": "failed", "detail": str(exc)}
                return self._verify_release(entry, release)
        rec = ToolRegistry(run_health_checks=True).get_tool(tool)
        return {"state": "verified" if rec.status == "healthy" and bool(rec.version_args or rec.python_module) else ("installed_unverified" if rec.status != "not_detected" else "missing"), "path": rec.executable_path, "version": rec.version}

    def plan(self, ids=None, profile=None):
        if profile and profile not in (*PROFILES, "full"):
            raise ValueError("Unknown profile: " + profile)
        wanted = list(ids or [])
        if profile:
            wanted += list(self.specs) if profile == "full" else PROFILES[profile]
        if not wanted:
            wanted = PROFILES["core"][:]
        plan, visiting, done = [], set(), set()
        def visit(tool):
            if tool not in self.specs:
                raise ValueError("Unknown tool: " + tool)
            if tool in visiting:
                raise ValueError("Dependency cycle at " + tool)
            if tool in done:
                return
            visiting.add(tool)
            spec = self.specs[tool]
            for dependency in spec.get("dependencies", []):
                visit(dependency)
            visiting.remove(tool)
            done.add(tool)
            status = self.inspect(tool)
            method = None
            if self.env["os"] in spec["platforms"]:
                # A system package is offered first but not silently installed.
                manager = next((p for p in self.env["package_managers"] if p in spec.get("packages", {})), None)
                if manager:
                    method = {"kind": "system", "manager": manager, "package": spec["packages"][manager]}
                elif spec.get("pip_pin"):
                    method = {"kind": "venv", "package": spec["pip_pin"], "source": "https://pypi.org/"}
                elif spec.get("release") and self.env["os"] in ("linux", "darwin") and self.env["arch"] in ("x86_64", "aarch64"):
                    method = {"kind": "release", **spec["release"]}
            fallback = None
            if (method and method["kind"] == "system" and spec.get("release") and
                    self.env["os"] in ("linux", "darwin") and self.env["arch"] in ("x86_64", "aarch64")):
                fallback = {"kind": "release", **spec["release"]}
            plan.append({"tool": tool, "dependencies": spec.get("dependencies", []), "current": status,
                         "method": method, "fallback": fallback, "source": spec["source"]})
        for tool in wanted:
            visit(tool)
        return plan

    def install(self, plan, dry_run=False, allow_system=False):
        results = []
        states = {}
        for step in plan:
            tool, method = step["tool"], step["method"]
            if method and method["kind"] == "system" and not allow_system and step.get("fallback"):
                method = step["fallback"]
            state = step["current"]["state"]
            result = {"tool": tool, "state": state}
            if state == "verified":
                result["detail"] = "already verified"
            elif dry_run:
                result["state"] = "planned" if method else "unsupported"
                result["method"] = method
            elif any(states.get(dep) != "verified" for dep in step["dependencies"]):
                result.update(state="blocked", detail="dependency not verified")
            elif self.offline:
                result.update(state="skipped", detail="offline mode")
            elif not method:
                result.update(state="unsupported", detail="no compatible trusted installer configured")
            elif self.env["disk_free_bytes"] < 250 * 1024 * 1024:
                result.update(state="skipped", detail="less than 250 MiB free")
            elif method["kind"] == "release" and self.env["disk_free_bytes"] < method["max_bytes"] * 3:
                result.update(state="skipped", detail="insufficient space for download and extraction")
            elif method["kind"] == "system" and not allow_system:
                result.update(state="skipped", detail="system changes require --allow-system and appropriate permissions")
            else:
                try:
                    if method["kind"] == "venv":
                        self._install_venv(tool, method["package"])
                    elif method["kind"] == "release":
                        self._install_release(tool, method)
                    else:
                        self._install_system(method)
                    checked = self.inspect(tool)
                    result.update(checked)
                    if checked["state"] != "verified":
                        result.update(state="failed", detail="installation finished but execution verification failed")
                except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, subprocess.SubprocessError) as exc:
                    result.update(state="failed", detail=str(exc))
            states[tool] = result["state"]
            results.append(result)
        return results

    def _install_venv(self, tool, package):
        dest = self.root / tool
        if dest.exists() or dest.is_symlink():
            raise RuntimeError("managed destination already exists; refusing to overwrite")
        self.root.mkdir(parents=True, exist_ok=True)
        dest.mkdir()
        try:
            log = dest / "install.log"
            with log.open("w", encoding="utf-8") as out:
                for cmd in ([sys.executable, "-m", "venv", str(dest / "venv")],
                            [str(self.python(tool)), "-m", "pip", "--isolated", "install", "--disable-pip-version-check", "--only-binary=:all:", "--index-url", "https://pypi.org/simple", package]):
                    completed = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT, timeout=600, check=False)
                    if completed.returncode:
                        raise RuntimeError("installer failed (exit %s); transaction rolled back" % completed.returncode)
            check = self.inspect(tool)
            if check["state"] != "verified":
                raise RuntimeError("post-install verification failed: " + str(check))
            (dest / "metadata.json").write_text(json.dumps({"tool": tool, "package": package, "source": "https://pypi.org/simple", "installed_at": time.time(), "verification": check}, indent=2), encoding="utf-8")
        except Exception:
            # Only the freshly-created directory belongs to this transaction.
            shutil.rmtree(dest)
            raise

    def _java_version(self):
        exe = shutil.which("java")
        if not exe:
            raise RuntimeError("Java runtime not found")
        proc = subprocess.run([exe, "-version"], capture_output=True, text=True, timeout=15, check=False)
        output = proc.stderr or proc.stdout
        match = re.search(r'version\s+"(\d+)(?:\.(\d+))?', output)
        if proc.returncode or not match:
            raise RuntimeError("Could not verify Java runtime version")
        major = int(match.group(1))
        return int(match.group(2)) if major == 1 and match.group(2) else major

    def _verify_release(self, entry, release):
        try:
            java = shutil.which("java")
            if not java or self._java_version() < release["java_min"]:
                return {"state": "failed", "detail": "Java %s or newer is required" % release["java_min"]}
            if release["format"] == "jar":
                cmd = [java, "-jar", str(entry), "--help"]
            else:
                args = ["-help"] if entry.name == "analyzeHeadless" else ["--version"]
                cmd = [str(entry), *args]
            run = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
            if run.returncode != 0:
                return {"state": "failed", "detail": (run.stderr or run.stdout or "verification failed")[-500:]}
            return {"state": "verified", "path": str(entry), "version": release["version"]}
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            return {"state": "failed", "detail": str(exc)}

    def _install_release(self, tool, release):
        if self._java_version() < release["java_min"]:
            raise RuntimeError("Java %s or newer is required" % release["java_min"])
        dest = self.root / tool
        if dest.exists() or dest.is_symlink():
            raise RuntimeError("managed destination already exists; refusing to overwrite")
        self.root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".rex-stage-", dir=str(self.root)) as stage:
            stage = Path(stage)
            asset = stage / "download"
            content = stage / "content"
            content.mkdir()
            download(release["url"], asset, release["sha256"], release["max_bytes"])
            if release["format"] == "zip":
                extract_zip(asset, content)
            elif release["format"] == "jar":
                shutil.move(str(asset), str(content / release["entry"]))
            else:
                raise ValueError("unsupported release format")
            entry = content / release["entry"]
            if not entry.is_file() or content.resolve() not in entry.resolve().parents:
                raise RuntimeError("expected release executable is missing")
            check = self._verify_release(entry, release)
            if check["state"] != "verified":
                raise RuntimeError("release verification failed: " + str(check.get("detail")))
            (content / "metadata.json").write_text(json.dumps({"tool": tool, "version": release["version"], "source": release["url"], "sha256": release["sha256"], "installed_at": time.time()}, indent=2), encoding="utf-8")
            content.rename(dest)

    def _install_system(self, method):
        mgr, package = method["manager"], method["package"]
        commands = {"apt-get": ["install", "-y"], "dnf": ["install", "-y"], "yum": ["install", "-y"],
                    "pacman": ["-S", "--noconfirm"], "pkg": ["install", "-y"], "brew": ["install"]}
        if mgr not in commands:
            raise RuntimeError("package manager installation is not implemented: " + mgr)
        exe = shutil.which(mgr)
        if not exe:
            raise RuntimeError("package manager no longer available")
        if mgr in ("apt-get", "dnf", "yum", "pacman") and hasattr(os, "geteuid") and os.geteuid() != 0:
            raise RuntimeError("system package manager requires administrator privileges; no escalation attempted")
        proc = subprocess.run([exe, *commands[mgr], package], capture_output=True, text=True, timeout=900, check=False)
        if proc.returncode:
            raise RuntimeError("package manager failed: " + (proc.stderr or proc.stdout)[-1000:])

    def uninstall(self, tool, dry_run=False):
        if tool not in self.specs:
            raise ValueError("Unknown tool: " + tool)
        dest = self.root / tool
        if dest.is_symlink() or not (dest / "metadata.json").is_file():
            raise ValueError("No verified REX-managed installation for " + tool)
        meta = json.loads((dest / "metadata.json").read_text(encoding="utf-8"))
        if meta.get("tool") != tool:
            raise ValueError("Invalid installation metadata")
        if not dry_run:
            shutil.rmtree(dest)
        return {"tool": tool, "state": "planned_removal" if dry_run else "removed"}
