"""Actionable installation registry engine for ``TOOL_INSTALLATION_REGISTRY.md``.

This module turns the human-readable registry document into executable policy:

    READ (this registry) -> OFFICIAL REPO -> INSTALL -> CONFIGURE -> VERIFY -> RETRY

Design rules (deliberate, matching the rest of REX):

* No shell execution: every command is an argv list and the registry alone
  decides the arguments. Install hints from documents are never executed.
* A tool is only ``VERIFIED`` after a real version/functional probe succeeds;
  the mere presence of files is ``INSTALLED`` at best.
* Downloads are pinned (version + SHA-256) and restricted to official hosts by
  :mod:`rex.provisioning.releases`.
* System package managers are never invoked with privilege escalation.
* Unsupported environments are reported as ``UNSUPPORTED`` with an exact reason
  instead of being silently skipped.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from rex.provisioning.engine import Provisioner

# ---------------------------------------------------------------------------
# Status vocabulary used by the registry document.
# ---------------------------------------------------------------------------
NOT_INSTALLED = "NOT_INSTALLED"
INSTALLABLE = "INSTALLABLE"
INSTALLING = "INSTALLING"
INSTALLED = "INSTALLED"
CONFIGURED = "CONFIGURED"
VERIFIED = "VERIFIED"
FAILED = "FAILED"
UNSUPPORTED = "UNSUPPORTED"

STATES: Sequence[str] = (
    NOT_INSTALLED, INSTALLABLE, INSTALLING, INSTALLED, CONFIGURED, VERIFIED, FAILED, UNSUPPORTED,
)

STATE_FILE_NAME = "tool_registry_state.json"

#: Extra trusted hosts for pinned managed archives (npm registry + PyPI wheels).
PINNED_ARCHIVE_HOSTS = {"registry.npmjs.org", "files.pythonhosted.org", "pypi.org"}


@dataclass
class Method:
    """A single install method. ``kind`` drives which installer runs."""

    kind: str  # pip | source | archive | system | manual | blocked
    detail: str
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RegistryEntry:
    id: str
    name: str
    priority: int
    purpose: str
    upstream: str
    requirements: List[str]
    methods: Dict[str, List[Method]]  # os -> ordered methods
    verify: List[str]  # argv template, "{exe}" placeholder
    state_exe: Optional[str] = None  # binary to look for on PATH / managed dir
    managed_dir: Optional[str] = None  # ~/.rex/tools/<id>
    notes: str = ""
    unsupported_reason: Optional[str] = None

    def methods_for(self, os_id: str) -> List[Method]:
        return self.methods.get(os_id, []) or self.methods.get("any", [])


def _pip(package: str, detail: str = "") -> Method:
    return Method("pip", detail or f"pip install {package} into a managed venv", {"package": package})


def _source(url: str, sha256: str, configure: List[str], entry: str, detail: str) -> Method:
    return Method(
        "source",
        detail,
        {"url": url, "sha256": sha256, "configure": configure, "entry": entry,
         "max_bytes": 60 * 1024 * 1024},
    )


def _archive(url: str, sha256: str, entry: str, wrapper: str, detail: str,
             strip_components: int = 1, max_bytes: int = 60 * 1024 * 1024) -> Method:
    return Method(
        "archive",
        detail,
        {"url": url, "sha256": sha256, "entry": entry, "strip_components": strip_components,
         "wrapper": wrapper, "max_bytes": max_bytes},
    )


def _blocked(reason: str) -> Method:
    return Method("blocked", reason, {})


# ---------------------------------------------------------------------------
# The registry itself (mirrors TOOL_INSTALLATION_REGISTRY.md).
# ---------------------------------------------------------------------------
RADARE2_TARBALL = "https://codeload.github.com/radareorg/radare2/tar.gz/refs/tags/6.0.7"
RADARE2_SHA256 = "315f988cb5cc6f0e243bf191227cec1f54382056bdf7a1a21b26719528982a1f"
JADX_NODE_TARBALL = "https://registry.npmjs.org/@mishguru/jadx-node/-/jadx-node-3.1.0.tgz"
JADX_NODE_SHA256 = "1521a7a2d64f399cd5a3926a2ae363e4cdc5a81619fbe94a3f3f5c7d3c0263c7"
APKTOOL_TARBALL = "https://registry.npmjs.org/apktool-jar/-/apktool-jar-2.4.1.tgz"
APKTOOL_SHA256 = "65accb583cf50fea0f6990dd92ba6d4d9129945c7c1805a30d3594b75e071dd7"

REGISTRY: List[RegistryEntry] = [
    RegistryEntry(
        id="radare2",
        name="radare2",
        priority=1,
        purpose=("Native binary analysis, disassembly, debugging, binary inspection, "
                 "reverse engineering and scripting."),
        upstream="https://github.com/radareorg/radare2",
        requirements=["C compiler and make", "unzip-capable tar handling"],
        state_exe="r2",
        managed_dir="radare2",
        methods={
            "linux": [
                Method("system", "distribution package radare2", {"manager": "apt-get", "package": "radare2"}),
                _source(RADARE2_TARBALL, RADARE2_SHA256,
                        ["./configure", "--prefix={prefix}"], "bin/radare2",
                        "build from the pinned official source tarball"),
            ],
            "termux": [Method("system", "pkg install radare2", {"manager": "pkg", "package": "radare2"})],
            "darwin": [Method("system", "brew install radare2", {"manager": "brew", "package": "radare2"})],
            "windows": [Method("manual", "official Windows build", {"url": "https://github.com/radareorg/radare2/releases"})],
        },
        verify=["{exe}", "-v"],
        notes="Wrappers r2/rabin2/radare2/rasm2 export the managed library path.",
    ),
    RegistryEntry(
        id="jadx",
        name="JADX",
        priority=1,
        purpose=("Android APK and DEX decompilation, Java source reconstruction, class and "
                 "method analysis for Android application reverse engineering."),
        upstream="https://github.com/skylot/jadx",
        requirements=["Compatible Java runtime", "JADX CLI"],
        state_exe="jadx",
        managed_dir="jadx",
        methods={
            "any": [
                Method("system", "brew/pacman/winget package", {}),
                _archive(JADX_NODE_TARBALL, JADX_NODE_SHA256,
                         "package/resources/jadx-1.1.0", "bin/jadx",
                         "pinned JADX 1.1.0 distribution bundled in @mishguru/jadx-node 3.1.0",
                         max_bytes=40 * 1024 * 1024),
            ],
        },
        verify=["{exe}", "--version"],
        notes="Requires a java executable on PATH (see `rex registry install java`).",
    ),
    RegistryEntry(
        id="apktool",
        name="Apktool",
        priority=1,
        purpose=("Android APK resource decoding, AndroidManifest.xml analysis, Smali extraction, "
                 "APK inspection and authorized rebuilding."),
        upstream="https://github.com/iBotPeaches/Apktool",
        requirements=["Java runtime", "APK decoding functionality"],
        state_exe="apktool",
        managed_dir="apktool",
        methods={
            "any": [
                _archive(APKTOOL_TARBALL, APKTOOL_SHA256,
                         "package/bin", "bin/apktool",
                         "pinned Apktool 2.4.1 jar distributed by the apktool-jar npm package",
                         max_bytes=30 * 1024 * 1024),
                Method("manual", "official Apktool release", {"url": "https://apktool.org/"}),
            ],
        },
        verify=["{exe}", "--version"],
    ),
    RegistryEntry(
        id="binwalk",
        name="Binwalk",
        priority=1,
        purpose=("Firmware analysis, embedded-file detection, signature identification, "
                 "filesystem discovery and extraction of embedded data."),
        upstream="https://github.com/ReFirmLabs/binwalk",
        requirements=["Native binwalk v3 backend (Rust) plus extraction utilities"],
        state_exe="binwalk",
        managed_dir="binwalk",
        methods={
            "any": [
                _blocked("Binwalk v3 requires compiling the Rust backend (no rustc/cargo) and "
                         "binwalk v2 no longer runs on Python 3.11+; the PyPI `binwalk3` "
                         "wrapper ships without the v3 binary."),
            ],
        },
        verify=["{exe}", "--help"],
        notes="REX falls back to its own signature/entropy scanning in the firmware adapter.",
    ),
    RegistryEntry(
        id="tshark",
        name="TShark",
        priority=1,
        purpose=("Network packet analysis, PCAP inspection, protocol detection, packet "
                 "filtering and network artifact investigation."),
        upstream="https://github.com/wireshark/wireshark",
        requirements=["TShark CLI", "offline PCAP reading", "capture permissions are separate"],
        state_exe="tshark",
        managed_dir="tshark",
        methods={
            "linux": [Method("system", "apt-get install tshark", {"manager": "apt-get", "package": "tshark"})],
            "darwin": [Method("system", "brew install wireshark", {"manager": "brew", "package": "wireshark"})],
            "windows": [Method("manual", "official installer", {"url": "https://www.wireshark.org/download.html"})],
        },
        verify=["{exe}", "--version"],
        notes="Capture privileges are never assumed; offline analysis is the default.",
    ),
    RegistryEntry(
        id="ghidra",
        name="Ghidra",
        priority=2,
        purpose=("Advanced software reverse engineering, disassembly, decompilation, function "
                 "and control-flow analysis, symbol analysis and scripting."),
        upstream="https://github.com/NationalSecurityAgency/ghidra",
        requirements=["JDK 25 for Ghidra 12.x", "headless analyzer availability"],
        state_exe="analyzeHeadless",
        managed_dir="ghidra",
        methods={
            "any": [
                Method("release", "pinned Ghidra 12.2 official release",
                       {"tool": "ghidra", "url": "https://github.com/NationalSecurityAgency/ghidra/releases/download/"
                                                 "Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip",
                        "sha256": "2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67",
                        "max_bytes": 600000000, "entry": "ghidra_12.2_PUBLIC/support/analyzeHeadless",
                        "java_min": 25, "format": "zip"}),
            ],
        },
        verify=["{exe}", "-help"],
        notes="The 600 MB release asset host must be reachable; otherwise the state stays INSTALLABLE.",
    ),
    RegistryEntry(
        id="frida",
        name="Frida",
        priority=2,
        purpose=("Dynamic instrumentation, runtime observation, function tracing, debugging and "
                 "authorized application analysis (opt-in; disabled by default)."),
        upstream="https://github.com/frida/frida",
        requirements=["Compatible Python environment", "frida-tools CLI", "device/server access is separate"],
        state_exe="frida",
        managed_dir="frida",
        methods={"any": [_pip("frida-tools==14.13.2", "managed venv with frida-tools 14.13.2")]},
        verify=["{exe}", "--version"],
        notes="Installing frida does not grant instrumentation permission on any device.",
    ),
    RegistryEntry(
        id="java",
        name="Java runtime (dependency)",
        priority=1,
        purpose="Runtime required by JADX, Apktool, Ghidra and Vineflower.",
        upstream="https://openjdk.org/",
        requirements=["JDK/JRE matching the dependent tool"],
        state_exe="java",
        managed_dir="java",
        methods={
            "linux": [Method("system", "default-jre-headless", {"manager": "apt-get", "package": "default-jre-headless"}),
                      _pip("jdk4py==25.0.5.1", "managed Temurin JDK 25 wheel")],
            "darwin": [Method("system", "brew install openjdk", {"manager": "brew", "package": "openjdk"})],
            "windows": [Method("manual", "Temurin installer", {"url": "https://adoptium.net/"})],
            "termux": [Method("system", "pkg install openjdk-17", {"manager": "pkg", "package": "openjdk-17"})],
        },
        verify=["{exe}", "-version"],
    ),
]

BY_ID: Dict[str, RegistryEntry] = {entry.id: entry for entry in REGISTRY}
DEFAULT_PRIORITY: Dict[int, List[str]] = {
    1: [e.id for e in REGISTRY if e.priority == 1],
    2: [e.id for e in REGISTRY if e.priority == 2],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def os_id() -> str:
    if os.environ.get("TERMUX_VERSION") or "com.termux" in os.environ.get("PREFIX", ""):
        return "termux"
    system = platform.system().lower()
    return system if system in {"linux", "darwin", "windows"} else "linux"


def shim_dir(home: Optional[Path] = None) -> Path:
    """User-local executable directory used for registry wrappers."""
    return Path(home or Path.home()) / ".local" / "bin"


def tools_dir(home: Optional[Path] = None) -> Path:
    return Path(home or Path.home()) / ".rex" / "tools"


def state_path(home: Optional[Path] = None) -> Path:
    return Path(home or Path.home()) / ".rex" / STATE_FILE_NAME


def load_state(home: Optional[Path] = None) -> Dict[str, Any]:
    path = state_path(home)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(state: Dict[str, Any], home: Optional[Path] = None) -> Path:
    path = state_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def which_managed(exe: str, home: Optional[Path] = None) -> Optional[str]:
    """PATH lookup that also honours the REX shim dir and per-tool prefixes."""
    base = Path(home or Path.home())
    candidates = [shim_dir(base)]
    root = tools_dir(base)
    if root.is_dir():
        candidates.extend(sorted(p / "bin" for p in root.iterdir() if p.is_dir()))
    for directory in candidates:
        candidate = directory / exe
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    # System tools are only considered for the real home directory; an explicit
    # alternate home (tests, sandboxes) stays isolated from the host PATH unless
    # REX_USE_SYSTEM_PATH is set.
    if base == Path.home() or os.environ.get("REX_USE_SYSTEM_PATH") == "1":
        return shutil.which(exe)
    return None


def _probe(argv: List[str], timeout: int = 90) -> Dict[str, Any]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "detail": str(exc), "version": None}
    output = (proc.stdout or proc.stderr or "").strip()
    first = output.splitlines()[0][:160] if output else ""
    return {"ok": proc.returncode == 0, "detail": output[-400:], "version": first or None}


def detect(entry: RegistryEntry, home: Optional[Path] = None, deep: bool = True) -> Dict[str, Any]:
    """Return the honest state of one registry tool (VERIFIED only after a probe)."""
    exe = which_managed(entry.state_exe, home) if entry.state_exe else None
    record: Dict[str, Any] = {
        "id": entry.id, "name": entry.name, "priority": entry.priority,
        "state": NOT_INSTALLED, "path": exe, "version": None,
        "upstream": entry.upstream, "purpose": entry.purpose,
        "requirements": entry.requirements, "detail": "",
    }
    if exe:
        if not deep:
            record.update(state=INSTALLED, detail="executable present; probe skipped")
            return record
        probe = _probe([exe, *[a for a in entry.verify[1:]]], timeout=120)
        record["version"] = probe["version"]
        if probe["ok"]:
            record.update(state=VERIFIED, detail="version/functional probe succeeded")
        else:
            record.update(state=FAILED, detail=probe["detail"] or "probe failed")
        return record
    methods = entry.methods_for(os_id())
    if methods and methods[0].kind != "blocked":
        record.update(state=INSTALLABLE, detail=methods[0].detail)
    elif methods:
        record.update(state=UNSUPPORTED, detail=methods[0].detail)
    else:
        record.update(state=UNSUPPORTED, detail=f"no install method for {os_id()}")
    return record


def status(home: Optional[Path] = None, deep: bool = True) -> List[Dict[str, Any]]:
    return [detect(entry, home, deep) for entry in REGISTRY]


def plan(home: Optional[Path] = None, ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Preview what installing each tool would do, without touching the disk."""
    wanted = ids or [e.id for e in REGISTRY]
    out = []
    for tool in wanted:
        entry = BY_ID.get(tool)
        if not entry:
            out.append({"id": tool, "state": UNSUPPORTED, "detail": "unknown registry tool"})
            continue
        current = detect(entry, home)
        methods = entry.methods_for(os_id())
        out.append({**current, "methods": [{"kind": m.kind, "detail": m.detail} for m in methods],
                    "managed_dir": str(tools_dir(home) / (entry.managed_dir or tool)),
                    "verify": " ".join(entry.verify), "notes": entry.notes})
    return out


# ---------------------------------------------------------------------------
# Installers
# ---------------------------------------------------------------------------
class RegistryInstaller:
    def __init__(self, home: Optional[Path] = None, dry_run: bool = False,
                 allow_system: bool = False, log: Optional[Callable[[str], None]] = None):
        self.home = Path(home or Path.home())
        self.dry_run = dry_run
        self.allow_system = allow_system
        self.log = log or (lambda msg: None)
        self.state = load_state(self.home)

    # -- bookkeeping -------------------------------------------------------
    def _record(self, tool: str, state: str, **extra: Any) -> None:
        entry = self.state.setdefault("tools", {}).setdefault(tool, {})
        entry.update(state=state, updated_at=time.time(), **extra)
        if not self.dry_run:
            save_state(self.state, self.home)

    def _shim(self, name: str, body: str) -> Path:
        target = shim_dir(self.home) / name
        if self.dry_run:
            self.log(f"[DRY-RUN] wrapper {target}")
            return target
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        target.chmod(0o755)
        return target

    # -- public API --------------------------------------------------------
    def install(self, tool: str, force: bool = False) -> Dict[str, Any]:
        entry = BY_ID.get(tool)
        if not entry:
            return {"tool": tool, "state": UNSUPPORTED, "detail": "unknown registry tool"}
        current = detect(entry, self.home)
        if current["state"] == VERIFIED and not force:
            return {**current, "detail": "already verified"}
        methods = entry.methods_for(os_id())
        if not methods:
            return {**current, "state": UNSUPPORTED, "detail": f"no method for {os_id()}"}
        errors = []
        for method in methods:
            if method.kind == "blocked":
                errors.append(method.detail)
                continue
            if method.kind == "manual":
                errors.append(f"manual installation required: {method.data.get('url')}")
                continue
            if self.dry_run:
                return {**current, "state": INSTALLABLE, "method": {"kind": method.kind, "detail": method.detail},
                        "detail": "dry run: no changes made"}
            self._record(tool, INSTALLING, method=method.detail)
            try:
                if method.kind == "pip":
                    self._install_pip(tool, entry, method)
                elif method.kind == "source":
                    self._install_source(tool, entry, method)
                elif method.kind == "archive":
                    self._install_archive(tool, entry, method)
                elif method.kind == "release":
                    self._install_release(tool, method)
                elif method.kind == "system":
                    self._install_system(method)
                else:
                    raise RuntimeError(f"unsupported method kind {method.kind}")
            except Exception as exc:  # noqa: BLE001 - reported, never raised onward
                errors.append(f"{method.kind}: {exc}")
                self.log(f"[REX] {tool}: {method.kind} failed: {exc}")
                continue
            verified = detect(entry, self.home)
            if verified["state"] == VERIFIED:
                self._record(tool, VERIFIED, path=verified["path"], version=verified["version"],
                             method=method.detail)
                return {**verified, "method": {"kind": method.kind, "detail": method.detail}}
            errors.append(f"{method.kind}: verification failed ({verified['detail'][:200]})")
            self._record(tool, FAILED, detail=verified["detail"][:400], method=method.detail)
        detail = " | ".join(errors)[-800:]
        attempted = {m.kind for m in methods} - {"blocked", "manual"}
        # Honest failure classification: a permanently unavailable tool is
        # UNSUPPORTED, an environment/permission blocker leaves it INSTALLABLE,
        # anything else is a real FAILED install attempt.
        if not attempted:
            state = UNSUPPORTED
        elif "requires --allow-system" in detail:
            state = INSTALLABLE
            detail = "environment limitation: " + detail
        elif "administrator privileges" in detail:
            state = INSTALLABLE
            detail = "environment limitation: " + detail
            if entry.id == "tshark" and os_id() == "linux":
                detail += ("; tshark also has no pinned upstream archive, so a user-level "
                           "install is available only on distributions shipping a binary package")
        else:
            state = FAILED if errors else NOT_INSTALLED
        return {"id": tool, "name": entry.name, "state": state, "detail": detail,
                "path": current.get("path")}

    # -- method implementations -------------------------------------------
    def _install_pip(self, tool: str, entry: RegistryEntry, method: Method) -> None:
        """Use the reviewed Provisioner venv path for pinned PyPI packages."""
        package = method.data["package"]
        provisioner = Provisioner(self.home)
        spec_id = "frida" if tool == "frida" else None
        if spec_id and provisioner.specs.get(spec_id, {}).get("pip_pin") == package:
            plan = provisioner.plan([spec_id])
            results = provisioner.install(plan, dry_run=False, allow_system=False)
            result = results[0]
            if result.get("state") != "verified":
                raise RuntimeError(result.get("detail") or "provisioning failed")
        else:
            self._pip_into_managed_venv(tool, package)
        self._link_pip_binaries(tool)

    def _pip_into_managed_venv(self, tool: str, package: str) -> None:
        root = tools_dir(self.home) / tool
        venv = root / "venv"
        root.mkdir(parents=True, exist_ok=True)
        if not venv.exists():
            subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True,
                           capture_output=True, text=True, timeout=300)
        pip = venv / ("Scripts" if os.name == "nt" else "bin") / ("pip.exe" if os.name == "nt" else "pip")
        proc = subprocess.run([str(pip), "install", "--quiet", "--disable-pip-version-check",
                               "--index-url", "https://pypi.org/simple", package],
                              capture_output=True, text=True, timeout=900, check=False)
        if proc.returncode:
            raise RuntimeError((proc.stderr or proc.stdout)[-400:])
        (root / "metadata.json").write_text(json.dumps(
            {"tool": tool, "package": package, "source": "https://pypi.org/simple",
             "installed_at": time.time()}, indent=2) + "\n", encoding="utf-8")

    def _link_pip_binaries(self, tool: str) -> None:
        root = tools_dir(self.home) / tool
        venv_bin = root / "venv" / ("Scripts" if os.name == "nt" else "bin")
        for name in ("frida", "frida-ps", "frida-trace", "frida-ls-devices"):
            if (venv_bin / name).is_file():
                self._shim(name, f'#!/bin/sh\nexec "{venv_bin / name}" "$@"\n')
        java = venv_bin / "python"
        if tool == "java" and java.is_file():
            self._link_jdk(root, java)

    def _link_jdk(self, root: Path, python: Path) -> None:
        """Expose a jdk4py-managed JDK as ordinary java/javap executables."""
        probe = subprocess.run([str(python), "-c",
                                "import jdk4py, pathlib; print(jdk4py.JAVA_HOME)"],
                               capture_output=True, text=True, timeout=60, check=False)
        if probe.returncode:
            raise RuntimeError("jdk4py is not importable")
        java_home = Path(probe.stdout.strip())
        java_bin = java_home / "bin" / "java"
        if not java_bin.is_file():
            raise RuntimeError("managed JDK has no java executable")
        self._shim("java", f'#!/bin/sh\nJAVA_HOME="{java_home}"\nexport JAVA_HOME\nexec "{java_bin}" "$@"\n')
        (root / "JAVA_HOME").write_text(str(java_home) + "\n", encoding="utf-8")

    def _fetch_pinned(self, url: str, expected: str, max_bytes: int, destination: Path) -> None:
        host = urllib.parse.urlsplit(url).hostname or ""
        if not url.startswith("https://"):
            raise RuntimeError("pinned downloads must use https")
        allowed = {"github.com", "release-assets.githubusercontent.com",
                   "codeload.github.com", *PINNED_ARCHIVE_HOSTS}
        if host not in allowed:
            raise RuntimeError(f"untrusted download host: {host}")
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise RuntimeError("missing pinned SHA-256")
        request = urllib.request.Request(url, headers={"User-Agent": "REX-registry/1"})
        digest = hashlib.sha256()
        total = 0
        with urllib.request.urlopen(request, timeout=120) as response, destination.open("xb") as out:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > max_bytes:
                    raise RuntimeError("download exceeds pinned size limit")
                digest.update(block)
                out.write(block)
        if digest.hexdigest() != expected:
            destination.unlink(missing_ok=True)
            raise RuntimeError("SHA-256 mismatch for pinned download")

    def _install_source(self, tool: str, entry: RegistryEntry, method: Method) -> None:
        data = method.data
        prefix = tools_dir(self.home) / (entry.managed_dir or tool)
        if prefix.exists():
            raise RuntimeError("managed prefix already exists; refusing to overwrite")
        if not shutil.which("make") or not shutil.which("gcc"):
            raise RuntimeError("C toolchain (gcc/make) not available")
        tools_dir(self.home).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".rex-src-", dir=str(tools_dir(self.home))) as stage:
            stage_path = Path(stage)
            archive = stage_path / "source.tar.gz"
            self.log(f"[REX] downloading pinned source {data['url']}")
            self._fetch_pinned(data["url"], data["sha256"], data["max_bytes"], archive)
            source = stage_path / "src"
            source.mkdir()
            with tarfile.open(archive) as tar:
                for member in tar.getmembers():
                    if not (member.isfile() or member.isdir()) or member.name.startswith("/") \
                            or ".." in Path(member.name).parts:
                        raise RuntimeError("unsafe source archive entry")
                tar.extractall(source, filter="data") if hasattr(tarfile, "data_filter") else tar.extractall(source)
            roots = [p for p in source.iterdir() if p.is_dir()]
            build_root = roots[0] if len(roots) == 1 else source
            configure = [a.format(prefix=str(prefix)) for a in data["configure"]]
            for argv in ([configure[0], *configure[1:]], ["make", "-j2"],
                         ["make", "install", f"PREFIX={prefix}"]):
                self.log(f"[REX] {' '.join(argv)}")
                proc = subprocess.run(argv, cwd=str(build_root), capture_output=True, text=True,
                                      timeout=2400, check=False)
                if proc.returncode:
                    raise RuntimeError((proc.stderr or proc.stdout)[-400:])
        entry_path = prefix / data["entry"]
        if not entry_path.is_file():
            raise RuntimeError(f"built executable missing: {entry_path}")
        self._write_prefix_shims(tool, prefix)
        self._record(tool, CONFIGURED, path=str(entry_path), prefix=str(prefix))

    def _write_prefix_shims(self, tool: str, prefix: Path) -> None:
        """Create PATH wrappers for a prefix-style build (libraries live in prefix/lib)."""
        lib = prefix / "lib"
        for name in ("r2", "rabin2", "radare2", "rasm2", "rahash2", "radiff2", "rafind2", "r2pm"):
            exe = prefix / "bin" / name
            if not exe.is_file():
                continue
            self._shim(name, (
                '#!/bin/sh\n'
                f'LD_LIBRARY_PATH="{lib}:{lib / "radare2"}${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}"\n'
                'export LD_LIBRARY_PATH\n'
                f'exec "{exe}" "$@"\n'
            ))
        (prefix / "metadata.json").write_text(json.dumps(
            {"tool": tool, "prefix": str(prefix), "lib": str(lib),
             "installed_at": time.time()}, indent=2) + "\n", encoding="utf-8")
        (prefix / "env.sh").write_text(
            f'# REX managed prefix for {tool}\nexport PATH="{prefix}/bin:$PATH"\n'
            f'export LD_LIBRARY_PATH="{lib}:{lib / "radare2"}${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}"\n',
            encoding="utf-8")

    def _install_archive(self, tool: str, entry: RegistryEntry, method: Method) -> None:
        data = method.data
        dest = tools_dir(self.home) / (entry.managed_dir or tool)
        if dest.exists():
            raise RuntimeError("managed directory already exists; refusing to overwrite")
        tools_dir(self.home).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".rex-arc-", dir=str(tools_dir(self.home))) as stage:
            stage_path = Path(stage)
            archive = stage_path / "archive.tgz"
            self.log(f"[REX] downloading pinned archive {data['url']}")
            self._fetch_pinned(data["url"], data["sha256"], data["max_bytes"], archive)
            extracted = stage_path / "content"
            extracted.mkdir()
            with tarfile.open(archive) as tar:
                members = tar.getmembers()
                total = sum(m.size for m in members)
                if len(members) > 20000 or total > 250 * 1024 * 1024:
                    raise RuntimeError("archive exceeds extraction limits")
                for member in members:
                    path = Path(member.name)
                    if member.issym() or member.islnk() or member.name.startswith("/") or ".." in path.parts:
                        raise RuntimeError("unsafe archive entry")
                tar.extractall(extracted, filter="data") if hasattr(tarfile, "data_filter") else tar.extractall(extracted)
            entry_dir = extracted / data["entry"]
            if not entry_dir.is_dir():
                raise RuntimeError(f"expected payload missing: {data['entry']}")
            payload = dest / "payload"
            payload.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(entry_dir), str(payload))
        script = dest / data["wrapper"]
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(self._wrapper_body(tool, payload), encoding="utf-8")
        script.chmod(0o755)
        (dest / "metadata.json").write_text(json.dumps(
            {"tool": tool, "source": data["url"], "sha256": data["sha256"],
             "installed_at": time.time()}, indent=2) + "\n", encoding="utf-8")
        # Position the wrapper (or its mode-specific JAVA entry) on the shim dir.
        self._shim(tool, f'#!/bin/sh\nexec "{script}" "$@"\n')
        self._shim(shim_entry_name(tool), f'#!/bin/sh\nexec "{script}" "$@"\n')

    def _wrapper_body(self, tool: str, payload: Path) -> str:
        java_lookup = ('JAVA="${REX_JAVA:-}"\n'
                       'if [ -z "$JAVA" ]; then\n'
                       '  if command -v java >/dev/null 2>&1; then JAVA="$(command -v java)"; fi\n'
                       'fi\n'
                       'if [ -z "$JAVA" ]; then echo "rex: java runtime not found; run: rex registry install java" >&2; exit 127; fi\n')
        if tool == "jadx":
            return ("#!/bin/sh\n# REX-managed JADX wrapper (JADX 1.1.0 from the pinned npm archive)\n"
                    + java_lookup +
                    f'exec "$JAVA" -Xmx1024m -cp "{payload}/lib/*" jadx.cli.JadxCLI "$@"\n')
        if tool == "apktool":
            jar = payload / "apktool_2.4.1.jar"
            return ("#!/bin/sh\n# REX-managed Apktool wrapper (2.4.1, pinned npm archive)\n"
                    + java_lookup +
                    f'exec "$JAVA" -jar "{jar}" "$@"\n')
        raise RuntimeError(f"no wrapper template for {tool}")

    def _install_release(self, tool: str, method: Method) -> None:
        """Delegate to the reviewed pinned-release provisioner."""
        data = method.data
        provisioner = Provisioner(self.home)
        spec = provisioner.specs.get(data["tool"])
        if not spec or spec.get("release", {}).get("sha256") != data["sha256"]:
            raise RuntimeError("release pins do not match the central registry")
        results = provisioner.install(provisioner.plan([data["tool"]]), dry_run=False, allow_system=False)
        outcome = next((r for r in results if r.get("tool") == data["tool"]), None)
        if not outcome or outcome.get("state") != "verified" or not outcome.get("path"):
            raise RuntimeError((outcome or {}).get("detail") or "release provisioning failed")
        entry = Path(outcome["path"])
        self._shim(data["tool"], f'#!/bin/sh\nexec "{entry}" "$@"\n')

    def _install_system(self, method: Method) -> None:
        if not self.allow_system:
            raise RuntimeError("system package changes require --allow-system")
        manager, package = method.data["manager"], method.data["package"]
        exe = shutil.which(manager)
        if not exe:
            raise RuntimeError(f"package manager not available: {manager}")
        if manager in {"apt-get", "dnf", "yum", "pacman"} and hasattr(os, "geteuid") and os.geteuid() != 0:
            raise RuntimeError("system package manager requires administrator privileges; "
                               "REX does not escalate")
        commands = {"apt-get": ["install", "-y"], "dnf": ["install", "-y"], "yum": ["install", "-y"],
                    "pacman": ["-S", "--noconfirm"], "pkg": ["install", "-y"], "brew": ["install"]}
        proc = subprocess.run([exe, *commands[manager], package], capture_output=True, text=True,
                              timeout=900, check=False)
        if proc.returncode:
            raise RuntimeError((proc.stderr or proc.stdout)[-400:])


def shim_entry_name(tool: str) -> str:
    """Shim name that matches the registry probe binary."""
    return BY_ID[tool].state_exe if tool in BY_ID and BY_ID[tool].state_exe else tool


def install(tool: str, home: Optional[Path] = None, dry_run: bool = False,
            allow_system: bool = False, force: bool = False,
            log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    installer = RegistryInstaller(home, dry_run=dry_run, allow_system=allow_system, log=log)
    return installer.install(tool, force=force)


def install_priority(priority: int = 1, home: Optional[Path] = None, dry_run: bool = False,
                     allow_system: bool = False, log: Optional[Callable[[str], None]] = None) -> List[Dict[str, Any]]:
    results = []
    for tool in DEFAULT_PRIORITY.get(priority, []):
        results.append(install(tool, home=home, dry_run=dry_run, allow_system=allow_system, log=log))
    return results


def render_status(records: List[Dict[str, Any]]) -> str:
    lines = [f"{'TOOL':<12}{'PRIORITY':<10}{'STATE':<16}{'VERSION / DETAIL'}"]
    lines.append("-" * 96)
    for rec in records:
        tail = (rec.get("version") or rec.get("detail") or "")[:52]
        lines.append(f"{rec['id']:<12}P{rec['priority']:<9}{rec['state']:<16}{tail}")
    return "\n".join(lines)
