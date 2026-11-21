"""Centralized RE Tool Registry with granular status classification and health checks."""

import json
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


def find_executable(name: str) -> Optional[str]:
    """PATH lookup that also honours REX-managed locations.

    Registry-installed tools live in ``~/.local/bin`` (wrappers) or in a
    per-tool prefix under ``~/.rex/tools/<tool>/bin``. Only the executable is
    located here; ``PATH`` itself is never mutated.
    """
    home = Path.home()
    candidates = [home / ".local" / "bin"]
    root = home / ".rex" / "tools"
    if root.is_dir():
        candidates.extend(sorted(p / "bin" for p in root.iterdir() if p.is_dir()))
    for directory in candidates:
        candidate = directory / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return shutil.which(name)


class ToolStatus(str, Enum):
    NOT_DETECTED = "not_detected"
    AVAILABLE = "available"
    INSTALLED = "installed"
    CONFIGURED = "configured"
    RUNNING_REACHABLE = "running_reachable"
    HEALTHY = "healthy"
    VERIFIED = "verified"


@dataclass
class ToolRecord:
    id: str
    name: str
    category: str
    purpose: str
    targets: List[str]
    platforms: List[str]
    source: str
    binary: Optional[str]
    python_module: Optional[str]
    version_args: List[str]
    install_hints: Dict[str, str]
    status: str = ToolStatus.NOT_DETECTED.value
    version: Optional[str] = None
    executable_path: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "purpose": self.purpose,
            "targets": self.targets,
            "platforms": self.platforms,
            "source": self.source,
            "binary": self.binary,
            "python_module": self.python_module,
            "status": self.status,
            "version": self.version,
            "executable_path": self.executable_path,
            "install_hints": self.install_hints,
            "notes": self.notes,
        }


DEFAULT_TOOLS: List[Dict[str, Any]] = [
    {
        "id": "python3",
        "name": "Python 3 Runtime",
        "category": "core",
        "purpose": "Core REX engine, binary parsers, entropy, and automation scripts",
        "targets": ["all"],
        "platforms": ["linux", "darwin", "windows", "termux"],
        "source": "https://www.python.org/",
        "binary": "python3",
        "python_module": None,
        "version_args": ["--version"],
        "install_hints": {"apt": "sudo apt install python3", "brew": "brew install python", "pkg": "pkg install python"},
    },
    {
        "id": "lief",
        "name": "LIEF Binary Parser",
        "category": "native-binary",
        "purpose": "Cross-platform ELF, PE, and Mach-O header/section/symbol inspection",
        "targets": ["ELF", "PE", "Mach-O"],
        "platforms": ["linux", "darwin", "windows", "termux"],
        "source": "https://github.com/lief-project/LIEF",
        "binary": None,
        "python_module": "lief",
        "version_args": [],
        "install_hints": {"pip": "~/.rex/venv/bin/pip install lief"},
    },
    {
        "id": "pefile",
        "name": "pefile",
        "category": "native-binary",
        "purpose": "Windows PE/EXE/DLL/SYS and .NET CLR directory inspection",
        "targets": ["PE", "EXE", "DLL", ".NET"],
        "platforms": ["linux", "darwin", "windows", "termux"],
        "source": "https://github.com/erocarrera/pefile",
        "binary": None,
        "python_module": "pefile",
        "version_args": [],
        "install_hints": {"pip": "~/.rex/venv/bin/pip install pefile"},
    },
    {
        "id": "pyelftools",
        "name": "pyelftools",
        "category": "native-binary",
        "purpose": "Pure-Python ELF header, section, relocation, and DWARF parser",
        "targets": ["ELF"],
        "platforms": ["linux", "darwin", "windows", "termux"],
        "source": "https://github.com/eliben/pyelftools",
        "binary": None,
        "python_module": "elftools",
        "version_args": [],
        "install_hints": {"pip": "~/.rex/venv/bin/pip install pyelftools"},
    },
    {
        "id": "capstone",
        "name": "Capstone Disassembler",
        "category": "native-binary",
        "purpose": "Multi-architecture disassembly framework (x86, ARM, ARM64, MIPS, RISC-V)",
        "targets": ["ELF", "PE", "Mach-O", "Shellcode", "Firmware"],
        "platforms": ["linux", "darwin", "windows", "termux"],
        "source": "https://www.capstone-engine.org/",
        "binary": None,
        "python_module": "capstone",
        "version_args": [],
        "install_hints": {"pip": "~/.rex/venv/bin/pip install capstone"},
    },
    {
        "id": "radare2",
        "name": "radare2",
        "category": "native-binary",
        "purpose": "Headless disassembler, binary analyzer, and call-graph generator",
        "targets": ["ELF", "PE", "Mach-O", "DEX", "WASM", "Firmware"],
        "platforms": ["linux", "darwin", "windows", "termux"],
        "source": "https://github.com/radareorg/radare2",
        "binary": "r2",
        "python_module": None,
        "version_args": ["-v"],
        "install_hints": {"apt": "sudo apt install radare2", "brew": "brew install radare2", "pkg": "pkg install radare2"},
    },
    {
        "id": "ghidra",
        "name": "Ghidra Headless Analyzer",
        "category": "native-binary",
        "purpose": "NSA software reverse engineering suite and headless decompiler",
        "targets": ["ELF", "PE", "Mach-O", "Firmware", "Raw Binary"],
        "platforms": ["linux", "darwin", "windows"],
        "source": "https://github.com/NationalSecurityAgency/ghidra",
        "binary": "analyzeHeadless",
        "python_module": None,
        "version_args": [],
        "install_hints": {"brew": "brew install --cask ghidra", "manual": "Download official release from github.com/NationalSecurityAgency/ghidra/releases"},
    },
    {
        "id": "jadx",
        "name": "JADX Decompiler",
        "category": "android-jvm",
        "purpose": "Decompile Android DEX/APK and Java JAR/class files to readable Java source",
        "targets": ["APK", "DEX", "JAR", "AAB"],
        "platforms": ["linux", "darwin", "windows", "termux"],
        "source": "https://github.com/skylot/jadx",
        "binary": "jadx",
        "python_module": None,
        "version_args": ["--version"],
        "install_hints": {"brew": "brew install jadx", "pacman": "sudo pacman -S jadx", "winget": "winget install Skylot.Jadx"},
    },
    {
        "id": "apktool",
        "name": "APKTool",
        "category": "android",
        "purpose": "Decode Android resources, AndroidManifest.xml, and Smali bytecode",
        "targets": ["APK", "AAB"],
        "platforms": ["linux", "darwin", "windows", "termux"],
        "source": "https://apktool.org/",
        "binary": "apktool",
        "python_module": None,
        "version_args": ["--version"],
        "install_hints": {"apt": "sudo apt install apktool", "brew": "brew install apktool", "pkg": "pkg install apktool"},
    },
    {
        "id": "javap",
        "name": "JDK javap Bytecode Disassembler",
        "category": "jvm-minecraft",
        "purpose": "Disassemble JVM .class files and inspect constant pools/descriptors",
        "targets": ["JAR", "Class", "Minecraft Plugin/Mod"],
        "platforms": ["linux", "darwin", "windows", "termux"],
        "source": "https://openjdk.org/",
        "binary": "javap",
        "python_module": None,
        "version_args": ["-version"],
        "install_hints": {"apt": "sudo apt install default-jdk-headless", "brew": "brew install openjdk", "pkg": "pkg install openjdk-17"},
    },
    {
        "id": "binutils-readelf",
        "name": "GNU readelf",
        "category": "native-binary",
        "purpose": "ELF header, section, segment, and symbol table inspection",
        "targets": ["ELF"],
        "platforms": ["linux", "darwin", "termux"],
        "source": "https://www.gnu.org/software/binutils/",
        "binary": "readelf",
        "python_module": None,
        "version_args": ["--version"],
        "install_hints": {"apt": "sudo apt install binutils", "pkg": "pkg install binutils"},
    },
    {
        "id": "binutils-objdump",
        "name": "GNU objdump",
        "category": "native-binary",
        "purpose": "Linear disassembly and section dump for ELF/PE binaries",
        "targets": ["ELF", "PE"],
        "platforms": ["linux", "darwin", "windows", "termux"],
        "source": "https://www.gnu.org/software/binutils/",
        "binary": "objdump",
        "python_module": None,
        "version_args": ["--version"],
        "install_hints": {"apt": "sudo apt install binutils", "pkg": "pkg install binutils"},
    },
    {
        "id": "binwalk",
        "name": "Binwalk Firmware Extractor",
        "category": "firmware",
        "purpose": "Firmware signature scanning, entropy analysis, and filesystem extraction",
        "targets": ["Firmware", "SquashFS", "Bootloader"],
        "platforms": ["linux", "darwin", "termux"],
        "source": "https://github.com/ReFirmLabs/binwalk",
        "binary": "binwalk",
        "python_module": None,
        "version_args": ["--help"],
        "install_hints": {"apt": "sudo apt install binwalk", "brew": "brew install binwalk", "pkg": "pkg install binwalk"},
    },
    {
        "id": "tshark",
        "name": "Wireshark tshark",
        "category": "network",
        "purpose": "Headless PCAP/PCAPNG packet capture dissection and protocol statistics",
        "targets": ["PCAP", "PCAPNG"],
        "platforms": ["linux", "darwin", "windows"],
        "source": "https://www.wireshark.org/",
        "binary": "tshark",
        "python_module": None,
        "version_args": ["--version"],
        "install_hints": {"apt": "sudo apt install tshark", "brew": "brew install wireshark"},
    },
    {
        "id": "frida",
        "name": "Frida Dynamic Instrumentation",
        "category": "dynamic",
        "purpose": "Opt-in authorized runtime hooking and process inspection (disabled by default)",
        "targets": ["Android", "Linux", "Windows", "macOS"],
        "platforms": ["linux", "darwin", "windows"],
        "source": "https://frida.re/",
        "binary": "frida",
        "python_module": "frida",
        "version_args": ["--version"],
        "install_hints": {"pip": "~/.rex/venv/bin/pip install frida-tools"},
    },
    {
        "id": "node",
        "name": "Node.js Runtime",
        "category": "web-js",
        "purpose": "JavaScript AST tooling, Electron ASAR unpacking, and Playwright MCP runner",
        "targets": ["JavaScript", "TypeScript", "Electron", "Web"],
        "platforms": ["linux", "darwin", "windows", "termux"],
        "source": "https://nodejs.org/",
        "binary": "node",
        "python_module": None,
        "version_args": ["--version"],
        "install_hints": {"apt": "sudo apt install nodejs npm", "brew": "brew install node", "pkg": "pkg install nodejs"},
    },
]


class ToolRegistry:
    def __init__(
        self,
        venv_python: Optional[Path] = None,
        which_fn: Callable[[str], Optional[str]] = find_executable,
        run_health_checks: bool = False,
    ):
        self.venv_python = venv_python
        self.which_fn = which_fn
        self.run_health_checks = run_health_checks

    def _check_python_module(self, mod_name: str) -> tuple[bool, Optional[str]]:
        py_exec = str(self.venv_python) if (self.venv_python and self.venv_python.exists()) else None
        if py_exec:
            res = subprocess.run(
                [py_exec, "-c", f"import {mod_name}; print(getattr({mod_name}, '__version__', 'installed'))"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if res.returncode == 0:
                return True, res.stdout.strip() or "installed"
        try:
            mod = __import__(mod_name)
            return True, str(getattr(mod, "__version__", "installed"))
        except Exception:
            return False, None

    def _probe_binary_version(self, exe: str, args: List[str]) -> tuple[bool, Optional[str]]:
        if not args:
            return True, None
        try:
            res = subprocess.run([exe, *args], capture_output=True, text=True, timeout=6, check=False)
            out = (res.stdout or res.stderr or "").strip().splitlines()
            first_line = out[0][:100] if out else None
            return res.returncode == 0, first_line
        except Exception:
            return False, None

    def inspect_all(self) -> List[ToolRecord]:
        records: List[ToolRecord] = []
        for item in DEFAULT_TOOLS:
            rec = ToolRecord(
                id=item["id"],
                name=item["name"],
                category=item["category"],
                purpose=item["purpose"],
                targets=item["targets"],
                platforms=item["platforms"],
                source=item["source"],
                binary=item["binary"],
                python_module=item["python_module"],
                version_args=item["version_args"],
                install_hints=item["install_hints"],
            )

            if rec.binary:
                loc = self.which_fn(rec.binary)
                if loc:
                    rec.executable_path = loc
                    rec.status = ToolStatus.INSTALLED.value
                    if self.run_health_checks:
                        ok, ver = self._probe_binary_version(loc, rec.version_args)
                        if ver:
                            rec.version = ver
                        if ok:
                            rec.status = ToolStatus.HEALTHY.value
                else:
                    rec.status = ToolStatus.NOT_DETECTED.value
            elif rec.python_module:
                ok, ver = self._check_python_module(rec.python_module)
                if ok:
                    rec.status = ToolStatus.HEALTHY.value if self.run_health_checks else ToolStatus.INSTALLED.value
                    rec.version = ver
                    rec.executable_path = str(self.venv_python) if self.venv_python else "system-python"
                else:
                    rec.status = ToolStatus.NOT_DETECTED.value

            records.append(rec)
        return records

    def get_tool(self, tool_id: str) -> Optional[ToolRecord]:
        for rec in self.inspect_all():
            if rec.id == tool_id:
                return rec
        return None

# Provisioning metadata lives alongside the authoritative tool registry. Only
# explicitly mapped packages can be installed; free-form install hints are never
# executed. Versions for isolated PyPI installations are deliberately pinned.
DEFAULT_TOOLS.append({
    "id": "java", "name": "Java runtime", "category": "runtime",
    "purpose": "Java runtime for JVM analysis tools", "targets": ["JVM"],
    "platforms": ["linux", "darwin", "windows", "termux"],
    "source": "https://openjdk.org/", "binary": "java", "python_module": None,
    "version_args": ["-version"], "install_hints": {},
})

# Each entry augments a record in DEFAULT_TOOLS; these are installation policy,
# not another source of tool identity or detection.
for _item in DEFAULT_TOOLS:
    _item.setdefault("dependencies", [])
    _item.setdefault("packages", {})
    _item.setdefault("pip_pin", None)

for _item in DEFAULT_TOOLS:
    _id = _item["id"]
    if _id in ("jadx", "apktool", "ghidra", "javap"):
        _item["dependencies"] = ["java"]
    if _id == "java":
        _item["packages"] = {"apt-get": "default-jre-headless", "pacman": "jre-openjdk", "dnf": "java-17-openjdk", "brew": "openjdk", "pkg": "openjdk-17"}
    elif _id == "jadx":
        _item["packages"] = {"brew": "jadx", "pacman": "jadx"}
    elif _id == "apktool":
        _item["packages"] = {"apt-get": "apktool", "brew": "apktool", "pkg": "apktool"}
    elif _id == "radare2":
        _item["packages"] = {"apt-get": "radare2", "brew": "radare2", "pacman": "radare2", "pkg": "radare2"}
    elif _id == "javap":
        _item["packages"] = {"apt-get": "default-jdk-headless", "brew": "openjdk", "pacman": "jdk-openjdk", "pkg": "openjdk-17"}
    elif _id in ("binutils-readelf", "binutils-objdump"):
        _item["packages"] = {"apt-get": "binutils", "pacman": "binutils", "pkg": "binutils"}
    elif _id == "binwalk":
        _item["packages"] = {"apt-get": "binwalk", "brew": "binwalk", "pacman": "binwalk"}
    elif _id == "tshark":
        _item["packages"] = {"apt-get": "tshark", "dnf": "wireshark-cli", "pacman": "wireshark-cli", "brew": "wireshark"}
    elif _id == "node":
        _item["packages"] = {"apt-get": "nodejs", "dnf": "nodejs", "pacman": "nodejs", "brew": "node", "pkg": "nodejs"}
    elif _id in ("lief", "pefile", "pyelftools", "capstone", "frida"):
        _item["pip_pin"] = {"lief": "lief==0.15.1", "pefile": "pefile==2023.2.7", "pyelftools": "pyelftools==0.31", "capstone": "capstone==5.0.1", "frida": "frida-tools==13.6.1"}[_id]

# Pinned official GitHub release assets. Digests are published in the GitHub
# release API; changing a version requires updating the URL and digest together.
for _item in DEFAULT_TOOLS:
    if _item['id'] == 'jadx':
        _item['release'] = {'version': '1.5.7', 'url': 'https://github.com/skylot/jadx/releases/download/v1.5.7/jadx-1.5.7.zip', 'sha256': '1755e4242ade71a077438723689f404079592ec7764a3a0572f98fef94ebcbf3', 'max_bytes': 90000000, 'entry': 'bin/jadx', 'java_min': 11, 'format': 'zip'}
    elif _item['id'] == 'ghidra':
        _item['release'] = {'version': '12.2', 'url': 'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip', 'sha256': '2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67', 'max_bytes': 600000000, 'entry': 'ghidra_12.2_PUBLIC/support/analyzeHeadless', 'java_min': 25, 'format': 'zip'}
        _item['version_args'] = ['-help']

DEFAULT_TOOLS.append({
    'id': 'vineflower', 'name': 'Vineflower JVM decompiler', 'category': 'jvm',
    'purpose': 'Decompile JVM class and JAR files', 'targets': ['JAR', 'Class'],
    'platforms': ['linux', 'darwin'], 'source': 'https://github.com/Vineflower/vineflower',
    'binary': None, 'python_module': None, 'version_args': [], 'install_hints': {},
    'dependencies': ['java'], 'packages': {}, 'pip_pin': None,
    'release': {'version': '1.12.0', 'url': 'https://github.com/Vineflower/vineflower/releases/download/1.12.0/vineflower-1.12.0.jar', 'sha256': '1dfcfe974395734fa467ce620661c7623d05ba83670de0529b1fbd63ff548b9d', 'max_bytes': 2000000, 'entry': 'vineflower.jar', 'java_min': 17, 'format': 'jar'},
})

# Additional tools from the updated REX provisioning archive.
for _tool in (
    {'id': 'keystone', 'name': 'Keystone assembler', 'category': 'native-binary',
     'purpose': 'Assemble machine instructions', 'targets': ['ELF', 'PE', 'Mach-O'],
     'source': 'https://www.keystone-engine.org/', 'module': 'keystone', 'pin': 'keystone-engine==0.9.2'},
    {'id': 'scapy', 'name': 'Scapy', 'category': 'network',
     'purpose': 'Inspect network packets', 'targets': ['PCAP'],
     'source': 'https://scapy.net/', 'module': 'scapy', 'pin': 'scapy==2.6.1'},
):
    DEFAULT_TOOLS.append({
        'id': _tool['id'], 'name': _tool['name'], 'category': _tool['category'],
        'purpose': _tool['purpose'], 'targets': _tool['targets'],
        'platforms': ['linux', 'darwin', 'windows', 'termux'], 'source': _tool['source'],
        'binary': None, 'python_module': _tool['module'], 'version_args': [],
        'install_hints': {}, 'dependencies': [], 'packages': {}, 'pip_pin': _tool['pin'],
    })
DEFAULT_TOOLS.append({
    'id': 'cfr', 'name': 'CFR Java decompiler', 'category': 'jvm',
    'purpose': 'Java bytecode decompilation (manual installation)', 'targets': ['JAR', 'Class'],
    'platforms': ['linux', 'darwin', 'windows', 'termux'],
    'source': 'https://github.com/leibnitz27/cfr', 'binary': None, 'python_module': None,
    'version_args': [], 'install_hints': {'manual': 'See official upstream releases'},
    'dependencies': ['java'], 'packages': {}, 'pip_pin': None,
})
