# REX — Reverse Engineering Expert

**One Repository. One Installer. A Complete Reverse-Engineering Ecosystem.**

Paste this repository URL into **Claude Code, Codex, OpenCode, or Cursor** and say:

> *"Install this"*

Your AI agent will read `AGENTS.md`, detect your OS and installed runtimes, install 11 consolidated Reverse Engineering skills (including the **Minecraft Intelligence Pack**), configure the modular `rex` CLI engine, and safely register compatible upstream RE MCP servers without breaking your existing configuration.

---

## Quick Start (Installation & Diagnostics)

`install.py` and the core `rex` engine use **Python 3.9+ standard library only** (zero mandatory external dependencies required to run).

```bash
# 1. Instant Core install (skills + Python RE venv + compatible MCPs)
python3 install.py --auto

# 2. Preview changes without modifying disk
python3 install.py --auto --dry-run

# 3. Check environment, tool registry statuses, and MCP health
python3 -m rex.cli doctor

# 4. Install domain-specific heavy toolchains (Tier 2)
python3 install.py --profile android
python3 install.py --profile native
python3 install.py --profile web
python3 install.py --profile firmware
python3 install.py --profile minecraft
python3 install.py --profile full

# 5. Clean uninstall & restore backed-up agent configs
python3 install.py --uninstall
```

---

## CLI Usage (`python3 -m rex.cli` or `rex`)

All commands support `--json` for machine-readable automation output.

```bash
# Environment & tool diagnostics
python3 -m rex.cli doctor

# Tool registry management (distinguishes not_detected, available, installed, configured, healthy, verified)
python3 -m rex.cli tools list
python3 -m rex.cli tools check
python3 -m rex.cli tools install radare2 --dry-run

# Skills & MCP management
python3 -m rex.cli skills list
python3 -m rex.cli mcp list

# Universal Target Detection (magic bytes + structural inspection, never extension alone)
python3 -m rex.cli target inspect path/to/file.bin

# Run Analysis Modes: quick | deep | full
python3 -m rex.cli analyze path/to/target --mode quick
python3 -m rex.cli analyze path/to/target --mode deep
python3 -m rex.cli analyze path/to/target --mode full --allow-dynamic   # requires explicit opt-in

# Dedicated Minecraft Intelligence Pack (Bukkit/Spigot/Paper, Fabric/Forge/NeoForge, Velocity/BungeeCord, Resource Packs)
python3 -m rex.cli minecraft inspect path/to/Plugin.jar

# Safe URL & GitHub Repository Ingestion (with SSRF & redirect protection)
python3 -m rex.cli url inspect https://github.com/owner/repo
python3 -m rex.cli github inspect https://github.com/owner/repo

# Workspaces & Reports (Markdown + JSON)
python3 -m rex.cli workspace list
python3 -m rex.cli report <run-id> --format markdown
```

---

## APK reverse engineering (`rex apk`)

A first-class Android pipeline built for the "modded streaming app" workflow:
acquire → validate → static triage → report. Nothing in the APK is executed,
installed, or contacted.

```bash
# Full static report (Markdown + JSON) for a local APK
python3 -m rex.cli apk analyze MovieBox_app.apk --out ./reports/moviebox

# Structural validation only (ZIP + AndroidManifest.xml + classes*.dex)
python3 -m rex.cli apk validate MovieBox_app.apk

# Drive candidates for a query, and direct download when you have a URL
python3 -m rex.cli apk drive --query "name contains 'MovieBox'"
python3 -m rex.cli apk analyze --url "https://…/MovieBox.apk" --out ./reports/moviebox
```

What the analyzer produces (`rex/adapters/apk_analyzer.py`):

| Section | Contents |
|---|---|
| Identity | SHA-256, size, package, version name/code, app label, min/target SDK, DEX list, debuggable/backup/cleartext flags |
| Signing | v1/v2/v3 scheme coverage, certificate subject/issuer, validity, SHA-256 fingerprint |
| Components | Activities/services/receivers/providers, **exported** entry points (attack surface), main activity |
| Permissions | Full list plus a curated risk table (SMS, overlay, install-packages, accessibility, all-files, logs…) |
| Frameworks & SDKs | Fingerprints for Firebase, ExoPlayer/Media3, VLC/IJK/FFmpeg, Rhino/QuickJS, Flutter/RN, OkHttp, SQLCipher… and ad networks |
| API surface | Reflection, `DexClassLoader`, `Runtime.exec`, JS bridges, crypto, raw sockets — matched against the method index |
| Indicators | Hosts, domains, URLs, public IPv4s, emails, base64 blobs, tracker markers, licence-check string windows |
| Modified build | Weighted verdict: strong signals (mod-labelled name, debug/test-key certificate, debuggable, multi-cert) vs context (v1-only signing, many DEX…) |
| Findings ledger | Confidence-tagged claims (`Confirmed` … `Unverified`) with the tool that produced each |

Ingestion rules: a Drive file is never guessed. Use a Drive file ID with the
`google_drive` connector (or `apk drive --query`), and pass the resulting bytes
straight to `apk analyze`; `--url` accepts only HTTPS and caps downloads at
512 MiB. Every analysed APK is validated by structure before parsing, and all
strings inside it are treated as untrusted data (prompt-injection rule).

## Tool Installation Registry (`TOOL_INSTALLATION_REGISTRY.md`)

`TOOL_INSTALLATION_REGISTRY.md` is treated as an **actionable** registry, not
documentation. `rex/provisioning/managed.py` turns each entry into a pinned
install method, and the workflow is enforced end to end:

```
READ THIS REGISTRY -> OPEN OFFICIAL REPOSITORY -> CHECK INSTALL INSTRUCTIONS
-> DETECT ENVIRONMENT -> INSTALL TOOL -> CONFIGURE TOOL -> VERIFY TOOL -> RETRY ANALYSIS
```

```bash
# Honest per-tool states: NOT_INSTALLED | INSTALLABLE | INSTALLING |
# INSTALLED | CONFIGURED | VERIFIED | FAILED | UNSUPPORTED
python3 -m rex.cli registry list

# Preview what installation would do (no disk changes, --json supported)
python3 -m rex.cli registry plan radare2 ghidra

# Install + configure + verify individual registry tools / priorities
python3 -m rex.cli registry install radare2
python3 -m rex.cli registry install --priority 1
python3 -m rex.cli registry ensure --priority 1        # idempotent
python3 -m rex.cli registry install ghidra --dry-run
python3 -m rex.cli registry install tshark --allow-system   # still never escalates
python3 -m rex.cli registry retry                     # re-verify, reinstall if needed
```

| Tool | Priority | Install method | Notes |
|---|---|---|---|
| radare2 | 1 | distro package, else pinned source build from `codeload.github.com` (6.0.7, SHA-256 pinned) | shims in `~/.local/bin`; `LD_LIBRARY_PATH` exported by the wrapper |
| JADX | 1 | pinned `@mishguru/jadx-node@3.1.0` archive (JADX 1.1.0) → managed wrapper | needs `java` (registry provides a Temurin JDK 25 wheel via `jdk4py`) |
| Apktool | 1 | pinned `apktool-jar@2.4.1` archive | wrapper runs `java -jar apktool_2.4.1.jar` |
| Binwalk | 1 | `UNSUPPORTED` in environments without Rust/cargo | REX's own signature/entropy scanner is used instead; reported, never faked |
| TShark | 1 | distro package only | capture permissions are never assumed; offline analysis is the default |
| Ghidra | 2 | pinned Ghidra 12.2 official release (JDK 25 required) | stays `INSTALLABLE` if the 600 MB asset host is unreachable |
| Frida | 2 | managed venv with pinned `frida-tools` | installation does not grant device instrumentation permission |
| Java | 1 (dependency) | distro package, else `jdk4py` Temurin JDK 25 | exposes `java`/`JAVA_HOME` for JADX, Apktool and Ghidra |

Safety rules kept by the registry engine: no shell, argv-only commands, pinned
version + SHA-256 for every download, downloads limited to official hosts,
no privilege escalation, and `VERIFIED` only after a real version/functional
probe succeeds (present files alone are at most `INSTALLED`). Installed
wrappers live in `~/.local/bin` and per-tool prefixes in `~/.rex/tools/<tool>`;
`PATH` is never mutated by REX itself. `analyze --install-missing` now
provisions these registry tools instead of only reporting them as missing.

## Core Architecture (`rex/`)
- `rex/config.py` — Portable paths, safe defaults, validation, and environment-variable secret handling.
- `rex/detectors/` — Universal magic-byte, structural, archive, AI model (`.safetensors`, `.gguf`), and Minecraft artifact classifiers.
- `rex/registry/` — Tool Registry with granular status states (`not_detected`, `available`, `installed`, `configured`, `running_reachable`, `healthy`, `verified`) & Prerequisite-Gated MCP Manager.
- `rex/skills/` — Skill loader, frontmatter validator, and multi-skill target router.
- `rex/adapters/` — Static analysis adapters (General, JVM, Android, Native ELF/PE/Mach-O, Web/JS, Firmware, Network PCAP, File Format, AI Models) + opt-in Dynamic Framework (`disabled` by default).
- `rex/minecraft/` — Dedicated **Minecraft Intelligence Pack** (extracts `plugin.yml`, `fabric.mod.json`, `mods.toml`, `neoforge.mods.toml`, `velocity-plugin.json`, `bungee.yml`, `pack.mcmeta`, commands, permissions, mixins, entrypoints, dependencies, and server configs).
- `rex/ingestion/` — SSRF-hardened URL & GitHub repository metadata/artifact inspector.
- `rex/orchestrator/` — Task dependency planner and state machine (`pending`, `running`, `completed`, `failed`, `skipped`, `blocked`, `cancelled`).
- `rex/workspace/` — Per-run isolated workspaces with Zip-Slip path traversal and symlink escape protection.
- `rex/reporting/` — Evidence ledger (`Confirmed`, `Strongly supported`, `Probable`, `Unverified`, `Contradicted`) and dual Markdown + JSON report generator.

---

## Supported Agent Harnesses
| Agent | Skills Path | MCP Config Path |
|---|---|---|
| **Claude Code** | `~/.claude/skills/` | `~/.claude.json` |
| **Codex** | `~/.codex/skills/` | `~/.codex/config.toml` |
| **OpenCode** | `~/.config/opencode/skills/` | `~/.config/opencode/opencode.json` |
| **Cursor** | `~/.cursor/rules/` | `~/.cursor/mcp.json` |
| **Generic** | `~/.rex/installed/skills/` | `~/.rex/installed/mcp.json` |

---

## Validation & Tests

```bash
python3 scripts/validate_repo.py
python3 -m unittest discover -s tests -v
```

## Dependency provisioning (experimental)

`rex tools install` builds a dependency-ordered plan from the tool registry,
checks existing executables, and installs supported missing packages. Preview it
first; no downloads or filesystem changes are made by a dry run:

```bash
python3 -m rex.cli tools install --profile android --dry-run --json
python3 -m rex.cli tools install frida
python3 -m rex.cli tools missing --json
python3 -m rex.cli tools verify
python3 -m rex.cli setup --profile core --dry-run
python3 -m rex.cli doctor --fix --dry-run
python3 -m rex.cli tools uninstall frida
```

Available profiles are `core`, `android`, `native`, `jvm`, `web`, `firmware`,
`minecraft`, and `full`. The plan explicitly reports unsupported tools. System
package installs require `--allow-system` and sufficient existing permissions;
REX does **not** invoke sudo or request elevation. Review the plan first.
Package availability and compatibility depend on the host distribution and
package repositories, and are not guaranteed. System package manager failures
are reported; changes to system packages cannot be rolled back by REX.

Where no system package is selected, the supported Python packages (LIEF,
pefile, pyelftools, capstone, and Frida tools) use pinned top-level versions and
binary wheels from PyPI in separate `~/.rex/tools/<tool>/venv` environments.
The directory can be overridden with `--install-dir`. Each new installation is
verified before metadata is saved; a failed new installation is removed. Existing
managed directories are never overwritten. `uninstall` only removes a directory
with matching REX metadata, not system or user installations. pip validates
HTTPS, but these packages and their transitive dependencies are not hash-pinned
or signature-verified; this is not a fully reproducible or independently
verified software supply chain. Managed environments need network access and
Python's `venv` and pip. `--offline` skips installation. `doctor --fix` only
attempts non-system provisioning.

`analyze --install-missing` optionally tries provisioning for tools used by the
existing deep/full adapters before analysis; system installs remain disabled.
When a tool is unavailable, existing static analysis continues with its stated
limitations. Pinned, SHA-256-checked official releases for Ghidra 12.2, JADX 1.5.7 and
Vineflower 1.12.0 are available on Linux and macOS, subject to architecture,
Java version and disk checks; their release assets have not been end-to-end
tested on every platform. Release redirects are restricted to GitHub's asset
hosts and ZIP extraction rejects symlinks and traversal. Ghidra requires JDK 25,
JADX Java 11+, and Vineflower Java 17+. A system package remains the preferred
method when explicitly allowed. Otherwise a managed release is used where one is
available. The REX-managed JVM decompilers can be used by deep analysis.
CFR, upgrade/repair, and automatic MCP installation are not implemented.
`rex mcp verify <server-id>` explicitly launches an existing local preset and
attempts a real stdio initialize and tools/list handshake; runners such as npx
and uvx are not launched because they may download code. MCP entries identified
as eligible or configured are **not** verified connections. Frida CLI verification
also does not establish device instrumentation or permissions. Tshark
verification establishes CLI execution, not permission to capture packets.

### Provision command from the updated archive

The `provision` commands use the same central registry and managed per-tool
environments as `tools install`:

```bash
rex provision plan --profile native
rex provision install --profile core --dry-run
rex provision install --profile core --yes
rex provision install radare2 --yes --allow-system
rex --json provision plan --profile minecraft
```

Unlike `tools install`, `provision install` requires `--yes` for any actual
installation; system changes additionally require `--allow-system`. The updated
archive's `keystone` and `scapy` packages are included in the core profile. CFR
is registered but still requires manual installation.
