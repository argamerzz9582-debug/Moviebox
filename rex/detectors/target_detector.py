"""Universal Target Detector — Classifies binaries, archives, JVM/Android, Minecraft, AI models, and URLs via magic bytes and structure."""

import math
import os
import struct
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class TargetClassification:
    target_kind: str          # file | directory | url | unknown
    primary_type: str         # e.g., android_apk, minecraft_plugin_jar, elf_binary, pe_binary, etc.
    subtypes: List[str] = field(default_factory=list)
    architecture: Optional[str] = None
    confidence: str = "Probable"  # Confirmed | Strongly supported | Probable | Unverified
    evidence: List[str] = field(default_factory=list)
    recommended_skills: List[str] = field(default_factory=list)
    recommended_adapters: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_kind": self.target_kind,
            "primary_type": self.primary_type,
            "subtypes": self.subtypes,
            "architecture": self.architecture,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "recommended_skills": self.recommended_skills,
            "recommended_adapters": self.recommended_adapters,
            "next_steps": self.next_steps,
            "metadata": self.metadata,
        }


def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 4)


def _inspect_zip_container(path: Path) -> Optional[TargetClassification]:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = set(zf.namelist())
            sample_names = sorted(names)[:30]
            evidence = [f"ZIP container magic PK\\x03\\x04 with {len(names)} entries"]

            # Android APK / AAB
            if "AndroidManifest.xml" in names and any(n.endswith(".dex") for n in names):
                evidence.append("Contains AndroidManifest.xml and classes*.dex")
                abis = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and len(n.split("/")) >= 3})
                return TargetClassification(
                    target_kind="file",
                    primary_type="android_apk",
                    subtypes=["zip_archive", "android_package"] + (["has_native_libs"] if abis else []),
                    architecture=",".join(abis) if abis else "dalvik/art",
                    confidence="Confirmed",
                    evidence=evidence,
                    recommended_skills=["rex-master", "rex-android"] + (["rex-native-binary"] if abis else []),
                    recommended_adapters=["general", "android"] + (["native"] if abis else []),
                    next_steps=["Decode manifest & resources via apktool", "Decompile DEX via jadx"],
                    metadata={"entry_count": len(names), "native_abis": abis, "sample_entries": sample_names},
                )

            if "base/manifest/AndroidManifest.xml" in names or "BundleConfig.pb" in names:
                evidence.append("Contains Android App Bundle (AAB) structure")
                return TargetClassification(
                    target_kind="file",
                    primary_type="android_aab",
                    subtypes=["zip_archive", "android_bundle"],
                    confidence="Confirmed",
                    evidence=evidence,
                    recommended_skills=["rex-master", "rex-android"],
                    recommended_adapters=["general", "android"],
                    next_steps=["Inspect base/manifest/AndroidManifest.xml and base/dex/"],
                    metadata={"entry_count": len(names), "sample_entries": sample_names},
                )

            # Minecraft Plugin / Mod / Proxy / Server JAR
            mc_markers = {
                "plugin.yml": ("minecraft_bukkit_plugin", "Bukkit/Spigot/Paper plugin descriptor plugin.yml"),
                "paper-plugin.yml": ("minecraft_paper_plugin", "Paper plugin descriptor paper-plugin.yml"),
                "fabric.mod.json": ("minecraft_fabric_mod", "Fabric mod descriptor fabric.mod.json"),
                "META-INF/mods.toml": ("minecraft_forge_mod", "Forge mod descriptor META-INF/mods.toml"),
                "META-INF/neoforge.mods.toml": ("minecraft_neoforge_mod", "NeoForge mod descriptor META-INF/neoforge.mods.toml"),
                "velocity-plugin.json": ("minecraft_velocity_plugin", "Velocity proxy plugin descriptor velocity-plugin.json"),
                "bungee.yml": ("minecraft_bungeecord_plugin", "BungeeCord proxy plugin descriptor bungee.yml"),
            }
            matched_mc = [(m_type, desc) for fname, (m_type, desc) in mc_markers.items() if fname in names]
            if matched_mc:
                primary_mc = matched_mc[0][0]
                for _, desc in matched_mc:
                    evidence.append(f"Found {desc}")
                return TargetClassification(
                    target_kind="file",
                    primary_type=primary_mc,
                    subtypes=["jvm_jar", "minecraft_artifact"] + [m[0] for m in matched_mc],
                    architecture="jvm_bytecode",
                    confidence="Confirmed",
                    evidence=evidence,
                    recommended_skills=["rex-master", "rex-minecraft", "rex-managed-runtime"],
                    recommended_adapters=["general", "jvm", "minecraft"],
                    next_steps=["Run Minecraft Intelligence Pack inspection (commands, permissions, mixins, entrypoints)"],
                    metadata={"entry_count": len(names), "sample_entries": sample_names},
                )

            # Minecraft Resource Pack ZIP
            if "pack.mcmeta" in names and (any(n.startswith("assets/") for n in names) or "pack.png" in names):
                evidence.append("Found pack.mcmeta with assets/ structure (Minecraft Resource Pack)")
                return TargetClassification(
                    target_kind="file",
                    primary_type="minecraft_resource_pack",
                    subtypes=["zip_archive", "minecraft_artifact"],
                    confidence="Confirmed",
                    evidence=evidence,
                    recommended_skills=["rex-master", "rex-minecraft"],
                    recommended_adapters=["general", "minecraft"],
                    next_steps=["Inspect pack.mcmeta format version, models, blockstates, and shaders"],
                    metadata={"entry_count": len(names), "sample_entries": sample_names},
                )

            # Generic Java JAR / WAR
            if "META-INF/MANIFEST.MF" in names or any(n.endswith(".class") for n in names):
                evidence.append("Contains JVM .class files or META-INF/MANIFEST.MF")
                return TargetClassification(
                    target_kind="file",
                    primary_type="java_jar",
                    subtypes=["zip_archive", "jvm_archive"],
                    architecture="jvm_bytecode",
                    confidence="Confirmed",
                    evidence=evidence,
                    recommended_skills=["rex-master", "rex-managed-runtime"],
                    recommended_adapters=["general", "jvm"],
                    next_steps=["Inspect MANIFEST.MF, package tree, and decompile bytecode"],
                    metadata={"entry_count": len(names), "sample_entries": sample_names},
                )

            # Generic ZIP archive
            return TargetClassification(
                target_kind="file",
                primary_type="zip_archive",
                subtypes=["archive"],
                confidence="Confirmed",
                evidence=evidence,
                recommended_skills=["rex-master", "rex-file-format"],
                recommended_adapters=["general"],
                next_steps=["Safely extract archive into isolated workspace and inspect inner files"],
                metadata={"entry_count": len(names), "sample_entries": sample_names},
            )
    except zipfile.BadZipFile:
        return None


def _inspect_pe(header: bytes, file_path: Path) -> TargetClassification:
    evidence = ["MZ header (4D 5A) at offset 0x00"]
    arch = "x86/x64"
    is_dotnet = False
    is_dll = False

    if len(header) >= 0x40:
        e_lfanew = struct.unpack_from("<I", header, 0x3C)[0]
        if e_lfanew + 24 <= len(header) and header[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
            evidence.append(f"Valid PE\\0\\0 signature at offset 0x{e_lfanew:x}")
            machine, _num_sec, _ts, _sym, _nsym, opt_size, characteristics = struct.unpack_from(
                "<HHIIIHH", header, e_lfanew + 4
            )
            arch_map = {0x014C: "x86", 0x8664: "x86_64", 0xAA64: "aarch64", 0x01C0: "arm"}
            arch = arch_map.get(machine, f"machine_0x{machine:04x}")
            is_dll = bool(characteristics & 0x2000)

            opt_off = e_lfanew + 24
            if opt_off + opt_size <= len(header) and opt_size >= 2:
                magic = struct.unpack_from("<H", header, opt_off)[0]
                # DataDirectory[14] is COM/CLR Runtime Header
                clr_dd_off = opt_off + (112 if magic == 0x20B else 96) + (14 * 8)
                if clr_dd_off + 8 <= len(header):
                    clr_rva, clr_size = struct.unpack_from("<II", header, clr_dd_off)
                    if clr_rva > 0 and clr_size > 0:
                        is_dotnet = True
                        evidence.append(f"Non-zero CLR (.NET) Directory RVA=0x{clr_rva:x}")

    if is_dotnet:
        return TargetClassification(
            target_kind="file",
            primary_type="dotnet_assembly",
            subtypes=["pe_binary", "clr_managed"] + (["dll"] if is_dll else ["exe"]),
            architecture=arch,
            confidence="Confirmed",
            evidence=evidence,
            recommended_skills=["rex-master", "rex-managed-runtime", "rex-native-binary"],
            recommended_adapters=["general", "jvm", "native"],
            next_steps=["Inspect CLR metadata, namespaces, and IL bytecode"],
        )

    return TargetClassification(
        target_kind="file",
        primary_type="pe_dll" if is_dll else "pe_executable",
        subtypes=["pe_binary"],
        architecture=arch,
        confidence="Confirmed",
        evidence=evidence,
        recommended_skills=["rex-master", "rex-native-binary"],
        recommended_adapters=["general", "native"],
        next_steps=["Inspect PE sections, imports/exports, strings, and disassembly"],
    )


def _inspect_elf(header: bytes) -> TargetClassification:
    evidence = ["ELF magic (7F 45 4C 46) at offset 0x00"]
    ei_class = header[4] if len(header) > 4 else 0
    ei_data = header[5] if len(header) > 5 else 0
    bits = "64-bit" if ei_class == 2 else ("32-bit" if ei_class == 1 else "unknown-bit")
    endian = "<" if ei_data == 1 else ">"
    arch = bits
    if len(header) >= 20:
        e_type, e_machine = struct.unpack_from(f"{endian}HH", header, 16)
        m_map = {0x03: "x86", 0x3E: "x86_64", 0x28: "arm", 0xB7: "aarch64", 0x08: "mips", 0xF3: "riscv"}
        arch = f"{m_map.get(e_machine, f'machine_0x{e_machine:x}')} ({bits})"
        evidence.append(f"ELF type={e_type}, arch={arch}")

    return TargetClassification(
        target_kind="file",
        primary_type="elf_binary",
        subtypes=["native_binary"],
        architecture=arch,
        confidence="Confirmed",
        evidence=evidence,
        recommended_skills=["rex-master", "rex-native-binary"],
        recommended_adapters=["general", "native"],
        next_steps=["Inspect ELF headers, sections, dynamic symbols, strings, and disassembly"],
    )


def detect_target(target_str: str) -> TargetClassification:
    """Classifies a local file, directory, or URL using magic bytes, structure, and metadata."""
    if target_str.startswith(("http://", "https://")):
        return TargetClassification(
            target_kind="url",
            primary_type="remote_url",
            subtypes=["github_repo"] if "github.com/" in target_str else ["web_or_artifact_url"],
            confidence="Confirmed",
            evidence=[f"HTTP(S) URL target: {target_str}"],
            recommended_skills=["rex-master", "rex-web-js"],
            recommended_adapters=["url_ingestion"],
            next_steps=["Validate URL against SSRF rules and fetch permitted public metadata"],
        )

    p = Path(target_str)
    if not p.exists():
        raise FileNotFoundError(f"Target does not exist: {target_str}")

    if p.is_dir():
        files = [f.name for f in list(p.iterdir())[:50]]
        evidence = [f"Directory with {len(files)} top-level items"]
        subtypes = ["directory"]
        skills = ["rex-master"]
        if "package.json" in files:
            subtypes.append("nodejs_or_web_project")
            skills.append("rex-web-js")
            evidence.append("Found package.json")
        if "build.gradle" in files or "build.gradle.kts" in files or "pom.xml" in files:
            subtypes.append("jvm_or_minecraft_project")
            skills.extend(["rex-managed-runtime", "rex-minecraft"])
            evidence.append("Found Gradle/Maven build manifest")
        if "pyproject.toml" in files or "setup.py" in files:
            subtypes.append("python_project")
            evidence.append("Found Python project manifest")
        return TargetClassification(
            target_kind="directory",
            primary_type="source_or_project_directory",
            subtypes=subtypes,
            confidence="Confirmed",
            evidence=evidence,
            recommended_skills=list(dict.fromkeys(skills)),
            recommended_adapters=["general", "web"],
            next_steps=["Inventory directory structure, manifests, entrypoints, and dependencies"],
            metadata={"top_level_items": files},
        )

    size = p.stat().st_size
    with p.open("rb") as f:
        head = f.read(4096)

    entropy = compute_entropy(head)

    # 1. ZIP-based formats (APK, AAB, Minecraft Plugin/Mod/Pack, JAR, ZIP)
    if head.startswith(b"PK\x03\x04"):
        zip_cls = _inspect_zip_container(p)
        if zip_cls:
            zip_cls.metadata["file_size"] = size
            zip_cls.metadata["header_entropy"] = entropy
            return zip_cls

    # 2. Native Binaries
    if head.startswith(b"\x7fELF"):
        cls = _inspect_elf(head)
        cls.metadata.update({"file_size": size, "header_entropy": entropy})
        return cls

    if head.startswith(b"MZ"):
        cls = _inspect_pe(head, p)
        cls.metadata.update({"file_size": size, "header_entropy": entropy})
        return cls

    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return TargetClassification(
            target_kind="file",
            primary_type="macho_binary",
            subtypes=["native_binary", "apple_macho"],
            confidence="Confirmed",
            evidence=[f"Mach-O magic bytes ({head[:4].hex()}) at offset 0x00"],
            recommended_skills=["rex-master", "rex-native-binary"],
            recommended_adapters=["general", "native"],
            next_steps=["Inspect Mach-O load commands, segments, symbols, and entitlements"],
            metadata={"file_size": size, "header_entropy": entropy},
        )

    # 3. Java Class vs Fat Mach-O (CA FE BA BE)
    if head.startswith(b"\xca\xfe\xba\xbe") and len(head) >= 8:
        val = struct.unpack(">I", head[4:8])[0]
        if val >= 45:  # Java class major version >= 45 (JDK 1.1+)
            return TargetClassification(
                target_kind="file",
                primary_type="java_class_file",
                subtypes=["jvm_bytecode"],
                architecture="jvm_bytecode",
                confidence="Confirmed",
                evidence=[f"Java .class magic CA FE BA BE with major version {val & 0xFFFF}"],
                recommended_skills=["rex-master", "rex-managed-runtime"],
                recommended_adapters=["general", "jvm"],
                next_steps=["Disassemble bytecode via javap or decompile with CFR/Vineflower/JADX"],
                metadata={"file_size": size, "header_entropy": entropy},
            )

    # 4. Android DEX
    if head.startswith(b"dex\n"):
        return TargetClassification(
            target_kind="file",
            primary_type="android_dex",
            subtypes=["dalvik_bytecode"],
            architecture="dalvik",
            confidence="Confirmed",
            evidence=[f"Android DEX magic ({head[:8]!r}) at offset 0x00"],
            recommended_skills=["rex-master", "rex-android"],
            recommended_adapters=["general", "android"],
            next_steps=["Decompile DEX classes via jadx or inspect strings/methods"],
            metadata={"file_size": size, "header_entropy": entropy},
        )

    # 5. WebAssembly
    if head.startswith(b"\x00asm"):
        return TargetClassification(
            target_kind="file",
            primary_type="wasm_module",
            subtypes=["webassembly"],
            architecture="wasm32",
            confidence="Confirmed",
            evidence=["WebAssembly magic (00 61 73 6D) at offset 0x00"],
            recommended_skills=["rex-master", "rex-web-js"],
            recommended_adapters=["general", "web"],
            next_steps=["Inspect WASM sections, imports, exports, and convert to WAT if wasm2wat available"],
            metadata={"file_size": size, "header_entropy": entropy},
        )

    # 6. Network Captures (PCAP / PCAPNG)
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
        fmt = "pcapng" if head[:4] == b"\x0a\x0d\x0d\x0a" else "pcap"
        return TargetClassification(
            target_kind="file",
            primary_type=f"network_{fmt}",
            subtypes=["packet_capture"],
            confidence="Confirmed",
            evidence=[f"Packet capture magic ({head[:4].hex()}) at offset 0x00"],
            recommended_skills=["rex-master", "rex-network-protocol"],
            recommended_adapters=["general", "network"],
            next_steps=["Summarize protocol hierarchy, DNS/TLS SNI, and conversations via tshark or scapy"],
            metadata={"file_size": size, "header_entropy": entropy},
        )

    # 7. Firmware Signatures (SquashFS / uImage)
    if head[:4] in (b"hsqs", b"sqsh", b"\x27\x05\x19\x56"):
        return TargetClassification(
            target_kind="file",
            primary_type="firmware_image",
            subtypes=["embedded_firmware"],
            confidence="Strongly supported",
            evidence=[f"Firmware/SquashFS magic ({head[:4].hex()}) at offset 0x00"],
            recommended_skills=["rex-master", "rex-firmware-iot"],
            recommended_adapters=["general", "firmware"],
            next_steps=["Scan offsets/entropy with binwalk and extract embedded filesystem safely"],
            metadata={"file_size": size, "header_entropy": entropy},
        )

    # 8. AI Model Formats (GGUF, SafeTensors)
    if head.startswith(b"GGUF"):
        return TargetClassification(
            target_kind="file",
            primary_type="ai_model_gguf",
            subtypes=["ai_model_artifact"],
            confidence="Confirmed",
            evidence=["GGUF model magic (47 47 55 46) at offset 0x00"],
            recommended_skills=["rex-master", "rex-file-format"],
            recommended_adapters=["general", "ai_model"],
            next_steps=["Parse GGUF header metadata key-values and tensor count safely without executing code"],
            metadata={"file_size": size, "header_entropy": entropy},
        )

    if len(head) >= 16:
        hdr_len = struct.unpack("<Q", head[:8])[0]
        if 2 <= hdr_len <= 10 * 1024 * 1024 and head[8:9] == b"{":
            try:
                import json
                meta_preview = json.loads(head[8:8 + min(hdr_len, 4088)].decode("utf-8", errors="ignore"))
                if isinstance(meta_preview, dict):
                    return TargetClassification(
                        target_kind="file",
                        primary_type="ai_model_safetensors",
                        subtypes=["ai_model_artifact"],
                        confidence="Strongly supported",
                        evidence=[f"SafeTensors 8-byte JSON header length ({hdr_len} bytes) followed by JSON tensor map"],
                        recommended_skills=["rex-master", "rex-file-format"],
                        recommended_adapters=["general", "ai_model"],
                        next_steps=["Inspect tensor shapes, dtypes, and __metadata__ keys"],
                        metadata={"file_size": size, "header_length": hdr_len},
                    )
            except Exception:
                pass

    # 9. SQLite Database
    if head.startswith(b"SQLite format 3\x00"):
        return TargetClassification(
            target_kind="file",
            primary_type="sqlite_database",
            subtypes=["database"],
            confidence="Confirmed",
            evidence=["SQLite format 3 magic header at offset 0x00"],
            recommended_skills=["rex-master", "rex-file-format"],
            recommended_adapters=["general"],
            next_steps=["Inspect SQLite schema tables read-only via sqlite3"],
            metadata={"file_size": size},
        )

    # 10. Compressed archives (GZIP, XZ, BZIP2, 7z)
    if head.startswith(b"\x1f\x8b\x08") or head.startswith(b"\xfd7zXZ\x00") or head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return TargetClassification(
            target_kind="file",
            primary_type="compressed_archive",
            subtypes=["archive"],
            confidence="Confirmed",
            evidence=[f"Compressed archive magic ({head[:6].hex()}) at offset 0x00"],
            recommended_skills=["rex-master", "rex-file-format"],
            recommended_adapters=["general"],
            next_steps=["Decompress safely into workspace and re-run target detection on inner payload"],
            metadata={"file_size": size, "header_entropy": entropy},
        )

    # 11. Text / Script / JSON / Source Code heuristic
    if head:
        printable = sum(1 for b in head if 32 <= b <= 126 or b in (9, 10, 13))
        if printable / len(head) > 0.90:
            first_line = head.splitlines()[0].decode("utf-8", errors="ignore")[:120]
            subtypes = ["text_or_source"]
            skills = ["rex-master"]
            if p.suffix.lower() in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
                subtypes.append("javascript_typescript")
                skills.append("rex-web-js")
            return TargetClassification(
                target_kind="file",
                primary_type="text_or_source_code",
                subtypes=subtypes,
                confidence="Strongly supported",
                evidence=[f"High printable ASCII/UTF-8 ratio ({printable}/{len(head)})", f"First line: {first_line}"],
                recommended_skills=skills,
                recommended_adapters=["general", "web"],
                next_steps=["Inspect structure, imports, URLs, and configuration entries"],
                metadata={"file_size": size, "extension": p.suffix.lower()},
            )

    # 12. Unknown / Custom Binary
    return TargetClassification(
        target_kind="file",
        primary_type="unknown_binary",
        subtypes=["unclassified"],
        confidence="Unverified",
        evidence=[
            f"Unrecognized leading magic bytes: {head[:16].hex(' ')}",
            f"File size: {size} bytes, header Shannon entropy: {entropy} bits/byte",
        ],
        recommended_skills=["rex-master", "rex-file-format"],
        recommended_adapters=["general", "file_format"],
        next_steps=[
            "Inspect full hex header/footer, block entropy, and embedded magic signatures",
            "Use Kaitai Struct / ImHex or Python struct slicing to test format hypotheses",
        ],
        metadata={"file_size": size, "header_entropy": entropy, "head_hex": head[:32].hex(" ")},
    )
