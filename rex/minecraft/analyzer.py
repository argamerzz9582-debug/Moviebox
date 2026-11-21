"""Minecraft Intelligence Pack — Deep static inspection for plugins, mods, proxies, servers, and resource packs."""

import json
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List


def _parse_simple_yaml(text: str) -> Dict[str, Any]:
    """Minimal indentation-aware YAML subset parser for plugin.yml / bungee.yml without external PyYAML."""
    result: Dict[str, Any] = {}
    stack: List[tuple[int, Dict[str, Any]]] = [(-1, result)]

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        current = stack[-1][1]

        if line.startswith("- "):
            val = line[2:].strip().strip("'\"")
            current.setdefault("_list", []).append(val)
            continue

        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip()
            if val == "" or val in ("|", ">"):
                child: Dict[str, Any] = {}
                current[key] = child
                stack.append((indent, child))
            elif val.startswith("[") and val.endswith("]"):
                items = [x.strip().strip("'\"") for x in val[1:-1].split(",") if x.strip()]
                current[key] = items
            else:
                if val.lower() == "true":
                    current[key] = True
                elif val.lower() == "false":
                    current[key] = False
                else:
                    current[key] = val.strip("'\"")
    return result


def _parse_simple_toml(text: str) -> Dict[str, Any]:
    """Lightweight TOML extractor for META-INF/mods.toml and neoforge.mods.toml."""
    data: Dict[str, Any] = {"mods": [], "dependencies": []}
    current_section: Optional[Dict[str, Any]] = None

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[[") and line.endswith("]]"):
            sec_name = line[2:-2].strip()
            sec_obj: Dict[str, Any] = {}
            if sec_name == "mods":
                data["mods"].append(sec_obj)
            elif sec_name.startswith("dependencies"):
                data["dependencies"].append(sec_obj)
            current_section = sec_obj
        elif line.startswith("[") and line.endswith("]"):
            current_section = data
        elif "=" in line:
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip("'\"")
            target = current_section if current_section is not None else data
            target[k] = v
    return data


def inspect_minecraft_artifact(path: Path) -> Dict[str, Any]:
    """Performs read-only structural and metadata extraction on a Minecraft JAR or Resource Pack ZIP."""
    if not path.exists():
        raise FileNotFoundError(f"Minecraft artifact not found: {path}")

    report: Dict[str, Any] = {
        "artifact": str(path),
        "platform_type": "unknown_minecraft_artifact",
        "metadata": {},
        "commands": [],
        "permissions": [],
        "entrypoints": [],
        "mixins": [],
        "dependencies": [],
        "embedded_configs": [],
        "class_packages": [],
        "class_count": 0,
        "evidence": [],
        "limitations": [
            "Static metadata and bytecode structure inspection only; JAR was never executed.",
            "Full method-level logic requires Java decompiler (CFR/Vineflower/JADX) if installed.",
        ],
    }

    if not zipfile.is_zipfile(path):
        # Could be a standalone config or log file
        if path.suffix.lower() in (".yml", ".yaml", ".properties", ".toml", ".json", ".log"):
            text = path.read_text(encoding="utf-8", errors="ignore")[:32768]
            report["platform_type"] = "minecraft_config_or_log"
            report["metadata"] = {"filename": path.name, "line_count": len(text.splitlines())}
            report["evidence"].append(f"Inspected text artifact {path.name} ({len(text)} chars)")
            return report
        raise ValueError(f"Unsupported non-ZIP Minecraft artifact: {path}")

    with zipfile.ZipFile(path, "r") as zf:
        names = set(zf.namelist())
        class_files = [n for n in names if n.endswith(".class")]
        report["class_count"] = len(class_files)
        packages = sorted({n.rsplit("/", 1)[0].replace("/", ".") for n in class_files if "/" in n})
        report["class_packages"] = packages[:40]
        report["embedded_configs"] = sorted(
            n for n in names if n.endswith((".yml", ".yaml", ".toml", ".json", ".properties")) and not n.startswith("META-INF/maven/")
        )[:40]

        # 1. Bukkit / Spigot / Paper plugin.yml or paper-plugin.yml
        for yml_name in ("paper-plugin.yml", "plugin.yml"):
            if yml_name in names:
                raw_yml = zf.read(yml_name).decode("utf-8", errors="ignore")
                parsed = _parse_simple_yaml(raw_yml)
                report["platform_type"] = "minecraft_paper_plugin" if yml_name == "paper-plugin.yml" else "minecraft_bukkit_plugin"
                report["metadata"].update({
                    "name": parsed.get("name"),
                    "version": parsed.get("version"),
                    "main": parsed.get("main"),
                    "api_version": parsed.get("api-version"),
                    "author": parsed.get("author") or parsed.get("authors"),
                    "description": parsed.get("description"),
                })
                if parsed.get("main"):
                    report["entrypoints"].append(str(parsed["main"]))

                cmds = parsed.get("commands", {})
                if isinstance(cmds, dict):
                    for cmd_name, cmd_info in cmds.items():
                        info_dict = cmd_info if isinstance(cmd_info, dict) else {}
                        report["commands"].append({
                            "command": cmd_name,
                            "description": info_dict.get("description", ""),
                            "usage": info_dict.get("usage", ""),
                            "permission": info_dict.get("permission", ""),
                        })

                perms = parsed.get("permissions", {})
                if isinstance(perms, dict):
                    for perm_name, perm_info in perms.items():
                        p_dict = perm_info if isinstance(perm_info, dict) else {}
                        report["permissions"].append({
                            "permission": perm_name,
                            "default": p_dict.get("default", ""),
                            "description": p_dict.get("description", ""),
                        })

                for dep_key in ("depend", "softdepend", "loadbefore"):
                    deps = parsed.get(dep_key)
                    if isinstance(deps, list):
                        for d in deps:
                            report["dependencies"].append({"name": d, "type": dep_key})
                    elif isinstance(deps, dict) and "_list" in deps:
                        for d in deps["_list"]:
                            report["dependencies"].append({"name": d, "type": dep_key})

                report["evidence"].append(f"Parsed {yml_name}: name={parsed.get('name')}, main={parsed.get('main')}")

        # 2. Fabric mod (fabric.mod.json)
        if "fabric.mod.json" in names:
            fmod = json.loads(zf.read("fabric.mod.json").decode("utf-8", errors="ignore"))
            report["platform_type"] = "minecraft_fabric_mod"
            report["metadata"].update({
                "id": fmod.get("id"),
                "name": fmod.get("name"),
                "version": fmod.get("version"),
                "environment": fmod.get("environment"),
                "license": fmod.get("license"),
            })
            eps = fmod.get("entrypoints", {})
            if isinstance(eps, dict):
                for ep_type, ep_list in eps.items():
                    for ep in (ep_list if isinstance(ep_list, list) else [ep_list]):
                        report["entrypoints"].append(f"{ep_type}:{ep}")
            for mix in fmod.get("mixins", []):
                mix_name = mix if isinstance(mix, str) else mix.get("config", "")
                if mix_name:
                    report["mixins"].append(mix_name)
                    if mix_name in names:
                        mix_json = json.loads(zf.read(mix_name).decode("utf-8", errors="ignore"))
                        pkg = mix_json.get("package", "")
                        for m_cls in mix_json.get("mixins", []) + mix_json.get("client", []) + mix_json.get("server", []):
                            report["mixins"].append(f"{pkg}.{m_cls}" if pkg else m_cls)
            for dep_kind in ("depends", "recommends", "suggests", "breaks"):
                d_map = fmod.get(dep_kind, {})
                if isinstance(d_map, dict):
                    for dep_id, ver_range in d_map.items():
                        report["dependencies"].append({"name": dep_id, "version": ver_range, "type": dep_kind})
            report["evidence"].append(f"Parsed fabric.mod.json: id={fmod.get('id')}, version={fmod.get('version')}")

        # 3. Forge / NeoForge mod (META-INF/mods.toml or neoforge.mods.toml)
        for toml_name, plat in (("META-INF/neoforge.mods.toml", "minecraft_neoforge_mod"), ("META-INF/mods.toml", "minecraft_forge_mod")):
            if toml_name in names:
                parsed_toml = _parse_simple_toml(zf.read(toml_name).decode("utf-8", errors="ignore"))
                report["platform_type"] = plat
                mods_list = parsed_toml.get("mods", [])
                if mods_list:
                    m0 = mods_list[0]
                    report["metadata"].update({
                        "modId": m0.get("modId"),
                        "displayName": m0.get("displayName"),
                        "version": m0.get("version"),
                        "loaderVersion": parsed_toml.get("loaderVersion"),
                    })
                for dep in parsed_toml.get("dependencies", []):
                    if dep.get("modId"):
                        report["dependencies"].append({
                            "name": dep["modId"],
                            "version": dep.get("versionRange", ""),
                            "mandatory": dep.get("mandatory", ""),
                        })
                report["evidence"].append(f"Parsed {toml_name}")

        # 4. Velocity / BungeeCord Proxy Plugins
        if "velocity-plugin.json" in names:
            vjson = json.loads(zf.read("velocity-plugin.json").decode("utf-8", errors="ignore"))
            report["platform_type"] = "minecraft_velocity_plugin"
            report["metadata"].update(vjson)
            if vjson.get("main"):
                report["entrypoints"].append(str(vjson["main"]))
            report["evidence"].append(f"Parsed velocity-plugin.json: id={vjson.get('id')}")

        if "bungee.yml" in names:
            byml = _parse_simple_yaml(zf.read("bungee.yml").decode("utf-8", errors="ignore"))
            report["platform_type"] = "minecraft_bungeecord_plugin"
            report["metadata"].update(byml)
            if byml.get("main"):
                report["entrypoints"].append(str(byml["main"]))
            report["evidence"].append(f"Parsed bungee.yml: name={byml.get('name')}")

        # 5. Resource Pack (pack.mcmeta)
        if "pack.mcmeta" in names:
            pmc = json.loads(zf.read("pack.mcmeta").decode("utf-8", errors="ignore"))
            if report["platform_type"] == "unknown_minecraft_artifact":
                report["platform_type"] = "minecraft_resource_pack"
            report["metadata"]["pack_mcmeta"] = pmc.get("pack", {})
            model_files = [n for n in names if "/models/" in n and n.endswith(".json")]
            shader_files = [n for n in names if "/shaders/" in n]
            report["metadata"]["model_count"] = len(model_files)
            report["metadata"]["shader_count"] = len(shader_files)
            report["evidence"].append(f"Parsed pack.mcmeta (pack_format={pmc.get('pack', {}).get('pack_format')})")

        # Heuristic scan for Bukkit EventHandler or network packets inside class constant pools
        listener_classes = []
        for cf in class_files[:300]:
            blob = zf.read(cf)
            if b"org/bukkit/event/EventHandler" in blob or b"EventPriority" in blob:
                listener_classes.append(cf[:-6].replace("/", "."))
        if listener_classes:
            report["metadata"]["detected_event_listeners"] = listener_classes[:25]
            report["evidence"].append(f"Detected {len(listener_classes)} class(es) referencing Bukkit EventHandler in constant pool")

    return report
