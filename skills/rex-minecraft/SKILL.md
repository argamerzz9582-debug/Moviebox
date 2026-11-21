---
name: rex-minecraft
description: Dedicated Minecraft Intelligence Pack for Bukkit/Spigot/Paper plugins, Fabric/Forge/NeoForge mods, Velocity/BungeeCord proxies, servers, and resource packs.
triggers: minecraft, spigot, paper, bukkit, fabric mod, forge mod, neoforge, velocity, bungeecord, resource pack, plugin.yml, fabric.mod.json, mixin
tools_required: python3, javap, jadx, unzip
---

# REX Minecraft Intelligence Pack Skill

## Supported Targets
- **Server Plugins:** Bukkit, Spigot, Paper, Purpur (`plugin.yml`, `paper-plugin.yml`).
- **Mods:** Fabric (`fabric.mod.json`), Forge (`META-INF/mods.toml`), NeoForge (`META-INF/neoforge.mods.toml`).
- **Proxies:** Velocity (`velocity-plugin.json`), BungeeCord / Waterfall (`bungee.yml`).
- **Resource Packs:** ZIP archives containing `pack.mcmeta`, `assets/<namespace>/models/`, `blockstates/`, `shaders/`.
- **Configs & Logs:** `config.yml`, `server.properties`, `latest.log`.

## Automated Inspection Command
Run the built-in Minecraft Intelligence Pack analyzer first (static, read-only, never executes the JAR):
```bash
python3 -m rex.cli minecraft inspect "<artifact.jar>"
```

## Detailed Investigation Checklist
1. **Provenance & Version Compatibility:** Verify SHA-256, `api-version` (Paper/Spigot), `minecraft` / `fabricloader` dependency ranges, or `pack_format`.
2. **Entrypoints & Lifecycle:**
   - Bukkit/Paper: `main` class extending `JavaPlugin` (`onEnable`, `onDisable`).
   - Fabric: `entrypoints` (`main`, `client`, `server`) and `mixins` JSON configs.
   - Forge/NeoForge: `@Mod` annotated classes and `mods.toml` entries.
3. **Commands, Permissions & Listeners:** Extract registered commands, aliases, permission nodes (`default: op|true|false`), and `@EventHandler` listener classes.
4. **Decompilation (When Available):**
   - Prefer public source code via `python3 -m rex.cli github inspect <repo-url>` if available.
   - Otherwise decompile with `jadx -d "$WS/decompiled" "<artifact.jar>"` or inspect bytecode with `javap -c -p`.
   - Clearly label source-based findings versus decompiled findings.

## Safety & Evidence Rules
- **Never execute unknown plugin/mod JARs** on a live server or host machine.
- Never invent commands, permissions, or mixin targets not supported by descriptor files or bytecode evidence.
