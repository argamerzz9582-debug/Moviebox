# Minecraft Artifact Reference Guide

Quick reference for classifying and auditing Minecraft server, proxy, mod, and resource-pack artifacts safely.

| Platform / Type | Primary Descriptor File | Key Metadata & Entrypoints |
|---|---|---|
| **Bukkit / Spigot / Paper** | `plugin.yml` / `paper-plugin.yml` | `name`, `version`, `main`, `api-version`, `commands`, `permissions`, `depend`, `softdepend` |
| **Fabric Mod** | `fabric.mod.json` | `id`, `version`, `environment`, `entrypoints` (`main`/`client`/`server`), `mixins`, `depends` |
| **Forge Mod** | `META-INF/mods.toml` | `[[mods]]` (`modId`, `version`, `loaderVersion`), `[[dependencies.*]]` |
| **NeoForge Mod** | `META-INF/neoforge.mods.toml` | `[[mods]]` (`modId`, `version`), `[[dependencies.*]]` |
| **Velocity Proxy** | `velocity-plugin.json` | `id`, `name`, `version`, `main`, `dependencies` |
| **BungeeCord / Waterfall** | `bungee.yml` | `name`, `version`, `main`, `depends`, `softDepends` |
| **Resource Pack** | `pack.mcmeta` | `pack.pack_format`, `pack.description`, `assets/<ns>/models/`, `shaders/` |

## Upstream Official Metadata Sources
- **Modrinth API:** `https://api.modrinth.com/v2/project/<slug>`
- **GitHub Releases / Source:** `https://api.github.com/repos/<owner>/<repo>`
- **SpigotMC / Spiget:** `https://api.spiget.org/v2/resources/<id>`
