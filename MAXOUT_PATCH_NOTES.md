# REX MAXOUT — Auto-Provisioning Patch Notes

The updated Drive archive adds experimental dependency planning and installation.
It has been integrated with the existing provisioning engine and central tool
registry rather than replacing them with a second, conflicting registry.

- OS, architecture and available package-manager detection, including Termux.
- Profiles: core, android, native, jvm, web, firmware, minecraft and full.
- `rex provision plan --profile native` or selected tool IDs previews a plan.
- `rex provision install --profile core --yes` approves installation;
  `--dry-run` makes no changes and system installs also require `--allow-system`.
- Python wheels are installed into isolated per-tool environments under
  `~/.rex/tools/`, not the shared `~/.rex/venv` described in the uploaded ZIP.
  No automatic privilege escalation is attempted.
- Unsupported tools are reported. CFR remains manual. MCP auto-provisioning is
  not implemented; an explicit MCP health check is available for local presets.
- Ghidra, JADX and Vineflower have pinned official release installers on supported
  hosts; release downloads and execution could not be tested in this sandbox.

See README.md for commands and important security and platform limitations.
