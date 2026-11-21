---
name: rex-firmware-iot
description: Safe static extraction and filesystem analysis for embedded firmware images, routers, IoT dumps, and bootloaders.
triggers: firmware, iot, binwalk, squashfs, ubifs, jffs2, bootloader, flash dump, rom
tools_required: binwalk, file, strings, python3
---

# REX Firmware & IoT Analysis Skill

## Supported Targets
Flash dumps (`.bin`, `.img`, `.fw`), SquashFS (`hsqs`/`sqsh`), JFFS2/UBIFS, uImage (`27 05 19 56`), and embedded Linux filesystems.

## Headless Workflow
1. **Signature & Entropy Scan:** Run `binwalk "<firmware.bin>"` (or built-in signature offset scanner fallback). Flat entropy > 7.9 indicates encryption/compression—do not invent filesystems if encrypted.
2. **Safe Extraction:** Extract into `$WS/extracted/fw` and verify no symlinks escape the workspace.
3. **Embedded RootFS Triage:** Locate `init.d`, `rc.local`, web CGI binaries, configs, and route embedded ARM/MIPS ELF binaries to `rex-native-binary`.

## Evidence Rules
Record exact byte offsets (`0x1A400`), architecture/endianness, and filesystem type.
