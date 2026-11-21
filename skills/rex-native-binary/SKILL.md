---
name: rex-native-binary
description: Headless static analysis for ELF, PE/EXE/DLL, and Mach-O native binaries using radare2, Ghidra headless, binutils, and Python LIEF.
triggers: elf, pe, exe, dll, macho, binary, disassemble, ghidra, radare2, rizin, objdump, readelf
tools_required: file, readelf, objdump, r2, python3
---

# REX Native Binary Analysis Skill

## Supported Targets
Linux ELF executables & `.so` libraries, Windows PE/EXE/DLL/SYS, macOS/iOS Mach-O binaries.

## Detection Signals
- ELF: `7F 45 4C 46` (`\x7fELF`)
- PE: `4D 5A` (`MZ`) + `PE\0\0` at `e_lfanew`
- Mach-O: `FE ED FA CE/CF` or `CE/CF FA ED FE`

## Headless Workflow
1. **Headers, Sections & Protections:**
   ```bash
   readelf -h -S -l -d "<target>" > "$WS/generated/elf_headers.txt"
   ```
   Or cross-format via `~/.rex/venv/bin/python` using `lief`, `pefile`, or `pyelftools`.
2. **High-Signal Strings & Imports:** Extract strings to file and search URLs, crypto constants, paths, and dynamic imports.
3. **Headless Disassembly (`radare2` / `ghidra`):**
   ```bash
   r2 -q -c "aaa; afl ~[0,1,3]; ii; ie" "<target>" > "$WS/generated/r2_triage.txt"
   ```
4. **Packing & Stripped Binary Checks:** Check section entropy (> 7.2) and packer section names (`UPX0`, `.vmp0`).

## Evidence Rules
Always include virtual address (`0x4012a0`), section name (`.text`, `.rodata`), and exact tool/version used.
