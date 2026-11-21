# Common Magic Bytes & File Signatures

Never rely on file extensions alone. Verify leading bytes first.

| Format | Offset | Hex Signature | Notes |
|---|---|---|---|
| **ELF** | `0x00` | `7F 45 4C 46` | Linux / Android `.so` / Embedded |
| **PE / EXE / DLL / .NET** | `0x00` | `4D 5A` | `MZ` + `PE\0\0` at `e_lfanew` (check CLR Directory[14] for .NET) |
| **Mach-O (64-bit LE)** | `0x00` | `CF FA ED FE` | macOS / iOS ARM64 & x86_64 |
| **Java Class / Fat Mach-O** | `0x00` | `CA FE BA BE` | Bytes 6–7 >= 45 indicates JVM `.class` |
| **ZIP / APK / JAR / MC Pack** | `0x00` | `50 4B 03 04` | Inspect internal manifest (`AndroidManifest.xml`, `plugin.yml`, `fabric.mod.json`, `pack.mcmeta`) |
| **Android DEX** | `0x00` | `64 65 78 0A 30 33` | `dex\n03x` |
| **WebAssembly (WASM)** | `0x00` | `00 61 73 6D` | `\0asm` |
| **SquashFS (LE)** | `0x00` | `68 73 71 73` | `hsqs` (IoT firmware) |
| **uImage Boot Header** | `0x00` | `27 05 19 56` | U-Boot kernel image |
| **PCAP / PCAPNG** | `0x00` | `D4 C3 B2 A1` / `0A 0D 0D 0A` | Packet captures |
| **GGUF AI Model** | `0x00` | `47 47 55 46` | `GGUF` quantized/LLM model format |
| **SQLite 3** | `0x00` | `53 51 4C 69 74 65 20 66` | `SQLite format 3` |
