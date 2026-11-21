# Decompiler Pitfalls, Obfuscation & False Positives

Decompilers (Ghidra, JADX, CFR, Vineflower, ILSpy) produce **reconstructions**, not original source code.

1. **Packing & Encryption:** High section entropy (> 7.2) or packer sections (`UPX0`, `.vmp0`) indicate packed stubs. Do not treat stub code as application logic.
2. **Stripped Symbols:** Anchor analysis on imports, string cross-references, and framework APIs rather than auto-generated function names (`FUN_00401000`).
3. **Decompiler Type/Control-Flow Artifacts:** Always verify surprising conditions against raw disassembly, Smali, or `javap` bytecode.
4. **ProGuard / R8 / Remapped Minecraft Mappings:** Obfuscated class/method names (`a.b.c`) still preserve Bukkit/Paper/Fabric/Minecraft API method signatures and string literals.
