---
name: rex-managed-runtime
description: Static analysis for .NET/C#/IL assemblies and Java JAR/WAR/class bytecode targets.
triggers: dotnet, c#, il, jar, war, class file, jvm, ilspy, javap
tools_required: python3, unzip, javap, jadx
---

# REX Managed Runtime (.NET & JVM) Skill

## Supported Targets
- **JVM:** `.jar`, `.war`, `.ear`, `.class` bytecode files.
- **.NET:** `.exe` and `.dll` assemblies containing a CLR / `.NET` metadata header.

## Headless Workflow
1. **JVM Inspection:**
   ```bash
   unzip -p "<target.jar>" META-INF/MANIFEST.MF
   javap -c -p -cp "<target.jar>" com.example.Main > "$WS/generated/Main.bytecode.txt"
   ```
   Use `jadx` or `cfr`/`vineflower` when installed for full Java decompilation.
2. **.NET Inspection:**
   Verify CLR header presence via `python3 -m rex.cli target inspect "<target.dll>"` and decompile with `ilspycmd` if available, or inspect UTF-16LE strings (`strings -el`) and PE metadata via `pefile`.

## Evidence Rules
Reference exact namespace/class/method signatures and IL/bytecode offsets. Separate compiler boilerplate from application logic.
