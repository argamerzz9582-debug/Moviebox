---
name: rex-android
description: Static reverse engineering workflow for Android APK, AAB, DEX, Smali, Manifest, resources, and native .so libraries.
triggers: apk, aab, dex, smali, android app, jadx, apktool, AndroidManifest
tools_required: jadx, apktool, unzip, python3
---

# REX Android Analysis Skill

## Supported Targets
APK, AAB, DEX/ODEX, Smali, `AndroidManifest.xml`, `resources.arsc`, and JNI native libraries (`lib/<abi>/*.so`).

## Detection Signals
- ZIP header (`50 4B 03 04`) containing `AndroidManifest.xml` and `classes*.dex`.
- Raw DEX header (`64 65 78 0A 30 33` -> `dex\n03x`).

## Headless Workflow
1. **Inventory & Native ABI Check:** List archive entries (`unzip -l`) and note `lib/<abi>/*.so` native libraries.
2. **Resource & Manifest Decoding (`apktool`):**
   ```bash
   apktool d -f -o "$WS/extracted/apktool" "<target.apk>"
   ```
   Inspect `AndroidManifest.xml` for `package`, `android:debuggable`, `android:allowBackup`, `android:exported="true"` components, permissions, and deep links.
3. **Java/Kotlin Decompilation (`jadx`):**
   ```bash
   jadx --deobf -d "$WS/decompiled/jadx" "<target.apk>"
   ```
   Query decompiled sources via `rg` into bounded slices.
4. **Native JNI Libraries:** Route `lib/<abi>/*.so` to `rex-native-binary` and check `Java_*` / `JNI_OnLoad` exports.

## Fallback & Evidence Rules
- If `jadx`/`apktool` are unavailable, inspect archive entries and DEX strings via `python3 -m rex.cli analyze <target.apk> --mode deep`.
- Cite exact class paths (`sources/com/example/Auth.java`), manifest tags, or `.so` symbol offsets.
