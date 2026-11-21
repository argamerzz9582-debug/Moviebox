# REX Tool Installation Registry

## 1. RADARE2

**Name:** radare2

**Purpose:** Native binary analysis, disassembly, debugging, binary inspection, reverse engineering and scripting.

**Official Repository:** https://github.com/radareorg/radare2

**Installation Instructions:** https://github.com/radareorg/radare2/blob/master/INSTALL.md

**Installation Status:** install this

## 2. GHIDRA

**Name:** Ghidra

**Purpose:** Advanced software reverse engineering, disassembly, decompilation, function analysis, control-flow analysis, symbol analysis and scripting.

**Official Repository:** https://github.com/NationalSecurityAgency/ghidra

**Installation Status:** install this

**Requirements:**

- Compatible Java runtime/JDK as required by the installed Ghidra release.
- Compatible OS and architecture.
- Verify both GUI and headless analyzer availability where supported.

## 3. JADX

**Name:** JADX

**Purpose:** Android APK and DEX decompilation, Java source reconstruction, class inspection, method analysis and Android application reverse engineering.

**Official Repository:** https://github.com/skylot/jadx

**Installation Status:** install this

**Requirements:**

- Compatible Java runtime.
- Install JADX CLI.
- Install JADX GUI only if the environment supports GUI applications.

## 4. APKTOOL

**Name:** Apktool

**Purpose:** Android APK resource decoding, AndroidManifest.xml analysis, Smali extraction, APK inspection and authorized APK rebuilding.

**Official Repository:** https://github.com/iBotPeaches/Apktool

**Installation Status:** install this

**Requirements:**

- Java runtime where required.
- APK decoding functionality.
- CLI verification.

## 5. BINWALK

**Name:** Binwalk

**Purpose:** Firmware analysis, embedded-file detection, signature identification, filesystem discovery and extraction of embedded data.

**Official Repository:** https://github.com/ReFirmLabs/binwalk

**Installation Status:** install this

**Requirements:**

- Python dependencies.
- Compatible extraction utilities when needed.
- Verify signature scanning and extraction functionality separately.

## 6. TSHARK / WIRESHARK

**Name:** TShark

**Purpose:** Network packet analysis, PCAP inspection, protocol detection, packet filtering and network artifact investigation.

**Official Repository:** https://github.com/wireshark/wireshark

**Installation Status:** install this

**Requirements:**

- Install TShark CLI.
- Install Wireshark GUI only when supported.
- Verify PCAP reading.
- Do not assume packet capture permissions are available.
- Prefer offline packet analysis when live capture permissions are unavailable.

## 7. FRIDA

**Name:** Frida

**Purpose:** Dynamic instrumentation, runtime observation, function tracing, debugging and authorized application analysis.

**Official Repository:** https://github.com/frida/frida

**Python Repository:** https://github.com/frida/frida-python

**Installation Status:** install this

**Requirements:**

- Compatible Python environment.
- frida-tools CLI.
- Verify frida command.
- Verify frida-ps command where supported.
- Device/server instrumentation is a separate capability and must be checked independently.

## INSTALLATION PRIORITY

**Priority 1:**

- radare2
- JADX
- Apktool
- Binwalk
- TShark

**Priority 2:**

- Ghidra
- Frida

Do not skip Priority 2 tools just because installation is more complicated.

If a tool cannot be installed through a package manager:

1. Read the official repository.
2. Locate official release assets.
3. Check OS and architecture compatibility.
4. Resolve dependencies.
5. Download the compatible release.
6. Validate the download.
7. Install in a managed REX tools directory.
8. Add a user-local executable path if appropriate.
9. Verify actual functionality.

## INSTALLATION ENVIRONMENT RULES

**Linux:**

- Detect distribution.
- Detect package manager.
- Use compatible packages or official releases.

**Windows:**

- Detect architecture.
- Use supported package managers or official releases.

**macOS:**

- Detect architecture.
- Prefer supported package managers or official releases.

**Termux / Android:**

- Detect Termux specifically.
- Use pkg and compatible Termux packages.
- Use Python virtual environments where appropriate.
- Do not assume desktop Linux binaries will work on Android.
- Do not assume Ghidra GUI is available.
- Prioritize compatible CLI tools.
- Report unsupported tools honestly.

## REX TOOL STATUS

Use these states:

- NOT_INSTALLED
- INSTALLABLE
- INSTALLING
- INSTALLED
- CONFIGURED
- VERIFIED
- FAILED
- UNSUPPORTED

A tool must not be marked VERIFIED merely because its files exist.

Verification must include:

- Executable detection
- Version check where available
- Basic command/functionality check
- Dependency check

## FINAL REQUIREMENT

REX must treat this file as an actionable installation registry.

Whenever a reverse-engineering workflow needs a missing tool:

READ THIS REGISTRY  
→ OPEN OFFICIAL REPOSITORY  
→ CHECK INSTALLATION INSTRUCTIONS  
→ DETECT ENVIRONMENT  
→ INSTALL TOOL  
→ CONFIGURE TOOL  
→ VERIFY TOOL  
→ RETRY ANALYSIS

Do not stop at reporting that Ghidra, radare2, JADX, Apktool, Binwalk, TShark or Frida is missing.

Attempt installation first whenever technically supported, safe and permitted.

If installation cannot be completed, explain the exact limitation and continue with the best available alternative.
