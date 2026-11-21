# REX Headless Tool Cheat Sheets

Non-interactive CLI commands safe for AI coding agents. Always store large output inside `~/.rex/workspaces/<run_id>/`.

## 1. REX Unified CLI
```bash
python3 -m rex.cli doctor
python3 -m rex.cli target inspect <path>
python3 -m rex.cli analyze <path> --mode quick
python3 -m rex.cli analyze <path> --mode deep
python3 -m rex.cli minecraft inspect <plugin_or_mod.jar>
python3 -m rex.cli github inspect https://github.com/owner/repo
```

## 2. Android & JVM (JADX, APKTool, javap)
```bash
apktool d -f -o out_apktool app.apk
jadx --deobf -d out_jadx app.apk
javap -c -p -cp plugin.jar com.example.Main
```

## 3. Native Binaries (binutils, radare2, Ghidra Headless)
```bash
readelf -h -S -l -d binary.elf
objdump -d -M intel binary.elf > disasm.txt
r2 -q -c "aaa; afl; ii; ie" binary
analyzeHeadless /tmp/ghidra_proj proj_name -import binary -deleteProject
```

## 4. Firmware & Network (Binwalk, tshark)
```bash
binwalk firmware.bin
binwalk -e -C out_fw firmware.bin
tshark -r capture.pcap -q -z io,phs
```
