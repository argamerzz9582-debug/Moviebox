---
name: rex-dynamic-frida
description: Opt-in authorized runtime observation, Frida instrumentation, and strace/ltrace workflows (disabled by default).
triggers: frida, dynamic analysis, runtime hook, strace, ltrace, gdb, attach process
tools_required: frida, python3, adb
---

# REX Controlled Dynamic Analysis Skill (Disabled by Default)

## Mandatory Pre-Execution Safety Gate
Dynamic analysis is **disabled by default**. Before running any runtime tool:
1. Verify explicit user authorization and opt-in (`--mode full --allow-dynamic`).
2. Confirm execution occurs inside an **isolated environment** (dedicated Android emulator, VM, or `docker run --network none --cap-drop ALL --read-only`).
3. Never execute untrusted binaries, JARs, or scripts directly on the host OS.

## Headless Workflow (Only After Approval)
1. **Read-Only Process Observation:** Use `frida-ps -Ua` or `strace -f -e trace=openat,connect` inside the isolated container.
2. **Non-Destructive Logging Hook:** Write minimal observation hooks to `$WS/generated/observe.js` and capture logs to file.
3. **Reconciliation:** Compare observed runtime behavior against static predictions and document any discrepancies.
