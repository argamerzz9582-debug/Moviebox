#!/usr/bin/env bash
# Native (arm64) lane: the APK is the container, but MovieBox ships real .so
# libraries. This extracts them with REA's artifact extractor, inventories them
# with REA, and decompiles them with Ghidra headless (the engine REA drives).
set -euo pipefail

APK="apk/${APK_BASENAME}"
R=reports
mkdir -p "$R" work/lib

echo "### 1. extract native libraries with REA"
if rea extract-artifact "$APK" --json > "$R/extract-artifact.json" 2> "$R/extract-artifact.stderr"; then
  echo "    ok -> $R/extract-artifact.json"
else
  echo "    REA extractor declined; falling back to unzip for lib/ payload"
  unzip -o -q "$APK" 'lib/*' -d work/lib 2>/dev/null || true
fi
unzip -o -q "$APK" 'lib/*' -d work/lib 2>/dev/null || true

echo "### 2. inventory the .so files"
find work/lib -name '*.so' -printf '%p %s bytes\n' | sort | tee "$R/native-libs.txt" || true

# Focus the deep lane on the largest arm64 library (that is where the app logic
# that is not Java lives); record why the specific file was chosen.
TARGET="$(find work/lib -path '*arm64*' -name '*.so' -printf '%s %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)"
if [ -z "${TARGET:-}" ]; then
  TARGET="$(find work/lib -name '*.so' -printf '%s %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)"
fi
if [ -z "${TARGET:-}" ]; then
  echo "    no native libraries present: this build is Java/Kotlin-only; skipping Ghidra lane"
  echo "no-native-code" > "$R/native-lane.txt"
  exit 0
fi
echo "    primary native target: $TARGET ($(stat -c%s "$TARGET") bytes)" | tee "$R/native-lane.txt"
echo "$TARGET" > work/primary-so.txt

echo "### 3. ELF facts with REA"
rea inspect-native-exports "$TARGET" --json > "$R/native-exports.json" 2> "$R/native-exports.stderr" \
  && echo "    ok (exports)" || echo "    export inspection failed -> $R/native-exports.stderr"

if [ "${RUN_GHIDRA:-true}" != "true" ]; then
  echo "    Ghidra lane disabled by input; stopping here"
  exit 0
fi
if [ -z "${GHIDRA_INSTALL_DIR:-}" ]; then
  echo "    GHIDRA_INSTALL_DIR is not set; Ghidra lane skipped"
  exit 0
fi

echo "### 4. Ghidra headless import + auto-analysis"
mkdir -p ghidra_project
# Analyze only the selected library: full auto-analysis of a large obfuscated
# .so can take a long time; the timeout bounds it and the log is retained.
timeout 3600 "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
  "$PWD/ghidra_project" moviebox \
  -import "$TARGET" \
  -processor AARCH64:LE:64:v8A \
  -analysisTimeoutPerFile 2400 \
  -scriptPath "$PWD/scripts/ghidra" \
  -postScript FunctionInventory.java \
  -deleteProject \
  > "$R/ghidra-headless.log" 2>&1 \
  && echo "    ok -> $R/ghidra-headless.log" \
  || echo "    Ghidra headless exited nonzero (bounded by timeout); log retained at $R/ghidra-headless.log"

tail -20 "$R/ghidra-headless.log" || true
echo "### native lane complete"
