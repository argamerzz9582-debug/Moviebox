#!/usr/bin/env bash
# Verification gate. The rebuilt APK must be structurally complete and
# cryptographically valid, otherwise the run fails and nothing is published.
set -euo pipefail

R=reports
SIGNED="$(cat work/signed-apk-path.txt)"
FAIL=0

note() { echo "$1" | tee -a "$R/verification.log"; }
check() { # check <description> <command...>
  local desc="$1"; shift
  if "$@" >> "$R/verification.log" 2>&1; then
    note "PASS  ${desc}"
  else
    note "FAIL  ${desc}"
    FAIL=1
  fi
}

: > "$R/verification.log"

echo "### 1. signing verification (apksigner verify --print-certs)"
if apksigner verify --verbose --print-certs "$SIGNED" > "$R/apksigner-verify.txt" 2>&1; then
  note "PASS  apksigner verify (v1/v2/v3)"
else
  note "FAIL  apksigner verify"
  FAIL=1
fi
cat "$R/apksigner-verify.txt"

echo "### 2. integrity (zipalign -c 4)"
check "zipalign 4-byte aligned" zipalign -c 4 "$SIGNED"

echo "### 3. archive integrity"
check "zip central directory intact" unzip -t "$SIGNED"

echo "### 4. structural completeness"
ENTRIES="$(unzip -l "$SIGNED")"
echo "$ENTRIES" > "$R/rebuilt-entries.txt"
for must in AndroidManifest.xml classes.dex resources.arsc; do
  if grep -q " ${must}$" <<<"$ENTRIES"; then
    note "PASS  contains ${must}"
  else
    note "FAIL  missing ${must}"
    FAIL=1
  fi
done
DEX_COUNT=$(grep -cE ' classes[0-9]*\.dex$' <<<"$ENTRIES" || true)
note "INFO  dex files: ${DEX_COUNT}"
note "INFO  total entries: $(grep -c '^' <<<"$ENTRIES")"

echo "### 5. decoded manifest of the rebuilt APK (aapt2 dump) — proves it is readable"
if aapt2 dump badging "$SIGNED" > "$R/rebuilt-badging.txt" 2>&1; then
  note "PASS  aapt2 dump badging"
  head -5 "$R/rebuilt-badging.txt" | sed 's/^/      /' | tee -a "$R/verification.log"
  aapt2 dump xmltree --file AndroidManifest.xml "$SIGNED" > "$R/rebuilt-manifest.xml" 2>&1 || true
else
  note "FAIL  aapt2 dump badging (manifest not parseable)"
  FAIL=1
fi

echo "### 6. native libs preserved"
SRC_SO=$(unzip -l "apk/${APK_BASENAME}" | grep -cE ' lib/.*\.so$' || true)
NEW_SO=$(unzip -l "$SIGNED" | grep -cE ' lib/.*\.so$' || true)
note "INFO  native libs: source=${SRC_SO} rebuilt=${NEW_SO}"
if [ "$SRC_SO" -gt 0 ] && [ "$NEW_SO" -lt "$SRC_SO" ]; then
  note "FAIL  rebuilt APK lost native libraries"
  FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
  echo "### VERIFICATION FAILED"
  exit 1
fi
echo "### VERIFICATION PASSED"
