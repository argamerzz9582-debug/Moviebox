#!/usr/bin/env bash
# Verification gate. The rebuilt APK must be structurally complete and
# cryptographically valid, or the run fails and nothing is published.
# A check that can run and fails always fails the build; a missing optional tool
# is reported instead of silently passing.
set -uo pipefail

R=reports
SIGNED="$(cat work/signed-apk-path.txt)"
FAIL=0
: > "$R/verification.log"

note() { echo "$*" | tee -a "$R/verification.log"; }
pass() { note "PASS  $*"; }
fail() { note "FAIL  $*"; FAIL=1; }
info() { note "INFO  $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "### 1. signature verification"
if have apksigner; then
  if apksigner verify --verbose --print-certs "$SIGNED" > "$R/apksigner-verify.txt" 2>&1; then
    pass "apksigner verify (v1/v2/v3)"
    grep -E "Verified using|Signer #1 certificate SHA-256|Number of signers" "$R/apksigner-verify.txt" | sed 's/^/      /' | tee -a "$R/verification.log"
  else
    fail "apksigner verify"; sed -n '1,15p' "$R/apksigner-verify.txt"
  fi
else
  # Full v1/v2/v3 verification needs apksigner; without it, prove the signing
  # block and v1 digests are present and say plainly what was not executed.
  if python3 scripts/check-apk-signature.py "$SIGNED" > "$R/signature-structure.txt" 2>&1; then
    pass "APK Signing Block + v1 digest structure (python)"
    sed 's/^/      /' "$R/signature-structure.txt" | tee -a "$R/verification.log"
  else
    fail "signature structure check"; cat "$R/signature-structure.txt"
  fi
  note "WARN  apksigner unavailable: full v1/v2/v3 verification not executed"
fi

echo "### 2. archive + alignment"
if have zipalign; then
  if zipalign -c 4 "$SIGNED" >> "$R/verification.log" 2>&1; then pass "zipalign 4-byte aligned"; else fail "zipalign -c 4"; fi
else
  if python3 scripts/check-alignment.py "$SIGNED" > "$R/alignment.txt" 2>&1; then
    pass "4-byte alignment (python check)"
    sed 's/^/      /' "$R/alignment.txt" | tee -a "$R/verification.log"
  else
    fail "4-byte alignment (python check)"; cat "$R/alignment.txt"
  fi
fi
if unzip -t "$SIGNED" > "$R/ziptest-rebuilt.txt" 2>&1; then pass "zip central directory intact"; else fail "unzip -t"; fi

echo "### 3. structural completeness"
ENTRIES="$(unzip -l "$SIGNED")"
echo "$ENTRIES" > "$R/rebuilt-entries.txt"
for must in AndroidManifest.xml classes.dex resources.arsc; do
  if grep -qE "[[:space:]]${must}$" <<<"$ENTRIES"; then pass "contains ${must}"; else fail "missing ${must}"; fi
done
info "dex files: $(grep -cE ' classes[0-9]*\.dex$' <<<"$ENTRIES" || true)"
info "total entries: $(wc -l <<<"$ENTRIES")"

echo "### 4. manifest of the rebuilt APK is parseable"
if have aapt2; then
  if aapt2 dump badging "$SIGNED" > "$R/rebuilt-badging.txt" 2>&1; then
    pass "aapt2 dump badging"
    head -4 "$R/rebuilt-badging.txt" | sed 's/^/      /' | tee -a "$R/verification.log"
  else
    fail "aapt2 dump badging"
  fi
else
  DECODED=0
  for dflags in "-f -s -r" "-f -s" "-f"; do
    rm -rf work/verify-decoded
    if apktool d $dflags "$SIGNED" -o work/verify-decoded >> "$R/verify-decode.log" 2>&1 \
       && [ -f work/verify-decoded/AndroidManifest.xml ]; then DECODED=1; break; fi
  done
  if [ "$DECODED" -eq 1 ]; then
    pass "manifest decodes (apktool)"
    grep -oE 'android:extractNativeLibs="[^"]*"|package="[^"]*"' work/verify-decoded/AndroidManifest.xml | head -3 | sed 's/^/      /' | tee -a "$R/verification.log"
  else
    fail "manifest does not decode"
  fi
fi

echo "### 5. native libraries preserved"
SRC_SO=$(unzip -l "apk/${APK_BASENAME}" | grep -cE ' lib/.*\.so$' || true)
NEW_SO=$(unzip -l "$SIGNED" | grep -cE ' lib/.*\.so$' || true)
info "native libs: source=${SRC_SO} rebuilt=${NEW_SO}"
if [ "${SRC_SO:-0}" -gt 0 ] && [ "${NEW_SO:-0}" -lt "${SRC_SO:-0}" ]; then
  fail "rebuilt APK lost native libraries"
fi

if [ "$FAIL" -ne 0 ]; then echo "### VERIFICATION FAILED"; exit 1; fi
echo "### VERIFICATION PASSED"
