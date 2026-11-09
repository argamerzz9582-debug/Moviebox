#!/usr/bin/env bash
# Baseline static reverse engineering of the APK.
#   REA + apktool  -> decoded manifest, resources, string tables
#   REA + JADX     -> package declarations, SDK/permissions, class inventory
#   REA            -> APK signing-scheme self-consistency of the shipped artifact
# Everything is saved as evidence JSON: the rebuild decision must be justified
# by decoded facts, not guesses.
set -euo pipefail

APK="apk/${APK_BASENAME}"
R=reports
mkdir -p "$R" build

run() { # run <label> <command...>; never aborts the lane, but records failures
  local label="$1"; shift
  echo "==> REA: ${label}"
  if "$@" > "$R/${label}.json" 2> "$R/${label}.stderr"; then
    echo "    ok  -> $R/${label}.json ($(stat -c%s "$R/${label}.json") bytes)"
    return 0
  fi
  echo "    FAILED -> see $R/${label}.stderr"
  return 0
}

echo "### 1. resources + manifest (apktool lane)"
rea decode-android-resources "$APK" --json > "$R/apktool-decode.json" 2> "$R/apktool-decode.stderr" \
  && echo "    ok (apktool)" || echo "    apktool lane failed -> $R/apktool-decode.stderr"

echo "### 2. package declarations (JADX lane)"
# The APK is 64 MiB; give JADX a realistic heap and operation budget.
export REA_JADX_HEAP_MIB="${REA_JADX_HEAP_MIB:-6144}"
export REA_JADX_OPERATION_TIMEOUT_MS="${REA_JADX_OPERATION_TIMEOUT_MS:-3600000}"
rea inspect-android-package "$APK" --json > "$R/android-package.json" 2> "$R/android-package.stderr" \
  && echo "    ok (jadx)" || echo "    jadx lane failed -> $R/android-package.stderr"

echo "### 3. shipped signing schemes"
run apk-signature rea inspect-apk-signature "$APK" --json

echo "### 4. Flutter / framework fingerprint (cheap structural probe)"
run flutter-build rea identify-flutter-build "$APK" --json

echo "### 5. class inventory (JADX)"
run class-inventory rea search-android-classes "$APK" "" --json

echo "### 6. deterministic decode of the APK for the rebuild (apktool d)"
# Flag sets differ across apktool major versions; try the richest form first and
# fall back on an option error instead of assuming one CLI shape.
DECODE_OK=0
for flags in "-f -p work/framework" "-f -p framework" "-f"; do
  if apktool d $flags "$APK" -o work/decoded >> "$R/apktool-decode.log" 2>&1; then
    DECODE_OK=1; echo "    decode flags accepted: apktool d $flags"; break
  fi
  rm -rf work/decoded
  echo "    retrying decode without: $flags"
done
if [ "$DECODE_OK" -ne 1 ]; then
  echo "    apktool decode FAILED -> $R/apktool-decode.log"; tail -30 "$R/apktool-decode.log"; exit 1
fi
echo "    ok -> work/decoded"

# The decoded tree is the authoritative source for the rebuild; snapshot the
# facts a reviewer needs to see before trusting it.
{
  echo "# Decoded tree"
  echo
  echo "smali roots:"
  find work/decoded -maxdepth 1 -type d -name 'smali*' -printf '  %f (%s bytes)\n' 2>/dev/null || true
  for d in work/decoded/smali*; do
    [ -d "$d" ] && echo "  $(find "$d" -name '*.smali' | wc -l) smali files in $(basename "$d")"
  done
  echo
  echo "native libs:"
  find work/decoded -path '*/lib/*' -name '*.so' -printf '  %p (%s bytes)\n' 2>/dev/null || echo "  (none)"
  echo
  echo "dex:"
  ls -l work/decoded/*.dex 2>/dev/null || echo "  (smali only)"
} | tee "$R/decoded-tree.txt"

echo "### baseline analysis complete"
