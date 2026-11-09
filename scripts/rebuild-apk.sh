#!/usr/bin/env bash
# Repacks the decoded sources into a new, signed APK.
#
# Lane A (preferred): apktool b --use-aapt2  (uses the APK's own resource set)
# Lane B (fallback):   smali assemble + aapt2 link   (only if A is impossible)
#
# Everything is logged to reports/ so a failed build is diagnosable rather than
# silent.
set -euo pipefail

R=reports
mkdir -p "$R" build
OUT_VERSION="v4.0.02.0831.03"
SIGNED="build/MovieBox_${OUT_VERSION}_rebuilt_signed.apk"

echo "### 0. pre-flight"
test -d work/decoded || { echo "ERROR: work/decoded missing (decode lane failed)"; exit 1; }
test -n "${KEYSTORE_PATH:-}" || { echo "ERROR: KEYSTORE_PATH not set"; exit 1; }
ls work/decoded/AndroidManifest.xml >/dev/null

echo "### 1. reviewed manifest modification"
python3 scripts/mod_manifest.py work/decoded/AndroidManifest.xml | tee "$R/manifest-mod.txt"

echo "### 2. repack (apktool b)"
# aapt2 is the default decoder/compiler in apktool 3.x and an explicit opt-in in
# 2.x, and the framework-dir flag moved. Try the forms in order; the first one
# the installed version accepts wins.
BUILD_OK=0
for flags in "--use-aapt2 -p work/framework" "--use-aapt2" "-p work/framework" ""; do
  rm -f build/unsigned.apk
  {
    echo "--- attempt: apktool b $flags"
    apktool b $flags work/decoded -o build/unsigned.apk 2>&1
  } >> "$R/apktool-build.log"
  if [ -s build/unsigned.apk ]; then
    BUILD_OK=1
    echo "    apktool build ok with flags [${flags}] ($(stat -c%s build/unsigned.apk) bytes)"
    break
  fi
  echo "    attempt [${flags}] produced no APK; trying next form"
done
if [ "$BUILD_OK" -ne 1 ]; then
  echo "    apktool build failed; see $R/apktool-build.log"
  tail -40 "$R/apktool-build.log" || true
fi

if [ "$BUILD_OK" -ne 1 ]; then
  echo "### 3. fallback lane: smali assemble + aapt2 link"
  bash scripts/repack-smali.sh > "$R/smali-build.log" 2>&1 \
    && { BUILD_OK=1; echo "    smali fallback ok"; } \
    || { echo "    smali fallback failed; see $R/smali-build.log"; tail -40 "$R/smali-build.log" || true; }
fi

if [ "$BUILD_OK" -ne 1 ]; then
  echo "ERROR: could not repack the application with either lane."
  echo "The analysis artifacts are still published, but no APK can be produced."
  exit 1
fi

echo "### 4. zipalign"
zipalign -p -f 4 build/unsigned.apk build/unsigned-aligned.apk | tee "$R/zipalign.log"

echo "### 5. sign (v1+v2+v3, apksig)"
: "${KEYSTORE_PASS_USED:?}"
apksigner sign \
  --ks "$KEYSTORE_PATH" \
  --ks-type PKCS12 \
  --ks-key-alias "$KEY_ALIAS_USED" \
  --ks-pass env:KEYSTORE_PASS_USED \
  --key-pass env:KEYSTORE_PASS_USED \
  --v1-signing-enabled true \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --out "$SIGNED" \
  build/unsigned-aligned.apk 2>&1 | tee "$R/apksigner.log"

test -s "$SIGNED"
echo "    signed -> $SIGNED ($(stat -c%s "$SIGNED") bytes)"

( cd build && sha256sum "$(basename "$SIGNED")" ) | tee "$R/rebuilt-apk.sha256"
echo "$SIGNED" > work/signed-apk-path.txt

echo "### 6. artifact checksum manifest"
( cd build && sha256sum *.apk *cert.pem 2>/dev/null ) > "$R/build-artifacts.sha256" || true
cat "$R/build-artifacts.sha256"
