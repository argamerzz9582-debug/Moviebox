#!/usr/bin/env bash
# Repacks the decoded sources into a new, signed APK.
#   Lane A (preferred): apktool b (bundles aapt2; uses the APK's resource set)
#   Lane B (fallback):  smali assemble + aapt2 link
# Signing: apksigner+zipalign when build-tools exist, else uber-apk-signer.
set -uo pipefail

R=reports
mkdir -p "$R" build
# Retain this step's console so a failure can be reported as a check-run
# annotation even where workflow logs are unreachable.
exec > >(tee -a "$R/rebuild-console.log") 2>&1

OUT_VERSION="v4.0.02.0831.03"
SIGNED="build/MovieBox_${OUT_VERSION}_rebuilt_signed.apk"

echo "### 0. pre-flight"
test -d work/decoded || { echo "ERROR: work/decoded missing (decode lane failed)"; exit 1; }
test -n "${KEYSTORE_PATH:-}" || { echo "ERROR: KEYSTORE_PATH not set"; exit 1; }
test -f work/decoded/AndroidManifest.xml || { echo "ERROR: decoded manifest missing"; exit 1; }
echo "    signer: ${SIGNER_MODE:-?}"

echo "### 1. reviewed manifest modification"
python3 scripts/mod_manifest.py work/decoded/AndroidManifest.xml | tee "$R/manifest-mod.txt"

echo "### 2. repack (apktool b)"
# apktool 3.x always uses aapt2 (--use-aapt2 was removed there), 2.x wants it
# explicitly, and the framework-dir flag moved between majors. Each form is
# tried in isolation so one rejection cannot abort the chain.
BUILD_OK=0
for flags in "-p work/framework" "--use-aapt2 -p work/framework" "--use-aapt2" ""; do
  rm -f build/unsigned.apk
  {
    echo "--- attempt: apktool b ${flags} work/decoded -o build/unsigned.apk"
    ( set +e; apktool b ${flags} work/decoded -o build/unsigned.apk 2>&1; echo "rc=$?" )
  } >> "$R/apktool-build.log"
  if [ -s build/unsigned.apk ]; then
    BUILD_OK=1
    echo "    ok with flags [${flags}] -> $(stat -c%s build/unsigned.apk) bytes"
    break
  fi
  echo "    attempt [${flags}] produced no APK"
done

if [ "$BUILD_OK" -ne 1 ]; then
  echo "    apktool build failed; tail:"
  tail -30 "$R/apktool-build.log"
  echo "### 3. fallback lane: smali assemble + aapt2 link"
  if bash scripts/repack-smali.sh >> "$R/smali-build.log" 2>&1 && [ -s build/unsigned.apk ]; then
    BUILD_OK=1; echo "    smali fallback ok"
  else
    echo "    smali fallback failed; tail:"; tail -30 "$R/smali-build.log"
  fi
fi

if [ "$BUILD_OK" -ne 1 ]; then
  echo "ERROR: neither repack lane produced an APK; analysis artifacts are still published"
  {
    echo "--- apktool version"; apktool --version 2>&1 | head -3
    echo "--- apktool b usage"; apktool b --help 2>&1 | head -30
    echo "--- decoded tree"; ls -la work/decoded 2>&1 | head -20
    echo "--- smali dirs"; ls -d work/decoded/smali* 2>&1
    echo "--- apktool-build.log tail"; tail -40 "$R/apktool-build.log" 2>&1
  }
  exit 1
fi

case "${SIGNER_MODE:-}" in
  apksigner)
    echo "### 4. zipalign + apksigner"
    zipalign -p -f 4 build/unsigned.apk build/unsigned-aligned.apk | tee "$R/zipalign.log"
    : "${KEYSTORE_PASS_USED:?}"
    apksigner sign \
      --ks "$KEYSTORE_PATH" --ks-type PKCS12 \
      --ks-key-alias "$KEY_ALIAS_USED" \
      --ks-pass env:KEYSTORE_PASS_USED \
      --key-pass env:KEYSTORE_PASS_USED \
      --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
      --out "$SIGNED" build/unsigned-aligned.apk 2>&1 | tee "$R/apksigner.log"
    ;;
  uber)
    echo "### 4. sign with uber-apk-signer (zipalign + v1/v2/v3 in one pass)"
    UBER="${RUNNER_TEMP:-/tmp}/tools/uber-apk-signer.jar"
    JAVA_KEYSTORE="$RUNNER_TEMP/keys/release.jks"
    keytool -importkeystore -noprompt \
      -srckeystore "$KEYSTORE_PATH" -srcstoretype PKCS12 -srcstorepass "$KEYSTORE_PASS_USED" \
      -destkeystore "$JAVA_KEYSTORE" -deststoretype JKS \
      -deststorepass "$KEYSTORE_PASS_USED" -destkeypass "$KEYSTORE_PASS_USED" \
      > "$R/keystore-convert.log" 2>&1
    java -jar "$UBER" \
      --apks build/unsigned.apk \
      --ks "$JAVA_KEYSTORE" \
      --ksAlias "$KEY_ALIAS_USED" \
      --ksPass "$KEYSTORE_PASS_USED" \
      --ksKeyPass "$KEYSTORE_PASS_USED" \
      --allowResign --overwrite \
      --out "$R/uber-out" 2>&1 | tee "$R/uber-apk-signer.log"
    PRODUCED="$(find "$R/uber-out" -name '*signed*.apk' -o -name '*aligned*.apk' 2>/dev/null | head -1)"
    test -n "$PRODUCED" || { echo "ERROR: uber-apk-signer produced no APK"; exit 1; }
    cp "$PRODUCED" "$SIGNED"
    ;;
  *)
    echo "ERROR: no signing tool was resolved (SIGNER_MODE=${SIGNER_MODE:-unset})"
    exit 1
    ;;
esac

test -s "$SIGNED" || { echo "ERROR: signed APK missing"; exit 1; }
echo "    signed -> $SIGNED ($(stat -c%s "$SIGNED") bytes)"
( cd build && sha256sum "$(basename "$SIGNED")" ) | tee "$R/rebuilt-apk.sha256"
echo "$SIGNED" > work/signed-apk-path.txt

echo "### 5. artifact digests"
( cd build && sha256sum *.apk *cert.pem 2>/dev/null ) > "$R/build-artifacts.sha256" || true
cat "$R/build-artifacts.sha256"
