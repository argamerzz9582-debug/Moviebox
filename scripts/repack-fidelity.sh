#!/usr/bin/env bash
# High-fidelity repack: keep the original APK's entries BYTE-FOR-BYTE and change
# only the signature.
#
# Why this exists: an apktool round-trip recompiles resources.arsc and rebuilds
# every DEX. Those are behaviour-preserving in principle, but on real apps they
# can shift resource ids, multidex ordering or compiled-XML details, which shows
# up as a startup crash. Repacking the original bytes removes that entire class
# of failure: the app code and resources are exactly what the vendor shipped; the
# only difference is the signer.
set -uo pipefail

R=reports
mkdir -p "$R" build
exec > >(tee -a "$R/fidelity-console.log") 2>&1

SRC="apk/${APK_BASENAME}"
OUT_VERSION="v4.0.02.0831.03"
SIGNED="build/MovieBox_${OUT_VERSION}_fidelity_signed.apk"
WORK="work/fidelity"

echo "### 0. pre-flight"
test -s "$SRC" || { echo "ERROR: source APK missing"; exit 1; }
test -n "${KEYSTORE_PATH:-}" || { echo "ERROR: KEYSTORE_PATH not set"; exit 1; }
rm -rf "$WORK"; mkdir -p "$WORK"

echo "### 1. verify the source is intact before touching it"
unzip -t "$SRC" > "$R/fidelity-ziptest.txt" 2>&1 && echo "    zip integrity OK" || { echo "ERROR: source zip is corrupt"; exit 1; }

echo "### 2. drop only the old signature material"
# v1 signature lives in META-INF/*.SF|RSA|DSA|EC and breaks the moment bytes
# change; the v2/v3 block is stripped by the signer. Everything else is kept.
python3 - "$SRC" "$WORK/base.apk" <<'PY'
import shutil, sys, zipfile
src, dst = sys.argv[1], sys.argv[2]
DROP = (".sf", ".rsa", ".dsa", ".ec")
kept = dropped = 0
with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
    for info in zin.infolist():
        lname = info.filename.lower()
        is_sig = lname.startswith("meta-inf/") and lname.endswith(DROP)
        # Preserve compression and metadata exactly for everything retained:
        # a STORED .so must stay STORED so it is memory-mappable as shipped.
        if is_sig:
            dropped += 1
            continue
        data = zin.read(info.filename)
        out = zipfile.ZipInfo(info.filename, date_time=info.date_time)
        out.compress_type = info.compress_type
        out.external_attr = info.external_attr
        out.internal_attr = info.internal_attr
        out.create_system = info.create_system
        zout.writestr(out, data)
        kept += 1
print(f"kept {kept} entries, dropped {dropped} old signature entries")
PY
test -s "$WORK/base.apk" || { echo "ERROR: repack produced nothing"; exit 1; }

echo "### 3. prove the repack did not change the app's own bytes"
python3 - "$SRC" "$WORK/base.apk" <<'PY' | tee "$R/fidelity-diff.txt"
import hashlib, sys, zipfile
def m(p):
    d = {}
    with zipfile.ZipFile(p) as z:
        for i in z.infolist():
            if i.is_dir():
                continue
            n = i.filename.lower()
            if n.startswith("meta-inf/") and n.endswith((".sf", ".rsa", ".dsa", ".ec")):
                continue
            d[i.filename] = (hashlib.sha256(z.read(i.filename)).hexdigest(), i.compress_type)
    return d
a, b = m(sys.argv[1]), m(sys.argv[2])
changed = [k for k in a if k in b and a[k][0] != b[k][0]]
comp = [k for k in a if k in b and a[k][1] != b[k][1]]
missing = [k for k in a if k not in b]
print(f"entries compared      : {len(a)}")
print(f"content changed       : {len(changed)}")
print(f"compression changed   : {len(comp)}")
print(f"missing from repack   : {len(missing)}")
for k in (changed + comp + missing)[:10]:
    print(f"  ! {k}")
sys.exit(1 if (changed or comp or missing) else 0)
PY
[ $? -eq 0 ] || { echo "ERROR: repack altered app content; refusing to continue"; exit 1; }

echo "### 4. zipalign + sign"
case "${SIGNER_MODE:-}" in
  apksigner)
    zipalign -p -f 4 "$WORK/base.apk" "$WORK/base-aligned.apk" | tee "$R/fidelity-zipalign.log"
    : "${KEYSTORE_PASS_USED:?}"
    apksigner sign --ks "$KEYSTORE_PATH" --ks-type PKCS12 \
      --ks-key-alias "$KEY_ALIAS_USED" \
      --ks-pass env:KEYSTORE_PASS_USED --key-pass env:KEYSTORE_PASS_USED \
      --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
      --out "$SIGNED" "$WORK/base-aligned.apk" 2>&1 | tee "$R/fidelity-apksigner.log"
    ;;
  uber)
    UBER="${RUNNER_TEMP:-/tmp}/tools/uber-apk-signer.jar"
    JKS="$RUNNER_TEMP/keys/release.jks"
    keytool -importkeystore -noprompt \
      -srckeystore "$KEYSTORE_PATH" -srcstoretype PKCS12 -srcstorepass "$KEYSTORE_PASS_USED" \
      -destkeystore "$JKS" -deststoretype JKS \
      -deststorepass "$KEYSTORE_PASS_USED" -destkeypass "$KEYSTORE_PASS_USED" \
      > "$R/fidelity-keystore.log" 2>&1
    rm -rf "$R/fidelity-out"
    java -jar "$UBER" --apks "$WORK/base.apk" --ks "$JKS" \
      --ksAlias "$KEY_ALIAS_USED" --ksPass "$KEYSTORE_PASS_USED" --ksKeyPass "$KEYSTORE_PASS_USED" \
      --allowResign --out "$R/fidelity-out" 2>&1 | tee "$R/fidelity-uber.log"
    PROD="$(find "$R/fidelity-out" -name '*signed*.apk' 2>/dev/null | head -1)"
    [ -n "$PROD" ] || PROD="$(find "$R/fidelity-out" -name '*.apk' 2>/dev/null | head -1)"
    test -n "$PROD" || { echo "ERROR: signing produced no APK"; java -jar "$UBER" --help 2>&1 | head -30; exit 1; }
    cp "$PROD" "$SIGNED"
    ;;
  *) echo "ERROR: no signer resolved (SIGNER_MODE=${SIGNER_MODE:-unset})"; exit 1 ;;
esac

test -s "$SIGNED" || { echo "ERROR: signed APK missing"; exit 1; }
echo "    signed -> $SIGNED ($(stat -c%s "$SIGNED") bytes)"
( cd build && sha256sum "$(basename "$SIGNED")" ) | tee "$R/fidelity-sha256.txt"
echo "$SIGNED" > work/fidelity-apk-path.txt
