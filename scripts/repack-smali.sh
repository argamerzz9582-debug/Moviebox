#!/usr/bin/env bash
# Fallback repack lane used only when `apktool b` cannot build the decoded tree.
#   smali -> dex  (smali assembler, per smali_classesN dir)
#   res   -> apk  (aapt2 compile/link against android.jar from the platform)
#   dex + assets + libs are then merged into the linked APK.
set -euo pipefail

R=reports
SMALI_VER="${SMALI_VERSION:-3.0.9}"
mkdir -p "$R" work/smali work/dex

echo "### fetch smali assembler ${SMALI_VER}"
if [ ! -f work/smali.jar ]; then
  URL="https://github.com/google/smali/releases/download/v${SMALI_VER}/smali-${SMALI_VER}-fat.jar"
  curl -fsSL --retry 3 -o work/smali.jar "$URL" \
    || curl -fsSL --retry 3 -o work/smali.jar \
        "https://github.com/google/smali/releases/download/smali-${SMALI_VER}/smali-${SMALI_VER}-fat.jar"
fi
ls -l work/smali.jar

echo "### assemble smali"
i=1
for d in work/decoded/smali work/decoded/smali_classes*; do
  [ -d "$d" ] || continue
  n=$(basename "$d" | sed 's/^smali_classes//; s/^smali$//')
  [ -z "$n" ] && n=1
  java -jar work/smali.jar assemble "$d" -o "work/dex/classes${n}.dex" 
  i=$((i + 1))
done
ls -l work/dex

echo "### determine min/target sdk from the decoded manifest"
read -r MIN_SDK TGT_SDK <<<"$(python3 - <<'PY'
import re
m = open('work/decoded/AndroidManifest.xml', encoding='utf-8').read()
def sdk(attr):
    mm = re.search(attr + r'="(\d+)"', m)
    return mm.group(1) if mm else ''
print(sdk('android:minSdkVersion') or '21', sdk('android:targetSdkVersion') or '35')
PY
)"
echo "    minSdk=${MIN_SDK} targetSdk=${TGT_SDK}"

echo "### aapt2 compile resources"
rm -rf work/rescompiled && mkdir -p work/rescompiled
aapt2 compile --dir work/decoded/res -o work/rescompiled/ > "$R/aapt2-compile.log" 2>&1

echo "### aapt2 link"
PLATFORM_JAR="$(ls -d "${ANDROID_HOME}"/platforms/android-*/android.jar 2>/dev/null | sort -V | tail -1)"
if [ -z "${PLATFORM_JAR:-}" ]; then
  yes | sdkmanager --licenses >/dev/null 2>&1 || true
  sdkmanager --install "platforms;android-35" >/dev/null
  PLATFORM_JAR="$(ls -d "${ANDROID_HOME}"/platforms/android-*/android.jar | sort -V | tail -1)"
fi
echo "    platform jar: $PLATFORM_JAR"

# Thousands of compiled resources exceed the shell argument limit; aapt2 reads
# an @argfile instead.
find work/rescompiled -name '*.flat' -printf '-R\n%p\n' > work/aapt2-args.txt
echo "    compiled resource files: $(grep -c '^-R$' work/aapt2-args.txt)"

aapt2 link \
  -I "$PLATFORM_JAR" \
  --manifest work/decoded/AndroidManifest.xml \
  -o work/linked.apk \
  @work/aapt2-args.txt \
  --auto-add-overlay \
  --min-sdk-version "$MIN_SDK" \
  --target-sdk-version "$TGT_SDK" \
  > "$R/aapt2-link.log" 2>&1

echo "### merge dex + assets + native libs + kotlin metadata"
cp work/linked.apk build/unsigned.apk
for f in work/dex/classes*.dex; do
  [ -f "$f" ] || continue
  ( cd work/dex && zip -q -0 "../../build/unsigned.apk" "$(basename "$f")" )
done
if [ -d work/decoded/assets ]; then
  ( cd work/decoded && zip -q -r "../../build/unsigned.apk" assets -x '*.DS_Store' )
fi
if [ -d work/decoded/lib ]; then
  ( cd work/decoded && zip -q -r "../../build/unsigned.apk" lib )
fi
if [ -d work/decoded/kotlin ]; then
  ( cd work/decoded && zip -q -r "../../build/unsigned.apk" kotlin )
fi
for extra in work/decoded/META-INF/services; do
  [ -d "$extra" ] || continue
done
echo "    merged -> build/unsigned.apk ($(stat -c%s build/unsigned.apk) bytes)"
