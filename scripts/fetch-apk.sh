#!/usr/bin/env bash
# Fetches the source APK from Google Drive (or an explicit URL) and proves it is
# a real, intact APK before anything analyses it.
set -euo pipefail

mkdir -p apk reports
DEST="apk/${APK_BASENAME}"
URL="${APK_URL:-}"

fetch() {
  ( set +e; curl -fL --retry 3 --retry-delay 5 --connect-timeout 30 -o "$DEST" "$1"; echo $? > /tmp/curl.rc )
}

if [ -n "$URL" ]; then
  echo "==> using caller-supplied APK URL"
  fetch "$URL"
else
  echo "==> fetching from Google Drive (file id ${APK_DRIVE_FILE_ID})"
  fetch "https://drive.usercontent.google.com/download?id=${APK_DRIVE_FILE_ID}&export=download&confirm=t"
  if [ "$(cat /tmp/curl.rc)" != "0" ] || ! python3 -c "import sys; sys.exit(0 if open('$DEST','rb').read(2)==b'PK' else 1)" 2>/dev/null; then
    echo "==> primary endpoint did not return a zip; retrying via uc?export=download"
    fetch "https://drive.google.com/uc?export=download&confirm=t&id=${APK_DRIVE_FILE_ID}"
  fi
fi

if head -c 200 "$DEST" | grep -qi '<!DOCTYPE html\|<html'; then
  echo "ERROR: Google returned an HTML page instead of the APK (file not shared publicly?)."
  head -c 400 "$DEST"; exit 1
fi

if ! python3 -c "import sys; sys.exit(0 if open('$DEST','rb').read(4)[:2]==b'PK' else 1)"; then
  echo "ERROR: downloaded file is not a ZIP/APK. First bytes:"; od -An -c -N 32 "$DEST"; exit 1
fi

SIZE=$(stat -c%s "$DEST")
echo "==> downloaded ${DEST} (${SIZE} bytes)"
if [ "$SIZE" -lt 1000000 ]; then echo "ERROR: file suspiciously small"; exit 1; fi

unzip -t "$DEST" > reports/source-apk-ziptest.txt 2>&1 && echo "==> zip integrity OK"

( cd apk && sha256sum "${APK_BASENAME}" ) | tee reports/source-apk.sha256

if [ -n "${EXPECTED_SHA256:-}" ]; then
  echo "==> verifying pinned digest"
  echo "${EXPECTED_SHA256}  ${DEST}" | sha256sum -c -
fi

echo "==> source APK entries: $(unzip -l "$DEST" | tail -1)"
