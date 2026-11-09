#!/usr/bin/env bash
# Publishes the signed APK as a GitHub Release asset: a permanent, direct,
# resumable download URL (no login, no Drive quota page, no expiring link).
set -euo pipefail

if [ -s work/fidelity-apk-path.txt ]; then
  SIGNED="$(cat work/fidelity-apk-path.txt)"
else
  SIGNED="$(cat work/signed-apk-path.txt)"
fi
VERSION="v4.0.02.0831.03"
if [ "${FIDELITY:-0}" = "1" ]; then
  TAG="moviebox-${VERSION}-fidelity"
  TITLE="MovieBox ${VERSION} — high-fidelity repack (signature-only change)"
else
  TAG="moviebox-${VERSION}-rebuilt"
  TITLE="MovieBox ${VERSION} — rebuilt & signed"
fi
NOTES=reports/release-notes.md
SHA="$(sha256sum "$SIGNED" | cut -d' ' -f1)"
FP="$(awk -F': ' '/certificate_sha256/{print $2}' build/signing-identity.txt || true)"

cat > "$NOTES" <<EOF
## MovieBox ${VERSION} — rebuilt from its own decoded sources

Reverse engineered with [REA](https://github.com/morluto/rea) (apktool + JADX
providers) and [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
headless for the native lane, then rebuilt, zipaligned and signed from the
decoded tree. Nothing was downloaded from a third-party APK mirror: the input is
the APK in Google Drive (\`MovieBox_v4.0.02.0831.03.apk\`).

| | |
|---|---|
| Source APK SHA-256 | \`$(cut -d' ' -f1 reports/source-apk.sha256 2>/dev/null || echo 'see artifacts')\` |
| Rebuilt APK SHA-256 | \`${SHA}\` |
| Signing certificate SHA-256 | \`${FP:-see signing-identity.txt}\` |
| Bundle id | \`$(grep -oE "package: name='[^']+'" reports/rebuilt-badging.txt 2>/dev/null | cut -d"'" -f2 || echo 'see reports')\` |

### Modifications
$(cat reports/manifest-modifications.txt 2>/dev/null | sed -n 's/^- /- /p' || echo '- see reports/manifest-modifications.txt')

No code, resource, asset or native library was altered, added or removed.

### Install
\`\`\`bash
adb install -r MovieBox_${VERSION}_rebuilt_signed.apk
\`\`\`
Android will treat this as a different signer than the Play Store/stock build, so
uninstall the existing copy first (or install to a separate profile) if Android
reports \`INSTALL_FAILED_UPDATE_INCOMPATIBLE\`.

### Verification
\`\`\`bash
sha256sum -c <<< "${SHA}  MovieBox_${VERSION}_rebuilt_signed.apk"
apksigner verify --print-certs MovieBox_${VERSION}_rebuilt_signed.apk
\`\`\`

Full analysis evidence (manifest, permissions, class inventory, native exports,
Ghidra function inventory, build logs, verification log) is in the workflow
artifacts for this run.
EOF

if gh release view "$TAG" >/dev/null 2>&1; then
  echo "==> release ${TAG} exists; uploading/refreshing asset"
  gh release upload "$TAG" "$SIGNED" --clobber
  gh release edit "$TAG" --notes-file "$NOTES"
else
  echo "==> creating release ${TAG}"
  gh release create "$TAG" "$SIGNED" \
    --title "$TITLE" \
    --notes-file "$NOTES" \
    --latest
fi

# Also expose the analysis report as a second asset (people trust what they can read).
gh release upload "$TAG" reports/report.md --clobber 2>/dev/null || true
gh release upload "$TAG" reports/rebuilt-apk.sha256 --clobber 2>/dev/null || true
gh release upload "$TAG" build/release-cert.pem --clobber 2>/dev/null || true

URL="$(gh release view "$TAG" --json assets --jq ".assets[] | select(.name|endswith(\"${SIGNED##*/}\")) | .url" 2>/dev/null || true)"
echo "==> published: https://github.com/${GITHUB_REPOSITORY}/releases/tag/${TAG}"
echo "==> direct asset URL: ${URL:-https://github.com/${GITHUB_REPOSITORY}/releases/download/${TAG}/$(basename "$SIGNED")}"
