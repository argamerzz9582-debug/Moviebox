#!/usr/bin/env bash
# Restores the release signing key from repository secrets.
# The key material lives only in ${RUNNER_TEMP}; it is never uploaded as an
# artifact and never written to the workspace.
set -euo pipefail

mkdir -p build "$RUNNER_TEMP/keys"
KEY="$RUNNER_TEMP/keys/release.p12"
CERT="build/release-cert.pem"

if [ -n "${KEYSTORE_B64:-}" ]; then
  printf '%s' "$KEYSTORE_B64" | base64 -d > "$KEY"
  chmod 600 "$KEY"
  if [ -z "${KEYSTORE_PASS:-}" ]; then
    echo "ERROR: RELEASE_KEYSTORE_B64 is set but RELEASE_KEYSTORE_PASS is empty"; exit 1
  fi
  ALIAS="${KEY_ALIAS:-moviebox-rebuild}"
  PASS="$KEYSTORE_PASS"
  MODE="repository-secret"
else
  echo "::warning::No RELEASE_KEYSTORE_B64 secret found: generating an ephemeral signing key for this run."
  echo "::warning::The APK will install, but future builds will not update over it (different signer)."
  ALIAS="moviebox-rebuild"
  PASS="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
  keytool -genkeypair \
    -keystore "$KEY" -storetype PKCS12 -alias "$ALIAS" \
    -keyalg RSA -keysize 3072 -validity 10000 \
    -storepass "$PASS" -keypass "$PASS" \
    -dname "CN=MovieBox Ephemeral, O=MovieBox Rebuild, OU=Android, C=IN" >/dev/null 2>&1
  MODE="ephemeral"
fi

keytool -exportcert -keystore "$KEY" -storepass "$PASS" -alias "$ALIAS" -rfc -file "$CERT" >/dev/null 2>&1
FINGERPRINT="$(keytool -printcert -file "$CERT" | awk -F': ' '/SHA256:/{print $2; exit}')"

{
  echo "keystore_mode: ${MODE}"
  echo "alias: ${ALIAS}"
  echo "certificate_sha256: ${FINGERPRINT}"
  echo "certificate_file: release-cert.pem"
} | tee build/signing-identity.txt

{
  echo "KEYSTORE_PATH=$KEY"
  echo "KEY_ALIAS_USED=$ALIAS"
} >> "$GITHUB_ENV"
printf 'KEYSTORE_PASS_USED=%s\n' "$PASS" >> "$GITHUB_ENV"
