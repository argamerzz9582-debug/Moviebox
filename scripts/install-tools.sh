#!/usr/bin/env bash
# Resolves the reverse-engineering toolchain and a usable signer.
#
# Signer strategy (in order):
#   1. Android build-tools (zipalign + apksigner) from Google's stable repo
#   2. uber-apk-signer (same apksig library; also zipaligns via zipflinger)
#
# apktool ships its own aapt2, so a full Android SDK is not required to repack.
# Nothing here assumes a CLI shape that was not probed; the resolved versions are
# printed and retained in reports/toolchain.txt.
set -uo pipefail

ROOT="$PWD"
TOOLS="${RUNNER_TEMP:-/tmp}/tools"
mkdir -p "$TOOLS/bin" "$TOOLS/engines" "$ROOT/reports" "$ROOT/build" "$ROOT/apk" "$ROOT/work"
export PATH="$TOOLS/bin:$PATH"
REPORT="$ROOT/reports/toolchain.txt"
: > "$REPORT"

log() { echo "$*" | tee -a "$REPORT"; }

reach() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 20 -L "$1" || echo "ERR"
}

dl() { # dl <url> <dest>
  local url="$1" dest="$2"
  for attempt in 1 2 3; do
    if curl -fsSL --retry 3 --retry-delay 2 --retry-connrefused \
         --connect-timeout 20 --max-time 600 -o "$dest" "$url" && [ -s "$dest" ]; then
      return 0
    fi
    log "    attempt ${attempt} failed: ${url}"
    sleep $((attempt * 3))
  done
  return 1
}

log "## host"
log "  $(uname -srm)"
log "  java: $(java -version 2>&1 | head -1)"
log "  node: $(node -v)  npm: $(npm -v)"
log "  disk: $(df -h / | tail -1 | awk '{print $4" free"}')"

log "## reachability"
for u in https://github.com https://dl.google.com https://registry.npmjs.org; do
  log "  ${u} -> $(reach "$u")"
done

# ---------------------------------------------------------------- REA
log "## REA ${REA_VERSION}"
mkdir -p "$TOOLS/rea"
( cd "$TOOLS/rea" && npm init -y >/dev/null 2>&1 \
    && npm install --no-audit --no-fund "rea-agents@${REA_VERSION}" >/dev/null 2>&1 )
ln -sf "$TOOLS/rea/node_modules/.bin/rea" "$TOOLS/bin/rea"
log "  version: $(rea --version 2>&1 | head -1)"

# ---------------------------------------------------------------- apktool
log "## apktool ${APKTOOL_VERSION}"
if dl "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" "$TOOLS/apktool.jar"; then
  cat > "$TOOLS/bin/apktool" <<EOF
#!/usr/bin/env bash
exec java -jar "$TOOLS/apktool.jar" "\$@"
EOF
  chmod +x "$TOOLS/bin/apktool"
  log "  version: $(apktool --version 2>&1 | head -1)"
  log "  bundled aapt2 entries: $(unzip -l "$TOOLS/apktool.jar" | grep -cE 'prebuilt/.*aapt2')"
else
  log "  DOWNLOAD FAILED"
fi

# ---------------------------------------------------------------- JADX engine
log "## jadx-headless-mcp ${JADX_MCP_VERSION}"
if dl "https://github.com/1013503897/jadx-headless-mcp/releases/download/v${JADX_MCP_VERSION}/jadx-headless-mcp-${JADX_MCP_VERSION}-all.jar" "$TOOLS/jadx-headless-mcp.jar"; then
  ACTUAL="$(sha256sum "$TOOLS/jadx-headless-mcp.jar" | cut -d' ' -f1)"
  if [ "$ACTUAL" = "$JADX_MCP_SHA256" ]; then
    log "  digest verified (audited release)"
  else
    log "  ::warning::digest mismatch: expected ${JADX_MCP_SHA256}, got ${ACTUAL}"
  fi
  echo "REA_JADX_MCP_JAR=$TOOLS/jadx-headless-mcp.jar" >> "$GITHUB_ENV"
else
  log "  DOWNLOAD FAILED (JADX lane will report capability_unavailable)"
fi

# ---------------------------------------------------------------- smali (fallback repack)
log "## smali ${SMALI_VERSION} (only if apktool cannot repack)"
if dl "https://github.com/google/smali/releases/download/v${SMALI_VERSION}/smali-${SMALI_VERSION}-fat.jar" "$ROOT/work/smali.jar"; then
  log "  ok ($(stat -c%s "$ROOT/work/smali.jar") bytes)"
else
  rm -f "$ROOT/work/smali.jar"; log "  unavailable"
fi

# ---------------------------------------------------------------- Ghidra
log "## Ghidra ${GHIDRA_VERSION}"
if [ "${RUN_GHIDRA:-true}" = "true" ]; then
  if dl "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ZIP}" "$TOOLS/ghidra.zip"; then
    unzip -q "$TOOLS/ghidra.zip" -d "$TOOLS/engines"
    GDIR="$(find "$TOOLS/engines" -maxdepth 1 -type d -name 'ghidra_*_PUBLIC' | head -1)"
    if [ -n "$GDIR" ]; then
      chmod +x "$GDIR/support/analyzeHeadless"
      echo "GHIDRA_INSTALL_DIR=$GDIR" >> "$GITHUB_ENV"
      log "  GHIDRA_INSTALL_DIR=$GDIR"
    else
      log "  extraction failed"
    fi
  else
    log "  DOWNLOAD FAILED (native Ghidra lane will be skipped)"
  fi
else
  log "  skipped by input"
fi

# ---------------------------------------------------------------- signer
log "## signer"
SIGNER_MODE="none"
if dl "https://dl.google.com/android/repository/build-tools_r${BUILD_TOOLS}-linux.zip" /tmp/build-tools.zip; then
  mkdir -p "$HOME/android-sdk/build-tools" /tmp/bt
  unzip -q -o /tmp/build-tools.zip -d /tmp/bt
  SRC="$(find /tmp/bt -maxdepth 2 -name aapt2 -printf '%h\n' | head -1)"
  if [ -n "${SRC:-}" ]; then
    DEST="$HOME/android-sdk/build-tools/${BUILD_TOOLS}"
    rm -rf "$DEST"; mv "$SRC" "$DEST"; chmod +x "$DEST"/* 2>/dev/null || true
    if [ -x "$DEST/apksigner" ] && [ -x "$DEST/zipalign" ]; then
      echo "$DEST" >> "$GITHUB_PATH"
      echo "ANDROID_HOME=$HOME/android-sdk" >> "$GITHUB_ENV"
      SIGNER_MODE="apksigner"
      log "  build-tools ${BUILD_TOOLS}: apksigner + zipalign ready"
      log "  aapt2: $("$DEST/aapt2" version 2>&1 | head -1)"
    else
      log "  build-tools archive lacked apksigner/zipalign"
    fi
  else
    log "  build-tools archive layout unexpected"
  fi
else
  log "  build-tools download failed"
fi

if [ "$SIGNER_MODE" = "none" ]; then
  log "  falling back to uber-apk-signer"
  if dl "https://github.com/patrickfav/uber-apk-signer/releases/download/v${UBER_APK_SIGNER_VERSION}/uber-apk-signer-${UBER_APK_SIGNER_VERSION}.jar" "$TOOLS/uber-apk-signer.jar"; then
    log "  uber-apk-signer bytes: $(stat -c%s "$TOOLS/uber-apk-signer.jar")"
    log "  sha256: $(sha256sum "$TOOLS/uber-apk-signer.jar" | cut -d' ' -f1)"
    SIGNER_MODE="uber"
  else
    log "  ::error::no signer available"
  fi
fi
echo "SIGNER_MODE=$SIGNER_MODE" >> "$GITHUB_ENV"
log "  selected: ${SIGNER_MODE}"

# ---------------------------------------------------------------- readiness
log "## REA readiness"
echo "$TOOLS/bin" >> "$GITHUB_PATH"
echo "REA_APKTOOL_COMMAND=$TOOLS/bin/apktool" >> "$GITHUB_ENV"
export REA_APKTOOL_COMMAND="$TOOLS/bin/apktool"
[ -f "$TOOLS/jadx-headless-mcp.jar" ] && export REA_JADX_MCP_JAR="$TOOLS/jadx-headless-mcp.jar"
rea doctor --json > "$ROOT/reports/rea-doctor.json" 2>&1 || true
rea inspect-apktool-client --json > "$ROOT/reports/rea-apktool-client.json" 2>&1 || true
python3 - "$ROOT/reports/rea-doctor.json" <<'PY' | tee -a "$REPORT" || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as exc:
    print(f"  doctor unreadable: {exc}"); raise SystemExit(0)
for c in d.get("checks", []):
    print(f"  {c.get('name'):<18} ok={c.get('ok')} {c.get('classification','')}")
for p in (d.get("providerInspections") or []):
    print(f"  provider {p.get('id'):<10} configured={p.get('configured')} available={p.get('available')}")
PY
log "## done"
