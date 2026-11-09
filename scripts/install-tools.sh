#!/usr/bin/env bash
# Installs the reverse-engineering toolchain on the CI runner:
#   REA (morluto/rea) CLI + its apktool launcher + jadx-headless engine + Ghidra
set -euo pipefail

ROOT="$PWD"
TOOLS="${RUNNER_TEMP:-/tmp}/tools"
mkdir -p "$TOOLS/bin" "$TOOLS/engines" "$ROOT/reports" "$ROOT/build" "$ROOT/apk"

export PATH="$TOOLS/bin:$PATH"

echo "==> [1/4] REA ${REA_VERSION}"
mkdir -p "$TOOLS/rea"
if [ ! -x "$TOOLS/rea/node_modules/.bin/rea" ]; then
  ( cd "$TOOLS/rea" && npm init -y >/dev/null 2>&1 \
      && npm install --no-audit --no-fund "rea-agents@${REA_VERSION}" >/dev/null )
fi
ln -sf "$TOOLS/rea/node_modules/.bin/rea" "$TOOLS/bin/rea"
rea --version || true

echo "==> [2/4] apktool ${APKTOOL_VERSION} (REA apktool lane launcher)"
curl -fsSL --retry 3 -o "$TOOLS/apktool.jar" \
  "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar"
cat > "$TOOLS/bin/apktool" <<EOF
#!/usr/bin/env bash
exec java -jar "$TOOLS/apktool.jar" "\$@"
EOF
chmod +x "$TOOLS/bin/apktool"

echo "==> [3/4] jadx-headless-mcp ${JADX_MCP_VERSION} (REA JADX engine, digest-pinned)"
curl -fsSL --retry 3 -o "$TOOLS/jadx-headless-mcp.jar" \
  "https://github.com/1013503897/jadx-headless-mcp/releases/download/v${JADX_MCP_VERSION}/jadx-headless-mcp-${JADX_MCP_VERSION}-all.jar"
echo "${JADX_MCP_SHA256}  $TOOLS/jadx-headless-mcp.jar" | sha256sum -c -

echo "==> smali assembler ${SMALI_VERSION} (fallback repack lane)"
if [ ! -f "$ROOT/work/smali.jar" ]; then
  mkdir -p "$ROOT/work"
  curl -fsSL --retry 3 -o "$ROOT/work/smali.jar" \
    "https://github.com/google/smali/releases/download/v${SMALI_VERSION}/smali-${SMALI_VERSION}-fat.jar" \
    || echo "    smali prefetch skipped (fallback lane will try again if needed)"
fi

if [ "${RUN_GHIDRA:-true}" = "true" ]; then
  echo "==> [4/4] Ghidra ${GHIDRA_VERSION} (REA native lane)"
  curl -fsSL --retry 3 -o "$TOOLS/ghidra.zip" \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ZIP}"
  unzip -q "$TOOLS/ghidra.zip" -d "$TOOLS/engines"
  GHIDRA_DIR="$(find "$TOOLS/engines" -maxdepth 1 -type d -name 'ghidra_*_PUBLIC' | head -1)"
  if [ -z "$GHIDRA_DIR" ]; then echo "Ghidra extraction failed"; exit 1; fi
  echo "GHIDRA_INSTALL_DIR=$GHIDRA_DIR" >> "$GITHUB_ENV"
  chmod +x "$GHIDRA_DIR/support/analyzeHeadless" || true
else
  echo "==> [4/4] Ghidra lane skipped (run_ghidra=false)"
fi

{
  echo "$TOOLS/bin" >> "$GITHUB_PATH"
  echo "REA_APKTOOL_COMMAND=$TOOLS/bin/apktool" >> "$GITHUB_ENV"
  echo "REA_JADX_MCP_JAR=$TOOLS/jadx-headless-mcp.jar" >> "$GITHUB_ENV"
}

echo "==> readiness probes"
rea doctor --json > "$ROOT/reports/rea-doctor.json" 2>&1 || true
rea inspect-apktool-client --json > "$ROOT/reports/rea-apktool-client.json" 2>&1 || true
rea capabilities --json > "$ROOT/reports/rea-capabilities.json" 2>&1 || true
python3 - "$ROOT/reports/rea-doctor.json" <<'PY' || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as exc:
    print(f"doctor report unreadable: {exc}"); raise SystemExit(0)
for c in d.get("checks", []):
    print(f"  doctor: {c.get('name'):<18} ok={c.get('ok')} {c.get('classification','')}")
PY
echo "==> toolchain ready"
