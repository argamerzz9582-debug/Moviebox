#!/usr/bin/env bash
# Failure diagnostics.
#
# Workflow logs and artifacts are served from blob storage that some
# environments cannot reach, so the important evidence is also emitted as
# check-run annotations: they are readable through the REST API and appear
# inline on the run page.
set -uo pipefail

R=reports
MAX_LINES=12
MAX_COL=640

ann() { # ann <title> <text>
  local title="$1" text="$2" line n=0
  while IFS= read -r line; do
    n=$((n + 1))
    [ "$n" -gt "$MAX_LINES" ] && break
    [ -z "${line// /}" ] && continue
    printf '::error title=%s::%s\n' "$title" "${line:0:$MAX_COL}"
  done <<< "$text"
}

section() { # section <title> <file>
  local title="$1" file="$2"
  [ -s "$file" ] || return 0
  ann "$title" "$(tail -n 40 "$file")"
}

echo "## failure diagnostics"
{
  echo "### environment"
  uname -srm
  java -version 2>&1 | head -1
  node -v
  echo "SIGNER_MODE=${SIGNER_MODE:-unset}"
  echo "RUN_GHIDRA=${RUN_GHIDRA:-unset}"
  echo "GHIDRA_INSTALL_DIR=${GHIDRA_INSTALL_DIR:-unset}"
  echo "PATH tools: $(echo "$PATH" | tr ':' '\n' | grep -c . ) entries"
  for t in apktool zipalign apksigner aapt2 java rea; do
    printf '  %-10s %s\n' "$t" "$(command -v "$t" 2>/dev/null || echo MISSING)"
  done
  df -h / | tail -1
} 2>&1 | tee "$R/diagnostics.txt"

# Bounded, high-signal evidence only: the failure point first.
section "rebuild console" "$R/rebuild-console.log"
section "apktool build" "$R/apktool-build.log"
section "smali build" "$R/smali-build.log"
section "apksigner" "$R/apksigner.log"
section "uber-apk-signer" "$R/uber-apk-signer.log"
section "verification" "$R/verification.log"
section "REA jadx" "$R/android-package.stderr"

echo
echo "### file inventory"
ls -la build "$R" 2>/dev/null | head -60
echo
echo "### last 40 lines of apktool build"
tail -40 "$R/apktool-build.log" 2>/dev/null || echo "(no build log)"
