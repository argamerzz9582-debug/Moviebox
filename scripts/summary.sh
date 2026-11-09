#!/usr/bin/env bash
# Writes the job summary that shows up on the Actions run page.
set -uo pipefail

{
  echo "## MovieBox rebuild"
  echo
  if [ -f build/signing-identity.txt ]; then
    echo "**Signing identity**"
    echo '```'
    cat build/signing-identity.txt
    echo '```'
    echo
  fi
  if [ -f reports/manifest-modifications.txt ]; then
    echo "**Modifications**"
    sed -n 's/^- /- /p' reports/manifest-modifications.txt
    echo
  fi
  if [ -f reports/verification.log ]; then
    echo "**Verification**"
    echo '```'
    cat reports/verification.log
    echo '```'
    echo
  fi
  if [ -f reports/rebuilt-apk.sha256 ]; then
    echo "**Artifact**"
    echo '```'
    cat reports/rebuilt-apk.sha256
    echo '```'
    echo
  fi
  echo "**Release**"
  if [ -n "${GITHUB_REPOSITORY:-}" ]; then
    echo "https://github.com/${GITHUB_REPOSITORY}/releases/tag/moviebox-v4.0.02.0831.03-rebuilt"
  fi
} >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"
