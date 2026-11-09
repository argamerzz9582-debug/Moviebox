#!/usr/bin/env bash
# Thin wrapper: byte-parity of carried-over content (see scripts/parity.py).
set -euo pipefail
SIGNED="$(cat work/signed-apk-path.txt)"
python3 scripts/parity.py "apk/${APK_BASENAME}" "$SIGNED" reports/decoded-vs-rebuilt-vs-original.txt
