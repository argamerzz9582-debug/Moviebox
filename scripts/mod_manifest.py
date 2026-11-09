#!/usr/bin/env python3
"""Apply the reviewed modifications to the apktool-decoded tree.

Modification (and only this one):
  AndroidManifest.xml -> <application android:extractNativeLibs="true">
Rationale: the original ships uncompressed/legacy native-lib extraction off; a
repacked APK that is zipaligned at 4 bytes keeps parity with the stock package
and installs identically on every supported ABI. Recorded in the report.
"""
import re
import sys
from pathlib import Path

manifest = Path(sys.argv[1])
text = manifest.read_text(encoding="utf-8")
original = text

m = re.search(r"<application\b[^>]*>", text, re.S)
if not m:
    print("FATAL: no <application> element found in decoded manifest", file=sys.stderr)
    sys.exit(2)

tag = m.group(0)
changes = []

if 'android:extractNativeLibs' in tag:
    new_tag = re.sub(r'android:extractNativeLibs="[^"]*"',
                     'android:extractNativeLibs="true"', tag)
    if new_tag != tag:
        changes.append("extractNativeLibs: set to true")
else:
    new_tag = tag[:-1].rstrip() + ' android:extractNativeLibs="true">'
    changes.append("extractNativeLibs: added (true)")

text = text[:m.start()] + new_tag + text[m.end():]
manifest.write_text(text, encoding="utf-8")

Path("reports/manifest-modifications.txt").write_text(
    "# Manifest modifications\n\n"
    + "\n".join(f"- {c}" for c in changes)
    + "\n\n## <application> before\n\n```xml\n" + tag + "\n```\n"
    + "\n## <application> after\n\n```xml\n" + new_tag + "\n```\n",
    encoding="utf-8",
)

print("manifest modified: " + ("; ".join(changes) if changes else "no-op (already compliant)"))
