#!/usr/bin/env python3
"""Byte-parity check for content carried through the rebuild untouched.

Native libraries, assets, kotlin metadata and META-INF/services must be
identical in the original and the rebuilt APK. This turns the "nothing else was
changed" claim into something a reviewer can verify.
"""
import hashlib
import sys
import zipfile
from pathlib import Path

PREFIXES = ("assets/", "lib/", "kotlin/", "META-INF/services/")
MAX_LIST = 20


def digest_map(path, prefixes):
    out = {}
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if info.is_dir() or not info.filename.startswith(prefixes):
                continue
            h = hashlib.sha256()
            with z.open(info) as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            out[info.filename] = (h.hexdigest(), info.file_size)
    return out


def main():
    src, new, report = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    a, b = digest_map(src, PREFIXES), digest_map(new, PREFIXES)

    identical = sorted(k for k in a if k in b and a[k][0] == b[k][0])
    only_orig = sorted(k for k in a if k not in b)
    only_new = sorted(k for k in b if k not in a)
    changed = sorted(k for k in a if k in b and a[k][0] != b[k][0])

    lines = [
        "# Untouched-content parity: original vs rebuilt",
        "",
        "Scanned prefixes: " + ", ".join(f"`{p}`" for p in PREFIXES),
        "",
        "| Result | Count |",
        "|---|---|",
        f"| byte-identical entries | {len(identical)} |",
        f"| only in original | {len(only_orig)} |",
        f"| only in rebuilt | {len(only_new)} |",
        f"| content differs | {len(changed)} |",
        "",
    ]
    for title, items in (
        ("Missing from the rebuild", only_orig),
        ("Added by the rebuild", only_new),
        ("Content differs", changed),
    ):
        if items:
            lines += [f"## {title} (first {MAX_LIST})", ""]
            lines += [f"- `{i}`" for i in items[:MAX_LIST]]
            if len(items) > MAX_LIST:
                lines.append(f"- … and {len(items) - MAX_LIST} more")
            lines.append("")

    if identical:
        lines += ["## Sample of verified-identical entries", ""]
        lines += [f"- `{i}` ({a[i][1]} bytes)" for i in identical[:10]]
        lines.append("")

    report.write_text("\n".join(lines), encoding="utf-8")
    print(
        f"parity: identical={len(identical)} only_orig={len(only_orig)} "
        f"only_new={len(only_new)} changed={len(changed)}"
    )
    if only_orig or changed:
        print("PARITY FAILED: carried-over content changed or went missing", file=sys.stderr)
        return 1
    print("PARITY OK: every carried-over file is byte-identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
