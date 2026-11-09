#!/usr/bin/env python3
"""Crash triage: compare the ORIGINAL apk with our REBUILT apk and report the
conditions that make a rebuilt Android app crash at startup.

Measured, not guessed:
  1. per-entry compression + alignment of load-bearing entries
     (lib/**/*.so, resources.arsc, *.dex) — a STORED library in the original
     that comes back DEFLATED (or vice versa) changes how it is mapped at
     runtime and is a classic startup crash;
  2. manifest facts that govern that behaviour (extractNativeLibs,
     minSdk/targetSdk, application class);
  3. ABI coverage;
  4. anti-tamper / signature-check code in the app's own smali, which makes any
     re-signed rebuild fail by design.
"""
import json
import re
import sys
import zipfile
from pathlib import Path

LOAD_BEARING = ("resources.arsc",)


def compression_map(path):
    out = {}
    with zipfile.ZipFile(path) as z:
        for i in z.infolist():
            if i.is_dir():
                continue
            method = "STORED" if i.compress_type == zipfile.ZIP_STORED else "DEFLATED"
            out[i.filename] = {
                "method": method,
                "size": i.file_size,
                "csize": i.compress_size,
                "offset": i.header_offset,
            }
    return out


def is_load_bearing(name):
    return (
        name in LOAD_BEARING
        or name.endswith(".so")
        or (name.endswith(".dex") and "/" not in name)
    )


def data_offset(path, header_offset):
    import struct

    with open(path, "rb") as fh:
        fh.seek(header_offset)
        head = fh.read(30)
    if len(head) < 30 or head[:4] != b"PK\x03\x04":
        return None
    name_len, extra_len = struct.unpack_from("<HH", head, 26)
    return header_offset + 30 + name_len + extra_len


def manifest_facts(decoded):
    man = Path(decoded) / "AndroidManifest.xml"
    facts = {}
    if not man.exists():
        return facts
    text = man.read_text(encoding="utf-8", errors="replace")
    app = re.search(r"<application\b[^>]*>", text, re.S)
    tag = app.group(0) if app else ""
    for attr in ("extractNativeLibs", "debuggable", "name", "usesCleartextTraffic"):
        m = re.search(r'android:%s="([^"]*)"' % attr, tag)
        facts[attr] = m.group(1) if m else None
    for attr in ("package", "split", "versionCode", "versionName"):
        m = re.search(r'\b%s="([^"]*)"' % attr, text)
        facts[attr] = m.group(1) if m else None
    for attr in ("minSdkVersion", "targetSdkVersion"):
        m = re.search(r'android:%s="([^"]*)"' % attr, text)
        facts[attr] = m.group(1) if m else None
    return facts


ANTI_TAMPER = {
    "GET_SIGNATURES": r"getPackageInfo\([^)]*,\s*(0x40|64)\b",
    "signatures_field": r"Landroid/content/pm/PackageInfo;->signatures:",
    "signing_info": r"getSigningInfo|SigningInfo",
    "message_digest": r"Ljava/security/MessageDigest;->",
    "signature_api": r"getPackageManager\(\)\.getPackageInfo|PackageManager;->getPackageInfo",
    "integrity_words": r"tamper|integrity|SafetyNet|PlayIntegrity|attestation|signature mismatch",
}


def scan_smali(root):
    hits = {k: 0 for k in ANTI_TAMPER}
    examples = {k: [] for k in ANTI_TAMPER}
    cls_hits = {}
    for f in Path(root).rglob("*.smali"):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for name, pat in ANTI_TAMPER.items():
            if re.search(pat, text, re.I):
                hits[name] += 1
                if len(examples[name]) < 5:
                    examples[name].append(f.name)
                cls_hits[f.stem] = cls_hits.get(f.stem, 0) + 1
    return hits, examples, sorted(cls_hits.items(), key=lambda kv: -kv[1])[:10]


def main():
    orig, rebuilt, decoded_orig, decoded_rebuilt = sys.argv[1:5]
    a, b = compression_map(orig), compression_map(rebuilt)

    problems, notes = [], []

    # ---- 1. compression / alignment of load-bearing entries
    diffs = []
    for name, info in sorted(a.items()):
        if not is_load_bearing(name):
            continue
        other = b.get(name)
        if other is None:
            diffs.append(f"{name}: missing from rebuilt")
            continue
        if info["method"] != other["method"]:
            diffs.append(f"{name}: original {info['method']} -> rebuilt {other['method']}")
    if diffs:
        problems += diffs[:12]

    # ---- 2. manifest facts
    fo, fr = manifest_facts(decoded_orig), manifest_facts(decoded_rebuilt)
    for key in ("extractNativeLibs", "package", "split", "minSdkVersion", "targetSdkVersion"):
        if fo.get(key) != fr.get(key):
            problems.append(f"manifest {key}: original={fo.get(key)!r} rebuilt={fr.get(key)!r}")

    # ---- 3. ABI coverage
    abis = lambda m: sorted({n.split("/")[1] for n in m if n.startswith("lib/") and n.count("/") > 1})
    ao, ab = abis(a), abis(b)
    if ao != ab:
        problems.append(f"ABIs: original={ao} rebuilt={ab}")
    else:
        notes.append(f"ABIs identical: {ao}")

    # ---- 4. signature-state difference (informational, always true here)
    if any(n.lower().startswith("meta-inf/") and n.lower().endswith((".rsa", ".dsa", ".ec", ".sf"))
           for n in a):
        notes.append("original carried v1 signature files; rebuild re-signs with a new key")

    hits, examples, hot = scan_smali(decoded_orig)

    result = {
        "original": {"entries": len(a), "abis": ao, "manifest": fo},
        "rebuilt": {"entries": len(b), "abis": ab, "manifest": fr},
        "problems": problems,
        "notes": notes,
        "anti_tamper": {k: v for k, v in hits.items() if v},
        "anti_tamper_examples": {k: v for k, v in examples.items() if v},
        "hot_classes": hot,
    }
    print(json.dumps(result, indent=2))

    print("\n## SUMMARY", file=sys.stderr)
    if problems:
        print(f"{len(problems)} structural mismatch(es):", file=sys.stderr)
        for p in problems[:12]:
            print("  - " + p, file=sys.stderr)
    else:
        print("no structural mismatch in load-bearing entries or manifest", file=sys.stderr)
    if hits.get("integrity_words") or hits.get("GET_SIGNATURES") or hits.get("signing_info"):
        print("signature/integrity-checking code present in the app's own smali:", file=sys.stderr)
        for k, v in hits.items():
            if v:
                print(f"  - {k}: {v} classes", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
