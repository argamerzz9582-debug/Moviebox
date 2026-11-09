#!/usr/bin/env python3
"""Detect app-hardening / licence / anti-tamper machinery directly in an APK.

Works on the ZIP and the raw DEX bytes: no Java, no decompiler, no device. It is
deliberately crude — it answers one question, "does this app verify its own
signature or run under a protector?", because that decides whether ANY re-signed
rebuild can run without crashing.

Exit code 0 always (this is a report, not a gate); the JSON says what was found.
"""
import json
import re
import sys
import zipfile

# Known packers / protectors, matched against entry names.
PACKERS = {
    "Google PairIP / Play Integrity": [r"libpairipcore\.so", r"com/pairip/"],
    "Bangcle": [r"libjiagu", r"libsecexe", r"libsecmain", r"libSecShell"],
    "Naver DexHelper": [r"libDexHelper"],
    "Tencent": [r"libmobisec", r"libshell", r"libexec\.so", r"libtosprotection"],
    "Qihoo 360": [r"libjiagu_art", r"libprotectClass"],
    "Alibaba": [r"libmobisec", r"aliprotect"],
    "DexGuard": [r"dexguard", r"libdexguard"],
    "Promon SHIELD": [r"libshield"],
    "Legu / 梆梆": [r"libbaiduprotect"],
}

# Tell-tale strings inside DEX/native payloads. DEX stores plain UTF-8 strings,
# so a byte search is a valid (if coarse) detector.
MARKERS = {
    "signature_verification": [
        rb"getPackageInfo", rb"signatures", rb"getSigningInfo", rb"SigningInfo",
        rb"GET_SIGNATURES", rb"GET_SIGNING_CERTIFICATES",
    ],
    "integrity_api": [rb"PlayIntegrity", rb"SafetyNet", rb"attestation", rb"IntegrityToken"],
    "tamper_words": [rb"tamper", rb"integrity check", rb"signature mismatch",
                     rb"signature check", rb"repackag", rb"modif(?:ied|ication) detected"],
    "hook_detection": [rb"frida", rb"xposed", rb"substrate", rb"LSPosed", rb"riru"],
    "root_detection": [rb"/system/xbin/su", rb"superuser", rb"magisk", rb"busybox"],
    "pairip_runtime": [rb"VMRunner", rb"LicenseClient", rb"pairip"],
}


def scan(apk):
    findings = {"packers": {}, "markers": {}, "samples": {}, "dex_files": 0, "libs": []}
    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
        lower = [n.lower() for n in names]

        for product, pats in PACKERS.items():
            hits = [n for n, ln in zip(names, lower) if any(re.search(p.lower(), ln) for p in pats)]
            if hits:
                findings["packers"][product] = hits[:6]

        findings["libs"] = sorted({n for n in names if n.endswith(".so")})[:40]

        dexes = [n for n in names if re.match(r"classes\d*\.dex$", n)]
        findings["dex_files"] = len(dexes)
        blobs = []
        for name in dexes:
            with z.open(name) as fh:
                blobs.append((name, fh.read()))

        # A few native libs are worth scanning too (strings survive in .so).
        for name in findings["libs"][:6]:
            try:
                with z.open(name) as fh:
                    blobs.append((name, fh.read(6 << 20)))
            except Exception:
                pass

    for label, pats in MARKERS.items():
        total, where = 0, []
        for pattern in pats:
            for name, blob in blobs:
                n = len(re.findall(pattern, blob, re.I))
                if n:
                    total += n
                    if name not in where:
                        where.append(name)
                    if label not in findings["samples"]:
                        findings["samples"][label] = []
                    if len(findings["samples"][label]) < 5:
                        findings["samples"][label].append(pattern.decode("utf-8", "replace"))
        if total:
            findings["markers"][label] = {"matches": total, "in": where[:5]}
    return findings


def verdict(f):
    protected = bool(f["packers"])
    sig = "signature_verification" in f["markers"] or "pairip_runtime" in f["markers"]
    hard = protected or ("integrity_api" in f["markers"]) or sig
    if protected:
        return ("blocked-packers",
                "The APK runs under a known protector. Such protectors verify their own "
                "signature/checksum; ANY re-signed rebuild crashes or refuses to start. "
                "No rebuild of this APK can work.")
    if hard:
        return ("blocked-signature-checks",
                "The app contains signature/integrity verification. A re-signed rebuild is "
                "detected and exits/crashes by design.")
    return ("rebuildable",
            "No protector or signature verification was detected, so a re-signed rebuild "
            "should run. Any crash then comes from the repack itself (resources/dex), "
            "which the high-fidelity repack avoids.")


def main():
    apk = sys.argv[1]
    f = scan(apk)
    state, why = verdict(f)
    f["verdict"] = {"state": state, "reason": why}
    print(json.dumps(f, indent=2))
    print(f"\nVERDICT: {state}\n  {why}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
