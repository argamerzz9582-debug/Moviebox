# MovieBox — reverse engineering & rebuild pipeline

Reverse engineers the MovieBox APK that lives in Google Drive, rebuilds it from
its own decoded sources, signs it, verifies the result, and publishes a
permanently downloadable APK as a GitHub Release asset.

Everything is static: **the app is never executed and no device is involved.**

## Tools

| Tool | Role in this pipeline | Version (pinned) |
|---|---|---|
| [REA](https://github.com/morluto/rea) (`rea-agents`) | Orchestrator: Android resource decode (apktool provider), package/class/signature inspection, artifact extraction, native export inspection | 6.8.0 |
| [apktool](https://github.com/iBotPeaches/Apktool) | Decodes `resources.arsc`, binary `AndroidManifest.xml` and smali; repacks the modified tree | 3.0.3 |
| [jadx-headless-mcp](https://github.com/1013503897/jadx-headless-mcp) | JADX engine REA drives for the Java/Kotlin layer (digest-pinned: `6e5eacf5…3ff75`) | 0.7.1 |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Headless auto-analysis of the native `.so` libraries REA extracts | 12.1.4 |
| Android build-tools | `zipalign`, `aapt2`, `apksigner` | 35.0.0 |

## Pipeline (`.github/workflows/rebuild-moviebox.yml`)

1. **Toolchain** — JDK 21, Node 24, Android SDK, REA + apktool + JADX + Ghidra. Readiness is
   probed (`rea doctor`, `rea inspect-apktool-client`) and the probe output is retained.
2. **Fetch** — the APK is pulled straight from Google Drive and must pass a ZIP
   integrity test and an optional pinned SHA-256 before any tool touches it.
3. **Baseline RE** (`scripts/baseline-re.sh`) — `decode-android-resources` (apktool),
   `inspect-android-package` (JADX), `inspect-apk-signature`,
   `identify-flutter-build`, `search-android-classes`, plus a full `apktool d` of the
   APK that becomes the rebuild source tree.
4. **Native lane** (`scripts/native-re.sh`) — `extract-artifact` to get the `.so`
   files out, `inspect-native-exports` for ELF facts, then Ghidra headless with a
   post-script (`scripts/ghidra/FunctionInventory.java`) that writes a function
   inventory.
5. **Rebuild** (`scripts/rebuild-apk.sh`) — applies the single reviewed manifest
   change (`android:extractNativeLibs="true"`), repacks with `apktool b --use-aapt2`
   (falls back to a smali + `aapt2 link` lane), `zipalign -p 4`, then signs v1+v2+v3.
6. **Verify** (`scripts/verify.sh`) — `apksigner verify --print-certs`,
   `zipalign -c 4`, `unzip -t`, `aapt2 dump badging`, dex/lib completeness. A failure
   here fails the run; nothing bad is published.
7. **Parity** (`scripts/parity.py`) — every carried-over `assets/`, `lib/`, `kotlin/`
   and `META-INF/services/` entry must be byte-identical to the original APK.
8. **Report + release** (`scripts/report.py`, `scripts/publish-release.sh`) — one
   markdown report from the retained evidence, then a GitHub Release with the signed
   APK, its SHA-256, the signing certificate and the report.

## Running it

```bash
gh workflow run rebuild-moviebox.yml -R argamerzz9582-debug/Moviebox \
  -f run_ghidra=true -f publish_release=true
gh run watch -R argamerzz9582-debug/Moviebox
```

Inputs: `apk_url` (override the Drive file), `apk_sha256` (pin provenance),
`run_ghidra` (skip the slow native lane), `publish_release`.

## Signing

The APK is signed with the key in the `RELEASE_KEYSTORE_B64` /
`RELEASE_KEYSTORE_PASS` / `RELEASE_KEY_ALIAS` repository secrets (PKCS#12).
If those secrets are absent the workflow generates a throwaway key and says so in
the run summary — the APK still installs, but a later build signed with a
different key cannot update over it.

The certificate is not the vendor's, so Android treats this as a different
application identity: uninstall the store/stock copy first, or expect
`INSTALL_FAILED_UPDATE_INCOMPATIBLE`.

## Download

Releases: <https://github.com/argamerzz9582-debug/Moviebox/releases>

Each release carries:

- `MovieBox_v4.0.02.0831.03_rebuilt_signed.apk` — installable, signed
- `rebuilt-apk.sha256` — checksum
- `release-cert.pem` — the signer certificate
- `report.md` — the analysis + build report

## Scope and limits

This repository rebuilds an APK you supply, for interoperability and analysis on
your own copy. It does not circumvent DRM, does not strip licence checks, and
makes no claim to the vendor's signature. Static engines can return partial results
on obfuscated or packed code; the report states what was and was not observed.
