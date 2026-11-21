# MovieBox 4.0.04.1119.02 (build 50020134) "Mod_V2" — reverse engineering report

Static-only analysis. Nothing from this APK was installed or executed.
Analysis was produced by repo code: `rex apk analyze` (surface) and
`rex apk deep` (packing/shell triage), plus the one-off decompilation notes
recorded below (commands are reproduced so every claim can be re-derived).

| Field | Value |
| --- | --- |
| File | `MovieBox_v4.0.04.1119.02_(50020134)_Mod_V2.apk` |
| Size | 70,166,916 B (66.9 MiB) |
| SHA-256 | `6fdd667f53706b03c0c34b14296273be4fdc010447fcb636b5ce305d566aab45` |
| MD5 | `7fa30edc8957fd0bf7cd81a107242165` (matches Drive metadata) |
| Package | `com.community.oneroom` |
| Version | 4.0.04.1119.02 (code 50020134) |
| Signing | APK Signature Scheme v2 + v3; cert `CN=IN`, 2022-12-24 → 2123-03-10, SHA-256 `1da5e08fffa51acf0ae1cab33b0878b3…` |
| SDK | minSdk 23, targetSdk 35 |
| ZIP entries | 6,305 |
| Verdict | **modified/repackage** carrying an **iJiami-packed** original wrapped by an **open-source "hx" patch runtime** |

Machine-readable companions: `apk_report.{md,json}` (surface), `deep_report.{md,json}` (packing).

---

## 0. Getting the exact sample

The analysed file is the one on Drive (public read-only link, not search-indexed):

- **View**: <https://drive.google.com/file/d/1lLq-VDN8zCFByKjfLxsc9Qe_4HSnGUzG/view>
- **Direct download**: <https://drive.google.com/uc?export=download&id=1lLq-VDN8zCFByKjfLxsc9Qe_4HSnGUzG>
  (Google shows an "can't scan this file" interstitial for large APKs — choose *Download anyway*)

Verify before doing anything with it:

```bash
sha256sum "MovieBox_v4.0.04.1119.02_(50020134)_Mod_V2.apk"
# 6fdd667f53706b03c0c34b14296273be4fdc010447fcb636b5ce305d566aab45
md5sum    "MovieBox_v4.0.04.1119.02_(50020134)_Mod_V2.apk"
# 7fa30edc8957fd0bf7cd81a107242165
```

The sample itself is deliberately **not** committed to this repo (`.gitignore` covers
`google_drive/` and `*.apk`); this report and the two generated reports are the evidence
trail. Because the build is packed, re-signed (`CN=IN`) and carries a third-party playback
patch, treat installing it as a deliberate risk decision, not a normal app install.

---

## 1. Bottom line

This APK contains **two independent tampering layers**, and they are not from the same
author:

1. **A packer (iJiami / 爱加密).** `classes.dex` is a 61.4 MiB shell whose DEX tables stop
   at 26 KiB. The real application code is encrypted and only materialised in memory after
   `JNI_OnLoad`. Evidence is measured, not inferred (§2).
2. **A playback-patch runtime ("hx", `hxreborn/morphe-patches`).** A readable 0.15 MiB
   `classes2.dex` with 104 classes that hooks the app's networking layer to rewrite JSON
   (VIP/membership fields, resolutions), sign CloudFront play-info requests, and serve DASH
   segments from a local HTTP proxy. This is open-source patch code, shipped inside the APK
   as `assets/hx.classes|code|hook|factory|cer` and re-injected at boot.

So "Mod_V2" = **packed multi-layer build + community playback patch**. A static reader who
ignores the packing evidence would review the 104 `hx` classes and wrongly conclude they are
the whole program.

---

## 2. Evidence: the DEX is a shell

`map_list` is the authoritative inventory of a DEX. Parsed from `classes.dex`:

| Map item | Count | Offset |
| --- | ---: | ---: |
| header_item | 1 | 0 |
| string_id_item | 212 | 112 |
| type_id_item | 58 | 960 |
| proto_id_item | 54 | 1,192 |
| field_id_item | 19 | 1,840 |
| method_id_item | 114 | 1,992 |
| class_def_item | **4** | 2,904 |
| string_data_item | 212 | 3,032 |
| type_list | 31 | 6,452 |
| annotation_item | 5 | 6,722 |
| annotation_set_item | 6 | 6,768 |
| annotations_directory_item | 2 | 6,812 |
| debug_info_item | 1 | 6,900 |
| code_item | 32 | 6,908 |
| class_data_item | 4 | 26,504 |
| map_list | 1 | 26,756 |

**The entire DEX — classes, methods, code, strings — ends at 26,772 bytes. The file is
64,397,164 bytes.** 61.4 MiB (100.0 %) of the file is not described by any DEX table.

For comparison, `classes2.dex` (155,260 B) describes 99.9 % of itself with 104 classes and
1,840 strings — that is a normal DEX. The contrast is the whole argument:

| DEX | Size | Classes | Strings | Tables end | Undescribed |
| --- | ---: | ---: | ---: | ---: | ---: |
| `classes.dex` | 61.4 MiB | 4 | 212 | 26,772 B | 99.96 % |
| `classes2.dex` | 0.15 MiB | 104 | 1,840 | 155,068 B | 0.12 % |

The 4 surviving shell classes are `Luvj/ucxx/mb/BJAvhDvBU;`, `FNGpGGx`,
`MtvCsRB` and `QiQ9O3z` — obfuscated names, and `assets/hx.factory` points at
`uvj.ucxx.mb.QiQ9O3z`, confirming the factory class the loader uses.

---

## 3. Packer identification: iJiami (Confirmed)

| Evidence | Value |
| --- | --- |
| Loader assets | `assets/hx.classes` (lists `com.ijiami.residconfusion.ConfusionUtils`), `assets/hx.code`, `assets/hx.hook` (`hx.AppPatch`), `assets/hx.factory` (`uvj.ucxx.mb.QiQ9O3z`), `assets/hx.cer` |
| Native loader | `lib/arm64-v8a/libhxpatch.so` (15,312 B) — exports `JNI_OnLoad`, `Java_hx_Boot_writeCode`; strings: `hxreborn/ijiami`, `[anon:dalvik-DEX data]`, `packer image at %p`, `visit_dex_line`, `Unsupported packer build at +%#x` |
| Hidden natives | `assets/LYouKWv/{arm64-v8a,armeabi,x86,x86_64}/libbqhvot.so` + `libsjqyxms.so` — 8 ELF files stored **outside `lib/`** so `PackageManager` never extracts them; all UPX-packed and carry `ijiami SecLLVM compiler 1.7.4.20` and `ijiami.dat` |
| Encrypted overlay | `assets/IFVjuYd`, 8,351,192 B, entropy 7.994, header `indl01\0\0\x18\0\0\0` (numeric-tag container: `indl` + version `01` + LE length fields, not a known public format) |
| Ciphertext blobs | `assets/D9vOj2k` (0.31 MiB), `assets/KqF3de4hw` (0.19 MiB), `assets/Z9fPj0A9K` — entropy 8.00, random headers |
| Config | `assets/labresencscfg`, `assets/lable_art_xxx.lab`, `assets/dic` |

`libhxpatch.so` is the tell for the loader mechanism: `Java_hx_Boot_writeCode` takes a byte
array from Java (`hx.Boot`) and writes it into a DEX map in memory, i.e. a Java-side bridge
into the iJiami native unpacker rather than a conventional `attachBaseContext` stub.

---

## 4. The patch layer: hxreborn MovieBox patch (Confirmed)

`assets/hx.hook` = `hx.AppPatch`; `assets/hx.factory` = `uvj.ucxx.mb.QiQ9O3z`;
`classes2.dex` string pool contains `hxreborn/moviebox`. The class layout matches the
open-source project `hxreborn/morphe-patches` (`extensions/moviebox/src/hx/*`), whose
release notes describe the same `PlayInfoRewriter`, `CloudFrontPlayInfoClient`, `DashServer`
and `X-Client-Build` work. Upstream is public, so behaviour can be read rather than guessed;
the APK's copy is a compiled snapshot.

### 4.1 What the patch rewrites (verified from strings, constants and method names)

`classes2.dex` was decompiled to Java with jadx 1.1.0 and read as data. Method bodies are
obfuscated at the instruction level (`bogus element_width` — the dex is valid but the
instruction stream is deliberately misaligned, likely a further iJiami transform), so the
*field names, constants and call graph* are the reliable evidence, not full source recovery.

| Class | Constant / member | Meaning |
| --- | --- | --- |
| `hx.rewrite.MemberInfoRewriter` | `DAYS_LEFT = 9999`, `EXPIRY_DATE = "2099-12-31"` | rewrites membership JSON so the account looks like a ~27-year VIP |
| `hx.rewrite.PlayInfoRewriter` | `URL_FIELDS`, `highestResolution()`, `pointAtManifest()` | forces the highest advertised resolution and repoints stream URLs at a local manifest |
| `hx.rewrite.PromotionRewriter` | — | strips upsell/promotion blocks |
| `hx.rewrite.ResourceListRewriter`, `JsonObjectRewrite`, `JsonTree` | `&isVip=true`, `&page=1&perPage=8…resolution=` | injects VIP query parameters into resource-list requests |
| `hx.gateway.CloudFrontPlayInfoClient` | `CloudFront-Policy=`, `SigningKey`, `x-tr-signature`, `fromCloudFront` | mints CloudFront signed-cookie play-info requests |
| `hx.gateway.BuildTagInterceptor` | `X-Client-Build`, `X-Client-Info` | fakes the client build tag the API now requires |
| `hx.rewrite.DashInterceptor` | `http://127.0.0.1:47291/dash/`, `/index.mpd` | reroutes playback through a loopback HTTP server |
| `hx.loopback.DashServer`, `hx.dash.DashFile` | `Content-Range: bytes`, `Accept-Ranges: bytes` | local proxy that re-fetches DASH ranges from the CDN and serves them to the player |
| `hx.source.MovieBoxSource` | `NoSignedResourceException`, `/subject-api/play-info/`, `/subject-api/resource/v2` | fallback direct-file playback when signed resources are unavailable |
| `hx.platform.HotPatches`, `hx.platform.InstalledApp` | `PATCH_DIRECTORY`, `Disable "Optimize for device architecture" & re-patch` | updates its own patch code at runtime |
| `hx.AppPatch.Installer` | `MANAGER_CLASS = "fh.c"`, `SHARED_HEADERS_CLASS = "eh.b"` | targets classes inside the *packed* original — proof the patch expects the packed app's real class names |

That last row is the cross-check that binds both layers: the patch is written against
`fh.c` / `eh.b`, class names that do not exist in either readable DEX. It can only work
against the decrypted payload.

### 4.2 Network surface (from string clusters)

Hosts: `api3.aoneroom.com`, `api4.aoneroom.com`, `api4sg.aoneroom.com`,
`api5.aoneroom.com`, `api6.aoneroom.com`, `sacdn.hakunaymatata.com` (CDN).
Endpoints include `wefeed-mobile-bff/subject-api/play-info/v2`,
`wefeed-mobile-bff/subject-api/resource`, `wefeed-mobile-bff/vip/member/detail`,
`wefeed-mobile-bff/user-api/profile`, `wefeed-tv-bff/subject/play-info/v2`.
Custom headers: `X-Client-Build`, `X-Client-Info`, `x-client-token`, `x-tr-signature`,
`x-forwarded-for`. Cleartext traffic is enabled (`usesCleartextTraffic=true`) — needed for
the `http://127.0.0.1:47291` loopback hop.

Note: none of this traffic is authored by the patch — it reuses the app's own API. What the
patch changes is the *content* of the responses the app acts on, and the *transport* of the
media (CDN → localhost proxy → player).

---

## 5. Risk assessment of the tampering

| Observation | Assessment |
| --- | --- |
| Two unrelated tampering layers (commercial packer + community patch) | The packer is the vendor's own protection; the patch is third-party. "Mod_V2" describes only the patch. |
| Certificate `CN=IN`, 100-year validity, v2+v3 only | Not a public CA identity; a re-signing key, not the original publisher's. Consistent with a repackage. Do **not** treat the file as an authentic MovieBox release. |
| `REQUEST_INSTALL_PACKAGES`, `SYSTEM_ALERT_WINDOW` among 17 flagged permissions | Self-update + overlay capability. Combined with `HotPatches` (runtime patch downloads), the installed app can change its own behaviour after install. |
| Hidden natives outside `lib/`, UPX-packed, iJiami SecLLVM | Anti-analysis. Cannot be verified as benign by reading them; UPX halves are not reviewed here. |
| Encrypted overlay `IFVjuYd` (8.35 MB, unknown `indl` container) | Opaque payload. Not identified as any known asset class. |
| `assets/*.pem`, `license.crt` XOR-obfuscated | Deliberate hiding of key material from static readers. |

What is *not* established: no evidence of exfiltration beyond the app's own API hosts, no
third-party C2 host in the readable layer, and nothing was executed to observe runtime
behaviour. The honest statement is "modded and unpackable only dynamically", not "malware".

---

## 6. What was attempted and did not work

Recorded so the next pass does not repeat it.

1. **Hand-rolled DEX class walk → `IndexError`.** Manual `string_id` → `string_data_item`
   parsing assumed the uleb128 prefix was a *byte* length; it is a *UTF-16 unit* count, and
   offsets can point past missing tables in a stripped DEX. Replaced by `map_list` parsing
   plus androguard/jadx. Fixed in `rex/adapters/apk_deep.py` with tests.
2. **jadx full method recovery → 597 errors** (`bogus element_width`). The DEX is structurally
   valid (androguard parses its header, map, strings and classes fine) but the instruction
   streams are deliberately misaligned. Class/member/constant recovery works; control-flow
   decompilation does not. A DEX re-alignment pass or a memory dump after unpacking would be
   needed, which requires either writing a custom deobfuscator or executing the sample.
3. **Unpacking → not performed.** The decryption lives in `libhxpatch.so` +
   `assets/LYouKWv/*/libbqhvot.so` behind JNI, with a certificate check
   ("Playback patch cannot read its certificate") and an architecture gate
   ("This device's architecture is not supported by the patch"). Static unpacking of iJiami
   is not a solved generic problem; doing it honestly needs a sandboxed device and
   `frida`-based DEX dumping at `DexFile.loadDex` / `[anon:dalvik-DEX data]`. That crosses from
   static analysis into executing the sample, so it was left out deliberately.
4. **Drive ingest via shell → blocked.** `drive.google.com` is unreachable from this sandbox
   (`curl` exit 000). Bytes were fetched through the `google_drive` connector instead; SHA-256
   matches Drive metadata exactly (`6fdd667f…aab45`).

---

## 7. Reproducing

```bash
# surface report (manifest, signing, permissions, components, SDKs, API strings)
python3 -m rex.cli apk analyze "google_drive/MovieBox_v4.0.04.1119.02_(50020134)_Mod_V2.apk" \
    --out reverse-engineering/moviebox-v4.0.04

# packing/deep triage (DEX table accounting, packer fingerprints, blob classes)
python3 -m rex.cli apk deep "google_drive/MovieBox_v4.0.04.1119.02_(50020134)_Mod_V2.apk" \
    --out reverse-engineering/moviebox-v4.0.04

# decompile the readable patch layer only (never the 61 MiB shell)
~/.rex/venv/bin/python - <<'EOF'
import zipfile
open("/tmp/classes2.dex","wb").write(zipfile.ZipFile(
  "google_drive/MovieBox_v4.0.04.1119.02_(50020134)_Mod_V2.apk").read("classes2.dex"))
EOF
~/.local/bin/jadx -d /tmp/hx-out /tmp/classes2.dex
```

`python3 -m rex.cli apk deep` is pure `struct` + `zipfile`: no androguard, no jadx, no
network, ~0.9 s on this 67 MiB file. Both `apk_report.*` and `deep_report.*` are
generated artifacts, committed on purpose as the evidence trail for this sample; the APK
itself is git-ignored (see `.gitignore`).

---

## 8. Limitations

- **Class coverage is a lower bound.** Only 108 classes are readable on disk (4 shell + 104
  patch). The decrypted application almost certainly ships thousands; none are analysed here.
- **Patch source is inferred upstream, not recovered.** The `hx` layer's *identity* is
  Confirmed (markers/strings/class layout). Its *exact* behaviour is reconstructed from
  constants and names, because method bodies do not decompile. Treat §4.1 semantics as
  Strongly supported, not byte-exact.
- **Encryption is inferred from entropy + naming.** No cipher, key or plaintext was recovered.
- **Hidden natives are unreviewed.** UPX-packed, iJiami-hardened; de-UPXing and r2 review of
  `libbqhvot.so` is the clear next step and was not done.
- **No differential analysis.** The clean 4.0.02.0831.03 build on Drive
  (`1yTSTuPz5VUeTw4Gt3FSj1h-ryCqQyO_J`, 64,138,531 B) was not fetched; a byte-level diff of
  the two would isolate exactly what the mod added.
- **Static only.** No runtime observation, so no claim is made about what the app does once
  the decrypted payload is loaded.
