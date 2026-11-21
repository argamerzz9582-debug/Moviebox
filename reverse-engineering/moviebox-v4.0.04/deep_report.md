# Deep APK triage

- **File**: `google_drive/MovieBox_v4.0.04.1119.02_(50020134)_Mod_V2.apk`
- **SHA-256**: `6fdd667f53706b03c0c34b14296273be4fdc010447fcb636b5ce305d566aab45`
- **Size**: 70,166,916 B (66.9 MiB)
- **ZIP entries**: 6,305

## 1. Findings

| Finding | Confidence | Evidence | Tool |
| --- | --- | --- | --- |
| `dex-shell-detected` | Confirmed | classes.dex: 61.4 MiB file, only 4 class definition(s) and 212 string(s); DEX tables cover 26 KiB (100.0% of the file unddescribed) | `apk_deep.parse_dex_index + map_list accounting` |
| `packer-identified` | Confirmed | iJiami (爱加密) (files: assets/hx.classes, assets/hx.code, assets/hx.cer, assets/labresencscfg) | `apk_deep.detect_packers` |
| `patch-framework` | Confirmed | hxreborn/morphe MovieBox patch markers: hxreborn/moviebox, hx/AppPatch, hx/source/MovieBoxSource | `apk_deep.detect_patch_frameworks` |
| `native-code-outside-lib` | Confirmed | 8 ELF payload(s) in assets/: assets/LYouKWv/x86_64/libbqhvot.so, assets/LYouKWv/arm64-v8a/libbqhvot.so, assets/LYouKWv/x86/libbqhvot.so, assets/LYouKWv/armeabi/libbqhvot.so, assets/LYouKWv/x86_64/libsjqyxms.so, assets/LYouKWv/arm64-v8a/libsjqyxms.so | `apk_deep.classify_blob` |
| `encrypted-overlays` | Strongly supported | 4 high-entropy asset(s), 8.6 MiB total: assets/IFVjuYd (entropy 7.99, header 'indl01..'), assets/D9vOj2k (entropy 8.00, header 'W.]...N.'), assets/KqF3de4hw (entropy 8.00, header 'MO..cx..'), assets/Z9fPj0A9K (entropy 8.00, header '.R...]..') | `apk_deep.classify_blob` |

## 2. DEX table accounting

| DEX | Size | Classes | Strings | Tables end | Undescribed | Share |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `classes.dex` | 64,397,164 B | 4 | 212 | 26,772 B | 64,370,392 B | 100.0% |
| `classes2.dex` | 155,260 B | 104 | 1840 | 155,068 B | 192 B | 0.1% |

<details><summary>classes.dex map_list</summary>

| Type | Count | Offset |
| --- | ---: | ---: |
| header_item | 1 | 0 |
| string_id_item | 212 | 112 |
| type_id_item | 58 | 960 |
| proto_id_item | 54 | 1,192 |
| field_id_item | 19 | 1,840 |
| method_id_item | 114 | 1,992 |
| class_def_item | 4 | 2,904 |
| string_data_item | 212 | 3,032 |
| type_list | 31 | 6,452 |
| annotation_item | 5 | 6,722 |
| annotation_set_item | 6 | 6,768 |
| annotations_directory_item | 2 | 6,812 |
| debug_info_item | 1 | 6,900 |
| code_item | 32 | 6,908 |
| class_data_item | 4 | 26,504 |
| map_list | 1 | 26,756 |

</details>

<details><summary>classes2.dex map_list</summary>

| Type | Count | Offset |
| --- | ---: | ---: |
| header_item | 1 | 0 |
| string_id_item | 1,840 | 112 |
| type_id_item | 278 | 7,472 |
| proto_id_item | 399 | 8,584 |
| field_id_item | 435 | 13,372 |
| method_id_item | 899 | 16,852 |
| class_def_item | 104 | 24,044 |
| string_data_item | 1,840 | 27,372 |
| type_list | 234 | 58,668 |
| encoded_array_item | 46 | 61,030 |
| annotation_item | 141 | 61,557 |
| annotation_set_item | 125 | 63,748 |
| annotations_directory_item | 89 | 64,912 |
| debug_info_item | 460 | 68,088 |
| code_item | 523 | 73,692 |
| class_data_item | 104 | 150,564 |
| map_list | 1 | 155,052 |

</details>

## 3. Packer / patch fingerprints

### iJiami (爱加密) - Confirmed
- File markers: `assets/hx.classes`, `assets/hx.code`, `assets/hx.cer`, `assets/labresencscfg`
- Text markers: `hxreborn/ijiami`

- **Patch runtime**: hxreborn/morphe MovieBox patch (Confirmed) - `hxreborn/moviebox`, `hx/AppPatch`, `hx/source/MovieBoxSource`

## 4. Classes by package

- `hx/dash` - 20
- `hx/gateway` - 17
- `hx/rewrite` - 15
- `hx/source` - 11
- `hx/loopback` - 9
- `hx/mp4` - 7
- `hx/util` - 5
- `uvj/ucxx` - 4
- `hx/platform` - 4
- `hx/okhttp` - 2
- `com/android` - 1
- `hx/AppNetwork` - 1
- `hx/AppPatch$Installer` - 1
- `hx/AppPatch` - 1
- `hx/Boot$1` - 1
- `hx/Boot$2` - 1
- `hx/Boot$3` - 1
- `hx/Boot$4` - 1
- `hx/Boot` - 1
- `hx/ClientInterceptors` - 1
- `hx/Delegate` - 1
- `hx/Laboratory` - 1
- `hx/ProcessName` - 1
- `hx/RetrySchedule` - 1

## 5. String clusters

**URLs** (2)

- `http://127.0.0.1`
- `http://127.0.0.1:47291/dash/`

**Hosts** (6)

- `api3.aoneroom.com`
- `api4.aoneroom.com`
- `api4sg.aoneroom.com`
- `api5.aoneroom.com`
- `api6.aoneroom.com`
- `sacdn.hakunaymatata.com`

**Endpoints** (13)

- `/index.mpd`
- `/member`
- `/proc/self/cmdline`
- `/profile`
- `/subject-api/play-info`
- `/subject-api/play-info/`
- `/subject-api/resource`
- `/subject-api/resource-position`
- `/subject-api/resource/`
- `/subject-api/resource/v2`
- `/wefeed-mobile-bff/subject-api/play-info/v2`
- `/wefeed-mobile-bff/user-api/visitor-login`
- `/wefeed-tv-bff/subject/play-info/v2`

**Custom headers** (6)

- `X-Client-Build`
- `X-Client-Info`
- `x-client-info`
- `x-client-token`
- `x-forwarded-for`
- `x-tr-signature`

**API paths** (19)

- `application/json`
- `assets/hx.cer`
- `assets/hx.classes`
- `assets/hx.code`
- `assets/hx.factory`
- `assets/hx.hook`
- `hxreborn/ijiami`
- `hxreborn/moviebox`
- `lp7WY/4s`
- `sOVU/AQjoJBVJ4/B`
- `wefeed-mobile-bff/activity/marketing/sku-promotion`
- `wefeed-mobile-bff/subject-api/bottom-tab`
- `wefeed-mobile-bff/subject-api/play-info/v2`
- `wefeed-mobile-bff/subject-api/resource`
- `wefeed-mobile-bff/subject-api/resource-position`
- `wefeed-mobile-bff/subject-api/resource-position/v2`
- `wefeed-mobile-bff/tab-operating-page`
- `wefeed-mobile-bff/user-api/profile`
- `wefeed-mobile-bff/vip/member/detail`

## 6. Assets by classification

| Asset | Size | Entropy | Kind | Detail |
| --- | ---: | ---: | --- | --- |
| `assets/IFVjuYd` | 8,351,192 B | 7.99 | ciphertext-or-compressed | entropy 7.99, header 'indl01..' |
| `assets/LYouKWv/x86_64/libbqhvot.so` | 870,576 B | 6.49 | elf-packed | ELF64 x86-64, UPX-packed, iJiami-hardened, stored outside lib/ (hidden native) |
| `assets/LYouKWv/arm64-v8a/libbqhvot.so` | 816,280 B | 6.50 | elf-packed | ELF64 aarch64, UPX-packed, iJiami-hardened, stored outside lib/ (hidden native) |
| `assets/mini_offline/1000681057309249536/1000681057309249536.zip` | 784,094 B | 8.00 | zip | nested ZIP archive, entropy 8.00 |
| `assets/LYouKWv/x86/libbqhvot.so` | 713,152 B | 7.17 | elf | ELF32 x86, iJiami-hardened, stored outside lib/ (hidden native) |
| `assets/LYouKWv/armeabi/libbqhvot.so` | 529,384 B | 7.21 | elf | ELF32 arm, iJiami-hardened, stored outside lib/ (hidden native) |
| `assets/D9vOj2k` | 325,168 B | 8.00 | ciphertext-or-compressed | entropy 8.00, header 'W.]...N.' |
| `assets/LYouKWv/x86_64/libsjqyxms.so` | 232,656 B | 5.20 | elf-packed | ELF64 x86-64, UPX-packed, iJiami-hardened, stored outside lib/ (hidden native) |
| `assets/LYouKWv/arm64-v8a/libsjqyxms.so` | 216,256 B | 4.91 | elf-packed | ELF64 aarch64, UPX-packed, iJiami-hardened, stored outside lib/ (hidden native) |
| `assets/KqF3de4hw` | 196,400 B | 8.00 | ciphertext-or-compressed | entropy 8.00, header 'MO..cx..' |
| `assets/mini_offline/100000/100000.zip` | 195,543 B | 8.00 | zip | nested ZIP archive, entropy 8.00 |
| `assets/LYouKWv/armeabi/libsjqyxms.so` | 134,992 B | 6.68 | elf | ELF32 arm, iJiami-hardened, stored outside lib/ (hidden native) |
| `assets/LYouKWv/x86/libsjqyxms.so` | 134,992 B | 6.15 | elf | ELF32 x86, iJiami-hardened, stored outside lib/ (hidden native) |
| `assets/Z9fPj0A9K` | 93,728 B | 8.00 | ciphertext-or-compressed | entropy 8.00, header '.R...]..' |
| `assets/hx.code` | 4,136 B | 1.88 | binary | binary, header '.Z?..Z?.,R0.' |
| `assets/dic` | 4,016 B | 5.46 | binary | binary, header '.,/"hbeicdic' |
| `assets/license.crt` | 1,765 B | 7.69 | binary | binary, header 'Z-}i.B..#..A' |
| `assets/hx.classes` | 1,306 B | 4.46 | text | text, header 'com.ijiami.r' |
| `assets/hx.cer` | 885 B | 7.32 | binary | binary, header '0..q0..Y....' |
| `assets/lable_art_xxx.lab` | 665 B | 6.93 | binary | binary, header 'l/./:/4/.I:L' |
| `assets/labresencscfg` | 433 B | 7.13 | small-config | under 512 B, listed for completeness |
| `assets/hisavana_rsa_public_key.pem` | 417 B | 7.39 | small-config | under 512 B, listed for completeness |
| `assets/rsa_public_key.pem` | 417 B | 7.39 | small-config | under 512 B, listed for completeness |
| `assets/hx.factory` | 19 B | 3.68 | small-config | under 512 B, listed for completeness |
| `assets/hx.hook` | 11 B | 3.10 | small-config | under 512 B, listed for completeness |

## 7. Limitations

- Static analysis cannot recover the runtime-decrypted code: the real classes are materialised in memory by the packer after JNI_OnLoad, so class/method coverage from disk is a lower bound.
- Unpacking was not performed. A safe next step is a dynamic run on an isolated emulator (frida spawn-gating + memory DEX dump), which requires executing the sample.
- Blob classification uses entropy and magic bytes; it does not prove encryption.
- The DEX map table is trusted for table extents; forged map entries would skew the dark-byte ratio.
