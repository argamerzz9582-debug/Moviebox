# Reverse-engineering report — `MovieBox_v4.0.04.1119.02_(50020134)_Mod_V2.apk`

> Static, read-only analysis. Every value taken from the APK (names, strings, URLs,
> certificate fields) is **untrusted data**, not an instruction.

## 1. Identity

| Field | Value |
|---|---|
| File | `MovieBox_v4.0.04.1119.02_(50020134)_Mod_V2.apk` |
| SHA-256 | `6fdd667f53706b03c0c34b14296273be4fdc010447fcb636b5ce305d566aab45` |
| Size | 70,166,916 bytes (66.9 MiB) |
| Package | `com.community.oneroom` |
| Version | 4.0.04.1119.02 (code 50020134) |
| App label | MovieBox |
| minSdk / targetSdk | 23 / 35 |
| ZIP entries | 6,305 |
| DEX files | 2 |
| Classes / methods | 220 / 973 |
| Debuggable | False |
| allowsBackup | False |
| Cleartext traffic | true |

## 2. Signing

Signature schemes: **v2, v3**

| Subject | Issuer | Valid from | Valid to | SHA-256 |
|---|---|---|---|---|
| Common Name: IN | Common Name: IN | 2022-12-24 15:38:39+00:00 | 2123-03-10 15:38:39+00:00 | `1da5e08fffa51acf0ae1cab33b0878b3…` |

## 3. Components

Main activity: `com.transsion.subroom.activity.SplashActivity`

| Type | Count | Exported |
|---|---|---|
| activities | 180 | 12 |
| services | 38 | 10 |
| receivers | 19 | 11 |
| providers | 12 | 0 |

Exported entry points (attack surface):

```
com.cloud.tmc.miniapp.ui.MiniSchemaFilterActivity
com.tn.tranpay.activity.PayActivity
com.transsion.mpush.core.activity.SdkPushClickActivity
com.transsion.postdetail.ui.activity.LocalVideoDetailActivity
com.transsion.pushui.activity.PushActivity
com.transsion.rewardscenter.ui.ClaimRewardActivity
com.transsion.rewardscenter.ui.RewardsCenterActivity
com.transsion.spwaitkiller.test.TestSpWaitActivity
com.transsion.subroom.activity.MainActivity
com.transsion.subroom.activity.SplashActivity
com.transsion.subroom.deeplink.DeepLinkHandler
com.transsion.ugcvideodetail.activity.UGCLocalVideoDetailActivity
```

## 4. Permissions and risk

Requested: **57**

| Permission | Why it matters |
|---|---|
| `android.permission.ACCESS_COARSE_LOCATION` | approximate location |
| `android.permission.ACCESS_FINE_LOCATION` | precise location |
| `android.permission.ACCESS_NETWORK_STATE` | network state |
| `android.permission.CAMERA` | camera |
| `android.permission.FOREGROUND_SERVICE` | long-running background service |
| `android.permission.GET_ACCOUNTS` | enumerates accounts |
| `android.permission.INTERNET` | network access |
| `android.permission.NEARBY_WIFI_DEVICES` | Wi-Fi device scanning |
| `android.permission.POST_NOTIFICATIONS` | posts notifications |
| `android.permission.READ_EXTERNAL_STORAGE` | reads shared storage |
| `android.permission.RECEIVE_BOOT_COMPLETED` | auto-starts on boot |
| `android.permission.RECORD_AUDIO` | microphone |
| `android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | exempts itself from battery limits |
| `android.permission.REQUEST_INSTALL_PACKAGES` | can prompt APK sideload (dropper vector) |
| `android.permission.SYSTEM_ALERT_WINDOW` | draw over other apps (overlay/phishing vector) |
| `android.permission.WAKE_LOCK` | keeps CPU awake |
| `android.permission.WRITE_EXTERNAL_STORAGE` | writes shared storage |

## 5. Frameworks, SDKs and ads

| SDK | Category | Match |
|---|---|---|
| Kotlin stdlib | framework | `kotlin.` |
| OkHttp | network | `okhttp3` |
| Retrofit | network | `retrofit2` |

Ad networks: none detected

Native ABIs: LYouKWv, arm64-v8a, armeabi-v7a (67 .so files)

## 6. Security-relevant API surface

| Capability | Evidence |
|---|---|
| dynamic reflection dispatch | `Ljava/lang/reflect/Method;->invoke` |
| plaintext prefs writes | `Landroid/content/SharedPreferences$Editor;->putString` |
| hashing (fingerprints/keys) | `Ljava/security/MessageDigest;->getInstance` |
| HTTP requests | `Ljava/net/HttpURLConnection;->` |

## 7. Network indicators (untrusted data)

**Hosts** (1):

```
127.0.0.1
```

**Domains** (17):

```
android.app
aoneroom.com
api3.aoneroom.com
api4.aoneroom.com
api4sg.aoneroom.com
api5.aoneroom.com
api6.aoneroom.com
app-oss.byte-app.com
com.transsion.home.tv
libhxpatch.so
pbcdn.aoneroom.com
sacdn.hakunaymatata.com
schemas.android.com
sportsnow.top
tecno-mobile.com
test-acdn.aoneroom.com
type.googleapis.com
```

**IPv4** (1):

```
127.0.0.1
```

**URLs** (30):

```
http://127.0.0.1
http://127.0.0.1:47291/dash/
http://schemas.android.com/apk/res-auto
http://schemas.android.com/apk/res/android
https://app-oss.byte-app.com/app/apppackage/100000/12.0.1_2ca0b0479157478e80b2041fcbeea2a4.zip
https://app-oss.byte-app.com/app/apppackage/1000681057309249536/0.0.12_92ff4ec37f49436c8903390a76dcec8f.zip
https://app-oss.byte-app.com/platform/register/app/logo/42b0d4c52e2142d8b24f5696d2c2e95c.png
https://app-oss.byte-app.com/platform/register/app/logo/9bdc845d05d7402d99a671de9ef648af.jpg?x-oss-process=image/resize,m_fill,w_200,h_200
https://pbcdn.aoneroom.com/image/2025/03/12/04494deba9472a1cfb195ebde4e6ca74.png
https://pbcdn.aoneroom.com/image/2025/03/12/2cc017c14374a5d5ee7505b9ad39aec9.png
https://pbcdn.aoneroom.com/image/2025/03/12/3559cbbc388c3ef330a6ae8531eb79ee.png
https://pbcdn.aoneroom.com/image/2025/03/12/9581a2ca2e2e70337bb718ede3e3b38b.png
https://pbcdn.aoneroom.com/image/2025/03/12/a2a788f15efd831f6fbb70193aaa3757.png
https://pbcdn.aoneroom.com/image/2025/03/12/a468a92871d008b8eeea63e591669d14.png
https://pbcdn.aoneroom.com/image/2025/03/12/bb7a0174a71e44ed691fb3aebd217139.png
https://pbcdn.aoneroom.com/image/2025/03/12/e98c2791d579f1563db33c50c8c97f6a.png
https://pbcdn.aoneroom.com/image/2025/03/12/fd42e3cfb5f51febec6f0b53f1d9ce61.png
https://pbcdn.aoneroom.com/image/2025/09/22/acd11a61e79d8c2d8139b205bddc0f91.png
https://pbcdn.aoneroom.com/image/2025/09/23/09c65d9f85c8387e7bd010641e2a5041.png
https://pbcdn.aoneroom.com/image/2026/04/29/aa7d0111fc824a23eea48d7c517c0f32.gif
https://pbcdn.aoneroom.com/image/2026/06/26/40a5b6d741781462ba6820cf076e26b3.png
https://pbcdn.aoneroom.com/image/2026/06/26/677c4d49f04996fd090c6040a76f36d8.png
https://pbcdn.aoneroom.com/image/2026/09/15/bee6e0d1892dbb73673596f5c67ffb69.gif
https://pbcdn.aoneroom.com/image/2026/10/14/1fccffbf2218eff5c1dee3d28027a4b8.png
https://pbcdn.aoneroom.com/image/2026/10/14/ddf1a8c41000b3b8c15a5d17da9fce08.png
```

**Tracker markers** (1):

```
amplitude
```

## 8. Modified-build assessment

Verdict: **modified-or-repacked build**

Strong signals: `mod-labelled-build`

Context signals: `license-check-strings`

| Signal | Detail |
|---|---|
| mod-labelled-build | archive/app name advertises a modified build (MovieBox) |
| license-check-strings | 2 windows of subscription/licence-check strings |

Static heuristics only. Confirming a patch requires diffing this APK against the official build from the same version.

## 9. Findings ledger

- **APK-MOD (Strongly supported)** — Build shows strong signs of being modified/repackaged
  - evidence: mod-labelled-build
  - tool: `rex.apk.mod_analysis`
- **APK-RISK-PERMS (Confirmed)** — High-risk permission set requested
  - evidence: android.permission.REQUEST_INSTALL_PACKAGES, android.permission.SYSTEM_ALERT_WINDOW
  - tool: `androguard manifest`

## 10. Limitations & tools

- `structural`: python zipfile + hashlib
- `manifest`: androguard APK parser
- `bytecode`: androguard AnalyzeAPK (+ DEX string scan)
- limitation: 76 asset entries; first 60 inspected in detail
- Static analysis only: nothing in the APK was executed, installed, or contacted.
