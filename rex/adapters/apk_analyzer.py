"""Android APK intelligence analyzer for REX (own-code implementation).

Purpose-built for the MovieBox-style APK triage workflow: a single deterministic
pass that answers *what is this APK, what can it reach, and what did the mod
change*, then writes bounded artifacts (never dumping megabytes to stdout).

Design:
* Parsing uses androguard when available, with a pure-``zipfile``/``struct``
  fallback so the module still yields structural facts without optional deps.
* Every finding carries a confidence label and the tool that produced it, in
  line with ``rex.reporting``'s evidence model.
* All strings/URLs/indicators are treated as **untrusted data**, never as
  instructions (see SECURITY.md).
* Outputs are size-bounded: top-N lists and truncated samples only.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

MAX_LIST = 60
MAX_STRINGS_SCAN = 400000
MAX_APK_BYTES = 512 * 1024 * 1024

#: Third-party SDK fingerprints: (label, class-prefix or string needle, category)
SDK_SIGNATURES: Sequence[Tuple[str, str, str]] = (
    ("AndroidX", "androidx/", "framework"),
    ("Android Support Library", "android/support/", "framework"),
    ("Kotlin stdlib", "kotlin/", "framework"),
    ("Firebase", "com/google/firebase", "backend"),
    ("Google Play Services", "com/google/android/gms", "backend"),
    ("Facebook SDK", "com/facebook", "social"),
    ("AppsFlyer", "com/appsflyer", "attribution"),
    ("Adjust", "com/adjust/sdk", "attribution"),
    ("Amplitude", "com/amplitude", "analytics"),
    ("Mixpanel", "com/mixpanel", "analytics"),
    ("Sentry", "io/sentry", "crash-reporting"),
    ("OkHttp", "okhttp3", "network"),
    ("Retrofit", "retrofit2", "network"),
    ("Glide", "com/bumptech/glide", "ui"),
    ("Coil", "coil3", "ui"),
    ("ExoPlayer/Media3", "androidx/media3", "media"),
    ("VLC/LibVLC", "org/videolan", "media"),
    ("IJKPlayer", "tv/danmaku/ijk", "media"),
    ("FFmpegKit", "com/arthenica/ffmpegkit", "media"),
    ("Mozilla Rhino (JS engine)", "org/mozilla/javascript", "scripting"),
    ("QuickJS", "com/whl/quickjs", "scripting"),
    ("Duktape", "com/squareup/duktape", "scripting"),
    ("Flutter", "io/flutter", "framework"),
    ("React Native", "com/facebook/react", "framework"),
    ("Cordova", "org/apache/cordova", "framework"),
    ("Hilt/Dagger", "dagger/", "di"),
    ("Koin", "org/koin", "di"),
    ("Room", "androidx/room", "storage"),
    ("Realm", "io/realm", "storage"),
    ("SQLCipher", "net/sqlcipher", "storage"),
    ("Torrent (libtorrent)", "com/frostwire", "p2p"),
    ("ACRA", "org/acra", "crash-reporting"),
    ("Bugsnag", "com/bugsnag", "crash-reporting"),
    ("OneSignal", "com/onesignal", "push"),
    ("FCM Push", "com/google/firebase/messaging", "push"),
)

#: Java/Kotlin packages seen in decompiled output that usually mean an ad network.
AD_NETWORK_HINTS: Sequence[Tuple[str, str]] = (
    ("Google AdMob", "com/google/android/gms/ads"),
    ("Facebook Audience", "com/facebook/ads"),
    ("Unity Ads", "com/unity3d/ads"),
    ("AppLovin", "com/applovin"),
    ("IronSource", "com/ironsource"),
    ("Vungle", "com/vungle"),
    ("AdColony", "com/adcolony"),
    ("Mintegral", "com/mbridge"),
    ("Pangle", "com/bytedance/sdk/openadsdk"),
    ("InMobi", "com/inmobi"),
)

#: High-signal Android permissions with a plain-English risk note.
PERMISSION_NOTES: Dict[str, str] = {
    "android.permission.INTERNET": "network access",
    "android.permission.ACCESS_NETWORK_STATE": "network state",
    "android.permission.WRITE_EXTERNAL_STORAGE": "writes shared storage",
    "android.permission.READ_EXTERNAL_STORAGE": "reads shared storage",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "broad file access (all-files)",
    "android.permission.READ_SMS": "reads SMS",
    "android.permission.RECEIVE_SMS": "receives SMS",
    "android.permission.SEND_SMS": "sends SMS (premium-rate abuse vector)",
    "android.permission.READ_CONTACTS": "reads contacts",
    "android.permission.READ_CALL_LOG": "reads call log",
    "android.permission.CALL_PHONE": "places calls",
    "android.permission.READ_PHONE_STATE": "device identifiers (IMEI/IMSI)",
    "android.permission.ACCESS_FINE_LOCATION": "precise location",
    "android.permission.ACCESS_COARSE_LOCATION": "approximate location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "location while backgrounded",
    "android.permission.RECORD_AUDIO": "microphone",
    "android.permission.CAMERA": "camera",
    "android.permission.SYSTEM_ALERT_WINDOW": "draw over other apps (overlay/phishing vector)",
    "android.permission.REQUEST_INSTALL_PACKAGES": "can prompt APK sideload (dropper vector)",
    "android.permission.INSTALL_PACKAGES": "can install packages silently",
    "android.permission.QUERY_ALL_PACKAGES": "enumerates installed apps",
    "android.permission.PACKAGE_USAGE_STATS": "usage stats access",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "accessibility service (keylogging vector)",
    "android.permission.BIND_DEVICE_ADMIN": "device admin (hard-to-remove)",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "reads all notifications",
    "android.permission.READ_LOGS": "reads system logs",
    "android.permission.GET_ACCOUNTS": "enumerates accounts",
    "android.permission.RECEIVE_BOOT_COMPLETED": "auto-starts on boot",
    "android.permission.FOREGROUND_SERVICE": "long-running background service",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": "exempts itself from battery limits",
    "android.permission.WAKE_LOCK": "keeps CPU awake",
    "android.permission.POST_NOTIFICATIONS": "posts notifications",
    "android.permission.USE_BIOMETRIC": "biometric auth",
    "android.permission.BLUETOOTH_CONNECT": "Bluetooth device control",
    "android.permission.NEARBY_WIFI_DEVICES": "Wi-Fi device scanning",
}

#: Sinks worth calling out when their API string appears in the DEX.
SENSITIVE_APIS: Sequence[Tuple[str, str, str]] = (
    ("reflect", "Ljava/lang/reflect/Method;->invoke", "dynamic reflection dispatch"),
    ("runtime-exec", "Ljava/lang/Runtime;->exec", "process execution"),
    ("process-builder", "Ljava/lang/ProcessBuilder;-><init>", "process execution"),
    ("dexclassloader", "Ldalvik/system/DexClassLoader;-><init>", "runtime code loading"),
    ("pathclassloader", "Ldalvik/system/PathClassLoader;-><init>", "runtime code loading"),
    ("inlinedexloader", "Ldalvik/system/InMemoryDexClassLoader;-><init>", "runtime code loading"),
    ("classloader-define", "Ljava/lang/ClassLoader;->defineClass", "runtime class definition"),
    ("setaccessible", "Ljava/lang/reflect/AccessibleObject;->setAccessible", "reflection bypass"),
    ("webview-jsi", "Landroid/webkit/WebView;->addJavascriptInterface", "JS bridge into Java"),
    ("webview-loadurl", "Landroid/webkit/WebView;->loadUrl", "in-app URL loading"),
    ("eval-js", "Landroid/webkit/WebSettings;->setJavaScriptEnabled", "JS execution enabled"),
    ("javacrypto-aes", "Ljavax/crypto/Cipher;->getInstance", "cryptography use"),
    ("package-installer", "Landroid/content/pm/PackageInstaller;->", "APK installation API"),
    ("intent-install", "Landroid/content/Intent;->ACTION_VIEW", "intent dispatch (sideload prompts)"),
    ("sharedprefs", "Landroid/content/SharedPreferences$Editor;->putString", "plaintext prefs writes"),
    ("hashing-md5", "Ljava/security/MessageDigest;->getInstance", "hashing (fingerprints/keys)"),
    ("okhttp-builder", "Lokhttp3/Request$Builder;->", "HTTP requests"),
    ("httpurlconnection", "Ljava/net/HttpURLConnection;->", "HTTP requests"),
    ("socket-raw", "Ljava/net/Socket;-><init>", "raw socket connections"),
    ("ssl-trust-all", "Landroid/net/http/X509TrustManagerExtensions", "TLS trust handling"),
    ("superuser-check", "/system/app/Superuser", "root detection string"),
)

#: Regex bank for indicators found inside DEX string data.
URL_RE = re.compile(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{6,200}")
DOMAIN_RE = re.compile(rb"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                       rb"(?:com|net|org|io|xyz|top|club|site|online|app|tv|cc|me|info|co|in|ru|cn|to|so)\b")
IPV4_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,12}")
B64_BLOB_RE = re.compile(rb"[A-Za-z0-9+/]{120,}={0,2}")
ERROR_NEEDLES = (
    b"licen", b"verif", b"signature invalid", b"tamper", b"integrity", b"premium",
    b"subscri", b"vip", b"unlock", b"bypass", b"adblock", b"ad-free", b"pro version",
)
#: Names that advertise a modified/repacked build (filename or app label).
_MOD_NAME_RE = re.compile(
    r"(?:^|[^a-z0-9])mod(?:ded|ified)?(?:[^a-z0-9]|$)|patched|unlocked|premium|cracked|repack",
    re.IGNORECASE)

TRACKER_NEEDLES = (
    b"appsflyer", b"adjust.com", b"facebook.net", b"doubleclick", b"googletagmanager",
    b"crashlytics", b"amplitude", b"mixpanel", b"sentry.io", b"onesignal", b"umeng",
)


@dataclass
class Finding:
    id: str
    claim: str
    confidence: str  # Confirmed | Strongly supported | Probable | Unverified
    tool: str
    evidence: str = ""
    location: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {"id": self.id, "claim": self.claim, "confidence": self.confidence,
                "tool": self.tool, "evidence": self.evidence[:600], "location": self.location}


@dataclass
class ApkReport:
    apk: Path
    identity: Dict[str, Any] = field(default_factory=dict)
    signing: Dict[str, Any] = field(default_factory=dict)
    components: Dict[str, Any] = field(default_factory=dict)
    permissions: Dict[str, Any] = field(default_factory=dict)
    sdk_fingerprints: List[Dict[str, str]] = field(default_factory=list)
    ad_networks: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    native_libs: List[Dict[str, str]] = field(default_factory=list)
    bytecode: Dict[str, Any] = field(default_factory=dict)
    sensitive_apis: List[Dict[str, str]] = field(default_factory=list)
    indicators: Dict[str, List[str]] = field(default_factory=dict)
    mod_analysis: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    tools_used: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "apk": str(self.apk),
            "identity": self.identity,
            "signing": self.signing,
            "components": self.components,
            "permissions": self.permissions,
            "sdk_fingerprints": self.sdk_fingerprints,
            "ad_networks": self.ad_networks,
            "libraries": self.libraries,
            "native_libs": self.native_libs,
            "bytecode": self.bytecode,
            "sensitive_apis": self.sensitive_apis,
            "indicators": self.indicators,
            "mod_analysis": self.mod_analysis,
            "findings": [f.to_dict() for f in self.findings],
            "limitations": self.limitations,
            "tools_used": self.tools_used,
        }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _quiet_androguard() -> None:
    """androguard logs through loguru, which ignores stdlib ``logging``.

    We remove its default sink (stderr) so analysis output stays clean, and also
    silence the stdlib loggers for the helper libraries.
    """
    logging.disable(logging.CRITICAL)
    for name in ("androguard", "asn1crypto", "apkutils"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    try:
        from loguru import logger as _loguru_logger
        _loguru_logger.remove()
        _loguru_logger.disable("androguard")
    except Exception:
        pass


def _short(value: Any, limit: int = 160) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


class ApkAnalyzer:
    """Deterministic, read-only APK triage (no target execution)."""

    def __init__(self, apk: Path, deep: bool = False, max_strings: int = MAX_STRINGS_SCAN):
        self.apk = Path(apk)
        self.deep = deep
        self.max_strings = max_strings
        self.report = ApkReport(apk=self.apk)

    # -- entry point -------------------------------------------------------
    def analyze(self) -> ApkReport:
        if not self.apk.is_file():
            raise FileNotFoundError(self.apk)
        size = self.apk.stat().st_size
        self.report.identity = {
            "name": self.apk.name,
            "size_bytes": size,
            "sha256": _sha256(self.apk),
        }
        if size > MAX_APK_BYTES:
            self.report.limitations.append("APK larger than 512 MiB; bytecode scan capped")
        if not zipfile.is_zipfile(self.apk):
            self.report.limitations.append("Not a ZIP container — not a valid APK")
            return self.report

        self._structural_pass()
        self._manifest_pass()
        self._bytecode_pass()
        self._mod_pass()
        self._conclude()
        return self.report

    # -- structural --------------------------------------------------------
    def _structural_pass(self) -> None:
        with zipfile.ZipFile(self.apk) as zf:
            infos = zf.infolist()
            names = [i.filename for i in infos]
            dex = [n for n in names if n.endswith(".dex")]
            native = sorted({n for n in names if n.endswith(".so")})
            res_files = [n for n in names if n.startswith("res/")]
            assets = [n for n in names if n.startswith("assets/")]
            self.report.identity.update({
                "entries": len(infos),
                "dex_files": dex,
                "asset_count": len(assets),
                "resource_count": len(res_files),
                "uncompressed_bytes": sum(i.file_size for i in infos),
            })
            self.report.bytecode["dex_count"] = len(dex)
            self.report.bytecode["dex_bytes"] = sum(i.file_size for i in infos if i.filename in dex)

            # Native libraries carry the ABI + any embedded framework hints.
            for name in native:
                abi = name.split("/")[1] if name.count("/") >= 2 else "unknown"
                info = next((i for i in infos if i.filename == name), None)
                self.report.native_libs.append({
                    "path": name,
                    "abi": abi,
                    "size": info.file_size if info else 0,
                    "sha256": hashlib.sha256(zf.read(name)).hexdigest()[:32]
                    if (info and info.file_size < 8 * 1024 * 1024) else "",
                })
            assets_of_interest = [a for a in assets if re.search(
                r"\.(js|html|json|xml|lua|bin|dat|pak|zip|apk|so|ttf|db)$", a, re.I)]
            self.report.identity["assets_of_interest"] = assets_of_interest[:MAX_LIST]
            if len(assets) > MAX_LIST:
                self.report.limitations.append(
                    f"{len(assets)} asset entries; first {MAX_LIST} inspected in detail")
            if any(n.endswith((".apk", ".jar", ".dex")) for n in assets):
                self.report.findings.append(Finding(
                    "APK-NESTED", "APK contains nested executable archives/xdex in assets/",
                    "Confirmed", "rex.apk.structural",
                    ", ".join([a for a in assets if a.endswith((".apk", ".jar", ".dex"))][:5])))
        self.report.tools_used["structural"] = "python zipfile + hashlib"

    # -- manifest / signing ------------------------------------------------
    def _manifest_pass(self) -> None:
        try:
            _quiet_androguard()
            from androguard.core.apk import APK  # local import: optional dependency
        except Exception as exc:  # pragma: no cover - optional dependency
            self.report.limitations.append(f"androguard unavailable ({exc}); manifest not decoded")
            return
        try:
            apk = APK(str(self.apk))
        except Exception as exc:
            self.report.limitations.append(f"manifest decode failed: {exc}")
            return

        self.report.tools_used["manifest"] = "androguard APK parser"

        def safe(getter: str, default: Any = None) -> Any:
            """Manifest getters raise on unusual/hand-crafted manifests; never abort."""
            try:
                value = getattr(apk, getter)()
                return default if value in (None, "") else value
            except Exception:
                return default

        debuggable = safe("get_attribute_value", "unset")
        self.report.identity.update({
            "package": safe("get_package"),
            "version_name": safe("get_androidversion_name"),
            "version_code": str(safe("get_androidversion_code")),
            "app_label": safe("get_app_name"),
            "min_sdk": safe("get_min_sdk_version"),
            "target_sdk": safe("get_target_sdk_version"),
            "effective_target_sdk": safe("get_effective_target_sdk_version"),
            "is_debuggable": _attr(apk, "application", "debuggable") in ("true", True, "1"),
            "allows_backup": _attr(apk, "application", "allowBackup") not in ("false", False, "0"),
            "uses_cleartext_traffic": _attr(apk, "application", "usesCleartextTraffic"),
            "network_security_config": _attr(apk, "application", "networkSecurityConfig"),
        })
        del debuggable

        perms = sorted(safe("get_permissions", []) or [])
        flags = sorted(safe("get_permission_flags", {}) .items()) if hasattr(apk, "get_permission_flags") else []
        self.report.permissions = {
            "count": len(perms),
            "permissions": perms[:MAX_LIST * 2],
            "risk": [{"permission": p, "note": PERMISSION_NOTES[p]}
                     for p in perms if p in PERMISSION_NOTES],
            "custom_or_signature": [p for p in perms
                                    if not p.startswith("android.permission.")][:MAX_LIST],
            "flags": flags[:20],
        }

        def _list(getter: str) -> List[str]:
            return sorted(safe(getter, []) or [])

        self.report.components = {
            "activities": _list("get_activities")[:MAX_LIST * 3],
            "services": _list("get_services")[:MAX_LIST * 2],
            "receivers": _list("get_receivers")[:MAX_LIST],
            "providers": _list("get_providers")[:MAX_LIST],
            "main_activity": safe("get_main_activity"),
            "exported_activities": _exported(apk, "activity"),
            "exported_services": _exported(apk, "service"),
            "exported_receivers": _exported(apk, "receiver"),
            "permissions_declared": _list("get_declared_permissions")[:MAX_LIST],
        }
        self.report.libraries = _list("get_libraries")[:MAX_LIST]
        self.report.identity["features"] = _list("get_features")[:30]

        # Signing scheme coverage + certificate identity.
        schemes = []
        for label, getter in (("v1", "is_signed_v1"), ("v2", "is_signed_v2"), ("v3", "is_signed_v3")):
            try:
                if getattr(apk, getter)():
                    schemes.append(label)
            except Exception:
                pass
        certs = []
        try:
            for cert in (safe("get_certificates", []) or [])[:5]:
                certs.append({
                    "subject": _short(cert.subject.human_friendly, 200),
                    "issuer": _short(cert.issuer.human_friendly, 200),
                    "serial": str(cert.serial_number),
                    "sha256": cert.sha256.hex(),
                    "not_before": str(getattr(cert, "not_valid_before", "")),
                    "not_after": str(getattr(cert, "not_valid_after", "")),
                    "signature_algo": str(getattr(cert, "signature_algo", "")),
                })
        except Exception as exc:
            self.report.limitations.append(f"certificate extraction failed: {exc}")
        self.report.signing = {"schemes": schemes, "certificates": certs,
                               "apk_signer_names": _list("get_signature_names")[:10]}

        if certs and "v2" not in schemes and "v3" not in schemes:
            self.report.findings.append(Finding(
                "APK-SIG-V1ONLY", "APK is signed with v1 (JAR) signature only",
                "Confirmed", "androguard", "no APK Signature Scheme v2/v3 block found"))
        if not certs:
            self.report.findings.append(Finding(
                "APK-UNSIGNED", "No signing certificate could be extracted",
                "Probable", "androguard", "certificate list empty"))

    # -- bytecode ----------------------------------------------------------
    def _bytecode_pass(self) -> None:
        try:
            _quiet_androguard()
            from androguard.misc import AnalyzeAPK  # optional dependency
        except Exception:
            self.report.limitations.append("androguard DEX analysis unavailable")
            self._raw_string_scan()
            return
        try:
            _, dexes, dx = AnalyzeAPK(str(self.apk))
        except Exception as exc:
            self.report.limitations.append(f"DEX analysis failed: {exc}")
            self._raw_string_scan()
            return

        classes = [c.name for c in dx.get_classes()]
        methods = list(dx.get_methods())
        external = [c.name for c in dx.get_external_classes()]
        self.report.bytecode.update({
            "classes": len(classes),
            "methods": len(methods),
            "external_classes": len(external),
            "dex_objects": len(dexes),
        })
        self.report.tools_used["bytecode"] = "androguard AnalyzeAPK (+ DEX string scan)"

        # Third-party SDK fingerprinting over DEX class names.
        joined = "\n".join(classes)
        for label, needle, category in SDK_SIGNATURES:
            hit = needle if needle in joined else needle.replace("/", ".")
            if needle in joined or hit in joined:
                self.report.sdk_fingerprints.append(
                    {"sdk": label, "category": category, "match": needle})
        for label, needle in AD_NETWORK_HINTS:
            if needle in joined or needle.replace("/", ".") in joined:
                self.report.ad_networks.append(label)

        # Fallback fingerprinting: DEX constant pools carry the same package names.
        pool = "\n".join(_dex_strings(dexes, cap=self.max_strings))
        if not self.report.sdk_fingerprints:
            for label, needle, category in SDK_SIGNATURES:
                if needle.replace("/", ".") in pool or needle in pool:
                    self.report.sdk_fingerprints.append(
                        {"sdk": label, "category": category, "match": needle.replace("/", ".")})
        if not self.report.ad_networks:
            for label, needle in AD_NETWORK_HINTS:
                if needle.replace("/", ".") in pool or needle in pool:
                    self.report.ad_networks.append(label)

        strings = set()
        for analysis in dx.get_strings():
            value = analysis.get_value()
            if value:
                strings.add(value)
                if len(strings) >= self.max_strings:
                    self.report.limitations.append(
                        f"DEX string collection capped at {self.max_strings} entries")
                    break
        blob = "\n".join(strings) if strings else pool
        # API sinks live in method signatures/type descriptors, not the string
        # pool, so match them against the method index (class + method name).
        signatures = set()
        for analysis in methods:
            try:
                method = analysis.get_method()
                signatures.add(f"{method.get_class_name()}->{method.get_name()}")
            except Exception:
                continue
        for key, needle, label in SENSITIVE_APIS:
            if _match_api(needle, blob, signatures):
                self.report.sensitive_apis.append({"api": key, "meaning": label, "match": needle})

        # Indicator harvest from DEX strings (untrusted data, never executed).
        self.report.indicators = _harvest(blob)
        self._raw_string_scan()
        # Union the structural scan with what the analysis graph exposed.
        for key in ("emails", "base64_blobs", "license_keywords", "domains"):
            merged = sorted({*self.report.indicators.get(key, []), *_harvest(blob).get(key, [])})
            if merged:
                self.report.indicators[key] = merged[:MAX_LIST]

        if self.report.ad_networks:
            self.report.findings.append(Finding(
                "APK-ADS", "Ad SDKs detected", "Confirmed", "androguard DEX class index",
                ", ".join(self.report.ad_networks)))
        if any(a["api"] in ("dexclassloader", "pathclassloader", "inlinedexloader")
               for a in self.report.sensitive_apis):
            self.report.findings.append(Finding(
                "APK-DYNDEX", "APK loads DEX code at runtime", "Strongly supported",
                "androguard",
                "DexClassLoader/PathClassLoader referenced — code may be fetched after install"))

    def _raw_string_scan(self, extra: Optional[Dict[str, List[str]]] = None) -> None:
        """Interesting byte sequences straight out of the DEX/asset blobs."""
        buckets: Dict[str, set] = {
            "urls": set(), "domains": set(), "ipv4": set(), "emails": set(),
            "base64_blobs": set(), "license_keywords": set(), "trackers": set(),
        }
        scanned = 0
        with zipfile.ZipFile(self.apk) as zf:
            for name in [n for n in zf.namelist() if n.endswith((".dex", ".js", ".json", ".xml"))][:32]:
                info = zf.getinfo(name)
                if info.file_size > 64 * 1024 * 1024:
                    continue
                data = zf.read(name)
                scanned += len(data)
                for match in URL_RE.findall(data)[:400]:
                    buckets["urls"].add(match.decode("latin-1"))
                for match in IPV4_RE.findall(data)[:200]:
                    buckets["ipv4"].add(match.decode())
                for match in EMAIL_RE.findall(data)[:200]:
                    buckets["emails"].add(match.decode())
                for match in DOMAIN_RE.findall(data)[:300]:
                    buckets["domains"].add(match.decode())
                for match in B64_BLOB_RE.findall(data)[:20]:
                    buckets["base64_blobs"].add(match.decode()[:60] + f"…({len(match)} B)")
                lower = data.lower()
                for needle in ERROR_NEEDLES:
                    if needle in lower and len(buckets["license_keywords"]) < 40:
                        idx = lower.find(needle)
                        snippet = data[max(0, idx - 40): idx + 60]
                        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in snippet)
                        if printable.strip("."):
                            buckets["license_keywords"].add(printable)
                for needle in TRACKER_NEEDLES:
                    if needle in lower:
                        buckets["trackers"].add(needle.decode())
                if scanned > 96 * 1024 * 1024:
                    break
        merged = {k: list(v) for k, v in (self.report.indicators or {}).items()}
        for key, values in buckets.items():
            union = sorted({*merged.get(key, []), *values})
            if union:
                merged[key] = union[:MAX_LIST]
        self.report.indicators = merged
        self.report.bytecode["raw_scan_bytes"] = scanned

    # -- mod / patch analysis ---------------------------------------------
    def _mod_pass(self) -> None:
        """Look for the usual signatures of a *modded* build without executing it.

        Signals are weighted: only *strong* evidence (mod labelling, debug/repack
        certificate, debuggable flag) can carry a verdict on its own; packaging
        habits such as v1-only signing are common in legitimate old releases and
        are recorded as weak context.
        """
        strong: List[Dict[str, str]] = []
        weak: List[Dict[str, str]] = []
        identity = self.report.identity
        signing = self.report.signing
        certs = signing.get("certificates") or []
        label = str(identity.get("app_label") or "")
        name = self.apk.name

        if _MOD_NAME_RE.search(name) or _MOD_NAME_RE.search(label):
            strong.append({"signal": "mod-labelled-build",
                           "detail": f"archive/app name advertises a modified build "
                                     f"({_short(label or name, 80)})"})
        issuers = " ".join(c.get("issuer", "") + " " + c.get("subject", "") for c in certs)
        if re.search(r"android debug|debug key|testkey|unknown", issuers, re.I):
            strong.append({"signal": "debug-or-test-key-certificate",
                           "detail": f"signing identity looks like a debug/test key: {_short(issuers, 120)}"})
        if identity.get("is_debuggable"):
            strong.append({"signal": "debuggable",
                           "detail": "android:debuggable=true permits runtime attach"})
        if len(certs) > 1:
            strong.append({"signal": "multi-certificate",
                           "detail": f"{len(certs)} signing certificates present (re-signing often leaves one)"})

        for scheme in ("v2", "v3"):
            if scheme not in (signing.get("schemes") or []):
                weak.append({"signal": f"no-{scheme}-signature",
                             "detail": f"APK Signature Scheme {scheme} absent (normal for pre-2017 builds)"})
        if len(identity.get("dex_files") or []) > 2:
            weak.append({"signal": "many-dex",
                         "detail": f"{len(identity.get('dex_files'))} DEX files (large or repackaged app)"})
        kw = self.report.indicators.get("license_keywords") or []
        if kw:
            weak.append({"signal": "license-check-strings",
                         "detail": f"{len(kw)} windows of subscription/licence-check strings"})
        if self.report.indicators.get("base64_blobs"):
            weak.append({"signal": "embedded-blobs",
                         "detail": f"{len(self.report.indicators['base64_blobs'])} long base64 blobs "
                                   "(possible embedded payloads or keystores)"})
        if self.report.ad_networks:
            weak.append({"signal": "ad-sdks-present",
                         "detail": "ad SDKs present: " + ", ".join(self.report.ad_networks)
                                   + " (their removal is a common mod target)"})
        if self.report.native_libs and len({n["abi"] for n in self.report.native_libs}) == 1:
            weak.append({"signal": "single-abi-native",
                         "detail": "native libraries for one ABI only (stripped packaging)"})

        signals = strong + weak
        if strong:
            verdict = "modified-or-repacked build"
        elif len(weak) >= 4:
            verdict = "possible modification (weak signals only)"
        else:
            verdict = "no strong modification signal"
        self.report.mod_analysis = {
            "verdict": verdict,
            "strong_signals": [s["signal"] for s in strong],
            "weak_signals": [s["signal"] for s in weak],
            "signals": signals,
            "note": ("Static heuristics only. Confirming a patch requires diffing this APK "
                     "against the official build from the same version."),
        }
        if strong:
            self.report.findings.append(Finding(
                "APK-MOD", "Build shows strong signs of being modified/repackaged",
                "Strongly supported", "rex.apk.mod_analysis",
                "; ".join(s["signal"] for s in strong)))
        elif len(weak) >= 4:
            self.report.findings.append(Finding(
                "APK-MOD-WEAK", "Packaging differences worth diffing against the official build",
                "Unverified", "rex.apk.mod_analysis",
                "; ".join(s["signal"] for s in weak[:5])))

    # -- conclusions -------------------------------------------------------
    def _conclude(self) -> None:
        risk_bits = [r["permission"] for r in self.report.permissions.get("risk", [])
                     if r["permission"] in (
                         "android.permission.SEND_SMS", "android.permission.SYSTEM_ALERT_WINDOW",
                         "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.READ_SMS",
                         "android.permission.BIND_ACCESSIBILITY_SERVICE",
                         "android.permission.BIND_DEVICE_ADMIN",
                         "android.permission.MANAGE_EXTERNAL_STORAGE",
                         "android.permission.READ_LOGS")]
        if risk_bits:
            self.report.findings.append(Finding(
                "APK-RISK-PERMS", "High-risk permission set requested", "Confirmed",
                "androguard manifest",
                ", ".join(risk_bits)))
        ips = self.report.indicators.get("ipv4") or []
        public_ips = [ip for ip in ips
                      if not ip.startswith(("0.", "127.", "10.", "192.168.", "255.", "172.", "169.254."))
                      and ip not in {"1.1.1.1", "8.8.8.8", "8.8.4.4"}]
        if public_ips:
            self.report.findings.append(Finding(
                "APK-HARDCODED-IP", "Hardcoded public IPv4 addresses in app data",
                "Probable", "regex over DEX/assets", ", ".join(public_ips[:8])))
        if not self.report.findings:
            self.report.findings.append(Finding(
                "APK-BASELINE", "No high-signal static indicators found", "Confirmed",
                "rex.apk", "structure, manifest and bytecode analyzed cleanly"))


def _attr(apk: Any, element: str, name: str) -> Any:
    """Read an android: attribute without letting a malformed manifest abort."""
    try:
        return apk.get_attribute_value(element, name)
    except Exception:
        return None


def _exported(apk: Any, tag: str) -> List[str]:
    """Components with android:exported=true (plus ones relying on intent filters)."""
    out: List[str] = []
    try:
        manifest = apk.get_android_manifest_xml()
        for node in manifest.iter(tag):
            name = node.get("{http://schemas.android.com/apk/res/android}name") or ""
            exported = (node.get("{http://schemas.android.com/apk/res/android}exported") or "").lower()
            has_filter = node.find("intent-filter") is not None
            if exported == "true" or (exported == "" and has_filter):
                out.append(name)
    except Exception:
        return []
    return sorted(set(out))[:MAX_LIST]


def _match_api(needle: str, blob: str, signatures: Iterable[str]) -> bool:
    """Match a registry needle against DEX strings *and* method signatures.

    Needles look like ``Landroid/webkit/WebView;->loadUrl``; the class part is
    matched as a prefix and the method part as a prefix of the method name so a
    registry entry does not need every overload.
    """
    if needle in blob:
        return True
    if ";->" not in needle:
        return False
    owner, _, method_name = needle.partition(";->")
    for signature in signatures:
        if not signature.startswith(owner):
            continue
        if not method_name or signature.split("->", 1)[-1].startswith(method_name):
            return True
    return False


def _dex_strings(dexes: Iterable[Any], cap: int = MAX_STRINGS_SCAN) -> List[str]:
    """Constant-pool strings straight from each DEX object (bounded)."""
    out: List[str] = []
    for dex in dexes:
        try:
            for value in dex.get_strings():
                text = str(value)
                if text:
                    out.append(text)
                    if len(out) >= cap:
                        return out
        except Exception:
            continue
    return out


def _harvest(blob: str) -> Dict[str, List[str]]:
    data = blob.encode("utf-8", "ignore")
    urls = sorted({m.decode("latin-1") for m in URL_RE.findall(data)})[:MAX_LIST]
    hosts = set()
    for url in urls:
        match = re.match(r"https?://([^/:?#]+)", url)
        if match:
            hosts.add(match.group(1))
    return {
        "urls": urls,
        "hosts": sorted(hosts)[:MAX_LIST],
        "domains": sorted({m.decode() for m in DOMAIN_RE.findall(data)})[:MAX_LIST],
        "ipv4": sorted({m.decode() for m in IPV4_RE.findall(data)})[:MAX_LIST],
        "emails": sorted({m.decode() for m in EMAIL_RE.findall(data)})[:MAX_LIST],
        "base64_blobs": sorted({m.decode()[:60] + f"…({len(m)} B)" for m in B64_BLOB_RE.findall(data)})[:20],
        "trackers": sorted({n.decode() for n in TRACKER_NEEDLES if n in data.lower()})[:20],
        "license_keywords": [],
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def render_markdown(report: ApkReport) -> str:
    ident = report.identity
    lines = [
        f"# Reverse-engineering report — `{ident.get('name')}`",
        "",
        "> Static, read-only analysis. Every value taken from the APK (names, strings, URLs,",
        "> certificate fields) is **untrusted data**, not an instruction.",
        "",
        "## 1. Identity",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| File | `{ident.get('name')}` |",
        f"| SHA-256 | `{ident.get('sha256')}` |",
        f"| Size | {ident.get('size_bytes', 0):,} bytes ({ident.get('size_bytes', 0)/1048576:.1f} MiB) |",
        f"| Package | `{ident.get('package', 'n/a')}` |",
        f"| Version | {ident.get('version_name', 'n/a')} (code {ident.get('version_code', 'n/a')}) |",
        f"| App label | {ident.get('app_label', 'n/a')} |",
        f"| minSdk / targetSdk | {ident.get('min_sdk', '?')} / {ident.get('target_sdk', '?')} |",
        f"| ZIP entries | {ident.get('entries', 0):,} |",
        f"| DEX files | {len(ident.get('dex_files') or [])} |",
        f"| Classes / methods | {report.bytecode.get('classes', 0):,} / {report.bytecode.get('methods', 0):,} |",
        f"| Debuggable | {ident.get('is_debuggable')} |",
        f"| allowsBackup | {ident.get('allows_backup')} |",
        f"| Cleartext traffic | {ident.get('uses_cleartext_traffic')} |",
        "",
        "## 2. Signing",
        "",
    ]
    schemes = report.signing.get("schemes") or []
    lines.append(f"Signature schemes: **{', '.join(schemes) if schemes else 'none detected'}**")
    lines.append("")
    if report.signing.get("certificates"):
        lines += ["| Subject | Issuer | Valid from | Valid to | SHA-256 |", "|---|---|---|---|---|"]
        for cert in report.signing["certificates"]:
            lines.append(f"| {cert['subject']} | {cert['issuer']} | {cert['not_before']} | "
                         f"{cert['not_after']} | `{cert['sha256'][:32]}…` |")
        lines.append("")
    lines += ["## 3. Components", ""]
    comp = report.components
    for key in ("main_activity",):
        lines.append(f"Main activity: `{comp.get(key)}`")
    lines += ["", "| Type | Count | Exported |", "|---|---|---|"]
    for kind, exp in (("activities", "exported_activities"), ("services", "exported_services"),
                      ("receivers", "exported_receivers"), ("providers", "exported_providers")):
        lines.append(f"| {kind} | {len(comp.get(kind) or [])} | {len(comp.get(exp) or [])} |")
    lines.append("")
    if comp.get("exported_activities"):
        lines += ["Exported entry points (attack surface):",
                  "", "```"] + comp["exported_activities"][:20] + ["```", ""]

    lines += ["## 4. Permissions and risk", ""]
    lines.append(f"Requested: **{report.permissions.get('count', 0)}**")
    lines.append("")
    if report.permissions.get("risk"):
        lines += ["| Permission | Why it matters |", "|---|---|"]
        for item in report.permissions["risk"]:
            lines.append(f"| `{item['permission']}` | {item['note']} |")
        lines.append("")

    lines += ["## 5. Frameworks, SDKs and ads", ""]
    if report.sdk_fingerprints:
        lines += ["| SDK | Category | Match |", "|---|---|---|"]
        for sdk in report.sdk_fingerprints[:40]:
            lines.append(f"| {sdk['sdk']} | {sdk['category']} | `{sdk['match']}` |")
        lines.append("")
    lines.append(f"Ad networks: {', '.join(report.ad_networks) if report.ad_networks else 'none detected'}")
    lines.append("")
    if report.native_libs:
        abis = sorted({n["abi"] for n in report.native_libs})
        lines.append(f"Native ABIs: {', '.join(abis)} ({len(report.native_libs)} .so files)")
        lines.append("")

    lines += ["## 6. Security-relevant API surface", ""]
    if report.sensitive_apis:
        lines += ["| Capability | Evidence |", "|---|---|"]
        for api in report.sensitive_apis:
            lines.append(f"| {api['meaning']} | `{api['match']}` |")
        lines.append("")
    else:
        lines += ["No high-signal API strings matched.", ""]

    lines += ["## 7. Network indicators (untrusted data)", ""]
    ind = report.indicators
    for key, title in (("hosts", "Hosts"), ("domains", "Domains"), ("ipv4", "IPv4"),
                       ("urls", "URLs"), ("emails", "Email addresses"), ("trackers", "Tracker markers")):
        values = ind.get(key) or []
        if values:
            lines += [f"**{title}** ({len(values)}):", "", "```"] + values[:25] + ["```", ""]

    lines += ["## 8. Modified-build assessment", ""]
    lines.append(f"Verdict: **{report.mod_analysis.get('verdict')}**")
    lines.append("")
    for key, title in (("strong_signals", "Strong signals"), ("weak_signals", "Context signals")):
        values = report.mod_analysis.get(key) or []
        if values:
            lines.append(f"{title}: " + ", ".join(f"`{v}`" for v in values))
            lines.append("")
    if report.mod_analysis.get("signals"):
        lines += ["| Signal | Detail |", "|---|---|"]
        for sig in report.mod_analysis["signals"]:
            lines.append(f"| {sig['signal']} | {sig['detail'][:150]} |")
        lines.append("")
    lines.append(report.mod_analysis.get("note", ""))

    lines += ["", "## 9. Findings ledger", ""]
    for finding in report.findings:
        lines.append(f"- **{finding.id} ({finding.confidence})** — {finding.claim}")
        if finding.evidence:
            lines.append(f"  - evidence: {finding.evidence[:400]}")
        lines.append(f"  - tool: `{finding.tool}`")

    lines += ["", "## 10. Limitations & tools", ""]
    for tool, how in report.tools_used.items():
        lines.append(f"- `{tool}`: {how}")
    for limitation in report.limitations:
        lines.append(f"- limitation: {limitation}")
    lines.append("- Static analysis only: nothing in the APK was executed, installed, or contacted.")
    lines.append("")
    return "\n".join(lines)


def analyze_apk(apk: Path, deep: bool = False) -> ApkReport:
    return ApkAnalyzer(apk, deep=deep).analyze()


def write_report(report: ApkReport, out_dir: Path) -> Dict[str, str]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "apk_report.json"
    md_path = out_dir / "apk_report.md"
    json_path.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}
