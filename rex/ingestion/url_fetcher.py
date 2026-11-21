"""SSRF-Hardened URL, GitHub Repository, and Minecraft Source Ingestion Module."""

import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain", "metadata.google.internal", "169.254.169.254"}


class SsrfSecurityError(ValueError):
    """Raised when a URL fails scheme, hostname, DNS, IP range, or redirect safety validation."""


def is_ip_blocked(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_public_url(
    url: str,
    resolver: Callable[[str], List[str]] = lambda host: [info[4][0] for info in socket.getaddrinfo(host, None)],
) -> urllib.parse.ParseResult:
    """Validates scheme, hostname, and resolved IP addresses against SSRF vectors."""
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise SsrfSecurityError(f"Unsupported or unsafe URL scheme: {parsed.scheme!r}. Only http/https allowed.")

    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise SsrfSecurityError("URL is missing a valid hostname.")

    if host in BLOCKED_HOSTNAMES or host.endswith(".local") or host.endswith(".internal"):
        raise SsrfSecurityError(f"Blocked internal/reserved hostname: {host}")

    # Direct IP literal check
    try:
        if is_ip_blocked(host):
            raise SsrfSecurityError(f"Blocked non-public IP literal: {host}")
        return parsed
    except ValueError:
        pass

    # DNS resolution check
    try:
        resolved_ips = resolver(host)
    except socket.gaierror as exc:
        raise SsrfSecurityError(f"DNS resolution failed for {host}: {exc}") from exc

    if not resolved_ips:
        raise SsrfSecurityError(f"No DNS records resolved for {host}")

    for ip_str in resolved_ips:
        if is_ip_blocked(ip_str):
            raise SsrfSecurityError(f"Blocked DNS resolution to non-public IP {ip_str} for host {host}")

    return parsed


def classify_source_platform(parsed: urllib.parse.ParseResult) -> str:
    host = (parsed.hostname or "").lower()
    if host in ("github.com", "api.github.com", "raw.githubusercontent.com"):
        return "github"
    if host in ("gitlab.com",):
        return "gitlab"
    if host in ("modrinth.com", "api.modrinth.com", "cdn.modrinth.com"):
        return "modrinth"
    if host in ("spigotmc.org", "www.spigotmc.org", "api.spiget.org"):
        return "spigotmc"
    if host in ("curseforge.com", "www.curseforge.com", "api.curseforge.com"):
        return "curseforge"
    return "generic_web"


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, resolver):
        super().__init__()
        self.resolver = resolver

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        abs_url = urllib.parse.urljoin(req.full_url, newurl)
        validate_public_url(abs_url, resolver=self.resolver)
        return super().redirect_request(req, fp, code, msg, headers, abs_url)


@dataclass
class UrlInspectionResult:
    url: str
    platform: str
    status: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "platform": self.platform,
            "status": self.status,
            "metadata": self.metadata,
            "evidence": self.evidence,
            "limitations": self.limitations,
        }


def inspect_remote_url(
    url: str,
    offline_mode: bool = False,
    timeout_sec: int = 12,
    max_bytes: int = 2 * 1024 * 1024,
    github_token: Optional[str] = None,
    resolver: Callable[[str], List[str]] = lambda host: [info[4][0] for info in socket.getaddrinfo(host, None)],
) -> UrlInspectionResult:
    """Safely validates and fetches public metadata for URLs or GitHub repositories."""
    parsed = validate_public_url(url, resolver=resolver)
    platform_name = classify_source_platform(parsed)

    if offline_mode:
        return UrlInspectionResult(
            url=url,
            platform=platform_name,
            status="skipped_offline",
            metadata={"host": parsed.hostname, "path": parsed.path},
            evidence=[f"Validated public URL structure ({platform_name}) without network request"],
            limitations=["Offline mode is enabled; remote metadata fetch was skipped."],
        )

    headers = {"User-Agent": "REX-Reverse-Engineering-Expert/2.0", "Accept": "application/vnd.github+json, application/json, text/html"}
    if platform_name == "github" and github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    target_fetch_url = url
    parts = [p for p in parsed.path.split("/") if p]
    if platform_name == "github" and parsed.hostname == "github.com" and len(parts) >= 2:
        owner, repo = parts[0], parts[1].removesuffix(".git")
        target_fetch_url = f"https://api.github.com/repos/{owner}/{repo}"

    opener = urllib.request.build_opener(_SafeRedirectHandler(resolver))
    req = urllib.request.Request(target_fetch_url, headers=headers)

    try:
        with opener.open(req, timeout=timeout_sec) as resp:
            raw = resp.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise ValueError(f"Remote response exceeded safety limit of {max_bytes} bytes.")
            content_type = resp.headers.get("Content-Type", "")
            meta: Dict[str, Any] = {
                "http_status": resp.status,
                "content_type": content_type,
                "fetched_url": target_fetch_url,
                "bytes_read": len(raw),
            }
            if "json" in content_type or target_fetch_url.startswith("https://api.github.com/"):
                payload = json.loads(raw.decode("utf-8", errors="ignore"))
                if isinstance(payload, dict):
                    for key in ("full_name", "description", "language", "default_branch", "stargazers_count", "license", "topics", "html_url"):
                        if key in payload:
                            meta[key] = payload[key]
            return UrlInspectionResult(
                url=url,
                platform=platform_name,
                status="completed",
                metadata=meta,
                evidence=[f"Fetched public metadata from {target_fetch_url} (HTTP {resp.status})"],
                limitations=["Downloaded artifacts are never executed automatically."],
            )
    except urllib.error.HTTPError as exc:
        return UrlInspectionResult(
            url=url,
            platform=platform_name,
            status="blocked_or_error",
            metadata={"http_status": exc.code},
            limitations=[f"HTTP {exc.code}: Access denied, rate-limited, or requires authentication (never bypassed by REX)."],
        )
    except Exception as exc:
        return UrlInspectionResult(
            url=url,
            platform=platform_name,
            status="error",
            limitations=[f"Network fetch failed: {exc}"],
        )
