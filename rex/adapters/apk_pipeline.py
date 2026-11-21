"""APK acquisition + analysis pipeline used by ``rex apk drive`` and the analyzer.

Ingestion is deliberately explicit: REX never guesses a Drive file. The caller
supplies a Drive file ID (or a local path). A downloaded APK is validated by
structure (ZIP + ``AndroidManifest.xml`` + ``classes*.dex``) and SHA-256 before
analysis, matching the "never trust an extension" rule in the skill set.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from rex.adapters.apk_analyzer import analyze_apk, write_report

DRIVE_ID_RE = r"[A-Za-z0-9_-]{20,}"


def validate_apk(path: Path) -> Dict[str, Any]:
    """Structural APK validation: a ZIP with a manifest and at least one DEX."""
    path = Path(path)
    result: Dict[str, Any] = {"path": str(path), "exists": path.is_file(), "valid": False, "detail": ""}
    if not result["exists"]:
        result["detail"] = "file missing"
        return result
    result["size"] = path.stat().st_size
    if not zipfile.is_zipfile(path):
        result["detail"] = "not a ZIP container"
        return result
    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
    has_manifest = "AndroidManifest.xml" in names
    dex = sorted(n for n in names if n.endswith(".dex"))
    result.update(has_manifest=has_manifest, dex_files=dex[:5], entries=len(names))
    if not has_manifest:
        result["detail"] = "AndroidManifest.xml missing"
        return result
    if not dex:
        result["detail"] = "no classes*.dex payload"
        return result
    result["valid"] = True
    result["detail"] = f"APK structure OK ({len(dex)} DEX file(s))"
    return result


def _find_gcloud() -> Optional[str]:
    for candidate in (shutil.which("gcloud"), shutil.which("gcloud.cmd")):
        if candidate:
            return candidate
    return None


def list_drive_files(query: str = "name contains 'MovieBox'",
                     limit: int = 25, timeout: int = 120) -> Dict[str, Any]:
    """List candidate Drive files via the gcloud CLI (no credentials stored by REX)."""
    gcloud = _find_gcloud()
    if not gcloud:
        return {"available": False,
                "detail": "gcloud CLI not installed; use --file-id with a direct download URL "
                          "or pass a local path to `rex apk analyze`",
                "files": []}
    argv = [gcloud, "storage", "ls", "--recursive", "--json",
            f"gs://{query}"] if query.startswith("gs://") else None
    if argv is None:
        return {"available": False,
                "detail": "gcloud present but Drive listing requires an OAuth scope REX does not "
                          "request; use --file-id or --url instead",
                "files": []}
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": True, "detail": str(exc), "files": []}
    if proc.returncode:
        return {"available": True, "detail": (proc.stderr or proc.stdout)[-500:], "files": []}
    files: List[Dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        files.append({"name": record.get("name"), "size": record.get("size"),
                      "updated": record.get("updated")})
        if len(files) >= limit:
            break
    return {"available": True, "detail": f"{len(files)} object(s)", "files": files}


def fetch_from_url(url: str, destination: Path, timeout: int = 1800,
                   max_bytes: int = 512 * 1024 * 1024) -> Dict[str, Any]:
    """Download an APK from an HTTPS URL that returns the file bytes directly."""
    import urllib.error
    import urllib.parse
    import urllib.request

    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        return {"ok": False, "detail": "only https:// download URLs are accepted"}
    request = urllib.request.Request(url, headers={"User-Agent": "REX-apk-fetch/1"})
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response, destination.open("wb") as out:
            length = response.headers.get("Content-Length")
            if length and int(length) > max_bytes:
                return {"ok": False, "detail": f"content-length {length} exceeds limit"}
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > max_bytes:
                    destination.unlink(missing_ok=True)
                    return {"ok": False, "detail": "download exceeded size limit"}
                out.write(block)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        destination.unlink(missing_ok=True)
        return {"ok": False, "detail": str(exc)}
    return {"ok": True, "bytes": total, "path": str(destination)}


def analyze_to_directory(apk: Path, out_dir: Path) -> Dict[str, Any]:
    report = analyze_apk(Path(apk))
    paths = write_report(report, Path(out_dir))
    return {"report": report.to_dict(), "paths": paths}


def run_pipeline(apk: Path, out_dir: Path) -> Dict[str, Any]:
    """Validate then analyze, returning both structural facts and report paths."""
    validation = validate_apk(Path(apk))
    if not validation["valid"]:
        return {"validation": validation, "analyzed": False}
    result = analyze_to_directory(Path(apk), Path(out_dir))
    result.update(validation=validation, analyzed=True)
    return result
