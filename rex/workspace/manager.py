"""Safe workspace and artifact management with Zip-Slip and symlink escape protection."""

import hashlib
import json
import os
import re
import shutil
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sanitize_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return cleaned or "target"


@dataclass
class WorkspaceRun:
    run_id: str
    root: Path
    raw_dir: Path
    downloaded_dir: Path
    extracted_dir: Path
    generated_dir: Path
    reports_dir: Path
    meta_file: Path
    provenance: Dict[str, str] = field(default_factory=dict)

    def record_metadata(self, extra: Optional[Dict] = None) -> Dict:
        data = {
            "run_id": self.run_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "provenance": self.provenance,
            "artifacts": self.list_artifacts(),
        }
        if extra:
            data.update(extra)
        self.meta_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return data

    def list_artifacts(self) -> List[str]:
        items: List[str] = []
        for p in sorted(self.root.rglob("*")):
            if p.is_file() and p != self.meta_file:
                items.append(str(p.relative_to(self.root)))
        return items


class WorkspaceManager:
    def __init__(self, workspaces_root: Path):
        self.workspaces_root = workspaces_root.resolve()

    def create_run(self, label: str, source_path: Optional[Path] = None, source_url: Optional[str] = None) -> WorkspaceRun:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        digest_prefix = ""
        provenance: Dict[str, str] = {}
        if source_path and source_path.exists() and source_path.is_file():
            sha = compute_sha256(source_path)
            digest_prefix = f"_{sha[:12]}"
            provenance["sha256"] = sha
            provenance["original_path"] = str(source_path.resolve())
        if source_url:
            provenance["source_url"] = source_url

        run_id = f"{ts}_{sanitize_name(label)}{digest_prefix}"
        root = (self.workspaces_root / run_id).resolve()
        try:
            root.relative_to(self.workspaces_root)
        except ValueError as exc:
            raise ValueError("Unsafe workspace path resolution detected.") from exc

        raw_dir = root / "raw"
        downloaded_dir = root / "downloaded"
        extracted_dir = root / "extracted"
        generated_dir = root / "generated"
        reports_dir = root / "reports"
        for d in (raw_dir, downloaded_dir, extracted_dir, generated_dir, reports_dir):
            d.mkdir(parents=True, exist_ok=True)

        run = WorkspaceRun(
            run_id=run_id,
            root=root,
            raw_dir=raw_dir,
            downloaded_dir=downloaded_dir,
            extracted_dir=extracted_dir,
            generated_dir=generated_dir,
            reports_dir=reports_dir,
            meta_file=root / "workspace.json",
            provenance=provenance,
        )

        if source_path and source_path.exists() and source_path.is_file():
            dest_copy = raw_dir / sanitize_name(source_path.name)
            shutil.copy2(source_path, dest_copy)
            provenance["staged_raw"] = str(dest_copy)

        run.record_metadata()
        return run

    def get_run(self, run_id: str) -> WorkspaceRun:
        safe_id = sanitize_name(run_id)
        root = (self.workspaces_root / safe_id).resolve()
        try:
            root.relative_to(self.workspaces_root)
        except ValueError as exc:
            raise FileNotFoundError(f"Workspace run not found: {run_id}") from exc
        if not root.exists():
            raise FileNotFoundError(f"Workspace run not found: {run_id}")
        meta_file = root / "workspace.json"
        prov = {}
        if meta_file.exists():
            prov = json.loads(meta_file.read_text(encoding="utf-8")).get("provenance", {})
        return WorkspaceRun(
            run_id=safe_id,
            root=root,
            raw_dir=root / "raw",
            downloaded_dir=root / "downloaded",
            extracted_dir=root / "extracted",
            generated_dir=root / "generated",
            reports_dir=root / "reports",
            meta_file=meta_file,
            provenance=prov,
        )

    def list_runs(self) -> List[Dict]:
        if not self.workspaces_root.exists():
            return []
        runs = []
        for d in sorted(self.workspaces_root.iterdir(), reverse=True):
            if d.is_dir():
                meta_file = d / "workspace.json"
                if meta_file.exists():
                    runs.append(json.loads(meta_file.read_text(encoding="utf-8")))
                else:
                    runs.append({"run_id": d.name, "provenance": {}})
        return runs

    @staticmethod
    def safe_extract_zip(
        archive_path: Path,
        dest_dir: Path,
        max_total_bytes: int = 200 * 1024 * 1024,
        max_entries: int = 5000,
    ) -> List[str]:
        """Safely extracts a ZIP/JAR/APK archive preventing Zip-Slip, zip-bombs, and symlinks."""
        dest_root = dest_dir.resolve()
        dest_root.mkdir(parents=True, exist_ok=True)
        extracted_files: List[str] = []
        total_uncompressed = 0

        with zipfile.ZipFile(archive_path, "r") as zf:
            infos = zf.infolist()
            if len(infos) > max_entries:
                raise ValueError(f"Archive exceeds maximum allowed entry count ({len(infos)} > {max_entries}).")

            for info in infos:
                # Detect Unix symlink mode (0120000)
                unix_mode = (info.external_attr >> 16) & 0o170000
                if unix_mode == 0o120000:
                    raise ValueError(f"Unsafe symlink entry blocked in archive: {info.filename}")

                # Treat archive names as POSIX paths regardless of host OS. Also reject
                # Windows drive paths and backslash traversal before resolving on disk.
                normalized_name = info.filename.replace("\\", "/")
                archive_parts = normalized_name.split("/")
                if (
                    normalized_name.startswith("/")
                    or any(part == ".." for part in archive_parts)
                    or (archive_parts and ":" in archive_parts[0])
                ):
                    raise ValueError(f"Unsafe path traversal entry blocked in archive: {info.filename}")

                target_path = (dest_root / normalized_name).resolve()
                try:
                    target_path.relative_to(dest_root)
                except ValueError as exc:
                    raise ValueError(f"Path traversal escape blocked: {info.filename}") from exc

                if info.is_dir():
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue

                total_uncompressed += info.file_size
                if total_uncompressed > max_total_bytes:
                    raise ValueError(f"Archive uncompressed size exceeds safety limit ({max_total_bytes} bytes).")

                target_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src, target_path.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
                extracted_files.append(info.filename)

        return extracted_files
