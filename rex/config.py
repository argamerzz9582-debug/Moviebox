"""Configuration management, portable paths, environment secret helpers, and logging."""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

SECRET_ENV_KEYS = ("GITHUB_TOKEN", "GITLAB_TOKEN", "MODRINTH_TOKEN", "CURSEFORGE_API_KEY")


class SecretRedactingFilter(logging.Filter):
    """Redacts known environment secret values from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for env_key in SECRET_ENV_KEYS:
            val = os.environ.get(env_key)
            if val and len(val) > 4 and val in msg:
                msg = msg.replace(val, f"<REDACTED:{env_key}>")
        record.msg = msg
        record.args = ()
        return True


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("rex")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
        handler.addFilter(SecretRedactingFilter())
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger


@dataclass
class RexConfig:
    repo_root: Path
    rex_home: Path
    offline_mode: bool = False
    max_download_bytes: int = 50 * 1024 * 1024  # 50 MB default
    request_timeout_sec: int = 15
    command_timeout_sec: int = 120
    allow_dynamic: bool = False
    secrets: Dict[str, str] = field(default_factory=dict, repr=False)

    @classmethod
    def load(
        cls,
        repo_root: Optional[Path] = None,
        home: Optional[Path] = None,
        offline_mode: Optional[bool] = None,
    ) -> "RexConfig":
        root = (repo_root or Path(__file__).resolve().parent.parent).resolve()
        user_home = (home or Path.home()).resolve()
        rex_home = user_home / ".rex"

        cfg_data: Dict[str, Any] = {}
        cfg_file = rex_home / "config.json"
        if cfg_file.exists():
            raw = cfg_file.read_text(encoding="utf-8").strip()
            if raw:
                loaded = json.loads(raw)
                if not isinstance(loaded, dict):
                    raise ValueError(f"Invalid config format in {cfg_file}: expected JSON object.")
                cfg_data = loaded

        env_offline = os.environ.get("REX_OFFLINE", "").lower() in ("1", "true", "yes")
        resolved_offline = offline_mode if offline_mode is not None else bool(cfg_data.get("offline_mode", env_offline))

        max_bytes = int(cfg_data.get("max_download_bytes", 50 * 1024 * 1024))
        req_timeout = int(cfg_data.get("request_timeout_sec", 15))
        cmd_timeout = int(cfg_data.get("command_timeout_sec", 120))
        if max_bytes <= 0 or req_timeout <= 0 or cmd_timeout <= 0:
            raise ValueError("Numeric limits in REX configuration must be positive integers.")

        secrets = {k: os.environ[k] for k in SECRET_ENV_KEYS if os.environ.get(k)}

        return cls(
            repo_root=root,
            rex_home=rex_home,
            offline_mode=resolved_offline,
            max_download_bytes=max_bytes,
            request_timeout_sec=req_timeout,
            command_timeout_sec=cmd_timeout,
            allow_dynamic=False,
            secrets=secrets,
        )

    @property
    def workspaces_dir(self) -> Path:
        return self.rex_home / "workspaces"

    @property
    def backups_dir(self) -> Path:
        return self.rex_home / "backups"

    @property
    def venv_python(self) -> Optional[Path]:
        cand = self.rex_home / "venv" / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
        return cand if cand.exists() else None


def redact_sensitive_text(text: str) -> str:
    """Redacts common bearer tokens, API keys, and private key blocks from report strings."""
    patterns = [
        (r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", "<REDACTED:PRIVATE_KEY>"),
        (r"(?i)(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{12,})['\"]?", r"\1=<REDACTED>"),
        (r"\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,})\b", "<REDACTED:TOKEN>"),
    ]
    out = text
    for pat, repl in patterns:
        out = re.sub(pat, repl, out)
    return out
