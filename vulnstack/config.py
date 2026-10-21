"""Configuration handling.

Precedence (lowest to highest):

    built-in defaults  <  config file  <  environment variables  <  CLI options

The config file is TOML at ``~/.config/vulnstack/config.toml`` (override with
``VULNSTACK_CONFIG``). CLI options are applied by the caller after loading.

Secrets (the optional ``NVD_API_KEY``) are read from the environment only and
are never written to the config file, reports or logs.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from vulnstack import paths
from vulnstack.logging_config import get_logger

log = get_logger("config")

VALID_FORMATS = ("terminal", "json", "html")
VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


@dataclass
class Config:
    # Networking / scanning
    timeout: float = 15.0
    max_redirects: int = 5
    max_response_bytes: int = 5 * 1024 * 1024  # 5 MiB
    user_agent: str = "VulnStack/0.1 (+https://github.com/m0rph39s/vulnstack)"
    allow_private_targets: bool = False

    # Reporting
    default_format: str = "terminal"
    output_dir: str = field(default_factory=lambda: str(Path.cwd()))

    # Storage
    database_path: str = field(default_factory=lambda: str(paths.default_database_path()))
    cache_dir: str = field(default_factory=lambda: str(paths.default_cache_path()))
    cache_ttl_seconds: int = 3600

    # Update behaviour
    default_source: str = "repo"   # "repo" = pull the published database; "nvd" = query NVD directly
    logging_level: str = "WARNING"

    # ---- validation -------------------------------------------------------

    def validate(self) -> None:
        if self.timeout <= 0:
            raise ValueError("timeout must be a positive number")
        if self.max_redirects < 0:
            raise ValueError("max_redirects must be >= 0")
        if self.max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if self.default_format not in VALID_FORMATS:
            raise ValueError(
                f"default_format must be one of {VALID_FORMATS}, got {self.default_format!r}"
            )
        if self.cache_ttl_seconds < 0:
            raise ValueError("cache_ttl_seconds must be >= 0")
        if self.logging_level not in VALID_LOG_LEVELS:
            raise ValueError(
                f"logging_level must be one of {VALID_LOG_LEVELS}, got {self.logging_level!r}"
            )

    # ---- (de)serialisation ------------------------------------------------

    def to_public_dict(self) -> dict[str, Any]:
        """Return a dict safe to display (no secrets are stored on Config)."""
        return asdict(self)


def _config_file_path() -> Path:
    override = os.environ.get("VULNSTACK_CONFIG")
    if override:
        return Path(override).expanduser()
    return paths.default_config_path()


def _apply_file(cfg: Config, path: Path) -> None:
    if not path.exists():
        return
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        log.warning("Ignoring unreadable config file %s: %s", path, exc)
        return
    for key, value in data.items():
        if hasattr(cfg, key):
            setattr(cfg, key, value)
        else:
            log.warning("Ignoring unknown config key %r in %s", key, path)


_ENV_MAP = {
    "VULNSTACK_TIMEOUT": ("timeout", float),
    "VULNSTACK_FORMAT": ("default_format", str),
    "VULNSTACK_OUTPUT_DIR": ("output_dir", str),
    "VULNSTACK_DATABASE": ("database_path", str),
    "VULNSTACK_CACHE_DIR": ("cache_dir", str),
    "VULNSTACK_LOG_LEVEL": ("logging_level", str),
    "VULNSTACK_ALLOW_PRIVATE": ("allow_private_targets", lambda v: v.lower() in ("1", "true", "yes")),
}


def _apply_env(cfg: Config) -> None:
    for env_var, (attr, caster) in _ENV_MAP.items():
        raw = os.environ.get(env_var)
        if raw is None:
            continue
        try:
            setattr(cfg, attr, caster(raw))
        except (ValueError, TypeError) as exc:
            log.warning("Ignoring invalid %s=%r: %s", env_var, raw, exc)


def load_config() -> Config:
    """Load effective configuration from defaults, file and environment."""
    cfg = Config()
    _apply_file(cfg, _config_file_path())
    _apply_env(cfg)
    cfg.validate()
    return cfg


def config_file_location() -> Path:
    return _config_file_path()


def nvd_api_key() -> str | None:
    """Return the NVD API key from the environment, if set (never logged)."""
    key = os.environ.get("NVD_API_KEY")
    return key.strip() if key and key.strip() else None
