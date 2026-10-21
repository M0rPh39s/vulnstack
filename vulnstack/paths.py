"""Platform-appropriate path handling following the XDG Base Directory spec.

All paths honour the standard XDG environment variables when set, falling back
to the conventional ``~/.local/share``, ``~/.config`` and ``~/.cache`` roots.
Directories are created lazily with private (0700) permissions.
"""

from __future__ import annotations

import os
from pathlib import Path

_APP = "vulnstack"


def _xdg(env_var: str, default_suffix: str) -> Path:
    base = os.environ.get(env_var)
    if base:
        return Path(base).expanduser() / _APP
    return Path.home() / default_suffix / _APP


def data_dir() -> Path:
    """Persistent application data (the CVE database lives here)."""
    return _xdg("XDG_DATA_HOME", ".local/share")


def config_dir() -> Path:
    """User configuration directory."""
    return _xdg("XDG_CONFIG_HOME", ".config")


def cache_dir() -> Path:
    """Ephemeral cache directory (safe to delete at any time)."""
    return _xdg("XDG_CACHE_HOME", ".cache")


def ensure_dir(path: Path) -> Path:
    """Create ``path`` (and parents) with private permissions if missing."""
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        # Best effort: some filesystems (e.g. certain network mounts) refuse chmod.
        pass
    return path


def default_database_path() -> Path:
    return data_dir() / "vulnstack.db"


def default_config_path() -> Path:
    return config_dir() / "config.toml"


def default_cache_path() -> Path:
    return cache_dir()
