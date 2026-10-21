"""Lightweight on-disk HTTP/fingerprint cache.

This cache is distinct from the persistent CVE database: it only stores
reusable *scan-side* data (fetched response metadata) and is safe to clear at
any time. Entries carry a TTL; expired entries are ignored. Cached data never
overrides the CVE database and is never used for credentials or secrets.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from vulnstack import paths
from vulnstack.logging_config import get_logger

log = get_logger("cache")


class Cache:
    def __init__(self, directory: str | Path | None = None, ttl_seconds: int = 3600) -> None:
        self.directory = Path(directory) if directory else paths.default_cache_path()
        self.ttl_seconds = ttl_seconds

    def _path_for(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.directory / f"{digest}.json"

    def get(self, key: str) -> dict | None:
        if self.ttl_seconds <= 0:
            return None
        path = self._path_for(key)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        stored_at = data.get("_stored_at", 0)
        if time.time() - stored_at > self.ttl_seconds:
            return None
        return data.get("payload")

    def set(self, key: str, payload: dict) -> None:
        if self.ttl_seconds <= 0:
            return
        paths.ensure_dir(self.directory)
        path = self._path_for(key)
        try:
            path.write_text(
                json.dumps({"_stored_at": time.time(), "payload": payload}),
                encoding="utf-8",
            )
        except OSError as exc:
            log.debug("cache write failed (non-fatal): %s", exc)

    def clear(self) -> int:
        """Delete all cache entries; return the number removed."""
        if not self.directory.exists():
            return 0
        removed = 0
        for file in self.directory.glob("*.json"):
            try:
                file.unlink()
                removed += 1
            except OSError:
                pass
        return removed
