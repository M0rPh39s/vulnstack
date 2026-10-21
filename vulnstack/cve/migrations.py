"""Schema definition and versioned migrations.

The schema version is stored in ``database_metadata``. :func:`apply_migrations`
brings a database from whatever version it is at up to :data:`SCHEMA_VERSION`,
so upgrades never silently break an existing database. Each migration is an
idempotent-enough step guarded by the recorded version.
"""

from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 1

_SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS database_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS data_sources (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    name                 TEXT UNIQUE NOT NULL,
    last_sync_time       TEXT,
    last_source_modified TEXT,
    last_status          TEXT,
    last_error           TEXT
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id        TEXT PRIMARY KEY,
    description   TEXT,
    published     TEXT,
    last_modified TEXT,
    cvss_score    REAL,
    cvss_version  TEXT,
    cvss_vector   TEXT,
    severity      TEXT,
    status        TEXT,
    source        TEXT
);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_published ON vulnerabilities(published);

CREATE TABLE IF NOT EXISTS weaknesses (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    cwe    TEXT,
    UNIQUE(cve_id, cwe),
    FOREIGN KEY(cve_id) REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_references (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id   TEXT NOT NULL,
    url      TEXT,
    ref_type TEXT,
    UNIQUE(cve_id, url),
    FOREIGN KEY(cve_id) REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS affected_products (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id         TEXT NOT NULL,
    vendor         TEXT,
    product        TEXT,
    cpe_vendor     TEXT,
    cpe_product    TEXT,
    cpe23          TEXT,
    version        TEXT,
    version_scheme TEXT,
    FOREIGN KEY(cve_id) REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_affected_cpe ON affected_products(cpe_vendor, cpe_product);
CREATE INDEX IF NOT EXISTS idx_affected_product ON affected_products(cpe_product);
CREATE INDEX IF NOT EXISTS idx_affected_cve ON affected_products(cve_id);

CREATE TABLE IF NOT EXISTS affected_version_ranges (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    affected_product_id INTEGER NOT NULL,
    version_start       TEXT,
    version_start_type  TEXT,
    version_end         TEXT,
    version_end_type    TEXT,
    version_scheme      TEXT,
    fixed_version       TEXT,
    FOREIGN KEY(affected_product_id) REFERENCES affected_products(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ranges_product ON affected_version_ranges(affected_product_id);

CREATE TABLE IF NOT EXISTS technology_aliases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alias       TEXT UNIQUE NOT NULL,
    canonical   TEXT NOT NULL,
    cpe_vendor  TEXT,
    cpe_product TEXT
);
"""


def _get_version(conn: sqlite3.Connection) -> int:
    try:
        cur = conn.execute(
            "SELECT value FROM database_metadata WHERE key = 'schema_version'"
        )
        row = cur.fetchone()
        return int(row[0]) if row else 0
    except sqlite3.OperationalError:
        return 0


def _set_version(conn: sqlite3.Connection, version: int) -> None:
    conn.execute(
        "INSERT INTO database_metadata(key, value) VALUES('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(version),),
    )


def apply_migrations(conn: sqlite3.Connection) -> int:
    """Create or upgrade the schema; return the resulting schema version."""
    current = _get_version(conn)
    if current < 1:
        conn.executescript(_SCHEMA_V1)
        _set_version(conn, 1)
        current = 1
    # Future migrations: `if current < 2: ...; _set_version(conn, 2)`.
    conn.commit()
    return current
