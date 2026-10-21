"""SQLite persistence for the local vulnerability database.

The database lives at ``~/.local/share/vulnstack/vulnstack.db`` by default and
persists between runs. It is a *dataset*, never executed as code. Writes use
transactions and batched statements; WAL mode is enabled for better
concurrency and crash resilience. Foreign keys are enforced so dependent rows
(ranges, references, weaknesses) are cleaned up with their parent CVE.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

from vulnstack import product_mapping
from vulnstack.cve import migrations
from vulnstack.cve.models import Vulnerability
from vulnstack.logging_config import get_logger

log = get_logger("database")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._conn: sqlite3.Connection | None = None

    # ---- lifecycle --------------------------------------------------------

    def connect(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        self._conn = conn
        return conn

    def initialize(self) -> int:
        """Create/upgrade the schema and seed the alias table. Returns schema version."""
        conn = self.connect()
        version = migrations.apply_migrations(conn)
        self._seed_aliases(conn)
        return version

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "Database":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- metadata ---------------------------------------------------------

    def is_initialized(self) -> bool:
        conn = self.connect()
        try:
            cur = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerabilities'"
            )
            return cur.fetchone() is not None
        except sqlite3.DatabaseError:
            return False

    def schema_version(self) -> int:
        conn = self.connect()
        cur = conn.execute("SELECT value FROM database_metadata WHERE key='schema_version'")
        row = cur.fetchone()
        return int(row[0]) if row else 0

    def set_metadata(self, key: str, value: str) -> None:
        conn = self.connect()
        conn.execute(
            "INSERT INTO database_metadata(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        conn.commit()

    def get_metadata(self, key: str) -> str | None:
        conn = self.connect()
        cur = conn.execute("SELECT value FROM database_metadata WHERE key=?", (key,))
        row = cur.fetchone()
        return row[0] if row else None

    # ---- source sync bookkeeping -----------------------------------------

    def record_source_sync(
        self,
        name: str,
        *,
        status: str,
        source_modified: str | None = None,
        error: str | None = None,
        sync_time: str | None = None,
    ) -> None:
        conn = self.connect()
        sync_time = sync_time or _now()
        existing = conn.execute(
            "SELECT last_source_modified FROM data_sources WHERE name=?", (name,)
        ).fetchone()
        # On failure keep the previous watermark so we do not advance past
        # records we never ingested.
        if source_modified is None and existing is not None:
            source_modified = existing[0]
        conn.execute(
            """
            INSERT INTO data_sources(name, last_sync_time, last_source_modified, last_status, last_error)
            VALUES(?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                last_sync_time = excluded.last_sync_time,
                last_source_modified = excluded.last_source_modified,
                last_status = excluded.last_status,
                last_error = excluded.last_error
            """,
            (name, sync_time, source_modified, status, error),
        )
        conn.commit()

    def get_source(self, name: str) -> sqlite3.Row | None:
        conn = self.connect()
        return conn.execute("SELECT * FROM data_sources WHERE name=?", (name,)).fetchone()

    def all_sources(self) -> list[sqlite3.Row]:
        conn = self.connect()
        return list(conn.execute("SELECT * FROM data_sources ORDER BY name"))

    def last_successful_sync(self, name: str) -> str | None:
        row = self.get_source(name)
        if row and row["last_status"] == "success":
            return row["last_source_modified"] or row["last_sync_time"]
        return None

    # ---- alias seeding ----------------------------------------------------

    def _seed_aliases(self, conn: sqlite3.Connection) -> None:
        rows = []
        for alias, canonical in product_mapping.alias_pairs():
            ident = product_mapping.identity_for_canonical(canonical)
            rows.append(
                (
                    alias,
                    canonical,
                    ident.cpe_vendor if ident else None,
                    ident.cpe_product if ident else None,
                )
            )
        conn.executemany(
            "INSERT INTO technology_aliases(alias, canonical, cpe_vendor, cpe_product) "
            "VALUES(?, ?, ?, ?) ON CONFLICT(alias) DO UPDATE SET "
            "canonical = excluded.canonical, cpe_vendor = excluded.cpe_vendor, "
            "cpe_product = excluded.cpe_product",
            rows,
        )
        conn.commit()

    # ---- writes -----------------------------------------------------------

    def upsert_vulnerabilities(self, vulns: Iterable[Vulnerability]) -> tuple[int, int]:
        """Insert or update CVE records in a single transaction.

        Returns ``(inserted, updated)``. Child rows (products, ranges, refs,
        weaknesses) are replaced atomically so structured data is never
        partially applied.
        """
        conn = self.connect()
        inserted = 0
        updated = 0
        try:
            conn.execute("BEGIN")
            for vuln in vulns:
                exists = conn.execute(
                    "SELECT 1 FROM vulnerabilities WHERE cve_id=?", (vuln.cve_id,)
                ).fetchone()
                if exists:
                    updated += 1
                    # Remove dependent rows; FK cascade handles ranges under products.
                    conn.execute("DELETE FROM affected_products WHERE cve_id=?", (vuln.cve_id,))
                    conn.execute("DELETE FROM cve_references WHERE cve_id=?", (vuln.cve_id,))
                    conn.execute("DELETE FROM weaknesses WHERE cve_id=?", (vuln.cve_id,))
                else:
                    inserted += 1
                conn.execute(
                    """
                    INSERT INTO vulnerabilities(
                        cve_id, description, published, last_modified,
                        cvss_score, cvss_version, cvss_vector, severity, status, source)
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        description=excluded.description,
                        published=excluded.published,
                        last_modified=excluded.last_modified,
                        cvss_score=excluded.cvss_score,
                        cvss_version=excluded.cvss_version,
                        cvss_vector=excluded.cvss_vector,
                        severity=excluded.severity,
                        status=excluded.status,
                        source=excluded.source
                    """,
                    (
                        vuln.cve_id,
                        vuln.description,
                        vuln.published,
                        vuln.last_modified,
                        vuln.cvss_score,
                        vuln.cvss_version,
                        vuln.cvss_vector,
                        vuln.severity,
                        vuln.status,
                        vuln.source,
                    ),
                )
                for cwe in dict.fromkeys(vuln.weaknesses):
                    conn.execute(
                        "INSERT OR IGNORE INTO weaknesses(cve_id, cwe) VALUES(?, ?)",
                        (vuln.cve_id, cwe),
                    )
                for ref in vuln.references:
                    conn.execute(
                        "INSERT OR IGNORE INTO cve_references(cve_id, url, ref_type) VALUES(?, ?, ?)",
                        (vuln.cve_id, ref.url, ref.ref_type),
                    )
                for product in vuln.affected:
                    cur = conn.execute(
                        """
                        INSERT INTO affected_products(
                            cve_id, vendor, product, cpe_vendor, cpe_product,
                            cpe23, version, version_scheme)
                        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            vuln.cve_id,
                            product.vendor,
                            product.product,
                            product.cpe_vendor,
                            product.cpe_product,
                            product.cpe23,
                            product.version,
                            product.version_scheme,
                        ),
                    )
                    product_id = cur.lastrowid
                    for rng in product.ranges:
                        conn.execute(
                            """
                            INSERT INTO affected_version_ranges(
                                affected_product_id, version_start, version_start_type,
                                version_end, version_end_type, version_scheme, fixed_version)
                            VALUES(?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                product_id,
                                rng.version_start,
                                rng.version_start_type,
                                rng.version_end,
                                rng.version_end_type,
                                rng.version_scheme,
                                rng.fixed_version,
                            ),
                        )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return inserted, updated

    # ---- reads / stats ----------------------------------------------------

    def count_vulnerabilities(self) -> int:
        conn = self.connect()
        return conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]

    def count_affected_products(self) -> int:
        conn = self.connect()
        return conn.execute("SELECT COUNT(*) FROM affected_products").fetchone()[0]

    def count_version_ranges(self) -> int:
        conn = self.connect()
        return conn.execute("SELECT COUNT(*) FROM affected_version_ranges").fetchone()[0]

    def severity_breakdown(self) -> dict[str, int]:
        conn = self.connect()
        rows = conn.execute(
            "SELECT COALESCE(severity, 'UNKNOWN') AS sev, COUNT(*) AS n "
            "FROM vulnerabilities GROUP BY sev ORDER BY n DESC"
        )
        return {r["sev"]: r["n"] for r in rows}

    def year_breakdown(self) -> dict[str, int]:
        conn = self.connect()
        rows = conn.execute(
            "SELECT substr(cve_id, 5, 4) AS yr, COUNT(*) AS n "
            "FROM vulnerabilities WHERE cve_id LIKE 'CVE-%' GROUP BY yr ORDER BY yr DESC"
        )
        return {r["yr"]: r["n"] for r in rows}

    def get_vulnerability(self, cve_id: str) -> dict | None:
        conn = self.connect()
        row = conn.execute(
            "SELECT * FROM vulnerabilities WHERE cve_id=?", (cve_id.upper(),)
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["weaknesses"] = [
            r["cwe"] for r in conn.execute(
                "SELECT cwe FROM weaknesses WHERE cve_id=?", (row["cve_id"],)
            )
        ]
        result["references"] = [
            dict(r) for r in conn.execute(
                "SELECT url, ref_type FROM cve_references WHERE cve_id=?", (row["cve_id"],)
            )
        ]
        products = []
        for p in conn.execute(
            "SELECT * FROM affected_products WHERE cve_id=?", (row["cve_id"],)
        ):
            prod = dict(p)
            prod["ranges"] = [
                dict(r) for r in conn.execute(
                    "SELECT * FROM affected_version_ranges WHERE affected_product_id=?",
                    (p["id"],),
                )
            ]
            products.append(prod)
        result["affected_products"] = products
        return result

    def search_by_text(self, term: str, limit: int = 50) -> list[dict]:
        """Free-text search across product names and descriptions.

        This is a *discovery* aid only; it is not treated as proof that a
        product is affected. Uses LIKE with escaped wildcards and parameter
        binding (no string interpolation) to stay injection-safe.
        """
        conn = self.connect()
        like = "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        rows = conn.execute(
            """
            SELECT DISTINCT v.cve_id, v.severity, v.cvss_score, v.published, v.description
            FROM vulnerabilities v
            LEFT JOIN affected_products ap ON ap.cve_id = v.cve_id
            WHERE v.cve_id LIKE ? ESCAPE '\\'
               OR v.description LIKE ? ESCAPE '\\'
               OR ap.product LIKE ? ESCAPE '\\'
               OR ap.vendor LIKE ? ESCAPE '\\'
               OR ap.cpe_product LIKE ? ESCAPE '\\'
            ORDER BY v.published DESC
            LIMIT ?
            """,
            (like, like, like, like, like, limit),
        )
        return [dict(r) for r in rows]

    def references_for_many(self, cve_ids: Sequence[str]) -> dict[str, list[dict]]:
        """Batched reference lookup for a set of CVE ids (avoids N+1)."""
        if not cve_ids:
            return {}
        conn = self.connect()
        ids = list(dict.fromkeys(cve_ids))
        qmarks = ",".join("?" * len(ids))
        rows = conn.execute(
            f"SELECT cve_id, url, ref_type FROM cve_references WHERE cve_id IN ({qmarks})",
            ids,
        )
        out: dict[str, list[dict]] = {cid: [] for cid in ids}
        for r in rows:
            out.setdefault(r["cve_id"], []).append({"url": r["url"], "ref_type": r["ref_type"]})
        return out

    def clear(self) -> None:
        """Delete all vulnerability data and sync bookkeeping (keeps schema)."""
        conn = self.connect()
        try:
            conn.execute("BEGIN")
            for table in (
                "affected_version_ranges",
                "affected_products",
                "cve_references",
                "weaknesses",
                "vulnerabilities",
                "data_sources",
            ):
                conn.execute(f"DELETE FROM {table}")
            # Clear sync watermarks but preserve schema_version.
            conn.execute("DELETE FROM database_metadata WHERE key != 'schema_version'")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        conn.execute("VACUUM")

    def file_size_bytes(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    # ---- candidate retrieval (used by the search engine) ------------------

    def candidates_for_products(
        self, cpe_pairs: Sequence[tuple[str, str]]
    ) -> dict[tuple[str, str], list[dict]]:
        """Batched candidate retrieval keyed by (cpe_vendor, cpe_product).

        Uses the ``idx_affected_cpe`` index. Returns, per requested pair, the
        matching affected-product rows (with their version ranges) joined to
        the parent CVE. Avoids N+1 by fetching all products in one query and
        all ranges in a second batched query.
        """
        if not cpe_pairs:
            return {}
        conn = self.connect()
        unique_pairs = list(dict.fromkeys(cpe_pairs))
        placeholders = " OR ".join(["(cpe_vendor = ? AND cpe_product = ?)"] * len(unique_pairs))
        params: list[str] = []
        for vendor, product in unique_pairs:
            params.extend([vendor, product])
        rows = conn.execute(
            f"""
            SELECT ap.id AS ap_id, ap.cve_id, ap.vendor, ap.product,
                   ap.cpe_vendor, ap.cpe_product, ap.cpe23, ap.version, ap.version_scheme,
                   v.description, v.severity, v.cvss_score, v.cvss_version,
                   v.cvss_vector, v.published, v.last_modified, v.source
            FROM affected_products ap
            JOIN vulnerabilities v ON v.cve_id = ap.cve_id
            WHERE {placeholders}
            """,
            params,
        ).fetchall()

        result: dict[tuple[str, str], list[dict]] = {pair: [] for pair in unique_pairs}
        by_ap_id: dict[int, dict] = {}
        for row in rows:
            d = dict(row)
            d["ranges"] = []
            by_ap_id[d["ap_id"]] = d
            key = (d["cpe_vendor"], d["cpe_product"])
            result.setdefault(key, []).append(d)

        if by_ap_id:
            ap_ids = list(by_ap_id.keys())
            qmarks = ",".join("?" * len(ap_ids))
            range_rows = conn.execute(
                f"SELECT * FROM affected_version_ranges "
                f"WHERE affected_product_id IN ({qmarks})",
                ap_ids,
            ).fetchall()
            for r in range_rows:
                by_ap_id[r["affected_product_id"]]["ranges"].append(dict(r))
        return result
