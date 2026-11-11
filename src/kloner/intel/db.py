"""Local SQLite database (§17): WAL mode, single writer (the main process).

The spec's tables are kept verbatim; ``run_sources``, ``run_samples`` and ``facts`` are additions
kept on purpose (they let ``report``, ``explain`` and ``reverify`` work offline).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from kloner.models import Anchor, Evaluation, EvaluationFacts, Sighting, SourceStatus
from kloner.util.canonical import canonical_bytes
from kloner.util.timeutil import now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs        (run_id TEXT PRIMARY KEY, package TEXT, started_utc TEXT, finished_utc TEXT,
                                        kloner_version TEXT, apksig_version TEXT, anchor_sha256 TEXT,
                                        config_sha256 TEXT, exit_code INTEGER);
CREATE TABLE IF NOT EXISTS anchors     (package TEXT, record_sha256 TEXT, record_json TEXT, stored_utc TEXT,
                                        PRIMARY KEY (package, record_sha256));
CREATE TABLE IF NOT EXISTS samples     (sha256 TEXT PRIMARY KEY, size INTEGER, format TEXT, package TEXT,
                                        version_code INTEGER, version_name TEXT, parent_sha256 TEXT);
CREATE TABLE IF NOT EXISTS sightings   (id INTEGER PRIMARY KEY, run_id TEXT, sample_sha256 TEXT, source TEXT,
                                        store TEXT, offer_url TEXT, final_url TEXT, retrieved_utc TEXT,
                                        claimed_json TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS evaluations (sample_sha256 TEXT, anchor_sha256 TEXT, kloner_version TEXT,
                                        apksig_version TEXT, verdict TEXT, labels_json TEXT, reasons_json TEXT,
                                        verdict_json TEXT,
                                        PRIMARY KEY (sample_sha256, anchor_sha256, kloner_version, apksig_version));
CREATE TABLE IF NOT EXISTS signers     (cert_sha256 TEXT PRIMARY KEY, subject TEXT, issuer TEXT, serial TEXT,
                                        key_alg TEXT, key_bits INTEGER, not_before TEXT, not_after TEXT,
                                        known_key TEXT, first_seen_utc TEXT);
CREATE TABLE IF NOT EXISTS sample_signers (sample_sha256 TEXT, cert_sha256 TEXT, scheme TEXT, min_sdk INTEGER,
                                        max_sdk INTEGER);
CREATE TABLE IF NOT EXISTS payloads    (payload_id TEXT, shape_id TEXT, sample_sha256 TEXT, package TEXT);
CREATE TABLE IF NOT EXISTS findings    (sample_sha256 TEXT, kind TEXT, data_json TEXT);
CREATE TABLE IF NOT EXISTS run_sources (run_id TEXT, source TEXT, status TEXT, reason TEXT, offers INTEGER,
                                        fetched INTEGER, failed INTEGER, stores_json TEXT);
CREATE TABLE IF NOT EXISTS run_samples (run_id TEXT, sample_sha256 TEXT, expected_package TEXT,
                                        parent_sha256 TEXT, verdict TEXT, PRIMARY KEY (run_id, sample_sha256));
CREATE TABLE IF NOT EXISTS facts       (sample_sha256 TEXT, anchor_sha256 TEXT, kloner_version TEXT,
                                        apksig_version TEXT, facts_json TEXT,
                                        PRIMARY KEY (sample_sha256, anchor_sha256, kloner_version, apksig_version));
CREATE TABLE IF NOT EXISTS run_anchors (run_id TEXT, package TEXT, record_sha256 TEXT,
                                        PRIMARY KEY (run_id, package));
CREATE TABLE IF NOT EXISTS run_meta    (run_id TEXT PRIMARY KEY, command TEXT, report_dir TEXT);
CREATE INDEX IF NOT EXISTS idx_sightings_sample ON sightings(sample_sha256);
CREATE INDEX IF NOT EXISTS idx_sample_signers_cert ON sample_signers(cert_sha256);
CREATE INDEX IF NOT EXISTS idx_payloads_id ON payloads(payload_id);
CREATE INDEX IF NOT EXISTS idx_payloads_shape ON payloads(shape_id);
"""


def verdict_json(ev: Evaluation) -> str:
    """Canonical verdict JSON: the byte string ``kloner reverify`` must reproduce exactly."""
    return canonical_bytes(ev.model_dump(mode="json", by_alias=True)).decode("utf-8")


class IntelDB:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.conn = sqlite3.connect(path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def commit(self) -> None:
        self.conn.commit()

    # -- writes -------------------------------------------------------------------------------

    def put_anchor(self, anchor: Anchor) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO anchors VALUES (?,?,?,?)",
            (
                anchor.package,
                anchor.record_sha256,
                json.dumps(anchor.model_dump(mode="json", by_alias=True), sort_keys=True),
                now_iso(),
            ),
        )
        self.conn.commit()

    def start_run(
        self,
        run_id: str,
        package: str | None,
        kloner_version: str,
        apksig_version: str | None,
        anchor_sha: str | None,
        config_sha: str,
        started: str,
    ) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?,?,?)",
            (run_id, package, started, None, kloner_version, apksig_version, anchor_sha, config_sha, None),
        )
        self.conn.commit()

    def finish_run(self, run_id: str, exit_code: int, finished: str) -> None:
        self.conn.execute("UPDATE runs SET finished_utc=?, exit_code=? WHERE run_id=?", (finished, exit_code, run_id))
        self.conn.commit()

    def put_run_anchors(self, run_id: str, anchors: Iterable[Anchor]) -> None:
        for a in anchors:
            self.put_anchor(a)
            self.conn.execute("INSERT OR REPLACE INTO run_anchors VALUES (?,?,?)", (run_id, a.package, a.record_sha256))
        self.conn.commit()

    def run_anchor_snapshot(self, run_id: str) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for r in self.conn.execute("SELECT package, record_sha256 FROM run_anchors WHERE run_id=?", (run_id,)):
            rec = self.anchor_record(str(r["package"]), str(r["record_sha256"]))
            if rec is not None:
                out[str(r["package"])] = rec
        return out

    def put_run_meta(self, run_id: str, command: str, report_dir: str) -> None:
        self.conn.execute("INSERT OR REPLACE INTO run_meta VALUES (?,?,?)", (run_id, command, report_dir))
        self.conn.commit()

    def run_meta(self, run_id: str) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self.conn.execute("SELECT * FROM run_meta WHERE run_id=?", (run_id,)).fetchone()
        return row

    def put_source_status(self, run_id: str, st: SourceStatus) -> None:
        self.conn.execute(
            "INSERT INTO run_sources VALUES (?,?,?,?,?,?,?,?)",
            (run_id, st.source, st.status, st.reason, st.offers, st.fetched, st.failed, json.dumps(st.stores)),
        )

    def put_sample(self, ev: Evaluation, parent: str | None) -> None:
        self.conn.execute(
            "INSERT INTO samples VALUES (?,?,?,?,?,?,?) ON CONFLICT(sha256) DO UPDATE SET "
            "format=excluded.format, package=excluded.package, version_code=excluded.version_code, "
            "version_name=excluded.version_name, parent_sha256=COALESCE(samples.parent_sha256, excluded.parent_sha256)",
            (ev.sample_sha256, ev.size, ev.format, ev.package, ev.version_code, ev.version_name, parent),
        )

    def put_run_sample(self, run_id: str, ev: Evaluation, expected: str | None, parent: str | None) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO run_samples VALUES (?,?,?,?,?)",
            (run_id, ev.sample_sha256, expected, parent, ev.verdict.value),
        )

    def put_sighting(self, run_id: str, s: Sighting, status: str = "OK") -> None:
        self.conn.execute(
            "INSERT INTO sightings (run_id, sample_sha256, source, store, offer_url, final_url, retrieved_utc, "
            "claimed_json, status) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                run_id,
                s.sample_sha256,
                s.source,
                s.store,
                s.offer_url,
                s.final_url,
                s.retrieved_utc,
                json.dumps(s.claimed.model_dump(mode="json"), sort_keys=True),
                status,
            ),
        )

    def put_evaluation(self, ev: Evaluation, facts: EvaluationFacts | None) -> None:
        anchor = ev.anchor_record_sha256 or ""
        ver = ev.apksig_version or ""
        self.conn.execute(
            "INSERT OR REPLACE INTO evaluations VALUES (?,?,?,?,?,?,?,?)",
            (
                ev.sample_sha256,
                anchor,
                ev.kloner_version,
                ver,
                ev.verdict.value,
                json.dumps(ev.label_codes()),
                json.dumps(ev.reasons),
                verdict_json(ev),
            ),
        )
        if facts is not None:
            self.conn.execute(
                "INSERT OR REPLACE INTO facts VALUES (?,?,?,?,?)",
                (
                    ev.sample_sha256,
                    anchor,
                    ev.kloner_version,
                    ver,
                    json.dumps(facts.model_dump(mode="json", by_alias=True), sort_keys=True),
                ),
            )
        certs = facts.native_inventory.certs if facts and facts.native_inventory else {}
        self.conn.execute("DELETE FROM sample_signers WHERE sample_sha256=?", (ev.sample_sha256,))
        for s in ev.signers:
            info = certs.get(s.cert_sha256)
            self.conn.execute(
                "INSERT OR IGNORE INTO signers VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    s.cert_sha256,
                    s.subject,
                    s.issuer,
                    info.serial if info else None,
                    s.key_algorithm,
                    s.key_bits,
                    info.not_before if info else None,
                    info.not_after if info else None,
                    s.known_key,
                    now_iso(),
                ),
            )
            for scheme in s.schemes or ["unknown"]:
                self.conn.execute(
                    "INSERT INTO sample_signers VALUES (?,?,?,?,?)",
                    (ev.sample_sha256, s.cert_sha256, scheme, None, None),
                )

    def put_payload(self, payload_id: str, shape_id: str, sample: str, package: str | None) -> None:
        self.conn.execute("DELETE FROM payloads WHERE sample_sha256=?", (sample,))
        self.conn.execute("INSERT INTO payloads VALUES (?,?,?,?)", (payload_id, shape_id, sample, package))

    def put_finding(self, sample: str, kind: str, data: dict[str, Any]) -> None:
        self.conn.execute("DELETE FROM findings WHERE sample_sha256=? AND kind=?", (sample, kind))
        self.conn.execute("INSERT INTO findings VALUES (?,?,?)", (sample, kind, json.dumps(data, sort_keys=True)))

    # -- reads --------------------------------------------------------------------------------

    def run(self, run_id: str) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self.conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return row

    def latest_run(self) -> str | None:
        row = self.conn.execute("SELECT run_id FROM runs ORDER BY started_utc DESC LIMIT 1").fetchone()
        return str(row["run_id"]) if row else None

    def run_samples(self, run_id: str) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM run_samples WHERE run_id=? ORDER BY sample_sha256", (run_id,)))

    def run_sources(self, run_id: str) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM run_sources WHERE run_id=?", (run_id,)))

    def anchor_record(self, package: str, record_sha256: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT record_json FROM anchors WHERE package=? AND record_sha256=?", (package, record_sha256)
        ).fetchone()
        return json.loads(row["record_json"]) if row else None

    def evaluation(self, sample: str, anchor_sha: str | None = None) -> sqlite3.Row | None:
        if anchor_sha is not None:
            row: sqlite3.Row | None = self.conn.execute(
                "SELECT * FROM evaluations WHERE sample_sha256=? AND anchor_sha256=? ORDER BY rowid DESC LIMIT 1",
                (sample, anchor_sha),
            ).fetchone()
            return row
        row = self.conn.execute(
            "SELECT * FROM evaluations WHERE sample_sha256=? ORDER BY rowid DESC LIMIT 1", (sample,)
        ).fetchone()
        return row

    def facts_json(self, sample: str, anchor_sha: str | None) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT facts_json FROM facts WHERE sample_sha256=? AND anchor_sha256=? ORDER BY rowid DESC LIMIT 1",
            (sample, anchor_sha or ""),
        ).fetchone()
        return json.loads(row["facts_json"]) if row else None

    def sightings(self, sample: str, run_id: str | None = None) -> list[sqlite3.Row]:
        if run_id:
            return list(
                self.conn.execute(
                    "SELECT * FROM sightings WHERE sample_sha256=? AND run_id=? ORDER BY id", (sample, run_id)
                )
            )
        return list(self.conn.execute("SELECT * FROM sightings WHERE sample_sha256=? ORDER BY id", (sample,)))

    def seen_before(self, sample: str, run_id: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM run_samples WHERE sample_sha256=? AND run_id<>? LIMIT 1", (sample, run_id)
        ).fetchone()
        return row is not None

    def signer_census(self, cert: str) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT s.package, s.sha256 AS sample, e.verdict, MIN(g.retrieved_utc) AS first_seen, "
                "MAX(g.retrieved_utc) AS last_seen, GROUP_CONCAT(DISTINCT g.source) AS sources "
                "FROM sample_signers ss JOIN samples s ON s.sha256 = ss.sample_sha256 "
                "LEFT JOIN evaluations e ON e.sample_sha256 = s.sha256 "
                "LEFT JOIN sightings g ON g.sample_sha256 = s.sha256 "
                "WHERE ss.cert_sha256=? GROUP BY s.sha256 ORDER BY s.package",
                (cert,),
            )
        )

    def payload_census(self, payload: str) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT DISTINCT payload_id, shape_id, sample_sha256, package FROM payloads "
                "WHERE payload_id=? OR shape_id=? ORDER BY package, sample_sha256",
                (payload, payload),
            )
        )

    def package_census(self, package: str) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT s.sha256, s.version_code, s.version_name, e.verdict, e.labels_json, "
                "GROUP_CONCAT(DISTINCT g.source) AS sources, COUNT(g.id) AS sightings "
                "FROM samples s LEFT JOIN evaluations e ON e.sample_sha256 = s.sha256 "
                "LEFT JOIN sightings g ON g.sample_sha256 = s.sha256 WHERE s.package=? "
                "GROUP BY s.sha256 ORDER BY s.version_code DESC",
                (package,),
            )
        )

    def source_census(self) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT g.source, e.verdict, COUNT(DISTINCT g.sample_sha256) AS samples, "
                "SUM(CASE WHEN g.status LIKE '%METADATA_MISMATCH%' THEN 1 ELSE 0 END) AS mismatches "
                "FROM sightings g LEFT JOIN evaluations e ON e.sample_sha256 = g.sample_sha256 "
                "GROUP BY g.source, e.verdict ORDER BY g.source, e.verdict"
            )
        )

    def foreign_signer_packages(self, cert: str, exclude_sample: str) -> list[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT s.package FROM sample_signers ss JOIN samples s ON s.sha256 = ss.sample_sha256 "
            "JOIN evaluations e ON e.sample_sha256 = s.sha256 "
            "WHERE ss.cert_sha256=? AND s.sha256<>? AND e.verdict IN ('FORGED','IMPERSONATOR','TAMPERED')",
            (cert, exclude_sample),
        )
        return sorted(str(r["package"]) for r in rows if r["package"])

    def payload_packages(self, payload_id: str, shape_id: str, exclude_sample: str) -> list[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT package FROM payloads WHERE (payload_id=? OR shape_id=?) AND sample_sha256<>?",
            (payload_id, shape_id, exclude_sample),
        )
        return sorted(str(r["package"]) for r in rows if r["package"])

    def executemany(self, sql: str, rows: Iterable[tuple[Any, ...]]) -> None:
        self.conn.executemany(sql, rows)
