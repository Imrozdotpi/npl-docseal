"""
audit_db.py — SQLite-backed audit logging for NPL DocSeal.

Logs every real /api/seal and /api/verify operation for the Audit Log
dashboard (Tab 3). Uses only the stdlib sqlite3 module.
"""

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Optional

DB_DIR = Path("data")
DB_PATH = DB_DIR / "audit_log.db"

_write_lock = threading.Lock()

_COLUMNS = [
    "timestamp", "operation_type", "filename", "file_size_bytes", "file_format",
    "parse_duration_ms", "merkle_duration_ms", "sign_duration_ms",
    "verify_sig_duration_ms", "encrypt_duration_ms", "decrypt_duration_ms",
    "compare_duration_ms", "blockchain_duration_ms", "total_duration_ms",
    "field_count", "intact_count", "tampered_count", "missing_count",
    "tampered_field_names",
    "signature_valid", "root_matches",
    "tx_hash", "block_number", "confirmation_time_ms", "etherscan_url",
    "test_scenario", "overall_status",
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    operation_type TEXT NOT NULL,
    filename TEXT,
    file_size_bytes INTEGER,
    file_format TEXT,

    parse_duration_ms REAL,
    merkle_duration_ms REAL,
    sign_duration_ms REAL,
    verify_sig_duration_ms REAL,
    encrypt_duration_ms REAL,
    decrypt_duration_ms REAL,
    compare_duration_ms REAL,
    blockchain_duration_ms REAL,
    total_duration_ms REAL,

    field_count INTEGER,
    intact_count INTEGER,
    tampered_count INTEGER,
    missing_count INTEGER,
    tampered_field_names TEXT,

    signature_valid INTEGER,
    root_matches INTEGER,

    tx_hash TEXT,
    block_number INTEGER,
    confirmation_time_ms REAL,
    etherscan_url TEXT,

    test_scenario TEXT,

    overall_status TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_timestamp ON operations(timestamp);
CREATE INDEX IF NOT EXISTS idx_operation_type ON operations(operation_type);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create data/ dir and audit_log.db with schema if not already present."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    with _write_lock:
        conn = _connect()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()


def log_operation(record: dict) -> int:
    """Insert one row. Missing keys default to None. Returns inserted row id."""
    row = {col: record.get(col) for col in _COLUMNS}
    if row.get("test_scenario") is None:
        row["test_scenario"] = "real_usage"
    if row.get("overall_status") is None:
        row["overall_status"] = "FAIL"
    if row.get("tampered_field_names") is not None and not isinstance(row["tampered_field_names"], str):
        row["tampered_field_names"] = json.dumps(row["tampered_field_names"])

    columns = ", ".join(_COLUMNS)
    placeholders = ", ".join(f":{c}" for c in _COLUMNS)

    with _write_lock:
        conn = _connect()
        try:
            cur = conn.execute(
                f"INSERT INTO operations ({columns}) VALUES ({placeholders})", row
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


def _row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)


def get_all_operations(limit: int = 500) -> list[dict]:
    """Return most recent operations, newest first."""
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT * FROM operations ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [_row_to_dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_operations_since(timestamp_iso: str) -> list[dict]:
    """For polling — returns rows with timestamp > given value, oldest first."""
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT * FROM operations WHERE timestamp > ? ORDER BY timestamp ASC",
            (timestamp_iso,),
        )
        return [_row_to_dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_summary_stats() -> dict:
    conn = _connect()
    try:
        total_operations = conn.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
        total_seals = conn.execute(
            "SELECT COUNT(*) FROM operations WHERE operation_type = 'seal'"
        ).fetchone()[0]
        total_verifies = conn.execute(
            "SELECT COUNT(*) FROM operations WHERE operation_type = 'verify'"
        ).fetchone()[0]

        avg_seal_duration_ms = conn.execute(
            "SELECT AVG(total_duration_ms) FROM operations WHERE operation_type = 'seal'"
        ).fetchone()[0]
        avg_verify_duration_ms = conn.execute(
            "SELECT AVG(total_duration_ms) FROM operations WHERE operation_type = 'verify'"
        ).fetchone()[0]

        totals = conn.execute(
            "SELECT COALESCE(SUM(field_count),0), COALESCE(SUM(intact_count),0), "
            "COALESCE(SUM(tampered_count),0) FROM operations"
        ).fetchone()
        total_fields_checked, total_intact, total_tampered = totals

        pass_count = conn.execute(
            "SELECT COUNT(*) FROM operations WHERE overall_status = 'PASS'"
        ).fetchone()[0]
        pass_rate_percent = (pass_count / total_operations * 100.0) if total_operations else 0.0

        avg_blockchain_confirmation_ms = conn.execute(
            "SELECT AVG(confirmation_time_ms) FROM operations WHERE confirmation_time_ms IS NOT NULL"
        ).fetchone()[0]

        return {
            "total_operations": total_operations,
            "total_seals": total_seals,
            "total_verifies": total_verifies,
            "avg_seal_duration_ms": avg_seal_duration_ms,
            "avg_verify_duration_ms": avg_verify_duration_ms,
            "total_fields_checked": total_fields_checked,
            "total_intact": total_intact,
            "total_tampered": total_tampered,
            "pass_rate_percent": pass_rate_percent,
            "avg_blockchain_confirmation_ms": avg_blockchain_confirmation_ms,
        }
    finally:
        conn.close()


def get_field_tamper_frequency() -> dict:
    """{field_name: tamper_count} across all logged operations."""
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT tampered_field_names FROM operations WHERE tampered_field_names IS NOT NULL"
        )
        freq: dict[str, int] = {}
        for (raw,) in cur.fetchall():
            try:
                names = json.loads(raw)
            except (TypeError, ValueError):
                continue
            if not isinstance(names, list):
                continue
            for name in names:
                freq[name] = freq.get(name, 0) + 1
        return freq
    finally:
        conn.close()


def get_test_coverage_matrix() -> list[dict]:
    """Rows grouped by (file_format, test_scenario) with pass/fail counts."""
    conn = _connect()
    try:
        cur = conn.execute(
            """
            SELECT
                COALESCE(file_format, 'unknown') AS file_format,
                COALESCE(test_scenario, 'real_usage') AS test_scenario,
                SUM(CASE WHEN overall_status = 'PASS' THEN 1 ELSE 0 END) AS pass_count,
                SUM(CASE WHEN overall_status = 'FAIL' THEN 1 ELSE 0 END) AS fail_count
            FROM operations
            GROUP BY file_format, test_scenario
            ORDER BY file_format, test_scenario
            """
        )
        return [_row_to_dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_duration_breakdown_series(operation_type: str, limit: int = 50) -> list[dict]:
    """Last N operations of a given type with step-by-step duration breakdown, oldest first."""
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT * FROM operations WHERE operation_type = ? ORDER BY id DESC LIMIT ?",
            (operation_type, limit),
        )
        rows = [_row_to_dict(r) for r in cur.fetchall()]
        rows.reverse()
        return rows
    finally:
        conn.close()


def clear_all_logs() -> None:
    """Wipe the operations table."""
    with _write_lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM operations")
            conn.commit()
        finally:
            conn.close()
