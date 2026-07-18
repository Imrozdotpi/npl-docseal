"""
registry_db.py: Public certificate registry for NPL DocSeal.

Backs the registry-based verification model: instead of shipping the
Merkle proof, signature, and blockchain receipt bundled in a ZIP with the
document, that proof is published here at seal time, keyed by
certificate_number. A third party who only has the plain document (no
password, no bundle) can be verified against this registry directly via
POST /api/public/verify: that's the entire point of this file existing.

Deliberately a separate SQLite file from data/audit_log.db: the audit log
is NPL's internal telemetry, this is public-facing certificate data, and
the two are never merged.
"""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DB_DIR = Path("data")
DB_PATH = DB_DIR / "public_registry.db"

_write_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS registry (
    certificate_number TEXT PRIMARY KEY,
    merkle_root TEXT NOT NULL,
    field_hashes TEXT NOT NULL,
    signature_hex TEXT NOT NULL,
    public_key_fingerprint TEXT,
    tx_hash TEXT,
    block_number INTEGER,
    etherscan_url TEXT,
    sealed_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    revoked_at TEXT,
    revoked_reason TEXT,
    revocation_signature_hex TEXT
);

CREATE INDEX IF NOT EXISTS idx_cert_number ON registry(certificate_number);
"""


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_registry_db() -> None:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    with _write_lock:
        conn = _get_conn()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()


def register_certificate(
    certificate_number: str,
    merkle_root: str,
    field_hashes: dict,
    signature_hex: str,
    public_key_fingerprint: str,
    tx_hash: Optional[str],
    block_number: Optional[int],
    etherscan_url: Optional[str],
) -> None:
    """INSERT OR REPLACE: re-sealing a certificate_number (e.g. after
    fixing a mistake) overwrites its prior registry entry entirely."""
    sealed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with _write_lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO registry (
                    certificate_number, merkle_root, field_hashes, signature_hex,
                    public_key_fingerprint, tx_hash, block_number, etherscan_url,
                    sealed_at, revoked, revoked_at, revoked_reason, revocation_signature_hex
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, NULL)
                """,
                (
                    certificate_number,
                    merkle_root,
                    json.dumps(field_hashes),
                    signature_hex,
                    public_key_fingerprint,
                    tx_hash,
                    block_number,
                    etherscan_url,
                    sealed_at,
                ),
            )
            conn.commit()
        finally:
            conn.close()


def lookup_certificate(certificate_number: str) -> Optional[dict]:
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM registry WHERE certificate_number = ?", (certificate_number,)
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return None

    result = dict(row)
    result["field_hashes"] = json.loads(result["field_hashes"])
    result["revoked"] = bool(result["revoked"])
    return result


def mark_revoked(
    certificate_number: str,
    reason: str,
    revocation_signature_hex: str,
    revoked_at: Optional[str] = None,
) -> bool:
    """
    revoked_at should be the exact timestamp the caller already signed into
    the revocation payload (cert_number:reason:revoked_at) - passing it in
    rather than generating a fresh one here keeps the stored value and the
    signed value identical, so the signature stays independently
    re-verifiable later. Only falls back to "now" if the caller has no
    signed timestamp to give (there shouldn't be a legitimate case of that
    in this codebase, but the parameter is optional rather than required
    to avoid breaking direct callers that don't sign anything).
    """
    if revoked_at is None:
        revoked_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with _write_lock:
        conn = _get_conn()
        try:
            existing = conn.execute(
                "SELECT 1 FROM registry WHERE certificate_number = ?", (certificate_number,)
            ).fetchone()
            if existing is None:
                return False

            conn.execute(
                """
                UPDATE registry
                SET revoked = 1, revoked_at = ?, revoked_reason = ?, revocation_signature_hex = ?
                WHERE certificate_number = ?
                """,
                (revoked_at, reason, revocation_signature_hex, certificate_number),
            )
            conn.commit()
            return True
        finally:
            conn.close()


def is_revoked(certificate_number: str) -> Optional[dict]:
    entry = lookup_certificate(certificate_number)
    if entry is None or not entry["revoked"]:
        return None
    return {"revoked_at": entry["revoked_at"], "revoked_reason": entry["revoked_reason"]}
