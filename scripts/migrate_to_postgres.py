"""
scripts/migrate_to_postgres.py

One-time (but safely re-runnable) migration: copies every row out of the
old per-machine SQLite files -

    data/verification_registry.db  (table: verification_registry)
    data/audit_log.db              (table: operations)

- into the shared PostgreSQL database (DATABASE_URL), as the
verification_registry and audit_log tables respectively.

Data safety: both source SQLite files are opened strictly read-only
(sqlite3 URI mode=ro) and are never written to or deleted by this
script. Keep them as a backup after migrating; nothing here needs them
again once the shared Postgres database is in use.

What gets preserved exactly as it was:
    - Every verification_registry row: certificate_number (primary key),
      merkle_root, field_hashes, signature_hex, public_key_fingerprint,
      tx_hash, block_number, etherscan_url, sealed_at, issue_date,
      expiry_date, status, created_at.
    - Every audit_log row, including its original integer id (so
      existing audit history keeps the same ids rather than being
      renumbered). The audit_log_id_seq sequence is reset afterward so
      new rows continue from the correct next id instead of colliding
      with migrated ones.

Re-running this script is safe:
    - verification_registry rows are upserted (same last-write-wins
      behaviour the app itself already uses for re-sealed certificates).
    - audit_log rows are skipped if that id already exists in Postgres,
      rather than inserted a second time.

Usage:
    python scripts/migrate_to_postgres.py
    python scripts/migrate_to_postgres.py --verification-db path/to/verification_registry.db --audit-db path/to/audit_log.db

Requires DATABASE_URL to be set (.env is auto-loaded the same way the
rest of the app loads it, via core.timestamper's loader import).
"""

import argparse
import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Triggers the same .env auto-load the rest of the app relies on.
import core.timestamper  # noqa: E402, F401

from sqlalchemy import text  # noqa: E402

from core.db import SessionLocal  # noqa: E402
from core.verification_db import VerificationRegistry  # noqa: E402
from core.audit_db import AuditLog, _COLUMNS as AUDIT_COLUMNS  # noqa: E402


def _open_readonly(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _parse_datetime(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def migrate_verification_registry(db_path: Path) -> int:
    if not db_path.exists():
        print(f"[skip] {db_path} not found, nothing to migrate for the Verification Registry.")
        return 0

    conn = _open_readonly(db_path)
    session = SessionLocal()
    migrated = 0
    try:
        rows = conn.execute("SELECT * FROM verification_registry").fetchall()
        for row in rows:
            row = dict(row)
            field_hashes = row.get("field_hashes")
            if isinstance(field_hashes, str):
                try:
                    field_hashes = json.loads(field_hashes)
                except (TypeError, ValueError):
                    pass  # leave as-is; better to migrate something than crash

            certificate_number = row["certificate_number"]
            existing = session.get(VerificationRegistry, certificate_number)
            if existing is not None:
                target = existing
            else:
                target = VerificationRegistry(certificate_number=certificate_number)
                session.add(target)

            target.merkle_root = row.get("merkle_root")
            target.field_hashes = field_hashes
            target.signature_hex = row.get("signature_hex")
            target.public_key_fingerprint = row.get("public_key_fingerprint")
            target.tx_hash = row.get("tx_hash")
            target.block_number = row.get("block_number")
            target.etherscan_url = row.get("etherscan_url")
            target.sealed_at = row.get("sealed_at")
            target.issue_date = _parse_datetime(row.get("issue_date"))
            target.expiry_date = _parse_datetime(row.get("expiry_date"))
            target.status = row.get("status") or "ACTIVE"
            target.created_at = _parse_datetime(row.get("created_at")) or datetime.utcnow()
            migrated += 1

        session.commit()
        print(f"[verification_registry] Migrated {migrated} row(s) from {db_path}.")
        return migrated
    finally:
        session.close()
        conn.close()


def migrate_audit_log(db_path: Path) -> int:
    if not db_path.exists():
        print(f"[skip] {db_path} not found, nothing to migrate for the Audit Log.")
        return 0

    conn = _open_readonly(db_path)
    session = SessionLocal()
    migrated = 0
    skipped = 0
    try:
        rows = conn.execute("SELECT * FROM operations").fetchall()
        for row in rows:
            row = dict(row)
            row_id = row["id"]

            if session.get(AuditLog, row_id) is not None:
                skipped += 1
                continue

            values = {col: row.get(col) for col in AUDIT_COLUMNS}
            session.add(AuditLog(id=row_id, **values))
            migrated += 1

        session.commit()

        # Reset the SERIAL sequence so the next real INSERT (with no
        # explicit id) continues after the highest migrated id, instead
        # of colliding with it.
        max_id = session.query(AuditLog.id).order_by(AuditLog.id.desc()).limit(1).scalar()
        if max_id is not None:
            session.execute(
                text("SELECT setval('audit_log_id_seq', :max_id)"), {"max_id": max_id}
            )
            session.commit()

        print(f"[audit_log] Migrated {migrated} row(s), skipped {skipped} already-present row(s), from {db_path}.")
        return migrated
    finally:
        session.close()
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Migrate NPL DocSeal's local SQLite databases into the shared PostgreSQL database."
    )
    parser.add_argument(
        "--verification-db", type=str, default="data/verification_registry.db",
        help="Path to the old verification_registry.db (default: data/verification_registry.db)."
    )
    parser.add_argument(
        "--audit-db", type=str, default="data/audit_log.db",
        help="Path to the old audit_log.db (default: data/audit_log.db)."
    )
    args = parser.parse_args()

    print("NPL DocSeal: SQLite -> PostgreSQL migration")
    print("Source databases are opened read-only and are never modified.\n")

    from core.verification_db import init_verification_db
    from core.audit_db import init_db as init_audit_db
    init_audit_db()
    init_verification_db()

    total = 0
    total += migrate_verification_registry(Path(args.verification_db))
    total += migrate_audit_log(Path(args.audit_db))

    print(f"\nDone. {total} row(s) migrated in total.")
    print("The source SQLite files were not modified; keep them as a backup.")


if __name__ == "__main__":
    main()
