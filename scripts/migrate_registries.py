"""
scripts/migrate_registries.py

One-time data migration: merges the legacy data/public_registry.db
(certificate_number, merkle_root, field_hashes, signature_hex,
public_key_fingerprint, tx_hash, block_number, etherscan_url, sealed_at)
and the older lean data/verification_registry.db (certificate_id,
merkle_root, issue_date, expiry_date, status) into one unified
verification_registry.db row per certificate, matching the schema in
core/verification_db.py.

Conflict policy when the same certificate exists in both source
databases with DIFFERENT merkle_root values (can happen from repeated
dev-time re-sealing of the same certificate_number): the public-registry
row wins for merkle_root/field_hashes/signature_hex/etc, since it's the
self-consistent, signature-backed record; issue_date/expiry_date/status
are still taken from the verification_registry row regardless, since
that's independent lifecycle metadata. A warning is printed for every
such conflict so it can be reviewed/re-sealed if a fully clean record is
wanted.

Data safety: this script never deletes data/public_registry.db. If an
old-schema data/verification_registry.db is found, it's renamed to
data/verification_registry.db.pre_merge_backup (not deleted) before a
fresh, fully-correct-schema table is created and populated - this is a
full table rebuild rather than an in-place ALTER, because SQLite can't
alter an existing CHECK constraint (the old table only allowed
ACTIVE/REVOKED; the merged schema also allows EXPIRED).

Usage:
    python scripts/migrate_registries.py

Safe to re-run: it's a full rebuild of verification_registry.db from
both source databases every time, not an incremental append.
"""

import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import verification_db  # noqa: E402

DATA_DIR = ROOT / "data"
PUBLIC_DB_PATH = DATA_DIR / "public_registry.db"
VERIFICATION_DB_PATH = Path(verification_db.DB_PATH)
if not VERIFICATION_DB_PATH.is_absolute():
    VERIFICATION_DB_PATH = ROOT / VERIFICATION_DB_PATH


def _read_public_registry() -> dict:
    """Returns {certificate_number: row_dict} from the legacy public
    registry, or {} if that database doesn't exist."""
    if not PUBLIC_DB_PATH.exists():
        print(f"[migrate] No legacy public registry at {PUBLIC_DB_PATH} - skipping that source.")
        return {}

    conn = sqlite3.connect(PUBLIC_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM registry").fetchall()
    finally:
        conn.close()

    import json
    result = {}
    for row in rows:
        d = dict(row)
        d["field_hashes"] = json.loads(d["field_hashes"]) if d.get("field_hashes") else None
        result[d["certificate_number"]] = d
    print(f"[migrate] Read {len(result)} row(s) from legacy public registry ({PUBLIC_DB_PATH}).")
    return result


def _read_old_verification_registry() -> dict:
    """Returns {certificate_number: row_dict} from whatever schema the
    existing verification_registry.db currently has (old lean schema with
    certificate_id, or already-upgraded), or {} if it doesn't exist."""
    if not VERIFICATION_DB_PATH.exists():
        print(f"[migrate] No existing verification registry at {VERIFICATION_DB_PATH} - skipping that source.")
        return {}

    conn = sqlite3.connect(VERIFICATION_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(verification_registry)")}
        if not cols:
            return {}
        id_col = "certificate_number" if "certificate_number" in cols else "certificate_id"
        rows = conn.execute("SELECT * FROM verification_registry").fetchall()
    finally:
        conn.close()

    result = {}
    for row in rows:
        d = dict(row)
        d["certificate_number"] = d.pop(id_col)
        result[d["certificate_number"]] = d
    print(f"[migrate] Read {len(result)} row(s) from existing verification registry ({VERIFICATION_DB_PATH}), "
          f"id column was '{id_col}'.")
    return result


def _parse_dt(value) -> "datetime | None":
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(value), fmt)
        except ValueError:
            continue
    return None


def merge() -> list[dict]:
    public_rows = _read_public_registry()
    old_verif_rows = _read_old_verification_registry()

    all_cert_numbers = set(public_rows) | set(old_verif_rows)
    merged = []

    for cert_number in sorted(all_cert_numbers):
        pub = public_rows.get(cert_number)
        old = old_verif_rows.get(cert_number)

        if pub and old and pub["merkle_root"] != old["merkle_root"]:
            print(f"[migrate] WARNING: '{cert_number}' has conflicting merkle_root between the two "
                  f"source registries (public={pub['merkle_root'][:16]}..., "
                  f"verification={old['merkle_root'][:16]}...). Keeping the public registry's crypto "
                  f"fields as authoritative; keeping the verification registry's lifecycle fields "
                  f"regardless. Re-seal this certificate if you want a fully consistent record.")

        merged.append({
            "certificate_number": cert_number,
            "merkle_root": (pub or old)["merkle_root"],
            "field_hashes": pub["field_hashes"] if pub else None,
            "signature_hex": pub["signature_hex"] if pub else None,
            "public_key_fingerprint": pub.get("public_key_fingerprint") if pub else None,
            "tx_hash": pub.get("tx_hash") if pub else None,
            "block_number": pub.get("block_number") if pub else None,
            "etherscan_url": pub.get("etherscan_url") if pub else None,
            "sealed_at": pub.get("sealed_at") if pub else None,
            "issue_date": _parse_dt(old.get("issue_date")) if old else None,
            "expiry_date": _parse_dt(old.get("expiry_date")) if old else None,
            "status": (old.get("status") if old and old.get("status") else "ACTIVE"),
        })

    return merged


def main():
    merged_rows = merge()

    if VERIFICATION_DB_PATH.exists():
        backup_path = VERIFICATION_DB_PATH.with_name(VERIFICATION_DB_PATH.name + ".pre_merge_backup")
        shutil.move(str(VERIFICATION_DB_PATH), str(backup_path))
        print(f"[migrate] Backed up existing verification registry to {backup_path} (not deleted).")

    verification_db.init_verification_db()

    for row in merged_rows:
        verification_db.upsert_certificate(
            certificate_number=row["certificate_number"],
            merkle_root=row["merkle_root"],
            field_hashes=row["field_hashes"],
            signature_hex=row["signature_hex"],
            public_key_fingerprint=row["public_key_fingerprint"],
            tx_hash=row["tx_hash"],
            block_number=row["block_number"],
            etherscan_url=row["etherscan_url"],
            sealed_at=row["sealed_at"],
            issue_date=row["issue_date"],
            expiry_date=row["expiry_date"],
            status=row["status"],
        )

    print(f"[migrate] Wrote {len(merged_rows)} merged row(s) to {VERIFICATION_DB_PATH}.")
    print(f"[migrate] Legacy public registry left untouched at {PUBLIC_DB_PATH} (not deleted, not written to).")
    print("[migrate] Done.")


if __name__ == "__main__":
    main()
