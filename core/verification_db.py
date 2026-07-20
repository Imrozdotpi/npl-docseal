"""
verification_db.py: unified Verification Registry for NPL DocSeal.

The single source of truth for third-party certificate verification.
Formerly split across two independent tables (core/registry_db.py's
public_registry.db, holding crypto proof; and this module's earlier lean
verification_registry.db, holding lifecycle data) - merged here because
two independently-written tables for the same certificate is a
consistency hazard, not just duplication: they drifted apart during
development and produced a wrong "0 fields tampered" result before the
drift was caught. There is now exactly one row per certificate_number,
so that failure mode is structurally impossible.

Still completely independent of core/audit_db.py (the Audit Log) - the
Verify Document module and the public /verify page must never read from
or write to the Audit Log database, and vice versa.
"""

import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import create_engine, Column, String, Text, DateTime, Integer, JSON, CheckConstraint
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import SQLAlchemyError

# Read from an env var if set; otherwise fall back to the project's default
# data location (same convention as core/audit_db.py used: a relative path
# under data/, never hardcoded absolute).
DB_PATH = Path(os.environ.get("VERIFICATION_DB_PATH", "data/verification_registry.db"))

Base = declarative_base()

# Columns added after the original lean schema shipped. Used by the
# startup upgrade step in init_verification_db() to ALTER TABLE any of
# these into an existing database without touching its existing rows.
_NEW_COLUMNS = [
    ("field_hashes", "JSON"),
    ("signature_hex", "TEXT"),
    ("public_key_fingerprint", "VARCHAR"),
    ("tx_hash", "VARCHAR"),
    ("block_number", "INTEGER"),
    ("etherscan_url", "TEXT"),
    ("sealed_at", "VARCHAR"),
]


class VerificationRegistry(Base):
    __tablename__ = "verification_registry"

    # Renamed from certificate_id: matches the field name used everywhere
    # else in this codebase (parse_xml, the public verify.js page) and
    # matches the legacy registry's column name it's replacing.
    certificate_number = Column(String, primary_key=True)

    merkle_root = Column(Text, nullable=False)

    # Crypto/blockchain proof, migrated in from the legacy public registry.
    # Nullable: a certificate can still be registered (and root/lifecycle
    # checked) even if these aren't available for some reason.
    field_hashes = Column(JSON, nullable=True)
    signature_hex = Column(Text, nullable=True)
    public_key_fingerprint = Column(String, nullable=True)
    tx_hash = Column(String, nullable=True)
    block_number = Column(Integer, nullable=True)
    etherscan_url = Column(Text, nullable=True)
    sealed_at = Column(String, nullable=True)

    # Lifecycle data. Nullable: registration must never be blocked just
    # because the XML lacked a parseable ValidUntil/DateOfIssue - a
    # missing expiry_date just means the expiry check is skipped later.
    issue_date = Column(DateTime, nullable=True)
    expiry_date = Column(DateTime, nullable=True)
    status = Column(String(20), nullable=False, default="ACTIVE")
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        CheckConstraint("status IN ('ACTIVE', 'REVOKED', 'EXPIRED')", name="ck_verification_status"),
    )


class VerificationDBError(Exception):
    """Raised when the Verification Registry itself can't be reached or
    written to - distinct from a normal 'certificate not found' result,
    which is a valid outcome, not an error."""
    pass


_engine = None
_SessionLocal = None


def _get_engine():
    global _engine, _SessionLocal
    if _engine is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(
            f"sqlite:///{DB_PATH}",
            connect_args={"check_same_thread": False},
        )
        _SessionLocal = sessionmaker(bind=_engine)
    return _engine


def _upgrade_schema() -> None:
    """
    Idempotent, Alembic-free upgrade for databases created before the
    crypto/blockchain fields (and the certificate_number rename) existed
    on this table. Only ever renames/adds columns - never drops or
    rewrites a row. Safe to run on every startup; a no-op once already
    upgraded. No-ops entirely if the table itself doesn't exist yet
    (create_all() in init_verification_db() handles that case with the
    full up-to-date schema directly).
    """
    if not DB_PATH.exists():
        return
    conn = sqlite3.connect(DB_PATH)
    try:
        existing = {row[1] for row in conn.execute("PRAGMA table_info(verification_registry)")}
        if not existing:
            return  # table doesn't exist yet; create_all() will make it fresh

        # The original lean schema's primary key was named certificate_id.
        if "certificate_id" in existing and "certificate_number" not in existing:
            conn.execute("ALTER TABLE verification_registry RENAME COLUMN certificate_id TO certificate_number")
            existing.discard("certificate_id")
            existing.add("certificate_number")

        for col_name, col_type in _NEW_COLUMNS:
            if col_name not in existing:
                conn.execute(f"ALTER TABLE verification_registry ADD COLUMN {col_name} {col_type}")
        conn.commit()
    finally:
        conn.close()


def init_verification_db() -> None:
    """Create the verification_registry table if it doesn't already exist,
    and upgrade an existing table to the current schema if it predates the
    crypto/blockchain columns. Called once at app startup; safe to call
    more than once (idempotent)."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _upgrade_schema()
    engine = _get_engine()
    Base.metadata.create_all(engine)


def _session():
    _get_engine()
    return _SessionLocal()


def upsert_certificate(
    certificate_number: str,
    merkle_root: str,
    field_hashes: Optional[dict] = None,
    signature_hex: Optional[str] = None,
    public_key_fingerprint: Optional[str] = None,
    tx_hash: Optional[str] = None,
    block_number: Optional[int] = None,
    etherscan_url: Optional[str] = None,
    sealed_at: Optional[str] = None,
    issue_date: Optional[datetime] = None,
    expiry_date: Optional[datetime] = None,
    status: str = "ACTIVE",
) -> None:
    """
    Insert a new certificate row, or update it in place if
    certificate_number already exists (re-sealing the same certificate
    updates its entry rather than raising a primary-key conflict - the
    same last-write-wins behaviour the legacy registry used for re-seals).
    Raises VerificationDBError on any database failure; callers are
    expected to catch this and treat it as a non-fatal warning.
    """
    if status not in ("ACTIVE", "REVOKED", "EXPIRED"):
        raise ValueError(f"Invalid status '{status}': must be ACTIVE, REVOKED, or EXPIRED.")

    session = _session()
    try:
        existing = session.get(VerificationRegistry, certificate_number)
        if existing is not None:
            existing.merkle_root = merkle_root
            existing.field_hashes = field_hashes
            existing.signature_hex = signature_hex
            existing.public_key_fingerprint = public_key_fingerprint
            existing.tx_hash = tx_hash
            existing.block_number = block_number
            existing.etherscan_url = etherscan_url
            existing.sealed_at = sealed_at
            existing.issue_date = issue_date
            existing.expiry_date = expiry_date
            existing.status = status
        else:
            session.add(VerificationRegistry(
                certificate_number=certificate_number,
                merkle_root=merkle_root,
                field_hashes=field_hashes,
                signature_hex=signature_hex,
                public_key_fingerprint=public_key_fingerprint,
                tx_hash=tx_hash,
                block_number=block_number,
                etherscan_url=etherscan_url,
                sealed_at=sealed_at,
                issue_date=issue_date,
                expiry_date=expiry_date,
                status=status,
            ))
        session.commit()
    except SQLAlchemyError as e:
        session.rollback()
        raise VerificationDBError(str(e)) from e
    finally:
        session.close()


def get_certificate(certificate_number: str) -> Optional[dict]:
    """
    Returns the registry row as a plain dict, or None if certificate_number
    has no entry (a genuine "not issued by NPL" outcome). Raises
    VerificationDBError if the registry itself can't be reached - callers
    must distinguish that from a clean not-found.
    """
    session = _session()
    try:
        row = session.get(VerificationRegistry, certificate_number)
        if row is None:
            return None
        return {
            "certificate_number": row.certificate_number,
            "merkle_root": row.merkle_root,
            "field_hashes": row.field_hashes,
            "signature_hex": row.signature_hex,
            "public_key_fingerprint": row.public_key_fingerprint,
            "tx_hash": row.tx_hash,
            "block_number": row.block_number,
            "etherscan_url": row.etherscan_url,
            "sealed_at": row.sealed_at,
            "issue_date": row.issue_date,
            "expiry_date": row.expiry_date,
            "status": row.status,
            "created_at": row.created_at,
        }
    except SQLAlchemyError as e:
        raise VerificationDBError(str(e)) from e
    finally:
        session.close()
