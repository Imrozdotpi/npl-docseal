"""
verification_db.py: Verification Registry table, in the shared
PostgreSQL database (core/db.py).

The single source of truth for third-party certificate verification.
Now lives as the verification_registry table inside the shared
PostgreSQL database (DATABASE_URL) instead of its own local SQLite
file, so multiple machines can query the same live registry. Migrated
from the old per-machine data/verification_registry.db via
scripts/migrate_to_postgres.py; that SQLite file is left untouched as
a backup, never written to again.

Still completely independent of core/audit_db.py's table (audit_log) -
the Verify Document module and the public /verify page must never read
from or write to the Audit Log, and vice versa, even though both now
live in the same PostgreSQL database.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import Column, String, Text, DateTime, Integer, JSON, CheckConstraint
from sqlalchemy.exc import SQLAlchemyError

from core.db import Base, engine, SessionLocal


class VerificationRegistry(Base):
    __tablename__ = "verification_registry"

    # Matches the field name used everywhere else in this codebase
    # (parse_xml, the public verify.js page).
    certificate_number = Column(String, primary_key=True)

    merkle_root = Column(Text, nullable=False)

    # Crypto/blockchain proof. Nullable: a certificate can still be
    # registered (and root/lifecycle checked) even if these aren't
    # available for some reason.
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


def init_verification_db() -> None:
    """Create the verification_registry table if it doesn't already
    exist. Called once at app startup; safe to call more than once
    (idempotent)."""
    Base.metadata.create_all(engine)


def _session():
    return SessionLocal()


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
