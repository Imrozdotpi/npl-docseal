"""
audit_db.py: Audit Log table, in the shared PostgreSQL database
(core/db.py).

Logs every real /api/seal and /api/verify operation for the Audit Log
dashboard (Tab 3). Now lives as the audit_log table inside the shared
PostgreSQL database (DATABASE_URL) instead of its own local SQLite
file, so multiple machines see the same live audit history. Migrated
from the old per-machine data/audit_log.db via
scripts/migrate_to_postgres.py; that SQLite file is left untouched as
a backup, never written to again.

Every public function here keeps its original signature and return
shape (list[dict] / dict), so backend/api.py's audit endpoints needed
no changes at all for this migration.
"""

import json

from sqlalchemy import Column, Integer, String, Text, Float, func, case
from sqlalchemy.exc import SQLAlchemyError

from core.db import Base, engine, SessionLocal

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


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(String, nullable=False, index=True)
    operation_type = Column(String, nullable=False, index=True)
    filename = Column(String, nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    file_format = Column(String, nullable=True)

    parse_duration_ms = Column(Float, nullable=True)
    merkle_duration_ms = Column(Float, nullable=True)
    sign_duration_ms = Column(Float, nullable=True)
    verify_sig_duration_ms = Column(Float, nullable=True)
    encrypt_duration_ms = Column(Float, nullable=True)
    decrypt_duration_ms = Column(Float, nullable=True)
    compare_duration_ms = Column(Float, nullable=True)
    blockchain_duration_ms = Column(Float, nullable=True)
    total_duration_ms = Column(Float, nullable=True)

    field_count = Column(Integer, nullable=True)
    intact_count = Column(Integer, nullable=True)
    tampered_count = Column(Integer, nullable=True)
    missing_count = Column(Integer, nullable=True)
    tampered_field_names = Column(Text, nullable=True)

    # Kept as 0/1 integers (not native Boolean): backend/api.py already
    # builds these records as "1 if x else 0", so keeping the same
    # storage type means zero changes needed there.
    signature_valid = Column(Integer, nullable=True)
    root_matches = Column(Integer, nullable=True)

    tx_hash = Column(String, nullable=True)
    block_number = Column(Integer, nullable=True)
    confirmation_time_ms = Column(Float, nullable=True)
    etherscan_url = Column(Text, nullable=True)

    test_scenario = Column(String, nullable=True)
    overall_status = Column(String, nullable=False)


def _session():
    return SessionLocal()


def _obj_to_dict(obj: "AuditLog") -> dict:
    return {c.name: getattr(obj, c.name) for c in AuditLog.__table__.columns}


def init_db() -> None:
    """Create the audit_log table (and its indexes) if it doesn't
    already exist. Safe to call more than once (idempotent)."""
    Base.metadata.create_all(engine)


def log_operation(record: dict) -> int:
    """Insert one row. Missing keys default to None. Returns inserted row id."""
    row = {col: record.get(col) for col in _COLUMNS}
    if row.get("test_scenario") is None:
        row["test_scenario"] = "real_usage"
    if row.get("overall_status") is None:
        row["overall_status"] = "FAIL"
    if row.get("tampered_field_names") is not None and not isinstance(row["tampered_field_names"], str):
        row["tampered_field_names"] = json.dumps(row["tampered_field_names"])

    session = _session()
    try:
        entry = AuditLog(**row)
        session.add(entry)
        session.commit()
        session.refresh(entry)
        return entry.id
    finally:
        session.close()


def get_all_operations(limit: int = 500) -> list[dict]:
    """Return most recent operations, newest first."""
    session = _session()
    try:
        rows = (
            session.query(AuditLog)
            .order_by(AuditLog.id.desc())
            .limit(limit)
            .all()
        )
        return [_obj_to_dict(r) for r in rows]
    finally:
        session.close()


def get_operations_since(timestamp_iso: str) -> list[dict]:
    """For polling: returns rows with timestamp > given value, oldest first."""
    session = _session()
    try:
        rows = (
            session.query(AuditLog)
            .filter(AuditLog.timestamp > timestamp_iso)
            .order_by(AuditLog.timestamp.asc())
            .all()
        )
        return [_obj_to_dict(r) for r in rows]
    finally:
        session.close()


def get_summary_stats() -> dict:
    session = _session()
    try:
        total_operations = session.query(func.count(AuditLog.id)).scalar()
        total_seals = session.query(func.count(AuditLog.id)).filter(
            AuditLog.operation_type == "seal"
        ).scalar()
        total_verifies = session.query(func.count(AuditLog.id)).filter(
            AuditLog.operation_type == "verify"
        ).scalar()

        avg_seal_duration_ms = session.query(func.avg(AuditLog.total_duration_ms)).filter(
            AuditLog.operation_type == "seal"
        ).scalar()
        avg_verify_duration_ms = session.query(func.avg(AuditLog.total_duration_ms)).filter(
            AuditLog.operation_type == "verify"
        ).scalar()

        total_fields_checked, total_intact, total_tampered = session.query(
            func.coalesce(func.sum(AuditLog.field_count), 0),
            func.coalesce(func.sum(AuditLog.intact_count), 0),
            func.coalesce(func.sum(AuditLog.tampered_count), 0),
        ).one()

        pass_count = session.query(func.count(AuditLog.id)).filter(
            AuditLog.overall_status == "PASS"
        ).scalar()
        pass_rate_percent = (pass_count / total_operations * 100.0) if total_operations else 0.0

        avg_blockchain_confirmation_ms = session.query(
            func.avg(AuditLog.confirmation_time_ms)
        ).filter(AuditLog.confirmation_time_ms.isnot(None)).scalar()

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
        session.close()


def get_field_tamper_frequency() -> dict:
    """{field_name: tamper_count} across all logged operations."""
    session = _session()
    try:
        rows = (
            session.query(AuditLog.tampered_field_names)
            .filter(AuditLog.tampered_field_names.isnot(None))
            .all()
        )
        freq: dict[str, int] = {}
        for (raw,) in rows:
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
        session.close()


def get_test_coverage_matrix() -> list[dict]:
    """Rows grouped by (file_format, test_scenario) with pass/fail counts."""
    session = _session()
    try:
        file_format = func.coalesce(AuditLog.file_format, "unknown").label("file_format")
        test_scenario = func.coalesce(AuditLog.test_scenario, "real_usage").label("test_scenario")
        pass_count = func.sum(
            case((AuditLog.overall_status == "PASS", 1), else_=0)
        ).label("pass_count")
        fail_count = func.sum(
            case((AuditLog.overall_status == "FAIL", 1), else_=0)
        ).label("fail_count")

        rows = (
            session.query(file_format, test_scenario, pass_count, fail_count)
            .group_by(file_format, test_scenario)
            .order_by(file_format, test_scenario)
            .all()
        )
        return [
            {
                "file_format": r.file_format,
                "test_scenario": r.test_scenario,
                "pass_count": r.pass_count,
                "fail_count": r.fail_count,
            }
            for r in rows
        ]
    finally:
        session.close()


def get_duration_breakdown_series(operation_type: str, limit: int = 50) -> list[dict]:
    """Last N operations of a given type with step-by-step duration breakdown, oldest first."""
    session = _session()
    try:
        rows = (
            session.query(AuditLog)
            .filter(AuditLog.operation_type == operation_type)
            .order_by(AuditLog.id.desc())
            .limit(limit)
            .all()
        )
        result = [_obj_to_dict(r) for r in rows]
        result.reverse()
        return result
    finally:
        session.close()


def clear_all_logs() -> None:
    """Wipe the audit_log table."""
    session = _session()
    try:
        session.query(AuditLog).delete()
        session.commit()
    finally:
        session.close()
