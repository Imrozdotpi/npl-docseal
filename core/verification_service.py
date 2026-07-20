"""
verification_service.py: business logic for the unified certificate
verification system (the internal dashboard's Verify Document tab and the
public /verify page both go through this).

Deliberately thin: all cryptographic/parsing work is delegated to the
existing building blocks (core.xml_parser.parse_xml,
core.merkle.build_merkle_tree, core.merkle.compare_trees,
core.signer.verify_bytes, core.timestamper.verify_timestamp) - nothing
here re-implements hashing, parsing, signature verification, or tree
comparison. This module only adds what those building blocks don't
already provide: certificate-date parsing, the single Verification
Registry insert helper, and the expiry/revocation decision logic that
turns a lookup result into one of the six defined final verification
outcomes.
"""

from datetime import datetime
from typing import Optional

from core import verification_db

# Common certificate-date formats seen across calibration XML schemas.
# parse_xml() returns these as free text (e.g. valid_until, date_of_issue);
# this project doesn't constrain the source XML's date format, so several
# candidates are tried in order.
_DATE_FORMATS = [
    "%Y-%m-%d",
    "%d-%m-%Y",
    "%d/%m/%Y",
    "%Y/%m/%d",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%d %B %Y",
    "%B %d, %Y",
    "%B %d %Y",
]


def parse_certificate_date(value: Optional[str]) -> Optional[datetime]:
    """Best-effort parse of a free-text certificate date field (e.g. from
    parse_xml()'s date_of_issue/valid_until) into a naive datetime.
    Returns None if the value is missing, 'N/A', or unparseable - callers
    decide how to handle that rather than this function guessing a date."""
    if not value:
        return None
    text = value.strip()
    if not text or text.upper() == "N/A":
        return None
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def register_certificate(
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
) -> dict:
    """
    Insert/update this certificate's entry in the Verification Registry -
    the single registration call for a successful seal. It only inserts
    data, it does not recompute the Merkle root, re-parse the XML, re-sign
    anything, or re-check the blockchain - callers pass in values already
    produced by the sealing workflow.

    issue_date/expiry_date may be None (e.g. the XML had no parseable
    ValidUntil) - registration still proceeds, since the crypto/blockchain
    proof is independently valuable even without a lifecycle window; the
    verify flow simply skips the expiry check for a NULL expiry_date.

    Never raises. A successful seal must never be invalidated by a
    Verification Registry problem, so any failure here is caught, logged,
    and returned as {"success": False, "error": "..."} for the caller to
    surface as a warning alongside the (still valid) sealed output.
    """
    try:
        verification_db.upsert_certificate(
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
            status="ACTIVE",
        )
        return {"success": True, "error": None}
    except Exception as e:
        print(f"[verification_registry] Failed to register certificate '{certificate_number}': {e}")
        return {"success": False, "error": str(e)}


def classify_result(is_expired: bool, is_revoked: bool) -> str:
    """Maps the expiry/revocation combination to one of the four
    'authentic' final results (called only once integrity has already
    been confirmed - tampered/not-issued are handled by the caller before
    this is ever reached)."""
    if is_expired and is_revoked:
        return "Certificate Authentic but Expired and Revoked"
    if is_expired:
        return "Certificate Authentic but Expired"
    if is_revoked:
        return "Certificate Authentic but Revoked"
    return "Certificate Authentic"
