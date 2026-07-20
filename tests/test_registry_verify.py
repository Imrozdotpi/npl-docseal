"""
tests/test_registry_verify.py

Tests the unified certificate verification architecture:
core/verification_db.py (data/verification_registry.db) and
POST /api/public/verify. Runs against the REAL live server (no mocking),
same policy as the rest of this suite.

Run with the server already running (see backend/api.py), then:
    venv/Scripts/python.exe -m pytest tests/test_registry_verify.py -v
"""

import pytest

from tests import api_helpers as api
from tests.xml_generator import build_flat_xml, default_rows, DEFAULT_VALID_UNTIL
from core import verification_db


@pytest.fixture(scope="module", autouse=True)
def _require_server():
    if not api.server_reachable():
        pytest.exit(
            f"Server not reachable at {api.API_URL}: start it first "
            f"(uvicorn backend.api:app --host 127.0.0.1 --port 8000).",
            returncode=1,
        )


def _seal_fresh_document(tag: str) -> tuple[str, str]:
    """Seals a brand-new tiny document so each test registers its own
    certificate_number, never one another test also depends on. Returns
    (xml_text, certificate_number)."""
    seed = abs(hash(tag)) % 100000
    rows = default_rows(2, seed=seed)
    xml_text = build_flat_xml(num_rows=2, rows=rows, seed=seed)
    result = api.seal(xml_text, f"registry_{tag}.xml", test_scenario="registry")
    assert result["status_code"] == 200, result
    body = result["json"]
    assert body["overall"] == "PASS", body
    assert body["registered"] is True, body
    return xml_text, body["certificate_number"]


def test_seal_registers_certificate():
    xml_text, cert_number = _seal_fresh_document("case1")
    entry = verification_db.get_certificate(cert_number)
    assert entry is not None
    assert entry["certificate_number"] == cert_number
    assert entry["field_hashes"] is not None
    assert entry["signature_hex"] is not None
    assert entry["expiry_date"] is not None
    assert entry["status"] == "ACTIVE"


def test_public_verify_clean_document_passes():
    xml_text, cert_number = _seal_fresh_document("case2")
    result = api.public_verify(xml_text)
    body = result["json"]
    assert result["status_code"] == 200
    assert body["found"] is True
    assert body["overall"] == "PASS"
    assert body["root_matches"] is True
    assert body["signature_valid"] is True
    assert all(f["status"] == "INTACT" for f in body["fields"].values())


def test_public_verify_tampered_field_fails():
    xml_text, cert_number = _seal_fresh_document("case3")
    tampered_xml = xml_text.replace(DEFAULT_VALID_UNTIL, "2099-12-31", 1)

    result = api.public_verify(tampered_xml)
    body = result["json"]
    assert body["found"] is True
    assert body["overall"] == "FAIL"
    assert body["fields"]["valid_until"]["status"] == "TAMPERED"

    other_fields = {k: v for k, v in body["fields"].items() if k != "valid_until"}
    assert all(f["status"] == "INTACT" for f in other_fields.values())


def test_public_verify_unknown_certificate():
    xml_text, cert_number = _seal_fresh_document("case4")
    fake_xml = xml_text.replace(cert_number, "NEVER-SEALED-CERT-000", 1)

    result = api.public_verify(fake_xml)
    body = result["json"]
    assert body["found"] is False


def test_public_verify_expired_and_revoked():
    """Confirms the merged registry's lifecycle fields (previously only
    reachable via the internal-only /verification/verify) now drive the
    same one /api/public/verify endpoint both frontends call."""
    from datetime import datetime

    xml_text, cert_number = _seal_fresh_document("case5")
    entry = verification_db.get_certificate(cert_number)

    verification_db.upsert_certificate(
        certificate_number=cert_number, merkle_root=entry["merkle_root"],
        field_hashes=entry["field_hashes"], signature_hex=entry["signature_hex"],
        public_key_fingerprint=entry["public_key_fingerprint"], tx_hash=entry["tx_hash"],
        block_number=entry["block_number"], etherscan_url=entry["etherscan_url"],
        sealed_at=entry["sealed_at"], issue_date=entry["issue_date"],
        expiry_date=datetime(2020, 1, 1), status="REVOKED",
    )

    result = api.public_verify(xml_text)
    body = result["json"]
    assert body["overall"] == "WARNING"
    assert body["result"] == "Certificate Authentic but Expired and Revoked"
    assert body["is_expired"] is True
    assert body["is_revoked"] is True
    assert body["signature_valid"] is True
    assert body["root_matches"] is True

