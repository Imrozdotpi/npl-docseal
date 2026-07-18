"""
tests/test_registry_verify.py

Tests the registry-based verification architecture: core/registry_db.py,
POST /api/public/verify, and POST /api/internal/revoke. Runs against the
REAL live server (no mocking), same policy as the rest of this suite.

Run with the server already running (see backend/api.py), then:
    venv/Scripts/python.exe -m pytest tests/test_registry_verify.py -v
"""

import hashlib

import pytest

from tests import api_helpers as api
from tests.xml_generator import build_flat_xml, default_rows, DEFAULT_VALID_UNTIL
from core import registry_db
from core.signer import verify_bytes

PUBLIC_KEY_PATH = "keys/public_key.pem"


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
    entry = registry_db.lookup_certificate(cert_number)
    assert entry is not None
    assert entry["certificate_number"] == cert_number
    assert entry["revoked"] is False


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


def test_revoked_certificate_fails_verification():
    xml_text, cert_number = _seal_fresh_document("case5")

    pre = api.public_verify(xml_text)
    assert pre["json"]["overall"] == "PASS"

    revoke_result = api.internal_revoke(
        cert_number, "Calibration reading error discovered post-issuance", api.KEYPASS
    )
    assert revoke_result["status_code"] == 200, revoke_result

    # Same unmodified document: still cryptographically perfect, but must
    # now fail because NPL has revoked it.
    post = api.public_verify(xml_text)
    post_body = post["json"]
    assert post_body["overall"] == "FAIL"
    assert post_body["signature_valid"] is True
    assert post_body["root_matches"] is True
    assert post_body["revoked"] is True


def test_revocation_requires_correct_keypass():
    xml_text, cert_number = _seal_fresh_document("case6")
    result = api.internal_revoke(cert_number, "Should never apply", "definitely-wrong-passphrase")
    assert result["status_code"] == 401, result


def test_revocation_signature_is_verifiable():
    xml_text, cert_number = _seal_fresh_document("case7")
    revoke_result = api.internal_revoke(cert_number, "Independently re-verified reason", api.KEYPASS)
    assert revoke_result["status_code"] == 200, revoke_result
    entry = revoke_result["json"]

    # Reconstruct exactly what was signed and check it against the public
    # key ourselves, bypassing is_revoked()/mark_revoked() entirely - this
    # is what makes a revocation non-repudiable rather than just a
    # database flag.
    payload = f"{entry['certificate_number']}:{entry['reason']}:{entry['revoked_at']}"
    digest = hashlib.sha256(payload.encode("utf-8")).digest()
    signature = bytes.fromhex(entry["revocation_signature_hex"])
    assert verify_bytes(digest, signature, PUBLIC_KEY_PATH) is True
