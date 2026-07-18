"""
tests/test_revocation.py

Tests core/revocation.py and the /api/revoke, /api/revocations endpoints,
plus the revocation check inside /api/verify. Runs against the REAL live
server (no mocking), same approach as tests/test_comprehensive_suite.py.

Run with the server already running (see backend/api.py), then:
    venv/Scripts/python.exe -m pytest tests/test_revocation.py -v

Note: revocation is append-only by design, so entries created by this
suite become permanent additions to data/revocation_list.json, consistent
with how the rest of the suite permanently populates the real audit log.
"""

import base64
import json
from pathlib import Path

import pytest

from tests import api_helpers as api
from tests.xml_generator import build_flat_xml, default_rows
from core import revocation

PRIVATE_KEY_PATH = "keys/private_key.pem"
PUBLIC_KEY_PATH = "keys/public_key.pem"


@pytest.fixture(scope="module", autouse=True)
def _require_server():
    if not api.server_reachable():
        pytest.exit(
            f"Server not reachable at {api.API_URL}: start it first "
            f"(uvicorn backend.api:app --host 127.0.0.1 --port 8000).",
            returncode=1,
        )


def _seal_fresh_document(tag: str) -> dict:
    """Seals a brand-new tiny document so each test revokes its own root,
    never a root some other test also depends on being un-revoked."""
    seed = abs(hash(tag)) % 100000
    rows = default_rows(2, seed=seed)
    xml_text = build_flat_xml(num_rows=2, rows=rows, seed=seed)
    result = api.seal(xml_text, f"revocation_{tag}.xml", test_scenario="revocation")
    assert result["status_code"] == 200, result
    body = result["json"]
    assert body["overall"] == "PASS", body
    return body


def test_revoke_certificate_and_is_revoked():
    body = _seal_fresh_document("case1")
    root = body["hash"]

    entry = revocation.revoke_certificate(
        merkle_root=root,
        certificate_number="TEST-CASE-1",
        reason="Unit test revocation",
        private_key_path=PRIVATE_KEY_PATH,
        keypass=api.KEYPASS,
    )
    assert entry["merkle_root"] == root
    assert entry["reason"] == "Unit test revocation"

    found = revocation.is_revoked(root)
    assert found is not None
    assert found["merkle_root"] == root
    assert found["reason"] == "Unit test revocation"

    # A root that was never sealed/revoked must not be reported as revoked.
    assert revocation.is_revoked("0" * 64) is None


def test_verify_fails_after_revocation_via_api():
    body = _seal_fresh_document("case2")
    zip_bytes = base64.b64decode(body["zip_data"])

    # Clean and un-revoked: verify should PASS.
    pre = api.verify(zip_bytes, api.PASSWORD, test_scenario="revocation")
    assert pre["json"]["overall"] == "PASS"
    assert pre["json"]["revoked"] is False

    revoke_result = api.revoke(
        merkle_root=body["hash"],
        certificate_number="TEST-CASE-2",
        reason="Calibration reading error discovered post-issuance",
        keypass=api.KEYPASS,
    )
    assert revoke_result["status_code"] == 200, revoke_result

    # Same package, same password: now must FAIL with revoked:True, even
    # though the signature and Merkle root are still perfectly valid.
    post = api.verify(zip_bytes, api.PASSWORD, test_scenario="revocation")
    post_body = post["json"]
    assert post_body["overall"] == "FAIL"
    assert post_body["signature_valid"] is True
    assert post_body["root_matches"] is True
    assert post_body["revoked"] is True
    assert post_body["revocation_details"]["reason"] == "Calibration reading error discovered post-issuance"

    all_revocations = api.list_revocations()
    assert any(r["merkle_root"] == body["hash"] for r in all_revocations)


def test_tampered_revocation_list_fails_signature_check():
    body = _seal_fresh_document("case3")
    root = body["hash"]

    entry = revocation.revoke_certificate(
        merkle_root=root,
        certificate_number="TEST-CASE-3",
        reason="Original, untampered reason",
        private_key_path=PRIVATE_KEY_PATH,
        keypass=api.KEYPASS,
    )
    assert revocation.verify_revocation_signature(entry, PUBLIC_KEY_PATH) is True

    # Bypass the API entirely: hand-edit the registry file on disk, as if
    # an attacker (or a careless admin) had modified the reason directly.
    registry_path = revocation.REVOCATION_LIST_PATH
    original_bytes = registry_path.read_bytes()
    try:
        registry = json.loads(original_bytes)
        for e in registry["revoked"]:
            if e["merkle_root"] == root:
                e["reason"] = "Tampered reason: never actually signed"
        registry_path.write_text(json.dumps(registry, indent=2))

        tampered_entry = revocation.is_revoked(root)
        assert tampered_entry["reason"] == "Tampered reason: never actually signed"
        assert revocation.verify_revocation_signature(tampered_entry, PUBLIC_KEY_PATH) is False
    finally:
        # Restore the registry so this deliberately-corrupted entry doesn't
        # linger as permanent bad data (unlike genuine revocations, which
        # this suite intentionally leaves in place).
        registry_path.write_bytes(original_bytes)


def test_revoke_with_wrong_keypass_is_rejected():
    body = _seal_fresh_document("case4")

    result = api.revoke(
        merkle_root=body["hash"],
        certificate_number="TEST-CASE-4",
        reason="Should never be applied",
        keypass="definitely-the-wrong-passphrase",
    )
    assert result["status_code"] == 401, result

    assert revocation.is_revoked(body["hash"]) is None
