"""
tests/test_comprehensive_suite.py

Comprehensive end-to-end test suite for NPL DocSeal. Generates synthetic
CalibrationCertificate XML documents across a range of sizes, seals and
verifies them against the REAL running server (no mocking), and exercises
the full tamper-detection + package-integrity matrix. Every call here is a
genuine HTTP request that also populates the audit dashboard as a side
effect — this is both a correctness test suite and a data-generation tool
for the Performance / Validation / Coverage dashboards.

Run with the server already running (see backend/api.py), then:
    venv/Scripts/python.exe -m pytest tests/test_comprehensive_suite.py -v

Override the target server / credentials with env vars if needed:
    SUITE_API_URL, SUITE_PASSWORD, SUITE_KEYPASS
"""

import base64
import io
import zipfile

import pytest

from tests import api_helpers as api
from tests.xml_generator import (
    DEFAULT_CERTIFICATE_NUMBER,
    DEFAULT_SERIAL_NUMBER,
    DEFAULT_VALID_UNTIL,
    build_flat_xml,
    default_rows,
)

# ── Size matrix ──────────────────────────────────────────────────────────
# The full sweep drives the "File Size vs Total Duration" performance
# chart; the core sizes are reused (not re-sealed) for every tamper test
# below, so a 100-row document only ever gets sealed once.
SIZE_SWEEP = [1, 3, 5, 10, 25, 50, 100, 250, 500]
CORE_SIZES = [1, 10, 100]
CORE_SIZES_MULTI_ROW = [10, 100]  # "tamper several rows at once" needs >=3 rows

_SEAL_CACHE: dict[int, dict] = {}


def get_sealed(num_rows: int) -> dict:
    """Seal a num_rows-row document once and cache the result for reuse
    across every test that needs a baseline of that size."""
    if num_rows not in _SEAL_CACHE:
        rows = default_rows(num_rows, seed=1000 + num_rows)
        xml_text = build_flat_xml(num_rows=num_rows, rows=rows, seed=1000 + num_rows)
        result = api.seal(xml_text, f"gen_{num_rows}row.xml", test_scenario="clean")
        assert result["status_code"] == 200, f"seal HTTP failure at size={num_rows}: {result}"
        body = result["json"]
        assert body.get("overall") == "PASS", f"seal did not PASS at size={num_rows}: {body}"
        zip_bytes = base64.b64decode(body["zip_data"])
        _SEAL_CACHE[num_rows] = {"xml_text": xml_text, "rows": rows, "zip_bytes": zip_bytes, "body": body}
    return _SEAL_CACHE[num_rows]


@pytest.fixture(scope="session", autouse=True)
def _require_server():
    if not api.server_reachable():
        pytest.exit(
            f"Server not reachable at {api.API_URL} — start it first "
            f"(uvicorn backend.api:app --host 127.0.0.1 --port 8000).",
            returncode=1,
        )
    yield
    api.cleanup_workdir()


# ═══════════════════════════════════════════════════════════════════════
# 1. Size sweep — clean seal + verify at every size (9 cases)
# ═══════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("num_rows", SIZE_SWEEP)
def test_clean_seal_and_verify(num_rows):
    sealed = get_sealed(num_rows)
    result = api.verify(sealed["zip_bytes"], api.PASSWORD, test_scenario="clean")
    body = result["json"]

    assert result["status_code"] == 200
    assert body["overall"] == "PASS", body
    assert body["signature_valid"] is True
    assert body["root_matches"] is True

    fields = body.get("fields", {})
    assert len(fields) > 0
    assert all(f["status"] == "INTACT" for f in fields.values()), fields


# ═══════════════════════════════════════════════════════════════════════
# 2. Field-level tamper matrix — 3 core sizes x 7 tamper types (20 cases)
# ═══════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("num_rows", CORE_SIZES)
def test_tampered_date(num_rows):
    sealed = get_sealed(num_rows)
    tampered_xml = sealed["xml_text"].replace(DEFAULT_VALID_UNTIL, "2099-01-01", 1)
    tampered_zip = api.swap_encrypted_content(sealed["zip_bytes"], tampered_xml, api.PASSWORD)

    body = api.verify(tampered_zip, api.PASSWORD, test_scenario="tampered_date")["json"]

    assert body["overall"] == "FAIL", body
    assert body["root_matches"] is False
    assert body["fields"]["valid_until"]["status"] == "TAMPERED"


@pytest.mark.parametrize("num_rows", CORE_SIZES)
def test_tampered_single_reading(num_rows):
    sealed = get_sealed(num_rows)
    _, measured, _ = sealed["rows"][0]
    tampered_xml = api.mutate_one_char(sealed["xml_text"], measured)
    tampered_zip = api.swap_encrypted_content(sealed["zip_bytes"], tampered_xml, api.PASSWORD)

    body = api.verify(tampered_zip, api.PASSWORD, test_scenario="tampered_reading")["json"]

    assert body["overall"] == "FAIL", body
    assert body["root_matches"] is False
    assert body["fields"]["result_1_measured"]["status"] == "TAMPERED"


@pytest.mark.parametrize("num_rows", CORE_SIZES_MULTI_ROW)
def test_tampered_multiple_readings(num_rows):
    sealed = get_sealed(num_rows)
    xml_text = sealed["xml_text"]
    for _, measured, _ in sealed["rows"][:3]:
        xml_text = api.mutate_one_char(xml_text, measured)
    tampered_zip = api.swap_encrypted_content(sealed["zip_bytes"], xml_text, api.PASSWORD)

    body = api.verify(tampered_zip, api.PASSWORD, test_scenario="tampered_multiple_readings")["json"]

    assert body["overall"] == "FAIL", body
    tampered_names = [k for k, v in body["fields"].items() if v["status"] == "TAMPERED"]
    assert len(tampered_names) >= 3, body["fields"]


@pytest.mark.parametrize("num_rows", CORE_SIZES)
def test_tampered_identity(num_rows):
    sealed = get_sealed(num_rows)
    tampered_xml = sealed["xml_text"].replace(
        DEFAULT_CERTIFICATE_NUMBER, "FORGED-CERT-0000", 1
    )
    tampered_zip = api.swap_encrypted_content(sealed["zip_bytes"], tampered_xml, api.PASSWORD)

    body = api.verify(tampered_zip, api.PASSWORD, test_scenario="tampered_identity")["json"]

    assert body["overall"] == "FAIL", body
    assert body["fields"]["certificate_number"]["status"] == "TAMPERED"


@pytest.mark.parametrize("num_rows", CORE_SIZES)
def test_tampered_instrument(num_rows):
    sealed = get_sealed(num_rows)
    tampered_xml = sealed["xml_text"].replace(DEFAULT_SERIAL_NUMBER, "SN-FORGED-999", 1)
    tampered_zip = api.swap_encrypted_content(sealed["zip_bytes"], tampered_xml, api.PASSWORD)

    body = api.verify(tampered_zip, api.PASSWORD, test_scenario="tampered_instrument")["json"]

    assert body["overall"] == "FAIL", body
    assert body["fields"]["instrument_serial_number"]["status"] == "TAMPERED"


@pytest.mark.parametrize("num_rows", CORE_SIZES)
def test_missing_field_status(num_rows):
    sealed = get_sealed(num_rows)
    # Break the proof/document correspondence for one field so it can
    # never be found in stored_hashes — this is the only way to reach the
    # MISSING branch (a removed XML tag just re-parses as 'N/A', which is
    # a value change, not an absent field name).
    tampered_zip = api.remove_proof_field(sealed["zip_bytes"], "instrument_model")

    body = api.verify(tampered_zip, api.PASSWORD, test_scenario="missing_field")["json"]

    assert body["fields"]["instrument_model"]["status"] == "MISSING", body["fields"]


@pytest.mark.parametrize("num_rows", CORE_SIZES)
def test_byte_flip_reading(num_rows):
    sealed = get_sealed(num_rows)
    _, measured, _ = sealed["rows"][-1]
    tampered_xml = api.mutate_one_char(sealed["xml_text"], measured)
    tampered_zip = api.swap_encrypted_content(sealed["zip_bytes"], tampered_xml, api.PASSWORD)

    body = api.verify(tampered_zip, api.PASSWORD, test_scenario="byte_flip_reading")["json"]

    assert body["overall"] == "FAIL", body
    last_idx = len(sealed["rows"])
    assert body["fields"][f"result_{last_idx}_measured"]["status"] == "TAMPERED"


@pytest.mark.parametrize("num_rows", CORE_SIZES)
def test_double_tamper(num_rows):
    sealed = get_sealed(num_rows)
    xml_text = sealed["xml_text"].replace(DEFAULT_VALID_UNTIL, "2099-01-01", 1)
    _, measured, _ = sealed["rows"][0]
    xml_text = api.mutate_one_char(xml_text, measured)
    tampered_zip = api.swap_encrypted_content(sealed["zip_bytes"], xml_text, api.PASSWORD)

    body = api.verify(tampered_zip, api.PASSWORD, test_scenario="double_tamper")["json"]

    assert body["overall"] == "FAIL", body
    assert body["fields"]["valid_until"]["status"] == "TAMPERED"
    assert body["fields"]["result_1_measured"]["status"] == "TAMPERED"


# ═══════════════════════════════════════════════════════════════════════
# 3. Package / crypto-level integrity (7 cases, against one baseline)
# ═══════════════════════════════════════════════════════════════════════

def test_wrong_password():
    sealed = get_sealed(10)
    body = api.verify(sealed["zip_bytes"], "definitely-wrong-password", test_scenario="wrong_password")["json"]

    assert body["overall"] == "FAIL", body
    assert body["signature_valid"] is False
    assert body["root_matches"] is False


def test_corrupted_signature():
    sealed = get_sealed(10)
    sig_arcname = api.find_arcname(sealed["zip_bytes"], ".sig")
    with zipfile.ZipFile(io.BytesIO(sealed["zip_bytes"])) as zf:
        sig_bytes = zf.read(sig_arcname)
    corrupted_zip = api.rebuild_zip_with_replacement(sealed["zip_bytes"], sig_arcname, api.flip_bytes(sig_bytes))

    body = api.verify(corrupted_zip, api.PASSWORD, test_scenario="corrupted_signature")["json"]

    assert body["overall"] == "FAIL", body
    assert body["signature_valid"] is False
    assert body["root_matches"] is True  # content itself is untouched


def test_corrupted_ots():
    sealed = get_sealed(10)
    ots_arcname = api.find_arcname(sealed["zip_bytes"], ".ots")
    with zipfile.ZipFile(io.BytesIO(sealed["zip_bytes"])) as zf:
        ots_bytes = zf.read(ots_arcname)
    corrupted_zip = api.rebuild_zip_with_replacement(sealed["zip_bytes"], ots_arcname, api.flip_bytes(ots_bytes))

    body = api.verify(corrupted_zip, api.PASSWORD, test_scenario="corrupted_ots")["json"]

    # Signature + root are untouched — only the blockchain proof is broken.
    assert body["signature_valid"] is True
    assert body["root_matches"] is True
    assert body["timestamp"]["status"] != "confirmed"


def test_missing_zip_member():
    sealed = get_sealed(10)
    sig_arcname = api.find_arcname(sealed["zip_bytes"], ".sig")
    broken_zip = api.rebuild_zip_without_member(sealed["zip_bytes"], sig_arcname)

    result = api.verify(broken_zip, api.PASSWORD, test_scenario="missing_zip_member")
    body = result["json"]

    assert body.get("overall") == "FAIL", body
    assert "sig" in api.all_response_text(body)


def test_duplicate_zip_member():
    sealed = get_sealed(10)
    enc_arcname = api.find_arcname(sealed["zip_bytes"], ".enc")
    broken_zip = api.rebuild_zip_with_extra(sealed["zip_bytes"], "extra_copy.xml.enc", b"decoy")

    result = api.verify(broken_zip, api.PASSWORD, test_scenario="duplicate_zip_member")
    body = result["json"]

    assert body.get("overall") == "FAIL", body
    assert "enc" in api.all_response_text(body)


def test_non_xml_upload():
    result = api.seal("This is plainly not an XML document.", "not_xml.xml", test_scenario="non_xml_upload")
    body = result["json"]

    assert body.get("overall") == "FAIL", body
    assert "pars" in api.all_response_text(body)  # "parse"/"parsing" failed


def test_empty_file_upload():
    result = api.seal("", "empty.xml", test_scenario="empty_file")
    body = result["json"]

    assert body.get("overall") == "FAIL", body
