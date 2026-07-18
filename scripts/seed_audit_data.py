"""
scripts/seed_audit_data.py

Populates data/audit_log.db with realistic operations by calling the real
/api/seal and /api/verify endpoints against both sample XML schemas
(flat_xml and dcc_xml), tagged with test_scenario values so the Audit Log
dashboard's coverage matrix, tamper-frequency chart, and performance charts
have meaningful content for a demo. No rows are inserted directly: every
row in the DB corresponds to a real HTTP request the server actually
processed.

Usage:
    python scripts/seed_audit_data.py

Requires the FastAPI server to already be running (see backend/api.py).
Override defaults with env vars if your dev key/password differ:
    SEED_API_URL, SEED_PASSWORD, SEED_KEYPASS
"""

import base64
import io
import os
import shutil
import sys
import zipfile
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.encryptor import encrypt_file  # noqa: E402

API_URL = os.environ.get("SEED_API_URL", "http://127.0.0.1:8000")
PASSWORD = os.environ.get("SEED_PASSWORD", "karan")
KEYPASS = os.environ.get("SEED_KEYPASS", "karan")

# DCC_clamp_meter1.xml uses the flat <CalibrationCertificate> schema.
# certificate.xml uses the PTB <digitalCalibrationCertificate> (DCC) schema.
FLAT_XML_SAMPLE = ROOT / "samples" / "DCC_clamp_meter1.xml"
DCC_XML_SAMPLE = ROOT / "samples" / "certificate.xml"

WORKDIR = ROOT / "scripts" / "_seed_tmp"


def seal(xml_path: Path, test_scenario: str) -> dict:
    with open(xml_path, "rb") as f:
        files = {"document": (xml_path.name, f, "text/xml")}
        data = {"password": PASSWORD, "keypass": KEYPASS, "test_scenario": test_scenario}
        resp = requests.post(f"{API_URL}/api/seal", files=files, data=data)
    resp.raise_for_status()
    return resp.json()


def verify(zip_bytes: bytes, password: str, test_scenario: str) -> dict:
    files = {"document_zip": ("sealed.zip", io.BytesIO(zip_bytes), "application/zip")}
    data = {"password": password, "test_scenario": test_scenario}
    resp = requests.post(f"{API_URL}/api/verify", files=files, data=data)
    resp.raise_for_status()
    result = resp.json()
    print(f"    -> overall={result.get('overall')} signature_valid={result.get('signature_valid')} root_matches={result.get('root_matches')}")
    return result


def rebuild_zip_with_replacement(original_zip_bytes: bytes, arcname: str, new_bytes: bytes) -> bytes:
    """Return a copy of the ZIP with a single entry's bytes replaced."""
    src = zipfile.ZipFile(io.BytesIO(original_zip_bytes), "r")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as out:
        for name in src.namelist():
            out.writestr(name, new_bytes if name == arcname else src.read(name))
    return buf.getvalue()


def flip_bytes(data: bytes, index: int = 5) -> bytes:
    b = bytearray(data)
    if len(b) > index:
        b[index] ^= 0xFF
    return bytes(b)


def find_arcname(zip_bytes: bytes, suffix: str) -> str:
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        return next(n for n in zf.namelist() if n.endswith(suffix))


def make_text_variant(xml_path: Path, old: str, new: str) -> Path:
    text = xml_path.read_text(encoding="utf-8")
    if old not in text:
        raise ValueError(f"'{old}' not found in {xml_path.name}")
    text = text.replace(old, new, 1)
    out_path = WORKDIR / f"tampered_{xml_path.name}"
    out_path.write_text(text, encoding="utf-8")
    return out_path


def swap_encrypted_content(zip_bytes: bytes, tampered_xml_path: Path) -> bytes:
    """Re-encrypt a modified XML and splice it into an otherwise-unchanged sealed ZIP,
    simulating post-seal content tampering while keeping the original signature/proof."""
    enc_arcname = find_arcname(zip_bytes, ".enc")
    enc_path = encrypt_file(str(tampered_xml_path), PASSWORD)
    try:
        new_enc_bytes = Path(enc_path).read_bytes()
        return rebuild_zip_with_replacement(zip_bytes, enc_arcname, new_enc_bytes)
    finally:
        os.remove(enc_path)


def run_flat_xml_scenarios():
    print(f"\n=== flat_xml sample: {FLAT_XML_SAMPLE.name} ===")

    print("[clean] sealing...")
    seal_result = seal(FLAT_XML_SAMPLE, "clean")
    zip_bytes = base64.b64decode(seal_result["zip_data"])
    print("[clean] verifying...")
    verify(zip_bytes, PASSWORD, "clean")

    print("[tampered_date] tampering ValidUntil and re-verifying...")
    tampered_date_path = make_text_variant(FLAT_XML_SAMPLE, "2032-09-15", "2099-01-01")
    tampered_zip = swap_encrypted_content(zip_bytes, tampered_date_path)
    verify(tampered_zip, PASSWORD, "tampered_date")

    print("[tampered_reading] tampering a MeasuredValueA and re-verifying...")
    tampered_reading_path = make_text_variant(
        FLAT_XML_SAMPLE,
        "<MeasuredValueA>50.0</MeasuredValueA>",
        "<MeasuredValueA>999.9</MeasuredValueA>",
    )
    tampered_zip2 = swap_encrypted_content(zip_bytes, tampered_reading_path)
    verify(tampered_zip2, PASSWORD, "tampered_reading")

    print("[wrong_password] verifying with an incorrect password...")
    verify(zip_bytes, "definitely-wrong-password", "wrong_password")

    print("[corrupted_signature] flipping signature bytes and re-verifying...")
    sig_arcname = find_arcname(zip_bytes, ".sig")
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        sig_bytes = zf.read(sig_arcname)
    corrupted_zip = rebuild_zip_with_replacement(zip_bytes, sig_arcname, flip_bytes(sig_bytes))
    verify(corrupted_zip, PASSWORD, "corrupted_signature")


def run_dcc_xml_scenarios():
    # Note: core/xml_parser.py's field-name aliases target the flat
    # CalibrationCertificate schema, so the PTB digitalCalibrationCertificate
    # sample mostly parses to "N/A" fields. Content tampering wouldn't
    # register as a field-level TAMPERED result here, so this schema is
    # only exercised for scenarios that don't depend on field extraction.
    print(f"\n=== dcc_xml sample: {DCC_XML_SAMPLE.name} ===")

    print("[clean] sealing...")
    seal_result = seal(DCC_XML_SAMPLE, "clean")
    zip_bytes = base64.b64decode(seal_result["zip_data"])
    print("[clean] verifying...")
    verify(zip_bytes, PASSWORD, "clean")

    print("[wrong_password] verifying with an incorrect password...")
    verify(zip_bytes, "definitely-wrong-password", "wrong_password")

    print("[corrupted_signature] flipping signature bytes and re-verifying...")
    sig_arcname = find_arcname(zip_bytes, ".sig")
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        sig_bytes = zf.read(sig_arcname)
    corrupted_zip = rebuild_zip_with_replacement(zip_bytes, sig_arcname, flip_bytes(sig_bytes))
    verify(corrupted_zip, PASSWORD, "corrupted_signature")


def main():
    try:
        requests.get(API_URL, timeout=3)
    except requests.exceptions.ConnectionError:
        print(f"ERROR: cannot reach {API_URL}. Start the server first, e.g.:")
        print("    venv/Scripts/python.exe -m backend.api")
        sys.exit(1)

    WORKDIR.mkdir(exist_ok=True)
    try:
        run_flat_xml_scenarios()
        run_dcc_xml_scenarios()
    finally:
        shutil.rmtree(WORKDIR, ignore_errors=True)

    print("\nSeeding complete. Open the Audit Log tab to see populated charts.")


if __name__ == "__main__":
    main()
