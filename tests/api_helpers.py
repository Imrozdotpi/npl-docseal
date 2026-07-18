"""
tests/api_helpers.py

Shared HTTP + ZIP-manipulation utilities for the comprehensive test suite.
Every helper here talks to the REAL running server over HTTP (same as the
browser does) — nothing is mocked. Tamper scenarios work by unzipping a
genuinely sealed package, swapping one member's bytes, and rezipping —
never by hand-crafting fake packages.
"""

import io
import json
import os
import sys
import zipfile
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.encryptor import encrypt_file  # noqa: E402

API_URL = os.environ.get("SUITE_API_URL", "http://127.0.0.1:8000")
PASSWORD = os.environ.get("SUITE_PASSWORD", "karan")
KEYPASS = os.environ.get("SUITE_KEYPASS", "karan")

_WORKDIR = ROOT / "tests" / "_suite_tmp"


def server_reachable(timeout: float = 3.0) -> bool:
    try:
        requests.get(API_URL, timeout=timeout)
        return True
    except requests.exceptions.RequestException:
        return False


def workdir() -> Path:
    _WORKDIR.mkdir(exist_ok=True)
    return _WORKDIR


def seal(xml_text: str, filename: str, test_scenario: str,
         password: str = None, keypass: str = None) -> dict:
    """POST an XML document to /api/seal. Returns the parsed JSON body
    regardless of status (callers decide what counts as pass/fail)."""
    files = {"document": (filename, xml_text.encode("utf-8"), "text/xml")}
    data = {
        "password": password or PASSWORD,
        "keypass": keypass or KEYPASS,
        "test_scenario": test_scenario,
    }
    resp = requests.post(f"{API_URL}/api/seal", files=files, data=data, timeout=240)
    return {"status_code": resp.status_code, "json": _safe_json(resp)}


def verify(zip_bytes: bytes, password: str, test_scenario: str) -> dict:
    """POST a ZIP package to /api/verify. Returns the parsed JSON body
    regardless of status."""
    files = {"document_zip": ("sealed.zip", io.BytesIO(zip_bytes), "application/zip")}
    data = {"password": password, "test_scenario": test_scenario}
    resp = requests.post(f"{API_URL}/api/verify", files=files, data=data, timeout=60)
    return {"status_code": resp.status_code, "json": _safe_json(resp)}


def _safe_json(resp) -> dict:
    try:
        return resp.json()
    except ValueError:
        return {"detail": resp.text}


def find_arcname(zip_bytes: bytes, suffix: str) -> str:
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        return next(n for n in zf.namelist() if n.endswith(suffix))


def rebuild_zip_with_replacement(zip_bytes: bytes, arcname: str, new_bytes: bytes) -> bytes:
    """Copy of a ZIP with a single entry's bytes replaced."""
    src = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as out:
        for name in src.namelist():
            out.writestr(name, new_bytes if name == arcname else src.read(name))
    return buf.getvalue()


def rebuild_zip_without_member(zip_bytes: bytes, arcname: str) -> bytes:
    """Copy of a ZIP with one entry removed entirely (malformed-package test)."""
    src = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as out:
        for name in src.namelist():
            if name != arcname:
                out.writestr(name, src.read(name))
    return buf.getvalue()


def rebuild_zip_with_extra(zip_bytes: bytes, extra_name: str, extra_bytes: bytes) -> bytes:
    """Copy of a ZIP with an extra member added (duplicate-type malformed-package test)."""
    src = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as out:
        for name in src.namelist():
            out.writestr(name, src.read(name))
        out.writestr(extra_name, extra_bytes)
    return buf.getvalue()


def flip_bytes(data: bytes, index: int = 5) -> bytes:
    b = bytearray(data)
    if len(b) > index:
        b[index] ^= 0xFF
    return bytes(b)


def mutate_one_char(text: str, target: str) -> str:
    """Replace the first occurrence of `target` (a plain numeric string like
    '20.2') with a variant differing by one digit — a generic, undirected
    single-value corruption rather than a purpose-built field tamper."""
    idx = text.index(target)
    chars = list(target)
    for i, ch in enumerate(chars):
        if ch.isdigit():
            chars[i] = str((int(ch) + 1) % 10)
            break
    mutated = "".join(chars)
    return text[:idx] + mutated + text[idx + len(target):]


def remove_proof_field(zip_bytes: bytes, field_name: str) -> bytes:
    """Delete one field's hash from merkle_proof.json inside a sealed ZIP,
    simulating a proof/document correspondence break (e.g. the document
    was sealed under a different field schema) — exercises the MISSING
    field-status path, which a plain content edit can never reach (a
    removed XML tag just parses back as an unchanged 'N/A' field name,
    which is detected as TAMPERED, not MISSING)."""
    proof_arcname = find_arcname(zip_bytes, "merkle_proof.json")
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        proof = json.loads(zf.read(proof_arcname))
    proof["field_hashes"].pop(field_name, None)
    new_bytes = json.dumps(proof, indent=2).encode("utf-8")
    return rebuild_zip_with_replacement(zip_bytes, proof_arcname, new_bytes)


def all_response_text(body: dict) -> str:
    """Flatten every human-readable string in a seal/verify response into
    one lowercase blob, for robust substring assertions regardless of
    exactly which step or field carries the message."""
    parts = [str(body.get("detail", "")), str(body.get("overall", ""))]
    for step in body.get("steps", []):
        parts.append(str(step.get("summary", "")))
        err = step.get("error")
        if err:
            parts.append(str(err.get("message", "")))
    return " ".join(parts).lower()


def swap_encrypted_content(zip_bytes: bytes, new_xml_text: str, password: str) -> bytes:
    """Re-encrypt modified XML and splice it into an otherwise-unchanged
    sealed ZIP, simulating post-seal content tampering while keeping the
    original signature/proof/timestamp untouched."""
    enc_arcname = find_arcname(zip_bytes, ".enc")
    tmp_path = workdir() / f"tampered_{os.urandom(4).hex()}.xml"
    tmp_path.write_text(new_xml_text, encoding="utf-8")
    enc_path = encrypt_file(str(tmp_path), password)
    try:
        new_enc_bytes = Path(enc_path).read_bytes()
        return rebuild_zip_with_replacement(zip_bytes, enc_arcname, new_enc_bytes)
    finally:
        os.remove(enc_path)
        os.remove(tmp_path)


def cleanup_workdir() -> None:
    import shutil
    shutil.rmtree(_WORKDIR, ignore_errors=True)
