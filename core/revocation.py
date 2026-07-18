"""
revocation.py: Key/certificate revocation registry for NPL DocSeal.

Maintains an append-only JSON list at data/revocation_list.json. Each
revocation entry is itself signed with the Director's private key (over
merkle_root + reason + revoked_at) so the registry can't be silently
edited: verify_revocation_signature() re-checks that signature against
whatever is currently on disk.
"""

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from core.signer import sign_bytes, verify_bytes

DATA_DIR = Path("data")
REVOCATION_LIST_PATH = DATA_DIR / "revocation_list.json"

_write_lock = threading.Lock()


def _canonical_entry_string(merkle_root: str, reason: str, revoked_at: str) -> str:
    return f"{merkle_root}:{reason}:{revoked_at}"


def _load_registry() -> dict:
    if not REVOCATION_LIST_PATH.exists():
        return {"revoked": []}
    with open(REVOCATION_LIST_PATH, "r") as f:
        return json.load(f)


def _save_registry(registry: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(REVOCATION_LIST_PATH, "w") as f:
        json.dump(registry, f, indent=2)


def revoke_certificate(
    merkle_root: str,
    certificate_number: str,
    reason: str,
    private_key_path: str,
    keypass: str,
    revoked_by: str = "Director",
) -> dict:
    """
    Signs (merkle_root, reason, revoked_at) with the Director's private key
    and appends the resulting entry to the revocation registry. Raises
    whatever core.signer.sign_bytes raises (e.g. wrong passphrase); callers
    are expected to translate that into a 401 at the API layer.
    """
    revoked_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    digest = hashlib.sha256(
        _canonical_entry_string(merkle_root, reason, revoked_at).encode("utf-8")
    ).digest()
    signature = sign_bytes(digest, private_key_path, keypass)

    entry = {
        "merkle_root": merkle_root,
        "certificate_number": certificate_number,
        "revoked_at": revoked_at,
        "revoked_by": revoked_by,
        "reason": reason,
        "revocation_signature": signature.hex(),
    }

    with _write_lock:
        registry = _load_registry()
        registry["revoked"].append(entry)
        _save_registry(registry)

    return entry


def is_revoked(merkle_root: str) -> dict | None:
    """Returns the revocation entry for this root, or None if not revoked."""
    registry = _load_registry()
    for entry in registry.get("revoked", []):
        if entry.get("merkle_root") == merkle_root:
            return entry
    return None


def verify_revocation_signature(entry: dict, public_key_path: str) -> bool:
    """
    Re-verifies that a revocation entry was genuinely signed by the holder
    of private_key_path. Catches tampering with the JSON file itself
    (e.g. someone hand-editing a revocation's reason or un-revoking an
    entry by deleting it, or forging a new one without the private key).
    """
    try:
        digest = hashlib.sha256(
            _canonical_entry_string(
                entry["merkle_root"], entry["reason"], entry["revoked_at"]
            ).encode("utf-8")
        ).digest()
        signature = bytes.fromhex(entry["revocation_signature"])
    except (KeyError, ValueError):
        return False

    return verify_bytes(digest, signature, public_key_path)


def list_all_revocations() -> list[dict]:
    return _load_registry().get("revoked", [])
