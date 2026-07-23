"""
Runs once at application startup. Ensures the runtime environment is
ready even on a completely fresh container with no persisted volumes:
  - generates a demo RSA keypair if none exists
  - initializes both SQLite databases if they don't exist
Idempotent and safe to run on every container boot: never overwrites an
existing keypair or database.
"""

import os
from pathlib import Path

from core.audit_db import init_db as init_audit_db
from core.verification_db import init_verification_db
from keygen import generate_keys

DEMO_KEY_PASSPHRASE = os.environ.get("DEMO_KEY_PASSPHRASE", "demo-passphrase-change-me")


def ensure_keys_exist():
    priv = Path("keys/private_key.pem")
    pub = Path("keys/public_key.pem")
    if priv.exists() and pub.exists():
        return

    print("[startup] No RSA keypair found, generating fresh demo keypair.")
    generate_keys(DEMO_KEY_PASSPHRASE, output_dir=priv.parent)
    print("[startup] Demo keypair generated. Passphrase from DEMO_KEY_PASSPHRASE env var.")


def ensure_databases_exist():
    init_audit_db()
    try:
        init_verification_db()
    except Exception as e:
        # Non-fatal: the rest of the app (Seal, Decrypt, Audit Log) must
        # keep working even if the Verification Registry can't be
        # initialized. /api/public/verify and the seal-time registration
        # hook both check the registry defensively at call time too.
        print(f"[verification_registry] Failed to initialize database: {e}")


def run_startup_checks():
    Path("data").mkdir(exist_ok=True)
    Path("sealed").mkdir(exist_ok=True)
    ensure_keys_exist()
    ensure_databases_exist()
