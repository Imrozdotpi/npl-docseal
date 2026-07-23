"""
Minimal auth for the internal dashboard.
NOT production-grade: a placeholder that prevents an open public
deployment from letting strangers seal certificates with the real
demo Sepolia wallet or impersonate the Director's signature.

A production version would need proper session management, hashed
credentials, and rate limiting. Documented as a known limitation.
"""

import os
import secrets
from fastapi import HTTPException, Header

DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")


def verify_dashboard_access(x_dashboard_key: str = Header(default="")):
    if not DASHBOARD_PASSWORD:
        # No password configured: dashboard access is open. Acceptable for
        # pure local dev only, never for a live deployment.
        return True
    if not secrets.compare_digest(x_dashboard_key, DASHBOARD_PASSWORD):
        raise HTTPException(401, "Invalid or missing dashboard access key")
    return True
