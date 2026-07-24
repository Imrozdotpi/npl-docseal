"""
db.py: shared PostgreSQL connection for NPL DocSeal.

The Verification Registry and the Audit Log used to be two independent
local SQLite files, one per machine. They're now two tables
(verification_registry, audit_log) inside one PostgreSQL database
(DATABASE_URL), so multiple machines can query the same live data.
core/verification_db.py and core/audit_db.py both import Base/engine/
SessionLocal from here rather than each managing their own connection.
"""

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.environ.get("DATABASE_URL", "")

if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is not set. NPL DocSeal requires a PostgreSQL "
        "connection string, e.g. "
        "postgresql://user:password@host:5432/npl_docseal. "
        "See .env.example."
    )

# pool_pre_ping: reconnects transparently if the shared Postgres instance
# (on a remote VM, possibly across a flaky network) drops an idle
# connection, instead of surfacing a stale-connection error to callers.
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()
