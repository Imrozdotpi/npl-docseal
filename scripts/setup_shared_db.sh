#!/usr/bin/env bash
# scripts/setup_shared_db.sh
#
# One-command bootstrap for a new machine (e.g. a collaborator) to get
# the shared PostgreSQL + Adminer stack running locally, pointed at
# their own copy of the database by default. Safe to re-run: never
# overwrites an existing .env, and `docker compose up -d` is itself
# idempotent.
#
# Usage:
#   bash scripts/setup_shared_db.sh
#
# After this finishes, edit .env with your real Sepolia/dashboard
# secrets (DATABASE_URL is already usable as-is for local testing),
# then run the app normally: uvicorn backend.api:app --reload

set -e

if ! command -v docker &> /dev/null; then
    echo "[setup] Docker is not installed or not on PATH. Install Docker Desktop first:"
    echo "        https://www.docker.com/products/docker-desktop/"
    exit 1
fi

if [ ! -f .env ]; then
    echo "[setup] No .env found, copying .env.example -> .env"
    cp .env.example .env
    echo "[setup] Edit .env now to fill in real Sepolia/dashboard values if you have them."
    echo "        The Postgres/DATABASE_URL defaults are already usable for local testing."
else
    echo "[setup] .env already exists, leaving it untouched."
fi

echo "[setup] Starting Postgres + Adminer..."
docker compose up -d

echo "[setup] Waiting for Postgres to report healthy..."
until [ "$(docker inspect -f '{{.State.Health.Status}}' npl-docseal-postgres-1 2>/dev/null)" = "healthy" ]; do
    sleep 2
done

echo ""
echo "[setup] Done. Postgres and Adminer are running."
echo "        Adminer (database GUI): http://localhost:8080"
echo "          System: PostgreSQL | Server: postgres | credentials: your .env"
echo ""
echo "Next steps:"
echo "  1. python -m venv venv && source venv/Scripts/activate  (or venv/bin/activate on Mac/Linux)"
echo "  2. pip install -r requirements.txt"
echo "  3. If you have old local SQLite data to bring over: python scripts/migrate_to_postgres.py"
echo "  4. uvicorn backend.api:app --host 127.0.0.1 --port 8000 --reload"
echo "  5. Open http://127.0.0.1:8000 and try sealing/verifying a certificate."
