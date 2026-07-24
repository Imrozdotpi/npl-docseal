# NPL DocSeal

![Tests](https://github.com/Imrozdotpi/npl-docseal/actions/workflows/test.yml/badge.svg)

A cryptographic document sealing and verification system for calibration
certificates. Combines RSA-4096 digital signatures, AES-256-GCM encryption,
Merkle-tree field-level tamper detection, and Ethereum Sepolia blockchain
anchoring into a single seal/verify pipeline, with a FastAPI backend and a
vanilla JS dashboard.

## What it does

- **Seal**: parses a calibration certificate XML, builds a Merkle tree over
  its fields, signs the root with RSA-4096, encrypts the original document
  with AES-256-GCM, anchors the root to Ethereum Sepolia, packages
  everything into a ZIP for NPL's own archival, and publishes the proof to
  a public registry keyed by certificate number.
- **Certificate verification** (`POST /api/public/verify`): a third party
  uploads only the plain certificate document, no password, no ZIP, and
  gets back one comprehensive report - Merkle root match, field-level
  tamper detail, RSA signature validity, blockchain anchor status,
  expiry, and revocation - collapsing to one of six results: Authentic,
  Authentic but Expired, Authentic but Revoked, Authentic but Expired and
  Revoked, Tampered, or Not Issued by NPL. This matches how certificates
  actually get used: customers forward the plain document to auditors,
  never a crypto bundle. The same endpoint backs **two** frontends - the
  standalone public page (`/verify`, no login) and the internal
  dashboard's "Verify Document" tab - so results can never disagree
  between them. Every certificate is registered automatically the moment
  `/api/seal` completes successfully, never a manual step, and never for
  a seal that failed partway.
- **Decrypt** (internal dashboard): decrypts a sealed ZIP, rebuilds the
  Merkle tree from the recovered document, and reports field-by-field
  which values are `INTACT`, `TAMPERED`, or `MISSING`. Kept for NPL's own
  internal QA against the original bundle format.
- **Audit Log dashboard**: every real seal/verify call is logged to the
  shared PostgreSQL database and surfaced as a live dashboard: performance
  timing broken down per pipeline step, tamper-frequency by field, a
  test-coverage matrix, and the blockchain anchor log.
- **Certificate preview**: renders the actual calibration certificate as a
  branded PDF (via ReportLab) directly in the Seal/Verify tabs.

## Architecture: registry-based verification

Earlier versions of this project shipped the cryptographic proof (Merkle
root, signature, blockchain receipt) bundled in a ZIP alongside the
document, so verifying it meant re-uploading that whole bundle plus a
password. That doesn't match how certificates actually get used: a
customer forwards the plain certificate to their auditor, not a crypto
bundle.

The fix: at seal time, the proof is published independently to a
Verification Registry (the `verification_registry` table, keyed by
certificate number), in addition to the ZIP NPL keeps for its own
archival. A third party can then verify with nothing but the document
itself, hitting `POST /api/public/verify` with just the plain XML, no
password, no bundled files required.

This used to be two separate SQLite tables (a "public registry" holding
crypto proof, and a leaner "verification registry" holding only expiry/
revocation) populated by two independent calls at seal time. They
drifted apart during development and produced an incorrect result before
the drift was caught, so they were merged into the single table
described above: one row per certificate, written once per seal, read by
the one verification endpoint. See `core/verification_db.py`.

Both this table and the Audit Log now live in a shared **PostgreSQL**
database (see "Shared database" below) rather than per-machine SQLite
files, so multiple machines, yours and a colleague's, can query the same
live registry and audit history at once.

This splits the project into three static pages sharing one backend:

- **Landing page** (`/`, `frontend/landing/`): a small portal picker with
  no functionality of its own, just two links. No login/access control on
  any of this yet (see "Known limitations") - this is a basic version to
  be layered with real security later.
- **Internal dashboard** (`/dashboard`, `frontend/internal/`): Seal, the
  legacy ZIP-based Decrypt tab (internal QA only), Verify Document, and
  the Audit Log. This is NPL's own tool, requiring the Director's key
  passphrase for sealing.
- **Public verification page** (`/verify`, `frontend/public/`): a single-
  purpose checker with nothing else on it, no encryption, no passwords,
  no audit log. This is the link meant to be shared publicly. Both this
  page and the internal dashboard's Verify Document tab call the same
  `/api/public/verify`.

Each of the internal dashboard and public page has an "All Portals" link
back to the landing page, so switching between them doesn't mean typing
a new URL by hand. All three pages share design tokens/CSS via `/shared`
(`frontend/shared/`), mounted as its own static route since each portal
is otherwise an isolated static root that can't reach into another's
directory.

## Project layout

```
core/                  Cryptographic + parsing modules (signer, encryptor,
                        merkle, xml_parser, timestamper, audit_db,
                        verification_db, verification_service,
                        batch_anchor, pdf_generator), plus db.py (shared
                        PostgreSQL engine/session), startup.py (first-boot
                        key/DB bring-up), and auth.py (dashboard access gate)
backend/api.py          FastAPI app - seal/verify/verification/audit/batch endpoints
frontend/landing/       Portal picker page, served at "/"
frontend/internal/      NPL's dashboard (served at "/dashboard"): Seal, Decrypt,
                        Verify Document, Audit Log, gated by dashboard-auth.js
frontend/public/        Standalone public verification page, served at "/verify"
                        (no auth, no dashboard)
frontend/shared/        CSS shared by all three pages (mounted at /shared)
tests/                  Unit tests (hasher/merkle/signer) + comprehensive pytest
                        suites that exercise the full pipeline against a live server
scripts/                Data-seeding utilities for the audit dashboard, the
                        SQLite -> PostgreSQL migration utility
                        (migrate_to_postgres.py), and setup_shared_db.sh
                        for bootstrapping the Postgres/Adminer stack
cli.py                  Command-line seal/verify, independent of the web UI
keygen.py               RSA key-pair generation (interactive or scripted)
Dockerfile,             Containerization for the FastAPI app itself: image
.dockerignore           build, directories/secrets deliberately excluded from
                        the image (see "Deployment: the app itself"). Not
                        currently run by docker-compose.yml (see below).
docker-compose.yml      Runs ONLY the shared PostgreSQL + Adminer stack (see
                        "Shared database"); does not containerize the app.
```

## Setup

```bash
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
python keygen.py                # generates keys/private_key.pem + public_key.pem
```

Copy `.env.example` to `.env` and fill in real values (`.env` is
gitignored, never commit it). At minimum you need:

```
DATABASE_URL=postgresql://user:password@host:5432/npl_docseal
SEPOLIA_RPC_URL=...
SEPOLIA_PRIVATE_KEY=0x...
SEPOLIA_WALLET=0x...
```

`DATABASE_URL` is required: the app now stores the Verification Registry
and Audit Log in PostgreSQL, not local SQLite files, so it always needs a
real database to connect to, even for local development. The quickest way
to get one running locally is the bundled `docker-compose.yml` (see
"Shared database" below); `POSTGRES_USER`/`POSTGRES_PASSWORD`/
`POSTGRES_DB` in `.env` configure that local container, and `DATABASE_URL`
should point at it (or, for a real shared setup, at wherever the database
is actually hosted, see "Shared database").

## Running it

```bash
uvicorn backend.api:app --host 127.0.0.1 --port 8000 --reload
```

- Landing page (choose a portal): `http://127.0.0.1:8000`
- NPL internal dashboard: `http://127.0.0.1:8000/dashboard`
- Public verification page: `http://127.0.0.1:8000/verify`
- Health check (used by the Docker healthcheck): `http://127.0.0.1:8000/health`

Set `DASHBOARD_PASSWORD` in `.env` to require an access key for sealing
and clearing the audit log; leave it unset for open local dev (see
"Deployment" below).

## Testing

```bash
pip install -r requirements-dev.txt

# Fast, no network: hasher/merkle/signer logic
pytest tests/test_hasher.py tests/test_merkle.py tests/test_signer.py tests/test_signer_v2.py -v

# Full pipeline: needs the server running (above) first; makes real
# RSA/AES/blockchain calls, no mocking. Takes several minutes.
pytest tests/test_comprehensive_suite.py -v
pytest tests/test_batch_anchor.py -v
pytest tests/test_registry_verify.py -v
```

CI runs the fast tier on every push/PR. The full live/blockchain tier is
manual-dispatch only (see `.github/workflows/test.yml`): it's slow, costs
real Sepolia testnet gas per run, and isn't meant to gate every merge.

## Deployment

There are two independent things that can be deployed here: the shared
**database** (so multiple machines see the same Verification Registry and
Audit Log), and the **app itself** (so it's reachable at a public URL
instead of only `localhost`). They don't depend on each other, you can
run the app locally against a shared cloud database, or run everything
locally, or eventually deploy both.

### Shared database (PostgreSQL)

`docker-compose.yml` at the project root runs **only** PostgreSQL and
Adminer (a web GUI for browsing the database); it does not containerize
the FastAPI app.

**Local development:**

```bash
docker compose up -d
```

This starts Postgres (with a named volume, so data survives container
restarts and even a full `docker compose down && docker compose up`) and
Adminer at `http://localhost:8080`. Log into Adminer with System:
PostgreSQL, Server: `postgres` (the Docker service name, not `localhost`,
Adminer runs in its own container), and the username/password/database
from your `.env`. Point `DATABASE_URL` in `.env` at this same local
instance, then run the app normally (`uvicorn backend.api:app ...`); it
creates the `verification_registry` and `audit_log` tables on first
startup.

**Migrating existing local SQLite data:**

If you have pre-existing `data/verification_registry.db` and/or
`data/audit_log.db` files from before this migration, copy every row
across (once, safely re-runnable) with:

```bash
python scripts/migrate_to_postgres.py
```

This only reads the SQLite files (never modifies or deletes them, keep
them as a backup) and preserves every field exactly, including original
audit log ids and certificate data. See the docstring at the top of that
script for full details on conflict handling and re-run safety.

**Deploying the database to a cloud VM** (so more than one machine can
reach it, e.g. Oracle Cloud's Always Free tier):

1. Provision a small VM (Oracle Cloud's Always Free Ampere instance
   works well) and install Docker on it.
2. Copy `docker-compose.yml` and a real `.env` (with `POSTGRES_USER`,
   `POSTGRES_PASSWORD`, `POSTGRES_DB` set, never commit this file) to the
   VM.
3. `docker compose up -d` on the VM.
4. Open the VM's firewall/security-list for the Postgres port (5432) and
   Adminer's port (8080) if you want remote GUI access too. Restrict
   these to known IPs where possible rather than the whole internet.
5. On every client machine (yours, a colleague's), set `DATABASE_URL` in
   their own local `.env` to point at the VM's address instead of
   `localhost`, e.g. `postgresql://user:password@<vm-ip>:5432/npl_docseal`.
   Everyone's local app now reads and writes the same shared registry and
   audit log.

### The app itself (optional, for later)

Separately from the database, the FastAPI app can also be containerized
and deployed publicly using the standalone `Dockerfile` (not orchestrated
by `docker-compose.yml`, which is dedicated to the database stack above).
This is dormant until you actually want the app reachable at a public
URL; nothing about the database migration requires it.

```bash
docker build -t npl-docseal .
docker run -p 8000:8000 \
    -v "$(pwd)/keys:/app/keys" \
    -v "$(pwd)/sealed:/app/sealed" \
    --env-file .env \
    npl-docseal
```

`keys/` and `sealed/` are never baked into the image (see
`.dockerignore`): on a container with no mounted volumes, `core/startup.py`
generates a fresh demo RSA keypair (passphrase from `DEMO_KEY_PASSPHRASE`,
defaults to `demo-passphrase-change-me`) if none exists. `DATABASE_URL`
still needs to point at a real reachable PostgreSQL instance, either the
same shared one from above, or a fresh one, since the app no longer has a
local-file fallback. `GET /health` is the container healthcheck endpoint.

**Deploying the app to Render (or Railway), once you want it public:**

1. Push `Dockerfile`, `.dockerignore`, and all source to GitHub. Confirm
   `.gitignore` already excludes `keys/`, `data/`, and `.env` (it does).
2. Create a new Web Service, connect the GitHub repo, select "Docker" as
   the environment.
3. Set environment variables in the platform's dashboard: `DATABASE_URL`
   (pointing at your shared Postgres instance), `SEPOLIA_RPC_URL`,
   `SEPOLIA_WALLET`, `SEPOLIA_PRIVATE_KEY`, `DASHBOARD_PASSWORD`,
   `DEMO_KEY_PASSPHRASE`.
4. If you want sealed ZIPs/keys to persist across redeploys, add a
   persistent disk mounted at `/app/keys`; without it, a fresh demo
   keypair is generated on every redeploy (harmless, just not the same
   key as before).
5. Deploy. The platform builds the Docker image and exposes a public URL.
   Its root (`/`) is already the landing page per the static mount order
   in `backend/api.py`, so visitors land on the portal picker first.

### Access control on `/dashboard`

Setting `DASHBOARD_PASSWORD` gates `POST /api/seal` and
`POST /api/audit/clear` behind an `X-Dashboard-Key` header
(`core/auth.py`); the internal dashboard prompts for this key on first
load and stores it in `sessionStorage` (`frontend/internal/dashboard-auth.js`).
This is explicitly a placeholder, not a real auth system: no hashing, no
sessions, no rate limiting, just enough to stop casual public misuse of a
live demo's real signing key and real (test) Sepolia wallet. Leaving
`DASHBOARD_PASSWORD` unset (e.g. local dev) leaves the dashboard open, as
before. `POST /api/public/verify` is never gated, by design.

### Non-goals for this sprint

- No real user account system: `DASHBOARD_PASSWORD` is one shared key, not
  per-user accounts.
- No HTTPS termination configuration: hosting platforms handle this
  automatically.
- No orchestration beyond `docker compose` (Postgres + Adminer): plenty
  for this scale, no Kubernetes/managed-database service needed.
- Real Sepolia private keys are never committed, only ever supplied via
  `.env` (gitignored) or the hosting platform's secret store.

## Known limitations / non-goals

- `POST /api/public/verify` genuinely needs no password, no authentication,
  and no bundled files: only the certificate document itself, matching how
  documents are actually forwarded to third-party auditors in practice.
- No real authentication or user accounts for the internal portal.
  `DASHBOARD_PASSWORD` (see "Deployment" above) gates sealing and clearing
  the audit log behind one shared key, a placeholder stopgap, not proper
  auth: no hashing, no sessions, no rate limiting, and every other internal
  endpoint (Decrypt, Verify Document, reading the audit log) is still
  open to anyone with network access. Fine for this project's current
  scope; a real deployment would need proper per-user auth.
- The Verification Registry and Audit Log are two tables
  (`verification_registry`, `audit_log`) in one shared PostgreSQL
  database (`DATABASE_URL`), not separate SQLite files anymore. They're
  still logically independent within that database: separate tables,
  separate SQLAlchemy models, and the Verify Document / public
  verification flows never read from or write to the audit log.
- The Verification Registry (`verification_registry` table) stores
  `certificate_number`, `merkle_root`, `field_hashes`, `signature_hex`,
  `public_key_fingerprint`, `tx_hash`, `block_number`, `etherscan_url`,
  `sealed_at`, `issue_date`, `expiry_date`, `status`, and `created_at` -
  not the XML content itself, so it can never substitute for the sealed
  ZIP. There's no revoke/expire UI yet; `status` is settable today only
  by editing the row directly (or via `core.verification_service.register_certificate`).
  `scripts/migrate_to_postgres.py` is the one-time migration from
  per-machine SQLite files into the shared PostgreSQL database; it backs
  up rather than deletes whatever it finds.
- Public verification only accepts XML; PDF parsing is not implemented.
- All blockchain anchoring targets Ethereum **Sepolia** (testnet) only;
  never mainnet.
