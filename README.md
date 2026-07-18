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
- **Public verification** (`/verify`): a third party uploads only the plain
  certificate document, no password, no ZIP, and gets back an independent
  PASS / FAIL / REVOKED verdict checked against NPL's registry. This is
  the realistic case: customers forward plain certificates to auditors,
  never cryptographic bundles.
- **Verify & Recover** (internal dashboard): decrypts a sealed ZIP,
  rebuilds the Merkle tree from the recovered document, and reports
  field-by-field which values are `INTACT`, `TAMPERED`, or `MISSING`. Kept
  for NPL's own internal QA against the original bundle format.
- **Revoke**: invalidates a certificate after the fact (a bad calibration
  reading discovered post-issuance, a compromised key, a failed audit) via
  a Director's-key-authorized action. A revoked certificate reports
  REVOKED to any verifier, even though it remains cryptographically valid,
  since revocation is a business decision, not a tampering signal.
- **Audit Log dashboard**: every real seal/verify call is logged to a local
  SQLite database and surfaced as a live dashboard: performance timing
  broken down per pipeline step, tamper-frequency by field, a test-coverage
  matrix, and the blockchain anchor log.
- **Certificate preview**: renders the actual calibration certificate as a
  branded PDF (via ReportLab) directly in the Seal/Verify tabs.

## Architecture: registry-based verification

Earlier versions of this project shipped the cryptographic proof (Merkle
root, signature, blockchain receipt) bundled in a ZIP alongside the
document, so verifying it meant re-uploading that whole bundle plus a
password. That doesn't match how certificates actually get used: a
customer forwards the plain certificate to their auditor, not a crypto
bundle.

The fix: at seal time, the proof is published independently to a small
public registry (`data/public_registry.db`, keyed by certificate number),
in addition to the ZIP NPL keeps for its own archival. A third party can
then verify with nothing but the document itself, hitting
`POST /api/public/verify` with just the plain XML, no password, no
bundled files required.

This splits the project into two portals sharing one backend:

- **Internal dashboard** (`/`, `frontend/internal/`): Seal, the legacy
  ZIP-based Verify & Recover (internal QA only), Revoke, and the Audit Log.
  This is NPL's own tool, requiring the Director's key passphrase for
  sealing and revoking.
- **Public verification page** (`/verify`, `frontend/public/`): a single-
  purpose checker with nothing else on it, no nav back to the internal
  dashboard, no encryption, no passwords, no audit log. This is the link
  meant to be shared publicly.

Both pages share design tokens/CSS via `/shared` (`frontend/shared/`),
mounted as its own static route since the two portals are otherwise
isolated static roots that can't reach into each other's directory.

Note there are two independent revocation mechanisms by design: the
legacy `core/revocation.py` / `/api/revoke` guards the old ZIP-based
`/api/verify` path, while `core/registry_db.py` / `/api/internal/revoke`
guards the registry and is what `/api/public/verify` actually checks. They
intentionally don't share state.

## Project layout

```
core/                  Cryptographic + parsing modules (signer, encryptor,
                        merkle, xml_parser, timestamper, audit_db,
                        revocation, registry_db, batch_anchor, pdf_generator)
backend/api.py          FastAPI app - seal/verify/registry/audit/batch endpoints
frontend/internal/      NPL's dashboard: Seal, Verify & Recover, Revoke, Audit Log
frontend/public/        Standalone public verification page (no auth, no dashboard)
frontend/shared/        CSS shared by both portals (mounted at /shared)
tests/                  Unit tests (hasher/merkle/signer) + comprehensive pytest
                        suites that exercise the full pipeline against a live server
scripts/                Data-seeding utilities for the audit dashboard
cli.py                  Command-line seal/verify, independent of the web UI
keygen.py               RSA key-pair generation (interactive or scripted)
```

## Setup

```bash
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
python keygen.py                # generates keys/private_key.pem + public_key.pem
```

Blockchain anchoring needs a `.env` file (not committed) with:

```
SEPOLIA_RPC_URL=...
SEPOLIA_PRIVATE_KEY=0x...
SEPOLIA_WALLET=0x...
```

## Running it

```bash
uvicorn backend.api:app --host 127.0.0.1 --port 8000 --reload
```

- NPL internal dashboard: `http://127.0.0.1:8000`
- Public verification page: `http://127.0.0.1:8000/verify`

## Testing

```bash
pip install -r requirements-dev.txt

# Fast, no network: hasher/merkle/signer logic
pytest tests/test_hasher.py tests/test_merkle.py tests/test_signer.py tests/test_signer_v2.py -v

# Full pipeline: needs the server running (above) first; makes real
# RSA/AES/blockchain calls, no mocking. Takes several minutes.
pytest tests/test_comprehensive_suite.py -v
pytest tests/test_revocation.py -v
pytest tests/test_batch_anchor.py -v
pytest tests/test_registry_verify.py -v
```

CI runs the fast tier on every push/PR. The full live/blockchain tier is
manual-dispatch only (see `.github/workflows/test.yml`): it's slow, costs
real Sepolia testnet gas per run, and isn't meant to gate every merge.

## Deployment

_Docker + live deployment instructions go here: in progress._

## Known limitations / non-goals

- `POST /api/public/verify` genuinely needs no password, no authentication,
  and no bundled files: only the certificate document itself, matching how
  documents are actually forwarded to third-party auditors in practice.
- No authentication or user accounts for the internal portal: anyone with
  network access to the API can call any endpoint, including sealing,
  revocation, and the audit log. Fine for this project's current scope;
  a real deployment would need at minimum a hardcoded admin password check
  here as a stopgap, and ideally proper auth. The `/api/internal/*` prefix
  exists specifically so it's obvious where that middleware would attach.
- The audit log is SQLite: sufficient at this scale, not intended to
  migrate to a heavier database. `data/public_registry.db` is kept as a
  separate SQLite file from `data/audit_log.db` and the two are never merged.
- Public verification only accepts XML; PDF parsing is not implemented.
- All blockchain anchoring targets Ethereum **Sepolia** (testnet) only;
  never mainnet.
