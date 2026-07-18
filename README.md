# NPL DocSeal

![Tests](https://github.com/Imrozdotpi/npl-docseal/actions/workflows/test.yml/badge.svg)

A cryptographic document sealing and verification system for calibration
certificates. Combines RSA-4096 digital signatures, AES-256-GCM encryption,
Merkle-tree field-level tamper detection, and Ethereum Sepolia blockchain
anchoring into a single seal/verify pipeline, with a FastAPI backend and a
vanilla JS dashboard.

## What it does

- **Seal** — parses a calibration certificate XML, builds a Merkle tree over
  its fields, signs the root with RSA-4096, encrypts the original document
  with AES-256-GCM, anchors the root to Ethereum Sepolia, and packages
  everything into a single ZIP.
- **Verify & Recover** — decrypts a sealed ZIP, rebuilds the Merkle tree from
  the recovered document, and reports field-by-field which values are
  `INTACT`, `TAMPERED`, or `MISSING` relative to what was originally sealed —
  not just an overall pass/fail.
- **Audit Log dashboard** — every real seal/verify call is logged to a local
  SQLite database and surfaced as a live dashboard: performance timing
  broken down per pipeline step, tamper-frequency by field, a test-coverage
  matrix, and the blockchain anchor log.
- **Certificate preview** — renders the actual calibration certificate as a
  branded PDF (via ReportLab) directly in the Seal/Verify tabs.

## Project layout

```
core/            Cryptographic + parsing modules (signer, encryptor, merkle,
                 xml_parser, timestamper, audit_db, pdf_generator)
backend/api.py   FastAPI app: /api/seal, /api/verify, /api/audit/*, /api/preview-pdf
frontend/        Seal / Verify / Audit Log dashboard (vanilla HTML/CSS/JS)
tests/           Unit tests (hasher/merkle/signer) + a comprehensive pytest
                 suite that exercises the full pipeline against a live server
scripts/         Data-seeding utilities for the audit dashboard
cli.py           Command-line seal/verify, independent of the web UI
keygen.py        RSA key-pair generation (interactive or scripted)
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

Then open `http://127.0.0.1:8000`.

## Testing

```bash
pip install -r requirements-dev.txt

# Fast, no network — hasher/merkle/signer logic
pytest tests/test_hasher.py tests/test_merkle.py tests/test_signer.py tests/test_signer_v2.py -v

# Full pipeline — needs the server running (above) first; makes real
# RSA/AES/blockchain calls, no mocking. Takes several minutes.
pytest tests/test_comprehensive_suite.py -v
```

CI runs the fast tier on every push/PR. The full live/blockchain tier is
manual-dispatch only (see `.github/workflows/test.yml`) — it's slow, costs
real Sepolia testnet gas per run, and isn't meant to gate every merge.

## Deployment

_Docker + live deployment instructions go here — in progress._

## Known limitations / non-goals

- No authentication or user accounts — anyone with network access to the
  API can call any endpoint, including the audit log and (once added)
  revocation. Fine for this project's current scope; would need addressing
  before any real production use.
- The audit log is SQLite, sufficient at this scale — not intended to
  migrate to a heavier database.
- All blockchain anchoring targets Ethereum **Sepolia** (testnet) only —
  never mainnet.
