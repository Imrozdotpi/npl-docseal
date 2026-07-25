# NPL DocSeal

Cryptographic sealing and verification for calibration certificates, tamper-evident at the field level, no password or bundle required.

![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

**Live demo:** [ placeholder, deployed URL TBD ]

## The Problem

Calibration certificates from NPL are issued as plain, editable files. A customer can quietly alter a validity date or a measurement reading and hand the altered document to an auditor. There is no way for a third party to tell the file was ever changed, and NPL bears the liability for an instrument that was actually out of calibration.

## The Solution

Each certificate's XML is parsed into individual fields: dates, readings, instrument identity, uncertainties. Every field is hashed and combined into a Merkle tree, producing one root hash for the entire document. That root is signed with an RSA-4096 private key, the original document is encrypted with AES-256-GCM for archival, and the root is anchored to the Ethereum Sepolia blockchain as an independent, public timestamp. The resulting proof, root, signature, and blockchain reference, is published to a Verification Registry keyed by certificate number.

## Why It's Different

- **Field-level tamper attribution**: not a whole-document binary pass/fail; the exact altered field is flagged.
- **No password or bundle needed**: verification works from the plain certificate alone.
- **Fully decentralized checking**: the public endpoint recomputes and looks up the proof; no contact with NPL required.

## Architecture

```
┌────────────────┐   ┌────────────────┐   ┌────────────────┐
│  Landing /     │   │  Internal NPL  │   │  Public verify │
│  portal picker │   │  dashboard     │   │  page (no login│
│                │   │  (seal / audit)│   │  required)     │
└───────┬────────┘   └───────┬────────┘   └───────┬────────┘
        │                    │                     │
        └────────────────────┼─────────────────────┘
                              │
                     ┌────────▼─────────┐
                     │  FastAPI backend │
                     └────────┬─────────┘
                              │
                ┌─────────────┼─────────────┐
                │                           │
       ┌────────▼─────────┐       ┌─────────▼──────────┐
       │ PostgreSQL        │       │ Ethereum Sepolia    │
       │ (verification_    │       │ (blockchain anchor  │
       │ registry +        │       │ + confirmation)      │
       │ audit_log tables) │       │                      │
       └────────────────────┘       └──────────────────────┘
```

The internal dashboard and public verify page are two of three static frontends (plus the landing/portal picker) served by the same FastAPI backend, all reading and writing the same PostgreSQL database, so results can never disagree between an NPL staff member's view and a third party's.

## Tech Stack

| Layer | Tools |
|---|---|
| Language / API | Python, FastAPI |
| Crypto | `cryptography` (RSA-4096-PSS, AES-256-GCM) |
| Blockchain | web3.py, Ethereum Sepolia |
| Data | PostgreSQL, SQLAlchemy |
| Deployment | Docker (database stack), Render/Railway (optional, for the app itself) |

## Quick Start

```bash
# clone
git clone https://github.com/Imrozdotpi/npl-docseal.git
cd npl-docseal

# install
python -m venv venv
venv\Scripts\activate          # Windows; venv/bin/activate on Mac/Linux
pip install -r requirements.txt

# generate RSA-4096 signing keys
python keygen.py

# set up your own .env (DATABASE_URL, Sepolia RPC/wallet/key, dashboard password)
# then bring up the shared PostgreSQL + Adminer stack:
bash scripts/setup_shared_db.sh

# run
uvicorn backend.api:app --host 127.0.0.1 --port 8000 --reload
```

Open `http://127.0.0.1:8000` for the portal picker, `/dashboard` for the internal tool, or `/verify` for the public checker.

## Status / Known Limitations

- The internal dashboard has a lightweight access-key gate (`DASHBOARD_PASSWORD`), not full user authentication, by design for the current scope.
- Blockchain anchoring runs on Ethereum Sepolia (testnet) only, never mainnet.
- Verification currently supports XML-format certificates only.
- This snapshot of the repository does not currently include an automated test suite.

## License / Author

License: [MIT](LICENSE)

Authors:
- [Imroz Kamboj](https://github.com/Imrozdotpi)
- [Karan Chauhan](https://github.com/Karan-11-Coder)
