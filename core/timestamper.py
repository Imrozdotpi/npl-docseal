"""
timestamper.py: Ethereum Sepolia blockchain timestamping

Replaces the OpenTimestamps/WSL implementation.
Anchors the Merkle root hash to Ethereum Sepolia testnet.
Confirmation time: ~12 seconds (vs ~1 hour for Bitcoin).
No WSL, no subprocess, works natively on Windows/Linux/Mac.

Environment variables required:
    SEPOLIA_RPC_URL: Alchemy Sepolia HTTPS endpoint
    SEPOLIA_PRIVATE_KEY: wallet private key (hex, with 0x prefix)
    SEPOLIA_WALLET: wallet address (0x...)
"""

import json
import os

# auto-load .env file if present
from pathlib import Path as _Path
_env_file = _Path(__file__).parent.parent / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        if "=" in _line and not _line.startswith("#"):
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())


import hashlib
from pathlib import Path

from web3 import Web3


# ── configuration ──────────────────────────────────────────────

RPC_URL     = os.environ.get("SEPOLIA_RPC_URL", "")
PRIVATE_KEY = os.environ.get("SEPOLIA_PRIVATE_KEY", "")
WALLET      = os.environ.get("SEPOLIA_WALLET", "")
CHAIN_ID    = 11155111  # Ethereum Sepolia


class TimestampError(Exception):
    """Raised when timestamping operations fail."""
    pass


def _get_web3() -> Web3:
    """Connect to Sepolia and validate connection."""
    if not RPC_URL:
        raise TimestampError(
            "SEPOLIA_RPC_URL environment variable not set."
        )
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        raise TimestampError(
            "Cannot connect to Ethereum Sepolia. Check your RPC URL."
        )
    return w3


# ── stamp ──────────────────────────────────────────────────────

def stamp_hash(hash_hex: str) -> dict:
    """
    Anchor an arbitrary SHA-256 hex hash to Ethereum Sepolia blockchain.

    Same transaction-sending logic stamp_file() uses, factored out so
    batch anchoring (core/batch_anchor.py) can anchor a batch root
    directly without needing a file on disk to hash first.

    Returns the proof dict directly. Unlike stamp_file(), this does not
    write anything to disk; callers decide whether and where to persist it.
    """
    if not PRIVATE_KEY or not WALLET:
        raise TimestampError(
            "SEPOLIA_PRIVATE_KEY and SEPOLIA_WALLET must be set."
        )

    w3 = _get_web3()

    checksum_wallet = w3.to_checksum_address(WALLET)
    nonce = w3.eth.get_transaction_count(checksum_wallet, "pending")

    # embed hash as transaction data
    data_hex = "0x" + hash_hex

    tx = {
        "nonce":    nonce,
        "to":       checksum_wallet,  # self-send to anchor data only
        "value":    0,
        "gas":      50000,
        "gasPrice": w3.eth.gas_price,
        "chainId":  CHAIN_ID,
        "data":     data_hex,
    }

    # sign and broadcast
    signed   = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash  = w3.eth.send_raw_transaction(signed.raw_transaction)
    tx_hex   = tx_hash.hex()

    print(f"  Blockchain tx sent : {tx_hex}")
    print(f"  Etherscan URL      : https://sepolia.etherscan.io/tx/{tx_hex}")
    print(f"  Waiting for confirmation (~12 seconds)...")

    # wait for receipt
    try:
        receipt      = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180, poll_latency=3)
        block_number = receipt.blockNumber
        status       = "confirmed" if receipt.status == 1 else "failed"
        print(f"  Confirmed in block : {block_number}")
    except Exception:
        block_number = None
        status       = "pending"
        print(f"  Still pending, check Etherscan for confirmation.")

    return {
        "hash":          hash_hex,
        "tx_hash":       tx_hex,
        "block_number":  block_number,
        "chain":         "Ethereum Sepolia",
        "chain_id":      CHAIN_ID,
        "status":        status,
        "etherscan_url": f"https://sepolia.etherscan.io/tx/{tx_hex}",
        "wallet":        WALLET,
    }


def stamp_file(filepath: str) -> str:
    """
    Anchor a file's SHA-256 hash to Ethereum Sepolia blockchain.

    Embeds the hash as transaction data and waits for confirmation.
    Saves a .ots JSON proof file alongside the original.

    Returns:
        Path to the generated .ots proof file.
    """
    file_path = Path(filepath).resolve()
    if not file_path.exists():
        raise FileNotFoundError(filepath)

    # compute SHA-256 of file
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    file_hash = sha256.hexdigest()

    result = stamp_hash(file_hash)

    # write proof file, same shape as before the stamp_hash() refactor
    proof = {
        "file":          file_path.name,
        "file_hash":     result["hash"],
        "tx_hash":       result["tx_hash"],
        "block_number":  result["block_number"],
        "chain":         result["chain"],
        "chain_id":      result["chain_id"],
        "status":        result["status"],
        "etherscan_url": result["etherscan_url"],
        "wallet":        result["wallet"],
    }

    ots_path = str(file_path) + ".ots"
    with open(ots_path, "w") as f:
        json.dump(proof, f, indent=2)

    return ots_path


# ── verify ─────────────────────────────────────────────────────

def verify_timestamp(ots_path: str) -> dict:
    """
    Verify a previously created timestamp proof against Sepolia.

    Returns:
        {
            "status":        "confirmed" | "pending" | "failed",
            "block_height":  int | None,
            "tx_hash":       str | None,
            "etherscan_url": str | None
        }
    """
    ots_file = Path(ots_path).resolve()

    if not ots_file.exists():
        return {
            "status": "failed",
            "block_height": None,
            "tx_hash": None,
            "etherscan_url": None,
        }

    try:
        with open(ots_file, "r") as f:
            proof = json.load(f)
    except Exception:
        return {
            "status": "failed",
            "block_height": None,
            "tx_hash": None,
            "etherscan_url": None,
        }

    tx_hash   = proof.get("tx_hash")
    etherscan = proof.get("etherscan_url")

    if not tx_hash:
        return {
            "status": "failed",
            "block_height": None,
            "tx_hash": None,
            "etherscan_url": None,
        }

    try:
        w3      = _get_web3()
        receipt = w3.eth.get_transaction_receipt(tx_hash)

        if receipt is None:
            return {
                "status": "pending",
                "block_height": None,
                "tx_hash": tx_hash,
                "etherscan_url": etherscan,
            }

        status = "confirmed" if receipt.status == 1 else "failed"
        return {
            "status":        status,
            "block_height":  receipt.blockNumber,
            "tx_hash":       tx_hash,
            "etherscan_url": etherscan,
        }

    except Exception:
        # network issue, fall back to saved proof status
        return {
            "status":        proof.get("status", "pending"),
            "block_height":  proof.get("block_number"),
            "tx_hash":       tx_hash,
            "etherscan_url": etherscan,
        }


def upgrade_timestamp(ots_path: str) -> bool:
    """
    Check if timestamp is confirmed.
    Returns True if confirmed, False if pending.
    Kept for compatibility with existing api.py and cli.py calls.
    """
    result = verify_timestamp(ots_path)
    return result["status"] == "confirmed"


def get_timestamp_info(ots_path: str) -> str:
    """
    Return human-readable timestamp summary.
    Kept for CLI compatibility.
    """
    ots_file = Path(ots_path).resolve()
    if not ots_file.exists():
        raise FileNotFoundError(ots_path)

    with open(ots_file, "r") as f:
        proof = json.load(f)

    lines = [
        f"Chain    : {proof.get('chain', 'Ethereum Sepolia')}",
        f"TX Hash  : {proof.get('tx_hash', 'N/A')}",
        f"Block    : {proof.get('block_number', 'pending')}",
        f"Status   : {proof.get('status', 'unknown')}",
        f"Etherscan: {proof.get('etherscan_url', 'N/A')}",
    ]
    return "\n".join(lines)