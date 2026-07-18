"""
batch_anchor.py: Batch Merkle anchoring for NPL DocSeal.

Instead of one Ethereum transaction per sealed document, BatchQueue groups
several document Merkle roots into a second-level Merkle tree and anchors
only the resulting batch_root: one transaction covers N documents. Each
document keeps a per-document inclusion proof (the sibling hashes needed
to walk back up to batch_root) as its evidence of having been anchored.

Note on proof format: core.merkle's tree hashes concatenate leaves in a
fixed left/right order (current[i] + current[i+1]), so verifying a proof
there requires knowing each sibling's side. The batch proof format here is
a flat list of sibling hashes with no side information (per spec), so this
tree instead combines pairs order-independently (sorted(a, b) before
hashing), making a flat sibling list sufficient to verify unambiguously.
"""

import threading
import time
from datetime import datetime, timezone

from core.merkle import _sha256
from core.timestamper import stamp_hash


def _pair_hash(a: str, b: str) -> str:
    lo, hi = sorted((a, b))
    return _sha256(lo + hi)


def _build_batch_tree(leaves: list) -> list:
    """
    Pair-and-hash Merkle construction (same pattern as core.merkle's
    _build_tree), returning every level bottom-to-top. Odd-sized levels are
    padded by duplicating the last node, and that padding is written back
    into the stored level so inclusion-proof lookups stay index-accurate.
    """
    if not leaves:
        return [[]]

    levels = [list(leaves)]
    current = list(leaves)

    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + [current[-1]]
            levels[-1] = current
        next_level = [_pair_hash(current[i], current[i + 1]) for i in range(0, len(current), 2)]
        levels.append(next_level)
        current = next_level

    return levels


def _inclusion_proof_for_index(levels: list, idx: int) -> list:
    proof = []
    index = idx
    for level in levels[:-1]:
        sibling_index = index + 1 if index % 2 == 0 else index - 1
        proof.append(level[sibling_index])
        index //= 2
    return proof


def verify_inclusion(document_root: str, proof: list, batch_root: str) -> bool:
    """
    Recomputes the path from document_root through the proof's sibling
    hashes and confirms it reaches batch_root.
    """
    current = document_root
    for sibling in proof:
        current = _pair_hash(current, sibling)
    return current == batch_root


class BatchQueue:
    """
    Holds pending document Merkle roots awaiting blockchain anchoring.
    Flushes when either max_batch_size documents have accumulated or
    max_wait_seconds has elapsed since the oldest pending item was added,
    whichever comes first.
    """

    def __init__(self, max_batch_size: int = 20, max_wait_seconds: int = 60):
        self.max_batch_size = max_batch_size
        self.max_wait_seconds = max_wait_seconds
        self._pending: list[tuple[str, str]] = []  # (document_id, document_root)
        self._first_added_at: float | None = None
        self._lock = threading.Lock()

    def add(self, document_root: str, document_id: str) -> None:
        with self._lock:
            if not self._pending:
                self._first_added_at = time.time()
            self._pending.append((document_id, document_root))

    def should_flush(self) -> bool:
        with self._lock:
            if not self._pending:
                return False
            if len(self._pending) >= self.max_batch_size:
                return True
            return (
                self._first_added_at is not None
                and (time.time() - self._first_added_at) >= self.max_wait_seconds
            )

    def flush(self) -> dict | None:
        """
        Builds the second-level Merkle tree over all currently pending
        document roots, anchors batch_root to Ethereum, and computes each
        document's inclusion proof. Returns None if nothing was pending.
        """
        with self._lock:
            if not self._pending:
                return None
            batch = self._pending
            self._pending = []
            self._first_added_at = None

        document_ids = [doc_id for doc_id, _ in batch]
        leaves = [root for _, root in batch]

        levels = _build_batch_tree(leaves)
        batch_root = levels[-1][0]

        anchor = stamp_hash(batch_root)

        proofs = {
            document_ids[i]: _inclusion_proof_for_index(levels, i)
            for i in range(len(leaves))
        }

        return {
            "batch_root": batch_root,
            "tx_hash": anchor["tx_hash"],
            "block_number": anchor["block_number"],
            "status": anchor["status"],
            "etherscan_url": anchor["etherscan_url"],
            "flushed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "document_ids": document_ids,
            "proofs": proofs,
        }
