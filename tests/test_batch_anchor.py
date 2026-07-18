"""
tests/test_batch_anchor.py

Tests core/batch_anchor.py's BatchQueue and verify_inclusion(). These
exercise core.batch_anchor directly (not the HTTP API), but flush() still
performs a REAL Ethereum Sepolia transaction via core.timestamper.stamp_hash
— no mocking, same policy as the rest of this suite. The two tests that
need a flushed batch share a single real flush rather than repeating one
per test, to avoid firing a blockchain transaction for every assertion.

Requires the real SEPOLIA_* env vars configured (same requirement as any
other seal) — the server itself does not need to be running, since this
talks to core.batch_anchor directly.
    venv/Scripts/python.exe -m pytest tests/test_batch_anchor.py -v
"""

import hashlib
import time

from core.batch_anchor import BatchQueue, verify_inclusion


def _fake_root(tag: str) -> str:
    """A syntactically valid (64 hex char) fake Merkle root, unique per
    tag. Batch anchoring only cares that these are hex strings — it
    doesn't need a real sealed document behind them, so there's no need
    to actually run the seal pipeline for these tests."""
    return hashlib.sha256(tag.encode("utf-8")).hexdigest()


_FLUSH_CACHE: dict = {}


def _flushed_batch_of_5() -> tuple[dict, dict]:
    if "result" not in _FLUSH_CACHE:
        queue = BatchQueue(max_batch_size=5, max_wait_seconds=3600)
        roots = {f"doc-{i}": _fake_root(f"doc-{i}") for i in range(5)}
        for doc_id, root in roots.items():
            queue.add(root, doc_id)
        result = queue.flush()
        assert result is not None
        _FLUSH_CACHE["result"] = result
        _FLUSH_CACHE["roots"] = roots
    return _FLUSH_CACHE["result"], _FLUSH_CACHE["roots"]


def test_should_flush_triggers_at_max_batch_size():
    queue = BatchQueue(max_batch_size=3, max_wait_seconds=3600)
    assert queue.should_flush() is False

    queue.add(_fake_root("a"), "doc-a")
    assert queue.should_flush() is False

    queue.add(_fake_root("b"), "doc-b")
    assert queue.should_flush() is False

    queue.add(_fake_root("c"), "doc-c")
    assert queue.should_flush() is True


def test_flush_produces_valid_inclusion_proof_for_every_document():
    result, roots = _flushed_batch_of_5()
    batch_root = result["batch_root"]

    assert result["tx_hash"]
    assert set(result["proofs"].keys()) == set(roots.keys())

    for doc_id, root in roots.items():
        proof = result["proofs"][doc_id]
        assert verify_inclusion(root, proof, batch_root) is True


def test_tampered_root_fails_inclusion_while_others_still_pass():
    result, roots = _flushed_batch_of_5()
    batch_root = result["batch_root"]

    doc_ids = list(roots.keys())
    tampered_id = doc_ids[0]
    original = roots[tampered_id]
    flipped_char = "0" if original[0] == "f" else "f"
    tampered_root = flipped_char + original[1:]
    tampered_proof = result["proofs"][tampered_id]

    assert verify_inclusion(tampered_root, tampered_proof, batch_root) is False

    for doc_id in doc_ids[1:]:
        assert verify_inclusion(roots[doc_id], result["proofs"][doc_id], batch_root) is True


def test_max_wait_seconds_triggers_flush_before_batch_size_reached():
    queue = BatchQueue(max_batch_size=100, max_wait_seconds=2)
    queue.add(_fake_root("solo"), "doc-solo")
    assert queue.should_flush() is False

    time.sleep(2.5)
    assert queue.should_flush() is True

    result = queue.flush()
    assert result is not None
    assert result["document_ids"] == ["doc-solo"]
    assert verify_inclusion(_fake_root("solo"), result["proofs"]["doc-solo"], result["batch_root"]) is True
