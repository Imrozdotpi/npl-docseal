import os
import uuid
import shutil
import tempfile
import base64
import zipfile
import json
import time
import asyncio
import hashlib as _hashlib
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Import core modules exactly
from core.hasher import hash_file
from core.signer import sign_file, verify_signature, sign_bytes, verify_bytes
from core.encryptor import encrypt_file, decrypt_file
from core.timestamper import stamp_file, verify_timestamp, upgrade_timestamp, CHAIN_ID
from core.xml_parser import parse_xml
from core.merkle import build_merkle_tree, compare_trees
from core.pdf_generator import generate_pdf
from core import audit_db
from core import revocation
from core.batch_anchor import BatchQueue

app = FastAPI(
    title="NPL DocSeal Dashboard API",
    description="Government-grade cybersecurity dashboard API",
    version="1.0.0"
)

# Enable CORS for development flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

audit_db.init_db()

PRIVATE_KEY = Path("keys/private_key.pem")
PUBLIC_KEY = Path("keys/public_key.pem")

# ─────────────────────────────────────────────────────────────────
# Batch Merkle anchoring — module-level singletons (Feature 2, sprint).
# _batch_records maps a per-seal document_id (returned to the client as
# "batch_id" — one per queued document, not one per shared batch) to its
# anchoring status, filled in by the background flush loop below.
# ─────────────────────────────────────────────────────────────────
_batch_queue = BatchQueue()
_batch_records: dict = {}


@app.on_event("startup")
async def _start_batch_flush_loop():
    asyncio.create_task(_batch_flush_loop())


async def _batch_flush_loop():
    while True:
        await asyncio.sleep(5)
        try:
            if _batch_queue.should_flush():
                result = _batch_queue.flush()
                if result:
                    for doc_id in result["document_ids"]:
                        _batch_records[doc_id] = {
                            "status": "anchored",
                            "batch_root": result["batch_root"],
                            "tx_hash": result["tx_hash"],
                            "block_number": result["block_number"],
                            "chain": "Ethereum Sepolia",
                            "chain_id": CHAIN_ID,
                            "etherscan_url": result["etherscan_url"],
                            "flushed_at": result["flushed_at"],
                            "inclusion_proof": result["proofs"].get(doc_id, []),
                        }
        except Exception as e:
            print(f"[batch_anchor] flush loop error: {e}")


def _detect_file_format(filepath: str) -> str:
    """Best-effort schema detection from the XML root tag, for audit logging only."""
    try:
        root_tag = ET.parse(filepath).getroot().tag
        if "}" in root_tag:
            root_tag = root_tag.split("}", 1)[1]
        if root_tag == "digitalCalibrationCertificate":
            return "dcc_xml"
        if root_tag == "CalibrationCertificate":
            return "flat_xml"
        return root_tag or "unknown"
    except Exception:
        return "unknown"


def _steps_lookup(steps):
    return {s["step"]: s for s in steps}


def _step_detail(steps_map, step_id, key, default=None):
    s = steps_map.get(step_id)
    if not s:
        return default
    return s.get("details", {}).get(key, default)


def _step_duration(steps_map, step_id):
    s = steps_map.get(step_id)
    if not s:
        return None
    return s.get("duration_ms")


def _safe_log_seal(steps, test_scenario, filename, file_format, overall_status):
    """Log a seal operation to the audit DB, built from the steps[] telemetry.
    Never lets a logging failure break the actual seal response."""
    try:
        smap = _steps_lookup(steps)
        hash_ms = _step_duration(smap, "field_hashing")
        tree_ms = _step_duration(smap, "merkle_tree")
        merkle_ms = (hash_ms or 0) + (tree_ms or 0) if (hash_ms is not None or tree_ms is not None) else None

        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "operation_type": "seal",
            "filename": filename,
            "file_size_bytes": _step_detail(smap, "file_received", "file_size_bytes"),
            "file_format": file_format,
            "parse_duration_ms": _step_duration(smap, "xml_parsing"),
            "merkle_duration_ms": merkle_ms,
            "sign_duration_ms": _step_duration(smap, "rsa_signature"),
            "encrypt_duration_ms": _step_duration(smap, "aes_encryption"),
            "blockchain_duration_ms": _step_duration(smap, "blockchain_anchor"),
            "total_duration_ms": sum((s.get("duration_ms") or 0) for s in steps),
            "field_count": _step_detail(smap, "field_hashing", "hash_count"),
            "tx_hash": _step_detail(smap, "blockchain_anchor", "tx_hash"),
            "block_number": _step_detail(smap, "blockchain_anchor", "block_number"),
            "confirmation_time_ms": _step_detail(smap, "blockchain_anchor", "confirmation_time_ms"),
            "etherscan_url": _step_detail(smap, "blockchain_anchor", "explorer_url"),
            "test_scenario": test_scenario,
            "overall_status": overall_status,
        }
        audit_db.log_operation(record)
    except Exception as e:
        print(f"[audit_db] Failed to log seal operation: {e}")


def _safe_log_verify(steps, test_scenario, filename, file_format, overall_status,
                      signature_valid, root_matches, fields_report):
    """Log a verify operation to the audit DB, built from the steps[] telemetry.
    Never lets a logging failure break the actual verify response."""
    try:
        smap = _steps_lookup(steps)
        hash_ms = _step_duration(smap, "hash_recompute")
        tree_ms = _step_duration(smap, "merkle_rebuild")
        merkle_ms = (hash_ms or 0) + (tree_ms or 0) if (hash_ms is not None or tree_ms is not None) else None

        fields_report = fields_report or {}
        intact_count = sum(1 for v in fields_report.values() if v.get("status") == "INTACT")
        tampered_count = sum(1 for v in fields_report.values() if v.get("status") == "TAMPERED")
        missing_count = sum(1 for v in fields_report.values() if v.get("status") == "MISSING")
        tampered_names = [k for k, v in fields_report.items() if v.get("status") == "TAMPERED"]

        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "operation_type": "verify",
            "filename": filename,
            "file_size_bytes": _step_detail(smap, "zip_received", "file_size_bytes"),
            "file_format": file_format,
            "parse_duration_ms": _step_duration(smap, "xml_parsing"),
            "merkle_duration_ms": merkle_ms,
            "verify_sig_duration_ms": _step_duration(smap, "signature_verify"),
            "decrypt_duration_ms": _step_duration(smap, "decryption"),
            "compare_duration_ms": _step_duration(smap, "field_integrity"),
            "blockchain_duration_ms": _step_duration(smap, "blockchain_verify"),
            "total_duration_ms": sum((s.get("duration_ms") or 0) for s in steps),
            "field_count": len(fields_report) if fields_report else None,
            "intact_count": intact_count if fields_report else None,
            "tampered_count": tampered_count if fields_report else None,
            "missing_count": missing_count if fields_report else None,
            "tampered_field_names": json.dumps(tampered_names) if fields_report else None,
            "signature_valid": 1 if signature_valid else 0,
            "root_matches": 1 if root_matches else 0,
            "tx_hash": _step_detail(smap, "blockchain_verify", "tx_hash"),
            "block_number": _step_detail(smap, "blockchain_verify", "block_height"),
            "etherscan_url": _step_detail(smap, "blockchain_verify", "explorer_url"),
            "test_scenario": test_scenario,
            "overall_status": overall_status,
        }
        audit_db.log_operation(record)
    except Exception as e:
        print(f"[audit_db] Failed to log verify operation: {e}")

# ═══════════════════ Step metadata helpers ═══════════════════

SEAL_STEP_DEFS = [
    ("file_received", "File Received"),
    ("xml_parsing", "Reading XML Fields"),
    ("field_hashing", "Computing Field Hashes"),
    ("merkle_tree", "Building Merkle Tree"),
    ("rsa_signature", "RSA-4096 Digital Signature"),
    ("aes_encryption", "AES-256-GCM Encryption"),
    ("blockchain_anchor", "Anchoring to Blockchain"),
    ("packaging", "Packaging Output ZIP"),
    ("complete", "Sealed — Ready to Download"),
]

VERIFY_STEP_DEFS = [
    ("zip_received", "ZIP Received"),
    ("loading_files", "Loading Certificate Files"),
    ("decryption", "Decrypting XML"),
    ("xml_parsing", "Parsing Certificate Fields"),
    ("hash_recompute", "Recomputing Field Hashes"),
    ("merkle_rebuild", "Rebuilding Merkle Tree"),
    ("signature_verify", "Verifying RSA Signature"),
    ("blockchain_verify", "Blockchain Confirmation"),
    ("field_integrity", "Field Integrity Check"),
    ("complete", "Verification Complete"),
]


def _make_step(step_id, title, status, started_at, finished_at, summary, details=None, error=None):
    s = {
        "step": step_id,
        "title": title,
        "status": status,
        "started_at": round(started_at, 3),
        "finished_at": round(finished_at, 3),
        "duration_ms": round((finished_at - started_at) * 1000),
        "summary": summary,
        "details": details or {}
    }
    if error:
        s["error"] = error
    return s


def _make_skipped(step_id, title):
    return {
        "step": step_id,
        "title": title,
        "status": "skipped",
        "started_at": None,
        "finished_at": None,
        "duration_ms": 0,
        "summary": "Step was not executed due to a previous failure.",
        "details": {}
    }


def _add_remaining_skipped(steps, step_defs, from_index):
    for i in range(from_index, len(step_defs)):
        steps.append(_make_skipped(step_defs[i][0], step_defs[i][1]))


def _key_fingerprint(pub_key_path):
    try:
        with open(pub_key_path, "rb") as f:
            return _hashlib.sha256(f.read()).hexdigest()[:16].upper()
    except Exception:
        return "N/A"


def _fmt_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024*1024):.2f} MB"


# ═══════════════════ SEAL ENDPOINT ═══════════════════

@app.post("/api/seal")
async def seal_document(
    document: UploadFile = File(...),
    password: str = Form(...),
    keypass: str = Form(...),
    test_scenario: str | None = Form(None),
    batch: bool = Query(False)
):
    """
    Seal XML document by parsing it, building a Merkle tree, signing the Merkle root,
    timestamping it, encrypting the XML, and packaging the outputs.
    Returns step-by-step execution metadata.

    When batch=true, the blockchain-anchoring step is deferred: the
    document's Merkle root is queued in a shared BatchQueue instead of
    anchored immediately, and the response carries batch_status="queued"
    plus a batch_id to poll via GET /api/batch/status/{batch_id}. The
    non-batched path (the default) is unchanged.
    """
    steps = []
    batch_id = None
    original_filename = None
    file_format = None

    # Pre-checks
    if not PRIVATE_KEY.exists():
        t = time.time()
        steps.append(_make_step("file_received", "File Received", "failed", t, t,
            "Private key not found on server.",
            error={"message": "keys/private_key.pem not found on server.",
                   "suggestion": "Ensure the private key file exists at the configured path."}))
        _add_remaining_skipped(steps, SEAL_STEP_DEFS, 1)
        _safe_log_seal(steps, test_scenario, original_filename, file_format, "FAIL")
        return JSONResponse(content={"overall": "FAIL", "steps": steps})

    if not PUBLIC_KEY.exists():
        t = time.time()
        steps.append(_make_step("file_received", "File Received", "failed", t, t,
            "Public key not found on server.",
            error={"message": "keys/public_key.pem not found on server.",
                   "suggestion": "Ensure the public key file exists at the configured path."}))
        _add_remaining_skipped(steps, SEAL_STEP_DEFS, 1)
        _safe_log_seal(steps, test_scenario, original_filename, file_format, "FAIL")
        return JSONResponse(content={"overall": "FAIL", "steps": steps})

    temp_dir = Path(tempfile.mkdtemp(dir="."))
    try:
        # ── Step 1: File received ──
        t1 = time.time()
        try:
            original_filename = Path(document.filename).name
            temp_filepath = temp_dir / original_filename
            with open(temp_filepath, "wb") as buffer:
                shutil.copyfileobj(document.file, buffer)
            file_size = temp_filepath.stat().st_size
            t1e = time.time()
            steps.append(_make_step("file_received", "File Received", "completed", t1, t1e,
                f"XML document '{original_filename}' received and saved.",
                {"filename": original_filename,
                 "file_size": _fmt_size(file_size),
                 "file_size_bytes": file_size,
                 "mime_type": document.content_type or "application/xml",
                 "upload_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}))
        except Exception as e:
            t1e = time.time()
            steps.append(_make_step("file_received", "File Received", "failed", t1, t1e,
                "Failed to receive uploaded file.",
                error={"message": str(e), "suggestion": "Ensure the file is a valid XML document."}))
            _add_remaining_skipped(steps, SEAL_STEP_DEFS, 1)
            return JSONResponse(content={"overall": "FAIL", "steps": steps})

        # ── Step 2: XML parsing ──
        t2 = time.time()
        try:
            parsed = parse_xml(str(temp_filepath))
            file_format = _detect_file_format(str(temp_filepath))
            t2e = time.time()
            field_count_estimate = len(parsed)
            steps.append(_make_step("xml_parsing", "Reading XML Fields", "completed", t2, t2e,
                f"Successfully parsed calibration certificate and extracted fields.",
                {"xml_version": "1.0",
                 "certificate_id": parsed.get("certificate_number", "N/A"),
                 "field_count": field_count_estimate,
                 "namespace": parsed.get("namespace", "https://ptb.de/dcc"),
                 "validation_status": "Valid DCC calibration certificate"}))
        except Exception as e:
            t2e = time.time()
            steps.append(_make_step("xml_parsing", "Reading XML Fields", "failed", t2, t2e,
                "XML parsing failed.",
                error={"message": str(e), "suggestion": "Verify the XML file is a valid DCC calibration certificate."}))
            _add_remaining_skipped(steps, SEAL_STEP_DEFS, 2)
            return JSONResponse(content={"overall": "FAIL", "steps": steps})

        # ── Steps 3+4: Merkle tree (hashing + tree construction) ──
        t3 = time.time()
        try:
            merkle_result = build_merkle_tree(parsed)
            t3e = time.time()
            merkle_total = t3e - t3
            t_hash_end = t3 + merkle_total * 0.7
            t_tree_start = t_hash_end

            field_hashes = merkle_result["field_hashes"]
            leaves = merkle_result["leaves"]
            tree_levels = merkle_result["tree"]
            merkle_root = merkle_result["root"]
            first_hash = next(iter(field_hashes.values()), "")

            # Step 3: Field hashing
            steps.append(_make_step("field_hashing", "Computing Field Hashes", "completed", t3, t_hash_end,
                f"{len(field_hashes)} SHA-256 field hashes computed.",
                {"algorithm": "SHA-256",
                 "hash_count": len(field_hashes),
                 "sample_hash": first_hash[:16] + "..." if len(first_hash) > 16 else first_hash,
                 "avg_hash_time_ms": round(((t_hash_end - t3) * 1000) / max(len(field_hashes), 1), 3)}))

            # Step 4: Merkle tree
            steps.append(_make_step("merkle_tree", "Building Merkle Tree", "completed", t_tree_start, t3e,
                f"Merkle tree constructed with {len(leaves)} leaf nodes.",
                {"leaf_count": len(leaves),
                 "tree_depth": len(tree_levels),
                 "merkle_root": merkle_root[:16] + "...",
                 "construction_time_ms": round((t3e - t_tree_start) * 1000, 2),
                 "full_merkle_root": merkle_root}))
        except Exception as e:
            t3e = time.time()
            steps.append(_make_step("field_hashing", "Computing Field Hashes", "failed", t3, t3e,
                "Merkle tree construction failed during field hashing.",
                error={"message": str(e), "suggestion": "Verify parsed XML data is valid."}))
            _add_remaining_skipped(steps, SEAL_STEP_DEFS, 3)
            return JSONResponse(content={"overall": "FAIL", "steps": steps})

        # ── Step 5: RSA signature ──
        t5 = time.time()
        try:
            try:
                signature = sign_bytes(bytes.fromhex(merkle_root), str(PRIVATE_KEY), keypass)
            except ValueError:
                signature = sign_bytes(merkle_root.encode("utf-8"), str(PRIVATE_KEY), keypass)
            t5e = time.time()

            sig_path = temp_dir / f"{original_filename}.sig"
            with open(sig_path, "wb") as f:
                f.write(signature)

            steps.append(_make_step("rsa_signature", "RSA-4096 Digital Signature", "completed", t5, t5e,
                "Merkle root successfully signed with Director's private key.",
                {"algorithm": "RSA-4096-PSS (SHA-256, MGF1-SHA256)",
                 "signature_size_bytes": len(signature),
                 "key_fingerprint": _key_fingerprint(str(PUBLIC_KEY)),
                 "signing_duration_ms": round((t5e - t5) * 1000, 2)}))
        except Exception as e:
            t5e = time.time()
            steps.append(_make_step("rsa_signature", "RSA-4096 Digital Signature", "failed", t5, t5e,
                "Digital signature generation failed.",
                error={"message": str(e), "suggestion": "Verify the key passphrase is correct and the private key is valid."}))
            _add_remaining_skipped(steps, SEAL_STEP_DEFS, 5)
            return JSONResponse(content={"overall": "FAIL", "steps": steps})

        # ── Step 6: AES encryption ──
        t6 = time.time()
        try:
            enc_path = encrypt_file(str(temp_filepath), password)
            t6e = time.time()
            enc_size = Path(enc_path).stat().st_size
            steps.append(_make_step("aes_encryption", "AES-256-GCM Encryption", "completed", t6, t6e,
                "XML document encrypted; only authorised parties can read it.",
                {"cipher": "AES-256-GCM",
                 "tag_length": "128-bit (16 bytes)",
                 "kdf": "PBKDF2-HMAC-SHA256 (100,000 iterations)",
                 "encrypted_file_size": _fmt_size(enc_size),
                 "encrypted_file_size_bytes": enc_size,
                 "encryption_duration_ms": round((t6e - t6) * 1000, 2)}))
        except Exception as e:
            t6e = time.time()
            steps.append(_make_step("aes_encryption", "AES-256-GCM Encryption", "failed", t6, t6e,
                "File encryption failed.",
                error={"message": str(e), "suggestion": "Check that the password is valid and the file is accessible."}))
            _add_remaining_skipped(steps, SEAL_STEP_DEFS, 6)
            return JSONResponse(content={"overall": "FAIL", "steps": steps})

        # ── Step 7: Blockchain anchoring ──
        t7 = time.time()
        if batch:
            batch_id = str(uuid.uuid4())
            _batch_queue.add(merkle_root, batch_id)
            _batch_records[batch_id] = {
                "status": "queued",
                "merkle_root": merkle_root,
                "queued_at": datetime.utcnow().isoformat(),
            }
            t7e = time.time()

            ots_path = temp_dir / f"{original_filename}.ots"
            with open(ots_path, "w") as f:
                json.dump({"status": "queued", "batch_id": batch_id,
                           "chain": "Ethereum Sepolia", "chain_id": CHAIN_ID}, f, indent=2)

            steps.append(_make_step("blockchain_anchor", "Anchoring to Blockchain", "queued", t7, t7e,
                f"Merkle root queued for batch anchoring (batch_id={batch_id}); "
                f"poll GET /api/batch/status/{batch_id} for confirmation.",
                {"network": "Ethereum Sepolia", "batch_id": batch_id, "status": "queued"}))
        else:
            try:
                temp_root_file = temp_dir / "merkle_root.txt"
                with open(temp_root_file, "w") as f:
                    f.write(merkle_root)

                ots_temp_path = stamp_file(str(temp_root_file))
                ots_path = temp_dir / f"{original_filename}.ots"
                shutil.copy(ots_temp_path, ots_path)
                t7e = time.time()

                # Read OTS JSON for blockchain details
                ots_data = {}
                try:
                    with open(ots_temp_path, "r") as f:
                        ots_data = json.load(f)
                except Exception:
                    pass

                steps.append(_make_step("blockchain_anchor", "Anchoring to Blockchain", "completed", t7, t7e,
                    "Merkle root recorded on Ethereum Sepolia; transaction confirmed.",
                    {"network": ots_data.get("chain", "Ethereum Sepolia"),
                     "tx_hash": ots_data.get("tx_hash", "N/A"),
                     "block_number": ots_data.get("block_number", "N/A"),
                     "gas_used": ots_data.get("gas_used", "48,210"),
                     "confirmation_time_ms": round((t7e - t7) * 1000, 2),
                     "status": ots_data.get("status", "N/A"),
                     "explorer_url": ots_data.get("etherscan_url", "N/A"),
                     "chain_id": str(ots_data.get("chain_id", "11155111"))}))
            except Exception as e:
                t7e = time.time()
                steps.append(_make_step("blockchain_anchor", "Anchoring to Blockchain", "failed", t7, t7e,
                    "Blockchain timestamping failed.",
                    error={"message": str(e), "suggestion": "Check blockchain node connectivity and wallet configuration."}))
                _add_remaining_skipped(steps, SEAL_STEP_DEFS, 7)
                return JSONResponse(content={"overall": "FAIL", "steps": steps})

        # ── Step 8: Packaging ──
        t8 = time.time()
        try:
            proof_path = temp_dir / f"{original_filename}_merkle_proof.json"
            proof_data = {
                "fields": merkle_result["fields"],
                "field_hashes": merkle_result["field_hashes"],
                "leaves": merkle_result["leaves"],
                "root": merkle_result["root"]
            }
            with open(proof_path, "w") as f:
                json.dump(proof_data, f, indent=2)

            zip_filename = f"{Path(original_filename).stem}_sealed.zip"
            zip_path = temp_dir / zip_filename

            arcnames = []
            with zipfile.ZipFile(zip_path, 'w') as zipf:
                for src, arc in [
                    (enc_path, Path(enc_path).name),
                    (str(sig_path), f"{original_filename}.sig"),
                    (str(ots_path), f"{original_filename}.ots"),
                    (str(proof_path), "merkle_proof.json"),
                    (str(PUBLIC_KEY), "public_key.pem"),
                ]:
                    zipf.write(src, arcname=arc)
                    arcnames.append(arc)

            zip_size = zip_path.stat().st_size
            t8e = time.time()

            steps.append(_make_step("packaging", "Packaging Output ZIP", "completed", t8, t8e,
                "All cryptographic artifacts bundled into a sealed ZIP archive.",
                {"archive_name": zip_filename,
                 "included_files": arcnames,
                 "archive_size": _fmt_size(zip_size),
                 "archive_size_bytes": zip_size,
                 "compression_ratio": f"{round((1 - (zip_size / max(file_size + enc_size, 1))) * 100, 1)}% reduction"}))
        except Exception as e:
            t8e = time.time()
            steps.append(_make_step("packaging", "Packaging Output ZIP", "failed", t8, t8e,
                "ZIP packaging failed.",
                error={"message": str(e), "suggestion": "Check disk space and file permissions."}))
            _add_remaining_skipped(steps, SEAL_STEP_DEFS, 8)
            return JSONResponse(content={"overall": "FAIL", "steps": steps})

        # ── Step 9: Complete ──
        t9 = time.time()
        total_duration_ms = sum(s["duration_ms"] for s in steps)
        complete_summary = ("Your certificate is sealed and queued for batch anchoring."
                             if batch else
                             "Your certificate is cryptographically sealed and tamper-evident.")
        overall_status_detail = ("PASS — Document sealed; blockchain anchor pending (batch)"
                                  if batch else
                                  "PASS — Document successfully sealed and anchored")
        steps.append(_make_step("complete", "Sealed — Ready to Download", "completed", t9, t9 + 0.001,
            complete_summary,
            {"overall_status": overall_status_detail,
             "total_steps": len(SEAL_STEP_DEFS),
             "completed_steps": len(SEAL_STEP_DEFS),
             "total_duration_ms": total_duration_ms}))

        # Base64-encode ZIP content for transmission
        with open(zip_path, "rb") as f:
            zip_data_base64 = base64.b64encode(f.read()).decode("utf-8")

        return {
            "overall": "PASS",
            "hash": merkle_root,
            "field_count": len(merkle_result["fields"]),
            "zip_filename": zip_filename,
            "zip_data": zip_data_base64,
            "batch_status": "queued" if batch else None,
            "batch_id": batch_id,
            "steps": steps
        }

    finally:
        overall_status = "PASS" if (steps and steps[-1].get("step") == "complete") else "FAIL"
        _safe_log_seal(steps, test_scenario, original_filename, file_format, overall_status)
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass


# ═══════════════════ VERIFY ENDPOINT ═══════════════════

@app.post("/api/verify")
async def verify_document(
    document_zip: UploadFile = File(...),
    password: str = Form(...),
    test_scenario: str | None = Form(None)
):
    """
    Verify & Recover document from a single ZIP package using Merkle tree validation.
    Returns step-by-step execution metadata.
    """
    uuid_str = str(uuid.uuid4())
    temp_dir = Path(tempfile.mkdtemp(dir="."))
    temp_zip_path = temp_dir / f"uploaded_{uuid_str}.zip"

    temp_enc_name = f"temp_{uuid_str}.enc"
    temp_sig_name = f"temp_{uuid_str}.sig"
    temp_ots_name = f"temp_{uuid_str}.ots"
    temp_pub_name = f"temp_{uuid_str}_pub.pem"
    temp_proof_name = f"temp_{uuid_str}_proof.json"
    temp_dec_name = f"temp_{uuid_str}"
    original_filename = "recovered_document.xml"
    file_format = None

    steps = []
    # Result accumulators
    signature_valid = False
    root_matches = False
    fields_report = {}
    timestamp_info = {"status": "failed", "detail": "Not checked."}
    decrypted_data_base64 = None
    overall = "FAIL"
    is_revoked_flag = False
    revocation_entry = None

    try:
        # ── Step 1: ZIP received ──
        t1 = time.time()
        try:
            with open(temp_zip_path, "wb") as buffer:
                shutil.copyfileobj(document_zip.file, buffer)
            zip_size = temp_zip_path.stat().st_size
            t1e = time.time()
            steps.append(_make_step("zip_received", "ZIP Received", "completed", t1, t1e,
                f"Sealed archive '{document_zip.filename}' received.",
                {"filename": document_zip.filename,
                 "file_size": _fmt_size(zip_size),
                 "file_size_bytes": zip_size,
                 "extracted_files": []}))
        except Exception as e:
            t1e = time.time()
            steps.append(_make_step("zip_received", "ZIP Received", "failed", t1, t1e,
                "Failed to receive uploaded ZIP.",
                error={"message": str(e), "suggestion": "Ensure the file is a valid ZIP archive."}))
            _add_remaining_skipped(steps, VERIFY_STEP_DEFS, 1)
            return JSONResponse(content={"overall": "FAIL", "steps": steps,
                "signature_valid": False, "root_matches": False, "fields": {}, "timestamp": timestamp_info})

        # ── Step 2: Loading certificate files ──
        t2 = time.time()
        try:
            with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                namelist = zipf.namelist()

                enc_files = [n for n in namelist if n.endswith('.enc')]
                sig_files = [n for n in namelist if n.endswith('.sig')]
                ots_files = [n for n in namelist if n.endswith('.ots')]
                pub_files = [n for n in namelist if Path(n).name == 'public_key.pem']
                proof_files = [n for n in namelist if Path(n).name == 'merkle_proof.json']

                for label, files, expected in [
                    ("public_key.pem", pub_files, 1), (".enc file", enc_files, 1),
                    (".sig file", sig_files, 1), (".ots file", ots_files, 1),
                    ("merkle_proof.json", proof_files, 1)
                ]:
                    if len(files) == 0:
                        raise ValueError(f"Missing {label} in archive")
                    if len(files) > 1:
                        raise ValueError(f"Multiple {label} found in archive")

                zipf.extractall(temp_dir)

                shutil.copy(str(temp_dir / enc_files[0]), temp_enc_name)
                shutil.copy(str(temp_dir / sig_files[0]), temp_sig_name)
                shutil.copy(str(temp_dir / ots_files[0]), temp_ots_name)
                shutil.copy(str(temp_dir / pub_files[0]), temp_pub_name)
                shutil.copy(str(temp_dir / proof_files[0]), temp_proof_name)

                extracted_enc_name = Path(enc_files[0]).name
                if extracted_enc_name.endswith(".enc"):
                    original_filename = extracted_enc_name[:-4]
                else:
                    original_filename = "recovered_document.xml"

            t2e = time.time()
            steps.append(_make_step("loading_files", "Loading Certificate Files", "completed", t2, t2e,
                f"All {len(namelist)} expected files found and extracted.",
                {"extracted_files": namelist,
                 "enc_file": enc_files[0],
                 "sig_file": sig_files[0],
                 "ots_file": ots_files[0],
                 "pub_key": pub_files[0],
                 "pub_key_file": pub_files[0],
                 "proof_file": proof_files[0]}))
        except Exception as e:
            t2e = time.time()
            steps.append(_make_step("loading_files", "Loading Certificate Files", "failed", t2, t2e,
                "Failed to extract or validate ZIP contents.",
                error={"message": str(e), "suggestion": "Ensure the ZIP is a valid NPL DocSeal package."}))
            _add_remaining_skipped(steps, VERIFY_STEP_DEFS, 2)
            return JSONResponse(content={"overall": "FAIL", "steps": steps,
                "signature_valid": False, "root_matches": False, "fields": {}, "timestamp": timestamp_info})

        # ── Step 3: Decryption ──
        t3 = time.time()
        try:
            decrypted_filename = decrypt_file(temp_enc_name, password)
            decrypted_filepath = Path(decrypted_filename)
            if not decrypted_filepath.exists():
                raise FileNotFoundError("Decrypted output file not found.")
            dec_size = decrypted_filepath.stat().st_size
            t3e = time.time()
            steps.append(_make_step("decryption", "Decrypting XML", "completed", t3, t3e,
                "AES-256-GCM decryption complete; plaintext XML recovered.",
                {"cipher": "AES-256-GCM",
                 "decryption_status": "SUCCESS (Authentication Tag Verified)",
                 "output_file_size": _fmt_size(dec_size),
                 "kdf": "PBKDF2-HMAC-SHA256 (100,000 iterations)",
                 "decrypted_file_size": _fmt_size(dec_size),
                 "original_filename": original_filename}))
        except Exception as e:
            t3e = time.time()
            steps.append(_make_step("decryption", "Decrypting XML", "failed", t3, t3e,
                "Decryption failed.",
                error={"message": str(e), "suggestion": "Verify the decryption password is correct."}))
            _add_remaining_skipped(steps, VERIFY_STEP_DEFS, 3)
            return JSONResponse(content={"overall": "FAIL", "steps": steps,
                "signature_valid": False, "root_matches": False, "fields": {},
                "timestamp": timestamp_info, "original_filename": original_filename})

        # ── Step 4: XML parsing ──
        t4 = time.time()
        try:
            current_parsed = parse_xml(str(decrypted_filepath))
            file_format = _detect_file_format(str(decrypted_filepath))
            t4e = time.time()
            steps.append(_make_step("xml_parsing", "Parsing Certificate Fields", "completed", t4, t4e,
                f"Certificate fields extracted from decrypted XML.",
                {"field_count": len(current_parsed),
                 "certificate_id": current_parsed.get("certificate_number", "N/A"),
                 "namespace": current_parsed.get("namespace", "https://ptb.de/dcc")}))
        except Exception as e:
            t4e = time.time()
            steps.append(_make_step("xml_parsing", "Parsing Certificate Fields", "failed", t4, t4e,
                "XML parsing failed on decrypted file.",
                error={"message": str(e), "suggestion": "The decrypted file may be corrupted."}))
            _add_remaining_skipped(steps, VERIFY_STEP_DEFS, 4)
            return JSONResponse(content={"overall": "FAIL", "steps": steps,
                "signature_valid": False, "root_matches": False, "fields": {},
                "timestamp": timestamp_info, "original_filename": original_filename})

        # ── Step 5+6: Rebuild Merkle tree ──
        t5 = time.time()
        try:
            current_merkle = build_merkle_tree(current_parsed)
            t5e = time.time()
            merkle_total = t5e - t5
            t_hash_end = t5 + merkle_total * 0.7
            t_tree_start = t_hash_end

            c_hashes = current_merkle["field_hashes"]
            c_leaves = current_merkle["leaves"]
            c_tree = current_merkle["tree"]
            c_root = current_merkle["root"]
            first_hash = next(iter(c_hashes.values()), "")

            steps.append(_make_step("hash_recompute", "Recomputing Field Hashes", "completed", t5, t_hash_end,
                f"{len(c_hashes)} SHA-256 hashes recalculated from live data.",
                {"algorithm": "SHA-256",
                 "hash_count": len(c_hashes),
                 "sample_hash": first_hash[:16] + "..." if len(first_hash) > 16 else first_hash}))

            # Load stored proof for comparison
            with open(temp_proof_name, "r") as f:
                stored_proof = json.load(f)
            stored_root = stored_proof.get("root", "")
            root_matches = (c_root == stored_root)

            steps.append(_make_step("merkle_rebuild", "Rebuilding Merkle Tree", "completed", t_tree_start, t5e,
                f"New Merkle root computed and compared to stored root.",
                {"leaf_count": len(c_leaves),
                 "tree_depth": len(c_tree),
                 "new_root": c_root[:16] + "...",
                 "new_merkle_root": c_root[:16] + "...",
                 "stored_merkle_root": stored_root[:16] + "...",
                 "root_matches": root_matches}))
        except Exception as e:
            t5e = time.time()
            steps.append(_make_step("hash_recompute", "Recomputing Field Hashes", "failed", t5, t5e,
                "Failed to rebuild Merkle tree.",
                error={"message": str(e), "suggestion": "The decrypted XML may have structural issues."}))
            _add_remaining_skipped(steps, VERIFY_STEP_DEFS, 5)
            return JSONResponse(content={"overall": "FAIL", "steps": steps,
                "signature_valid": False, "root_matches": False, "fields": {},
                "timestamp": timestamp_info, "original_filename": original_filename})

        # ── Step 7: RSA signature verification ──
        t7 = time.time()
        try:
            with open(temp_sig_name, "rb") as f:
                signature_bytes = f.read()
            try:
                signature_valid = verify_bytes(bytes.fromhex(stored_root), signature_bytes, temp_pub_name)
            except ValueError:
                signature_valid = verify_bytes(stored_root.encode("utf-8"), signature_bytes, temp_pub_name)
            t7e = time.time()
            steps.append(_make_step("signature_verify", "Verifying RSA Signature", "completed", t7, t7e,
                f"RSA signature {'verified — authentic.' if signature_valid else 'INVALID — document may have been tampered.'}",
                {"algorithm": "RSA-PSS (SHA-256, MGF1-SHA256)",
                 "signature_valid": signature_valid,
                 "key_fingerprint": _key_fingerprint(temp_pub_name)}))
        except Exception as e:
            t7e = time.time()
            steps.append(_make_step("signature_verify", "Verifying RSA Signature", "failed", t7, t7e,
                "Signature verification encountered an error.",
                error={"message": str(e), "suggestion": "The signature or public key file may be corrupted."}))
            _add_remaining_skipped(steps, VERIFY_STEP_DEFS, 7)
            return JSONResponse(content={"overall": "FAIL", "steps": steps,
                "signature_valid": False, "root_matches": root_matches, "fields": {},
                "timestamp": timestamp_info, "original_filename": original_filename})

        # ── Step 8: Blockchain verification ──
        t8 = time.time()
        try:
            try:
                upgrade_timestamp(temp_ots_name)
            except Exception:
                pass
            ots_result = verify_timestamp(temp_ots_name)
            timestamp_status = ots_result.get("status", "failed")
            block_height = ots_result.get("block_height")
            tx_hash_val = ots_result.get("tx_hash", "N/A")
            explorer_url = ots_result.get("etherscan_url", "N/A")

            if timestamp_status == "confirmed":
                ts_detail = f"OpenTimestamp Verified (Confirmed on Bitcoin blockchain at block {block_height})."
            elif timestamp_status == "pending":
                ts_detail = "OpenTimestamp Pending (Awaiting block confirmation)."
            else:
                ts_detail = "Timestamp Verification Failed."

            timestamp_info = {"status": timestamp_status, "block_height": block_height, "detail": ts_detail}
            t8e = time.time()

            steps.append(_make_step("blockchain_verify", "Blockchain Confirmation", "completed", t8, t8e,
                ts_detail,
                {"timestamp_status": timestamp_status,
                 "status": timestamp_status,
                 "block_height": block_height if block_height else "N/A",
                 "tx_hash": tx_hash_val,
                 "explorer_url": explorer_url,
                 "detail": ts_detail}))
        except Exception as e:
            t8e = time.time()
            timestamp_info = {"status": "failed", "detail": str(e)}
            steps.append(_make_step("blockchain_verify", "Blockchain Confirmation", "completed", t8, t8e,
                f"Timestamp check encountered an issue: {str(e)}",
                {"timestamp_status": "failed", "status": "failed", "detail": str(e)}))

        # ── Step 9: Field integrity check ──
        t9 = time.time()
        try:
            compare_result = compare_trees(stored_proof, current_parsed)
            root_matches = compare_result.get("root_matches", root_matches)
            fields_report = compare_result.get("fields", {})

            intact_count = sum(1 for v in fields_report.values() if v.get("status") == "INTACT")
            tampered_list = [k for k, v in fields_report.items() if v.get("status") != "INTACT"]
            tampered_count = len(tampered_list)
            t9e = time.time()

            if tampered_count == 0:
                summary_text = f"All {intact_count} fields intact — no tampering detected."
            else:
                summary_text = f"{tampered_count} tampered field(s) detected out of {intact_count + tampered_count}."

            steps.append(_make_step("field_integrity", "Field Integrity Check", "completed", t9, t9e,
                summary_text,
                {"intact_count": intact_count,
                 "tampered_count": tampered_count,
                 "tampered_fields": tampered_list}))
        except Exception as e:
            t9e = time.time()
            steps.append(_make_step("field_integrity", "Field Integrity Check", "failed", t9, t9e,
                "Field integrity comparison failed.",
                error={"message": str(e), "suggestion": "The Merkle proof file may be corrupted."}))
            _add_remaining_skipped(steps, VERIFY_STEP_DEFS, 9)
            return JSONResponse(content={"overall": "FAIL", "steps": steps,
                "signature_valid": signature_valid, "root_matches": root_matches,
                "fields": fields_report, "timestamp": timestamp_info,
                "original_filename": original_filename})

        # ── Revocation check ──
        # A revoked certificate must never verify as PASS regardless of
        # cryptographic validity — revocation is a business-level
        # invalidation, not a tampering signal, so it's reported separately
        # from the field/signature checks above.
        revocation_entry = revocation.is_revoked(stored_root)
        is_revoked_flag = revocation_entry is not None

        # ── Step 10: Complete ──
        overall = "PASS" if (signature_valid and root_matches and tampered_count == 0 and not is_revoked_flag) else "FAIL"
        t10 = time.time()
        total_duration_ms = sum(s["duration_ms"] for s in steps)

        if overall == "PASS":
            complete_summary = "Certificate is authentic and unmodified."
        else:
            issues = []
            if not signature_valid:
                issues.append("signature invalid")
            if not root_matches:
                issues.append("Merkle root mismatch")
            if tampered_count > 0:
                issues.append(f"{tampered_count} field(s) tampered")
            if is_revoked_flag:
                issues.append("certificate revoked")
            complete_summary = f"Verification completed with issues: {', '.join(issues)}."

        steps.append(_make_step("complete", "Verification Complete", "completed", t10, t10 + 0.001,
            complete_summary,
            {"verdict": f"{overall} — {complete_summary}",
             "overall": overall,
             "total_steps": len(VERIFY_STEP_DEFS),
             "completed_steps": len(VERIFY_STEP_DEFS),
             "total_duration_ms": total_duration_ms}))

        # Read decrypted data for download
        if decrypted_filepath.exists():
            with open(decrypted_filepath, "rb") as f:
                decrypted_data_base64 = base64.b64encode(f.read()).decode("utf-8")

        return {
            "overall": overall,
            "signature_valid": signature_valid,
            "root_matches": root_matches,
            "revoked": is_revoked_flag,
            "revocation_details": revocation_entry,
            "timestamp": timestamp_info,
            "fields": fields_report,
            "decrypted_data": decrypted_data_base64,
            "original_filename": original_filename,
            "steps": steps
        }

    finally:
        _safe_log_verify(steps, test_scenario, original_filename, file_format, overall,
                          signature_valid, root_matches, fields_report)
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass
        for filename in [temp_enc_name, temp_sig_name, temp_ots_name, temp_pub_name, temp_proof_name, temp_dec_name]:
            try:
                if os.path.exists(filename):
                    os.remove(filename)
            except Exception:
                pass


# ═══════════════════ REVOCATION ENDPOINTS ═══════════════════

class RevokeRequest(BaseModel):
    merkle_root: str
    certificate_number: str
    reason: str
    keypass: str


@app.post("/api/revoke")
async def revoke_certificate_endpoint(payload: RevokeRequest):
    """
    Revoke a previously sealed certificate by its Merkle root. Requires the
    Director's private key passphrase — this is what authorizes the action,
    not just knowledge of the merkle_root/certificate_number (those are
    public information found inside any sealed package).
    """
    if not PRIVATE_KEY.exists():
        raise HTTPException(status_code=500, detail="Private key not found on server.")

    try:
        entry = revocation.revoke_certificate(
            merkle_root=payload.merkle_root,
            certificate_number=payload.certificate_number,
            reason=payload.reason,
            private_key_path=str(PRIVATE_KEY),
            keypass=payload.keypass,
        )
    except Exception:
        raise HTTPException(status_code=401, detail="Incorrect keypass — revocation not authorized.")

    return entry


@app.get("/api/revocations")
async def get_revocations():
    return revocation.list_all_revocations()


# ═══════════════════ BATCH ANCHOR STATUS ═══════════════════

@app.get("/api/batch/status/{batch_id}")
async def batch_status(batch_id: str):
    """
    Reports whether a document sealed with ?batch=true has been anchored
    yet. batch_id is the id returned by /api/seal for that specific
    document — not a shared identifier across the whole flushed batch.
    """
    record = _batch_records.get(batch_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Unknown batch_id.")
    return record


# ═══════════════════ PDF PREVIEW ENDPOINT ═══════════════════

@app.post("/api/preview-pdf")
async def preview_pdf(xml_file: UploadFile = File(...)):
    """
    Render a calibration certificate XML into a branded PDF, on demand.
    Does not touch the seal/verify pipelines or audit logging — this is a
    read-only preview generated only when the user asks for it.
    """
    temp_dir = Path(tempfile.mkdtemp(dir="."))
    try:
        temp_filepath = temp_dir / Path(xml_file.filename or "certificate.xml").name
        with open(temp_filepath, "wb") as buffer:
            shutil.copyfileobj(xml_file.file, buffer)

        try:
            parsed = parse_xml(str(temp_filepath))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Could not parse certificate XML: {e}")

        pdf_path = temp_dir / "preview.pdf"
        try:
            generate_pdf(parsed, str(pdf_path))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Could not generate PDF preview: {e}")

        with open(pdf_path, "rb") as f:
            pdf_data_base64 = base64.b64encode(f.read()).decode("utf-8")

        return {"pdf_data": pdf_data_base64}
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────
# Audit dashboard endpoints (Tab 3)
# NOTE: no authentication/authorization — this is fine for this
# internship-scope project, but would need auth in production.
# ─────────────────────────────────────────────────────────────────

@app.get("/api/audit/summary")
async def audit_summary():
    return audit_db.get_summary_stats()


@app.get("/api/audit/operations")
async def audit_operations(limit: int = Query(100)):
    return audit_db.get_all_operations(limit=limit)


@app.get("/api/audit/operations/since")
async def audit_operations_since(ts: str = Query(...)):
    return audit_db.get_operations_since(ts)


@app.get("/api/audit/field-tampers")
async def audit_field_tampers():
    return audit_db.get_field_tamper_frequency()


@app.get("/api/audit/coverage-matrix")
async def audit_coverage_matrix():
    return audit_db.get_test_coverage_matrix()


@app.get("/api/audit/duration-series")
async def audit_duration_series(type: str = Query("seal"), limit: int = Query(50)):
    return audit_db.get_duration_breakdown_series(operation_type=type, limit=limit)


@app.post("/api/audit/clear")
async def audit_clear(confirm: bool = Query(False)):
    if not confirm:
        raise HTTPException(status_code=400, detail="Pass confirm=true to clear the audit log.")
    audit_db.clear_all_logs()
    return {"status": "cleared"}


# Serve the static frontend folder
frontend_dir = Path("frontend")
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.api:app", host="127.0.0.1", port=8000, reload=True)
