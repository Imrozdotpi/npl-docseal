import argparse
import json
import shutil
import sys
from pathlib import Path

from core.encryptor import decrypt_file, encrypt_file
from core.merkle import build_merkle_tree, compare_trees
from core.signer import sign_bytes, verify_bytes
from core.timestamper import (
    get_timestamp_info,
    stamp_file,
    upgrade_timestamp,
    verify_timestamp,
)
from core.xml_parser import parse_xml

SEALED_DIR  = Path("sealed")
PRIVATE_KEY = Path("keys/private_key.pem")
PUBLIC_KEY  = Path("keys/public_key.pem")


def ensure_sealed_dir():
    SEALED_DIR.mkdir(exist_ok=True)


def move_to_sealed(filepath: Path) -> Path:
    destination = SEALED_DIR / Path(filepath).name
    shutil.move(str(filepath), str(destination))
    return destination


# ─────────────────────────────────────────────
#  SEAL
# ─────────────────────────────────────────────

def seal_document(filepath: str, password: str, keypass: str):

    file_path = Path(filepath)

    if not file_path.exists():
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    if not PRIVATE_KEY.exists():
        print("[ERROR] Private key not found at keys/private_key.pem")
        sys.exit(1)

    ensure_sealed_dir()

    # ── 1. Parse XML ──────────────────────────
    print("Parsing XML certificate...")
    try:
        parsed = parse_xml(str(file_path))
    except Exception as e:
        print(f"[ERROR] Failed to parse XML: {e}")
        sys.exit(1)

    # ── 2. Build Merkle tree ──────────────────
    print("Building Merkle tree...")
    merkle_result = build_merkle_tree(parsed)
    merkle_root   = merkle_result["root"]
    field_count   = len(merkle_result["fields"])

    # ── 3. Sign Merkle root ───────────────────
    print("Signing Merkle root...")
    try:
        signature  = sign_bytes(
            bytes.fromhex(merkle_root),
            str(PRIVATE_KEY),
            keypass
        )
    except Exception as e:
        print(f"[ERROR] Signing failed: {e}")
        sys.exit(1)

    sig_path = file_path.with_suffix(file_path.suffix + ".sig")
    sig_path.write_bytes(signature)

    # ── 4. Timestamp Merkle root ──────────────
    print("Creating blockchain timestamp...")
    try:
        ots_path = stamp_file(str(file_path))
    except Exception as e:
        print(f"[WARNING] Timestamping failed: {e}")
        ots_path = None

    # ── 5. Encrypt XML ────────────────────────
    print("Encrypting document...")
    enc_path = encrypt_file(str(file_path), password)

    # ── 6. Save Merkle proof ──────────────────
    proof_name = file_path.name + "_merkle_proof.json"
    proof_path = file_path.parent / proof_name
    proof_data = {
        "root":         merkle_result["root"],
        "fields":       merkle_result["fields"],
        "field_hashes": merkle_result["field_hashes"],
    }
    proof_path.write_text(json.dumps(proof_data, indent=2, ensure_ascii=False))

    # ── 7. Move all outputs to sealed/ ───────
    sig_path  = move_to_sealed(sig_path)
    enc_path  = move_to_sealed(Path(enc_path))
    proof_path = move_to_sealed(proof_path)
    if ots_path:
        ots_path = move_to_sealed(Path(ots_path))

    # ── 8. Report ─────────────────────────────
    print()
    print("=" * 45)
    print("NPL DOCSEAL: SEAL REPORT")
    print("=" * 45)
    print(f"File        : {file_path.name}")
    print(f"Merkle Root : {merkle_root[:32]}...")
    print(f"Fields      : {field_count} fields committed to Merkle tree")
    print(f"Signature   : {sig_path}")
    print(f"Timestamp   : {ots_path if ots_path else 'SKIPPED'}")
    print(f"Encrypted   : {enc_path}")
    print(f"Merkle Proof: {proof_path}")
    print(f"Status      : SUCCESS")
    print("=" * 45)


# ─────────────────────────────────────────────
#  VERIFY
# ─────────────────────────────────────────────

def verify_document(enc_file: str, password: str):

    enc_path = Path(enc_file)

    if not enc_path.exists():
        print(f"[ERROR] File not found: {enc_file}")
        sys.exit(1)

    if not PUBLIC_KEY.exists():
        print("[ERROR] Public key not found at keys/public_key.pem")
        sys.exit(1)

    sealed_dir = enc_path.parent

    # ── 1. Decrypt ────────────────────────────
    print("Decrypting document...")
    try:
        decrypted_path = Path(decrypt_file(str(enc_path), password))
    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")
        sys.exit(1)

    # ── 2. Parse decrypted XML ────────────────
    print("Parsing XML certificate...")
    try:
        current_parsed = parse_xml(str(decrypted_path))
    except Exception as e:
        print(f"[ERROR] XML parsing failed: {e}")
        sys.exit(1)

    # ── 3. Load Merkle proof ──────────────────
    proof_file = sealed_dir / f"{decrypted_path.name}_merkle_proof.json"
    if not proof_file.exists():
        print(f"[ERROR] Merkle proof not found: {proof_file}")
        sys.exit(1)

    stored_proof = json.loads(proof_file.read_text())
    stored_root  = stored_proof["root"]

    # ── 4. Compare Merkle trees ───────────────
    print("Comparing Merkle trees...")
    field_report = compare_trees(stored_proof, current_parsed)

    # ── 5. Verify RSA signature ───────────────
    print("Verifying signature...")
    sig_file = sealed_dir / f"{decrypted_path.name}.sig"

    if not sig_file.exists():
        print(f"[ERROR] Signature file not found: {sig_file}")
        sys.exit(1)

    sig_bytes_data = sig_file.read_bytes()

    try:
        signature_valid = verify_bytes(
            bytes.fromhex(stored_root),
            sig_bytes_data,
            str(PUBLIC_KEY)
        )
    except Exception as e:
        print(f"[WARNING] Signature verification error: {e}")
        signature_valid = False

    # ── 6. Verify timestamp ───────────────────
    print("Verifying blockchain timestamp...")
    ots_file        = sealed_dir / f"{decrypted_path.name}.ots"
    timestamp_info  = {"status": "unavailable", "block_height": None}

    if ots_file.exists():
        try:
            upgrade_timestamp(str(ots_file))
        except Exception:
            pass
        try:
            timestamp_info = verify_timestamp(str(ots_file))
        except Exception:
            pass

    # ── 7. Overall result ─────────────────────
    root_matches = field_report["root_matches"]
    overall      = "PASS" if (signature_valid and root_matches) else "FAIL"

    # ── 8. Report ─────────────────────────────
    ts_status    = timestamp_info.get("status", "unavailable").upper()
    block_height = timestamp_info.get("block_height")
    ts_display   = ts_status
    if block_height:
        ts_display += f" (block {block_height})"

    print()
    print("=" * 45)
    print("NPL DOCSEAL: VERIFICATION REPORT")
    print("=" * 45)
    print(f"File        : {decrypted_path.name}")
    print(f"Signature   : {'VALID' if signature_valid else 'INVALID'}")
    print(f"Root Match  : {'PASS' if root_matches else 'FAIL'}")
    print(f"Blockchain  : {ts_display}")
    print(f"Overall     : {overall}")
    print("=" * 45)
    print("FIELD REPORT:")

    fields = field_report.get("fields", {})
    intact_count   = 0
    tampered_count = 0

    for field_name, info in fields.items():
        status = info["status"]
        value  = info.get("value", "")
        # truncate long values for display
        display_value = (value[:40] + "...") if len(str(value)) > 40 else value

        if status == "INTACT":
            intact_count += 1
            print(f"  \u2713 {field_name:<35} : {display_value}")
        elif status == "TAMPERED":
            tampered_count += 1
            print(f"  \u2717 {field_name:<35} : {display_value}  <-- TAMPERED")
        else:
            print(f"  ? {field_name:<35} : {status}")

    print("=" * 45)
    print(f"Summary: {intact_count} intact, {tampered_count} tampered")
    print("=" * 45)

    # cleanup decrypted file
    try:
        decrypted_path.unlink()
    except Exception:
        pass


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():

    parser = argparse.ArgumentParser(
        description="NPL DocSeal: Cryptographic Calibration Certificate Protection"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # seal
    seal_parser = subparsers.add_parser("seal", help="Seal an XML certificate")
    seal_parser.add_argument("file",         help="Path to XML file")
    seal_parser.add_argument("--password",   required=True, help="AES encryption password")
    seal_parser.add_argument("--keypass",    required=True, help="RSA private key passphrase")

    # verify
    verify_parser = subparsers.add_parser("verify", help="Verify a sealed certificate")
    verify_parser.add_argument("file",       help="Path to .enc file in sealed/")
    verify_parser.add_argument("--password", required=True, help="AES decryption password")

    args = parser.parse_args()

    try:
        if args.command == "seal":
            seal_document(args.file, args.password, args.keypass)
        elif args.command == "verify":
            verify_document(args.file, args.password)
    except KeyboardInterrupt:
        print("\n[CANCELLED]")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()