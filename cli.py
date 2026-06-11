from pathlib import Path
import argparse
import shutil
import sys

from core.hasher import hash_file
from core.signer import sign_file, verify_signature
from core.encryptor import encrypt_file, decrypt_file
from core.timestamper import (
    stamp_file,
    verify_timestamp,
    upgrade_timestamp,
    get_timestamp_info
)

SEALED_DIR = Path("sealed")

PRIVATE_KEY = Path("keys/private_key.pem")
PUBLIC_KEY = Path("keys/public_key.pem")


def ensure_sealed_dir():
    SEALED_DIR.mkdir(exist_ok=True)


def move_to_sealed(filepath):
    destination = SEALED_DIR / Path(filepath).name
    shutil.move(str(filepath), str(destination))
    return destination


def seal_document(filepath, password, keypass):

    file_path = Path(filepath)

    if not file_path.exists():
        print(f"[ERROR] File not found: {filepath}")
        return

    if not PRIVATE_KEY.exists():
        print("[ERROR] Private key not found.")
        return

    ensure_sealed_dir()

    print("Hashing document...")

    sha256_hash = hash_file(filepath)

    print("Creating signature...")

    sig_path = sign_file(
        filepath,
        str(PRIVATE_KEY),
        keypass
    )

    print("Creating timestamp proof...")

    ots_path = stamp_file(filepath)

    print("Encrypting document...")

    enc_path = encrypt_file(filepath, password)

    sig_path = move_to_sealed(sig_path)
    ots_path = move_to_sealed(ots_path)
    enc_path = move_to_sealed(enc_path)

    print("\n" + "=" * 35)
    print("NPL DOCSEAL REPORT")
    print("=" * 35)

    print(f"\nFile:\n{file_path.name}")
    print(f"\nSHA256:\n{sha256_hash}")
    print(f"\nSignature:\n{sig_path}")
    print(f"\nTimestamp:\n{ots_path}")
    print(f"\nEncrypted:\n{enc_path}")

    print("\nStatus:\nSUCCESS")
    print("=" * 35)


def verify_document(enc_file, password):

    enc_path = Path(enc_file)

    if not enc_path.exists():
        print(f"[ERROR] File not found: {enc_file}")
        return

    if not PUBLIC_KEY.exists():
        print("[ERROR] Public key not found.")
        return

    print("Decrypting document...")

    decrypted_file = decrypt_file(enc_file, password)

    original_file = Path(decrypted_file)

    sealed_dir = Path("sealed")

    sig_file = sealed_dir / f"{original_file.name}.sig"

    ots_file = sealed_dir / f"{original_file.name}.ots"

    print("Verifying signature...")

    signature_valid = verify_signature(
        str(original_file),
        str(sig_file),
        str(PUBLIC_KEY)
    )

    print("Updating timestamp proof...")

    try:
        upgrade_timestamp(str(ots_file))
    except Exception:
        pass

    print("Verifying timestamp...")

    timestamp_valid = verify_timestamp(str(ots_file))

    try:
        ts_info = get_timestamp_info(str(ots_file))
    except Exception:
        ts_info = "Unavailable"

    block_height = "Unknown"


    integrity = "PASS" if signature_valid else "FAIL"
    authenticity = "PASS" if signature_valid else "FAIL"

    overall = (
        "PASS"
        if signature_valid
        else "FAIL"
    )

    print("\n" + "=" * 35)
    print("VERIFICATION REPORT")
    print("=" * 35)

    print(f"\nDocument:\n{original_file.name}")

    print(
        f"\nSignature:\n"
        f"{'VALID' if signature_valid else 'INVALID'}"
    )

    print(
        f"\nTimestamp:\n"
        f"{'VALID' if timestamp_valid else 'PENDING'}"
    )

    print(f"\nBlock Height:\n{block_height}")

    print(f"\nIntegrity:\n{integrity}")

    print(f"\nAuthenticity:\n{authenticity}")

    print(f"\nOverall:\n{overall}")

    print("=" * 35)

def check_document(filepath):

    file_path = Path(filepath)

    if not file_path.exists():
        print(f"[ERROR] File not found: {filepath}")
        return

    if not PUBLIC_KEY.exists():
        print("[ERROR] Public key not found.")
        return

    sig_file = SEALED_DIR / f"{file_path.name}.sig"

    if not sig_file.exists():
        print(f"[ERROR] Signature not found: {sig_file}")
        return

    signature_valid = verify_signature(
        str(file_path),
        str(sig_file),
        str(PUBLIC_KEY)
    )

    print("\n" + "=" * 35)
    print("TAMPER CHECK REPORT")
    print("=" * 35)

    print(f"\nDocument:\n{file_path.name}")

    print(
        f"\nSignature:\n"
        f"{'VALID' if signature_valid else 'INVALID'}"
    )

    print(
        f"\nStatus:\n"
        f"{'AUTHENTIC' if signature_valid else 'TAMPERED'}"
    )

    print("=" * 35)


def main():

    parser = argparse.ArgumentParser(
        description="NPL DocSeal"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    seal_parser = subparsers.add_parser(
        "seal",
        help="Seal a document"
    )

    seal_parser.add_argument(
        "file"
    )

    seal_parser.add_argument(
        "--password",
        required=True
    )

    seal_parser.add_argument(
        "--keypass",
        required=True
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify a document"
    )

    verify_parser.add_argument(
        "file"
    )

    verify_parser.add_argument(
        "--password",
        required=True
    )

    check_parser = subparsers.add_parser(
        "check",
        help="Check if a document has been tampered with"
    )

    check_parser.add_argument(
        "file"
    )
    args = parser.parse_args()

    try:

        if args.command == "seal":

            seal_document(
                args.file,
                args.password,
                args.keypass
            )

        elif args.command == "verify":

            verify_document(
                args.file,
                args.password
            )
        
        elif args.command == "check":

            check_document(
                args.file
            )

    except Exception as e:

        print(f"[ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()