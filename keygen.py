import argparse
import sys
from pathlib import Path
from getpass import getpass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_keys(passphrase: str, output_dir: Path = Path("keys"), name: str = "") -> tuple[Path, Path]:
    """
    Generate an RSA-4096 key pair and save it to PEM files.

    name, if given, prefixes the file names (e.g. name="demo" produces
    demo_private_key.pem / demo_public_key.pem). Used to keep a separate
    key pair for the public challenge demo distinct from the real signing
    key. An empty name preserves the original private_key.pem/public_key.pem
    naming.

    Returns (private_key_path, public_key_path).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    public_key = private_key.public_key()

    output_dir.mkdir(parents=True, exist_ok=True)

    prefix = f"{name}_" if name else ""
    private_path = output_dir / f"{prefix}private_key.pem"
    public_path = output_dir / f"{prefix}public_key.pem"

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=
        serialization.BestAvailableEncryption(passphrase.encode())
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(private_path, "wb") as f:
        f.write(private_pem)

    with open(public_path, "wb") as f:
        f.write(public_pem)

    print("RSA-4096 key pair generated successfully.")
    print(f"Private Key: {private_path}")
    print(f"Public Key : {public_path}")

    return private_path, public_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate an RSA-4096 key pair for NPL DocSeal."
    )
    parser.add_argument(
        "--passphrase", type=str, default=None,
        help="Passphrase to protect the private key. If omitted, prompts "
             "interactively (unless --non-interactive is set)."
    )
    parser.add_argument(
        "--non-interactive", action="store_true",
        help="Never prompt for input; --passphrase is then required. "
             "Used by CI, where there's no terminal to prompt on."
    )
    parser.add_argument(
        "--output-dir", type=str, default="keys",
        help="Directory to write the key pair into (default: keys)."
    )
    parser.add_argument(
        "--name", type=str, default="",
        help="Optional filename prefix, e.g. 'demo' produces "
             "demo_private_key.pem / demo_public_key.pem. Default: "
             "private_key.pem / public_key.pem."
    )
    args = parser.parse_args()

    if args.passphrase is not None:
        passphrase = args.passphrase
    elif args.non_interactive:
        print("[ERROR] --non-interactive requires --passphrase.", file=sys.stderr)
        sys.exit(1)
    else:
        passphrase = getpass("Enter passphrase to protect private key: ")

    generate_keys(passphrase, output_dir=Path(args.output_dir), name=args.name)


if __name__ == "__main__":
    main()
