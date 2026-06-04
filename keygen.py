from pathlib import Path
from getpass import getpass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_keys():
    """
    Generate RSA-4096 key pair and save to PEM files.
    """

    passphrase = getpass(
        "Enter passphrase to protect private key: "
    ).encode()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    public_key = private_key.public_key()

    keys_dir = Path("keys")
    keys_dir.mkdir(exist_ok=True)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=
        serialization.BestAvailableEncryption(passphrase)
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(keys_dir / "private_key.pem", "wb") as f:
        f.write(private_pem)

    with open(keys_dir / "public_key.pem", "wb") as f:
        f.write(public_pem)

    print("RSA-4096 key pair generated successfully.")
    print("Private Key: keys/private_key.pem")
    print("Public Key : keys/public_key.pem")


if __name__ == "__main__":
    generate_keys()