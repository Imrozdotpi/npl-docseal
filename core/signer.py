
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from core.hasher import hash_file


def sign_file(
    filepath: str,
    private_key_path: str,
    passphrase: str
) -> str:
    """
    Sign a file using RSA-PSS and return the
    generated signature file path.
    """

    # Load encrypted private key
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=passphrase.encode()
        )

    # Hash document using existing hasher module
    digest_hex = hash_file(filepath)

    # Convert hex digest to raw bytes
    digest_bytes = bytes.fromhex(digest_hex)

    # Create RSA-PSS signature
    signature = private_key.sign(
        digest_bytes,
        padding.PSS(
            mgf=padding.MGF1(
                hashes.SHA256()
            ),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Create .sig filename
    sig_path = f"{filepath}.sig"

    # Save signature bytes
    with open(sig_path, "wb") as f:
        f.write(signature)

    return sig_path


def verify_signature(
    filepath: str,
    sig_path: str,
    public_key_path: str
) -> bool:
    """
    Verify RSA-PSS signature.

    Returns:
        True  -> valid signature
        False -> invalid signature
    """

    # Load public key
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read()
        )

    # Recompute document hash
    digest_hex = hash_file(filepath)

    # Convert digest to bytes
    digest_bytes = bytes.fromhex(digest_hex)

    # Load signature file
    with open(sig_path, "rb") as f:
        signature = f.read()

    try:

        public_key.verify(
            signature,
            digest_bytes,
            padding.PSS(
                mgf=padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except InvalidSignature:

        return False