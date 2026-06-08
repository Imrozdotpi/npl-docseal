from pathlib import Path
import os

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32          
ITERATIONS = 100000


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive AES-256 key from password.
    """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )

    return kdf.derive(password.encode())


def encrypt_file(filepath: str, password: str) -> str:

    path = Path(filepath)

    with open(path, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(SALT_SIZE)

    key = derive_key(password, salt)

    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        None
    )

    output_path = str(path) + ".enc"

    with open(output_path, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

    return output_path


def decrypt_file(filepath: str, password: str) -> str:

    path = Path(filepath)

    with open(path, "rb") as f:
        data = f.read()

    salt = data[:16]

    nonce = data[16:28]

    ciphertext = data[28:]

    key = derive_key(password, salt)

    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )

    output_path = path.stem

    with open(output_path, "wb") as f:
        f.write(plaintext)

    return output_path

if __name__ == "__main__":

    encrypted = encrypt_file(
        "test.txt",
        "Password123"
    )

    print("Encrypted:", encrypted)

    # decrypted = decrypt_file(
    #     "test.txt.enc",
    #     "Password123"
    # )

    # print("Decrypted:", decrypted)