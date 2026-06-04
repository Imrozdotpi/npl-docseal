import hashlib

CHUNK_SIZE = 8192

def hash_bytes(data: bytes) -> str:
    
    sha256 = hashlib.sha256()
    sha256.update(data)

    return sha256.hexdigest()


def hash_file(filepath: str) -> str:
    
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as file:

        while True:

            chunk = file.read(CHUNK_SIZE)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()