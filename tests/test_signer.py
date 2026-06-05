# tests/test_signer.py

import os
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from core.signer import (
    sign_file,
    verify_signature
)


class TestSigner(unittest.TestCase):

    PASSPHRASE = "testpass"

    def setUp(self):
        """
        Create temporary RSA key pair
        and test document.
        """

        self.temp_dir = tempfile.TemporaryDirectory()

        self.private_key_path = os.path.join(
            self.temp_dir.name,
            "private_key.pem"
        )

        self.public_key_path = os.path.join(
            self.temp_dir.name,
            "public_key.pem"
        )

        self.document_path = os.path.join(
            self.temp_dir.name,
            "document.txt"
        )

        # Generate RSA key pair

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        public_key = private_key.public_key()

        with open(
            self.private_key_path,
            "wb"
        ) as f:

            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=
                    serialization.BestAvailableEncryption(
                        self.PASSPHRASE.encode()
                    )
                )
            )

        with open(
            self.public_key_path,
            "wb"
        ) as f:

            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=
                    serialization.PublicFormat.
                    SubjectPublicKeyInfo
                )
            )

        with open(
            self.document_path,
            "wb"
        ) as f:

            f.write(
                b"Original document"
            )

    def tearDown(self):
        """
        Delete temporary files.
        """

        self.temp_dir.cleanup()

    def test_signature_creation(self):

        sig_path = sign_file(
            self.document_path,
            self.private_key_path,
            self.PASSPHRASE
        )

        self.assertTrue(
            os.path.exists(sig_path)
        )

    def test_verify_original_document(self):

        sig_path = sign_file(
            self.document_path,
            self.private_key_path,
            self.PASSPHRASE
        )

        result = verify_signature(
            self.document_path,
            sig_path,
            self.public_key_path
        )

        self.assertTrue(result)

    def test_modified_document_fails(self):

        sig_path = sign_file(
            self.document_path,
            self.private_key_path,
            self.PASSPHRASE
        )

        with open(
            self.document_path,
            "wb"
        ) as f:

            f.write(
                b"Modified document"
            )

        result = verify_signature(
            self.document_path,
            sig_path,
            self.public_key_path
        )

        self.assertFalse(result)

    def test_wrong_public_key_fails(self):

        sig_path = sign_file(
            self.document_path,
            self.private_key_path,
            self.PASSPHRASE
        )

        wrong_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        wrong_public = wrong_private.public_key()

        wrong_public_path = os.path.join(
            self.temp_dir.name,
            "wrong_public.pem"
        )

        with open(
            wrong_public_path,
            "wb"
        ) as f:

            f.write(
                wrong_public.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=
                    serialization.PublicFormat.
                    SubjectPublicKeyInfo
                )
            )

        result = verify_signature(
            self.document_path,
            sig_path,
            wrong_public_path
        )

        self.assertFalse(result)

    def test_corrupted_signature_fails(self):

        sig_path = sign_file(
            self.document_path,
            self.private_key_path,
            self.PASSPHRASE
        )

        with open(
            sig_path,
            "wb"
        ) as f:

            f.write(
                b"corrupted signature"
            )

        result = verify_signature(
            self.document_path,
            sig_path,
            self.public_key_path
        )

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()