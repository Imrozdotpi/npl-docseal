import hashlib
import os
import tempfile
import unittest
from core.hasher import hash_file, hash_bytes


class TestHasher(unittest.TestCase):

    def test_same_file_same_hash(self):
        """
        Same file hashed twice
        should produce same digest.
        """

        with tempfile.NamedTemporaryFile(
            delete=False
        ) as temp:

            temp.write(b"Hello NPL")
            temp_path = temp.name

        try:

            hash1 = hash_file(temp_path)
            hash2 = hash_file(temp_path)

            self.assertEqual(hash1, hash2)

        finally:

            os.remove(temp_path)

    def test_modified_file_changes_hash(self):
        """
        Modifying file contents
        should change hash.
        """

        with tempfile.NamedTemporaryFile(
            delete=False
        ) as temp:

            temp.write(b"Version 1")
            temp_path = temp.name

        try:

            hash1 = hash_file(temp_path)

            with open(temp_path, "wb") as f:
                f.write(b"Version 2")

            hash2 = hash_file(temp_path)

            self.assertNotEqual(hash1, hash2)

        finally:

            os.remove(temp_path)

    def test_empty_file_hash(self):
        """
        Empty file should produce
        known SHA-256 digest.
        """

        expected = (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )

        with tempfile.NamedTemporaryFile(
            delete=False
        ) as temp:

            temp_path = temp.name

        try:

            actual = hash_file(temp_path)

            self.assertEqual(
                actual,
                expected
            )

        finally:

            os.remove(temp_path)

    def test_hash_bytes(self):
        """
        Verify hash_bytes()
        matches hashlib output.
        """

        data = b"Hello World"

        expected = hashlib.sha256(
            data
        ).hexdigest()

        actual = hash_bytes(data)

        self.assertEqual(
            actual,
            expected
        )

    def test_large_file(self):
        """
        Verify hashing large file
        works correctly.
        """

        large_data = b"A" * (10 * 1024 * 1024)

        with tempfile.NamedTemporaryFile(
            delete=False
        ) as temp:

            temp.write(large_data)
            temp_path = temp.name

        try:

            expected = hashlib.sha256(
                large_data
            ).hexdigest()

            actual = hash_file(
                temp_path
            )

            self.assertEqual(
                actual,
                expected
            )

        finally:

            os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()