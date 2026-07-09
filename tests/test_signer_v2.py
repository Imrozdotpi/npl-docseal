import os
import unittest

from core.signer import sign_bytes, verify_bytes
from core.xml_parser import parse_xml
from core.merkle import build_merkle_tree

PRIVATE_KEY = "keys/private_key.pem"
PUBLIC_KEY  = "keys/public_key.pem"
PASSPHRASE  = "karan"
XML_PATH    = "samples/DCC_clamp_meter1.xml"

# 32 bytes of known test data (valid input for Prehashed SHA256)
TEST_DATA = bytes.fromhex(
    "a" * 64  # 64 hex chars = 32 bytes
)


class TestSignBytes(unittest.TestCase):

    # ── basic sign/verify ─────────────────────────────────

    def test_sign_returns_bytes(self):
        sig = sign_bytes(TEST_DATA, PRIVATE_KEY, PASSPHRASE)
        self.assertIsInstance(sig, bytes)

    def test_rsa4096_signature_is_512_bytes(self):
        sig = sign_bytes(TEST_DATA, PRIVATE_KEY, PASSPHRASE)
        self.assertEqual(len(sig), 512)

    def test_verify_valid_signature(self):
        sig = sign_bytes(TEST_DATA, PRIVATE_KEY, PASSPHRASE)
        result = verify_bytes(TEST_DATA, sig, PUBLIC_KEY)
        self.assertTrue(result)

    # ── tamper data ───────────────────────────────────────

    def test_tampered_data_fails(self):
        sig = sign_bytes(TEST_DATA, PRIVATE_KEY, PASSPHRASE)
        tampered = bytes([TEST_DATA[0] ^ 0xFF]) + TEST_DATA[1:]
        result = verify_bytes(tampered, sig, PUBLIC_KEY)
        self.assertFalse(result)

    def test_tampered_signature_fails(self):
        sig = sign_bytes(TEST_DATA, PRIVATE_KEY, PASSPHRASE)
        tampered_sig = bytearray(sig)
        tampered_sig[10] ^= 0xFF
        result = verify_bytes(TEST_DATA, bytes(tampered_sig), PUBLIC_KEY)
        self.assertFalse(result)

    def test_wrong_data_fails(self):
        sig = sign_bytes(TEST_DATA, PRIVATE_KEY, PASSPHRASE)
        wrong_data = bytes(32)  # all zeros
        result = verify_bytes(wrong_data, sig, PUBLIC_KEY)
        self.assertFalse(result)

    def test_corrupted_signature_fails(self):
        sig = sign_bytes(TEST_DATA, PRIVATE_KEY, PASSPHRASE)
        result = verify_bytes(TEST_DATA, b"not a real signature", PUBLIC_KEY)
        self.assertFalse(result)

    # ── merkle root workflow ──────────────────────────────

    def test_sign_verify_merkle_root(self):
        """Full workflow: build tree, sign root, verify root."""
        parsed = parse_xml(XML_PATH)
        result = build_merkle_tree(parsed)
        root = result["root"]

        root_bytes = bytes.fromhex(root)
        sig = sign_bytes(root_bytes, PRIVATE_KEY, PASSPHRASE)
        valid = verify_bytes(root_bytes, sig, PUBLIC_KEY)

        self.assertTrue(valid)

    def test_tampered_root_fails_verification(self):
        """Tampered Merkle root should not verify against original signature."""
        parsed = parse_xml(XML_PATH)
        result = build_merkle_tree(parsed)
        root = result["root"]

        root_bytes = bytes.fromhex(root)
        sig = sign_bytes(root_bytes, PRIVATE_KEY, PASSPHRASE)

        # simulate tampered root (different 32 bytes)
        fake_root = bytes([b ^ 0x01 for b in root_bytes])
        valid = verify_bytes(fake_root, sig, PUBLIC_KEY)

        self.assertFalse(valid)

    def test_sign_same_data_deterministic_verify(self):
        """Two signatures of same data must both verify."""
        sig1 = sign_bytes(TEST_DATA, PRIVATE_KEY, PASSPHRASE)
        sig2 = sign_bytes(TEST_DATA, PRIVATE_KEY, PASSPHRASE)
        self.assertTrue(verify_bytes(TEST_DATA, sig1, PUBLIC_KEY))
        self.assertTrue(verify_bytes(TEST_DATA, sig2, PUBLIC_KEY))


class TestSignBytesEdgeCases(unittest.TestCase):

    def test_wrong_passphrase_raises(self):
        with self.assertRaises(Exception):
            sign_bytes(TEST_DATA, PRIVATE_KEY, "wrongpassphrase")

    def test_missing_key_file_raises(self):
        with self.assertRaises(Exception):
            sign_bytes(TEST_DATA, "keys/nonexistent.pem", PASSPHRASE)


if __name__ == "__main__":
    unittest.main()