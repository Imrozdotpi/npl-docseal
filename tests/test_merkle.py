import copy
import unittest

from core.xml_parser import parse_xml
from core.merkle import build_merkle_tree, compare_trees

XML_PATH = "samples/DCC_clamp_meter1.xml"


class TestMerkleTree(unittest.TestCase):

    def setUp(self):
        self.parsed = parse_xml(XML_PATH)
        self.result = build_merkle_tree(self.parsed)

    # ── root format ───────────────────────────────────────

    def test_root_is_64_char_hex(self):
        root = self.result["root"]
        self.assertEqual(len(root), 64)
        int(root, 16)  # raises ValueError if not valid hex

    def test_root_is_bytes_fromhex_compatible(self):
        root = self.result["root"]
        raw = bytes.fromhex(root)
        self.assertEqual(len(raw), 32)

    # ── determinism ───────────────────────────────────────

    def test_same_xml_same_root(self):
        result2 = build_merkle_tree(parse_xml(XML_PATH))
        self.assertEqual(self.result["root"], result2["root"])

    def test_same_xml_same_field_hashes(self):
        result2 = build_merkle_tree(parse_xml(XML_PATH))
        self.assertEqual(
            self.result["field_hashes"],
            result2["field_hashes"]
        )

    # ── field count ───────────────────────────────────────

    def test_field_count_is_31(self):
        self.assertEqual(len(self.result["fields"]), 31)

    def test_field_hashes_count_matches_fields(self):
        self.assertEqual(
            len(self.result["field_hashes"]),
            len(self.result["fields"])
        )

    def test_leaves_count_matches_fields(self):
        self.assertEqual(
            len(self.result["leaves"]),
            len(self.result["fields"])
        )

    # ── tamper changes root ───────────────────────────────

    def test_tampered_field_changes_root(self):
        tampered = copy.deepcopy(self.parsed)
        tampered["certificate_number"] = "FAKE-CERT-999"
        tampered_result = build_merkle_tree(tampered)
        self.assertNotEqual(
            self.result["root"],
            tampered_result["root"]
        )

    def test_tampered_measurement_changes_root(self):
        tampered = copy.deepcopy(self.parsed)
        tampered["results"][0]["measured_value"] = "999.9"
        tampered_result = build_merkle_tree(tampered)
        self.assertNotEqual(
            self.result["root"],
            tampered_result["root"]
        )

    def test_tampered_date_changes_root(self):
        tampered = copy.deepcopy(self.parsed)
        tampered["valid_until"] = "2099-01-01"
        tampered_result = build_merkle_tree(tampered)
        self.assertNotEqual(
            self.result["root"],
            tampered_result["root"]
        )

    # ── compare_trees: clean ──────────────────────────────

    def test_compare_trees_clean_pass(self):
        proof = {
            "root": self.result["root"],
            "fields": self.result["fields"],
            "field_hashes": self.result["field_hashes"],
        }
        report = compare_trees(proof, self.parsed)
        self.assertTrue(report["root_matches"])
        for field, info in report["fields"].items():
            self.assertEqual(
                info["status"], "INTACT",
                f"Expected INTACT for {field}, got {info['status']}"
            )

    # ── compare_trees: tampered ───────────────────────────

    def test_compare_trees_catches_certificate_number_tamper(self):
        proof = {
            "root": self.result["root"],
            "fields": self.result["fields"],
            "field_hashes": self.result["field_hashes"],
        }
        tampered = copy.deepcopy(self.parsed)
        tampered["certificate_number"] = "N25040063/D2.02/C-FAKE"

        report = compare_trees(proof, tampered)

        self.assertFalse(report["root_matches"])
        self.assertEqual(
            report["fields"]["certificate_number"]["status"],
            "TAMPERED"
        )

    def test_compare_trees_only_tampered_field_flagged(self):
        proof = {
            "root": self.result["root"],
            "fields": self.result["fields"],
            "field_hashes": self.result["field_hashes"],
        }
        tampered = copy.deepcopy(self.parsed)
        tampered["certificate_number"] = "TAMPERED"

        report = compare_trees(proof, tampered)

        intact_fields = [
            k for k, v in report["fields"].items()
            if v["status"] == "INTACT"
        ]
        tampered_fields = [
            k for k, v in report["fields"].items()
            if v["status"] == "TAMPERED"
        ]

        self.assertIn("certificate_number", tampered_fields)
        self.assertEqual(len(tampered_fields), 1)
        self.assertEqual(len(intact_fields), 30)

    def test_compare_trees_catches_valid_until_tamper(self):
        """Core fraud scenario: customer edits validity date."""
        proof = {
            "root": self.result["root"],
            "fields": self.result["fields"],
            "field_hashes": self.result["field_hashes"],
        }
        tampered = copy.deepcopy(self.parsed)
        tampered["valid_until"] = "2099-01-01"

        report = compare_trees(proof, tampered)

        self.assertFalse(report["root_matches"])
        self.assertEqual(
            report["fields"]["valid_until"]["status"],
            "TAMPERED"
        )

    def test_compare_trees_catches_measurement_tamper(self):
        proof = {
            "root": self.result["root"],
            "fields": self.result["fields"],
            "field_hashes": self.result["field_hashes"],
        }
        tampered = copy.deepcopy(self.parsed)
        tampered["results"][2]["measured_value"] = "999.9"

        report = compare_trees(proof, tampered)

        self.assertFalse(report["root_matches"])
        self.assertEqual(
            report["fields"]["result_3_measured"]["status"],
            "TAMPERED"
        )


if __name__ == "__main__":
    unittest.main()