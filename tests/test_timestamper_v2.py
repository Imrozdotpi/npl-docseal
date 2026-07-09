import unittest
from unittest.mock import patch

from core.timestamper import verify_timestamp, upgrade_timestamp


class TestVerifyTimestamp(unittest.TestCase):

    @patch("core.timestamper._run_wsl_command")
    @patch("core.timestamper._check_ots")
    @patch("pathlib.Path.exists", return_value=True)
    def test_pending_status(self, mock_exists, mock_check, mock_run):
        mock_run.return_value = "Pending confirmation in Bitcoin blockchain"
        result = verify_timestamp("sample.txt.ots")
        self.assertEqual(result["status"], "pending")
        self.assertIsNone(result["timestamp"])
        self.assertIsNone(result["block_height"])

    @patch("core.timestamper._run_wsl_command")
    @patch("core.timestamper._check_ots")
    @patch("pathlib.Path.exists", return_value=True)
    def test_confirmed_status(self, mock_exists, mock_check, mock_run):
        mock_run.return_value = "Success! Bitcoin block 950000"
        result = verify_timestamp("sample.txt.ots")
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["block_height"], 950000)

    @patch("core.timestamper._run_wsl_command")
    @patch("core.timestamper._check_ots")
    @patch("pathlib.Path.exists", return_value=True)
    def test_failed_status(self, mock_exists, mock_check, mock_run):
        mock_run.return_value = "Unknown error occurred"
        result = verify_timestamp("sample.txt.ots")
        self.assertEqual(result["status"], "failed")

    @patch("core.timestamper._run_wsl_command")
    @patch("core.timestamper._check_ots")
    @patch("pathlib.Path.exists", return_value=True)
    def test_pending_attestation_status(self, mock_exists, mock_check, mock_run):
        mock_run.return_value = "pendingAttestation https://alice.btc.calendar"
        result = verify_timestamp("sample.txt.ots")
        self.assertEqual(result["status"], "pending")


class TestUpgradeTimestamp(unittest.TestCase):

    @patch("core.timestamper._run_wsl_command")
    @patch("core.timestamper._check_ots")
    @patch("pathlib.Path.exists", return_value=True)
    def test_upgrade_pending(self, mock_exists, mock_check, mock_run):
        mock_run.return_value = "Pending confirmation in Bitcoin blockchain"
        result = upgrade_timestamp("sample.txt.ots")
        self.assertFalse(result)

    @patch("core.timestamper._run_wsl_command")
    @patch("core.timestamper._check_ots")
    @patch("pathlib.Path.exists", return_value=True)
    def test_upgrade_complete(self, mock_exists, mock_check, mock_run):
        mock_run.return_value = "Timestamp already complete"
        result = upgrade_timestamp("sample.txt.ots")
        self.assertTrue(result)

    @patch("core.timestamper._run_wsl_command")
    @patch("core.timestamper._check_ots")
    @patch("pathlib.Path.exists", return_value=True)
    def test_upgrade_waiting_for_confirmations(self, mock_exists, mock_check, mock_run):
        mock_run.return_value = "Waiting for confirmations"
        result = upgrade_timestamp("sample.txt.ots")
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()