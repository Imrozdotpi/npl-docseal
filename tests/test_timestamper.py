from unittest.mock import patch
from core.timestamper import verify_timestamp
from core.timestamper import upgrade_timestamp


@patch("core.timestamper._run_wsl_command")
@patch("pathlib.Path.exists")
def test_verify_pending(
    mock_exists,
    mock_run
):
    mock_exists.return_value = True

    mock_run.return_value = (
        "Pending confirmation "
        "in Bitcoin blockchain"
    )

    result = verify_timestamp(
        "sample.txt.ots"
    )

    assert result["status"] == "pending"
    assert result["timestamp"] is None
    assert result["block_height"] is None


@patch("core.timestamper._run_wsl_command")
@patch("pathlib.Path.exists")
def test_verify_confirmed(
    mock_exists,
    mock_run
):
    mock_exists.return_value = True

    mock_run.return_value = (
        "Success! Bitcoin block 950000"
    )

    result = verify_timestamp(
        "sample.txt.ots"
    )

    assert result["status"] == "confirmed"


@patch("core.timestamper._run_wsl_command")
@patch("pathlib.Path.exists")
def test_verify_failed(
    mock_exists,
    mock_run
):
    mock_exists.return_value = True

    mock_run.return_value = (
        "Unknown error"
    )

    result = verify_timestamp(
        "sample.txt.ots"
    )

    assert result["status"] == "failed"


@patch("core.timestamper._run_wsl_command")
@patch("pathlib.Path.exists")
def test_upgrade_pending(
    mock_exists,
    mock_run
):
    mock_exists.return_value = True

    mock_run.return_value = (
        "Pending confirmation "
        "in Bitcoin blockchain"
    )

    assert (
        upgrade_timestamp(
            "sample.txt.ots"
        ) is False
    )


@patch("core.timestamper._run_wsl_command")
@patch("pathlib.Path.exists")
def test_upgrade_complete(
    mock_exists,
    mock_run
):
    mock_exists.return_value = True

    mock_run.return_value = (
        "Timestamp already complete"
    )

    assert (
        upgrade_timestamp(
            "sample.txt.ots"
        ) is True
    )