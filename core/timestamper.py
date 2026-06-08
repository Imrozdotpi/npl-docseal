from pathlib import Path
from datetime import datetime
import subprocess
import platform


# OpenTimestamps executable inside WSL
OTS_PATH = "/home/touch_hp_840/.local/bin/ots"


class TimestampError(Exception):
    """Raised when OpenTimestamps operations fail."""
    pass


def _windows_to_wsl_path(filepath: str) -> str:
    """
    Convert Windows paths to WSL paths.

    Examples:

    Windows:
    C:\\Users\\User\\file.pdf
        ->
    /mnt/c/Users/User/file.pdf

    WSL:
    /mnt/c/Users/User/file.pdf
        ->
    /mnt/c/Users/User/file.pdf
    """

    path = Path(filepath).resolve()

    if not path.exists():
        raise FileNotFoundError(filepath)

    path_str = str(path)

    # Already a Linux/WSL path
    if path_str.startswith("/"):
        return path_str

    drive = path.drive[0].lower()

    return (
        f"/mnt/{drive}"
        + path_str.replace("\\", "/")[2:]
    )


def _run_wsl_command(args: list[str]) -> str:
    """
    Execute command and return combined stdout/stderr.
    Supports both:

    Windows Python -> WSL
    WSL Python     -> Native execution
    """

    # Running inside Linux/WSL
    if platform.system() == "Linux":

        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False
        )

    else:

        result = subprocess.run(
            ["wsl"] + args,
            capture_output=True,
            text=True,
            check=False
        )

    output = (
        (result.stdout or "")
        + (result.stderr or "")
    )

    return output.strip()


def stamp_file(filepath: str) -> str:
    """
    Create OpenTimestamps proof.

    Returns:
        Path to .ots file
    """

    file_path = Path(filepath).resolve()

    if not file_path.exists():
        raise FileNotFoundError(filepath)

    wsl_file = _windows_to_wsl_path(str(file_path))

    output = _run_wsl_command(
        [
            OTS_PATH,
            "stamp",
            wsl_file
        ]
    )

    ots_path = str(file_path) + ".ots"

    if not Path(ots_path).exists():

        raise TimestampError(
            f"Timestamp creation failed:\n{output}"
        )

    return ots_path


def upgrade_timestamp(ots_path: str) -> bool:
    """
    Upgrade timestamp proof.

    Returns:
        True  -> upgraded or complete
        False -> still pending
    """

    ots_file = Path(ots_path).resolve()

    if not ots_file.exists():
        raise FileNotFoundError(ots_path)

    wsl_ots = _windows_to_wsl_path(str(ots_file))

    output = _run_wsl_command(
        [
            OTS_PATH,
            "upgrade",
            wsl_ots
        ]
    )

    if "Pending confirmation" in output:
        return False

    return True


def get_timestamp_info(ots_path: str) -> str:
    """
    Return raw OTS info output.
    """

    ots_file = Path(ots_path).resolve()

    if not ots_file.exists():
        raise FileNotFoundError(ots_path)

    wsl_ots = _windows_to_wsl_path(str(ots_file))

    return _run_wsl_command(
        [
            OTS_PATH,
            "info",
            wsl_ots
        ]
    )


def verify_timestamp(ots_path: str) -> dict:
    """
    Verify OpenTimestamps proof.

    Returns:
    {
        "status": "pending" | "confirmed" | "failed",
        "timestamp": datetime | None,
        "block_height": int | None
    }
    """

    ots_file = Path(ots_path).resolve()

    if not ots_file.exists():
        raise FileNotFoundError(ots_path)

    wsl_ots = _windows_to_wsl_path(str(ots_file))

    output = _run_wsl_command(
        [
            OTS_PATH,
            "verify",
            wsl_ots
        ]
    )

    if "Pending confirmation" in output:

        return {
            "status": "pending",
            "timestamp": None,
            "block_height": None
        }

    if (
        "Bitcoin block" in output
        or "Success" in output
        or "verified" in output.lower()
    ):

        return {
            "status": "confirmed",
            "timestamp": datetime.utcnow(),
            "block_height": None
        }

    return {
        "status": "failed",
        "timestamp": None,
        "block_height": None
    }