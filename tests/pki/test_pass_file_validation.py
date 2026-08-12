import os
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
COMMON = (
    ROOT / "tests/pki/oracles/final-bash-source/lib/platform-pki-common.sh"
)
VALIDATOR = 'source "$1"; pki_require_pass_file "$2"'


@pytest.mark.parametrize(
    ("content", "mode", "status", "message"),
    [
        (b"\nthis-second-line-is-long-enough\n", 0o600, 1, "first line is empty"),
        (b"                \n", 0o600, 1, "non-whitespace characters"),
        (b"short-pass\n", 0o600, 1, "at least 16 characters"),
        (b"valid-passphrase-123\n", 0o644, 1, "permissions are too open"),
        (b"valid-passphrase-123\n", 0o600, 0, ""),
        (b"valid-passphrase-456", 0o600, 0, ""),
    ],
    ids=["empty-first-line", "whitespace-only", "short", "open-mode", "valid", "valid-no-newline"],
)
def test_pass_file_validation(
    tmp_path: Path,
    process_runner,
    content: bytes,
    mode: int,
    status: int,
    message: str,
) -> None:
    path = tmp_path / "passphrase"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
    path.chmod(mode)

    result = process_runner(["bash", "-c", VALIDATOR, "_", COMMON, path])

    assert result.status == status
    assert result.stdout == ""
    if status == 0:
        assert result.stderr == ""
    else:
        assert result.stderr.startswith("[ERROR] Passphrase file ")
        assert message in result.stderr
        assert result.stderr.endswith(f": {path}\n")
