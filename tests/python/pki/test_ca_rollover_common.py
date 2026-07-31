import os
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from ..harness import ProcessResult


pytestmark = pytest.mark.pki


def test_file_identity_detects_same_size_same_second_rewrite(
    tmp_path: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    common_library = (
        Path(__file__).resolve().parents[3] / "lib/platform-pki-common.sh"
    )
    rewritten = tmp_path / "key"
    rewritten.write_bytes(b"first")
    rewritten.chmod(0o600)

    second = rewritten.stat().st_mtime_ns // 1_000_000_000
    first_timestamp = second * 1_000_000_000 + 100_000_000
    second_timestamp = second * 1_000_000_000 + 200_000_000
    os.utime(rewritten, ns=(first_timestamp, first_timestamp))

    command = [
        "bash",
        "-c",
        'source "$1"; pki_file_identity "$2"',
        "_",
        common_library,
        rewritten,
    ]
    before = process_runner(command, env=isolated_environment, timeout=10)
    metadata_before = rewritten.stat()

    rewritten.write_bytes(b"other")
    os.utime(rewritten, ns=(second_timestamp, second_timestamp))
    after = process_runner(command, env=isolated_environment, timeout=10)
    metadata_after = rewritten.stat()

    assert before.status == after.status == 0
    assert before.stderr == after.stderr == ""
    assert before.stdout.strip()
    assert before.stdout != after.stdout
    assert metadata_before.st_dev == metadata_after.st_dev
    assert metadata_before.st_ino == metadata_after.st_ino
    assert metadata_before.st_mode == metadata_after.st_mode
    assert metadata_before.st_size == metadata_after.st_size == 5
    assert metadata_before.st_mtime_ns // 1_000_000_000 == (
        metadata_after.st_mtime_ns // 1_000_000_000
    )
