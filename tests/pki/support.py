from __future__ import annotations

import os
import shutil
import stat
import tempfile
from collections.abc import Generator, Mapping
from hashlib import sha256
from pathlib import Path

import pytest

from ..harness import ProcessResult


REPOSITORY = Path(__file__).resolve().parents[2]
BIN = REPOSITORY / "bin"
FINAL_BASH_SOURCE = REPOSITORY / "tests/pki/oracles/final-bash-source"
FINAL_BASH_LIB = FINAL_BASH_SOURCE / "lib"


def environment(base: Mapping[str, str], **values: str) -> dict[str, str]:
    return {**base, **values}


def write_private(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        stream = os.fdopen(descriptor, "w", encoding="utf-8")
    except BaseException:
        os.close(descriptor)
        raise
    with stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(content)


def write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def assert_result(
    result: ProcessResult,
    status: int,
    *,
    stdout: str | None = None,
    stderr: str | None = None,
) -> None:
    assert result.status == status, (
        f"status={result.status} stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    if stdout is not None:
        assert result.stdout == stdout
    if stderr is not None:
        assert result.stderr == stderr


def executable(name: str) -> str:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return os.fspath(candidate)
    raise FileNotFoundError(name)


@pytest.fixture
def executable_directory() -> Generator[Path, None, None]:
    parent = REPOSITORY / ".tmp"
    parent.mkdir(mode=0o700, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix="pytest-pki-exec.", dir=parent))
    try:
        yield path
    finally:
        shutil.rmtree(path)
