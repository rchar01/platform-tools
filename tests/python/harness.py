from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


@dataclass(frozen=True)
class ProcessResult:
    args: tuple[str, ...]
    status: int
    stdout: str
    stderr: str


class ProcessTimeout(TimeoutError):
    def __init__(self, timeout: float, result: ProcessResult) -> None:
        super().__init__(f"command timed out after {timeout:g}s: {result.args!r}")
        self.timeout = timeout
        self.result = result


def shell_status(returncode: int) -> int:
    return 128 - returncode if returncode < 0 else returncode


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_process_group(process_group: int, deadline: float) -> bool:
    while _process_group_exists(process_group):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))
    return True


def run_process(
    args: Sequence[str | os.PathLike[str]],
    *,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float = 30,
    term_grace: float = 1,
) -> ProcessResult:
    argv = tuple(os.fspath(arg) for arg in args)
    if not argv:
        raise ValueError("args must not be empty")
    if timeout <= 0 or term_grace < 0:
        raise ValueError("timeout must be positive and term_grace nonnegative")

    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        shell=False,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        deadline = time.monotonic() + term_grace
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=term_grace)
        except subprocess.TimeoutExpired:
            pass
        if not _wait_for_process_group(process.pid, deadline):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        stdout, stderr = process.communicate()
        result = ProcessResult(argv, shell_status(process.returncode), stdout, stderr)
        raise ProcessTimeout(timeout, result) from None

    return ProcessResult(argv, shell_status(process.returncode), stdout, stderr)


def copy_tree(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    subprocess.run(
        ("cp", "-a", "--", os.fspath(source), os.fspath(destination)),
        check=True,
        shell=False,
    )
