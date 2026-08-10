from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .conftest import _write_conditional_rollover_wrapper


pytestmark = pytest.mark.infrastructure


def _write_trace_tool(path: Path, name: str) -> None:
    path.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"printf '%s\\n' {name!r} \"$@\" >\"$TRACE_FILE\"\n",
        encoding="ascii",
    )
    path.chmod(0o755)


@pytest.mark.parametrize(
    ("arguments", "expected"),
    (
        (
            ("recover", "--transaction", "prepare-1", "--action", "resume"),
            (
                "unified\nca-rollover\nrecover\n--transaction\nprepare-1\n"
                "--action\nresume\n"
            ),
        ),
        (("status", "--format", "json"), "compatibility\nstatus\n--format\njson\n"),
        ((), "compatibility\n"),
    ),
)
def test_conditional_rollover_wrapper_routes_once(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    arguments: tuple[str, ...],
    expected: str,
) -> None:
    unified = tmp_path / "platform-pki"
    compatibility = tmp_path / "platform-pki-ca-rollover.real"
    wrapper = tmp_path / "platform-pki-ca-rollover"
    trace = tmp_path / "trace"
    _write_trace_tool(unified, "unified")
    _write_trace_tool(compatibility, "compatibility")
    _write_conditional_rollover_wrapper(wrapper, unified, compatibility)

    result = process_runner(
        [wrapper, *arguments],
        env={
            "LC_ALL": "C",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "TRACE_FILE": os.fspath(trace),
        },
    )

    assert result.status == 0
    assert result.stdout == ""
    assert result.stderr == ""
    assert trace.read_text(encoding="ascii") == expected
