from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from src.platform_pki.errors import ApplicationError, shell_status
from src.platform_pki.faults import (
    DEFAULT_FAULT_HOOK,
    DEFAULT_PAUSE_HOOK,
    FaultHook,
    PauseHook,
    PauseHookError,
)


PYTHON = sys.executable


def _run_fault(source: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        (PYTHON, "-c", source),
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3,
        check=False,
    )


def test_default_hooks_are_immutable_no_ops(tmp_path: Path) -> None:
    DEFAULT_FAULT_HOOK("unmatched")
    DEFAULT_PAUSE_HOOK("unmatched")
    assert not tuple(tmp_path.iterdir())
    with pytest.raises(FrozenInstanceError):
        DEFAULT_FAULT_HOOK.crash_at = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        DEFAULT_PAUSE_HOOK.pause_at = "changed"  # type: ignore[misc]


def test_fault_hook_matches_literal_points_only() -> None:
    hook = FaultHook(failure_at="publish-*")
    hook("publish-state")
    hook("PUBLISH-*")
    with pytest.raises(ApplicationError):
        hook("publish-*")


def test_configured_unmatched_pause_is_a_no_op(tmp_path: Path) -> None:
    marker = tmp_path / "marker"
    hook = PauseHook(
        pause_at="exact",
        marker=marker,
        release=tmp_path / "release",
    )
    hook("different")
    assert not marker.exists()


def test_fault_failure_is_public_and_does_not_disclose_point() -> None:
    point = "secret-checkpoint"
    with pytest.raises(ApplicationError) as caught:
        FaultHook(failure_at=point)(point)
    assert caught.value.status == 1
    assert point not in str(caught.value)
    assert point not in repr(caught.value)


def test_crash_precedes_signal_and_failure_with_shell_status_137() -> None:
    result = _run_fault(
        "from src.platform_pki.faults import FaultHook; "
        "import signal; "
        "FaultHook(crash_at='same', signal_at='same', failure_at='same', "
        "signum=signal.SIGTERM)('same')"
    )
    assert shell_status(result.returncode) == 137
    assert result.stdout == result.stderr == b""


def test_configured_signal_precedes_failure_with_shell_status_143() -> None:
    result = _run_fault(
        "from src.platform_pki.faults import FaultHook; "
        "import signal; "
        "FaultHook(signal_at='same', failure_at='same', "
        "signum=signal.SIGTERM)('same')"
    )
    assert shell_status(result.returncode) == 143
    assert result.stdout == result.stderr == b""


def _wait_for_path(path: Path, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            pytest.fail(f"pause process exited early with {process.returncode}")
        time.sleep(0.005)
    pytest.fail("timed out waiting for pause marker")


def test_pause_hook_really_blocks_until_release_and_preserves_marker_bytes(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "marker"
    release = tmp_path / "release"
    source = (
        "from src.platform_pki.faults import PauseHook; "
        f"PauseHook(pause_at='barrier', marker={os.fspath(marker)!r}, "
        f"release={os.fspath(release)!r}, marker_bytes=b'paused\\x00\\xff', "
        "poll_interval=0.002)('barrier')"
    )
    process = subprocess.Popen(
        (PYTHON, "-c", source),
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for_path(marker, process)
        assert marker.read_bytes() == b"paused\x00\xff"
        assert marker.stat().st_mode & 0o777 == 0o600
        time.sleep(0.05)
        assert process.poll() is None
        release.write_bytes(b"release")
        stdout, stderr = process.communicate(timeout=3)
        assert process.returncode == 0
        assert stdout == stderr == b""
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)


def test_pause_marker_callback_runs_after_closed_exact_publication(tmp_path: Path) -> None:
    marker = tmp_path / "marker"
    release = tmp_path / "release"
    observed: list[Path] = []

    def marker_published(path: Path) -> None:
        observed.append(path)
        assert path.read_bytes() == b"exact marker\n"
        if Path("/proc/self/fd").is_dir():
            descriptor_targets = []
            for descriptor in Path("/proc/self/fd").iterdir():
                try:
                    descriptor_targets.append(os.readlink(descriptor))
                except FileNotFoundError:
                    pass
            assert not any(".marker.pause-" in target for target in descriptor_targets)
        release.write_bytes(b"")

    hook = PauseHook(
        pause_at="ready",
        marker=marker,
        release=release,
        marker_bytes=b"exact marker\n",
        poll_interval=0.001,
        marker_callback=marker_published,
    )
    hook("ready")
    assert observed == [marker]


def test_pause_marker_collision_fails_closed_without_truncation(tmp_path: Path) -> None:
    marker = tmp_path / "marker"
    release = tmp_path / "release"
    marker.write_bytes(b"pre-existing")
    hook = PauseHook(pause_at="ready", marker=marker, release=release)
    with pytest.raises(PauseHookError):
        hook("ready")
    assert marker.read_bytes() == b"pre-existing"


@pytest.mark.parametrize("which", ("marker", "release"))
def test_pause_hook_rejects_symlink_controls(which: str, tmp_path: Path) -> None:
    marker = tmp_path / "marker"
    release = tmp_path / "release"
    target = tmp_path / "target"
    target.write_bytes(b"")
    if which == "marker":
        marker.symlink_to(target)
    else:
        release.symlink_to(target)
    hook = PauseHook(pause_at="ready", marker=marker, release=release)
    with pytest.raises(PauseHookError):
        hook("ready")
    assert target.read_bytes() == b""


@pytest.mark.parametrize("which", ("marker", "release"))
def test_pause_hook_rejects_symlinked_control_ancestors(
    which: str,
    tmp_path: Path,
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    marker_parent = linked if which == "marker" else tmp_path
    release_parent = linked if which == "release" else tmp_path
    hook = PauseHook(
        pause_at="ready",
        marker=marker_parent / "marker",
        release=release_parent / "release",
    )
    with pytest.raises(PauseHookError):
        hook("ready")
    assert not (real / "marker").exists()


def test_invalid_controls_and_same_pause_paths_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "barrier"
    with pytest.raises(ValueError):
        FaultHook(crash_at="bad\npoint")
    with pytest.raises(ValueError):
        PauseHook(pause_at="bad\x1bpoint", marker=path, release=tmp_path / "release")
    with pytest.raises(ValueError):
        PauseHook(pause_at="ready", marker=path, release=path)
