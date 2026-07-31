import os
import signal
import stat
import sys
import time
from pathlib import Path

import pytest

from . import harness
from .harness import ProcessResult, ProcessTimeout, shell_status


pytestmark = pytest.mark.infrastructure


@pytest.mark.parametrize(("returncode", "status"), [(0, 0), (23, 23), (-9, 137)])
def test_shell_status(returncode: int, status: int) -> None:
    assert shell_status(returncode) == status


def test_process_runner_passes_arguments_without_a_shell(
    tmp_path, process_runner
) -> None:
    argument = "$(touch should-not-exist); *"
    result = process_runner(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", argument],
        cwd=tmp_path,
    )

    assert result.status == 0
    assert result.stdout == f"{argument}\n"
    assert result.stderr == ""
    assert not (tmp_path / "should-not-exist").exists()


def test_process_runner_normalizes_signal_status(process_runner) -> None:
    result = process_runner(
        [sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"]
    )

    assert result.status == 128 + signal.SIGKILL


def test_process_runner_kills_timed_out_process_group(process_runner) -> None:
    command = (
        "import signal, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "print('ready', flush=True); "
        "time.sleep(60)"
    )
    started = time.monotonic()

    with pytest.raises(ProcessTimeout) as error:
        process_runner([sys.executable, "-c", command], timeout=0.5, term_grace=0.1)

    assert time.monotonic() - started < 5
    assert error.value.result.status == 128 + signal.SIGKILL
    assert error.value.result.stdout == "ready\n"


def test_process_runner_kills_child_after_parent_exits(tmp_path, process_runner) -> None:
    child_pid_file = tmp_path / "child.pid"
    child_command = (
        "import os, signal, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"open({os.fspath(child_pid_file)!r}, 'w').write(str(os.getpid())); "
        "os.close(1); os.close(2); time.sleep(60)"
    )
    parent_command = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child_command!r}]); "
        "time.sleep(60)"
    )

    with pytest.raises(ProcessTimeout) as error:
        process_runner([sys.executable, "-c", parent_command], timeout=0.5, term_grace=0.1)

    child_pid = int(child_pid_file.read_text(encoding="utf-8"))
    child_state = Path(f"/proc/{child_pid}/stat")
    deadline = time.monotonic() + 2
    while True:
        try:
            state = child_state.read_text(encoding="utf-8").split()[2]
        except FileNotFoundError:
            break
        if state == "Z":
            break
        assert time.monotonic() < deadline, "timed-out child remained alive"
        time.sleep(0.01)
    assert error.value.result.status == 128 + signal.SIGTERM


def test_tree_copier_preserves_modes_and_symlinks(tmp_path, tree_copier) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir(mode=0o750)
    source.chmod(0o750)
    payload = source / "payload"
    payload.write_text("value\n", encoding="utf-8")
    payload.chmod(0o640)
    (source / "payload-link").symlink_to("payload")

    tree_copier(source, destination)

    assert stat.S_IMODE(destination.stat().st_mode) == 0o750
    assert stat.S_IMODE((destination / "payload").stat().st_mode) == 0o640
    assert os.readlink(destination / "payload-link") == "payload"


def test_tree_copier_uses_bounded_process_runner(tmp_path, monkeypatch) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    observed = {}

    def fake_run_process(args, *, timeout):
        observed["args"] = tuple(args)
        observed["timeout"] = timeout
        return ProcessResult(tuple(args), 0, "", "")

    monkeypatch.setattr(harness, "run_process", fake_run_process)

    harness.copy_tree(source, destination)

    assert observed == {
        "args": ("cp", "-a", "--", os.fspath(source), os.fspath(destination)),
        "timeout": 30,
    }
