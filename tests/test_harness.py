import errno
import json
import os
import signal
import stat
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

import pytest

from . import harness
from .harness import (
    ProcessResult,
    ProcessTimeout,
    ProcessTracker,
    run_process,
    shell_status,
)


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


@pytest.mark.parametrize("payload", ["text input\n", b"byte input\n"])
def test_process_runner_supplies_controlled_input(process_runner, payload) -> None:
    result = process_runner(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())",
        ],
        input=payload,
    )

    expected = "text input\n" if isinstance(payload, str) else "byte input\n"
    assert result == ProcessResult(result.args, 0, expected, "")


def test_process_runner_streams_input(process_runner) -> None:
    before = {thread.ident for thread in threading.enumerate()}
    result = process_runner(
        [sys.executable, "-c", "import sys; print(len(sys.stdin.buffer.readlines()))"],
        input_chunks=(b"first\n", "second\n", b"third\n"),
    )

    assert result.stdout == "3\n"
    assert not any(
        thread.ident not in before and thread.name == "managed-process-stdin"
        for thread in threading.enumerate()
    )


@pytest.mark.parametrize(
    ("args", "keywords", "error"),
    [
        ([], {}, "args must not be empty"),
        ([sys.executable], {"timeout": 0}, "timeout must be positive"),
        ([sys.executable], {"term_grace": -1}, "term_grace nonnegative"),
        ([sys.executable], {"pass_fds": (-1,)}, "pass_fds"),
        ([sys.executable], {"pty_mode": "combined"}, "pty_mode"),
        (
            [sys.executable],
            {"controlling_terminal": True},
            "controlling_terminal requires pty_mode",
        ),
        (
            [sys.executable],
            {"input": b"one", "input_chunks": [b"two"]},
            "mutually exclusive",
        ),
    ],
)
def test_process_runner_rejects_invalid_arguments(args, keywords, error) -> None:
    with pytest.raises(ValueError, match=error):
        run_process(args, **keywords)


def test_process_runner_rejects_invalid_stream_chunk(process_runner) -> None:
    with pytest.raises(TypeError, match="process input must be str or bytes"):
        process_runner(
            [sys.executable, "-c", "import sys; sys.stdin.buffer.read()"],
            input_chunks=[object()],
        )


def test_process_runner_rejects_iterator_without_iterating() -> None:
    iterated = False

    def blocking_iterator():
        nonlocal iterated
        iterated = True
        yield b"data"

    with pytest.raises(TypeError, match="concrete list or tuple"):
        run_process(
            [sys.executable, "-c", "pass"],
            input_chunks=cast(Any, blocking_iterator()),
        )

    assert not iterated


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


def test_process_runner_allows_term_handler_to_finish(process_runner) -> None:
    command = (
        "import signal, time; "
        "signal.signal(signal.SIGTERM, lambda *_: exit(42)); "
        "print('ready', flush=True); time.sleep(60)"
    )

    with pytest.raises(ProcessTimeout) as error:
        process_runner(
            [sys.executable, "-c", command, "secret-value"],
            timeout=0.3,
            term_grace=0.5,
        )

    assert error.value.result.status == 42
    assert str(error.value) == "process timed out after 0.3s"
    assert "secret-value" not in str(error.value)


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


def test_process_runner_cleans_descendant_after_normal_parent_exit(
    tmp_path, process_runner
) -> None:
    child_pid_file = tmp_path / "normal-child.pid"
    child_command = (
        "import os, signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"open({os.fspath(child_pid_file)!r}, 'w').write(str(os.getpid())); "
        "os.close(1); os.close(2); time.sleep(60)"
    )
    parent_command = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child_command!r}]); "
        "time.sleep(.1)"
    )

    result = process_runner(
        [sys.executable, "-c", parent_command], timeout=2, term_grace=0.1
    )

    assert result.status == 0
    child_pid = int(child_pid_file.read_text(encoding="utf-8"))
    state_path = Path(f"/proc/{child_pid}/stat")
    deadline = time.monotonic() + 2
    while state_path.exists():
        if state_path.read_text(encoding="utf-8").split()[2] == "Z":
            break
        assert time.monotonic() < deadline, "normal descendant remained alive"
        time.sleep(0.01)


def test_process_runner_canonical_pty_delivers_eof_after_unterminated_input(
    process_runner,
) -> None:
    command = (
        "import os, sys; data = sys.stdin.buffer.read(); "
        "print(os.isatty(0)); print(data.decode())"
    )

    result = process_runner(
        [sys.executable, "-c", command],
        input="unterminated-secret",
        pty_mode="canonical",
    )

    assert result.status == 0
    assert result.stdout == "True\r\nunterminated-secret\r\n"
    assert result.stderr == ""
    assert result.stdout.count("unterminated-secret") == 1


def test_process_runner_canonical_pty_does_not_echo_secret(process_runner) -> None:
    result = process_runner(
        [
            sys.executable,
            "-c",
            "import sys; input(); print('accepted'); print('error', file=sys.stderr)",
        ],
        input="secret-value\n",
        pty_mode="canonical",
    )

    assert result.status == 0
    assert result.stdout == "accepted\r\n"
    assert result.stderr == "error\n"
    assert "secret-value" not in result.stdout
    assert "secret-value" not in result.stderr


def test_canonical_pty_does_not_claim_controlling_terminal_by_default(
    process_runner,
) -> None:
    command = (
        "import os; "
        "\ntry: fd = os.open('/dev/tty', os.O_RDWR)\n"
        "except OSError: print('unavailable')\n"
        "else: os.close(fd); print('available')"
    )

    result = process_runner(
        [sys.executable, "-c", command], pty_mode="canonical"
    )

    assert result.status == 0
    assert result.stdout == "unavailable\r\n"
    assert result.stderr == ""


def test_controlling_terminal_supports_dev_tty_eof_without_echo(
    process_runner,
) -> None:
    secret = "unterminated-controlling-secret"
    command = (
        "import os; fd = os.open('/dev/tty', os.O_RDWR); data = b''; "
        "\nwhile True:\n"
        " chunk = os.read(fd, 4096)\n"
        " if not chunk: break\n"
        " data += chunk\n"
        "os.write(fd, f'tty-bytes:{len(data)}\\n'.encode()); "
        "os.write(2, b'stderr-separated\\n'); os.close(fd)"
    )

    result = process_runner(
        [sys.executable, "-c", command],
        input=secret,
        pty_mode="canonical",
        controlling_terminal=True,
    )

    assert result.status == 0
    assert result.stdout == f"tty-bytes:{len(secret)}\r\n"
    assert result.stderr == "stderr-separated\n"
    assert secret not in result.stdout
    assert secret not in result.stderr


def test_controlling_terminal_preserves_explicit_file_descriptors(
    process_runner,
) -> None:
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"descriptor-data")
        os.close(write_fd)
        write_fd = -1
        command = (
            "import os, sys; tty_fd = os.open('/dev/tty', os.O_RDWR); "
            "print(os.read(int(sys.argv[1]), 64).decode()); os.close(tty_fd)"
        )
        result = process_runner(
            [sys.executable, "-c", command, str(read_fd)],
            pty_mode="canonical",
            controlling_terminal=True,
            pass_fds=(read_fd,),
        )

        assert result.status == 0
        assert result.stdout == "descriptor-data\r\n"
        assert result.stderr == ""
        os.fstat(read_fd)
    finally:
        for descriptor in (read_fd, write_fd):
            if descriptor >= 0:
                os.close(descriptor)


@pytest.mark.parametrize("pty_mode", [None, "canonical"])
def test_child_fd_mapping_has_exact_fds_and_preserves_parent(
    process_runner, pty_mode
) -> None:
    read_fd, write_fd = os.pipe()
    if read_fd == 3:
        replacement = os.dup(read_fd)
        os.close(read_fd)
        read_fd = replacement
    parent_fd3_before = None
    try:
        parent_fd3_before = os.fstat(3)
    except OSError:
        pass
    source_before = os.fstat(read_fd)
    try:
        os.write(write_fd, b"mapped-payload")
        os.close(write_fd)
        write_fd = -1
        command = (
            "import json, os; data = os.read(3, 64).decode(); fds = []; "
            "\nfor name in os.listdir('/proc/self/fd'):\n"
            " try: os.fstat(int(name))\n"
            " except OSError: continue\n"
            " fds.append(int(name))\n"
            "print(json.dumps({'data': data, 'fds': sorted(fds)}))"
        )
        result = process_runner(
            [sys.executable, "-c", command],
            pty_mode=pty_mode,
            fd_mappings=((read_fd, 3),),
        )

        probe = json.loads(result.stdout.strip())
        assert probe == {"data": "mapped-payload", "fds": [0, 1, 2, 3]}
        assert os.fstat(read_fd) == source_before
        if parent_fd3_before is None:
            with pytest.raises(OSError):
                os.fstat(3)
        else:
            assert os.fstat(3) == parent_fd3_before
    finally:
        for descriptor in (read_fd, write_fd):
            if descriptor >= 0:
                os.close(descriptor)


def test_child_fd_mapping_is_concurrency_safe(process_runner) -> None:
    pipes = [os.pipe() for _ in range(8)]
    parent_fd3_before = None
    try:
        parent_fd3_before = os.fstat(3)
    except OSError:
        pass
    try:
        for index, (_read_fd, write_fd) in enumerate(pipes):
            os.write(write_fd, f"payload-{index}".encode())
            os.close(write_fd)
        pipes = [(read_fd, -1) for read_fd, _write_fd in pipes]

        def consume(item) -> str:
            index, (read_fd, _write_fd) = item
            result = process_runner(
                [sys.executable, "-c", "import os; print(os.read(3, 64).decode())"],
                fd_mappings=((read_fd, 3),),
            )
            os.fstat(read_fd)
            assert result.status == 0
            return result.stdout.strip()

        with ThreadPoolExecutor(max_workers=8) as pool:
            observed = list(pool.map(consume, enumerate(pipes)))

        assert observed == [f"payload-{index}" for index in range(8)]
        if parent_fd3_before is None:
            with pytest.raises(OSError):
                os.fstat(3)
        else:
            assert os.fstat(3) == parent_fd3_before
    finally:
        for read_fd, write_fd in pipes:
            for descriptor in (read_fd, write_fd):
                if descriptor >= 0:
                    os.close(descriptor)


def test_child_fd_mapping_timeout_closes_child_copy_only(process_starter) -> None:
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"mapped")
        os.close(write_fd)
        write_fd = -1
        process = process_starter(
            [
                sys.executable,
                "-c",
                "import os, signal, time; os.read(3, 64); "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
            ],
            fd_mappings=((read_fd, 3),),
            timeout=0.3,
            term_grace=0.1,
        )

        with pytest.raises(ProcessTimeout) as error:
            process.wait()
        assert error.value.result.status == 128 + signal.SIGKILL
        assert process.finished
        os.fstat(read_fd)
    finally:
        for descriptor in (read_fd, write_fd):
            if descriptor >= 0:
                os.close(descriptor)


def test_child_fd_mapping_rejects_conflicts_and_closed_sources() -> None:
    first_read, first_write = os.pipe()
    second_read, second_write = os.pipe()
    closed_read, closed_write = os.pipe()
    os.close(closed_read)
    try:
        cases = (
            (((first_read, 2),), (), "at least 3"),
            (((first_read, 3), (second_read, 3)), (), "unique"),
            (
                ((first_read, second_read), (second_read, 9)),
                (),
                "conflict",
            ),
            (((first_read, 3),), (first_read,), "must not overlap"),
            (((closed_read, 3),), (), "source descriptor is not open"),
        )
        for mappings, pass_fds, message in cases:
            with pytest.raises(ValueError, match=message):
                run_process(
                    [sys.executable, "-c", "pass"],
                    fd_mappings=mappings,
                    pass_fds=pass_fds,
                )
    finally:
        for descriptor in (first_read, first_write, second_read, second_write, closed_write):
            os.close(descriptor)


def test_controlling_terminal_exec_preserves_identity_and_exact_fds(
    process_starter,
) -> None:
    read_fd, write_fd = os.pipe()
    try:
        command = (
            "import json, os, sys; "
            "tty_fd = os.open('/dev/tty', os.O_RDWR); os.close(tty_fd); "
            "fds = []; "
            "\nfor name in os.listdir('/proc/self/fd'):\n"
            " try: os.fstat(int(name))\n"
            " except OSError: continue\n"
            " fds.append(int(name))\n"
            "print(json.dumps({'argv': sys.argv, 'pid': os.getpid(), "
            "'pgid': os.getpgrp(), 'sid': os.getsid(0), 'fds': sorted(fds)}), flush=True); "
            "os.read(0, 1)"
        )
        process = process_starter(
            [sys.executable, "-c", command, "target-marker"],
            pty_mode="canonical",
            controlling_terminal=True,
            pass_fds=(read_fd,),
        )
        observed_pid = process._process.pid
        deadline = time.monotonic() + 2
        while "\n" not in process.observe().stdout:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        probe = json.loads(process.observe().stdout.strip())
        process.send_eof()
        result = process.wait()

        assert result.status == 0
        assert process.args == (sys.executable, "-c", command, "target-marker")
        assert probe["argv"] == ["-c", "target-marker"]
        assert probe["pid"] == observed_pid
        assert probe["pid"] == probe["pgid"] == probe["sid"]
        assert probe["fds"] == sorted((0, 1, 2, read_fd))
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_controlling_terminal_timeout_cleans_session_process_group(
    process_runner,
) -> None:
    command = (
        "import os, signal, time; os.open('/dev/tty', os.O_RDWR); "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "print('ready', flush=True); time.sleep(60)"
    )

    with pytest.raises(ProcessTimeout) as error:
        process_runner(
            [sys.executable, "-c", command],
            pty_mode="canonical",
            controlling_terminal=True,
            timeout=0.3,
            term_grace=0.1,
        )

    assert error.value.result.status == 128 + signal.SIGKILL
    assert error.value.result.stdout == "ready\r\n"
    assert error.value.result.stderr == ""


def test_timeout_kills_escaped_setsid_descendant_with_retained_capture_fds(
    tmp_path, process_runner
) -> None:
    child_pid_file = tmp_path / "escaped.pid"
    residue = tmp_path / "escaped-survived"
    child_command = (
        "import os, signal, time; os.setsid(); "
        f"open({os.fspath(child_pid_file)!r}, 'w').write(str(os.getpid())); "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60); "
        f"open({os.fspath(residue)!r}, 'w').write('survived')"
    )
    parent_command = (
        "import signal, subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child_command!r}]); "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "print('ready', flush=True); time.sleep(60)"
    )
    started = time.monotonic()

    with pytest.raises(ProcessTimeout) as error:
        process_runner(
            [sys.executable, "-c", parent_command],
            timeout=0.5,
            term_grace=0.2,
        )

    assert time.monotonic() - started < 5
    assert error.value.result.status == 128 + signal.SIGKILL
    assert error.value.result.stdout == "ready\n"
    escaped_pid = int(child_pid_file.read_text(encoding="utf-8"))
    escaped_stat = Path(f"/proc/{escaped_pid}/stat")
    deadline = time.monotonic() + 2
    while escaped_stat.exists():
        if escaped_stat.read_text(encoding="utf-8").rsplit(")", 1)[1].split()[0] == "Z":
            break
        assert time.monotonic() < deadline, "escaped setsid descendant remained alive"
        time.sleep(0.01)
    assert not residue.exists()


def test_process_runner_raw_pty_uses_fixed_length_input_and_separate_stderr(
    process_runner,
) -> None:
    command = (
        "import os; data = os.read(0, 6); "
        "os.write(1, data.upper()); os.write(2, b'error\\n')"
    )

    result = process_runner(
        [sys.executable, "-c", command], input=b"secret", pty_mode="raw"
    )

    assert result.stdout == "SECRET"
    assert result.stderr == "error\n"


def test_managed_raw_pty_rejects_synthetic_eof(process_starter) -> None:
    process = process_starter(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        pty_mode="raw",
        term_grace=0.1,
    )

    with pytest.raises(RuntimeError, match="raw PTY mode has no synthetic EOF"):
        process.send_eof()


def test_payload_eio_is_not_suppressed(process_starter, monkeypatch) -> None:
    process = process_starter(
        [sys.executable, "-c", "import sys; sys.stdin.buffer.read()"]
    )

    def fail_payload(_data) -> None:
        raise OSError(errno.EIO, "payload failed")

    monkeypatch.setattr(process, "write", fail_payload)
    with pytest.raises(OSError, match="payload failed") as error:
        harness._feed_and_wait(process, (b"payload",))
    assert error.value.errno == errno.EIO


@pytest.mark.parametrize("terminal_errno", [errno.EBADF, errno.EIO])
def test_closed_terminal_during_synthetic_eof_is_normal(
    process_starter, monkeypatch, terminal_errno
) -> None:
    process = process_starter([sys.executable, "-c", "pass"], pty_mode="canonical")

    def fail_eof() -> None:
        raise OSError(terminal_errno, "terminal closed")

    monkeypatch.setattr(process, "send_eof", fail_eof)
    assert harness._feed_and_wait(process, ()).status == 0


def test_process_runner_bounds_blocked_stream_input(process_runner) -> None:
    chunks = [b"x" * 65536] * 1024
    before = {thread.ident for thread in threading.enumerate()}
    started = time.monotonic()

    with pytest.raises(ProcessTimeout):
        process_runner(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            input_chunks=chunks,
            timeout=0.3,
            term_grace=0.1,
        )

    assert time.monotonic() - started < 5
    assert not any(
        thread.ident not in before and thread.name == "managed-process-stdin"
        for thread in threading.enumerate()
    )


def test_process_runner_decoding_is_explicit_for_invalid_bytes(process_runner) -> None:
    command = "import os; os.write(1, b'\\xff'); os.write(2, b'\\xfe')"

    with pytest.raises(UnicodeDecodeError):
        process_runner([sys.executable, "-c", command])

    result = process_runner(
        [sys.executable, "-c", command], errors="surrogateescape"
    )
    assert result.stdout == "\udcff"
    assert result.stderr == "\udcfe"


def test_process_runner_inherits_only_explicit_file_descriptors(process_runner) -> None:
    inherited_read, inherited_write = os.pipe()
    hidden_read, hidden_write = os.pipe()
    os.set_inheritable(hidden_read, True)
    try:
        os.write(inherited_write, b"explicit")
        os.close(inherited_write)
        inherited_write = -1
        command = (
            "import os, sys; "
            "print(os.read(int(sys.argv[1]), 64).decode()); "
            "\ntry: os.fstat(int(sys.argv[2]))\n"
            "except OSError: print('closed')\n"
            "else: print('inherited')"
        )
        result = process_runner(
            [sys.executable, "-c", command, str(inherited_read), str(hidden_read)],
            pass_fds=(inherited_read,),
        )

        assert result.stdout == "explicit\nclosed\n"
        os.fstat(inherited_read)
        os.fstat(hidden_read)
    finally:
        for descriptor in (inherited_read, inherited_write, hidden_read, hidden_write):
            if descriptor >= 0:
                os.close(descriptor)


@pytest.mark.parametrize("pty_mode", [None, "canonical", "raw"])
def test_managed_process_closes_harness_descriptors(process_starter, pty_mode) -> None:
    process = process_starter([sys.executable, "-c", "pass"], pty_mode=pty_mode)

    assert process.wait().status == 0
    assert process._master_fd is None
    if pty_mode is None:
        assert process._process.stdin.closed
        assert process._process.stdout.closed
    assert process._process.stderr.closed


def test_process_tracker_closes_abandoned_process_group(tmp_path) -> None:
    tracker = ProcessTracker()
    processes = []
    pid_files = []
    for index in range(2):
        pid_file = tmp_path / f"tracked-{index}.pid"
        pid_files.append(pid_file)
        processes.append(
            tracker.start(
                [
                    sys.executable,
                    "-c",
                    f"import os, time; open({os.fspath(pid_file)!r}, 'w').write(str(os.getpid())); time.sleep(60)",
                ],
                term_grace=0.1,
            )
        )
    deadline = time.monotonic() + 2
    while not all(pid_file.exists() for pid_file in pid_files):
        assert time.monotonic() < deadline
        time.sleep(0.01)

    tracker.close()

    assert all(process.finished for process in processes)
    for pid_file in pid_files:
        pid = int(pid_file.read_text(encoding="utf-8"))
        assert not Path(f"/proc/{pid}").exists()
    with pytest.raises(RuntimeError, match="process tracker is closed"):
        tracker.start([sys.executable, "-c", "pass"])


def test_reused_recorded_pid_cannot_seed_or_receive_descendant_signals(
    process_starter, monkeypatch
) -> None:
    process = process_starter(
        [sys.executable, "-c", "import time; time.sleep(60)"], term_grace=0.1
    )
    process._monitor_stop.set()
    process._monitor.join(1)
    assert not process._monitor.is_alive()
    stale_pid = 900_001
    unrelated_child_pid = 900_002
    assert process._process_identity is not None
    snapshot = {
        process._process.pid: (
            os.getpid(),
            process._process_identity.start_time,
            "S",
        ),
        stale_pid: (1, 222, "S"),
        unrelated_child_pid: (stale_pid, 333, "S"),
    }
    process._descendants[stale_pid] = harness._ProcIdentity(stale_pid, 111)
    signaled = []

    with monkeypatch.context() as patch:
        patch.setattr(harness, "_proc_snapshot", lambda: snapshot)
        patch.setattr(harness.os, "kill", lambda pid, process_signal: signaled.append((pid, process_signal)))
        process._record_descendants()
        process._signal_descendants(signal.SIGTERM)

    assert stale_pid not in process._descendants
    assert unrelated_child_pid not in process._descendants
    assert signaled == []
    process.close()


def test_pidfd_signal_rejects_reused_identity_before_signaling(monkeypatch) -> None:
    identity = harness._ProcIdentity(4242, 111)
    calls = []

    with monkeypatch.context() as patch:
        patch.setattr(
            harness.os,
            "pidfd_open",
            lambda pid, flags: calls.append(("open", pid, flags)) or 91,
        )
        patch.setattr(
            harness,
            "_proc_details",
            lambda pid: calls.append(("stat", pid)) or (1, 222, "S"),
        )
        patch.setattr(
            harness.signal,
            "pidfd_send_signal",
            lambda *_args: pytest.fail("mismatched identity was signaled"),
        )
        patch.setattr(
            harness.os,
            "close",
            lambda descriptor: calls.append(("close", descriptor)),
        )
        patch.setattr(
            harness.os,
            "kill",
            lambda *_args: pytest.fail("numeric PID signaling was used"),
        )

        harness._signal_proc_identity(identity, signal.SIGTERM)

    assert calls == [("open", 4242, 0), ("stat", 4242), ("close", 91)]


def test_pidfd_signal_cannot_redirect_after_validated_process_exits(
    monkeypatch,
) -> None:
    identity = harness._ProcIdentity(4343, 333)
    calls = []

    def process_exited(pidfd, process_signal) -> None:
        calls.append(("pidfd-signal", pidfd, process_signal))
        raise ProcessLookupError

    with monkeypatch.context() as patch:
        patch.setattr(
            harness.os,
            "pidfd_open",
            lambda pid, flags: calls.append(("open", pid, flags)) or 92,
        )
        patch.setattr(
            harness,
            "_proc_details",
            lambda pid: calls.append(("stat", pid)) or (1, 333, "S"),
        )
        patch.setattr(harness.signal, "pidfd_send_signal", process_exited)
        patch.setattr(
            harness.os,
            "close",
            lambda descriptor: calls.append(("close", descriptor)),
        )
        patch.setattr(
            harness.os,
            "kill",
            lambda *_args: pytest.fail("numeric PID signaling was used"),
        )

        harness._signal_proc_identity(identity, signal.SIGKILL)

    assert calls == [
        ("open", 4343, 0),
        ("stat", 4343),
        ("pidfd-signal", 92, signal.SIGKILL),
        ("close", 92),
    ]


def test_capture_reader_failure_is_reported_after_cleanup(
    process_starter, monkeypatch
) -> None:
    process = process_starter([sys.executable, "-c", "pass"])
    read_fd, write_fd = os.pipe()
    stream = os.fdopen(read_fd, "rb", buffering=0)
    real_read = os.read

    def fail_capture(descriptor, size):
        if descriptor == read_fd:
            raise OSError(errno.EIO, "capture failed")
        return real_read(descriptor, size)

    with monkeypatch.context() as patch:
        patch.setattr(harness.os, "read", fail_capture)
        reader = threading.Thread(
            target=process._capture, args=(stream, bytearray(), False)
        )
        reader.start()
        reader.join(1)
        assert not reader.is_alive()
    os.close(write_fd)

    with pytest.raises(RuntimeError, match="process output capture failed") as error:
        process.wait()
    assert isinstance(error.value.__cause__, OSError)
    assert error.value.__cause__.errno == errno.EIO
    assert process.finished


def test_process_tracker_linearizes_start_against_close(monkeypatch) -> None:
    tracker = ProcessTracker()
    real_start_process = harness.start_process
    spawn_entered = threading.Event()
    allow_spawn = threading.Event()
    close_entered = threading.Event()
    close_returned = threading.Event()
    processes = []
    failures = []

    def delayed_start(*args, **kwargs):
        spawn_entered.set()
        assert allow_spawn.wait(2), "test did not release delayed process start"
        return real_start_process(*args, **kwargs)

    def start() -> None:
        try:
            processes.append(
                tracker.start(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    term_grace=0.1,
                )
            )
        except BaseException as error:
            failures.append(error)

    def close() -> None:
        close_entered.set()
        try:
            tracker.close()
        except BaseException as error:
            failures.append(error)
        finally:
            close_returned.set()

    monkeypatch.setattr(harness, "start_process", delayed_start)
    start_thread = threading.Thread(target=start)
    close_thread = threading.Thread(target=close)
    start_thread.start()
    assert spawn_entered.wait(2), "process start did not reach race barrier"
    close_thread.start()

    assert close_entered.wait(2), "tracker close did not reach race barrier"
    assert not close_returned.wait(0.1)
    allow_spawn.set()
    start_thread.join(2)
    close_thread.join(2)

    assert not start_thread.is_alive()
    assert not close_thread.is_alive()
    assert failures == []
    assert len(processes) == 1
    assert processes[0].finished


def test_managed_process_replays_timeout_to_all_waiters(process_starter) -> None:
    process = process_starter(
        [
            sys.executable,
            "-c",
            "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
        ],
        timeout=0.3,
        term_grace=0.1,
    )
    barrier = threading.Barrier(3)
    timeouts = []
    failures = []

    def wait() -> None:
        barrier.wait()
        try:
            process.wait()
        except ProcessTimeout as error:
            timeouts.append(error)
        except BaseException as error:
            failures.append(error)

    waiters = [threading.Thread(target=wait) for _ in range(2)]
    for waiter in waiters:
        waiter.start()
    barrier.wait()
    for waiter in waiters:
        waiter.join(2)

    assert all(not waiter.is_alive() for waiter in waiters)
    assert failures == []
    assert len(timeouts) == 2
    assert all(error.timeout == 0.3 for error in timeouts)
    assert all(error.result.status == 128 + signal.SIGKILL for error in timeouts)
    assert timeouts[0].result == timeouts[1].result
    with pytest.raises(ProcessTimeout) as later:
        process.wait(timeout=10)
    assert later.value.timeout == 0.3
    assert later.value.result == timeouts[0].result


def test_managed_process_supports_pause_observe_release(process_starter) -> None:
    command = (
        "import time; print('ready', flush=True); time.sleep(.4); "
        "print('released', flush=True)"
    )
    process = process_starter([sys.executable, "-c", command], timeout=3)
    deadline = time.monotonic() + 2
    while "ready\n" not in process.observe().stdout:
        assert time.monotonic() < deadline
        time.sleep(0.01)
    process.pause()
    paused = process.observe()
    time.sleep(0.6)

    assert process.observe() == paused
    process.release()
    result = process.wait()
    assert result.status == 0
    assert result.stdout == "ready\nreleased\n"


def test_managed_process_accepts_concurrent_writers_and_observers(process_starter) -> None:
    process = process_starter(
        [sys.executable, "-c", "import sys; print(len(sys.stdin.readlines()))"],
        timeout=3,
    )
    observations = []
    writers = [
        threading.Thread(target=process.write, args=(f"{index}\n",))
        for index in range(20)
    ]
    observer = threading.Thread(target=lambda: observations.append(process.observe()))
    for thread in [*writers, observer]:
        thread.start()
    for thread in [*writers, observer]:
        thread.join()
    process.send_eof()

    results = []
    waiters = [
        threading.Thread(target=lambda: results.append(process.wait()))
        for _ in range(2)
    ]
    for thread in waiters:
        thread.start()
    for thread in waiters:
        thread.join()

    assert len(observations) == 1
    assert len(results) == 2
    assert results[0] == results[1]
    assert results[0].stdout == "20\n"


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
