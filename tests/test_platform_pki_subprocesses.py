from __future__ import annotations

import os
import shutil
import signal
import sys
import time
from pathlib import Path

import pytest

from src.platform_pki.errors import ApplicationError, render_error, shell_status
from src.platform_pki.subprocesses import (
    ProcessExecutionError,
    ProcessOutputOverflowError,
    ProcessResult,
    ProcessSpawnError,
    ProcessTimeoutError,
    run_process,
)


PYTHON = sys.executable
LIMIT = 4096


def _run(*arguments: str, **overrides: object) -> ProcessResult | None:
    options: dict[str, object] = {
        "env": {},
        "timeout": 3,
        "term_grace": 0.2,
        "stdout_limit": LIMIT,
        "stderr_limit": LIMIT,
    }
    options.update(overrides)
    return run_process((PYTHON, "-c", *arguments), **options)  # type: ignore[arg-type]


def test_application_error_rendering_and_status_mapping() -> None:
    error = ApplicationError("Public diagnostic", status=42)
    assert str(error) == "Public diagnostic"
    assert render_error(error) == "[ERROR] Public diagnostic\n"
    assert error.status == 42
    assert shell_status(42) == 42
    assert shell_status(-signal.SIGTERM) == 128 + signal.SIGTERM
    for control in ("\0", "\x1b", "\x7f", "\u0085", "\u202e", "\u2028"):
        with pytest.raises(ValueError):
            ApplicationError(f"unsafe{control}message")


def test_exact_argv_does_not_interpret_shell_metacharacters() -> None:
    arguments = ("space value", "; echo injected", "$(id)", "*", "'quoted'")
    result = _run(
        "import os,sys; os.write(1, b'\\0'.join(os.fsencode(v) for v in sys.argv[1:]))",
        *arguments,
    )
    assert result == ProcessResult(0, b"\0".join(value.encode() for value in arguments), b"")


def test_environment_is_exactly_the_explicit_mapping() -> None:
    env_command = shutil.which("env")
    assert env_command is not None
    result = run_process(
        (env_command, "-0"),
        env={"ONLY": "present"},
        timeout=3,
        term_grace=0.2,
        stdout_limit=LIMIT,
        stderr_limit=LIMIT,
    )
    assert result == ProcessResult(0, b"ONLY=present\0", b"")


@pytest.mark.parametrize(("descriptor", "stream"), ((1, "stdout"), (2, "stderr")))
def test_stream_limit_accepts_exact_boundary(descriptor: int, stream: str) -> None:
    result = _run(
        f"import os; os.write({descriptor}, b'x' * 32)",
        stdout_limit=32,
        stderr_limit=32,
    )
    assert isinstance(result, ProcessResult)
    assert getattr(result, stream) == b"x" * 32


def test_both_streams_are_continuously_drained() -> None:
    size = 256 * 1024
    result = _run(
        (
            "import os,threading; "
            f"threads=[threading.Thread(target=os.write, args=(fd, b'x' * {size})) "
            "for fd in (1, 2)]; "
            "[thread.start() for thread in threads]; "
            "[thread.join() for thread in threads]"
        ),
        stdout_limit=size,
        stderr_limit=size,
    )
    assert result == ProcessResult(0, b"x" * size, b"x" * size)


@pytest.mark.parametrize("descriptor", (1, 2))
def test_stream_overflow_terminates_with_generic_error(descriptor: int) -> None:
    secret = b"output-secret"
    with pytest.raises(ProcessOutputOverflowError) as caught:
        _run(
            f"import os; os.write({descriptor}, {secret!r} * 1000)",
            stdout_limit=8,
            stderr_limit=8,
        )
    assert "secret" not in str(caught.value)
    assert "secret" not in repr(caught.value)


def test_overflow_kills_a_term_ignoring_writer() -> None:
    started = time.monotonic()
    with pytest.raises(ProcessOutputOverflowError):
        _run(
            (
                "import os,signal; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "\nwhile True: os.write(1, b'x' * 65536)"
            ),
            stdout_limit=32,
            term_grace=0.1,
        )
    assert time.monotonic() - started < 2


def test_timeout_kills_term_ignoring_process() -> None:
    started = time.monotonic()
    with pytest.raises(ProcessTimeoutError):
        _run(
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
            timeout=0.15,
            term_grace=0.1,
        )
    assert time.monotonic() - started < 2


def test_post_spawn_setup_failure_is_cleaned_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_selector = __import__("selectors").DefaultSelector
    real_popen = __import__("subprocess").Popen
    spawned: list[tuple[int, str]] = []

    def recording_popen(*args: object, **kwargs: object):
        process = real_popen(*args, **kwargs)
        spawned.append((process.pid, _proc_start_time(process.pid)))
        return process

    class FailingSelector:
        def __init__(self) -> None:
            raise OSError("setup-secret")

    monkeypatch.setattr("src.platform_pki.subprocesses.selectors.DefaultSelector", FailingSelector)
    monkeypatch.setattr("src.platform_pki.subprocesses.subprocess.Popen", recording_popen)
    secret = "argv-secret"
    with pytest.raises(ProcessExecutionError) as caught:
        _run(
            "import time; time.sleep(60)",
            secret,
        )
    assert secret not in str(caught.value)
    assert "setup-secret" not in repr(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert len(spawned) == 1
    monkeypatch.setattr("src.platform_pki.subprocesses.selectors.DefaultSelector", real_selector)
    pid, start_time = spawned[0]
    assert not _same_process(pid, start_time)


def _proc_start_time(pid: int) -> str:
    return _proc_identity(pid)[0]


def _proc_identity(pid: int) -> tuple[str, str]:
    stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    fields = stat.rsplit(")", 1)[1].split()
    return fields[19], fields[0]


def _same_process(pid: int, start_time: str) -> bool:
    try:
        return _proc_start_time(pid) == start_time
    except FileNotFoundError:
        return False


@pytest.mark.skipif(not Path("/proc").is_dir(), reason="requires Linux procfs")
def test_successful_parent_cleans_background_child_holding_pipes(tmp_path: Path) -> None:
    identity_file = tmp_path / "child-identity"
    child_code = (
        "import signal,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "time.sleep(60)"
    )
    parent_code = (
        "import pathlib,subprocess,sys; "
        f"child=subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
        "stat=pathlib.Path(f'/proc/{child.pid}/stat').read_text(); "
        "start=stat.rsplit(')', 1)[1].split()[19]; "
        f"pathlib.Path({os.fspath(identity_file)!r}).write_text(f'{{child.pid}} {{start}}'); "
        "print('parent-complete')"
    )
    started = time.monotonic()
    result = _run(parent_code, timeout=2, term_grace=0.1)
    assert time.monotonic() - started < 1
    assert result == ProcessResult(0, b"parent-complete\n", b"")
    child_pid_text, start_time = identity_file.read_text(encoding="ascii").split()
    child_pid = int(child_pid_text)
    try:
        observed_start_time, state = _proc_identity(child_pid)
    except FileNotFoundError:
        pass
    else:
        assert observed_start_time != start_time or state == "Z"


@pytest.mark.skipif(not Path("/proc").is_dir(), reason="requires Linux procfs")
def test_timeout_cleans_term_ignoring_process_group_child(tmp_path: Path) -> None:
    pid_file = tmp_path / "child-pid"
    child_code = (
        "import signal,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "time.sleep(60)"
    )
    parent_code = (
        "import pathlib,signal,subprocess,sys,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"child=subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
        "stat=pathlib.Path(f'/proc/{child.pid}/stat').read_text(); "
        "start=stat.rsplit(')', 1)[1].split()[19]; "
        f"pathlib.Path({os.fspath(pid_file)!r}).write_text(f'{{child.pid}} {{start}}'); "
        "time.sleep(60)"
    )
    with pytest.raises(ProcessTimeoutError):
        _run(parent_code, timeout=0.3, term_grace=0.1)

    child_pid_text, child_start_time = pid_file.read_text(encoding="ascii").split()
    child_pid = int(child_pid_text)
    deadline = time.monotonic() + 1
    status = Path(f"/proc/{child_pid}/status")
    while time.monotonic() < deadline:
        if not _same_process(child_pid, child_start_time):
            break
        try:
            lines = status.read_text(encoding="ascii").splitlines()
        except FileNotFoundError:
            break
        state = next(line for line in lines if line.startswith("State:"))
        if "Z" in state:
            break
        time.sleep(0.01)
    if not _same_process(child_pid, child_start_time):
        return
    try:
        lines = status.read_text(encoding="ascii").splitlines()
    except FileNotFoundError:
        pass
    else:
        state = next(line for line in lines if line.startswith("State:"))
        assert "Z" in state


def test_pass_fds_are_explicit_and_other_inheritable_fds_are_closed() -> None:
    passed_read, passed_write = os.pipe()
    hidden_read, hidden_write = os.pipe()
    try:
        os.set_inheritable(hidden_read, True)
        os.write(passed_write, b"passed")
        os.close(passed_write)
        passed_write = -1
        os.write(hidden_write, b"hidden")
        result = _run(
            (
                "import os,sys; passed=int(sys.argv[1]); hidden=int(sys.argv[2]); "
                "data=os.read(passed, 64); "
                "\ntry: os.fstat(hidden)\nexcept OSError: data += b':closed'\n"
                "else: data += b':open'\n"
                "os.write(1, data)"
            ),
            str(passed_read),
            str(hidden_read),
            pass_fds=(passed_read,),
        )
        assert result == ProcessResult(0, b"passed:closed", b"")
    finally:
        for descriptor in (passed_read, passed_write, hidden_read, hidden_write):
            if descriptor >= 0:
                os.close(descriptor)


def test_direct_signal_and_command_statuses_are_preserved() -> None:
    failed = _run("import sys; sys.exit(37)")
    signaled = _run("import os,signal; os.kill(os.getpid(), signal.SIGTERM)")
    assert isinstance(failed, ProcessResult) and failed.status == 37
    assert isinstance(signaled, ProcessResult)
    assert signaled.status == 128 + signal.SIGTERM


def test_result_and_public_errors_do_not_disclose_secrets() -> None:
    secret = "argv-env-fd-output-secret"
    result = _run(
        "import os,sys; os.write(1, sys.argv[1].encode()); os.write(2, os.environ['SECRET'].encode())",
        secret,
        env={"SECRET": secret},
    )
    assert isinstance(result, ProcessResult)
    assert secret not in str(result)
    assert secret not in repr(result)

    with pytest.raises(ProcessSpawnError) as caught:
        run_process(
            (f"/missing/{secret}",),
            env={"SECRET": secret},
            timeout=1,
            term_grace=0.1,
            stdout_limit=1,
            stderr_limit=1,
            input=secret.encode(),
        )
    assert secret not in str(caught.value)
    assert secret not in repr(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_capture_is_bytes_and_preserves_invalid_utf8() -> None:
    result = _run("import os; os.write(1, b'\\xff\\xfe'); os.write(2, b'\\x80')")
    assert result == ProcessResult(0, b"\xff\xfe", b"\x80")


def test_bytes_input_and_optional_result() -> None:
    result = _run(
        "import os; data=os.read(0, 100); os.write(1, data)",
        input=b"\xffinput",
    )
    assert result == ProcessResult(0, b"\xffinput", b"")
    assert _run("pass", return_result=False) is None


@pytest.mark.parametrize(
    ("arguments", "keywords", "error"),
    (
        ("command string", {}, TypeError),
        ((), {}, ValueError),
        ((PYTHON,), {"env": None}, TypeError),
        ((PYTHON,), {"timeout": 0}, ValueError),
        ((PYTHON,), {"term_grace": 0}, ValueError),
        ((PYTHON,), {"stdout_limit": -1}, ValueError),
        ((PYTHON,), {"stderr_limit": -1}, ValueError),
        ((PYTHON,), {"pass_fds": (2,)}, ValueError),
        ((PYTHON,), {"input": "not bytes"}, TypeError),
        ((PYTHON,), {"return_result": 1}, TypeError),
    ),
)
def test_invalid_configuration_is_rejected(
    arguments: object,
    keywords: dict[str, object],
    error: type[Exception],
) -> None:
    options: dict[str, object] = {
        "env": {},
        "timeout": 1,
        "term_grace": 0.1,
        "stdout_limit": 1,
        "stderr_limit": 1,
    }
    options.update(keywords)
    with pytest.raises(error):
        run_process(arguments, **options)  # type: ignore[arg-type]


def test_closed_pass_fd_is_rejected_without_disclosing_its_number() -> None:
    descriptor = os.open(os.devnull, os.O_RDONLY)
    os.close(descriptor)
    with pytest.raises(ValueError) as caught:
        _run("pass", pass_fds=(descriptor,))
    assert str(descriptor) not in str(caught.value)
    assert str(descriptor) not in repr(caught.value)
