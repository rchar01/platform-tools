from __future__ import annotations

import errno
import os
import pty
import signal
import subprocess
import sys
import termios
import threading
import time
import tty
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

PtyMode = Literal["canonical", "raw"]

_CHILD_EXEC = """\
import fcntl
import os
import sys
import termios

claim_tty = sys.argv[1] == "1"
count = int(sys.argv[2])
pairs = [tuple(map(int, value.split(":", 1))) for value in sys.argv[3:3 + count]]
target_argv = sys.argv[3 + count:]
if claim_tty:
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
targets = {target for _source, target in pairs}
for source, target in pairs:
    if source == target:
        os.set_inheritable(target, True)
    else:
        os.dup2(source, target, inheritable=True)
for source, target in pairs:
    if source != target and source not in targets:
        os.close(source)
os.execvpe(target_argv[0], target_argv, os.environ)
"""


@dataclass(frozen=True)
class ProcessResult:
    args: tuple[str, ...]
    status: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class ProcessObservation:
    status: int | None
    stdout: str
    stderr: str


class ProcessTimeout(TimeoutError):
    def __init__(self, timeout: float, result: ProcessResult) -> None:
        # Arguments and captured streams can contain secrets. Keep diagnostics generic.
        super().__init__(f"process timed out after {timeout:g}s")
        self.timeout = timeout
        self.result = result


@dataclass(frozen=True)
class _ProcIdentity:
    pid: int
    start_time: int


def _require_linux_process_support() -> None:
    if not Path("/proc/self/stat").is_file() or not hasattr(os, "pidfd_open"):
        raise RuntimeError("Linux procfs and pidfd support are required")
    if not hasattr(signal, "pidfd_send_signal"):
        raise RuntimeError("Linux procfs and pidfd support are required")


def _proc_details(pid: int) -> tuple[int, int, str] | None:
    try:
        stat_fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return int(stat_fields[1]), int(stat_fields[19]), stat_fields[0]
    except (FileNotFoundError, IndexError, OSError, ValueError):
        return None


def _proc_snapshot() -> dict[int, tuple[int, int, str]]:
    snapshot = {}
    try:
        entries = os.scandir("/proc")
    except OSError:
        return snapshot
    with entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            details = _proc_details(pid)
            if details is not None:
                snapshot[pid] = details
    return snapshot


def _signal_proc_identity(
    identity: _ProcIdentity, process_signal: signal.Signals
) -> None:
    try:
        pidfd = os.pidfd_open(identity.pid, 0)
    except ProcessLookupError:
        return
    try:
        details = _proc_details(identity.pid)
        if details is None or details[1] != identity.start_time or details[2] == "Z":
            return
        try:
            signal.pidfd_send_signal(pidfd, process_signal)
        except ProcessLookupError:
            pass
    finally:
        os.close(pidfd)


def _fd_target(descriptor: int) -> str | None:
    try:
        return os.readlink(f"/proc/self/fd/{descriptor}")
    except OSError:
        return None


def _validate_fd_mappings(
    fd_mappings: Sequence[tuple[int, int]], pass_fds: tuple[int, ...]
) -> tuple[tuple[int, int], ...]:
    mappings = tuple(fd_mappings)
    sources = []
    targets = []
    for mapping in mappings:
        if not isinstance(mapping, tuple) or len(mapping) != 2:
            raise ValueError("fd_mappings must contain (source_fd, child_fd) tuples")
        source, target = mapping
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in mapping
        ):
            raise ValueError("fd_mappings must contain nonnegative integers")
        if target < 3:
            raise ValueError("fd_mappings child descriptors must be at least 3")
        try:
            os.fstat(source)
        except OSError as error:
            raise ValueError("fd_mappings source descriptor is not open") from error
        sources.append(source)
        targets.append(target)
    if len(targets) != len(set(targets)):
        raise ValueError("fd_mappings child descriptors must be unique")
    for source, target in mappings:
        if source != target and target in sources:
            raise ValueError("fd_mappings sources and child descriptors conflict")
    if set(pass_fds) & (set(sources) | set(targets)):
        raise ValueError("pass_fds and fd_mappings must not overlap")
    return mappings


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


def _validate_chunks(
    input: str | bytes | None,
    input_chunks: list[str | bytes] | tuple[str | bytes, ...] | None,
    encoding: str,
    errors: str,
) -> tuple[bytes, ...]:
    if input is not None and input_chunks is not None:
        raise ValueError("input and input_chunks are mutually exclusive")
    if input_chunks is not None and type(input_chunks) not in (list, tuple):
        raise TypeError("input_chunks must be a concrete list or tuple")
    values = () if input is None else (input,)
    if input_chunks is not None:
        values = tuple(input_chunks)

    chunks = []
    for value in values:
        if isinstance(value, str):
            chunks.append(value.encode(encoding, errors))
        elif isinstance(value, bytes):
            chunks.append(value)
        else:
            raise TypeError("process input must be str or bytes")
    return tuple(chunks)


class ManagedProcess:
    def __init__(
        self,
        args: Sequence[str | os.PathLike[str]],
        *,
        cwd: str | os.PathLike[str] | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float = 30,
        term_grace: float = 1,
        pty_mode: PtyMode | None = None,
        controlling_terminal: bool = False,
        pass_fds: Sequence[int] = (),
        fd_mappings: Sequence[tuple[int, int]] = (),
        encoding: str = "utf-8",
        errors: str = "strict",
    ) -> None:
        _require_linux_process_support()
        self.args = tuple(os.fspath(arg) for arg in args)
        if not self.args:
            raise ValueError("args must not be empty")
        if timeout <= 0 or term_grace < 0:
            raise ValueError("timeout must be positive and term_grace nonnegative")
        if pty_mode not in (None, "canonical", "raw"):
            raise ValueError("pty_mode must be 'canonical', 'raw', or None")
        if controlling_terminal and pty_mode is None:
            raise ValueError("controlling_terminal requires pty_mode")
        if controlling_terminal and not hasattr(termios, "TIOCSCTTY"):
            raise RuntimeError("controlling terminals are unsupported on this platform")
        inherited_fds = tuple(pass_fds)
        if any(
            not isinstance(fd, int) or isinstance(fd, bool) or fd < 0
            for fd in inherited_fds
        ):
            raise ValueError("pass_fds must contain nonnegative integers")
        mappings = _validate_fd_mappings(fd_mappings, inherited_fds)
        "".encode(encoding, errors)

        self.timeout = timeout
        self.term_grace = term_grace
        self.pty_mode = pty_mode
        self.controlling_terminal = controlling_terminal
        self.encoding = encoding
        self.errors = errors
        self._stdin_closed = False
        self._write_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._output_lock = threading.Lock()
        self._result: ProcessResult | None = None
        self._timeout_outcome: tuple[float, ProcessResult] | None = None
        self._finished = False
        self._failure: BaseException | None = None
        self._stdout = bytearray()
        self._stderr = bytearray()
        self._master_fd: int | None = None
        self._eof = b"\x04"
        self._capture_targets: set[str] = set()
        self._descendant_lock = threading.Lock()
        self._descendants: dict[int, _ProcIdentity] = {}
        self._monitor_stop = threading.Event()
        self._capture_stop = threading.Event()
        self._reader_error_lock = threading.Lock()
        self._reader_errors: list[BaseException] = []

        master_fd = slave_fd = None
        slave_target = None
        try:
            if pty_mode is not None:
                master_fd, slave_fd = pty.openpty()
                slave_target = _fd_target(slave_fd)
                attributes = termios.tcgetattr(slave_fd)
                if pty_mode == "canonical":
                    attributes[3] |= termios.ICANON
                    attributes[3] &= ~(
                        termios.ECHO
                        | termios.ECHOE
                        | termios.ECHOK
                        | termios.ECHONL
                    )
                    termios.tcsetattr(slave_fd, termios.TCSANOW, attributes)
                    eof = attributes[6][termios.VEOF]
                    self._eof = bytes((eof,)) if isinstance(eof, int) else eof
                else:
                    tty.setraw(slave_fd, termios.TCSANOW)
                stdin = stdout = slave_fd
            else:
                stdin = stdout = subprocess.PIPE
            child_args = self.args
            if controlling_terminal or mappings:
                child_args = (
                    sys.executable,
                    "-I",
                    "-c",
                    _CHILD_EXEC,
                    "1" if controlling_terminal else "0",
                    str(len(mappings)),
                    *(f"{source}:{target}" for source, target in mappings),
                    *self.args,
                )
            child_pass_fds = tuple(
                sorted({*inherited_fds, *(source for source, _target in mappings)})
            )
            self._process = subprocess.Popen(
                child_args,
                cwd=cwd,
                env=env,
                shell=False,
                start_new_session=True,
                stdin=stdin,
                stdout=stdout,
                stderr=subprocess.PIPE,
                text=False,
                close_fds=True,
                pass_fds=child_pass_fds,
            )
            process_details = _proc_snapshot().get(self._process.pid)
            self._process_identity = (
                _ProcIdentity(self._process.pid, process_details[1])
                if process_details is not None
                else None
            )
            self._master_fd = master_fd
            if pty_mode is not None and slave_target is not None:
                self._capture_targets.add(slave_target)
            else:
                assert self._process.stdout is not None
                stdout_target = _fd_target(self._process.stdout.fileno())
                if stdout_target is not None:
                    self._capture_targets.add(stdout_target)
            assert self._process.stderr is not None
            stderr_target = _fd_target(self._process.stderr.fileno())
            if stderr_target is not None:
                self._capture_targets.add(stderr_target)
        except BaseException:
            if master_fd is not None:
                os.close(master_fd)
            raise
        finally:
            if slave_fd is not None:
                os.close(slave_fd)

        stdout_stream = self._master_fd if pty_mode is not None else self._process.stdout
        self._readers = [
            threading.Thread(
                target=self._capture,
                args=(stdout_stream, self._stdout, pty_mode is not None),
                daemon=True,
                name="managed-process-stdout",
            ),
            threading.Thread(
                target=self._capture,
                args=(self._process.stderr, self._stderr, False),
                daemon=True,
                name="managed-process-stderr",
            ),
        ]
        for reader in self._readers:
            reader.start()
        self._monitor = threading.Thread(
            target=self._monitor_descendants,
            daemon=True,
            name="managed-process-descendants",
        )
        self._monitor.start()

    def _record_descendants(self) -> None:
        snapshot = _proc_snapshot()
        with self._descendant_lock:
            valid_recorded = {
                pid: identity
                for pid, identity in self._descendants.items()
                if (details := snapshot.get(pid)) is not None
                and details[1] == identity.start_time
                and details[2] != "Z"
            }
            self._descendants = valid_recorded
            process_details = snapshot.get(self._process.pid)
            process_identity_matches = (
                self._process_identity is not None
                and process_details is not None
                and process_details[1] == self._process_identity.start_time
            )
            seeds = set(valid_recorded)
            if process_identity_matches:
                seeds.add(self._process.pid)
        changed = True
        while changed:
            changed = False
            for pid, (parent_pid, _start_time, _state) in snapshot.items():
                if pid not in seeds and parent_pid in seeds:
                    seeds.add(pid)
                    changed = True

        candidates = seeds - {self._process.pid, os.getpid()}
        if self._capture_targets:
            for pid in snapshot:
                if pid in (self._process.pid, os.getpid()):
                    continue
                try:
                    descriptors = os.scandir(f"/proc/{pid}/fd")
                except OSError:
                    continue
                with descriptors:
                    for descriptor in descriptors:
                        try:
                            target = os.readlink(descriptor.path)
                        except OSError:
                            continue
                        if target in self._capture_targets:
                            candidates.add(pid)
                            break

        with self._descendant_lock:
            for pid in candidates:
                details = snapshot.get(pid)
                if details is not None:
                    self._descendants[pid] = _ProcIdentity(pid, details[1])

    def _monitor_descendants(self) -> None:
        while not self._monitor_stop.is_set():
            self._record_descendants()
            self._monitor_stop.wait(0.01)

    def _live_descendants(self) -> tuple[_ProcIdentity, ...]:
        self._record_descendants()
        snapshot = _proc_snapshot()
        with self._descendant_lock:
            recorded = tuple(self._descendants.values())
        return tuple(
            identity
            for identity in recorded
            if (details := snapshot.get(identity.pid)) is not None
            and details[1] == identity.start_time
            and details[2] != "Z"
        )

    def _signal_descendants(self, process_signal: signal.Signals) -> None:
        for identity in self._live_descendants():
            _signal_proc_identity(identity, process_signal)

    def _capture(self, stream, destination: bytearray, is_pty: bool) -> None:
        descriptor = stream if isinstance(stream, int) else stream.fileno()
        try:
            while True:
                try:
                    chunk = os.read(descriptor, 65536)
                except OSError as error:
                    if is_pty and error.errno == errno.EIO:
                        break
                    if self._capture_stop.is_set() and error.errno == errno.EBADF:
                        break
                    raise
                if not chunk:
                    break
                with self._output_lock:
                    destination.extend(chunk)
        except BaseException as error:
            with self._reader_error_lock:
                self._reader_errors.append(error)
        finally:
            if not isinstance(stream, int):
                stream.close()

    def _decode(self, value: bytearray) -> str:
        return bytes(value).decode(self.encoding, self.errors)

    def write(self, data: str | bytes) -> None:
        chunks = _validate_chunks(data, None, self.encoding, self.errors)
        payload = chunks[0]
        with self._write_lock:
            if self._stdin_closed:
                raise ValueError("process stdin is closed")
            if self.pty_mode is not None:
                assert self._master_fd is not None
                descriptor = self._master_fd
            else:
                assert self._process.stdin is not None
                descriptor = self._process.stdin.fileno()
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]

    def send_eof(self) -> None:
        with self._write_lock:
            if self._stdin_closed:
                return
            if self.pty_mode == "raw":
                raise RuntimeError("raw PTY mode has no synthetic EOF")
            if self.pty_mode == "canonical":
                assert self._master_fd is not None
                # One VEOF delivers an unterminated line; the second ends the next read.
                os.write(self._master_fd, self._eof * 2)
            else:
                assert self._process.stdin is not None
                self._process.stdin.close()
            self._stdin_closed = True

    def _close_stdin(self) -> None:
        with self._write_lock:
            if self._stdin_closed:
                return
            if self.pty_mode is None:
                assert self._process.stdin is not None
                self._process.stdin.close()
            self._stdin_closed = True

    def pause(self) -> None:
        os.killpg(self._process.pid, signal.SIGSTOP)

    def release(self) -> None:
        os.killpg(self._process.pid, signal.SIGCONT)

    def observe(self) -> ProcessObservation:
        returncode = self._process.poll()
        with self._output_lock:
            stdout = self._decode(self._stdout)
            stderr = self._decode(self._stderr)
        return ProcessObservation(
            None if returncode is None else shell_status(returncode), stdout, stderr
        )

    def _signal_group(self, process_signal: signal.Signals) -> None:
        try:
            os.killpg(self._process.pid, process_signal)
        except ProcessLookupError:
            pass

    def _supervise(self, timeout: float, *, timeout_is_error: bool) -> ProcessResult:
        timed_out = False
        reap_failure = None
        try:
            self._process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._record_descendants()
            self._signal_descendants(signal.SIGTERM)
            self._signal_group(signal.SIGTERM)
        else:
            self._record_descendants()
            self._signal_descendants(signal.SIGTERM)

        deadline = time.monotonic() + self.term_grace
        if self._process.poll() is None:
            try:
                self._process.wait(timeout=self.term_grace)
            except subprocess.TimeoutExpired:
                pass
        while self._live_descendants() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not _wait_for_process_group(self._process.pid, deadline):
            self._signal_group(signal.SIGKILL)
        self._signal_descendants(signal.SIGKILL)
        if self._process.poll() is None:
            try:
                self._process.wait(timeout=max(self.term_grace, 0.1))
            except subprocess.TimeoutExpired:
                reap_failure = RuntimeError("process did not exit after SIGKILL")

        self._close_stdin()
        self._monitor_stop.set()
        self._monitor.join(timeout=max(self.term_grace, 0.1))
        reader_deadline = time.monotonic() + max(self.term_grace, 0.5)
        for reader in self._readers:
            reader.join(timeout=max(0, reader_deadline - time.monotonic()))
        self._capture_stop.set()
        if self._master_fd is not None:
            os.close(self._master_fd)
            self._master_fd = None
        for stream in (self._process.stdout, self._process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
        for reader in self._readers:
            if reader.is_alive():
                reader.join(timeout=0.1)
        self._finished = True
        if self._monitor.is_alive() or any(reader.is_alive() for reader in self._readers):
            self._failure = RuntimeError("process cleanup did not finish within its deadline")
            raise self._failure
        with self._reader_error_lock:
            reader_error = self._reader_errors[0] if self._reader_errors else None
        if reader_error is not None:
            self._failure = RuntimeError("process output capture failed")
            raise self._failure from reader_error
        if reap_failure is not None:
            self._failure = reap_failure
            raise reap_failure
        try:
            observation = self.observe()
            assert observation.status is not None
            result = ProcessResult(
                self.args, observation.status, observation.stdout, observation.stderr
            )
        except BaseException as error:
            self._failure = error
            raise
        self._result = result
        if timed_out and timeout_is_error:
            self._timeout_outcome = (timeout, result)
            raise ProcessTimeout(timeout, result)
        return result

    def wait(self, timeout: float | None = None) -> ProcessResult:
        effective_timeout = self.timeout if timeout is None else timeout
        if effective_timeout <= 0:
            raise ValueError("timeout must be positive")
        with self._state_lock:
            if self._timeout_outcome is not None:
                timeout, result = self._timeout_outcome
                raise ProcessTimeout(timeout, result)
            if self._result is not None:
                return self._result
            if self._failure is not None:
                raise self._failure
            return self._supervise(effective_timeout, timeout_is_error=True)

    def close(self) -> ProcessResult | None:
        with self._state_lock:
            if self._finished:
                return self._result
            return self._supervise(0, timeout_is_error=False)

    @property
    def finished(self) -> bool:
        return self._finished

    def __enter__(self) -> ManagedProcess:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()


def start_process(
    args: Sequence[str | os.PathLike[str]],
    *,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float = 30,
    term_grace: float = 1,
    pty_mode: PtyMode | None = None,
    controlling_terminal: bool = False,
    pass_fds: Sequence[int] = (),
    fd_mappings: Sequence[tuple[int, int]] = (),
    encoding: str = "utf-8",
    errors: str = "strict",
) -> ManagedProcess:
    return ManagedProcess(
        args,
        cwd=cwd,
        env=env,
        timeout=timeout,
        term_grace=term_grace,
        pty_mode=pty_mode,
        controlling_terminal=controlling_terminal,
        pass_fds=pass_fds,
        fd_mappings=fd_mappings,
        encoding=encoding,
        errors=errors,
    )


def run_process(
    args: Sequence[str | os.PathLike[str]],
    *,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float = 30,
    term_grace: float = 1,
    input: str | bytes | None = None,
    input_chunks: list[str | bytes] | tuple[str | bytes, ...] | None = None,
    pty_mode: PtyMode | None = None,
    controlling_terminal: bool = False,
    pass_fds: Sequence[int] = (),
    fd_mappings: Sequence[tuple[int, int]] = (),
    encoding: str = "utf-8",
    errors: str = "strict",
) -> ProcessResult:
    chunks = _validate_chunks(input, input_chunks, encoding, errors)
    process = start_process(
        args,
        cwd=cwd,
        env=env,
        timeout=timeout,
        term_grace=term_grace,
        pty_mode=pty_mode,
        controlling_terminal=controlling_terminal,
        pass_fds=pass_fds,
        fd_mappings=fd_mappings,
        encoding=encoding,
        errors=errors,
    )
    return _feed_and_wait(process, chunks)


def _feed_and_wait(
    process: ManagedProcess, chunks: tuple[bytes, ...]
) -> ProcessResult:
    feed_error: list[BaseException] = []

    def feed() -> None:
        try:
            for chunk in chunks:
                process.write(chunk)
        except BaseException as error:
            feed_error.append(error)
        if process.pty_mode != "raw":
            try:
                process.send_eof()
            except OSError as error:
                if not (
                    process.pty_mode == "canonical"
                    and error.errno in (errno.EBADF, errno.EIO)
                ):
                    feed_error.append(error)
            except BaseException as error:
                feed_error.append(error)

    feeder = threading.Thread(
        target=feed, daemon=True, name="managed-process-stdin"
    )
    feeder.start()
    try:
        result = process.wait()
    except BaseException:
        process.close()
        raise
    finally:
        feeder.join(timeout=max(process.term_grace, 0.5))
    if feeder.is_alive():
        raise RuntimeError("process input did not finish within its deadline")
    if feed_error:
        raise feed_error[0]
    return result


class ProcessTracker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._processes: list[ManagedProcess] = []
        self._closed = False

    def start(self, *args, **kwargs) -> ManagedProcess:
        with self._lock:
            if self._closed:
                raise RuntimeError("process tracker is closed")
            process = start_process(*args, **kwargs)
            self._processes.append(process)
        return process

    def run(self, *args, **kwargs) -> ProcessResult:
        chunks = _validate_chunks(
            kwargs.get("input"),
            kwargs.get("input_chunks"),
            kwargs.get("encoding", "utf-8"),
            kwargs.get("errors", "strict"),
        )
        run_kwargs = dict(kwargs)
        run_kwargs.pop("input", None)
        run_kwargs.pop("input_chunks", None)
        process = self.start(*args, **run_kwargs)
        return _feed_and_wait(process, chunks)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            processes = tuple(reversed(self._processes))
            self._processes.clear()
        failures = []
        for process in processes:
            try:
                process.close()
            except BaseException as error:
                failures.append(error)
        if failures:
            raise failures[0]


def copy_tree(source: Path, destination: Path, *, timeout: float = 30) -> None:
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    result = run_process(
        ("cp", "-a", "--", os.fspath(source), os.fspath(destination)),
        timeout=timeout,
    )
    if result.status != 0:
        raise subprocess.CalledProcessError(
            result.status,
            result.args,
            output=result.stdout,
            stderr=result.stderr,
        )
