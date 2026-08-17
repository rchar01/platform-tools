"""Supervised OpenSSH key operations with inherited-terminal passphrase input."""

from __future__ import annotations

import os
import shutil
import signal
import stat
import sys
import termios
import tempfile
from collections.abc import Mapping, Sequence

from .errors import ApplicationError
from .subprocesses import ProcessResult, run_process


_INTERNAL_ASKPASS = "PLATFORM_PKI_INTERNAL_SSH_ASKPASS"


def _process_parent(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/stat", "rb") as stat_file:
            data = stat_file.read(4096)
        fields = data.rsplit(b") ", 1)[1].split()
        return int(fields[1])
    except (IndexError, OSError, ValueError):
        return None


def askpass() -> int:
    """Forward one supervisor-provided OpenSSH passphrase."""

    descriptor = -1
    parent = 0
    value = bytearray()
    try:
        fifo = os.environ.get("PLATFORM_PKI_ASKPASS_FIFO", "")
        parent = int(os.environ.get("PLATFORM_PKI_ASKPASS_PARENT", "0"))
        ssh_keygen_parent = os.getppid()
        if (
            not fifo
            or not os.path.isabs(fifo)
            or parent <= 1
            or _process_parent(ssh_keygen_parent) != parent
        ):
            return 1
        descriptor = os.open(
            fifo,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        current = os.fstat(descriptor)
        path_current = os.stat(fifo, follow_symlinks=False)
        directory = os.stat(os.path.dirname(fifo), follow_symlinks=False)
        if (
            not stat.S_ISFIFO(current.st_mode)
            or not stat.S_ISFIFO(path_current.st_mode)
            or (current.st_dev, current.st_ino)
            != (path_current.st_dev, path_current.st_ino)
            or current.st_uid != os.geteuid()
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_nlink != 1
            or not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != os.geteuid()
            or stat.S_IMODE(directory.st_mode) != 0o700
        ):
            return 1
        os.kill(parent, signal.SIGUSR1)
        while len(value) <= 4096:
            byte = os.read(descriptor, 1)
            if not byte or byte in (b"\n", b"\r"):
                break
            value.extend(byte)
        if len(value) > 4096:
            return 1
        os.write(1, value + b"\n")
        return 0
    except (OSError, ValueError):
        return 1
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        for index in range(len(value)):
            value[index] = 0


def _executable() -> tuple[str, tuple[int, int, int, int, int]]:
    candidate = sys.argv[0]
    if os.path.sep not in candidate:
        resolved = shutil.which(candidate)
        if resolved is None:
            raise ApplicationError("OpenSSH passphrase prompt could not be prepared")
        candidate = resolved
    path = os.path.realpath(os.path.abspath(candidate))
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError:
        raise ApplicationError("OpenSSH passphrase prompt could not be prepared") from None
    if not stat.S_ISREG(current.st_mode) or not current.st_mode & 0o111:
        raise ApplicationError("OpenSSH passphrase prompt could not be prepared")
    return path, (
        current.st_dev,
        current.st_ino,
        current.st_size,
        current.st_mtime_ns,
        current.st_ctime_ns,
    )


def run_ssh_keygen(
    argv: Sequence[str],
    environment: Mapping[str, str],
    *,
    input: bytes | None = None,
    pass_fds: Sequence[int] = (),
) -> ProcessResult:
    """Run ssh-keygen with bounded cleanup and optional terminal askpass input."""

    terminal = fifo_descriptor = -1
    helper_path = ""
    helper_identity: tuple[int, int, int, int, int] | None = None
    fifo_directory = fifo_path = ""
    fifo_identity: tuple[int, int] | None = None
    effective_environment = dict(environment)
    for name in (
        "DISPLAY",
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "PLATFORM_PKI_ASKPASS_FD",
        "PLATFORM_PKI_ASKPASS_PROMPT_FD",
        "PLATFORM_PKI_ASKPASS_PROMPT_PATH",
        "PLATFORM_PKI_ASKPASS_TTY",
        "PLATFORM_PKI_ASKPASS_FIFO",
        "PLATFORM_PKI_ASKPASS_PARENT",
        _INTERNAL_ASKPASS,
    ):
        effective_environment.pop(name, None)
    descriptors = list(pass_fds)
    try:
        try:
            terminal = os.open("/dev/tty", os.O_RDWR | os.O_CLOEXEC | os.O_NOCTTY)
        except OSError:
            terminal = -1
        if terminal >= 0 and input is None:
            helper_path, helper_identity = _executable()
            try:
                fifo_directory = tempfile.mkdtemp(prefix=".platform-pki-askpass.")
                os.chmod(fifo_directory, 0o700)
                fifo_path = os.path.join(fifo_directory, "passphrase")
                os.mkfifo(fifo_path, 0o600)
                current_fifo = os.stat(fifo_path, follow_symlinks=False)
                fifo_identity = (current_fifo.st_dev, current_fifo.st_ino)
                fifo_descriptor = os.open(
                    fifo_path,
                    os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
            except OSError:
                raise ApplicationError("OpenSSH passphrase prompt could not be prepared")
            effective_environment.update(
                {
                    "DISPLAY": "platform-pki",
                    "SSH_ASKPASS": helper_path,
                    "SSH_ASKPASS_REQUIRE": "force",
                    "PLATFORM_PKI_ASKPASS_FIFO": fifo_path,
                    "PLATFORM_PKI_ASKPASS_PARENT": str(os.getpid()),
                    _INTERNAL_ASKPASS: "1",
                }
            )
        previous_prompt = signal.getsignal(signal.SIGUSR1)

        def prompt(*_: object) -> None:
            value = bytearray()
            attributes = termios.tcgetattr(terminal)
            hidden = attributes.copy()
            hidden[3] &= ~termios.ECHO
            try:
                os.write(2, b"OpenSSH key passphrase: ")
                termios.tcsetattr(terminal, termios.TCSANOW, hidden)
                while len(value) <= 4096:
                    byte = os.read(terminal, 1)
                    if not byte or byte in (b"\n", b"\r"):
                        break
                    value.extend(byte)
                if len(value) > 4096:
                    value.clear()
                os.write(fifo_descriptor, value + b"\n")
            finally:
                termios.tcsetattr(terminal, termios.TCSANOW, attributes)
                os.write(2, b"\n")
                for index in range(len(value)):
                    value[index] = 0

        try:
            signal.signal(signal.SIGUSR1, prompt)
            result = run_process(
                tuple(argv),
                env=effective_environment,
                timeout=30.0,
                term_grace=1.0,
                stdout_limit=1024 * 1024,
                stderr_limit=1024 * 1024,
                input=input,
                pass_fds=tuple(descriptors),
            )
        finally:
            signal.signal(signal.SIGUSR1, previous_prompt)
        if helper_identity is not None and _executable() != (
            helper_path,
            helper_identity,
        ):
            raise ApplicationError("OpenSSH passphrase prompt executable changed")
        assert isinstance(result, ProcessResult)
        return result
    finally:
        for descriptor in (fifo_descriptor, terminal):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        cleanup_failed = False
        if fifo_path:
            try:
                current_fifo = os.stat(fifo_path, follow_symlinks=False)
                if (
                    fifo_identity is None
                    or not stat.S_ISFIFO(current_fifo.st_mode)
                    or (current_fifo.st_dev, current_fifo.st_ino) != fifo_identity
                ):
                    cleanup_failed = True
                else:
                    os.unlink(fifo_path)
            except OSError:
                cleanup_failed = True
        if fifo_directory:
            try:
                os.rmdir(fifo_directory)
            except OSError:
                cleanup_failed = True
        if cleanup_failed:
            raise ApplicationError("OpenSSH passphrase prompt cleanup could not be verified")
