"""Point-in-time active CA passphrase and certificate-match verification."""

from __future__ import annotations

import ctypes
import locale
import os
import re
import stat
import sys
from collections.abc import Mapping
from contextlib import ExitStack

from .errors import ApplicationError
from .filesystem import (
    DirectoryPolicy,
    FilePolicy,
    FilesystemError,
    OpenedDirectory,
    OpenedFile,
    identity_from_stat,
)
from .operational import (
    acquire_operational_locks,
    prepare_control_state,
    require_generation_layout,
    require_no_unresolved_state,
    require_pki_directory,
    require_program,
    resolve_paths,
)
from .parser import ParseResult
from .paths import expand_home
from .subprocesses import ProcessResult, run_process


_ROOT_GENERATION = re.compile(r"g[1-9][0-9]*", re.ASCII)
_INTERMEDIATE_GENERATION = re.compile(r"g[1-9][0-9]*-i[1-9][0-9]*", re.ASCII)
_PROCESS_OPTIONS = {
    "timeout": 30.0,
    "term_grace": 1.0,
    "stdout_limit": 64 * 1024,
    "stderr_limit": 64 * 1024,
}
_MAX_ACTIVE_ISSUER_SIZE = 4096
_PRIVATE_DIRECTORY = DirectoryPolicy(owner=os.geteuid(), mode=0o700)
_KEY_POLICY = FilePolicy(owner=os.geteuid(), mode=0o600, links=1)
_CERTIFICATE_POLICY = FilePolicy(owner=os.geteuid(), mode=0o644, links=1)
_PASSPHRASE_POLICY = FilePolicy(owner=os.geteuid(), forbidden_bits=0o077, links=1)
_ACTIVE_ISSUER_POLICY = FilePolicy(
    owner=os.geteuid(), mode=0o600, links=1, max_size=_MAX_ACTIVE_ISSUER_SIZE
)
_ASCII_WHITESPACE = frozenset(b" \t\r\v\f")
_ISWSPACE = ctypes.CDLL(None).iswspace
_ISWSPACE.argtypes = (ctypes.c_uint32,)
_ISWSPACE.restype = ctypes.c_int


def _expand_passphrase_path(value: object, environment: Mapping[str, str]) -> str | None:
    if value is None:
        return None
    assert isinstance(value, str)
    home = environment.get("HOME")
    if home is None:
        raise ApplicationError("HOME is required")
    return expand_home(value, home=home)


def _open_private_directory(path: str, label: str) -> OpenedDirectory:
    try:
        metadata = os.lstat(path)
    except OSError:
        raise ApplicationError(f"{label} must be a non-symlink directory: {path}") from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ApplicationError(f"{label} must be a non-symlink directory: {path}")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ApplicationError(f"{label} must be current-user-owned with mode 700: {path}")
    try:
        return OpenedDirectory(path, policy=_PRIVATE_DIRECTORY)
    except FilesystemError:
        raise ApplicationError(f"{label} changed while opening: {path}") from None


def _open_active_issuer(path: str) -> tuple[OpenedFile, str, str]:
    try:
        metadata = os.lstat(path)
    except OSError:
        raise ApplicationError(
            f"Active issuer manifest must be a non-symlink regular file: {path}"
        ) from None
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ApplicationError(
            f"Active issuer manifest must be a non-symlink regular file: {path}"
        )
    if (
        metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise ApplicationError(
            "Active issuer manifest must be current-user-owned, singly linked, "
            f"and mode 600: {path}"
        )
    if metadata.st_size > _MAX_ACTIVE_ISSUER_SIZE:
        raise ApplicationError(f"Active issuer manifest is too large: {path}")
    try:
        opened = OpenedFile(path, policy=_ACTIVE_ISSUER_POLICY)
    except FilesystemError:
        raise ApplicationError("Active issuer manifest identity changed while opening") from None
    try:
        try:
            data = opened.read(opened.identity.size)
        except FilesystemError:
            raise ApplicationError("Active issuer manifest changed while reading") from None

        lines = data.split(b"\n")
        if lines and lines[-1] == b"":
            lines.pop()
        if (
            len(lines) != 2
            or not lines[0].startswith(b"root=")
            or not lines[1].startswith(b"intermediate=")
        ):
            raise ApplicationError(f"Active issuer manifest has invalid content: {path}")
        try:
            root = lines[0].removeprefix(b"root=").decode("ascii")
            intermediate = lines[1].removeprefix(b"intermediate=").decode("ascii")
        except UnicodeDecodeError:
            raise ApplicationError(f"Active issuer manifest has invalid content: {path}") from None
        if _ROOT_GENERATION.fullmatch(root) is None:
            raise ApplicationError(f"Invalid root generation ID: {root}")
        if _INTERMEDIATE_GENERATION.fullmatch(intermediate) is None:
            raise ApplicationError(f"Invalid intermediate generation ID: {intermediate}")
        if not intermediate.startswith(f"{root}-i"):
            raise ApplicationError("Active issuer manifest selects mismatched generations")
        return opened, root, intermediate
    except BaseException:
        opened.close()
        raise


def _validate_passphrase_first_line(opened: OpenedFile, path: str) -> None:
    offset = 0
    length = 0
    non_whitespace = False
    complete = False
    utf8_locale = locale.getencoding().lower().replace("-", "") == "utf8"
    pending = 0
    sequence_length = 0
    codepoint = 0
    minimum_codepoint = 0
    buffer = bytearray(64 * 1024)
    try:
        while not complete:
            count = os.preadv(opened.fileno(), (buffer,), offset)
            try:
                if count == 0:
                    break
                newline = buffer.find(10, 0, count)
                selected_count = count if newline < 0 else newline
                for index in range(selected_count):
                    value = buffer[index]
                    if value == 0:
                        continue
                    if not utf8_locale:
                        length += 1
                        if value not in _ASCII_WHITESPACE:
                            non_whitespace = True
                        continue
                    while True:
                        if pending:
                            if 0x80 <= value <= 0xBF:
                                codepoint = (codepoint << 6) | (value & 0x3F)
                                pending -= 1
                                sequence_length += 1
                                if pending == 0:
                                    if (
                                        codepoint < minimum_codepoint
                                        or 0xD800 <= codepoint <= 0xDFFF
                                        or codepoint > 0x10FFFF
                                    ):
                                        length += sequence_length
                                    else:
                                        length += 1
                                        if not _ISWSPACE(codepoint):
                                            non_whitespace = True
                                break
                            length += sequence_length
                            pending = 0
                            sequence_length = 0
                            codepoint = 0
                            minimum_codepoint = 0
                            continue
                        if value < 0x80:
                            length += 1
                            if not _ISWSPACE(value):
                                non_whitespace = True
                        elif 0xC2 <= value <= 0xDF:
                            pending = 1
                            sequence_length = 1
                            codepoint = value & 0x1F
                            minimum_codepoint = 0x80
                        elif 0xE0 <= value <= 0xEF:
                            pending = 2
                            sequence_length = 1
                            codepoint = value & 0x0F
                            minimum_codepoint = 0x800
                        elif 0xF0 <= value <= 0xF4:
                            pending = 3
                            sequence_length = 1
                            codepoint = value & 0x07
                            minimum_codepoint = 0x10000
                        else:
                            length += 1
                        break
                offset += count
                complete = newline >= 0
            finally:
                for index in range(count):
                    buffer[index] = 0
        if pending:
            length += sequence_length
        opened.recheck()
    except (OSError, FilesystemError):
        raise ApplicationError(f"Passphrase file changed during validation: {path}") from None
    finally:
        for index in range(len(buffer)):
            buffer[index] = 0
    if length == 0:
        raise ApplicationError(f"Passphrase file first line is empty: {path}")
    if not non_whitespace:
        raise ApplicationError(
            f"Passphrase file first line must contain non-whitespace characters: {path}"
        )
    if length < 16:
        raise ApplicationError(
            f"Passphrase file first line must be at least 16 characters: {path}"
        )


def _open_passphrase(path: str) -> OpenedFile:
    try:
        metadata = os.lstat(path)
    except OSError:
        raise ApplicationError(
            f"Passphrase file must be a non-symlink regular file: {path}"
        ) from None
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ApplicationError(f"Passphrase file must be a non-symlink regular file: {path}")
    if metadata.st_uid != os.geteuid() or metadata.st_nlink != 1:
        raise ApplicationError(
            f"Passphrase file must be current-user-owned and singly linked: {path}"
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ApplicationError(
            "Passphrase file permissions are too open; use chmod 600 or stricter: "
            f"{path}"
        )
    try:
        opened = OpenedFile(path, policy=_PASSPHRASE_POLICY)
    except FilesystemError:
        raise ApplicationError(f"Passphrase file identity changed while opening: {path}") from None
    try:
        _validate_passphrase_first_line(opened, path)
    except BaseException:
        opened.close()
        raise
    return opened


def _open_authority_file(path: str, *, key: bool) -> OpenedFile:
    label = "private key" if key else "certificate"
    policy = _KEY_POLICY if key else _CERTIFICATE_POLICY
    try:
        metadata = os.lstat(path)
        policy.validate(identity_from_stat(metadata))
    except (OSError, FilesystemError):
        raise ApplicationError(f"Active CA {label} is unsafe") from None
    try:
        return OpenedFile(path, policy=policy)
    except FilesystemError:
        raise ApplicationError(f"Active CA {label} identity changed while opening") from None


def _fresh_descriptor(source: OpenedFile, failure: str) -> int:
    descriptor = -1
    try:
        current = identity_from_stat(os.fstat(source.fileno()))
        if current != source.identity and not (
            current.links == 0
            and (current.dev, current.ino) == (source.identity.dev, source.identity.ino)
        ):
            raise OSError
        descriptor = os.open(f"/proc/self/fd/{source.fileno()}", os.O_RDONLY | os.O_CLOEXEC)
        if os.get_inheritable(descriptor):
            raise OSError
        reopened = identity_from_stat(os.fstat(descriptor))
        if reopened != current:
            raise OSError
        return descriptor
    except (OSError, FilesystemError):
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise ApplicationError(failure) from None


def _run_openssl(
    argv: tuple[str, ...],
    environment: Mapping[str, str],
    descriptors: tuple[int, ...],
) -> bytes:
    try:
        result = run_process(
            argv,
            env=environment,
            pass_fds=descriptors,
            **_PROCESS_OPTIONS,
        )
    except ApplicationError:
        raise ApplicationError("CA passphrase verification failed") from None
    assert isinstance(result, ProcessResult)
    if result.status:
        raise ApplicationError("CA passphrase verification failed")
    return result.stdout


def _verify_authority(
    stack: ExitStack,
    passphrase_path: str,
    key_path: str,
    certificate_path: str,
    environment: Mapping[str, str],
) -> tuple[OpenedFile, OpenedFile, OpenedFile]:
    passphrase = stack.enter_context(_open_passphrase(passphrase_path))
    key = stack.enter_context(_open_authority_file(key_path, key=True))
    certificate = stack.enter_context(
        _open_authority_file(certificate_path, key=False)
    )
    try:
        key_header = key.read_prefix(65).split(b"\n", 1)[0]
    except FilesystemError:
        raise ApplicationError("CA passphrase verification failed") from None
    if key_header != b"-----BEGIN ENCRYPTED " b"PRIVATE KEY-----":
        raise ApplicationError("CA passphrase verification failed")

    pass_fd = _fresh_descriptor(
        passphrase, "Cannot duplicate passphrase file descriptor for OpenSSL"
    )
    try:
        _run_openssl(
            (
                "openssl",
                "pkey",
                "-in",
                f"/proc/self/fd/{key.fileno()}",
                "-passin",
                f"fd:{pass_fd}",
                "-check",
                "-noout",
            ),
            environment,
            (pass_fd, key.fileno()),
        )
    finally:
        os.close(pass_fd)

    pass_fd = _fresh_descriptor(
        passphrase, "Cannot duplicate passphrase file descriptor for OpenSSL"
    )
    try:
        key_public = _run_openssl(
            (
                "openssl",
                "pkey",
                "-in",
                f"/proc/self/fd/{key.fileno()}",
                "-passin",
                f"fd:{pass_fd}",
                "-pubout",
            ),
            environment,
            (pass_fd, key.fileno()),
        )
    finally:
        os.close(pass_fd)

    certificate_public = _run_openssl(
        (
            "openssl",
            "x509",
            "-in",
            f"/proc/self/fd/{certificate.fileno()}",
            "-pubkey",
            "-noout",
        ),
        environment,
        (certificate.fileno(),),
    )
    if key_public != certificate_public:
        raise ApplicationError("CA passphrase verification failed")
    return passphrase, key, certificate


def verify_ca_passphrases(parsed: ParseResult) -> int:
    environment = dict(os.environ)
    paths = resolve_paths(parsed.values, environment)
    root_passphrase = _expand_passphrase_path(
        parsed.values.get("--root-pass-file"), environment
    )
    intermediate_passphrase = _expand_passphrase_path(
        parsed.values.get("--intermediate-pass-file"), environment
    )
    require_program("openssl", environment)
    require_program("cmp", environment)
    require_pki_directory(paths.pki_dir)
    prepare_control_state(paths.pki_dir)
    require_program("flock", environment)
    os.umask(0o077)

    output: list[str] = []
    with acquire_operational_locks(paths.pki_dir, "intermediate"):
        require_no_unresolved_state(paths.pki_dir)
        require_generation_layout(paths.pki_dir)
        active_path = f"{paths.pki_dir}/state/active-issuer"
        with ExitStack() as stack:
            active, root, intermediate = _open_active_issuer(active_path)
            stack.enter_context(active)
            root_directory = stack.enter_context(
                _open_private_directory(
                    f"{paths.pki_dir}/authorities/roots/{root}",
                    "Root authority generation",
                )
            )
            intermediate_directory = stack.enter_context(
                _open_private_directory(
                    f"{paths.pki_dir}/authorities/intermediates/{intermediate}",
                    "Intermediate authority generation",
                )
            )
            verified_inputs: list[OpenedFile] = []
            if root_passphrase is not None:
                verified_inputs.extend(
                    _verify_authority(
                        stack,
                        root_passphrase,
                        f"{paths.pki_dir}/authorities/roots/{root}/private/root-ca.key",
                        f"{paths.pki_dir}/authorities/roots/{root}/certs/root-ca.crt",
                        environment,
                    )
                )
                output.append("root=valid\n")
            if intermediate_passphrase is not None:
                verified_inputs.extend(
                    _verify_authority(
                        stack,
                        intermediate_passphrase,
                        f"{paths.pki_dir}/authorities/intermediates/{intermediate}/private/intermediate-ca.key",
                        f"{paths.pki_dir}/authorities/intermediates/{intermediate}/certs/intermediate-ca.crt",
                        environment,
                    )
                )
                output.append("intermediate=valid\n")
            try:
                active.recheck()
                root_directory.recheck()
                intermediate_directory.recheck()
                for opened in verified_inputs:
                    opened.recheck()
            except FilesystemError:
                raise ApplicationError("CA verification input changed during verification") from None
            sys.stdout.write("".join(output))
            sys.stdout.flush()

    return 0
