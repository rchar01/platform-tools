from __future__ import annotations

import atexit
import os
import shutil
import stat
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

import pytest

from ..harness import ProcessResult


@dataclass(frozen=True)
class CreateTools:
    init: Path
    root: Path
    intermediate: Path
    issue: Path
    recover: Path
    version: str
    common: Path


@dataclass(frozen=True)
class CreateWorkspace:
    root: Path
    namespace: Path
    pki: Path
    root_pass: Path
    intermediate_pass: Path


def tools() -> CreateTools:
    repository = Path(__file__).resolve().parents[3]
    binaries = repository / "bin"
    return CreateTools(
        init=binaries / "platform-pki-init",
        root=binaries / "platform-pki-root-create",
        intermediate=binaries / "platform-pki-intermediate-create",
        issue=binaries / "platform-pki-service-issue",
        recover=binaries / "platform-pki-ca-rollover",
        version=(repository / "VERSION").read_text().strip(),
        common=repository / "lib/platform-pki-common.sh",
    )


def environment(root: Path) -> dict[str, str]:
    home = root / "home"
    config = root / "config"
    temporary = root / "tmp"
    for directory in (home, config, temporary):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    return {
        "HOME": os.fspath(home),
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "TMPDIR": os.fspath(temporary),
        "XDG_CONFIG_HOME": os.fspath(config),
    }


def private_text(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        stream = os.fdopen(descriptor, "w", encoding="utf-8")
    except BaseException:
        os.close(descriptor)
        raise
    with stream:
        stream.write(content)


def executable(path: Path, content: str) -> Path:
    repository_temporary = Path(__file__).resolve().parents[3] / ".tmp"
    repository_temporary.mkdir(mode=0o700, exist_ok=True)
    directory = Path(
        tempfile.mkdtemp(prefix="pytest-pki-create-", dir=repository_temporary)
    )
    atexit.register(shutil.rmtree, directory, ignore_errors=True)
    actual = directory / path.name
    descriptor = os.open(actual, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    try:
        stream = os.fdopen(descriptor, "w", encoding="utf-8")
    except BaseException:
        os.close(descriptor)
        raise
    with stream:
        stream.write(content)
    return actual


def workspace(root: Path) -> CreateWorkspace:
    root.mkdir(mode=0o700, parents=True)
    root.chmod(0o700)
    value = CreateWorkspace(
        root=root,
        namespace=root / "namespace",
        pki=root / "namespace/pki",
        root_pass=root / "root.pass",
        intermediate_pass=root / "intermediate.pass",
    )
    private_text(value.root_pass, "pytest-root-passphrase-value\n")
    private_text(value.intermediate_pass, "pytest-intermediate-passphrase-value\n")
    return value


def run(
    process_runner: Callable[..., ProcessResult],
    command: Sequence[str | os.PathLike[str]],
    env: Mapping[str, str],
    *,
    timeout: float = 120,
    **kwargs: object,
) -> ProcessResult:
    result = process_runner(command, env=env, timeout=timeout, **kwargs)
    passphrase_files = []
    rendered = tuple(os.fspath(argument) for argument in command)
    for index, argument in enumerate(rendered):
        if (
            argument in ("--root-pass-file", "--intermediate-pass-file")
            and index + 1 < len(rendered)
        ):
            passphrase_files.append(Path(rendered[index + 1]))
        elif argument.startswith("file:"):
            passphrase_files.append(Path(argument.removeprefix("file:")))
    assert_passphrase_content_absent(result, passphrase_files)
    return result


def assert_passphrase_content_absent(
    result: ProcessResult, passphrase_files: Sequence[Path]
) -> None:
    for path in passphrase_files:
        if not path.is_file():
            continue
        secret = path.read_text().splitlines()[0]
        if secret and (secret in result.stdout or secret in result.stderr):
            pytest.fail("passphrase content appeared in process output", pytrace=False)


def require_success(result: ProcessResult, operation: str) -> None:
    if result.status != 0:
        pytest.fail(f"{operation} failed with status {result.status}")


def initialize(
    process_runner: Callable[..., ProcessResult],
    value: CreateWorkspace,
    env: Mapping[str, str],
    toolset: CreateTools,
    *,
    pki_dir: Path | None = None,
) -> None:
    command: list[str | Path] = [toolset.init, "--namespace", value.namespace]
    if pki_dir is not None:
        command.extend(("--pki-dir", pki_dir))
    require_success(run(process_runner, command, env), "PKI initialization")


def create_root(
    process_runner: Callable[..., ProcessResult],
    value: CreateWorkspace,
    env: Mapping[str, str],
    toolset: CreateTools,
    *,
    unencrypted: bool = False,
    days: int | None = None,
) -> ProcessResult:
    command: list[str | Path] = [
        toolset.root,
        "--namespace",
        value.namespace,
        "--name",
        "Pytest Root CA",
        "--org",
        "Platform Test",
        "--country",
        "PL",
    ]
    if unencrypted:
        command.append("--allow-unencrypted-root-key")
    else:
        command.extend(("--root-pass-file", value.root_pass))
    if days is not None:
        command.extend(("--days", str(days)))
    return run(process_runner, command, env)


def create_intermediate(
    process_runner: Callable[..., ProcessResult],
    value: CreateWorkspace,
    env: Mapping[str, str],
    toolset: CreateTools,
    *,
    unencrypted: bool = False,
    days: int | None = None,
) -> ProcessResult:
    command: list[str | Path] = [
        toolset.intermediate,
        "--namespace",
        value.namespace,
        "--name",
        "Pytest Intermediate CA",
        "--org",
        "Platform Test",
        "--country",
        "PL",
        "--root-pass-file",
        value.root_pass,
    ]
    if unencrypted:
        command.append("--allow-unencrypted-intermediate-key")
    else:
        command.extend(("--intermediate-pass-file", value.intermediate_pass))
    if days is not None:
        command.extend(("--days", str(days)))
    return run(process_runner, command, env)


def ready_ca(
    process_runner: Callable[..., ProcessResult],
    value: CreateWorkspace,
    env: Mapping[str, str],
    toolset: CreateTools,
    inventory: str | None = None,
) -> None:
    initialize(process_runner, value, env, toolset)
    if inventory is not None:
        private_text(value.pki / "inventory/services.yml", inventory)
    require_success(create_root(process_runner, value, env, toolset), "root creation")
    require_success(
        create_intermediate(process_runner, value, env, toolset),
        "intermediate creation",
    )


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def file_object_identity(path: Path) -> str:
    metadata = path.stat()
    return ":".join(
        (
            str(metadata.st_dev),
            str(metadata.st_ino),
            str(metadata.st_uid),
            f"{stat.S_IMODE(metadata.st_mode):o}",
            str(metadata.st_nlink),
            str(metadata.st_size),
            "regular file",
        )
    )


def filesystem_snapshot(path: Path) -> tuple[tuple[object, ...], ...]:
    paths = [path]
    if path.is_dir() and not path.is_symlink():
        paths.extend(sorted(path.rglob("*")))
    snapshot = []
    for current in paths:
        metadata = current.lstat()
        relative = "." if current == path else current.relative_to(path).as_posix()
        content: str | None = None
        if stat.S_ISREG(metadata.st_mode):
            content = sha256(current.read_bytes()).hexdigest()
        elif stat.S_ISLNK(metadata.st_mode):
            content = os.readlink(current)
        snapshot.append(
            (
                relative,
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_uid,
                metadata.st_gid,
                stat.S_IFMT(metadata.st_mode),
                stat.S_IMODE(metadata.st_mode),
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
                content,
            )
        )
    return tuple(snapshot)


def assert_filesystem_snapshot_unchanged(
    path: Path, expected: tuple[tuple[object, ...], ...], label: str
) -> None:
    if filesystem_snapshot(path) != expected:
        pytest.fail(f"{label} content or security metadata changed", pytrace=False)


def lstat_identity(path: Path) -> str:
    metadata = path.lstat()
    return ":".join(
        str(value)
        for value in (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
    )


def record(path: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in path.read_text().splitlines())


def names(path: Path) -> tuple[str, ...]:
    return tuple(sorted(item.name for item in path.iterdir()))


def openssl(
    process_runner: Callable[..., ProcessResult],
    arguments: Sequence[str | os.PathLike[str]],
    env: Mapping[str, str],
) -> ProcessResult:
    return run(process_runner, ["openssl", *arguments], env, timeout=30)


def command_path(name: str, env: Mapping[str, str]) -> str:
    value = shutil.which(name, path=env["PATH"])
    if value is None:
        pytest.skip(f"required executable is unavailable: {name}")
    return value


def assert_no_glob(parent: Path, pattern: str) -> None:
    assert not tuple(parent.glob(pattern))
