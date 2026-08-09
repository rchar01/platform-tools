import hashlib
import os
import re
import stat
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from ..harness import ProcessResult, copy_tree, run_process


ContentNormalizer = Callable[[str, bytes], bytes]
OutputNormalizer = Callable[[Path, str], str]
ArgvFactory = Callable[[Path], Sequence[str | os.PathLike[str]]]
PreparationCallback = Callable[[Path, Mapping[str, str]], None]

_MANAGED_OPENSSL_CONFIG = re.compile(
    r"(?:(?:^|.*/)pki/|^)(?:authorities/(?:roots|intermediates)/[^/]+|root-ca|intermediate-ca)/openssl\.cnf$"
)
_OPENSSL_DIR = re.compile(rb"(?m)^dir[ \t]*=[ \t]*(?P<path>[^\r\n]+)$")


@dataclass(frozen=True)
class SemanticEntry:
    path: str
    kind: str
    mode: int
    owner: str
    group: str
    links: int
    object_class: tuple[str, ...]
    size: int
    content_sha256: str | None
    link_target: str | None
    identity: tuple[int, int] = field(compare=False, repr=False)


@dataclass(frozen=True)
class ComparableProcessResult:
    status: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class DifferentialObservation:
    process: ComparableProcessResult
    before: tuple[SemanticEntry, ...]
    after: tuple[SemanticEntry, ...]
    transitions: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class DifferentialResult:
    bash: DifferentialObservation
    python: DifferentialObservation

    def assert_equivalent(self) -> None:
        if self.bash.process != self.python.process:
            raise AssertionError("differential process observations differ")
        if self.bash.before != self.python.before:
            raise AssertionError("differential initial state trees differ")
        if self.bash.after != self.python.after:
            raise AssertionError("differential final state trees differ")
        if self.bash.transitions != self.python.transitions:
            raise AssertionError("differential state transitions differ")


def _principal_class(value: int, current: int) -> str:
    if value == current:
        return "current"
    if value == 0:
        return "root"
    return f"id:{value}"


def _kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "character-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    return "unknown"


def _walk_without_following(root: Path) -> Iterable[Path]:
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            children = sorted(entries, key=lambda entry: entry.name, reverse=True)
        for entry in children:
            path = Path(entry.path)
            yield path
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)


def snapshot_state(
    root: Path,
    normalizers: tuple[ContentNormalizer, ...] = (),
) -> tuple[SemanticEntry, ...]:
    root_stat = root.lstat()
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise ValueError(f"Snapshot root is not a real directory: {root}")
    identities: dict[tuple[int, int], list[str]] = {}
    root_identity = (root_stat.st_dev, root_stat.st_ino)
    identities[root_identity] = ["."]
    staged: list[tuple[Path, os.stat_result, str]] = [(root, root_stat, ".")]

    for path in _walk_without_following(root):
        path_stat = path.lstat()
        relative = path.relative_to(root).as_posix()
        identity = (path_stat.st_dev, path_stat.st_ino)
        identities.setdefault(identity, []).append(relative)
        staged.append((path, path_stat, relative))

    result = []
    for path, path_stat, relative in sorted(staged, key=lambda item: item[2]):
        entry_kind = _kind(path_stat.st_mode)
        content_sha256 = None
        link_target = None
        if entry_kind == "file":
            content = path.read_bytes()
            for normalizer in normalizers:
                content = normalizer(relative, content)
            content_sha256 = hashlib.sha256(content).hexdigest()
            semantic_size = len(content)
        elif entry_kind == "symlink":
            link_target = os.readlink(path)
            semantic_size = 0
        else:
            semantic_size = 0

        identity = (path_stat.st_dev, path_stat.st_ino)
        result.append(
            SemanticEntry(
                path=relative,
                kind=entry_kind,
                mode=stat.S_IMODE(path_stat.st_mode),
                owner=_principal_class(path_stat.st_uid, os.getuid()),
                group=_principal_class(path_stat.st_gid, os.getgid()),
                links=path_stat.st_nlink,
                object_class=tuple(sorted(identities[identity])),
                size=semantic_size,
                content_sha256=content_sha256,
                link_target=link_target,
                identity=identity,
            )
        )
    return tuple(result)


def managed_openssl_dir_normalizer(*roots: Path) -> ContentNormalizer:
    encoded_roots = tuple(os.fsencode(root) for root in roots)

    def normalize(relative: str, content: bytes) -> bytes:
        if _MANAGED_OPENSSL_CONFIG.fullmatch(relative) is None:
            return content
        matches = list(_OPENSSL_DIR.finditer(content))
        if len(matches) != 1:
            raise ValueError(
                f"Managed OpenSSL config must contain exactly one dir assignment: {relative}"
            )
        value = matches[0].group("path")
        for encoded_root in encoded_roots:
            if value == encoded_root or value.startswith(encoded_root + b"/"):
                suffix = value[len(encoded_root) :]
                if b"/../" in suffix or suffix.endswith(b"/.."):
                    raise ValueError(f"Managed OpenSSL config dir contains traversal: {relative}")
                start, end = matches[0].span("path")
                return content[:start] + b"<WORKSPACE>" + suffix + content[end:]
        raise ValueError(f"Managed OpenSSL config dir escapes known workspaces: {relative}")

    return normalize


def state_transitions(
    before: tuple[SemanticEntry, ...],
    after: tuple[SemanticEntry, ...],
) -> dict[str, str]:
    before_by_path = {entry.path: entry for entry in before}
    after_by_path = {entry.path: entry for entry in after}
    transitions = {}
    for path in sorted(before_by_path.keys() | after_by_path.keys()):
        old = before_by_path.get(path)
        new = after_by_path.get(path)
        if old is None:
            transitions[path] = "created"
        elif new is None:
            transitions[path] = "deleted"
        elif old.identity != new.identity:
            transitions[path] = "replaced"
        elif old == new:
            transitions[path] = "unchanged"
        else:
            transitions[path] = "modified"
    return transitions


def _require_relative_path(path: Path, label: str) -> None:
    if path.is_absolute() or path == Path() or ".." in path.parts:
        raise ValueError(f"{label} must be a nonempty relative path without parent traversal")


def _require_directory_components(root: Path, relative: Path) -> Path:
    current = root
    for component in relative.parts:
        current = current / component
        current_stat = current.lstat()
        if not stat.S_ISDIR(current_stat.st_mode) or stat.S_ISLNK(current_stat.st_mode):
            raise ValueError(f"Copied PKI path component is not a real directory: {current}")
    return current


def _require_config_file(config: Path) -> None:
    config_stat = config.lstat()
    if not stat.S_ISREG(config_stat.st_mode) or stat.S_ISLNK(config_stat.st_mode):
        raise ValueError(f"Managed OpenSSL config is not a regular file: {config}")
    if config_stat.st_nlink != 1:
        raise ValueError(f"Managed OpenSSL config must be singly linked: {config}")


def _managed_config_paths(pki_dir: Path) -> tuple[Path, ...]:
    configs = []
    for relative in (Path("root-ca"), Path("intermediate-ca")):
        authority = pki_dir / relative
        if authority.exists() or authority.is_symlink():
            authority_stat = authority.lstat()
            if not stat.S_ISDIR(authority_stat.st_mode) or stat.S_ISLNK(
                authority_stat.st_mode
            ):
                raise ValueError(f"Managed authority path is not a real directory: {authority}")
            config = authority / "openssl.cnf"
            if config.exists() or config.is_symlink():
                _require_config_file(config)
                configs.append(config)

    authorities = pki_dir / "authorities"
    if not authorities.exists() and not authorities.is_symlink():
        return tuple(configs)
    authorities = _require_directory_components(pki_dir, Path("authorities"))
    for collection in ("roots", "intermediates"):
        generations = authorities / collection
        if not generations.exists() and not generations.is_symlink():
            continue
        generations_stat = generations.lstat()
        if not stat.S_ISDIR(generations_stat.st_mode) or stat.S_ISLNK(
            generations_stat.st_mode
        ):
            raise ValueError(
                f"Managed authority collection is not a real directory: {generations}"
            )
        with os.scandir(generations) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                authority = Path(entry.path)
                if not entry.is_dir(follow_symlinks=False) or entry.is_symlink():
                    raise ValueError(
                        f"Managed authority generation is not a real directory: {authority}"
                    )
                config = authority / "openssl.cnf"
                if config.exists() or config.is_symlink():
                    _require_config_file(config)
                    configs.append(config)
    return tuple(configs)


def rebase_openssl_config(config: Path, source: Path, destination: Path) -> None:
    relative_config = config.relative_to(destination)
    expected_old_directory = source / relative_config.parent
    descriptor = os.open(
        config,
        os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    with os.fdopen(descriptor, "r+", encoding="utf-8") as opened:
        opened_stat = os.fstat(opened.fileno())
        if not stat.S_ISREG(opened_stat.st_mode) or opened_stat.st_nlink != 1:
            raise ValueError(f"Managed OpenSSL config changed while opening: {config}")
        content = opened.read()
        matches = list(re.finditer(r"(?m)^dir[ \t]*=[ \t]*(?P<path>[^\r\n]+)$", content))
        if len(matches) != 1:
            raise ValueError(
                f"OpenSSL config must contain exactly one dir assignment: {config}"
            )
        old_directory = Path(matches[0].group("path"))
        if (
            not old_directory.is_absolute()
            or ".." in old_directory.parts
            or old_directory != expected_old_directory
        ):
            raise ValueError(f"OpenSSL config dir escapes source workspace: {config}")
        start, end = matches[0].span("path")
        opened.seek(0)
        opened.truncate()
        opened.write(f"{content[:start]}{config.parent}{content[end:]}")
        opened.flush()
        path_stat = config.lstat()
        if (
            not stat.S_ISREG(path_stat.st_mode)
            or stat.S_ISLNK(path_stat.st_mode)
            or path_stat.st_nlink != 1
            or (path_stat.st_dev, path_stat.st_ino)
            != (opened_stat.st_dev, opened_stat.st_ino)
        ):
            raise ValueError(f"Managed OpenSSL config changed while rebasing: {config}")


def copy_private_case(source: Path, destination: Path, pki_relative: Path) -> None:
    _require_relative_path(pki_relative, "PKI path")
    copy_tree(source, destination)
    destination_stat = destination.lstat()
    if not stat.S_ISDIR(destination_stat.st_mode) or stat.S_ISLNK(
        destination_stat.st_mode
    ):
        raise ValueError(f"Copied workspace is not a real directory: {destination}")
    pki_dir = _require_directory_components(destination, pki_relative)
    for config in _managed_config_paths(pki_dir):
        rebase_openssl_config(config, source, destination)


def _case_environment(root: Path, base: Mapping[str, str]) -> dict[str, str]:
    environment_root = root / ".differential-environment"
    locations = {
        "HOME": environment_root / "home",
        "TMPDIR": environment_root / "tmp",
        "XDG_CACHE_HOME": environment_root / "cache",
        "XDG_CONFIG_HOME": environment_root / "config",
        "XDG_DATA_HOME": environment_root / "data",
        "XDG_RUNTIME_DIR": environment_root / "runtime",
        "XDG_STATE_HOME": environment_root / "state",
    }
    for directory in locations.values():
        directory.mkdir(mode=0o700, parents=True)
        directory.chmod(0o700)
    return {**base, **{name: os.fspath(path) for name, path in locations.items()}}


def _normalize_output(
    root: Path,
    value: str,
    normalizers: tuple[OutputNormalizer, ...],
) -> str:
    for normalizer in normalizers:
        value = normalizer(root, value)
    return value


def run_differential_case(
    seed: Path,
    case_root: Path,
    pki_relative: Path,
    bash_argv: ArgvFactory,
    python_argv: ArgvFactory,
    base_environment: Mapping[str, str],
    *,
    output_normalizers: tuple[OutputNormalizer, ...] = (),
    content_normalizers: tuple[ContentNormalizer, ...] = (),
    runner: Callable[..., ProcessResult] = run_process,
    run_options: Mapping[str, object] | None = None,
    cwd_relative: Path = Path("."),
    bash_prepare: PreparationCallback | None = None,
    python_prepare: PreparationCallback | None = None,
) -> DifferentialResult:
    _require_relative_path(pki_relative, "PKI path")
    if cwd_relative.is_absolute() or ".." in cwd_relative.parts:
        raise ValueError("working directory must be relative without parent traversal")
    if case_root.exists() or case_root.is_symlink():
        raise FileExistsError(case_root)
    case_root.mkdir(mode=0o700)

    bash_root = case_root / "bash"
    python_root = case_root / "python"
    for root in (bash_root, python_root):
        copy_private_case(seed, root, pki_relative)

    normalizers = (
        managed_openssl_dir_normalizer(seed, bash_root, python_root),
        *content_normalizers,
    )
    options = dict(run_options or {})
    if "cwd" in options or "env" in options:
        raise ValueError("run_options must not override cwd or env")

    def observe(
        root: Path,
        argv_factory: ArgvFactory,
        prepare: PreparationCallback | None,
    ) -> DifferentialObservation:
        root_identity = root.lstat()
        if not stat.S_ISDIR(root_identity.st_mode) or stat.S_ISLNK(root_identity.st_mode):
            raise ValueError(f"Copied workspace is not a real directory: {root}")
        state_root = root / pki_relative
        try:
            working_directory = _require_directory_components(root, cwd_relative)
        except OSError:
            raise ValueError(
                f"Copied working directory does not exist: {root / cwd_relative}"
            ) from None
        environment = _case_environment(root, base_environment)
        if prepare is not None:
            prepare(root, MappingProxyType(environment))
            current_root = root.lstat()
            if (
                not stat.S_ISDIR(current_root.st_mode)
                or stat.S_ISLNK(current_root.st_mode)
                or (current_root.st_dev, current_root.st_ino)
                != (root_identity.st_dev, root_identity.st_ino)
            ):
                raise ValueError(f"Copied workspace changed during preparation: {root}")
            state_root = _require_directory_components(root, pki_relative)
            try:
                working_directory = _require_directory_components(root, cwd_relative)
            except OSError:
                raise ValueError(
                    f"Copied working directory does not exist: {root / cwd_relative}"
                ) from None
        before = snapshot_state(state_root, normalizers)
        result = runner(
            tuple(argv_factory(root)),
            cwd=working_directory,
            env=environment,
            **options,
        )
        after = snapshot_state(state_root, normalizers)
        process = ComparableProcessResult(
            result.status,
            _normalize_output(root, result.stdout, output_normalizers),
            _normalize_output(root, result.stderr, output_normalizers),
        )
        return DifferentialObservation(
            process,
            before,
            after,
            tuple(state_transitions(before, after).items()),
        )

    return DifferentialResult(
        observe(bash_root, bash_argv, bash_prepare),
        observe(python_root, python_argv, python_prepare),
    )
