"""Outside-Git PKI namespace initialization."""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from collections.abc import Iterator, Mapping
from typing import NoReturn

from .errors import ApplicationError
from .operational import run_external
from .parser import ParseResult
from .subprocesses import ProcessSpawnError


_DIRECTORIES = (
    "inventory",
    "authorities",
    "authorities/roots",
    "authorities/intermediates",
    "state",
    "state/generation-reservations",
    "state/rollover",
    "locks",
    "services",
    "export",
    "export/ansible",
    "backups",
)


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


def _lexists(path: str) -> bool:
    return os.path.lexists(path)


def _lstat(path: str) -> os.stat_result:
    try:
        return os.lstat(path)
    except OSError:
        _die(f"Cannot inspect filesystem path: {path}")


def _is_directory(result: os.stat_result) -> bool:
    return stat.S_ISDIR(result.st_mode)


def _is_regular(result: os.stat_result) -> bool:
    return stat.S_ISREG(result.st_mode)


def _is_symlink(result: os.stat_result) -> bool:
    return stat.S_ISLNK(result.st_mode)


def _permissions(result: os.stat_result) -> int:
    return stat.S_IMODE(result.st_mode)


def _components(path: str) -> Iterator[str]:
    current = ""
    for component in path.split("/"):
        if not component:
            continue
        current = f"{current}/{component}"
        yield current


def _expand_path(path: str, environment: Mapping[str, str]) -> str:
    if path == "~":
        return environment.get("HOME", "")
    if path.startswith("~/"):
        return f"{environment.get('HOME', '')}/{path[2:]}"
    return path


def _default_namespace(environment: Mapping[str, str]) -> str:
    base = environment.get("XDG_CONFIG_HOME", "")
    if not base:
        base = f"{environment.get('HOME', '')}/.config"
    return f"{base}/platform-infrastructure"


def _script_directory() -> str:
    directory = os.path.dirname(sys.argv[0]) or "."
    try:
        return os.path.realpath(directory, strict=True)
    except OSError:
        return os.path.realpath(directory)


def _template_directory(environment: Mapping[str, str]) -> str:
    explicit = environment.get("PLATFORM_TOOLS_TEMPLATE_DIR", "")
    candidates = []
    if explicit:
        candidates.append(f"{explicit}/pki")
    candidates.extend(
        (
            f"{_script_directory()}/../templates/pki",
            f"{environment.get('PLATFORM_TOOLS_SHARE_DIR') or _user_share(environment)}/templates/pki",
            "/usr/local/share/platform-tools/templates/pki",
        )
    )
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    _die("PKI templates not found")


def _user_share(environment: Mapping[str, str]) -> str:
    data_home = environment.get("XDG_DATA_HOME", "")
    if not data_home:
        data_home = f"{environment.get('HOME', '')}/.local/share"
    return f"{data_home}/platform-tools"


def _require_templates(template_directory: str) -> str:
    source = f"{template_directory}/services.yml.example"
    try:
        result = os.lstat(source)
    except OSError:
        result = None
    if (
        result is None
        or not _is_regular(result)
        or _is_symlink(result)
        or not os.access(source, os.R_OK)
    ):
        _die(f"Required PKI template is missing or unsafe: {source}")
    return source


def _require_safe_init_path(path: str, label: str) -> None:
    if not path.startswith("/"):
        _die(f"{label} must be an absolute path: {path}")
    if path == "/":
        _die(f"{label} must not be the filesystem root")
    if path.endswith("/"):
        _die(f"{label} must not end with a slash: {path}")
    if "\n" in path or "\r" in path:
        _die(f"{label} must not contain newlines")
    components = path[1:].split("/")
    if any(component in ("", ".", "..") for component in components):
        _die(f"{label} must not contain empty, dot, or parent components: {path}")

    current_uid = os.geteuid()
    for current in _components(path):
        if not _lexists(current):
            continue
        result = _lstat(current)
        if _is_symlink(result):
            _die(f"{label} path component must not be a symlink: {current}")
        if not _is_directory(result):
            _die(f"{label} path component is not a directory: {current}")
        mode = _permissions(result)
        if mode & 0o022 and not mode & stat.S_ISVTX:
            _die(
                f"{label} path component is group- or world-writable without sticky bit: {current}"
            )
        if result.st_uid not in (current_uid, 0):
            _die(
                f"{label} path component is not owned by current user or root: {current}"
            )
        if current == path and result.st_uid != current_uid:
            _die(f"{label} directory is not owned by the current user: {path}")

    probe = path
    while not _lexists(probe):
        probe = os.path.dirname(probe)
    result = _lstat(probe)
    if _is_symlink(result) or not _is_directory(result) or not os.access(probe, os.W_OK):
        _die(f"{label} has no writable trusted creation parent: {probe}")


def _run(arguments: tuple[str, ...], environment: Mapping[str, str]) -> bool:
    try:
        result = run_external(arguments, environment)
    except ProcessSpawnError:
        return False
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.flush()
    return result.status == 0


def _prepare_private_path(path: str, label: str, environment: Mapping[str, str]) -> bool:
    current_uid = os.geteuid()
    for current in _components(path):
        if _lexists(current):
            result = _lstat(current)
            if _is_symlink(result) or not _is_directory(result):
                _die(
                    f"{label} path component must be a non-symlink directory: {current}"
                )
        else:
            if not _run(("mkdir", "-m", "700", "--", current), environment):
                _die(f"Cannot create {label} path component: {current}")
            if not _lexists(current):
                _die(f"{label} path component changed during creation: {current}")
            result = _lstat(current)
            if _is_symlink(result) or not _is_directory(result):
                _die(f"{label} path component changed during creation: {current}")

        result = _lstat(current)
        mode = _permissions(result)
        if mode & 0o022 and not mode & stat.S_ISVTX:
            _die(
                f"{label} path component is group- or world-writable without sticky bit: {current}"
            )
        if result.st_uid not in (current_uid, 0):
            _die(
                f"{label} path component is not owned by current user or root: {current}"
            )
        if current == path and result.st_uid != current_uid:
            _die(f"{label} directory is not owned by the current user: {path}")

    if not _run(("chmod", "700", path), environment):
        return False
    return True


def _walk(path: str) -> tuple[tuple[str, os.stat_result], ...]:
    entries: list[tuple[str, os.stat_result]] = []
    pending = [path]
    try:
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as children:
                current = tuple(children)
            directories = []
            for child in current:
                result = child.stat(follow_symlinks=False)
                entries.append((child.path, result))
                if _is_directory(result) and not _is_symlink(result):
                    directories.append(child.path)
            pending.extend(reversed(directories))
    except OSError:
        _die(f"Cannot inspect existing PKI directory: {path}")
    return tuple(entries)


def _require_safe_existing_pki_tree(path: str) -> None:
    if not os.path.isdir(path):
        return
    entries = _walk(path)
    for item, result in entries:
        if _is_symlink(result):
            _die(f"Existing PKI state must not contain symlinks: {item}")
    for item, result in entries:
        if _is_regular(result) and result.st_nlink > 1:
            _die(f"Existing PKI state must not contain hard-linked files: {item}")

    current_uid = os.geteuid()
    for item, result in entries:
        if _is_directory(result) and os.path.basename(item) == "private":
            if result.st_uid != current_uid:
                _die(f"Private directory is not owned by the current user: {item}")
            if _permissions(result) & 0o022:
                _die(f"Private directory is group- or world-writable: {item}")
    for item, result in entries:
        if _is_regular(result) and item.endswith(".key"):
            if result.st_uid != current_uid:
                _die(f"Private key is not owned by the current user: {item}")
            if _permissions(result) & 0o077:
                _die(
                    f"Private key permissions are too open; use chmod 600 or stricter: {item}"
                )


def _require_safe_destination_layout(namespace: str, pki_dir: str) -> None:
    current_uid = os.geteuid()
    for path in (namespace, pki_dir, *(f"{pki_dir}/{item}" for item in _DIRECTORIES)):
        if not _lexists(path):
            continue
        result = _lstat(path)
        if _is_symlink(result) or not _is_directory(result):
            _die(
                f"PKI directory destination must be a non-symlink directory: {path}"
            )
        if result.st_uid != current_uid:
            _die(f"PKI directory destination is not owned by the current user: {path}")
        if _permissions(result) & 0o022:
            _die(f"PKI directory destination is group- or world-writable: {path}")

    path = f"{pki_dir}/inventory/services.yml.example"
    if _lexists(path):
        result = _lstat(path)
        if _is_symlink(result) or not _is_regular(result):
            _die(f"PKI file destination must be a non-symlink regular file: {path}")
        if result.st_uid != current_uid:
            _die(f"PKI file destination is not owned by the current user: {path}")
        if _permissions(result) & 0o022:
            _die(f"PKI file destination is group- or world-writable: {path}")


def _copy_template(
    source: str,
    target: str,
    force: bool,
    environment: Mapping[str, str],
) -> None:
    if os.path.exists(target) and not force:
        print(f"[INFO] Kept existing file: {target}", flush=True)
        return
    if os.path.islink(target):
        _die(f"Template destination must not be a symlink: {target}")
    if os.path.exists(target) and not os.path.isfile(target):
        _die(f"Template destination must be a regular file: {target}")

    target_directory = os.path.dirname(target)
    descriptor = -1
    temporary = ""
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=".platform-pki-init.", dir=target_directory
        )
        os.close(descriptor)
        descriptor = -1
        if not _run(("cp", source, temporary), environment):
            _die(f"Failed to replace template: {target}")
        if not _run(("chmod", "600", temporary), environment):
            _die(f"Failed to replace template: {target}")
        if not _run(("mv", "-f", "--", temporary, target), environment):
            _die(f"Failed to replace template: {target}")
    except OSError:
        _die(f"Failed to replace template: {target}")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
    print(f"[OK] Wrote {target}", flush=True)


def initialize(parsed: ParseResult) -> int:
    """Create or refresh the Bash-compatible private PKI working tree."""

    environment = dict(os.environ)
    namespace_value = parsed.values.get("--namespace")
    namespace = _expand_path(
        str(namespace_value) if namespace_value is not None else _default_namespace(environment),
        environment,
    )
    pki_value = parsed.values.get("--pki-dir")
    pki_dir = (
        f"{namespace}/pki"
        if pki_value is None
        else _expand_path(str(pki_value), environment)
    )
    force = "--force" in parsed.provided

    if namespace == pki_dir or namespace.startswith(f"{pki_dir}/"):
        _die(f"PKI directory must not equal or contain the namespace: {pki_dir}")

    _require_safe_init_path(namespace, "Namespace")
    _require_safe_init_path(pki_dir, "PKI directory")
    _require_safe_existing_pki_tree(pki_dir)
    template_directory = _template_directory(environment)
    template = _require_templates(template_directory)
    _require_safe_destination_layout(namespace, pki_dir)

    if not _prepare_private_path(namespace, "Namespace", environment):
        return 1
    if not _prepare_private_path(pki_dir, "PKI directory", environment):
        return 1
    for relative in _DIRECTORIES:
        if not _prepare_private_path(
            f"{pki_dir}/{relative}", "PKI directory", environment
        ):
            return 1

    _copy_template(
        template,
        f"{pki_dir}/inventory/services.yml.example",
        force,
        environment,
    )
    print(f"[OK] PKI directory ready: {pki_dir}", flush=True)
    return 0
