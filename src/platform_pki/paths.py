"""Lexical path resolution and tree-relationship primitives."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from enum import Enum

from .errors import ApplicationError, ERROR_STATUS


class _PathErrorReason(Enum):
    NOT_ABSOLUTE = "Path must be absolute"
    ROOT = "Path must not be the filesystem root"
    TRAILING_SLASH = "Path must not end with a slash"
    NONCANONICAL_COMPONENT = "Path contains an empty, dot, or parent component"
    UNSAFE_TEXT = "Path contains unsafe text"


@dataclass(frozen=True, slots=True, repr=False)
class PathError(ApplicationError):
    """A static, immutable path error safe for public output."""

    reason: _PathErrorReason

    def __post_init__(self) -> None:
        if not isinstance(self.reason, _PathErrorReason):
            raise TypeError("reason must be a path error reason")
        object.__setattr__(self, "message", self.reason.value)
        object.__setattr__(self, "status", ERROR_STATUS)
        Exception.__init__(self, self.message)


@dataclass(frozen=True, slots=True)
class PkiPaths:
    """Resolved canonical paths for one PKI invocation."""

    namespace: str
    pki_dir: str

    def __post_init__(self) -> None:
        validate_absolute_path(self.namespace)
        validate_absolute_path(self.pki_dir)


def _require_text(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    return value


def _contains_unsafe_text(path: str) -> bool:
    return any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        for character in path
    )


def _validate_absolute_path(path: object, *, allow_root: bool) -> str:
    value = _require_text(path, "path")
    if _contains_unsafe_text(value):
        raise PathError(_PathErrorReason.UNSAFE_TEXT)
    if not value.startswith("/"):
        raise PathError(_PathErrorReason.NOT_ABSOLUTE)
    if value == "/":
        if allow_root:
            return value
        raise PathError(_PathErrorReason.ROOT)
    if value.endswith("/"):
        raise PathError(_PathErrorReason.TRAILING_SLASH)
    components = value[1:].split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise PathError(_PathErrorReason.NONCANONICAL_COMPONENT)
    return value


def validate_absolute_path(path: object) -> str:
    """Return *path* after validating its canonical lexical form."""

    return _validate_absolute_path(path, allow_root=False)


def expand_home(path: object, *, home: object) -> str:
    """Expand only ``~`` and ``~/`` using an explicit HOME value."""

    value = _require_text(path, "path")
    home_value = _require_text(home, "home")
    if value == "~":
        return home_value
    if value.startswith("~/"):
        return f"{home_value}/{value[2:]}"
    return value


def default_namespace(*, home: object, xdg_config_home: object | None) -> str:
    """Compute the Bash-compatible namespace default from explicit inputs."""

    home_value = _require_text(home, "home")
    if xdg_config_home is None:
        config_home = ""
    else:
        config_home = _require_text(xdg_config_home, "xdg_config_home")
    base = config_home if config_home else f"{home_value}/.config"
    return f"{base}/platform-infrastructure"


def default_pki_dir(namespace: object) -> str:
    """Return the PKI default below a validated namespace."""

    return f"{validate_absolute_path(namespace)}/pki"


def absolutize_path(path: object, *, physical_cwd: object) -> str:
    """Lexically join a relative path to an explicit physical current directory."""

    value = _require_text(path, "path")
    cwd = _validate_absolute_path(physical_cwd, allow_root=True)
    if not value:
        raise PathError(_PathErrorReason.NOT_ABSOLUTE)
    if value.startswith("/"):
        absolute = value
    elif cwd == "/":
        absolute = f"/{value}"
    else:
        absolute = f"{cwd}/{value}"
    return validate_absolute_path(absolute)


def resolve_pki_paths(
    *,
    namespace: object | None,
    pki_dir: object | None,
    home: object,
    xdg_config_home: object | None,
    physical_cwd: object,
) -> PkiPaths:
    """Resolve namespace and PKI paths without filesystem canonicalization."""

    namespace_input = (
        default_namespace(home=home, xdg_config_home=xdg_config_home)
        if namespace is None
        else expand_home(namespace, home=home)
    )
    resolved_namespace = absolutize_path(namespace_input, physical_cwd=physical_cwd)
    if pki_dir is None:
        resolved_pki_dir = default_pki_dir(resolved_namespace)
    else:
        resolved_pki_dir = absolutize_path(
            expand_home(pki_dir, home=home),
            physical_cwd=physical_cwd,
        )
    return PkiPaths(resolved_namespace, resolved_pki_dir)


def is_same_or_descendant(path: object, parent: object) -> bool:
    """Return whether *path* is *parent* or lies below it by components."""

    child = validate_absolute_path(path)
    ancestor = validate_absolute_path(parent)
    return child == ancestor or child.startswith(f"{ancestor}/")


def trees_are_disjoint(first: object, second: object) -> bool:
    """Return whether neither canonical path tree contains or equals the other."""

    first_path = validate_absolute_path(first)
    second_path = validate_absolute_path(second)
    return not (
        is_same_or_descendant(first_path, second_path)
        or is_same_or_descendant(second_path, first_path)
    )
