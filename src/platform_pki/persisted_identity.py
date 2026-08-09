"""Strict codecs for GNU ``stat`` identities persisted by the Bash PKI tools."""

from __future__ import annotations

import datetime
import re
from enum import Enum
from typing import Literal

from .filesystem import DirectoryIdentity, FileIdentity, FileObjectState


_DECIMAL = r"(?:0|[1-9][0-9]*)"
_MODE = r"(?:0|[1-7][0-7]{0,3})"
_TIMESTAMP = (
    r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\."
    r"[0-9]{9} [+-][0-9]{4}"
)
_KIND = r"(?:regular empty file|regular file|directory)"
_FULL_PATTERN = re.compile(
    rf"(?P<dev>{_DECIMAL}):(?P<ino>{_DECIMAL}):(?P<uid>{_DECIMAL}):"
    rf"(?P<mode>{_MODE}):(?P<links>{_DECIMAL}):(?P<size>{_DECIMAL}):"
    rf"(?P<mtime>{_TIMESTAMP}):(?P<ctime>{_TIMESTAMP}):(?P<kind>{_KIND})",
    re.ASCII,
)
_OBJECT_PATTERN = re.compile(
    rf"(?P<dev>{_DECIMAL}):(?P<ino>{_DECIMAL}):(?P<uid>{_DECIMAL}):"
    rf"(?P<mode>{_MODE}):(?P<links>{_DECIMAL}):(?P<size>{_DECIMAL}):"
    rf"(?P<kind>{_KIND})",
    re.ASCII,
)
_DIRECTORY_PATTERN = re.compile(
    rf"(?P<dev>{_DECIMAL}):(?P<ino>{_DECIMAL}):(?P<uid>{_DECIMAL}):"
    rf"(?P<mode>{_MODE}):directory",
    re.ASCII,
)
_TIMESTAMP_PATTERN = re.compile(
    r"(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2}) "
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})\."
    r"(?P<fraction>[0-9]{9}) (?P<sign>[+-])(?P<offset_hour>[0-9]{2})"
    r"(?P<offset_minute>[0-9]{2})",
    re.ASCII,
)

_UINT32_MAX = (1 << 32) - 1
_UINT64_MAX = (1 << 64) - 1
_INT64_MAX = (1 << 63) - 1
_EPOCH_ORDINAL = datetime.date(1970, 1, 1).toordinal()


class PersistedIdentityError(ValueError):
    """A persisted identity is malformed or cannot describe its claimed object."""


class IdentitySentinel(Enum):
    ABSENT = "absent"
    NONE = "none"


PersistedIdentity = (
    FileIdentity | FileObjectState | DirectoryIdentity | IdentitySentinel
)


def _sentinel(
    value: str,
    allowed_sentinels: frozenset[IdentitySentinel],
) -> IdentitySentinel | None:
    if not isinstance(allowed_sentinels, frozenset) or any(
        not isinstance(item, IdentitySentinel) for item in allowed_sentinels
    ):
        raise TypeError(
            "allowed_sentinels must be a frozenset of IdentitySentinel values"
        )
    for sentinel in IdentitySentinel:
        if value == sentinel.value:
            if sentinel not in allowed_sentinels:
                raise PersistedIdentityError("persisted identity sentinel is not allowed")
            return sentinel
    return None


def serialize_identity_sentinel(
    value: IdentitySentinel,
    *,
    allowed_sentinels: frozenset[IdentitySentinel],
) -> str:
    """Serialize a sentinel only when its caller explicitly permits that value."""

    if not isinstance(value, IdentitySentinel):
        raise TypeError("value must be an IdentitySentinel")
    if _sentinel(value.value, allowed_sentinels) is None:  # pragma: no cover
        raise AssertionError("validated sentinel unexpectedly disappeared")
    return value.value


def _integer(value: str, label: str, maximum: int, *, positive: bool = False) -> int:
    try:
        number = int(value, 10)
    except ValueError:
        raise PersistedIdentityError(
            f"persisted identity {label} is not an integer"
        ) from None
    if number < 0 or number > maximum or (positive and number == 0):
        raise PersistedIdentityError(
            f"persisted identity {label} is outside its range"
        )
    return number


def _mode(value: str) -> int:
    mode = int(value, 8)
    if mode > 0o7777 or format(mode, "o") != value:
        raise PersistedIdentityError("persisted identity mode is not canonical")
    return mode


def _kind(value: str, size: int) -> Literal["regular", "directory"]:
    if value == "directory":
        return "directory"
    if value == "regular empty file":
        if size != 0:
            raise PersistedIdentityError("nonempty object has an empty-file type")
        return "regular"
    if size == 0:
        raise PersistedIdentityError("empty object does not have the GNU empty-file type")
    return "regular"


def parse_gnu_stat_timestamp(value: str) -> int:
    """Parse exact GNU ``stat`` ``%y``/``%z`` timestamp text to epoch nanoseconds."""

    if not isinstance(value, str):
        raise TypeError("persisted timestamp must be text")
    match = _TIMESTAMP_PATTERN.fullmatch(value)
    if match is None:
        raise PersistedIdentityError("persisted identity timestamp is malformed")
    parts = {name: int(raw) for name, raw in match.groupdict().items() if name != "sign"}
    offset_minutes = parts["offset_hour"] * 60 + parts["offset_minute"]
    if parts["offset_hour"] > 23 or parts["offset_minute"] > 59:
        raise PersistedIdentityError("persisted identity timestamp offset is impossible")
    if match["sign"] == "-":
        if offset_minutes == 0:
            raise PersistedIdentityError("negative zero timestamp offset is not canonical")
        offset_minutes = -offset_minutes
    try:
        date = datetime.date(parts["year"], parts["month"], parts["day"])
    except ValueError:
        raise PersistedIdentityError("persisted identity timestamp date is impossible") from None
    if parts["hour"] > 23 or parts["minute"] > 59 or parts["second"] > 59:
        raise PersistedIdentityError("persisted identity timestamp time is impossible")
    seconds = (
        (date.toordinal() - _EPOCH_ORDINAL) * 86_400
        + parts["hour"] * 3_600
        + parts["minute"] * 60
        + parts["second"]
        - offset_minutes * 60
    )
    return seconds * 1_000_000_000 + parts["fraction"]


def format_gnu_stat_timestamp(
    value: int,
    *,
    utc_offset_minutes: int | None = None,
) -> str:
    """Format epoch nanoseconds exactly as GNU ``stat`` does for ``%y``/``%z``."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("persisted timestamp must be an integer")
    seconds, fraction = divmod(value, 1_000_000_000)
    try:
        instant = datetime.datetime.fromtimestamp(seconds, datetime.UTC)
    except (OverflowError, OSError, ValueError):
        raise PersistedIdentityError(
            "persisted identity timestamp is outside the supported calendar"
        ) from None
    if utc_offset_minutes is None:
        local = instant.astimezone()
        offset = local.utcoffset()
        if offset is None or offset.total_seconds() % 60:
            raise PersistedIdentityError("local timestamp offset is not minute-aligned")
        utc_offset_minutes = int(offset.total_seconds() // 60)
    if (
        isinstance(utc_offset_minutes, bool)
        or not isinstance(utc_offset_minutes, int)
        or not -1_439 <= utc_offset_minutes <= 1_439
    ):
        raise PersistedIdentityError("timestamp offset minutes are outside their range")
    try:
        local = instant + datetime.timedelta(minutes=utc_offset_minutes)
    except OverflowError:
        raise PersistedIdentityError(
            "persisted identity timestamp is outside the supported calendar"
        ) from None
    sign = "+" if utc_offset_minutes >= 0 else "-"
    offset = abs(utc_offset_minutes)
    return (
        f"{local:%Y-%m-%d %H:%M:%S}.{fraction:09d} "
        f"{sign}{offset // 60:02d}{offset % 60:02d}"
    )


def _components(
    match: re.Match[str],
) -> tuple[int, int, int, int, int, int, Literal["regular", "directory"]]:
    size = _integer(match["size"], "size", _INT64_MAX)
    return (
        _integer(match["dev"], "device", _UINT64_MAX),
        _integer(match["ino"], "inode", _UINT64_MAX, positive=True),
        _integer(match["uid"], "owner", _UINT32_MAX),
        _mode(match["mode"]),
        _integer(match["links"], "link count", _UINT64_MAX, positive=True),
        size,
        _kind(match["kind"], size),
    )


def parse_file_identity(
    value: str,
    *,
    allowed_sentinels: frozenset[IdentitySentinel] = frozenset(),
) -> FileIdentity | IdentitySentinel:
    if not isinstance(value, str):
        raise TypeError("persisted identity must be text")
    sentinel = _sentinel(value, allowed_sentinels)
    if sentinel is not None:
        return sentinel
    match = _FULL_PATTERN.fullmatch(value)
    if match is None:
        raise PersistedIdentityError("full persisted file identity is malformed")
    dev, ino, uid, mode, links, size, kind = _components(match)
    return FileIdentity(
        dev,
        ino,
        uid,
        mode,
        links,
        size,
        parse_gnu_stat_timestamp(match["mtime"]),
        parse_gnu_stat_timestamp(match["ctime"]),
        kind,
    )


def parse_file_object_state(
    value: str,
    *,
    allowed_sentinels: frozenset[IdentitySentinel] = frozenset(),
) -> FileObjectState | IdentitySentinel:
    if not isinstance(value, str):
        raise TypeError("persisted identity must be text")
    sentinel = _sentinel(value, allowed_sentinels)
    if sentinel is not None:
        return sentinel
    match = _OBJECT_PATTERN.fullmatch(value)
    if match is None:
        raise PersistedIdentityError("persisted file object state is malformed")
    return FileObjectState(*_components(match))


def parse_directory_identity(
    value: str,
    *,
    allowed_sentinels: frozenset[IdentitySentinel] = frozenset(),
) -> DirectoryIdentity | IdentitySentinel:
    if not isinstance(value, str):
        raise TypeError("persisted identity must be text")
    sentinel = _sentinel(value, allowed_sentinels)
    if sentinel is not None:
        return sentinel
    match = _DIRECTORY_PATTERN.fullmatch(value)
    if match is None:
        raise PersistedIdentityError("persisted directory identity is malformed")
    return DirectoryIdentity(
        _integer(match["dev"], "device", _UINT64_MAX),
        _integer(match["ino"], "inode", _UINT64_MAX, positive=True),
        _integer(match["uid"], "owner", _UINT32_MAX),
        _mode(match["mode"]),
        "directory",
    )


def _serialized_kind(kind: str, size: int) -> str:
    if kind == "directory":
        return "directory"
    if kind != "regular":
        raise PersistedIdentityError("persisted identity has an unsupported kind")
    return "regular empty file" if size == 0 else "regular file"


def _serialize_components(identity: FileIdentity | FileObjectState) -> str:
    values = (
        _integer(str(identity.dev), "device", _UINT64_MAX),
        _integer(str(identity.ino), "inode", _UINT64_MAX, positive=True),
        _integer(str(identity.uid), "owner", _UINT32_MAX),
        identity.permissions,
        _integer(str(identity.links), "link count", _UINT64_MAX, positive=True),
        _integer(str(identity.size), "size", _INT64_MAX),
    )
    if (
        isinstance(values[3], bool)
        or not isinstance(values[3], int)
        or not 0 <= values[3] <= 0o7777
    ):
        raise PersistedIdentityError("persisted identity mode is outside its range")
    return ":".join(
        (
            str(values[0]),
            str(values[1]),
            str(values[2]),
            format(values[3], "o"),
            str(values[4]),
            str(values[5]),
        )
    )


def serialize_file_identity(
    identity: FileIdentity,
    *,
    utc_offset_minutes: int | None = None,
) -> str:
    if not isinstance(identity, FileIdentity):
        raise TypeError("identity must be a FileIdentity")
    return ":".join(
        (
            _serialize_components(identity),
            format_gnu_stat_timestamp(
                identity.mtime_ns, utc_offset_minutes=utc_offset_minutes
            ),
            format_gnu_stat_timestamp(
                identity.ctime_ns, utc_offset_minutes=utc_offset_minutes
            ),
            _serialized_kind(identity.kind, identity.size),
        )
    )


def serialize_file_object_state(identity: FileObjectState) -> str:
    if not isinstance(identity, FileObjectState):
        raise TypeError("identity must be a FileObjectState")
    return f"{_serialize_components(identity)}:{_serialized_kind(identity.kind, identity.size)}"


def serialize_directory_identity(identity: DirectoryIdentity) -> str:
    if not isinstance(identity, DirectoryIdentity):
        raise TypeError("identity must be a DirectoryIdentity")
    if identity.kind != "directory":
        raise PersistedIdentityError("directory identity has an unsupported kind")
    dev = _integer(str(identity.dev), "device", _UINT64_MAX)
    ino = _integer(str(identity.ino), "inode", _UINT64_MAX, positive=True)
    uid = _integer(str(identity.uid), "owner", _UINT32_MAX)
    if (
        isinstance(identity.permissions, bool)
        or not isinstance(identity.permissions, int)
        or not 0 <= identity.permissions <= 0o7777
    ):
        raise PersistedIdentityError("persisted identity mode is outside its range")
    return f"{dev}:{ino}:{uid}:{identity.permissions:o}:directory"
