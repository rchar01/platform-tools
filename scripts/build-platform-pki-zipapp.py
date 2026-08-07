#!/usr/bin/env python3
import argparse
import os
import re
import stat
import tempfile
import zipfile
from pathlib import Path


SHEBANG = b"#!/usr/bin/env -S python3 -I -S\n"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
ENTRYPOINT = b"from platform_pki.__main__ import main\nraise SystemExit(main())\n"
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[+-][0-9A-Za-z.-]+)?")


def _read_version(path: Path) -> str:
    raw = path.read_bytes()
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise ValueError("VERSION must contain one newline-terminated value")
    version = raw[:-1].decode("ascii")
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError("VERSION has an unsupported format")
    return version


def _source_members(source: Path, version: str) -> dict[str, bytes]:
    if not source.is_dir() or source.is_symlink():
        raise ValueError(f"zipapp source must be a non-symlink directory: {source}")

    members = {
        "__main__.py": ENTRYPOINT,
        "platform_pki/_version.py": f'VERSION = "{version}"\n'.encode("ascii"),
    }
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"zipapp source must not contain symlinks: {path}")
        if "__pycache__" in path.parts:
            continue
        if path.is_dir():
            continue
        if not path.is_file() or path.suffix != ".py":
            raise ValueError(f"unexpected zipapp source file: {path}")
        relative = path.relative_to(source.parent).as_posix()
        if relative in members:
            raise ValueError(f"generated zipapp member conflicts with source: {relative}")
        members[relative] = path.read_bytes()
    return members


def _member_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info


def build_archive(source: Path, version_file: Path, output: Path) -> None:
    version = _read_version(version_file)
    members = _source_members(source, version)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        dir=output.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(SHEBANG)
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
                for name in sorted(members):
                    archive.writestr(_member_info(name), members[name])
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o755)
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()


def verify_archive(source: Path, version_file: Path, output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="platform-pki-zipapp-") as directory:
        temporary = Path(directory)
        first = temporary / "first"
        second = temporary / "second"
        build_archive(source, version_file, first)
        build_archive(source, version_file, second)
        if first.read_bytes() != second.read_bytes():
            raise RuntimeError("generated platform-pki zipapp is not deterministic")
        if not output.is_file() or output.is_symlink():
            raise RuntimeError(f"generated platform-pki zipapp is missing or unsafe: {output}")
        if first.read_bytes() != output.read_bytes():
            raise RuntimeError("bin/platform-pki is stale; run make generate-python")
        if output.stat().st_mode & 0o777 != 0o755:
            raise RuntimeError("bin/platform-pki must have mode 755")


def _parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--source", type=Path, default=root / "src/platform_pki")
    parser.add_argument("--version-file", type=Path, default=root / "VERSION")
    parser.add_argument("--output", type=Path, default=root / "bin/platform-pki")
    parser.add_argument("--verify", action="store_true")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if arguments.verify:
        verify_archive(arguments.source, arguments.version_file, arguments.output)
    else:
        build_archive(arguments.source, arguments.version_file, arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
