from __future__ import annotations

import os
import re
import shutil
import stat
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path

import pytest

from .harness import ProcessTimeout, run_process


ROOT_DIR = Path(__file__).resolve().parents[2]
TOOL = ROOT_DIR / "bin/platform-vm-env-collect"
SYNTHETIC_SECRET = "collector-secret-value"


@dataclass(frozen=True)
class CollectedArchive:
    archive: Path
    checksum: Path
    extraction_root: Path
    report: Path


def require_development_container() -> None:
    if os.environ.get("PLATFORM_TOOLS_DEV_CONTAINER") != "1":
        pytest.fail(
            "archive smoke test must run in the development container",
            pytrace=False,
        )


def collector_base_dir(stderr: str) -> Path | None:
    marker = "Output directory: "
    for line in stderr.splitlines():
        if marker not in line:
            continue
        base_dir = Path(line.partition(marker)[2]).parent
        if base_dir.parent == Path("/tmp") and re.fullmatch(
            r"platform-vm-env-collect\.[A-Za-z0-9]{6}", base_dir.name
        ):
            return base_dir
    return None


def test_development_container_guard() -> None:
    require_development_container()


@pytest.fixture(scope="module")
def collected_archive(tmp_path_factory) -> Generator[CollectedArchive, None, None]:
    require_development_container()
    work_dir = tmp_path_factory.mktemp("vm-env-collect-archive")
    base_dir: Path | None = None
    try:
        fake_bin = work_dir / "fake-bin"
        fake_bin.mkdir()
        for command in ("ip", "ss", "systemctl"):
            fake = fake_bin / command
            fake.write_text("#!/usr/bin/env sh\nexit 0\n")
            fake.chmod(0o755)

        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
                "COLLECT_ENV": "1",
                "COLLECTOR_TEST_PASSWORD": SYNTHETIC_SECRET,
            }
        )
        try:
            result = run_process((TOOL,), env=env, timeout=120)
        except ProcessTimeout as error:
            base_dir = collector_base_dir(error.result.stderr)
            raise
        base_dir = collector_base_dir(result.stderr)
        assert result.status == 0, (
            f"collector failed with status {result.status}:\n{result.stderr}"
        )
        assert base_dir is not None, "collector did not report its private base directory"

        archive_lines = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.startswith("  /tmp/platform-vm-env-collect.")
            and line.endswith(".tar.gz")
        ]
        assert len(archive_lines) == 1, "collector did not report one archive"
        archive = Path(archive_lines[0])
        assert archive.parent == base_dir, "archive is outside the reported base directory"
        assert archive.is_file(), "collector did not report a readable archive"

        extract_dir = work_dir / "extracted"
        extract_dir.mkdir()
        extraction = run_process(
            ("tar", "-C", extract_dir, "-xzf", archive), timeout=30
        )
        assert extraction.status == 0, extraction.stderr
        report = extract_dir / archive.name.removesuffix(".tar.gz")

        yield CollectedArchive(
            archive,
            Path(f"{archive}.sha256"),
            extract_dir,
            report,
        )
    finally:
        if base_dir is not None:
            shutil.rmtree(base_dir, ignore_errors=True)
        shutil.rmtree(work_dir, ignore_errors=True)


def test_collector_creates_archive(collected_archive: CollectedArchive) -> None:
    assert collected_archive.archive.is_file()


def test_archive_mode_is_private(collected_archive: CollectedArchive) -> None:
    assert collected_archive.archive.stat().st_mode & 0o777 == 0o600


def test_checksum_mode_is_private(collected_archive: CollectedArchive) -> None:
    assert collected_archive.checksum.stat().st_mode & 0o777 == 0o600


def test_checksum_verifies(collected_archive: CollectedArchive) -> None:
    result = run_process(
        ("sha256sum", "-c", collected_archive.checksum),
        cwd=collected_archive.archive.parent,
        timeout=30,
    )

    assert result.status == 0, result.stderr


def test_archive_extracts_report_directory(
    collected_archive: CollectedArchive,
) -> None:
    assert collected_archive.report.is_dir()


def test_archive_extracts_summary(collected_archive: CollectedArchive) -> None:
    assert (collected_archive.report / "SUMMARY.md").is_file()


def test_archive_extracts_environment_metadata(
    collected_archive: CollectedArchive,
) -> None:
    assert (collected_archive.report / "meta/collector-env.txt").is_file()


def test_environment_secret_is_redacted(collected_archive: CollectedArchive) -> None:
    metadata = (collected_archive.report / "meta/collector-env.txt").read_text()

    assert "COLLECTOR_TEST_PASSWORD=<REDACTED>" in metadata


def test_environment_secret_value_is_absent(
    collected_archive: CollectedArchive,
) -> None:
    secret = SYNTHETIC_SECRET.encode()

    for extracted_file in collected_archive.extraction_root.rglob("*"):
        if stat.S_ISREG(extracted_file.stat(follow_symlinks=False).st_mode):
            assert secret not in extracted_file.read_bytes(), extracted_file
